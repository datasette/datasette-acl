"""JSON API for datasette-acl (the share component's backend).

acl was form-POST only; this is the first JSON endpoint. Task 03 adds the
*read* side:

    GET /-/acl/api/resource/{resource_type}/{parent}/{child}

returning the share state for one resource — the dialog's main read. Grants are
grouped by principal, each principal's granted action-set is resolved to a
friendly role, and actor grants are enriched with display name / email / avatar
via core ``datasette.actors_from_ids`` (owned by user-profiles in phase-03;
degrades to ``{"id": id}`` when profiles is not installed). Group grants resolve
to a name + member count from ``acl_groups`` / ``acl_actor_groups``. Wildcard
principals (``*`` / ``_signed_in`` / ``_anonymous``) are flagged ``kind:"public"``
and surface in the dialog's "General access" section.

Task 04 adds the *write* side — three JSON POST endpoints, each authorized by a
**per-resource** manage check rather than a global flag:

    POST /-/acl/api/resource/{resource_type}/{parent}/{child}/grant
    POST .../revoke
    POST .../update

``can_manage`` (and its raising sibling ``_ensure_can_manage``) is the
authoritative authz gate: an actor may manage sharing if EITHER they hold the
global ``datasette-acl`` permission (admin) OR they are ``datasette.allowed`` a
``manage=True`` role's action on *this specific resource* (i.e. they hold a
Manager/Owner grant — which itself flows through the same acl machinery, so it
composes with groups). A resource type that registers no ``manage`` role falls
back to the global ``datasette-acl`` permission, so table-style resources still
work.

CSRF: datasette 1.0a30 replaced token-based asgi-csrf with the header-based
``CrossOriginProtectionMiddleware`` (Sec-Fetch-Site + Origin). That core
middleware rejects cross-origin browser writes before they reach these
handlers, so the endpoints carry no server-side CSRF token logic of their own;
the share component sends same-origin requests (and may set ``x-csrftoken`` for
forward compat, which core ignores). Non-browser clients (the test client,
curl) send neither header and pass through.
"""

import json

from datasette import Response, Forbidden

from datasette_acl.grants import grant, revoke, update_role, list_grants
from datasette_acl.roles import role_for_actions, manage_only_actions
from datasette_acl.utils import (
    build_resource,
    resource_class_for,
    can_edit_permissions,
    get_acl_valid_actors,
)

# Wildcard / "general access" principals. These are stored as actor_id values in
# acl rows but represent classes of actor rather than a specific person, so the
# UI renders them in a separate "General access" section.
PUBLIC_PRINCIPALS = {"*", "_signed_in", "_anonymous"}


def _roles_for(datasette, resource_type):
    registry = getattr(datasette, "_acl_roles_registry", None) or {}
    return registry.get(resource_type, [])


def _roles_payload(roles):
    """Serialize the roles registry for a resource type to the API shape."""
    payload = []
    for role in roles:
        entry = {
            "name": role.name,
            "actions": list(role.actions),
            "rank": role.rank,
        }
        if role.manage:
            entry["manage"] = True
        if role.description:
            entry["description"] = role.description
        payload.append(entry)
    return payload


async def can_manage(datasette, actor, resource_type, parent, child=None):
    """Whether ``actor`` may manage sharing for this resource.

    The authoritative per-resource manage check (task 04). An actor can manage
    if EITHER:

      * they are ``datasette.allowed`` one of the resource type's *manage-only*
        actions on this specific resource — i.e. they hold a ``manage=True``
        role grant (Manager/Owner), which flows through the same acl machinery
        and so composes with groups; OR
      * the resource type registers no ``manage`` role, in which case we fall
        back to the global ``datasette-acl`` permission so table-style resources
        (which only have raw actions, no roles) still work.

    The manage check authorizes against :func:`manage_only_actions` (the action
    exclusive to manage roles, e.g. ``paper-manage``) rather than the full
    Manager action bundle — otherwise any Viewer/Editor, who also holds
    ``*-view``, would pass. The global ``datasette-acl`` admin always wins.

    Returns False (rather than raising) for unknown resource types.
    """
    if await can_edit_permissions(datasette, actor):
        return True
    manage = manage_only_actions(_roles_for(datasette, resource_type))
    if not manage:
        # No manage role for this type: fall back to global admin (already
        # checked above and was False), so non-admins cannot manage.
        return False
    try:
        resource = build_resource(datasette, resource_type, parent, child)
    except ValueError:
        return False
    for action in manage:
        if await datasette.allowed(action=action, resource=resource, actor=actor):
            return True
    return False


async def _ensure_can_manage(datasette, request, resource_type, parent, child=None):
    """Raise ``Forbidden`` unless ``request.actor`` may manage this resource.

    The authoritative per-resource authz gate for the mutation endpoints: it
    delegates to :func:`can_manage` (global ``datasette-acl`` perm OR a
    per-resource ``manage=True`` role action) and raises rather than returning a
    bool so handlers can guard with a single ``await``.
    """
    if not await can_manage(datasette, request.actor, resource_type, parent, child):
        raise Forbidden("Cannot manage sharing for this resource")


def _kind_for(actor_id, enriched):
    """Resolve the ``kind`` for an actor-principal grant.

    Wildcard principals are ``public``. Otherwise prefer a ``kind`` supplied by
    the actor-resolution layer (profiles / agents); default to ``user``.
    """
    if actor_id in PUBLIC_PRINCIPALS:
        return "public"
    if enriched and enriched.get("kind"):
        return enriched["kind"]
    return "user"


async def _group_info(datasette, group_ids):
    """Return ``{group_id: {"name", "member_count"}}`` for the given ids."""
    if not group_ids:
        return {}
    db = datasette.get_internal_database()
    placeholders = ", ".join("?" for _ in group_ids)
    rows = await db.execute(
        f"""
        SELECT
            acl_groups.id AS id,
            acl_groups.name AS name,
            count(acl_actor_groups.actor_id) AS member_count
        FROM acl_groups
        LEFT JOIN acl_actor_groups ON acl_groups.id = acl_actor_groups.group_id
        WHERE acl_groups.id IN ({placeholders})
        GROUP BY acl_groups.id, acl_groups.name
        """,
        list(group_ids),
    )
    return {
        row["id"]: {"name": row["name"], "member_count": row["member_count"]}
        for row in rows.rows
    }


async def _actor_grant_entry(datasette, roles, actor_id, actions):
    """Build the enriched API entry for one actor-principal grant.

    Resolves the granted action-set to its best role, enriches via core
    ``actors_from_ids`` (skipped for wildcard principals), and tags ``kind``.
    """
    role = role_for_actions(roles, set(actions))
    enriched = {}
    if actor_id not in PUBLIC_PRINCIPALS:
        enriched = (await datasette.actors_from_ids([actor_id])) or {}
    info = enriched.get(actor_id) or {}
    entry = {
        "principal": "actor",
        "id": actor_id,
        "role": role.name if role else None,
        "actions": sorted(actions),
        "kind": _kind_for(actor_id, info),
    }
    for key in ("display_name", "email", "avatar_url"):
        if info.get(key):
            entry[key] = info[key]
    return entry


async def _group_grant_entry(datasette, roles, group_id, actions):
    """Build the enriched API entry for one group-principal grant."""
    role = role_for_actions(roles, set(actions))
    info = (await _group_info(datasette, [group_id])).get(group_id, {})
    return {
        "principal": "group",
        "id": str(group_id),
        "role": role.name if role else None,
        "actions": sorted(actions),
        "kind": "group",
        "display_name": info.get("name"),
        "member_count": info.get("member_count", 0),
    }


def _principal_from_body(body):
    """Extract ``(actor_id, group_id)`` from a request body, enforcing exactly one.

    Returns ``(actor_id, group_id)`` with exactly one non-None. Raises
    ``ValueError`` if neither or both are supplied (mirrors the acl CHECK
    invariant) so handlers can translate it to a 400.
    """
    actor_id = body.get("actor_id")
    group_id = body.get("group_id")
    if (actor_id is None) == (group_id is None):
        raise ValueError("Provide exactly one of actor_id or group_id")
    return actor_id, group_id


def _parse_json_body(request_body):
    """Parse the raw POST body as a JSON object, or raise ``ValueError``."""
    if not request_body:
        return {}
    try:
        data = json.loads(request_body)
    except json.JSONDecodeError:
        raise ValueError("Request body must be valid JSON")
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object")
    return data


async def _enriched_grant(datasette, roles, actor_id, group_id, actions):
    """Build the enriched grant entry for whichever principal was supplied."""
    if actor_id is not None:
        return await _actor_grant_entry(datasette, roles, actor_id, actions)
    return await _group_grant_entry(datasette, roles, group_id, actions)


async def resource_grants_json(request, datasette):
    """GET /-/acl/api/resource/{resource_type}/{parent}/{child}.

    The child segment is optional so parent-only resource types also resolve.
    """
    resource_type = request.url_vars["resource_type"]
    parent = request.url_vars["parent"]
    child = request.url_vars.get("child")

    if resource_class_for(datasette, resource_type) is None:
        raise Forbidden(f"Unknown resource type: {resource_type}")

    # Gate: for v1 the full grant list is readable only by managers.
    actor_can_manage = await can_manage(
        datasette, request.actor, resource_type, parent, child
    )
    if not actor_can_manage:
        raise Forbidden("Cannot manage sharing for this resource")

    roles = _roles_for(datasette, resource_type)
    raw_grants = await list_grants(datasette, resource_type, parent, child)

    # Enrich actor grants in one batch via core actors_from_ids. Wildcard
    # principals are not real actors; we never look them up.
    actor_ids = [
        g["actor_id"]
        for g in raw_grants
        if g["principal"] == "actor" and g["actor_id"] not in PUBLIC_PRINCIPALS
    ]
    enriched = {}
    if actor_ids:
        enriched = await datasette.actors_from_ids(actor_ids) or {}

    group_ids = [g["group_id"] for g in raw_grants if g["principal"] == "group"]
    group_info = await _group_info(datasette, group_ids)

    grants = []
    for g in raw_grants:
        role = role_for_actions(roles, set(g["actions"]))
        if g["principal"] == "actor":
            actor_id = g["actor_id"]
            entry = {
                "principal": "actor",
                "id": actor_id,
                "role": role.name if role else None,
                "actions": g["actions"],
                "kind": _kind_for(actor_id, enriched.get(actor_id)),
            }
            info = enriched.get(actor_id) or {}
            for key in ("display_name", "email", "avatar_url"):
                if info.get(key):
                    entry[key] = info[key]
            grants.append(entry)
        else:
            info = group_info.get(g["group_id"], {})
            grants.append(
                {
                    "principal": "group",
                    "id": str(g["group_id"]),
                    "role": role.name if role else None,
                    "actions": g["actions"],
                    "kind": "group",
                    "display_name": info.get("name", g["group_name"]),
                    "member_count": info.get("member_count", 0),
                }
            )

    return Response.json(
        {
            "resource_type": resource_type,
            "parent": parent,
            "child": child,
            "can_manage": actor_can_manage,
            "roles": _roles_payload(roles),
            "grants": grants,
        }
    )


class _ApiError(Exception):
    """Carries an HTTP status + message for a JSON error response."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _error_response(exc):
    return Response.json({"ok": False, "error": exc.message}, status=exc.status)


async def _begin_mutation(request, datasette):
    """Shared preamble for the mutation endpoints.

    Enforces POST, a known resource type, and the per-resource manage gate, then
    parses the JSON body. Returns ``(resource_type, parent, child, roles,
    body)``. Raises ``Forbidden`` (403) for the authz / unknown-type cases
    (handled by core) and ``_ApiError`` for a bad method (405) or unparseable
    body (400), which each handler catches and renders as a JSON error response.
    """
    if request.method != "POST":
        raise _ApiError(405, "Method not allowed")
    resource_type = request.url_vars["resource_type"]
    parent = request.url_vars["parent"]
    child = request.url_vars.get("child")
    if resource_class_for(datasette, resource_type) is None:
        raise Forbidden(f"Unknown resource type: {resource_type}")
    # Per-resource authorization — the correctness fix over a global flag.
    await _ensure_can_manage(datasette, request, resource_type, parent, child)
    try:
        body = _parse_json_body(await request.post_body())
    except ValueError as exc:
        raise _ApiError(400, str(exc))
    roles = _roles_for(datasette, resource_type)
    return resource_type, parent, child, roles, body


async def grant_json(request, datasette):
    """POST /-/acl/api/resource/{type}/{parent}/{child}/grant.

    Body: ``{actor_id|group_id, role}`` or ``{actor_id|group_id, actions: [...]}``.
    Upserts the grant (idempotent), audits, and returns the enriched grant.
    """
    try:
        resource_type, parent, child, roles, body = await _begin_mutation(
            request, datasette
        )
        actor_id, group_id = _principal_from_body(body)
        by_actor = (request.actor or {}).get("id")
        actions = await grant(
            datasette,
            resource_type,
            parent,
            child,
            actor_id=actor_id,
            group_id=group_id,
            role=body.get("role"),
            actions=body.get("actions"),
            by_actor=by_actor,
        )
    except _ApiError as exc:
        return _error_response(exc)
    except ValueError as exc:
        return _error_response(_ApiError(400, str(exc)))
    entry = await _enriched_grant(datasette, roles, actor_id, group_id, actions)
    return Response.json({"ok": True, "grant": entry})


# --- pickers ---------------------------------------------------------------
#
# The share dialog needs to populate the "add a person / group" boxes. Two
# decoupled endpoints back that:
#
#   GET /-/acl/api/groups          -> the group picker, drawn from acl_groups.
#   GET /-/acl/api/actors?q=&kind= -> the actor picker. The dialog MAY call the
#     user-profiles search API directly; this endpoint is the decoupled fallback
#     that delegates to profiles when installed and otherwise filters acl's own
#     ``datasette_acl_valid_actors`` in Python, so the picker still works on an
#     acl-only deployment (plan §C).
#
# Authorization: the share dialog is driven by per-resource Managers (a doc
# owner) who don't hold the global ``datasette-acl`` admin permission, so the
# pickers accept OPTIONAL ``resource_type`` / ``parent`` / ``child`` query
# params. When supplied, the request is authorized via the same per-resource
# :func:`can_manage` gate the read + mutation endpoints use (global admin OR a
# ``manage=True`` role action on that specific resource). When omitted, we fall
# back to the global ``datasette-acl`` permission (back-compat for acl's own
# admin pages). Neither passing → ``Forbidden``.


async def _ensure_can_pick(datasette, request, message):
    """Authorize a picker request.

    If ``resource_type`` / ``parent`` (+ optional ``child``) query params are
    present, authorize against the per-resource :func:`can_manage` gate.
    Otherwise fall back to the global ``datasette-acl`` admin check. Raises
    ``Forbidden(message)`` when neither passes.
    """
    resource_type = request.args.get("resource_type")
    parent = request.args.get("parent")
    if resource_type and parent:
        child = request.args.get("child")
        if await can_manage(datasette, request.actor, resource_type, parent, child):
            return
        raise Forbidden(message)
    if await can_edit_permissions(datasette, request.actor):
        return
    raise Forbidden(message)


async def groups_json(request, datasette):
    """GET /-/acl/api/groups[?resource_type=&parent=&child=].

    Returns ``{"groups": [{"id", "name", "member_count"}]}`` for every active
    (non soft-deleted) group, with a member-count subquery. Authorized per
    :func:`_ensure_can_pick`: a per-resource Manager (when the resource is
    supplied) or the global ``datasette-acl`` admin.
    """
    await _ensure_can_pick(datasette, request, "Cannot list groups")
    db = datasette.get_internal_database()
    rows = await db.execute(
        """
        SELECT
            acl_groups.id AS id,
            acl_groups.name AS name,
            count(acl_actor_groups.actor_id) AS member_count
        FROM acl_groups
        LEFT JOIN acl_actor_groups ON acl_groups.id = acl_actor_groups.group_id
        WHERE acl_groups.deleted IS NULL
        GROUP BY acl_groups.id, acl_groups.name
        ORDER BY acl_groups.name
        """
    )
    groups = [
        {"id": row["id"], "name": row["name"], "member_count": row["member_count"]}
        for row in rows.rows
    ]
    return Response.json({"groups": groups})


async def _profiles_search(datasette, q, kind):
    """Delegate the actor search to user-profiles' search API, if installed.

    Issues an internal request to ``GET /-/profiles/api/search`` (carrying the
    same query). Returns the parsed ``results`` list, or ``None`` when profiles
    is not installed / the route is absent (so the caller falls back). Any error
    response (e.g. 403) is treated as "no results" rather than propagated, since
    this is an autocomplete helper.
    """
    params = {}
    if q:
        params["q"] = q
    if kind:
        params["kind"] = kind
    try:
        response = await datasette.client.get(
            datasette.urls.path("/-/profiles/api/search"), params=params
        )
    except Exception:
        return None
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        return []
    try:
        data = response.json()
    except Exception:
        return []
    return data.get("results", [])


async def _valid_actors_fallback(datasette, q):
    """Filter ``datasette_acl_valid_actors`` by ``q`` (substring, case-insensitive).

    The acl-only fallback when user-profiles is not installed. ``valid_actors``
    yields ``(id, display)`` pairs with no avatar/email, so the entries are
    minimal: ``{"id", "display_name", "kind": "user"}``.
    """
    actors = await get_acl_valid_actors(datasette)
    needle = (q or "").lower()
    results = []
    for actor_id, display in actors:
        if needle and needle not in actor_id.lower() and needle not in (
            display or ""
        ).lower():
            continue
        results.append(
            {"id": actor_id, "display_name": display, "kind": "user"}
        )
    return results


async def actors_json(request, datasette):
    """GET /-/acl/api/actors?q=&kind=[&resource_type=&parent=&child=].

    Thin actor-autocomplete proxy. Delegates to the user-profiles search API
    when available, else falls back to ``datasette_acl_valid_actors`` filtered by
    ``q`` in Python. Returns ``{"results": [{"id", "display_name", "avatar_url",
    "kind", ...}]}``. Authorized per :func:`_ensure_can_pick`: a per-resource
    Manager (when the resource is supplied) or the global ``datasette-acl``
    admin.
    """
    await _ensure_can_pick(datasette, request, "Cannot search actors")
    q = (request.args.get("q") or "").strip()
    kind = request.args.get("kind")
    results = await _profiles_search(datasette, q, kind)
    if results is None:
        results = await _valid_actors_fallback(datasette, q)
    return Response.json({"results": results})


async def revoke_json(request, datasette):
    """POST /-/acl/api/resource/{type}/{parent}/{child}/revoke.

    Body: ``{actor_id}`` or ``{group_id}``. Deletes all acl rows for that
    principal on this resource, audits each removal, returns ``{ok: true}``.
    """
    try:
        resource_type, parent, child, roles, body = await _begin_mutation(
            request, datasette
        )
        actor_id, group_id = _principal_from_body(body)
        by_actor = (request.actor or {}).get("id")
        removed = await revoke(
            datasette,
            resource_type,
            parent,
            child,
            actor_id=actor_id,
            group_id=group_id,
            by_actor=by_actor,
        )
    except _ApiError as exc:
        return _error_response(exc)
    except ValueError as exc:
        return _error_response(_ApiError(400, str(exc)))
    return Response.json({"ok": True, "removed": removed})


async def update_json(request, datasette):
    """POST /-/acl/api/resource/{type}/{parent}/{child}/update.

    Body: ``{actor_id|group_id, role}``. Atomically swaps the principal's action
    set to the new role, audits each change, and returns the enriched grant.
    """
    try:
        resource_type, parent, child, roles, body = await _begin_mutation(
            request, datasette
        )
        actor_id, group_id = _principal_from_body(body)
        role = body.get("role")
        if not role:
            raise _ApiError(400, "update requires a role")
        by_actor = (request.actor or {}).get("id")
        actions = await update_role(
            datasette,
            resource_type,
            parent,
            child,
            actor_id=actor_id,
            group_id=group_id,
            role=role,
            by_actor=by_actor,
        )
    except _ApiError as exc:
        return _error_response(exc)
    except ValueError as exc:
        return _error_response(_ApiError(400, str(exc)))
    entry = await _enriched_grant(datasette, roles, actor_id, group_id, actions)
    return Response.json({"ok": True, "grant": entry})
