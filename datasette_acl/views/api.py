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

Per-resource authorization (the manage check) is formalized in task 04. Until
then ``can_manage`` is computed here from either the global ``datasette-acl``
permission OR the per-resource manage action (via the roles registry); the read
endpoint is gated on ``can_manage``.
"""

from datasette import Response, Forbidden

from datasette_acl.grants import list_grants
from datasette_acl.roles import role_for_actions, manage_actions
from datasette_acl.utils import build_resource, resource_class_for, can_edit_permissions

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

    Task 04 will own the authoritative per-resource manage check; this is the
    forward-compatible version it will build on. An actor can manage if EITHER:

      * they hold the global ``datasette-acl`` permission (admin), OR
      * they are allowed the resource type's "manage" action on this specific
        resource (i.e. they hold a ``manage=True`` role grant).

    Returns False (rather than raising) for unknown resource types.
    """
    if await can_edit_permissions(datasette, actor):
        return True
    manage = manage_actions(_roles_for(datasette, resource_type))
    if not manage:
        return False
    try:
        resource = build_resource(datasette, resource_type, parent, child)
    except ValueError:
        return False
    for action in manage:
        if await datasette.allowed(action=action, resource=resource, actor=actor):
            return True
    return False


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
