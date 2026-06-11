"""Reusable Python grant helpers for datasette-acl.

acl historically had no public Python API: callers wanting to grant access had
to write raw SQL into acl's tables. These helpers centralize the writes so other
plugins (the JSON API in tasks 03-05, and consumer data-migrations in later
phases) call functions instead of touching acl's schema directly.

Every mutating helper:
  * ensures the ``acl_resources`` row exists for ``(resource_type, parent, child)``,
  * ensures the relevant ``acl_actions`` rows exist,
  * writes the ``acl`` rows, and
  * appends ``acl_audit`` entries (``operation_by`` = ``by_actor``).

Principal invariant: a grant targets exactly one principal -- an actor
(``actor_id=``), a group (``group_id=``), or a public audience
(``principal_type=`` one of ``'everyone'`` / ``'authenticated'`` /
``'anonymous'``, with no id at all) -- matching the CHECK constraint on the
``acl`` table. :func:`principal_type_for` is the single place that resolves
and validates the combination.
"""

from __future__ import annotations

from typing import (
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    TypedDict,
    TYPE_CHECKING,
)

from datasette_acl.roles import actions_for_role, roles_for
from datasette_acl.utils import PUBLIC_PRINCIPAL_TYPES, actions_for_resource_type

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.database import Database


PrincipalType = Literal["actor", "group", "everyone", "authenticated", "anonymous"]


class Grant(TypedDict):
    """One principal's grants on a resource, as returned by :func:`list_grants`.

    ``principal`` is the stored ``principal_type``. ``actor_id`` is set only
    for ``actor`` grants and ``group_id``/``group_name`` only for ``group``
    grants; public-audience grants carry no id.
    """

    principal: PrincipalType
    actor_id: Optional[str]
    group_id: Optional[int]
    group_name: Optional[str]
    actions: List[str]


def _resolve_actions(
    datasette: Datasette,
    resource_type: str,
    role: Optional[str],
    actions: Optional[Iterable[str]],
) -> List[str]:
    """Resolve the action list for a grant from either ``role`` or ``actions``.

    Exactly one of ``role`` / ``actions`` must be provided. ``role`` is resolved
    against the startup roles registry via :func:`actions_for_role`. Raw
    ``actions`` are validated against the actions the resource type actually
    registers (:func:`actions_for_resource_type`) -- otherwise an unknown or
    future action name would be invented in ``acl_actions`` and could silently
    become a live grant once a later version registers it (issue #45).
    """
    if (role is None) == (actions is None):
        raise ValueError("Provide exactly one of role= or actions=")
    if role is not None:
        resolved = actions_for_role(roles_for(datasette, resource_type), role)
        if resolved is None:
            raise ValueError(
                f"Unknown role {role!r} for resource type {resource_type!r}"
            )
        return list(resolved)
    # The guard above guarantees actions is not None when role is None.
    assert actions is not None
    requested = list(actions)
    valid = set(actions_for_resource_type(datasette, resource_type))
    unknown = [action for action in requested if action not in valid]
    if unknown:
        raise ValueError(
            f"Unknown action(s) {unknown!r} for resource type {resource_type!r}"
        )
    return requested


def principal_type_for(
    actor_id: Optional[str],
    group_id: Optional[int],
    principal_type: Optional[str] = None,
) -> PrincipalType:
    """Resolve and validate the ``principal_type`` for a grant's principal.

    A principal is exactly one of: an actor (``actor_id=``), a group
    (``group_id=``), or a public audience (``principal_type=`` one of
    ``PUBLIC_PRINCIPAL_TYPES``, with neither id). ``principal_type`` may also
    redundantly name ``'actor'`` / ``'group'`` alongside the matching id.
    Raises ``ValueError`` for any other combination, mirroring the acl table's
    CHECK constraint.
    """
    if principal_type in PUBLIC_PRINCIPAL_TYPES:
        if actor_id is not None or group_id is not None:
            raise ValueError(
                f"principal_type {principal_type!r} cannot be combined with "
                "actor_id= or group_id="
            )
        return principal_type
    if (actor_id is None) == (group_id is None):
        raise ValueError(
            "Provide exactly one principal: actor_id=, group_id=, or a "
            f"public principal_type ({', '.join(PUBLIC_PRINCIPAL_TYPES)})"
        )
    if group_id is not None:
        if principal_type not in (None, "group"):
            raise ValueError(
                f"principal_type {principal_type!r} cannot be used with group_id="
            )
        return "group"
    if principal_type not in (None, "actor"):
        raise ValueError(
            f"principal_type {principal_type!r} cannot be used with actor_id="
        )
    return "actor"


async def _ensure_resource_id(
    db: Database, resource_type: str, parent: str, child: Optional[str]
) -> int:
    # NOTE: the acl_resources UNIQUE(resource_type, parent, child) constraint
    # treats NULL children as distinct in SQLite, so a bare INSERT OR IGNORE for
    # a parent-only resource (child IS NULL) would create a duplicate row on
    # every call. Select first and only insert when absent; return the lowest
    # existing id so repeated calls are stable.
    select_sql = (
        "SELECT id FROM acl_resources "
        "WHERE resource_type = ? AND parent = ? AND child IS ? "
        "ORDER BY id LIMIT 1"
    )
    existing = await db.execute(select_sql, [resource_type, parent, child])
    if existing.rows:
        return existing.rows[0][0]
    await db.execute_write(
        "INSERT INTO acl_resources (resource_type, parent, child) VALUES (?, ?, ?)",
        [resource_type, parent, child],
    )
    return (
        await db.execute(select_sql, [resource_type, parent, child])
    ).single_value()


async def _ensure_actions(db: Database, actions: Iterable[str]) -> None:
    if actions:
        await db.execute_write_many(
            "INSERT OR IGNORE INTO acl_actions (name) VALUES (:name)",
            [{"name": name} for name in actions],
        )


async def _current_actions(
    db: Database,
    resource_id: int,
    principal_type: PrincipalType,
    actor_id: Optional[str],
    group_id: Optional[int],
) -> Set[str]:
    """Return the set of action names currently granted to a principal."""
    if principal_type == "actor":
        where = "acl.principal_type = 'actor' AND acl.actor_id = :actor_id"
    elif principal_type == "group":
        where = "acl.principal_type = 'group' AND acl.group_id = :group_id"
    else:
        # Public audience: the type alone identifies the principal.
        where = "acl.principal_type = :principal_type"
    rows = await db.execute(
        f"""
        SELECT acl_actions.name AS name
        FROM acl
        JOIN acl_actions ON acl.action_id = acl_actions.id
        WHERE acl.resource_id = :resource_id AND {where}
        """,
        {
            "resource_id": resource_id,
            "principal_type": principal_type,
            "actor_id": actor_id,
            "group_id": group_id,
        },
    )
    return {row["name"] for row in rows.rows}


async def _insert_grant(
    db: Database,
    resource_id: int,
    principal_type: PrincipalType,
    actor_id: Optional[str],
    group_id: Optional[int],
    action_name: str,
    by_actor: Optional[str],
) -> None:
    await db.execute_write(
        """
        INSERT OR IGNORE INTO acl (
            principal_type, actor_id, group_id, resource_id, action_id
        )
        VALUES (
            :principal_type,
            :actor_id,
            :group_id,
            :resource_id,
            (SELECT id FROM acl_actions WHERE name = :action_name)
        )
        """,
        {
            "principal_type": principal_type,
            "actor_id": actor_id,
            "group_id": group_id,
            "resource_id": resource_id,
            "action_name": action_name,
        },
    )
    await _audit(
        db, "added", resource_id, principal_type, actor_id, group_id, action_name, by_actor
    )


async def _delete_grant(
    db: Database,
    resource_id: int,
    principal_type: PrincipalType,
    actor_id: Optional[str],
    group_id: Optional[int],
    action_name: str,
    by_actor: Optional[str],
) -> None:
    if principal_type == "actor":
        principal_where = "principal_type = 'actor' AND actor_id = :actor_id"
    elif principal_type == "group":
        principal_where = "principal_type = 'group' AND group_id = :group_id"
    else:
        # Public audience: the type alone identifies the principal.
        principal_where = "principal_type = :principal_type"
    await db.execute_write(
        f"""
        DELETE FROM acl
        WHERE {principal_where}
          AND resource_id = :resource_id
          AND action_id = (SELECT id FROM acl_actions WHERE name = :action_name)
        """,
        {
            "principal_type": principal_type,
            "actor_id": actor_id,
            "group_id": group_id,
            "resource_id": resource_id,
            "action_name": action_name,
        },
    )
    await _audit(
        db,
        "removed",
        resource_id,
        principal_type,
        actor_id,
        group_id,
        action_name,
        by_actor,
    )


async def _audit(
    db: Database,
    operation: Literal["added", "removed"],
    resource_id: int,
    principal_type: PrincipalType,
    actor_id: Optional[str],
    group_id: Optional[int],
    action_name: str,
    by_actor: Optional[str],
) -> None:
    await db.execute_write(
        """
        INSERT INTO acl_audit (
            operation, principal_type, actor_id, group_id, resource_id,
            action_id, operation_by
        ) VALUES (
            :operation,
            :principal_type,
            :actor_id,
            :group_id,
            :resource_id,
            (SELECT id FROM acl_actions WHERE name = :action_name),
            :operation_by
        )
        """,
        {
            "operation": operation,
            "principal_type": principal_type,
            "actor_id": actor_id,
            "group_id": group_id,
            "resource_id": resource_id,
            "action_name": action_name,
            "operation_by": by_actor,
        },
    )


async def grant(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
    *,
    actor_id: Optional[str] = None,
    group_id: Optional[int] = None,
    role: Optional[str] = None,
    actions: Optional[Iterable[str]] = None,
    by_actor: Optional[str] = None,
    principal_type: Optional[PrincipalType] = None,
) -> List[str]:
    """Grant a principal access to a resource, by role or by raw actions.

    The principal is exactly one of ``actor_id=``, ``group_id=``, or a public
    audience passed as ``principal_type=`` (``'everyone'`` /
    ``'authenticated'`` / ``'anonymous'``, with neither id). Exactly one of
    ``role`` / ``actions`` must be supplied. Only actions not already granted
    are inserted (idempotent). Returns the list of action names now held by
    the principal.
    """
    ptype = principal_type_for(actor_id, group_id, principal_type)
    resolved = _resolve_actions(datasette, resource_type, role, actions)
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    await _ensure_actions(db, resolved)
    existing = await _current_actions(db, resource_id, ptype, actor_id, group_id)
    for action_name in resolved:
        if action_name not in existing:
            await _insert_grant(
                db, resource_id, ptype, actor_id, group_id, action_name, by_actor
            )
    return sorted(existing | set(resolved))


async def revoke(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
    *,
    actor_id: Optional[str] = None,
    group_id: Optional[int] = None,
    by_actor: Optional[str] = None,
    principal_type: Optional[PrincipalType] = None,
) -> List[str]:
    """Remove all acl rows for a principal on a resource. Audits each removal.

    The principal is specified as in :func:`grant`. Returns the list of action
    names that were removed.
    """
    ptype = principal_type_for(actor_id, group_id, principal_type)
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    existing = await _current_actions(db, resource_id, ptype, actor_id, group_id)
    for action_name in sorted(existing):
        await _delete_grant(
            db, resource_id, ptype, actor_id, group_id, action_name, by_actor
        )
    return sorted(existing)


async def update_role(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
    *,
    actor_id: Optional[str] = None,
    group_id: Optional[int] = None,
    role: str,
    by_actor: Optional[str] = None,
    principal_type: Optional[PrincipalType] = None,
) -> List[str]:
    """Atomically swap a principal's action set on a resource to ``role``.

    The principal is specified as in :func:`grant`. Removes any currently-
    granted actions that are not in the new role, then adds any missing ones.
    Audits each change. Returns the new action list.
    """
    ptype = principal_type_for(actor_id, group_id, principal_type)
    resolved = set(_resolve_actions(datasette, resource_type, role, None))
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    await _ensure_actions(db, resolved)
    existing = await _current_actions(db, resource_id, ptype, actor_id, group_id)
    for action_name in sorted(existing - resolved):
        await _delete_grant(
            db, resource_id, ptype, actor_id, group_id, action_name, by_actor
        )
    for action_name in sorted(resolved - existing):
        await _insert_grant(
            db, resource_id, ptype, actor_id, group_id, action_name, by_actor
        )
    return sorted(resolved)


async def list_grants(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
) -> List[Grant]:
    """Return the grants on a resource as a list of dicts.

    Each dict is a :class:`Grant` with actions sorted; ``principal`` comes
    straight from the stored ``principal_type`` column. Group grants whose
    group is soft-deleted are omitted. The list is ordered actors first, then
    groups, then public audiences, then by id.
    """
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    rows = await db.execute(
        """
        SELECT
            acl.principal_type AS principal_type,
            acl.actor_id AS actor_id,
            acl.group_id AS group_id,
            acl_groups.name AS group_name,
            acl_actions.name AS action_name
        FROM acl
        JOIN acl_actions ON acl.action_id = acl_actions.id
        LEFT JOIN acl_groups ON acl.group_id = acl_groups.id
        WHERE acl.resource_id = :resource_id
          AND (acl.group_id IS NULL OR acl_groups.deleted IS NULL)
        """,
        {"resource_id": resource_id},
    )
    grants = {}
    for row in rows.rows:
        key = (
            row["principal_type"],
            row["actor_id"],
            row["group_id"],
            row["group_name"],
        )
        grants.setdefault(key, set()).add(row["action_name"])
    out: List[Grant] = []
    for (principal, actor_id, group_id, group_name), action_set in grants.items():
        out.append(
            {
                "principal": principal,
                "actor_id": actor_id,
                "group_id": group_id,
                "group_name": group_name,
                "actions": sorted(action_set),
            }
        )
    kind_order = {"actor": 0, "group": 1}
    out.sort(
        key=lambda g: (
            kind_order.get(g["principal"], 2),
            g["principal"],
            g["actor_id"] or "",
            g["group_id"] or 0,
        )
    )
    return out
