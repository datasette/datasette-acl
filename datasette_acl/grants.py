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

Principal invariant: exactly one of ``actor_id`` / ``group_id`` is set, matching
the CHECK constraint on the ``acl`` table.
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
from datasette_acl.utils import actions_for_resource_type

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.database import Database


class Grant(TypedDict):
    """One principal's grants on a resource, as returned by :func:`list_grants`."""

    principal: Literal["actor", "group"]
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


def _check_principal(actor_id: Optional[str], group_id: Optional[int]) -> None:
    """Enforce the acl CHECK invariant: exactly one of actor_id / group_id."""
    if (actor_id is None) == (group_id is None):
        raise ValueError("Provide exactly one of actor_id= or group_id=")


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
    db: Database, resource_id: int, actor_id: Optional[str], group_id: Optional[int]
) -> Set[str]:
    """Return the set of action names currently granted to a principal."""
    if actor_id is not None:
        where = "acl.actor_id = :actor_id AND acl.group_id IS NULL"
    else:
        where = "acl.group_id = :group_id AND acl.actor_id IS NULL"
    rows = await db.execute(
        f"""
        SELECT acl_actions.name AS name
        FROM acl
        JOIN acl_actions ON acl.action_id = acl_actions.id
        WHERE acl.resource_id = :resource_id AND {where}
        """,
        {"resource_id": resource_id, "actor_id": actor_id, "group_id": group_id},
    )
    return {row["name"] for row in rows.rows}


async def _insert_grant(
    db: Database,
    resource_id: int,
    actor_id: Optional[str],
    group_id: Optional[int],
    action_name: str,
    by_actor: Optional[str],
) -> None:
    await db.execute_write(
        """
        INSERT OR IGNORE INTO acl (actor_id, group_id, resource_id, action_id)
        VALUES (
            :actor_id,
            :group_id,
            :resource_id,
            (SELECT id FROM acl_actions WHERE name = :action_name)
        )
        """,
        {
            "actor_id": actor_id,
            "group_id": group_id,
            "resource_id": resource_id,
            "action_name": action_name,
        },
    )
    await _audit(db, "added", resource_id, actor_id, group_id, action_name, by_actor)


async def _delete_grant(
    db: Database,
    resource_id: int,
    actor_id: Optional[str],
    group_id: Optional[int],
    action_name: str,
    by_actor: Optional[str],
) -> None:
    if actor_id is not None:
        principal_where = "actor_id = :actor_id AND group_id IS NULL"
    else:
        principal_where = "group_id = :group_id AND actor_id IS NULL"
    await db.execute_write(
        f"""
        DELETE FROM acl
        WHERE {principal_where}
          AND resource_id = :resource_id
          AND action_id = (SELECT id FROM acl_actions WHERE name = :action_name)
        """,
        {
            "actor_id": actor_id,
            "group_id": group_id,
            "resource_id": resource_id,
            "action_name": action_name,
        },
    )
    await _audit(db, "removed", resource_id, actor_id, group_id, action_name, by_actor)


async def _audit(
    db: Database,
    operation: Literal["added", "removed"],
    resource_id: int,
    actor_id: Optional[str],
    group_id: Optional[int],
    action_name: str,
    by_actor: Optional[str],
) -> None:
    await db.execute_write(
        """
        INSERT INTO acl_audit (
            operation, actor_id, group_id, resource_id, action_id, operation_by
        ) VALUES (
            :operation,
            :actor_id,
            :group_id,
            :resource_id,
            (SELECT id FROM acl_actions WHERE name = :action_name),
            :operation_by
        )
        """,
        {
            "operation": operation,
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
) -> List[str]:
    """Grant a principal access to a resource, by role or by raw actions.

    Exactly one of ``actor_id`` / ``group_id`` and exactly one of ``role`` /
    ``actions`` must be supplied. Only actions not already granted are inserted
    (idempotent). Returns the list of action names now held by the principal.
    """
    _check_principal(actor_id, group_id)
    resolved = _resolve_actions(datasette, resource_type, role, actions)
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    await _ensure_actions(db, resolved)
    existing = await _current_actions(db, resource_id, actor_id, group_id)
    for action_name in resolved:
        if action_name not in existing:
            await _insert_grant(
                db, resource_id, actor_id, group_id, action_name, by_actor
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
) -> List[str]:
    """Remove all acl rows for a principal on a resource. Audits each removal.

    Returns the list of action names that were removed.
    """
    _check_principal(actor_id, group_id)
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    existing = await _current_actions(db, resource_id, actor_id, group_id)
    for action_name in sorted(existing):
        await _delete_grant(
            db, resource_id, actor_id, group_id, action_name, by_actor
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
) -> List[str]:
    """Atomically swap a principal's action set on a resource to ``role``.

    Removes any currently-granted actions that are not in the new role, then
    adds any missing ones. Audits each change. Returns the new action list.
    """
    _check_principal(actor_id, group_id)
    resolved = set(_resolve_actions(datasette, resource_type, role, None))
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    await _ensure_actions(db, resolved)
    existing = await _current_actions(db, resource_id, actor_id, group_id)
    for action_name in sorted(existing - resolved):
        await _delete_grant(
            db, resource_id, actor_id, group_id, action_name, by_actor
        )
    for action_name in sorted(resolved - existing):
        await _insert_grant(
            db, resource_id, actor_id, group_id, action_name, by_actor
        )
    return sorted(resolved)


async def list_grants(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
) -> List[Grant]:
    """Return the grants on a resource as a list of dicts.

    Each dict is ``{"principal": "actor"|"group", "actor_id", "group_id",
    "group_name", "actions": [...]}`` with actions sorted. Group grants whose
    group is soft-deleted are omitted. The list is ordered by principal then id.
    """
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    rows = await db.execute(
        """
        SELECT
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
        if row["actor_id"] is not None:
            key = ("actor", row["actor_id"], None, None)
        else:
            key = ("group", None, row["group_id"], row["group_name"])
        grants.setdefault(key, set()).add(row["action_name"])
    out: List[Grant] = []
    for (_principal, actor_id, group_id, group_name), action_set in grants.items():
        out.append(
            {
                "principal": "actor" if actor_id is not None else "group",
                "actor_id": actor_id,
                "group_id": group_id,
                "group_name": group_name,
                "actions": sorted(action_set),
            }
        )
    out.sort(
        key=lambda g: (
            g["principal"],
            g["actor_id"] or "",
            g["group_id"] or 0,
        )
    )
    return out
