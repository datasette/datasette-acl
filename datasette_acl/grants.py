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

Principal invariant: a grant targets exactly one principal -- an actor, a
group, or a public audience -- matching the CHECK constraint on the ``acl``
table. The :class:`Principal` value object is the single place that resolves
and validates the combination; every helper takes one ``principal`` rather
than threading ``(principal_type, actor_id, group_id)`` around by hand.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    TypedDict,
    TYPE_CHECKING,
)

from datasette_acl.roles import actions_for_role, manage_only_actions, roles_for
from datasette_acl.utils import PUBLIC_PRINCIPAL_TYPES, actions_for_resource_type

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.database import Database


PrincipalType = Literal["actor", "group", "everyone", "authenticated", "anonymous"]


class LastManagerError(Exception):
    """A mutation would remove the last manage-capable grant on a resource.

    Revoking or downgrading the only principal that can manage sharing orphans
    the resource: nobody could re-open the share dialog (the read endpoint is
    manager-only) to fix it. :func:`revoke` / :func:`update_role` raise this
    instead of carrying out such a mutation, and the JSON API surfaces it as a
    409 Conflict. Deliberately NOT a ``ValueError`` so callers can distinguish a
    refused-but-valid request from malformed input.
    """


@dataclass(frozen=True)
class Principal:
    """A grant's target: an actor, a group, or a public audience.

    Build one via the classmethods rather than the raw constructor so the
    "exactly one principal" invariant (which mirrors the ``acl`` CHECK
    constraint) is enforced in a single place::

        Principal.actor("alice")
        Principal.group(7)
        Principal.everyone()        # / .authenticated() / .anonymous()
        Principal.public("everyone")

    :meth:`from_parts` resolves the looser ``(actor_id, group_id,
    principal_type)`` combination that arrives from a request body, validating
    it the same way. :meth:`where_sql` / :meth:`sql_params` produce the
    principal-matching SQL fragment shared by every read/write helper.
    """

    principal_type: PrincipalType
    actor_id: Optional[str] = None
    group_id: Optional[int] = None

    @classmethod
    def actor(cls, actor_id: str) -> "Principal":
        if actor_id is None:
            raise ValueError("actor principal requires an actor_id")
        return cls("actor", actor_id=actor_id)

    @classmethod
    def group(cls, group_id: int) -> "Principal":
        if group_id is None:
            raise ValueError("group principal requires a group_id")
        return cls("group", group_id=group_id)

    @classmethod
    def public(cls, principal_type: str) -> "Principal":
        if principal_type not in PUBLIC_PRINCIPAL_TYPES:
            raise ValueError(
                f"Unknown public principal_type {principal_type!r}; expected "
                f"one of {', '.join(sorted(PUBLIC_PRINCIPAL_TYPES))}"
            )
        return cls(principal_type)

    @classmethod
    def everyone(cls) -> "Principal":
        return cls("everyone")

    @classmethod
    def authenticated(cls) -> "Principal":
        return cls("authenticated")

    @classmethod
    def anonymous(cls) -> "Principal":
        return cls("anonymous")

    @classmethod
    def from_parts(
        cls,
        actor_id: Optional[str],
        group_id: Optional[int],
        principal_type: Optional[str] = None,
    ) -> "Principal":
        """Resolve a principal from a loose ``(actor_id, group_id, type)`` set.

        A principal is exactly one of: an actor (``actor_id``), a group
        (``group_id``), or a public audience (``principal_type`` in
        ``PUBLIC_PRINCIPAL_TYPES``, with neither id). ``principal_type`` may
        also redundantly name ``'actor'`` / ``'group'`` alongside the matching
        id. Raises ``ValueError`` for any other combination, mirroring the
        acl table's CHECK constraint.
        """
        if principal_type in PUBLIC_PRINCIPAL_TYPES:
            if actor_id is not None or group_id is not None:
                raise ValueError(
                    f"principal_type {principal_type!r} cannot be combined "
                    "with actor_id= or group_id="
                )
            return cls(principal_type)
        if (actor_id is None) == (group_id is None):
            raise ValueError(
                "Provide exactly one principal: actor_id=, group_id=, or a "
                f"public principal_type ({', '.join(PUBLIC_PRINCIPAL_TYPES)})"
            )
        if group_id is not None:
            if principal_type not in (None, "group"):
                raise ValueError(
                    f"principal_type {principal_type!r} cannot be used "
                    "with group_id="
                )
            return cls("group", group_id=group_id)
        if principal_type not in (None, "actor"):
            raise ValueError(
                f"principal_type {principal_type!r} cannot be used " "with actor_id="
            )
        return cls("actor", actor_id=actor_id)

    def where_sql(self, alias: Optional[str] = None) -> str:
        """SQL fragment matching this principal's acl rows.

        ``alias`` qualifies the column references (e.g. ``"acl"`` for a joined
        query); omit it for a single-table statement. Pair with
        :meth:`sql_params` for the bind values.
        """
        col = f"{alias}." if alias else ""
        if self.principal_type == "actor":
            return f"{col}principal_type = 'actor' AND {col}actor_id = :actor_id"
        if self.principal_type == "group":
            return f"{col}principal_type = 'group' AND {col}group_id = :group_id"
        # Public audience: the type alone identifies the principal.
        return f"{col}principal_type = :principal_type"

    def sql_params(self) -> Dict[str, object]:
        return {
            "principal_type": self.principal_type,
            "actor_id": self.actor_id,
            "group_id": self.group_id,
        }


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
    return (await db.execute(select_sql, [resource_type, parent, child])).single_value()


async def _ensure_actions(db: Database, actions: Iterable[str]) -> None:
    if actions:
        await db.execute_write_many(
            "INSERT OR IGNORE INTO acl_actions (name) VALUES (:name)",
            [{"name": name} for name in actions],
        )


async def _current_actions(
    db: Database,
    resource_id: int,
    principal: Principal,
) -> Set[str]:
    """Return the set of action names currently granted to a principal."""
    rows = await db.execute(
        f"""
        SELECT acl_actions.name AS name
        FROM acl
        JOIN acl_actions ON acl.action_id = acl_actions.id
        WHERE acl.resource_id = :resource_id AND {principal.where_sql("acl")}
        """,
        {"resource_id": resource_id, **principal.sql_params()},
    )
    return {row["name"] for row in rows.rows}


async def _insert_grant(
    db: Database,
    resource_id: int,
    principal: Principal,
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
            **principal.sql_params(),
            "resource_id": resource_id,
            "action_name": action_name,
        },
    )
    await _audit(db, "added", resource_id, principal, action_name, by_actor)


async def _delete_grant(
    db: Database,
    resource_id: int,
    principal: Principal,
    action_name: str,
    by_actor: Optional[str],
) -> None:
    await db.execute_write(
        f"""
        DELETE FROM acl
        WHERE {principal.where_sql()}
          AND resource_id = :resource_id
          AND action_id = (SELECT id FROM acl_actions WHERE name = :action_name)
        """,
        {
            **principal.sql_params(),
            "resource_id": resource_id,
            "action_name": action_name,
        },
    )
    await _audit(db, "removed", resource_id, principal, action_name, by_actor)


async def _audit(
    db: Database,
    operation: Literal["added", "removed"],
    resource_id: int,
    principal: Principal,
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
            **principal.sql_params(),
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
    principal: Principal,
    role: Optional[str] = None,
    actions: Optional[Iterable[str]] = None,
    by_actor: Optional[str] = None,
) -> List[str]:
    """Grant a principal access to a resource, by role or by raw actions.

    ``principal`` is a :class:`Principal` (``Principal.actor(...)`` /
    ``.group(...)`` / ``.everyone()`` / etc). Exactly one of ``role`` /
    ``actions`` must be supplied. Only actions not already granted are
    inserted (idempotent). Returns the list of action names now held by the
    principal.
    """
    resolved = _resolve_actions(datasette, resource_type, role, actions)
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    await _ensure_actions(db, resolved)
    existing = await _current_actions(db, resource_id, principal)
    for action_name in resolved:
        if action_name not in existing:
            await _insert_grant(db, resource_id, principal, action_name, by_actor)
    return sorted(existing | set(resolved))


def _principal_key(principal: Principal):
    """Identity key for a principal, distinguishing a like-named actor/group.

    An actor and a group that happen to share a name/id are distinct managers,
    so the key is keyed on ``(principal_type, id)``. Public audiences have no
    id and are keyed by type alone.
    """
    if principal.principal_type == "actor":
        return ("actor", principal.actor_id)
    if principal.principal_type == "group":
        return ("group", principal.group_id)
    return (principal.principal_type, None)


def _grant_key(grant: Grant):
    """Identity key for a :func:`list_grants` entry; see :func:`_principal_key`."""
    if grant["principal"] == "actor":
        return ("actor", grant["actor_id"])
    if grant["principal"] == "group":
        return ("group", grant["group_id"])
    return (grant["principal"], None)


async def _guard_last_manager(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str],
    principal: Principal,
    new_actions: Set[str],
) -> None:
    """Refuse a mutation that would leave the resource with no manager.

    ``new_actions`` is the action set the principal will hold *after* the
    mutation (empty for a revoke). A principal is a manager iff its actions
    intersect :func:`manage_only_actions` (the action(s) exclusive to a
    ``manage=True`` role) -- NOT the full manage bundle, which a Viewer/Editor
    would share. Raises :class:`LastManagerError` when the target is currently
    the only manager and the mutation drops its manager status. Inert when the
    resource type registers no manage role (``manage_set`` empty).
    """
    roles = roles_for(datasette, resource_type)
    manage_set = manage_only_actions(roles)
    if not manage_set:
        return
    grants = await list_grants(datasette, resource_type, parent, child)
    managers = {_grant_key(g) for g in grants if manage_set & set(g["actions"])}
    target_key = _principal_key(principal)
    # Only an orphaning concern if the target is the *current* sole manager and
    # the mutation strips its manager status (revoke, or a downgrade whose new
    # actions no longer intersect manage_set).
    if managers != {target_key}:
        return
    if manage_set & set(new_actions):
        return
    raise LastManagerError(
        "Cannot remove the last manager: this is the only grant that can "
        "manage sharing for this resource. Add another manager first."
    )


async def revoke(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
    *,
    principal: Principal,
    by_actor: Optional[str] = None,
) -> List[str]:
    """Remove all acl rows for a principal on a resource. Audits each removal.

    The principal is specified as in :func:`grant`. Returns the list of action
    names that were removed. Raises :class:`LastManagerError` (and writes
    nothing) when the principal is the resource's last manager.
    """
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    await _guard_last_manager(datasette, resource_type, parent, child, principal, set())
    existing = await _current_actions(db, resource_id, principal)
    for action_name in sorted(existing):
        await _delete_grant(db, resource_id, principal, action_name, by_actor)
    return sorted(existing)


async def update_role(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
    *,
    principal: Principal,
    role: str,
    by_actor: Optional[str] = None,
) -> List[str]:
    """Atomically swap a principal's action set on a resource to ``role``.

    The principal is specified as in :func:`grant`. Removes any currently-
    granted actions that are not in the new role, then adds any missing ones.
    Audits each change. Returns the new action list. Raises
    :class:`LastManagerError` (and writes nothing) when the swap would downgrade
    the resource's last manager out of its manager role.
    """
    resolved = set(_resolve_actions(datasette, resource_type, role, None))
    db = datasette.get_internal_database()
    resource_id = await _ensure_resource_id(db, resource_type, parent, child)
    await _guard_last_manager(
        datasette, resource_type, parent, child, principal, resolved
    )
    await _ensure_actions(db, resolved)
    existing = await _current_actions(db, resource_id, principal)
    for action_name in sorted(existing - resolved):
        await _delete_grant(db, resource_id, principal, action_name, by_actor)
    for action_name in sorted(resolved - existing):
        await _insert_grant(db, resource_id, principal, action_name, by_actor)
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
