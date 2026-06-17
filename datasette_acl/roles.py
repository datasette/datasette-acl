"""Friendly roles layer for datasette-acl.

acl stores per-action grants, but users think in roles (Viewer / Editor /
Manager). Plugins declare roles for their resource types via the
``datasette_acl_roles`` hook; :func:`roles_for` gathers them on demand into a
registry keyed by ``resource_type``. Helpers resolve a granted action-set to
its best-matching role and back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, TYPE_CHECKING

from datasette.plugins import pm

if TYPE_CHECKING:
    from datasette.app import Datasette


@dataclass
class AclRole:
    """A friendly role mapping a name to an action bundle for one resource type.

    Attributes:
        resource_type: the Resource.name this role applies to, e.g. "playlist".
        name: friendly role name, e.g. "Editor".
        actions: action names this role grants, e.g. ["playlist-view", "playlist-edit"].
        rank: ordering / "highest role wins" weight; larger means higher.
        manage: True => holders of this role may change sharing (Manager/Owner).
        description: optional human-readable description.
    """

    resource_type: str
    name: str
    actions: List[str] = field(default_factory=list)
    rank: int = 0
    manage: bool = False
    description: str = ""


def standard_roles(
    resource_type: str,
    *,
    view,
    edit,
    manage,
    descriptions: Optional[Dict[str, str]] = None,
) -> List[AclRole]:
    """Build the canonical Viewer / Editor / Manager role triple.

    Most plugins want the same three cumulative roles: Viewer (can view),
    Editor (view + edit) and Manager (view + edit + manage sharing). This
    factory saves each plugin from re-declaring them by hand:

        from datasette_acl.roles import standard_roles

        @hookimpl
        def datasette_acl_roles(datasette):
            return standard_roles(
                "playlist",
                view="playlist-view",
                edit="playlist-edit",
                manage="playlist-manage",
            )

    Each of ``view``/``edit``/``manage`` accepts a single action name or a
    list of them. Bundles are cumulative (Editor includes Viewer's actions,
    Manager includes Editor's) and the Manager role carries ``manage=True``,
    so the action(s) exclusive to it authorize re-sharing (see
    :func:`manage_only_actions`).

    ``descriptions`` optionally overrides the default role descriptions,
    keyed by role name::

        standard_roles(..., descriptions={"Manager": "Full control"})

    For different role names or extra roles, adjust the returned list before
    returning it from the hook.
    """

    def as_list(value):
        return [value] if isinstance(value, str) else list(value)

    descriptions = descriptions or {}
    view_actions = as_list(view)
    edit_actions = view_actions + [
        a for a in as_list(edit) if a not in view_actions
    ]
    full_actions = edit_actions + [
        a for a in as_list(manage) if a not in edit_actions
    ]
    return [
        AclRole(
            resource_type,
            "Viewer",
            view_actions,
            rank=1,
            description=descriptions.get("Viewer", "Can view"),
        ),
        AclRole(
            resource_type,
            "Editor",
            edit_actions,
            rank=2,
            description=descriptions.get("Editor", "Can view and edit"),
        ),
        AclRole(
            resource_type,
            "Manager",
            full_actions,
            rank=3,
            manage=True,
            description=descriptions.get(
                "Manager", "Can view, edit and manage sharing"
            ),
        ),
    ]


def build_roles_registry(datasette) -> Dict[str, List[AclRole]]:
    """Gather declared roles into ``{resource_type: [AclRole, ...]}``.

    Calls the ``datasette_acl_roles`` hook across all plugins and groups the
    resulting AclRole objects by ``resource_type``. Within each resource type
    the roles are sorted by ``rank`` ascending (so the highest-rank role is
    last) for stable ordering.
    """
    registry: Dict[str, List[AclRole]] = {}
    for roles in pm.hook.datasette_acl_roles(datasette=datasette):
        if not roles:
            continue
        for role in roles:
            registry.setdefault(role.resource_type, []).append(role)
    for resource_type in registry:
        registry[resource_type].sort(key=lambda r: r.rank)
    return registry


def roles_for(datasette: Datasette, resource_type: str) -> List[AclRole]:
    """Return the registered roles for ``resource_type`` (``[]`` if none).

    Gathers roles from the ``datasette_acl_roles`` hook on demand via
    :func:`build_roles_registry`. Shared by the grants layer and the JSON API
    as the single way to ask "what roles exist for this resource type?".
    """
    return build_roles_registry(datasette).get(resource_type, [])


def role_for_actions(
    roles: List[AclRole], granted: Set[str]
) -> Optional[AclRole]:
    """Pick the highest-rank role whose actions are a subset of ``granted``.

    Returns the matching :class:`AclRole`, or ``None`` if no role's action set
    fits within the granted actions (the caller can then show raw actions).
    """
    granted = set(granted)
    best: Optional[AclRole] = None
    for role in roles:
        if set(role.actions) <= granted:
            if best is None or role.rank > best.rank:
                best = role
    return best


def actions_for_role(roles: List[AclRole], name: str) -> Optional[List[str]]:
    """Return the action list for the role named ``name``, or ``None``."""
    for role in roles:
        if role.name == name:
            return list(role.actions)
    return None


def manage_actions(roles: List[AclRole]) -> Set[str]:
    """Union of actions across all ``manage=True`` roles for a resource type.

    This is the full action bundle a manage role carries (e.g. Manager =
    view+edit+manage). Use :func:`manage_only_actions` for the authorization
    check — see its docstring for why the union is the wrong gate.
    """
    actions: Set[str] = set()
    for role in roles:
        if role.manage:
            actions.update(role.actions)
    return actions


def manage_only_actions(roles: List[AclRole]) -> Set[str]:
    """Actions that authorize re-sharing: those exclusive to ``manage`` roles.

    A manage role typically *bundles* the lower roles' actions (Manager =
    Viewer + Editor + ``manage``). Authorizing against the full bundle
    (:func:`manage_actions`) would wrongly let any Viewer/Editor manage sharing,
    since they too hold ``doc-view``. The action(s) that actually distinguish a
    manager are those appearing only in ``manage=True`` roles and in no
    non-manage role — typically a single ``*-manage`` action. Holding any one of
    these is what grants re-share ability (task 04 §D).

    Returns the empty set if no role is marked ``manage`` (callers then fall back
    to the global ``datasette-acl`` permission).
    """
    manage_union: Set[str] = set()
    non_manage_union: Set[str] = set()
    for role in roles:
        if role.manage:
            manage_union.update(role.actions)
        else:
            non_manage_union.update(role.actions)
    return manage_union - non_manage_union
