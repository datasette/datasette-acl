"""Friendly roles layer for datasette-acl.

acl stores per-action grants, but users think in roles (Viewer / Editor /
Manager). Plugins declare roles for their resource types via the
``datasette_acl_roles`` hook; they are collected at startup into a registry
keyed by ``resource_type``. Helpers resolve a granted action-set to its
best-matching role and back.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from datasette.plugins import pm
from datasette.utils import await_me_maybe


@dataclass
class AclRole:
    """A friendly role mapping a name to an action bundle for one resource type.

    Attributes:
        resource_type: the Resource.name this role applies to, e.g. "paper-doc".
        name: friendly role name, e.g. "Editor".
        actions: action names this role grants, e.g. ["paper-view", "paper-edit"].
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


async def build_roles_registry(datasette) -> Dict[str, List[AclRole]]:
    """Gather declared roles into ``{resource_type: [AclRole, ...]}``.

    Calls the ``datasette_acl_roles`` hook across all plugins, awaiting any
    callables/awaitables they return, and groups the resulting AclRole objects
    by ``resource_type``. Within each resource type the roles are sorted by
    ``rank`` ascending (so the highest-rank role is last) for stable ordering.
    """
    registry: Dict[str, List[AclRole]] = {}
    for hook_result in pm.hook.datasette_acl_roles(datasette=datasette):
        roles = await await_me_maybe(hook_result)
        if not roles:
            continue
        for role in roles:
            registry.setdefault(role.resource_type, []).append(role)
    for resource_type in registry:
        registry[resource_type].sort(key=lambda r: r.rank)
    return registry


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
