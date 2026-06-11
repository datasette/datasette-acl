from __future__ import annotations

from datasette.plugins import pm
from datasette.utils import await_me_maybe
from typing import List, Optional, Tuple, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.permissions import Resource


async def can_edit_permissions(datasette, actor):
    return await datasette.allowed(actor=actor, action="datasette-acl")


async def can_manage(datasette, actor, resource_type, parent, child=None):
    """Whether ``actor`` may manage sharing for this resource.

    The authoritative per-resource manage check. An actor can manage if EITHER:

      * they are ``datasette.allowed`` one of the resource type's *manage-only*
        actions on this specific resource — i.e. they hold a ``manage=True``
        role grant (Manager/Owner), which flows through the same acl machinery
        and so composes with groups; OR
      * the resource type registers no ``manage`` role, in which case we fall
        back to the global ``datasette-acl`` permission so table-style resources
        (which only have raw actions, no roles) still work.

    The manage check authorizes against :func:`manage_only_actions` (the action
    exclusive to manage roles, e.g. ``playlist-manage``) rather than the full
    Manager action bundle — otherwise any Viewer/Editor, who also holds
    ``*-view``, would pass. The global ``datasette-acl`` admin always wins.

    Returns False (rather than raising) for unknown resource types.
    """
    # Imported lazily to avoid a module-load cycle (roles imports nothing from
    # utils, but keeping the import local mirrors the prior api.py home and
    # documents the dependency direction).
    from datasette_acl.roles import manage_only_actions, roles_for

    if await can_edit_permissions(datasette, actor):
        return True
    manage = manage_only_actions(roles_for(datasette, resource_type))
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


def resource_class_for(
    datasette: Datasette, resource_type: str
) -> Optional[Type[Resource]]:
    """Return the Resource subclass whose .name == resource_type, or None.

    Resource types are discovered from registered actions (datasette.actions),
    so any plugin that registers actions with a resource_class is manageable by
    acl without a dedicated hook.
    """
    for action in datasette.actions.values():
        rc = action.resource_class
        if rc is not None and rc.name == resource_type:
            return rc
    return None


def actions_for_resource_type(
    datasette: Datasette, resource_type: str
) -> List[str]:
    """Action names whose resource_class.name == resource_type, in registration order."""
    return [
        action.name
        for action in datasette.actions.values()
        if action.resource_class is not None
        and action.resource_class.name == resource_type
    ]


async def resource_exists(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
) -> bool:
    """Whether ``(parent, child)`` is a real resource of ``resource_type``.

    Existence is defined by the resource type's ``resources_sql`` classmethod --
    the same query core uses to enumerate resources. We run it with
    ``actor=None`` (the full universe, independent of who is asking) and test for
    membership, so editing permissions for a made-up id 404s instead of silently
    creating it (issue #43). ``IS`` is NULL-safe, so a parent-only resource
    (``child`` NULL) matches correctly.

    Returns False for unknown resource types.
    """
    rc = resource_class_for(datasette, resource_type)
    if rc is None:
        return False
    inner = await rc.resources_sql(datasette, actor=None)
    result = await datasette.get_internal_database().execute(
        f"SELECT 1 FROM ({inner}) WHERE parent IS :parent AND child IS :child LIMIT 1",
        {"parent": parent, "child": child},
    )
    return bool(result.rows)


def build_resource(
    datasette: Datasette,
    resource_type: str,
    parent: str,
    child: Optional[str] = None,
) -> Resource:
    """Build a core ``Resource`` instance for ``(resource_type, parent, child)``.

    The acl JSON API and consumer data-migrations receive resources as strings
    but ``datasette.allowed()`` needs a ``Resource`` instance. We discover the
    resource class from the registered actions (see ``resource_class_for``) and
    construct it.

    Constructor convention: ``Resource.__init__(parent, child)`` accepts both
    positionally. A 2-level resource type (``parent_class`` set, e.g. a table
    inside a database) is built as ``rc(parent, child)``; a parent-only type
    (``parent_class is None``) is built as ``rc(parent)``. Consumers whose
    constructors do not follow this positional convention should add a
    ``from_parent_child`` classmethod (none do today).

    Raises ``ValueError`` if ``resource_type`` is unknown.
    """
    rc = resource_class_for(datasette, resource_type)
    if rc is None:
        raise ValueError(f"Unknown resource type: {resource_type}")
    if rc.parent_class is not None:
        return rc(parent, child)
    return rc(parent)


def generate_changes_message(changes_made, noun):
    messages = []
    for action, changes in changes_made.items():
        for name, permission in changes:
            messages.append(f"{action}: {noun} '{name}' can {permission}")
    if not messages:
        return None
    message = ", ".join(messages)
    # Capitalize first letter
    return message[0].upper() + message[1:]


async def get_acl_valid_actors(datasette) -> List[Tuple[str, str]]:
    all_actors = []
    for hook in pm.hook.datasette_acl_valid_actors(datasette=datasette):
        actors = await await_me_maybe(hook)
        for actor in actors:
            if isinstance(actor, str):
                all_actors.append((actor, actor))
            else:
                all_actors.append((actor["id"], actor["display"]))
    return all_actors


async def validate_actor_id(datasette, actor_id):
    actors = await get_acl_valid_actors(datasette)
    if not actors:
        # No validation has been configured
        return True
    else:
        return actor_id in dict(actors)
