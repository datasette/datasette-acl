from __future__ import annotations

from datasette.plugins import pm
from datasette.utils import await_me_maybe
from typing import List, Optional, Tuple, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.permissions import Resource


async def can_edit_permissions(datasette, actor):
    return await datasette.allowed(actor=actor, action="datasette-acl")


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
