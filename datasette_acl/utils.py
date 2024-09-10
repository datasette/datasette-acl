from datasette.plugins import pm
from datasette.utils import await_me_maybe
from typing import List, Tuple


async def can_edit_permissions(datasette, actor):
    return await datasette.permission_allowed(actor, "datasette-acl")


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
