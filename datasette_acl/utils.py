from datasette.plugins import pm
from datasette.utils import await_me_maybe


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


async def get_acl_actor_ids(datasette):
    actor_ids = []
    for hook in pm.hook.datasette_acl_actor_ids(datasette=datasette):
        actor_ids.extend(await await_me_maybe(hook))
    return actor_ids


async def validate_actor_id(datasette, actor_id):
    actor_ids = await get_acl_actor_ids(datasette)
    if not actor_ids:
        # No validation has been configured
        return True
    else:
        return actor_id in actor_ids
