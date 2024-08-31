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
