from pluggy import HookspecMarker

hookspec = HookspecMarker("datasette")


@hookspec
def datasette_acl_valid_actors(datasette):
    """
    List of actors that can be autocompleted against when editing permissions

    This hook can return:
    - A list of string actor IDs
    - A list of dictionaries with "id" and "display" keys
    - A function or awaitable function that returns one of the above
    """


@hookspec
def datasette_acl_roles(datasette):
    """
    Return list[AclRole] mapping friendly role names to action bundles per
    resource type.

    Each AclRole declares a resource_type, a friendly name (e.g. "Editor"), and
    the list of action names that role grants. A `rank` orders roles (highest
    wins for display) and `manage=True` marks the role(s) whose actions
    authorize re-sharing the resource.

    May return a list directly, or a function / awaitable returning one.
    """
