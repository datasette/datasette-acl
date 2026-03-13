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
def datasette_acl_resource_types(datasette):
    """
    Return adapters for serializing resources to resource-group entries.
    """


@hookspec
def datasette_acl_role_bundles(datasette):
    """
    Return role bundle definitions with "name", "actions", and optional metadata.
    """


@hookspec
def datasette_acl_default_resource_groups(datasette):
    """
    Return default resource groups that should exist at startup.
    """


@hookspec
def datasette_acl_grantable_actions(datasette):
    """
    Return action names that should be exposed in ACL management interfaces.
    """
