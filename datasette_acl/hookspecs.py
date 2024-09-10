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
