from pluggy import HookspecMarker

hookspec = HookspecMarker("datasette")


@hookspec
def datasette_acl_actor_ids(datasette):
    """
    List of actor IDs that can be autocompleted against when editing permissions
    """
