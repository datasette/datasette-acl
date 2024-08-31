from datasette import Response, Forbidden
from datasette_acl.utils import can_edit_permissions, generate_changes_message
import json


async def manage_groups(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    internal_db = datasette.get_internal_database()
    groups = [
        dict(r, actor_ids=json.loads(r["actor_ids"]))
        for r in await internal_db.execute(
            """
    select
        acl_groups.id,
        acl_groups.name,
        count(acl_actor_groups.actor_id) as size,
        json_group_array(
            acl_actor_groups.actor_id
        ) filter (
            where
            acl_actor_groups.actor_id is not null
        ) as actor_ids
    from
        acl_groups
    left join
        acl_actor_groups on acl_groups.id = acl_actor_groups.group_id
    group by
        acl_groups.id, acl_groups.name
    order by
        acl_groups.name;
    """
        )
    ]
    return Response.html(
        await datasette.render_template(
            "manage_acl_groups.html",
            {
                "groups": groups,
            },
            request=request,
        )
    )
