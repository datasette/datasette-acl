from datasette import Response, Forbidden, NotFound
from datasette_acl.utils import can_edit_permissions
import json

GROUPS_SQL = """
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
{extra_where}
group by
    acl_groups.id, acl_groups.name
order by
    acl_groups.name;
"""


def get_dynamic_groups(datasette):
    config = datasette.plugin_config("datasette-acl")
    return config.get("dynamic-groups") or {}


async def manage_groups(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    internal_db = datasette.get_internal_database()
    groups = [
        dict(r, actor_ids=json.loads(r["actor_ids"]))
        for r in await internal_db.execute(GROUPS_SQL.format(extra_where=""))
    ]
    dynamic_groups = get_dynamic_groups(datasette)
    return Response.html(
        await datasette.render_template(
            "manage_acl_groups.html",
            {
                "groups": groups,
                "dynamic_groups": dynamic_groups,
            },
            request=request,
        )
    )


async def manage_group(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    name = request.url_vars["name"]
    internal_db = datasette.get_internal_database()
    group = (
        await internal_db.execute(
            GROUPS_SQL.format(extra_where=" where acl_groups.name = :name"),
            {
                "name": name,
            },
        )
    ).first()
    if not group:
        raise NotFound("Group does not exist")
    dynamic_groups = get_dynamic_groups(datasette)
    dynamic_config = dynamic_groups.get(name)
    actor_ids = json.loads(group["actor_ids"])
    if request.method == "POST" and not dynamic_config:
        post_vars = await request.post_vars()
        to_add = post_vars.get("add")
        to_remove = post_vars.get("remove")
        audit_operation = None
        audit_actor_id = None
        fragment = ""
        if to_remove:
            if to_remove not in actor_ids:
                datasette.add_message(
                    request, "That user is not in the group", datasette.ERROR
                )
            else:
                # Remove user
                await internal_db.execute_write(
                    """
                    delete from acl_actor_groups
                    where actor_id = :actor_id
                    and group_id = :group_id
                """,
                    {"actor_id": to_remove, "group_id": group["id"]},
                )
                datasette.add_message(request, f"Removed {to_remove}")
                audit_operation = "removed"
                audit_actor_id = to_remove
        if to_add:
            if to_add in actor_ids:
                datasette.add_message(
                    request, "That user is already in the group", datasette.ERROR
                )
            else:
                # Add user
                await internal_db.execute_write(
                    """
                    insert into acl_actor_groups (actor_id, group_id)
                    values (:actor_id, :group_id)
                """,
                    {"actor_id": to_add, "group_id": group["id"]},
                )
                datasette.add_message(request, f"Added {to_add}")
                audit_operation = "added"
                audit_actor_id = to_add
                fragment = "#focus-add"
        if audit_operation:
            # Update audit log
            await internal_db.execute_write(
                """
                insert into acl_groups_audit (
                    operation_by, operation, group_id, actor_id
                ) values (
                    :operation_by, :operation, :group_id, :actor_id
                )
            """,
                {
                    "operation_by": request.actor["id"],
                    "operation": audit_operation,
                    "group_id": group["id"],
                    "actor_id": audit_actor_id,
                },
            )
        return Response.redirect(request.path + fragment)
    return Response.html(
        await datasette.render_template(
            "manage_acl_group.html",
            {
                "name": name,
                "size": group["size"],
                "members": actor_ids,
                "dynamic_config": dynamic_config,
                "audit_log": [
                    dict(r)
                    for r in await internal_db.execute(
                        """
                        select
                            timestamp, operation_by, operation, actor_id
                        from acl_groups_audit
                        where group_id = ?
                        order by id desc
                    """,
                        [group["id"]],
                    )
                ],
            },
            request=request,
        )
    )
