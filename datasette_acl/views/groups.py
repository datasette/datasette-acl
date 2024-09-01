from datasette import Response, Forbidden, NotFound
from datasette_acl.utils import can_edit_permissions
import json
import re

GROUPS_SQL = """
select
    acl_groups.id,
    acl_groups.name,
    acl_groups.deleted,
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


_group_name_re = re.compile(r"^[a-zA-Z0-9_-]+$")


def is_valid_group_name(new_group):
    return bool(_group_name_re.match(new_group))


async def manage_groups(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    internal_db = datasette.get_internal_database()
    groups = [
        dict(r, actor_ids=json.loads(r["actor_ids"]))
        for r in await internal_db.execute(
            GROUPS_SQL.format(extra_where=" where deleted is null")
        )
    ]
    if request.method == "POST":
        post_vars = await request.post_vars()
        new_group = (post_vars.get("new_group") or "").strip()
        if new_group:
            # Is it valid?
            if (
                await internal_db.execute(
                    "select 1 from acl_groups where name = :name and deleted is null",
                    {"name": new_group},
                )
            ).first():
                datasette.add_message(
                    request, "This group already exists", datasette.ERROR
                )
                return Response.redirect(
                    datasette.urls.path("/-/acl/groups/" + new_group)
                )
            elif not is_valid_group_name(new_group):
                datasette.add_message(
                    request,
                    "Group names must use characters a-zA-Z0-0_-",
                    datasette.ERROR,
                )
                return Response.redirect(datasette.urls.path("/-/acl/groups"))
            else:
                # Create group if it does not exist
                await internal_db.execute_write(
                    "insert or ignore into acl_groups (name) values (:name)",
                    {"name": new_group},
                )
                # Ensure it is not marked as deleted
                await internal_db.execute_write(
                    "update acl_groups set deleted = null where name = :name",
                    {"name": new_group},
                )
                # Audit log record
                await internal_db.execute_write(
                    """
                    insert into acl_groups_audit (
                        operation_by, operation, group_id
                    ) values (
                        :operation_by,
                        'created',
                        (select id from acl_groups where name = :group_name)
                    )
                """,
                    {"operation_by": request.actor["id"], "group_name": new_group},
                )
                datasette.add_message(request, f"Group created: {new_group}")
                return Response.redirect(
                    datasette.urls.path("/-/acl/groups/" + new_group)
                )

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
    group_id = group["id"]
    dynamic_groups = get_dynamic_groups(datasette)
    dynamic_config = dynamic_groups.get(name)
    actor_ids = json.loads(group["actor_ids"])

    async def audit_log(*, operation, actor_id=None):
        await internal_db.execute_write(
            f"""
            insert into acl_groups_audit (
                operation_by, operation, group_id, actor_id
            ) values (
                :operation_by,
                :operation,
                :group_id,
                {':actor_id' if actor_id else 'null'}
            )
        """,
            {
                "operation_by": request.actor["id"],
                "operation": operation,
                "group_id": group_id,
                "actor_id": actor_id,
            },
        )

    async def remove_member(actor_id):
        await internal_db.execute_write(
            """
            delete from acl_actor_groups
            where actor_id = :actor_id
            and group_id = :group_id
        """,
            {"actor_id": actor_id, "group_id": group_id},
        )
        await audit_log(operation="removed", actor_id=actor_id)

    if request.method == "POST" and not dynamic_config:
        post_vars = await request.post_vars()
        to_add = post_vars.get("add")
        to_remove = post_vars.get("remove")

        should_delete = post_vars.get("delete_group")
        if should_delete:
            # First remove all the members
            for actor_id in actor_ids:
                await remove_member(actor_id)
            # Now mark the group as deleted and record
            await internal_db.execute_write(
                "update acl_groups set deleted = 1 where id = :group_id",
                {"group_id": group_id},
            )
            await audit_log(operation="deleted")
            datasette.add_message(request, f"Group deleted: {name}")
            return Response.redirect(datasette.urls.path("/-/acl/groups"))

        fragment = ""
        if to_remove:
            if to_remove not in actor_ids:
                datasette.add_message(
                    request, "That user is not in the group", datasette.ERROR
                )
            else:
                await remove_member(to_remove)
                datasette.add_message(request, f"Removed {to_remove}")
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
                    {"actor_id": to_add, "group_id": group_id},
                )
                datasette.add_message(request, f"Added {to_add}")
                await audit_log(operation="added", actor_id=to_add)
                fragment = "#focus-add"
        return Response.redirect(request.path + fragment)

    return Response.html(
        await datasette.render_template(
            "manage_acl_group.html",
            {
                "name": name,
                "size": group["size"],
                "is_deleted": group["deleted"],
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
                        [group_id],
                    )
                ],
            },
            request=request,
        )
    )
