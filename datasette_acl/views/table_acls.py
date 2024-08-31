from datasette import Response, Forbidden
from datasette_acl.utils import can_edit_permissions, generate_changes_message


async def manage_table_acls(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    table = request.url_vars["table"]
    database = request.url_vars["database"]
    internal_db = datasette.get_internal_database()
    groups = [
        g["name"]
        for g in await datasette.get_internal_database().execute(
            "select name from acl_groups"
        )
    ]

    # Ensure we have a resource_id for this table
    await internal_db.execute_write(
        "INSERT OR IGNORE INTO acl_resources (database, resource) VALUES (?, ?);",
        [database, table],
    )
    resource_id = (
        await internal_db.execute(
            "SELECT id FROM acl_resources WHERE database = ? AND resource = ?",
            [database, table],
        )
    ).single_value()

    current_group_permissions = {}
    current_user_permissions = {}
    acl_rows = await internal_db.execute(
        """
        select
          acl_groups.name as group_name,
          acl.actor_id,
          acl_actions.name as action_name
        from acl
        left join acl_groups on acl.group_id = acl_groups.id
        join acl_actions on acl.action_id = acl_actions.id
        where acl.resource_id = ?
        """,
        [resource_id],
    )
    for row in acl_rows.rows:
        group_name = row["group_name"]
        actor_id = row["actor_id"]
        action_name = row["action_name"]
        if group_name:
            current_group_permissions.setdefault(group_name, {})[action_name] = True
            current_group_permissions[group_name][action_name] = True
        else:
            assert actor_id
            current_user_permissions.setdefault(actor_id, {})[action_name] = True

    if request.method == "POST":
        group_changes_made = {"added": [], "removed": []}
        post_vars = await request.post_vars()
        for group_name in groups:
            for action_name in [
                "insert-row",
                "delete-row",
                "update-row",
                "alter-table",
                "drop-table",
            ]:
                new_value = bool(
                    post_vars.get(f"group_permissions_{group_name}_{action_name}")
                )
                current_value = bool(
                    current_group_permissions.get(group_name, {}).get(action_name)
                )
                if new_value != current_value:
                    if new_value:
                        # They added it, add the record
                        await internal_db.execute_write(
                            """
                            INSERT INTO acl (actor_id, group_id, resource_id, action_id)
                            VALUES (
                                null,
                                (SELECT id FROM acl_groups WHERE name = :group_name),
                                :resource_id,
                                (SELECT id FROM acl_actions WHERE name = :action_name)
                            )
                            """,
                            {
                                "group_name": group_name,
                                "action_name": action_name,
                                "resource_id": resource_id,
                            },
                        )
                        operation = "added"
                        group_changes_made["added"].append((group_name, action_name))
                    else:
                        # They removed it
                        await internal_db.execute_write(
                            """
                            delete from acl where
                                actor_id is null and 
                                group_id = (SELECT id FROM acl_groups WHERE name = :group_name)
                                and resource_id = :resource_id
                                and action_id = (SELECT id FROM acl_actions WHERE name = :action_name)
                            """,
                            {
                                "group_name": group_name,
                                "action_name": action_name,
                                "resource_id": resource_id,
                            },
                        )
                        operation = "removed"
                        group_changes_made["removed"].append((group_name, action_name))
                    await internal_db.execute_write(
                        """
                        insert into acl_audit (
                            operation,
                            actor_id,
                            group_id,
                            resource_id,
                            action_id,
                            operation_by
                        ) values (
                            :operation,
                            null,
                            (SELECT id FROM acl_groups WHERE name = :group_name),
                            :resource_id,
                            (SELECT id FROM acl_actions WHERE name = :action_name),
                            :operation_by
                        )
                        """,
                        {
                            "operation": operation,
                            "group_name": group_name,
                            "resource_id": resource_id,
                            "action_name": action_name,
                            "operation_by": request.actor["id"],
                        },
                    )
        user_changes_made = {"added": [], "removed": []}
        for actor_id in list(current_user_permissions) + [None]:
            if actor_id is None:
                # This is the special case for new_user_{{ action }}
                actor_id = (post_vars.get("new_actor_id") or "").strip()
                if not actor_id:
                    continue
                post_key_prefix = "new_user"
            else:
                post_key_prefix = f"user_permissions_{actor_id}"

            for action_name in [
                "insert-row",
                "delete-row",
                "update-row",
                "alter-table",
                "drop-table",
            ]:
                new_value = bool(post_vars.get(f"{post_key_prefix}_{action_name}"))
                current_value = bool(
                    current_user_permissions.get(actor_id, {}).get(action_name)
                )
                if new_value != current_value:
                    if new_value:
                        # They added the permission
                        await internal_db.execute_write(
                            """
                            insert into acl (actor_id, group_id, resource_id, action_id)
                            values (
                                :actor_id,
                                null,
                                :resource_id,
                                (select id from acl_actions where name = :action_name)
                            )
                            """,
                            {
                                "actor_id": actor_id,
                                "action_name": action_name,
                                "resource_id": resource_id,
                            },
                        )
                        operation = "added"
                        user_changes_made["added"].append((actor_id, action_name))
                    else:
                        # They removed the permission
                        await internal_db.execute_write(
                            """
                            delete from acl where
                                actor_id = :actor_id
                                and group_id is null
                                and resource_id = :resource_id
                                and action_id = (select id from acl_actions where name = :action_name)
                            """,
                            {
                                "actor_id": actor_id,
                                "action_name": action_name,
                                "resource_id": resource_id,
                            },
                        )
                        operation = "removed"
                        user_changes_made["removed"].append((actor_id, action_name))
                    await internal_db.execute_write(
                        """
                        insert into acl_audit (
                            operation,
                            actor_id,
                            group_id,
                            resource_id,
                            action_id,
                            operation_by
                        ) values (
                            :operation,
                            :actor_id,
                            null,
                            :resource_id,
                            (SELECT id FROM acl_actions WHERE name = :action_name),
                            :operation_by
                        )
                        """,
                        {
                            "operation": operation,
                            "actor_id": actor_id,
                            "resource_id": resource_id,
                            "action_name": action_name,
                            "operation_by": request.actor["id"],
                        },
                    )

        if group_changes_made or user_changes_made:
            group_message = generate_changes_message(group_changes_made, "group")
            if group_message:
                datasette.add_message(request, group_message)
            user_message = generate_changes_message(user_changes_made, "user")
            if user_message:
                datasette.add_message(request, user_message)

        return Response.redirect(request.path)

    audit_log = await internal_db.execute(
        """
        select
            acl_audit.timestamp,
            acl_audit.operation_by,
            acl_audit.operation,
            acl_audit.actor_id,
            acl_groups.name as group_name,
            acl_actions.name as action_name
        from acl_audit
        left join acl_groups on acl_audit.group_id = acl_groups.id
        join acl_actions on acl_audit.action_id = acl_actions.id
        where acl_audit.resource_id = ?
        order by acl_audit.timestamp desc
        limit 50
        """,
        [resource_id],
    )

    # group_sizes dictionary for displaying their sizes
    group_sizes = {
        row["name"]: row["size"]
        for row in await internal_db.execute(
            """
            select
                acl_groups.name as name,
                count(acl_actor_groups.actor_id) as size
            from
                acl_groups
            left join
                acl_actor_groups on acl_groups.id = acl_actor_groups.group_id
            group by
                acl_groups.id, acl_groups.name
            """
        )
    }

    return Response.html(
        await datasette.render_template(
            "manage_table_acls.html",
            {
                "database_name": request.url_vars["database"],
                "table_name": request.url_vars["table"],
                "actions": [
                    "insert-row",
                    "delete-row",
                    "update-row",
                    "alter-table",
                    "drop-table",
                ],
                "groups": groups,
                "group_sizes": group_sizes,
                "group_permissions": current_group_permissions,
                "user_permissions": current_user_permissions,
                "audit_log": audit_log.rows,
            },
            request=request,
        )
    )
