from datasette import Response, Forbidden
from datasette_acl.grants import _ensure_resource_id
from datasette_acl.utils import (
    actions_for_resource_type,
    can_manage,
    generate_changes_message,
    get_acl_valid_actors,
    resource_class_for,
    validate_actor_id,
)
from datasette.utils import MultiParams
from urllib.parse import parse_qs


async def manage_resource_acls(request, datasette):
    resource_type = request.url_vars["resource_type"]
    parent = request.url_vars["parent"]
    child = request.url_vars.get("child")

    # The resource type must correspond to a known, action-bearing resource
    # class, otherwise there is nothing to manage.
    if resource_class_for(datasette, resource_type) is None:
        raise Forbidden(f"Unknown resource type: {resource_type}")

    # Per-resource authorization: the global datasette-acl admin OR an actor who
    # holds a manage=True role (Manager/Owner) on this specific resource —
    # directly or via a group — so an object's owner can control its sharing
    # without instance-wide permission. Mirrors the JSON API's can_manage gate.
    if not await can_manage(datasette, request.actor, resource_type, parent, child):
        raise Forbidden("You do not have permission to edit permissions")

    actions = actions_for_resource_type(datasette, resource_type)

    internal_db = datasette.get_internal_database()
    groups = [
        g["name"]
        for g in await internal_db.execute(
            "select name from acl_groups where deleted is null"
        )
    ]

    # Ensure we have a resource_id for this resource. Use the shared helper
    # rather than a bare INSERT OR IGNORE: SQLite treats NULL children as
    # distinct in the UNIQUE(resource_type, parent, child) constraint, so a
    # naive insert would duplicate the row for a parent-only resource that the
    # JSON API (via grants._ensure_resource_id) already created.
    resource_id = await _ensure_resource_id(
        internal_db, resource_type, parent, child
    )

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
        where acl.resource_id = ? and acl_groups.deleted is null
        """,
        [resource_id],
    )
    for row in acl_rows.rows:
        group_name = row["group_name"]
        actor_id = row["actor_id"]
        action_name = row["action_name"]
        if group_name:
            current_group_permissions.setdefault(group_name, {})[action_name] = True
        else:
            assert actor_id
            current_user_permissions.setdefault(actor_id, {})[action_name] = True

    if request.method == "POST":
        group_changes_made = {"added": [], "removed": []}
        body = await request.post_body()
        post_vars = MultiParams(
            parse_qs(qs=body.decode("utf-8"), keep_blank_values=True)
        )
        for group_name in groups:
            selected_group_actions = post_vars.getlist(
                f"group_permissions_{group_name}"
            )
            for action_name in actions:
                new_value = action_name in selected_group_actions
                current_value = bool(
                    current_group_permissions.get(group_name, {}).get(action_name)
                )
                if new_value != current_value:
                    if new_value:
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
                actor_id = (post_vars.get("new_actor_id") or "").strip()
                if not actor_id:
                    continue
                if not await validate_actor_id(datasette, actor_id):
                    datasette.add_message(
                        request, "That user ID is not valid", datasette.ERROR
                    )
                    return Response.redirect(request.path)
                user_actions_key = "new_user_actions"
            else:
                user_actions_key = f"user_permissions_{actor_id}"

            selected_user_actions = post_vars.getlist(user_actions_key)

            for action_name in actions:
                new_value = action_name in selected_user_actions
                current_value = bool(
                    current_user_permissions.get(actor_id, {}).get(action_name)
                )
                if new_value != current_value:
                    if new_value:
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
            where
                acl_groups.deleted is null
            group by
                acl_groups.id, acl_groups.name
            """
        )
    }

    return Response.html(
        await datasette.render_template(
            "manage_resource_acls.html",
            {
                "resource_type": resource_type,
                "parent": parent,
                "child": child,
                "actions": actions,
                "groups": groups,
                "group_sizes": group_sizes,
                "group_permissions": current_group_permissions,
                "user_permissions": current_user_permissions,
                "audit_log": audit_log.rows,
                "valid_actors": await get_acl_valid_actors(datasette),
            },
            request=request,
        )
    )
