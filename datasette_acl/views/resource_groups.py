from datasette import Forbidden, Response
from datasette.utils import MultiParams
from datasette_acl.resource_groups import (
    add_resource_group_grant,
    add_resource_group_item,
    create_resource_group,
    ensure_resource_group,
    get_resource_group,
    get_resource_group_detail,
    list_resource_groups,
    record_grant_audit,
    record_resource_group_audit,
    validate_resource,
)
from datasette_acl.utils import (
    can_edit_permissions,
    get_acl_valid_actors,
    validate_actor_id,
)
from urllib.parse import parse_qs


async def _post_vars(request):
    body = await request.post_body()
    return MultiParams(parse_qs(qs=body.decode("utf-8"), keep_blank_values=True))


async def _resource_group_id(db, slug):
    row = (
        await db.execute(
            "select id from acl_resource_groups where slug = :slug and deleted = 0",
            {"slug": slug},
        )
    ).first()
    return row["id"] if row else None


async def manage_resource_groups(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    db = datasette.get_internal_database()
    if request.method == "POST":
        post_vars = await _post_vars(request)
        slug = (post_vars.get("slug") or "").strip()
        name = (post_vars.get("name") or "").strip()
        if not slug or not name:
            datasette.add_message(
                request, "Slug and name are required", datasette.ERROR
            )
            return Response.redirect(request.path)
        resource_group = await create_resource_group(
            db=db,
            slug=slug,
            name=name,
            description=(post_vars.get("description") or "").strip() or None,
            created_by=request.actor["id"],
        )
        if resource_group is None:
            datasette.add_message(
                request,
                "A resource group with that slug already exists",
                datasette.ERROR,
            )
            return Response.redirect(
                datasette.urls.path(f"/-/acl/resource-groups/{slug}")
            )
        await record_resource_group_audit(
            db,
            operation="created",
            resource_group_id=await _resource_group_id(db, slug),
            operation_by=request.actor["id"],
        )
        datasette.add_message(request, f"Created resource group {slug}")
        return Response.redirect(datasette.urls.path(f"/-/acl/resource-groups/{slug}"))
    return Response.html(
        await datasette.render_template(
            "manage_resource_groups.html",
            {
                "resource_groups": await list_resource_groups(
                    db, request.args.get("q")
                ),
                "search": request.args.get("q") or "",
            },
            request=request,
        )
    )


async def manage_resource_group(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    db = datasette.get_internal_database()
    slug = request.url_vars["slug"]
    detail = await get_resource_group_detail(db, slug)
    if detail is None:
        return Response.html("Not found", status=404)
    if request.method == "POST":
        post_vars = await _post_vars(request)
        if post_vars.get("delete_resource_group"):
            await delete_resource_group_json(request, datasette)
            datasette.add_message(request, f"Deleted resource group {slug}")
            return Response.redirect(datasette.urls.path("/-/acl/resource-groups"))
        if post_vars.get("delete_resource_id"):
            request.url_vars["id"] = post_vars["delete_resource_id"]
            await delete_resource_group_item_json(request, datasette)
            datasette.add_message(request, "Removed resource")
            return Response.redirect(request.path)
        if post_vars.get("delete_grant_id"):
            request.url_vars["id"] = post_vars["delete_grant_id"]
            await delete_resource_group_grant_json(request, datasette)
            datasette.add_message(request, "Removed grant")
            return Response.redirect(request.path)
        if post_vars.get("resource_type") and post_vars.get("resource_key"):
            validation_error = await validate_resource(
                datasette,
                (post_vars.get("resource_type") or "").strip(),
                (post_vars.get("resource_key") or "").strip(),
            )
            if validation_error:
                datasette.add_message(request, validation_error, datasette.ERROR)
                return Response.redirect(request.path)
            added = await add_resource_group_item(
                db,
                slug=slug,
                resource_type=(post_vars.get("resource_type") or "").strip(),
                resource_key=(post_vars.get("resource_key") or "").strip(),
                note=(post_vars.get("note") or "").strip() or None,
                added_by=request.actor["id"],
            )
            if added is None:
                datasette.add_message(
                    request,
                    "That resource is already in this resource group",
                    datasette.ERROR,
                )
                return Response.redirect(request.path)
            await record_resource_group_audit(
                db,
                operation="resource-added",
                resource_group_id=await _resource_group_id(db, slug),
                operation_by=request.actor["id"],
                resource_type=added["resource_type"],
                resource_key=added["resource_key"],
            )
            datasette.add_message(request, "Added resource")
            return Response.redirect(request.path)
        if post_vars.get("subject_type") and post_vars.get("subject"):
            subject_type = (post_vars.get("subject_type") or "").strip()
            subject = (post_vars.get("subject") or "").strip()
            grant_mode = (post_vars.get("grant_mode") or "").strip()
            actor_id = None
            actor_group_id = None
            role_name = None
            action_name = None
            expires_at = (post_vars.get("expires_at") or "").strip() or None
            if subject_type == "actor":
                if not await validate_actor_id(datasette, subject):
                    datasette.add_message(
                        request, "That user ID is not valid", datasette.ERROR
                    )
                    return Response.redirect(request.path)
                actor_id = subject
            elif subject_type == "group":
                group_row = (
                    await db.execute(
                        "select id from acl_groups where name = :name and deleted is null limit 1",
                        {"name": subject},
                    )
                ).first()
                if group_row is None:
                    datasette.add_message(
                        request, "Unknown actor group", datasette.ERROR
                    )
                    return Response.redirect(request.path)
                actor_group_id = group_row["id"]
            else:
                datasette.add_message(request, "Invalid subject type", datasette.ERROR)
                return Response.redirect(request.path)
            if grant_mode == "role":
                role_name = (post_vars.get("role_name") or "").strip()
                role_row = (
                    await db.execute(
                        "select 1 from acl_role_bundles where name = :name limit 1",
                        {"name": role_name},
                    )
                ).first()
                if role_row is None:
                    datasette.add_message(
                        request, "Unknown role bundle", datasette.ERROR
                    )
                    return Response.redirect(request.path)
            elif grant_mode == "action":
                action_name = (post_vars.get("action_name") or "").strip()
                action_row = (
                    await db.execute(
                        "select 1 from acl_actions where name = :name limit 1",
                        {"name": action_name},
                    )
                ).first()
                if action_row is None:
                    datasette.add_message(request, "Unknown action", datasette.ERROR)
                    return Response.redirect(request.path)
            else:
                datasette.add_message(request, "Invalid grant mode", datasette.ERROR)
                return Response.redirect(request.path)
            grant = await add_resource_group_grant(
                db,
                slug=slug,
                actor_id=actor_id,
                actor_group_id=actor_group_id,
                role_name=role_name,
                action_name=action_name,
                granted_by=request.actor["id"],
                expires_at=expires_at,
            )
            if grant is None:
                datasette.add_message(
                    request, "That grant already exists", datasette.ERROR
                )
                return Response.redirect(request.path)
            await record_grant_audit(
                db,
                operation="grant-added",
                resource_group_id=await _resource_group_id(db, slug),
                operation_by=request.actor["id"],
                actor_id=grant["actor_id"],
                actor_group_id=actor_group_id,
                role_name=grant["role_name"],
                action_name=grant["action_name"],
            )
            datasette.add_message(request, "Added grant")
            return Response.redirect(request.path)
    return Response.html(
        await datasette.render_template(
            "manage_resource_group.html",
            {
                "resource_group": detail,
                "groups": [
                    row["name"]
                    for row in (
                        await db.execute(
                            "select name from acl_groups where deleted is null order by name"
                        )
                    ).rows
                ],
                "role_bundles": [
                    row["name"]
                    for row in (
                        await db.execute(
                            "select name from acl_role_bundles order by name"
                        )
                    ).rows
                ],
                "actions": [
                    row["name"]
                    for row in (
                        await db.execute("select name from acl_actions order by name")
                    ).rows
                ],
                "valid_actors": await get_acl_valid_actors(datasette),
            },
            request=request,
        )
    )


async def resource_groups_json(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    db = datasette.get_internal_database()
    if request.method == "POST":
        post_vars = await _post_vars(request)
        slug = (post_vars.get("slug") or "").strip()
        name = (post_vars.get("name") or "").strip()
        if not slug or not name:
            return Response.json(
                {"ok": False, "error": "slug and name are required"},
                status=400,
            )
        resource_group = await create_resource_group(
            db=db,
            slug=slug,
            name=name,
            description=(post_vars.get("description") or "").strip() or None,
            created_by=request.actor["id"],
        )
        if resource_group is None:
            return Response.json(
                {
                    "ok": False,
                    "error": "A resource group with that slug already exists",
                },
                status=409,
            )
        resource_group_id = (
            await db.execute(
                "select id from acl_resource_groups where slug = :slug",
                {"slug": slug},
            )
        ).single_value()
        await record_resource_group_audit(
            db,
            operation="created",
            resource_group_id=resource_group_id,
            operation_by=request.actor["id"],
        )
        return Response.json({"ok": True, "resource_group": dict(resource_group)})
    return Response.json(
        {"resource_groups": await list_resource_groups(db, request.args.get("q"))}
    )


async def resource_group_json(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    if request.method == "DELETE":
        return await delete_resource_group_json(request, datasette)
    detail = await get_resource_group_detail(
        datasette.get_internal_database(), request.url_vars["slug"]
    )
    if detail is None:
        return Response.json({"ok": False, "error": "Not found"}, status=404)
    return Response.json({"resource_group": detail})


async def resource_group_resources_json(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    db = datasette.get_internal_database()
    slug = request.url_vars["slug"]
    resource_group = await get_resource_group(db, slug)
    if resource_group is None:
        return Response.json({"ok": False, "error": "Not found"}, status=404)
    post_vars = await _post_vars(request)
    resource_type = (post_vars.get("resource_type") or "").strip()
    resource_key = (post_vars.get("resource_key") or "").strip()
    validation_error = await validate_resource(datasette, resource_type, resource_key)
    if validation_error:
        return Response.json({"ok": False, "error": validation_error}, status=400)
    resource = await add_resource_group_item(
        db,
        slug=slug,
        resource_type=resource_type,
        resource_key=resource_key,
        note=(post_vars.get("note") or "").strip() or None,
        added_by=request.actor["id"],
    )
    if resource is None:
        return Response.json(
            {
                "ok": False,
                "error": "That resource is already in this resource group",
            },
            status=409,
        )
    resource = dict(resource)
    await record_resource_group_audit(
        db,
        operation="resource-added",
        resource_group_id=(
            await db.execute(
                "select id from acl_resource_groups where slug = :slug",
                {"slug": slug},
            )
        ).single_value(),
        operation_by=request.actor["id"],
        resource_type=resource["resource_type"],
        resource_key=resource["resource_key"],
    )
    return Response.json({"ok": True, "resource": resource})


async def resource_group_grants_json(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    db = datasette.get_internal_database()
    slug = request.url_vars["slug"]
    resource_group = await get_resource_group(db, slug)
    if resource_group is None:
        return Response.json({"ok": False, "error": "Not found"}, status=404)
    post_vars = await _post_vars(request)
    subject_type = (post_vars.get("subject_type") or "").strip()
    subject = (post_vars.get("subject") or "").strip()
    grant_mode = (post_vars.get("grant_mode") or "").strip()
    expires_at = (post_vars.get("expires_at") or "").strip() or None
    actor_id = None
    actor_group_id = None
    role_name = None
    action_name = None
    if subject_type == "actor":
        if not await validate_actor_id(datasette, subject):
            return Response.json(
                {"ok": False, "error": "That user ID is not valid"}, status=400
            )
        actor_id = subject
    elif subject_type == "group":
        group_row = (
            await db.execute(
                "select id from acl_groups where name = :name and deleted is null limit 1",
                {"name": subject},
            )
        ).first()
        actor_group_id = group_row["id"] if group_row else None
        if actor_group_id is None:
            return Response.json(
                {"ok": False, "error": "Unknown actor group"}, status=400
            )
    else:
        return Response.json({"ok": False, "error": "Invalid subject_type"}, status=400)
    if grant_mode == "role":
        role_name = (post_vars.get("role_name") or "").strip()
        role_row = (
            await db.execute(
                "select 1 from acl_role_bundles where name = :name limit 1",
                {"name": role_name},
            )
        ).first()
        exists = role_row is not None
        if not exists:
            return Response.json(
                {"ok": False, "error": "Unknown role bundle"}, status=400
            )
    elif grant_mode == "action":
        action_name = (post_vars.get("action_name") or "").strip()
        action_row = (
            await db.execute(
                "select 1 from acl_actions where name = :name limit 1",
                {"name": action_name},
            )
        ).first()
        exists = action_row is not None
        if not exists:
            return Response.json({"ok": False, "error": "Unknown action"}, status=400)
    else:
        return Response.json({"ok": False, "error": "Invalid grant_mode"}, status=400)
    grant = await add_resource_group_grant(
        db,
        slug=slug,
        actor_id=actor_id,
        actor_group_id=actor_group_id,
        role_name=role_name,
        action_name=action_name,
        granted_by=request.actor["id"],
        expires_at=expires_at,
    )
    if grant is None:
        return Response.json(
            {"ok": False, "error": "That grant already exists"},
            status=409,
        )
    grant = dict(grant)
    await record_grant_audit(
        db,
        operation="grant-added",
        resource_group_id=(
            await db.execute(
                "select id from acl_resource_groups where slug = :slug",
                {"slug": slug},
            )
        ).single_value(),
        operation_by=request.actor["id"],
        actor_id=grant["actor_id"],
        actor_group_id=actor_group_id,
        role_name=grant["role_name"],
        action_name=grant["action_name"],
    )
    return Response.json({"ok": True, "grant": grant})


async def delete_resource_group_json(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    if request.method != "DELETE":
        return Response.json({"ok": False, "error": "404"}, status=404)
    db = datasette.get_internal_database()
    slug = request.url_vars["slug"]
    group_row = (
        await db.execute(
            "select id from acl_resource_groups where slug = :slug and deleted = 0",
            {"slug": slug},
        )
    ).first()
    if group_row is None:
        return Response.json({"ok": False, "error": "Not found"}, status=404)
    await db.execute_write(
        """
        update acl_resource_groups
        set deleted = 1, updated_at = datetime('now')
        where id = :id
        """,
        {"id": group_row["id"]},
    )
    await record_resource_group_audit(
        db,
        operation="deleted",
        resource_group_id=group_row["id"],
        operation_by=request.actor["id"],
    )
    return Response.json({"ok": True})


async def delete_resource_group_item_json(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    if request.method != "DELETE":
        return Response.json({"ok": False, "error": "404"}, status=404)
    db = datasette.get_internal_database()
    row = (
        await db.execute(
            """
            select id, resource_group_id, resource_type, resource_key
            from acl_resource_group_items
            where id = :id
              and resource_group_id = (
                select id from acl_resource_groups where slug = :slug and deleted = 0
              )
            """,
            {"id": request.url_vars["id"], "slug": request.url_vars["slug"]},
        )
    ).first()
    if row is None:
        return Response.json({"ok": False, "error": "Not found"}, status=404)
    await db.execute_write(
        "delete from acl_resource_group_items where id = :id",
        {"id": row["id"]},
    )
    await record_resource_group_audit(
        db,
        operation="resource-removed",
        resource_group_id=row["resource_group_id"],
        operation_by=request.actor["id"],
        resource_type=row["resource_type"],
        resource_key=row["resource_key"],
    )
    return Response.json({"ok": True})


async def delete_resource_group_grant_json(request, datasette):
    if not await can_edit_permissions(datasette, request.actor):
        raise Forbidden("You do not have permission to edit permissions")
    if request.method != "DELETE":
        return Response.json({"ok": False, "error": "404"}, status=404)
    db = datasette.get_internal_database()
    row = (
        await db.execute(
            """
            select id, resource_group_id, actor_id, actor_group_id, role_name, action_name
            from acl_resource_group_grants
            where id = :id
              and resource_group_id = (
                select id from acl_resource_groups where slug = :slug and deleted = 0
              )
            """,
            {"id": request.url_vars["id"], "slug": request.url_vars["slug"]},
        )
    ).first()
    if row is None:
        return Response.json({"ok": False, "error": "Not found"}, status=404)
    await db.execute_write(
        "delete from acl_resource_group_grants where id = :id",
        {"id": row["id"]},
    )
    await record_grant_audit(
        db,
        operation="grant-removed",
        resource_group_id=row["resource_group_id"],
        operation_by=request.actor["id"],
        actor_id=row["actor_id"],
        actor_group_id=row["actor_group_id"],
        role_name=row["role_name"],
        action_name=row["action_name"],
    )
    return Response.json({"ok": True})
