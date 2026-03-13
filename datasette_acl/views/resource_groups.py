from datasette import Forbidden, Response
from datasette.utils import MultiParams
from datasette_acl.resource_groups import (
    ensure_resource_group,
    get_resource_group,
    get_resource_group_detail,
    list_resource_groups,
    record_grant_audit,
    record_resource_group_audit,
    validate_resource,
)
from datasette_acl.utils import can_edit_permissions, validate_actor_id
from urllib.parse import parse_qs


async def _post_vars(request):
    body = await request.post_body()
    return MultiParams(parse_qs(qs=body.decode("utf-8"), keep_blank_values=True))


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
        resource_group = await ensure_resource_group(
            db=db,
            slug=slug,
            name=name,
            description=(post_vars.get("description") or "").strip() or None,
            created_by=request.actor["id"],
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
    await db.execute_write(
        """
        insert into acl_resource_group_items (
            resource_group_id, resource_type, resource_key, note, added_by
        ) values (
            (select id from acl_resource_groups where slug = :slug),
            :resource_type,
            :resource_key,
            :note,
            :added_by
        )
        """,
        {
            "slug": slug,
            "resource_type": resource_type,
            "resource_key": resource_key,
            "note": (post_vars.get("note") or "").strip() or None,
            "added_by": request.actor["id"],
        },
    )
    resource = dict(
        (
            await db.execute(
                """
                select id, resource_type, resource_key, note
                from acl_resource_group_items
                where resource_group_id = (
                    select id from acl_resource_groups where slug = :slug
                )
                order by id desc
                limit 1
                """,
                {"slug": slug},
            )
        ).first()
    )
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
        actor_group_id = (
            await db.execute(
                "select id from acl_groups where name = :name and deleted is null",
                {"name": subject},
            )
        ).single_value()
        if actor_group_id is None:
            return Response.json(
                {"ok": False, "error": "Unknown actor group"}, status=400
            )
    else:
        return Response.json({"ok": False, "error": "Invalid subject_type"}, status=400)
    if grant_mode == "role":
        role_name = (post_vars.get("role_name") or "").strip()
        exists = (
            await db.execute(
                "select 1 from acl_role_bundles where name = :name",
                {"name": role_name},
            )
        ).single_value()
        if not exists:
            return Response.json(
                {"ok": False, "error": "Unknown role bundle"}, status=400
            )
    elif grant_mode == "action":
        action_name = (post_vars.get("action_name") or "").strip()
        exists = (
            await db.execute(
                "select 1 from acl_actions where name = :name",
                {"name": action_name},
            )
        ).single_value()
        if not exists:
            return Response.json({"ok": False, "error": "Unknown action"}, status=400)
    else:
        return Response.json({"ok": False, "error": "Invalid grant_mode"}, status=400)
    await db.execute_write(
        """
        insert into acl_resource_group_grants (
            resource_group_id, actor_id, actor_group_id, role_name, action_name, granted_by, expires_at
        ) values (
            (select id from acl_resource_groups where slug = :slug),
            :actor_id,
            :actor_group_id,
            :role_name,
            :action_name,
            :granted_by,
            :expires_at
        )
        """,
        {
            "slug": slug,
            "actor_id": actor_id,
            "actor_group_id": actor_group_id,
            "role_name": role_name,
            "action_name": action_name,
            "granted_by": request.actor["id"],
            "expires_at": expires_at,
        },
    )
    grant = dict(
        (
            await db.execute(
                """
                select
                    rgg.id,
                    rgg.actor_id,
                    ag.name as actor_group,
                    rgg.role_name,
                    rgg.action_name,
                    rgg.expires_at
                from acl_resource_group_grants rgg
                left join acl_groups ag on ag.id = rgg.actor_group_id
                where rgg.resource_group_id = (
                    select id from acl_resource_groups where slug = :slug
                )
                order by rgg.id desc
                limit 1
                """,
                {"slug": slug},
            )
        ).first()
    )
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
