from datasette.resources import DatabaseResource, QueryResource, TableResource
from datasette.plugins import pm
from datasette.utils import await_me_maybe

DEFAULT_ROLE_BUNDLES = [
    {
        "name": "viewer",
        "description": "Read-only access to Datasette resources.",
        "actions": [
            "view-instance",
            "view-database",
            "view-table",
            "view-query",
        ],
    },
    {
        "name": "editor",
        "description": "Read and write access to tables.",
        "actions": [
            "view-instance",
            "view-database",
            "view-table",
            "view-query",
            "insert-row",
            "update-row",
            "delete-row",
        ],
    },
    {
        "name": "admin",
        "description": "Administrative access to tables.",
        "actions": [
            "view-instance",
            "view-database",
            "view-table",
            "view-query",
            "insert-row",
            "update-row",
            "delete-row",
            "alter-table",
            "drop-table",
        ],
    },
]


async def get_role_bundles(datasette):
    bundles_by_name = {bundle["name"]: bundle for bundle in DEFAULT_ROLE_BUNDLES}
    for hook in pm.hook.datasette_acl_role_bundles(datasette=datasette):
        for bundle in await await_me_maybe(hook) or []:
            existing = bundles_by_name.get(bundle["name"])
            if existing and existing != bundle:
                raise ValueError(
                    "Conflicting datasette_acl_role_bundles definition for "
                    f"{bundle['name']!r}"
                )
            bundles_by_name[bundle["name"]] = bundle
    return [bundles_by_name[name] for name in sorted(bundles_by_name)]


async def ensure_role_bundles(datasette):
    db = datasette.get_internal_database()
    for bundle in await get_role_bundles(datasette):
        await db.execute_write(
            """
            insert into acl_role_bundles (name, description, source_plugin, is_system)
            values (:name, :description, :source_plugin, :is_system)
            on conflict(name) do update set
                description = excluded.description,
                source_plugin = excluded.source_plugin,
                is_system = excluded.is_system
            """,
            {
                "name": bundle["name"],
                "description": bundle.get("description"),
                "source_plugin": bundle.get("source_plugin"),
                "is_system": int(
                    bundle.get(
                        "is_system", bundle["name"] in {"viewer", "editor", "admin"}
                    )
                ),
            },
        )
        role_bundle_id = (
            await db.execute(
                "select id from acl_role_bundles where name = :name",
                {"name": bundle["name"]},
            )
        ).single_value()
        await db.execute_write(
            "delete from acl_role_bundle_actions where role_bundle_id = :role_bundle_id",
            {"role_bundle_id": role_bundle_id},
        )
        await db.execute_write_many(
            """
            insert into acl_role_bundle_actions (role_bundle_id, action_name)
            values (:role_bundle_id, :action_name)
            """,
            [
                {"role_bundle_id": role_bundle_id, "action_name": action_name}
                for action_name in sorted(set(bundle["actions"]))
            ],
        )


async def get_resource_type_adapters(datasette):
    adapters = []
    for hook in pm.hook.datasette_acl_resource_types(datasette=datasette):
        adapters.extend(await await_me_maybe(hook) or [])
    return adapters


async def validate_resource(datasette, resource_type, resource_key):
    if resource_type == "database":
        try:
            datasette.get_database(resource_key)
        except KeyError:
            return f"Database not found: {resource_key}"
        return None
    if resource_type == "table":
        if "/" not in resource_key:
            return "Table resources must use database/table format"
        database_name, table_name = resource_key.split("/", 1)
        try:
            database = datasette.get_database(database_name)
        except KeyError:
            return f"Database not found: {database_name}"
        if table_name not in await database.table_names():
            return f"Table not found: {resource_key}"
        return None
    if resource_type == "query":
        if "/" not in resource_key:
            return "Query resources must use database/query-name format"
        database_name, query_name = resource_key.split("/", 1)
        try:
            datasette.get_database(database_name)
        except KeyError:
            return f"Database not found: {database_name}"
        queries = await datasette.get_canned_queries(database_name, actor=None)
        metadata_queries = (
            (datasette._metadata_local or {}).get("databases") or {}
        ).get(database_name, {}).get("queries") or {}
        queries.update(metadata_queries)
        if query_name not in queries:
            return f"Query not found: {resource_key}"
        return None
    for adapter in await get_resource_type_adapters(datasette):
        if adapter.type_name != resource_type:
            continue
        return await await_me_maybe(adapter.validate(datasette, resource_key))
    return f"Unknown resource type: {resource_type}"


async def serialize_resource(datasette, resource):
    if isinstance(resource, TableResource):
        return "table", f"{resource.parent}/{resource.child}"
    if isinstance(resource, QueryResource):
        return "query", f"{resource.parent}/{resource.child}"
    if isinstance(resource, DatabaseResource):
        return "database", resource.parent
    for adapter in await get_resource_type_adapters(datasette):
        serialized = await await_me_maybe(adapter.serialize(resource))
        if serialized is not None:
            return serialized
    return None


async def ensure_resource_group(
    db, slug, name, description=None, created_by=None, deleted=0
):
    await db.execute_write(
        """
        insert into acl_resource_groups (
            slug, name, description, created_by, updated_at, deleted
        ) values (
            :slug, :name, :description, :created_by, datetime('now'), :deleted
        )
        on conflict(slug) do update set
            name = excluded.name,
            description = excluded.description,
            updated_at = datetime('now'),
            deleted = excluded.deleted
        """,
        {
            "slug": slug,
            "name": name,
            "description": description,
            "created_by": created_by,
            "deleted": deleted,
        },
    )
    return await get_resource_group(db, slug)


async def create_resource_group(db, slug, name, description=None, created_by=None):
    existing = await get_resource_group(db, slug, include_deleted=True)
    if existing is not None:
        return None
    await db.execute_write(
        """
        insert into acl_resource_groups (
            slug, name, description, created_by, updated_at, deleted
        ) values (
            :slug, :name, :description, :created_by, datetime('now'), 0
        )
        """,
        {
            "slug": slug,
            "name": name,
            "description": description,
            "created_by": created_by,
        },
    )
    return await get_resource_group(db, slug)


async def get_resource_group(db, slug, include_deleted=False):
    row = await db.execute(
        """
        select slug, name, description, deleted
        from acl_resource_groups
        where slug = :slug
          and (:include_deleted = 1 or deleted = 0)
        """,
        {"slug": slug, "include_deleted": int(include_deleted)},
    )
    return row.first()


async def list_resource_groups(db, search=None):
    sql = """
        select
            rg.slug,
            rg.name,
            rg.description,
            count(distinct rgi.id) as resources_count,
            count(distinct rgg.id) as grants_count
        from acl_resource_groups rg
        left join acl_resource_group_items rgi
          on rgi.resource_group_id = rg.id
        left join acl_resource_group_grants rgg
          on rgg.resource_group_id = rg.id
        where rg.deleted = 0
    """
    params = {}
    if search:
        sql += """
          and (rg.slug like :search or rg.name like :search)
        """
        params["search"] = f"%{search}%"
    sql += """
        group by rg.id
        order by rg.slug
    """
    return [dict(row) for row in (await db.execute(sql, params)).rows]


async def record_resource_group_audit(
    db,
    operation,
    resource_group_id,
    operation_by,
    resource_type=None,
    resource_key=None,
    metadata=None,
):
    await db.execute_write(
        """
        insert into acl_resource_groups_audit (
            operation_by, operation, resource_group_id, resource_type, resource_key, metadata
        ) values (
            :operation_by, :operation, :resource_group_id, :resource_type, :resource_key, :metadata
        )
        """,
        {
            "operation_by": operation_by,
            "operation": operation,
            "resource_group_id": resource_group_id,
            "resource_type": resource_type,
            "resource_key": resource_key,
            "metadata": metadata,
        },
    )


async def record_grant_audit(
    db,
    operation,
    resource_group_id,
    operation_by,
    actor_id=None,
    actor_group_id=None,
    role_name=None,
    action_name=None,
    metadata=None,
):
    await db.execute_write(
        """
        insert into acl_resource_group_grants_audit (
            operation_by, operation, resource_group_id, actor_id, actor_group_id,
            role_name, action_name, metadata
        ) values (
            :operation_by, :operation, :resource_group_id, :actor_id, :actor_group_id,
            :role_name, :action_name, :metadata
        )
        """,
        {
            "operation_by": operation_by,
            "operation": operation,
            "resource_group_id": resource_group_id,
            "actor_id": actor_id,
            "actor_group_id": actor_group_id,
            "role_name": role_name,
            "action_name": action_name,
            "metadata": metadata,
        },
    )


async def get_resource_group_detail(db, slug):
    resource_group = await get_resource_group(db, slug)
    if resource_group is None:
        return None
    detail = dict(resource_group)
    detail["resources"] = [
        {
            "id": row["id"],
            "resource_type": row["resource_type"],
            "resource_key": row["resource_key"],
            "note": row["note"],
        }
        for row in (
            await db.execute(
                """
                select id, resource_type, resource_key, note
                from acl_resource_group_items
                where resource_group_id = (
                    select id from acl_resource_groups where slug = :slug
                )
                order by id
                """,
                {"slug": slug},
            )
        ).rows
    ]
    detail["grants"] = [
        {
            "id": row["id"],
            "actor_id": row["actor_id"],
            "actor_group": row["actor_group"],
            "role_name": row["role_name"],
            "action_name": row["action_name"],
            "expires_at": row["expires_at"],
        }
        for row in (
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
                order by rgg.id
                """,
                {"slug": slug},
            )
        ).rows
    ]
    return detail


async def add_resource_group_item(
    db, slug, resource_type, resource_key, note=None, added_by=None
):
    existing = (
        await db.execute(
            """
            select id, resource_type, resource_key, note
            from acl_resource_group_items
            where resource_group_id = (
                select id from acl_resource_groups where slug = :slug
            )
              and resource_type = :resource_type
              and resource_key = :resource_key
            """,
            {
                "slug": slug,
                "resource_type": resource_type,
                "resource_key": resource_key,
            },
        )
    ).first()
    if existing is not None:
        return None
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
            "note": note,
            "added_by": added_by,
        },
    )
    return (
        await db.execute(
            """
            select id, resource_type, resource_key, note
            from acl_resource_group_items
            where resource_group_id = (
                select id from acl_resource_groups where slug = :slug
            )
              and resource_type = :resource_type
              and resource_key = :resource_key
            """,
            {
                "slug": slug,
                "resource_type": resource_type,
                "resource_key": resource_key,
            },
        )
    ).first()


async def add_resource_group_grant(
    db,
    slug,
    actor_id=None,
    actor_group_id=None,
    role_name=None,
    action_name=None,
    granted_by=None,
    expires_at=None,
):
    existing = (
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
              and ((:actor_id is null and rgg.actor_id is null) or rgg.actor_id = :actor_id)
              and (
                (:actor_group_id is null and rgg.actor_group_id is null)
                or rgg.actor_group_id = :actor_group_id
              )
              and ((:role_name is null and rgg.role_name is null) or rgg.role_name = :role_name)
              and (
                (:action_name is null and rgg.action_name is null)
                or rgg.action_name = :action_name
              )
              and (
                (:expires_at is null and rgg.expires_at is null)
                or rgg.expires_at = :expires_at
              )
            """,
            {
                "slug": slug,
                "actor_id": actor_id,
                "actor_group_id": actor_group_id,
                "role_name": role_name,
                "action_name": action_name,
                "expires_at": expires_at,
            },
        )
    ).first()
    if existing is not None:
        return None
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
            "granted_by": granted_by,
            "expires_at": expires_at,
        },
    )
    return (
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
              and ((:actor_id is null and rgg.actor_id is null) or rgg.actor_id = :actor_id)
              and (
                (:actor_group_id is null and rgg.actor_group_id is null)
                or rgg.actor_group_id = :actor_group_id
              )
              and ((:role_name is null and rgg.role_name is null) or rgg.role_name = :role_name)
              and (
                (:action_name is null and rgg.action_name is null)
                or rgg.action_name = :action_name
              )
              and (
                (:expires_at is null and rgg.expires_at is null)
                or rgg.expires_at = :expires_at
              )
            order by rgg.id desc
            limit 1
            """,
            {
                "slug": slug,
                "actor_id": actor_id,
                "actor_group_id": actor_group_id,
                "role_name": role_name,
                "action_name": action_name,
                "expires_at": expires_at,
            },
        )
    ).first()


def table_resource_group_slug(database, table):
    return f"table:{database}/{table}"


async def ensure_implicit_table_resource_group(
    datasette, database, table, created_by=None
):
    db = datasette.get_internal_database()
    slug = table_resource_group_slug(database, table)
    await ensure_resource_group(
        db=db,
        slug=slug,
        name=f"Table {database}/{table}",
        description=f"Compatibility resource group for table {database}/{table}",
        created_by=created_by,
    )
    await db.execute_write(
        """
        insert or ignore into acl_resource_group_items (
            resource_group_id, resource_type, resource_key, added_by
        ) values (
            (select id from acl_resource_groups where slug = :slug),
            'table',
            :resource_key,
            :added_by
        )
        """,
        {
            "slug": slug,
            "resource_key": f"{database}/{table}",
            "added_by": created_by,
        },
    )
    return slug


async def sync_table_resource_group_grant(
    datasette,
    database,
    table,
    action_name,
    granted_by,
    actor_id=None,
    group_name=None,
    enabled=True,
):
    db = datasette.get_internal_database()
    slug = await ensure_implicit_table_resource_group(
        datasette, database, table, created_by=granted_by
    )
    params = {
        "slug": slug,
        "actor_id": actor_id,
        "group_name": group_name,
        "action_name": action_name,
        "granted_by": granted_by,
    }
    if enabled:
        await db.execute_write(
            """
            insert or ignore into acl_resource_group_grants (
                resource_group_id, actor_id, actor_group_id, role_name, action_name, granted_by
            ) values (
                (select id from acl_resource_groups where slug = :slug),
                :actor_id,
                (select id from acl_groups where name = :group_name),
                null,
                :action_name,
                :granted_by
            )
            """,
            params,
        )
        return
    await db.execute_write(
        """
        delete from acl_resource_group_grants
        where resource_group_id = (select id from acl_resource_groups where slug = :slug)
          and action_name = :action_name
          and role_name is null
          and (
            (:actor_id is not null and actor_id = :actor_id and actor_group_id is null)
            or (
                :group_name is not null
                and actor_id is null
                and actor_group_id = (select id from acl_groups where name = :group_name)
            )
          )
        """,
        params,
    )
