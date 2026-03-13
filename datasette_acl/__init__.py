from datasette import hookimpl
from datasette.events import CreateTableEvent
from datasette.permissions import Action, PermissionSQL
from datasette.resources import DatabaseResource, QueryResource, TableResource
from datasette.utils import actor_matches_allow
from datasette.plugins import pm
from datasette_acl.resource_groups import (
    ensure_role_bundles,
    sync_table_resource_group_grant,
)
from datasette_acl.utils import can_edit_permissions
from datasette_acl.views.table_acls import manage_table_acls
from datasette_acl.views.groups import manage_groups, manage_group
from datasette_acl.views.resource_groups import (
    resource_group_grants_json,
    resource_group_json,
    resource_group_resources_json,
    resource_groups_json,
)
from . import hookspecs
import json
import sys
import time

pm.add_hookspecs(hookspecs)

CREATE_TABLES_SQL = """
create table if not exists acl_resources (
    id integer primary key,
    database text not null,
    resource text,
    unique(database, resource)
);

create table if not exists acl_actions (
    id integer primary key,
    name text not null unique
);

-- new table for groups
create table if not exists acl_groups (
    id integer primary key,
    name text not null unique,
    deleted integer
);

-- new table for actor-group relationships
create table if not exists acl_actor_groups (
    actor_id text,
    group_id integer,
    primary key (actor_id, group_id),
    foreign key (group_id) references acl_groups(id)
);

-- Group membership audit log
create table if not exists acl_groups_audit (
    id integer primary key,
    timestamp text default (datetime('now')),
    operation_by text,
    operation text check (operation in ('added', 'removed', 'created', 'deleted')),
    group_id integer,
    actor_id text,
    foreign key (group_id) references acl_groups(id)
);

create table if not exists acl (
    acl_id integer primary key,
    actor_id text,
    group_id integer,
    resource_id integer,
    action_id integer,
    foreign key (group_id) references acl_groups(id),
    foreign key (resource_id) references acl_resources(id),
    foreign key (action_id) references acl_actions(id),
    check ((actor_id is null) != (group_id is null)),
    unique(actor_id, group_id, resource_id, action_id)
);

-- ACL audit log
create table if not exists acl_audit (
    id integer primary key,
    timestamp text default (datetime('now')),
    operation_by text,
    operation text check (operation in ('added', 'removed')),
    action_id integer,
    resource_id integer,
    group_id integer,
    actor_id text,
    foreign key (group_id) references acl_groups(id),
    foreign key (resource_id) references acl_resources(id),
    foreign key (action_id) references acl_actions(id)
);

create table if not exists acl_resource_groups (
    id integer primary key,
    slug text unique not null,
    name text not null,
    description text,
    created_by text,
    created_at text default (datetime('now')),
    updated_at text default (datetime('now')),
    deleted integer default 0
);

create table if not exists acl_resource_group_items (
    id integer primary key,
    resource_group_id integer not null references acl_resource_groups(id),
    resource_type text not null,
    resource_key text not null,
    note text,
    added_by text,
    added_at text default (datetime('now')),
    unique(resource_group_id, resource_type, resource_key)
);

create table if not exists acl_resource_groups_audit (
    id integer primary key,
    timestamp text default (datetime('now')),
    operation_by text,
    operation text,
    resource_group_id integer references acl_resource_groups(id),
    resource_type text,
    resource_key text,
    metadata text
);

create table if not exists acl_resource_group_grants (
    id integer primary key,
    resource_group_id integer not null references acl_resource_groups(id),
    actor_id text,
    actor_group_id integer references acl_groups(id),
    role_name text,
    action_name text,
    granted_by text,
    created_at text default (datetime('now')),
    expires_at text,
    check ((actor_id is null) != (actor_group_id is null)),
    check ((role_name is null) != (action_name is null)),
    unique(resource_group_id, actor_id, actor_group_id, role_name, action_name)
);

create table if not exists acl_resource_group_grants_audit (
    id integer primary key,
    timestamp text default (datetime('now')),
    operation_by text,
    operation text,
    resource_group_id integer references acl_resource_groups(id),
    actor_id text,
    actor_group_id integer references acl_groups(id),
    role_name text,
    action_name text,
    metadata text
);

create table if not exists acl_role_bundles (
    id integer primary key,
    name text unique not null,
    description text,
    source_plugin text,
    is_system integer default 0
);

create table if not exists acl_role_bundle_actions (
    role_bundle_id integer not null references acl_role_bundles(id),
    action_name text not null,
    primary key (role_bundle_id, action_name)
)
"""

EXPECTED_GROUPS_SQL = """
with expected_groups as (
  select value as group_name
  from json_each(:expected_groups_json)
),
dynamic_groups as (
  select value as group_name
  from json_each(:dynamic_groups)
),
actual_groups as (
  select g.name as group_name
  from acl_groups g
  join acl_actor_groups ug on g.id = ug.group_id
  where ug.actor_id = :actor_id
)
select
  'should-add' as status,
  eg.group_name
from expected_groups eg
where eg.group_name not in (select group_name from actual_groups)
  union all
select
  'should-remove' as status,
  ag.group_name
from actual_groups ag
where ag.group_name not in (select group_name from expected_groups)
and ag.group_name in (select group_name from dynamic_groups)
  union all
select
  'current' as status,
  group_name
from actual_groups
"""


@hookimpl
def startup(datasette):
    async def inner():
        db = datasette.get_internal_database()
        await db.execute_write_script(CREATE_TABLES_SQL)
        # Ensure permissions are in the DB
        await db.execute_write_many(
            """
            insert or ignore into acl_actions (name) values (:name)
        """,
            [{"name": name} for name in datasette.actions.keys()],
        )
        await ensure_role_bundles(datasette)
        # And any dynamic groups
        config = datasette.plugin_config("datasette-acl") or {}
        groups = config.get("dynamic-groups")
        if groups:
            await db.execute_write_many(
                "insert or ignore into acl_groups (name) values (:name)",
                [{"name": name} for name in groups.keys()],
            )

    return inner


class OneSecondCache:
    def __init__(self):
        self.cache = {}

    def set(self, key, value):
        self.cache[key] = (value, time.monotonic() + 1)

    def get(self, key):
        if key in self.cache:
            value, expiration_time = self.cache[key]
            if time.monotonic() < expiration_time:
                return value
            else:
                del self.cache[key]
        return None

    def clear_expired(self):
        current_time = time.monotonic()
        self.cache = {k: v for k, v in self.cache.items() if v[1] > current_time}


one_second_cache = OneSecondCache()


async def update_dynamic_groups(datasette, actor, skip_cache=False):
    if not actor or not actor.get("id"):
        return
    if (not skip_cache) and one_second_cache.get(actor["id"]):
        # Don't do this more than once a second per actor
        return
    one_second_cache.set(actor["id"], 1)
    config = datasette.plugin_config("datasette-acl") or {}
    groups = config.get("dynamic-groups")
    if not groups:
        return
    # Figure out the groups the user should be in
    should_have_groups = set(
        group_name
        for group_name, allow_block in groups.items()
        if actor_matches_allow(actor, allow_block)
    )
    db = datasette.get_internal_database()
    result = await db.execute(
        EXPECTED_GROUPS_SQL,
        {
            "actor_id": actor["id"],
            "expected_groups_json": json.dumps(list(should_have_groups)),
            "dynamic_groups": json.dumps(list(groups.keys())),
        },
    )
    should_add = []
    should_remove = []
    for row in result.rows:
        if row["status"] == "should-add":
            should_add.append(row["group_name"])
        elif row["status"] == "should-remove":
            should_remove.append(row["group_name"])
    # Add/remove groups as needed
    for group_name in should_add:
        # Make sure the group exists
        await db.execute_write(
            "insert or ignore into acl_groups (name) VALUES (:name);",
            {"name": group_name},
        )
        await db.execute_write(
            """
            insert into acl_actor_groups (
                actor_id, group_id
            ) values (
                :actor_id,
                (select id from acl_groups where name = :group_name)
            )""",
            {"actor_id": actor["id"], "group_name": group_name},
        )
        await db.execute_write(
            """
            insert into acl_groups_audit (
                operation_by, operation, group_id, actor_id
            ) values (
                null,
                'added',
                (select id from acl_groups where name = :group_name),
                :actor_id
            )
        """,
            {
                "group_name": group_name,
                "actor_id": actor["id"],
            },
        )
    for group_name in should_remove:
        await db.execute_write(
            """
            delete from acl_actor_groups
            where actor_id = :actor_id
            and group_id = (select id from acl_groups where name = :group_name)
            """,
            {"actor_id": actor["id"], "group_name": group_name},
        )
        await db.execute_write(
            """
            insert into acl_groups_audit (
                operation_by, operation, group_id, actor_id
            ) values (
                null,
                'removed',
                (select id from acl_groups where name = :group_name),
                :actor_id
            )
        """,
            {
                "group_name": group_name,
                "actor_id": actor["id"],
            },
        )


@hookimpl
def permission_resources_sql(datasette, actor, action):
    action_obj = datasette.actions.get(action)
    if not action_obj:
        return None
    resource_class = action_obj.resource_class
    resource_type = None
    if resource_class is None:
        return None
    if issubclass(resource_class, TableResource):
        resource_type = "table"
    elif issubclass(resource_class, QueryResource):
        resource_type = "query"
    elif issubclass(resource_class, DatabaseResource):
        resource_type = "database"
    else:
        return None

    async def inner():
        if not actor or not actor.get("id"):
            return None
        await update_dynamic_groups(
            datasette, actor, skip_cache=hasattr(sys, "_pytest_running")
        )
        resource_group_sql = """
WITH actor_groups AS (
    SELECT ag.group_id
    FROM acl_actor_groups ag
    JOIN acl_groups g ON ag.group_id = g.id
    WHERE ag.actor_id = :actor_id
      AND g.deleted IS NULL
),
matching_grants AS (
    select
        rgi.resource_type,
        rgi.resource_key,
        CASE
            when rgg.actor_id is not null
                then 'actor:' || rgg.actor_id
            ELSE 'group:' || g.name
        END AS reason_component
    from acl_resource_group_grants rgg
    join acl_resource_group_items rgi on rgi.resource_group_id = rgg.resource_group_id
    left join acl_groups g on g.id = rgg.actor_group_id
    left join acl_role_bundles arb on arb.name = rgg.role_name
    left join acl_role_bundle_actions arba on arba.role_bundle_id = arb.id
    where coalesce(rgg.action_name, arba.action_name) = :action
      and rgi.resource_type = :resource_type
      and (rgg.expires_at is null or rgg.expires_at > datetime('now'))
      AND (
        rgg.actor_id = :actor_id
        OR rgg.actor_group_id IN (SELECT group_id FROM actor_groups)
      )
      AND (rgg.actor_group_id IS NULL OR g.deleted IS NULL)
),
resource_group_permissions AS (
    SELECT
        case
            when resource_type = 'database' then resource_key
            else substr(resource_key, 1, instr(resource_key, '/') - 1)
        end as parent,
        case
            when resource_type = 'database' then null
            else substr(resource_key, instr(resource_key, '/') + 1)
        end as child,
        reason_component
    from matching_grants
)
SELECT
    parent,
    child,
    1 AS allow,
    'datasette-acl: ' || GROUP_CONCAT(reason_component, ', ') AS reason
FROM resource_group_permissions
GROUP BY parent, child
        """
        if resource_type == "table":
            resource_group_sql = """
WITH actor_groups AS (
    SELECT ag.group_id
    FROM acl_actor_groups ag
    JOIN acl_groups g ON ag.group_id = g.id
    WHERE ag.actor_id = :actor_id
      AND g.deleted IS NULL
),
legacy_permissions AS (
    SELECT
        ar.database AS parent,
        ar.resource AS child,
        CASE
            WHEN a.actor_id IS NOT NULL
                THEN 'actor:' || a.actor_id
            ELSE 'group:' || g.name
        END AS reason_component
    FROM acl a
    JOIN acl_actions aa ON a.action_id = aa.id
    JOIN acl_resources ar ON a.resource_id = ar.id
    LEFT JOIN acl_groups g ON a.group_id = g.id
    WHERE aa.name = :action
      AND (
        a.actor_id = :actor_id
        OR a.group_id IN (SELECT group_id FROM actor_groups)
      )
      AND (a.group_id IS NULL OR g.deleted IS NULL)
),
matching_grants AS (
    select
        rgi.resource_key,
        CASE
            when rgg.actor_id is not null
                then 'actor:' || rgg.actor_id
            ELSE 'group:' || g.name
        END AS reason_component
    from acl_resource_group_grants rgg
    join acl_resource_group_items rgi on rgi.resource_group_id = rgg.resource_group_id
    left join acl_groups g on g.id = rgg.actor_group_id
    left join acl_role_bundles arb on arb.name = rgg.role_name
    left join acl_role_bundle_actions arba on arba.role_bundle_id = arb.id
    where coalesce(rgg.action_name, arba.action_name) = :action
      and rgi.resource_type = 'table'
      and (rgg.expires_at is null or rgg.expires_at > datetime('now'))
      and (
        rgg.actor_id = :actor_id
        or rgg.actor_group_id in (select group_id from actor_groups)
      )
      and (rgg.actor_group_id is null or g.deleted is null)
),
resource_group_permissions AS (
    SELECT
        substr(resource_key, 1, instr(resource_key, '/') - 1) as parent,
        substr(resource_key, instr(resource_key, '/') + 1) as child,
        reason_component
    from matching_grants
),
matching_permissions AS (
    select * from legacy_permissions
    union all
    select * from resource_group_permissions
)
SELECT
    parent,
    child,
    1 AS allow,
    'datasette-acl: ' || GROUP_CONCAT(reason_component, ', ') AS reason
FROM matching_permissions
GROUP BY parent, child
            """
        return PermissionSQL(
            sql=resource_group_sql,
            params={
                "actor_id": actor["id"],
                "action": action,
                "resource_type": resource_type,
            },
        )

    return inner


@hookimpl
def register_actions(datasette):
    return [
        Action(
            name="datasette-acl",
            description="Configure permissions",
        )
    ]


@hookimpl
def table_actions(datasette, actor, database, table, request=None):
    async def inner():
        if await can_edit_permissions(datasette, actor):
            return [
                {
                    "href": datasette.urls.table(database, table) + "/-/acl",
                    "label": "Manage table permissions",
                    "description": "Control who can  write, and delete rows in this table",
                }
            ]

    return inner


@hookimpl
def track_event(datasette, event):
    async def inner():
        config = datasette.plugin_config("datasette-acl") or {}
        if not config.get("table-creator-permissions"):
            return
        if not isinstance(event, CreateTableEvent):
            return
        if not event.actor:
            return
        # Add ACLs for the user who created the table
        db = datasette.get_internal_database()
        # Ensure resource exists for table
        await db.execute_write(
            "INSERT OR IGNORE INTO acl_resources (database, resource) VALUES (?, ?);",
            [event.database, event.table],
        )
        resource_id = (
            await db.execute(
                "SELECT id FROM acl_resources WHERE database = ? AND resource = ?",
                [event.database, event.table],
            )
        ).single_value()
        await db.execute_write_many(
            """
            INSERT INTO acl (actor_id, group_id, resource_id, action_id)
            VALUES (
                :actor_id,
                null,
                :resource_id,
                (SELECT id FROM acl_actions WHERE name = :action_name)
            )
            """,
            [
                {
                    "actor_id": event.actor["id"],
                    "action_name": action_name,
                    "resource_id": resource_id,
                }
                for action_name in config["table-creator-permissions"]
            ],
        )
        for action_name in config["table-creator-permissions"]:
            await sync_table_resource_group_grant(
                datasette,
                event.database,
                event.table,
                action_name,
                granted_by=event.actor["id"],
                actor_id=event.actor["id"],
                enabled=True,
            )

    return inner


@hookimpl
def menu_links(datasette, actor, request=None):
    async def inner():
        if await can_edit_permissions(datasette, actor):
            return [
                {
                    "href": datasette.urls.path("/-/acl/groups"),
                    "label": "Manage user groups",
                }
            ]

    return inner


@hookimpl
def register_routes():
    return [
        ("^/(?P<database>[^/]+)/(?P<table>[^/]+)/-/acl$", manage_table_acls),
        ("^/-/acl/groups$", manage_groups),
        ("^/-/acl/groups/(?P<name>[^/]+)$", manage_group),
        ("^/-/acl/resource-groups\\.json$", resource_groups_json),
        ("^/-/acl/resource-groups/(?P<slug>[^/]+)\\.json$", resource_group_json),
        (
            "^/-/acl/resource-groups/(?P<slug>[^/]+)/resources\\.json$",
            resource_group_resources_json,
        ),
        (
            "^/-/acl/resource-groups/(?P<slug>[^/]+)/grants\\.json$",
            resource_group_grants_json,
        ),
    ]
