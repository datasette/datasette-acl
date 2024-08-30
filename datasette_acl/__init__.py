from datasette import hookimpl, Response, Permission, Forbidden
from datasette.utils import actor_matches_allow
import time
import json

CREATE_TABLES_SQL = """
create table if not exists acl_resources (
    id integer primary key autoincrement,
    database text not null,
    resource text,
    unique(database, resource)
);

create table if not exists acl_actions (
    id integer primary key autoincrement,
    name text not null unique
);

-- new table for groups
create table if not exists acl_groups (
    id integer primary key autoincrement,
    name text not null unique
);

-- new table for actor-group relationships
create table if not exists acl_actor_groups (
    actor_id text,
    group_id integer,
    primary key (actor_id, group_id),
    foreign key (group_id) references acl_groups(id)
);

create table if not exists acl (
    acl_id integer primary key autoincrement,
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
"""

ACL_RESOURCE_PAIR_SQL = """
with actor_groups as (
  select group_id
  from acl_actor_groups
  where actor_id = :actor_id
),
target_resource as (
  select id
  from acl_resources
  where database = :database and resource = :resource
),
target_action as (
  select id
  from acl_actions
  where name = :action
),
combined_permissions as (
    select resource_id, action_id
    from acl
    where actor_id = :actor_id
  union
    select resource_id, action_id
    from acl
    where group_id in (select group_id from actor_groups)
)
select count(*)
  from combined_permissions
  where resource_id = (select id from target_resource)
  and action_id = (select id from target_action)
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
            [{"name": n} for n in datasette.permissions.keys()],
        )
        # And any dynamic groups
        config = datasette.plugin_config("datasette-acl")
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
    if (not skip_cache) and one_second_cache.get(actor["id"]):
        # Don't do this more than once a second per actor
        return
    one_second_cache.set(actor["id"], 1)
    config = datasette.plugin_config("datasette-acl")
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
                :actor_id, (select id from acl_groups where name = :group_name)
            )""",
            {"actor_id": actor["id"], "group_name": group_name},
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


@hookimpl
def permission_allowed(datasette, actor, action, resource):
    if not resource or len(resource) != 2:
        return None

    async def inner():
        if not actor:
            return False
        await update_dynamic_groups(datasette, actor)
        db = datasette.get_internal_database()
        result = await db.execute(
            ACL_RESOURCE_PAIR_SQL,
            {
                "actor_id": actor["id"],
                "database": resource[0],
                "resource": resource[1],
                "action": action,
            },
        )
        return result.single_value() or None

    return inner


async def debug_acl(request, datasette):
    return Response.json(list(datasette.permissions.items()), default=str)


async def table_acls(request, datasette):
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

    if request.method == "POST":
        # Clear all existing ACLs
        await internal_db.execute_write(
            "DELETE FROM acl WHERE resource_id = ?", [resource_id]
        )
        changes_made = []
        post_vars = await request.post_vars()
        for group in groups:
            for action in [
                "insert-row",
                "delete-row",
                "update-row",
                "alter-table",
                "drop-table",
            ]:
                value = post_vars.get(f"permissions_{group}_{action}")
                if value:
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
                            "group_name": group,
                            "action_name": action,
                            "resource_id": resource_id,
                        },
                    )
                    changes_made.append(f"{group} {action}")

        datasette.add_message(request, f"Made changes: {', '.join(changes_made)}")
        return Response.redirect(request.path)

    permissions = {}
    # Read ACLs for this table
    acl_rows = await internal_db.execute(
        """
        SELECT acl_groups.name as group_name, acl_actions.name as action_name
        FROM acl
        JOIN acl_groups ON acl.group_id = acl_groups.id
        JOIN acl_actions ON acl.action_id = acl_actions.id
        WHERE acl.resource_id = ?
        """,
        [resource_id],
    )
    for row in acl_rows.rows:
        group_name = row["group_name"]
        action_name = row["action_name"]
        if group_name not in permissions:
            permissions[group_name] = {}
        permissions[group_name][action_name] = True

    return Response.html(
        await datasette.render_template(
            "table_acls.html",
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
                "permissions": permissions,
            },
            request=request,
        )
    )


@hookimpl
def register_permissions(datasette):
    return [
        Permission(
            name="datasette-acl",
            abbr=None,
            description="Configure permissions",
            takes_database=False,
            takes_resource=False,
            default=False,
        )
    ]


async def can_edit_permissions(datasette, actor):
    return await datasette.permission_allowed(actor, "datasette-acl")


@hookimpl
def table_actions(datasette, actor, database, table):
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
def register_routes():
    return [
        ("^/-/acl$", debug_acl),
        ("^/(?P<database>[^/]+)/(?P<table>[^/]+)/-/acl$", table_acls),
    ]
