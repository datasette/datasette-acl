from datasette import hookimpl
from datasette.events import CreateTableEvent
from datasette.permissions import Action, PermissionSQL
from datasette.utils import actor_matches_allow
from datasette.plugins import pm
from datasette_acl.utils import can_edit_permissions
from datasette_acl.views.table_acls import manage_table_acls
from datasette_acl.views.resource_acls import manage_resource_acls
from datasette_acl.views.groups import manage_groups, manage_group
from datasette_acl.views.api import resource_grants_json
from datasette_acl.roles import build_roles_registry
from . import hookspecs
import json
import sys
import time

pm.add_hookspecs(hookspecs)

CREATE_TABLES_SQL = """
create table if not exists acl_resources (
    id integer primary key,
    resource_type text not null,
    parent text not null,
    child text,
    unique(resource_type, parent, child)
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
        # Migrate old acl_resources (database, resource) schema to the
        # generalized (resource_type, parent, child) schema. Feature-detect by
        # probing for the resource_type column; if it is missing we have the
        # old schema and rewrite the table, backfilling resource_type='table'.
        try:
            await db.execute("select resource_type from acl_resources limit 0")
        except Exception:
            await db.execute_write_script(
                """
                ALTER TABLE acl_resources RENAME TO acl_resources_old;
                CREATE TABLE acl_resources (
                    id integer primary key,
                    resource_type text not null,
                    parent text not null,
                    child text,
                    unique(resource_type, parent, child)
                );
                INSERT INTO acl_resources (id, resource_type, parent, child)
                    SELECT id, 'table', database, resource FROM acl_resources_old;
                DROP TABLE acl_resources_old;
                """
            )
        # Ensure permissions are in the DB
        await db.execute_write_many(
            """
            insert or ignore into acl_actions (name) values (:name)
        """,
            [{"name": name} for name in datasette.actions.keys()],
        )
        # And any dynamic groups
        config = datasette.plugin_config("datasette-acl") or {}
        groups = config.get("dynamic-groups")
        if groups:
            await db.execute_write_many(
                "insert or ignore into acl_groups (name) values (:name)",
                [{"name": name} for name in groups.keys()],
            )
        # Collect friendly roles declared by plugins via datasette_acl_roles
        # into a registry keyed by resource_type and stash it on datasette.
        # Re-gathering is cheap; we do it once at startup.
        datasette._acl_roles_registry = await build_roles_registry(datasette)

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
    if resource_class is None:
        # Global-only actions: nothing for ACL to contribute
        return None

    async def inner():
        actor_id = actor.get("id") if actor else None
        if actor_id:
            await update_dynamic_groups(
                datasette, actor, skip_cache=hasattr(sys, "_pytest_running")
            )
        # General-access (wildcard) principals always apply:
        #   '*'          -> anyone, including anonymous
        #   '_signed_in' -> any actor that has an id (only when signed in)
        # Direct actor grants and group grants only apply when signed in.
        # NOTE: this must be a single SELECT statement with no leading CTE
        # (WITH ...). Datasette core inlines this SQL after a "UNION ALL" when
        # building its anon_rules block for include_is_private queries, and a
        # leading WITH there is a SQLite syntax error. The actor-groups lookup
        # is therefore expressed as an inline subquery rather than a CTE.
        return PermissionSQL(
            sql="""
SELECT
    ar.parent AS parent,
    ar.child AS child,
    1 AS allow,
    'datasette-acl: ' || GROUP_CONCAT(
        CASE
            WHEN a.actor_id IS NOT NULL
                THEN 'actor:' || a.actor_id
            ELSE 'group:' || g.name
        END,
        ', '
    ) AS reason
FROM acl a
JOIN acl_actions aa ON a.action_id = aa.id
JOIN acl_resources ar ON a.resource_id = ar.id
LEFT JOIN acl_groups g ON a.group_id = g.id
WHERE aa.name = :action
  AND ar.resource_type = :resource_type
  AND (
    a.actor_id = '*'
    OR (:actor_id IS NOT NULL AND a.actor_id = :actor_id)
    OR (:actor_id IS NOT NULL AND a.actor_id = '_signed_in')
    OR a.group_id IN (
        SELECT ag.group_id
        FROM acl_actor_groups ag
        JOIN acl_groups ig ON ag.group_id = ig.id
        WHERE :actor_id IS NOT NULL
          AND ag.actor_id = :actor_id
          AND ig.deleted IS NULL
    )
  )
  AND (a.group_id IS NULL OR g.deleted IS NULL)
GROUP BY ar.parent, ar.child
            """,
            params={
                "actor_id": actor_id,
                "resource_type": resource_class.name,
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
            "INSERT OR IGNORE INTO acl_resources (resource_type, parent, child) VALUES ('table', ?, ?);",
            [event.database, event.table],
        )
        resource_id = (
            await db.execute(
                "SELECT id FROM acl_resources WHERE resource_type = 'table' AND parent = ? AND child = ?",
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
        # Generic per-resource-type admin page. The child segment is optional
        # so parent-only resource types (e.g. a database) are also managed here.
        (
            "^/-/acl/resource/(?P<resource_type>[^/]+)/(?P<parent>[^/]+)/(?P<child>[^/]+)$",
            manage_resource_acls,
        ),
        (
            "^/-/acl/resource/(?P<resource_type>[^/]+)/(?P<parent>[^/]+)$",
            manage_resource_acls,
        ),
        # JSON API (phase-02). The child segment is optional so parent-only
        # resource types resolve through the same route.
        (
            "^/-/acl/api/resource/(?P<resource_type>[^/]+)/(?P<parent>[^/]+)/(?P<child>[^/]+)$",
            resource_grants_json,
        ),
        (
            "^/-/acl/api/resource/(?P<resource_type>[^/]+)/(?P<parent>[^/]+)$",
            resource_grants_json,
        ),
    ]
