from datasette import hookimpl, Response

CREATE_TABLES_SQL = """
create table if not exists acl_resources (
    id integer primary key autoincrement,
    database text not null,
    resource text
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
    foreign key (group_id) references groups(id)
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

    return inner


@hookimpl
def permission_allowed(datasette, actor, action, resource):
    if not resource or len(resource) != 2:
        return None

    async def inner():
        if not actor:
            return False
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


@hookimpl
def register_routes():
    return [
        ("^/-/acl$", debug_acl),
    ]
