"""Schema migrations for datasette-acl (sqlite-migrate).

All ACL tables live in Datasette's internal database. Migrations are
append-only: never edit an existing ``mNNN_`` function once it has shipped,
add a new one instead. They are applied from the ``startup`` hook via
:func:`datasette_acl.internal_migrations.internal_migrations.apply`.
"""

from sqlite_utils import Database
from sqlite_migrate import Migrations

internal_migrations = Migrations("datasette-acl.internal")


@internal_migrations()
def m001_initial(db: Database):
    db.executescript("""
    -- Resources are identified by (resource_type, parent, child); a table is
    -- ('table', database, table_name), other resource types use what they need.
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

    create table if not exists acl_groups (
        id integer primary key,
        name text not null unique,
        deleted integer
    );

    -- actor-group membership
    create table if not exists acl_actor_groups (
        actor_id text,
        group_id integer,
        primary key (actor_id, group_id),
        foreign key (group_id) references acl_groups(id)
    );

    -- group membership audit log
    create table if not exists acl_groups_audit (
        id integer primary key,
        timestamp text default (datetime('now')),
        operation_by text,
        operation text check (operation in ('added', 'removed', 'created', 'deleted')),
        group_id integer,
        actor_id text,
        foreign key (group_id) references acl_groups(id)
    );

    -- A grant's audience is named entirely by principal_type:
    --   'actor'         -> a specific actor_id
    --   'group'         -> a specific group_id
    --   'everyone'      -> any caller, signed in or not (no id)
    --   'authenticated' -> any signed-in caller (no id)
    --   'anonymous'     -> signed-out callers only (no id)
    -- The CHECK pins which of actor_id / group_id may be set for each type.
    create table if not exists acl (
        acl_id integer primary key,
        principal_type text not null
            check (principal_type in (
                'actor', 'group', 'everyone', 'authenticated', 'anonymous'
            )),
        actor_id text,
        group_id integer,
        resource_id integer not null,
        action_id integer not null,
        foreign key (group_id) references acl_groups(id),
        foreign key (resource_id) references acl_resources(id),
        foreign key (action_id) references acl_actions(id),
        check (
            (principal_type = 'actor' and actor_id is not null and group_id is null)
            or (principal_type = 'group' and group_id is not null and actor_id is null)
            or (principal_type in ('everyone', 'authenticated', 'anonymous')
                and actor_id is null and group_id is null)
        )
    );
    -- Partial unique indexes dedupe per principal kind (a plain UNIQUE across
    -- the nullable principal columns wouldn't fire, since SQLite treats NULLs
    -- as distinct).
    create unique index acl_actor_unique
        on acl (actor_id, resource_id, action_id)
        where actor_id is not null;
    create unique index acl_group_unique
        on acl (group_id, resource_id, action_id)
        where group_id is not null;
    create unique index acl_public_unique
        on acl (principal_type, resource_id, action_id)
        where actor_id is null and group_id is null;

    -- ACL audit log
    create table if not exists acl_audit (
        id integer primary key,
        timestamp text default (datetime('now')),
        operation_by text,
        operation text check (operation in ('added', 'removed')),
        principal_type text,
        action_id integer,
        resource_id integer,
        group_id integer,
        actor_id text,
        foreign key (group_id) references acl_groups(id),
        foreign key (resource_id) references acl_resources(id),
        foreign key (action_id) references acl_actions(id)
    );
    """)
