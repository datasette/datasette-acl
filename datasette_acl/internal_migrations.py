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
    """)


@internal_migrations()
def m002_generalize_acl_resources(db: Database):
    # Generalize acl_resources from the table-only (database, resource) shape to
    # (resource_type, parent, child) so any resource type can be tracked.
    # Existing rows are tables, so backfill resource_type='table', preserving
    # ids. SQLite can't rename/retype columns in place, so rewrite the table.
    db.executescript("""
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
    """)
