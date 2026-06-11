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


@internal_migrations()
def m003_principal_type(db: Database):
    # Add an explicit principal_type discriminator to acl. Wildcard "general
    # access" principals ('*', '_signed_in', '_anonymous') were stored in-band
    # as actor_id values and recognized everywhere by string comparison, so a
    # real user whose id collided with a wildcard inherited its grants. The
    # rebuild also replaces the old UNIQUE(actor_id, group_id, ...) constraint,
    # which never fired (exactly one principal column is always NULL and SQLite
    # treats NULLs as distinct in unique indexes), with partial unique indexes
    # that actually dedupe. Backfilling wildcard actor_ids as 'public' matches
    # the enforcement semantics those rows already had. Same
    # rename/recreate/copy/drop pattern as m002; the GROUP BY collapses any
    # duplicates the dead UNIQUE let through, min(acl_id) keeps stable ids.
    db.executescript("""
    ALTER TABLE acl RENAME TO acl_old;
    CREATE TABLE acl (
        acl_id integer primary key,
        principal_type text not null
            check (principal_type in ('actor', 'group', 'public')),
        actor_id text,
        group_id integer,
        resource_id integer not null,
        action_id integer not null,
        foreign key (group_id) references acl_groups(id),
        foreign key (resource_id) references acl_resources(id),
        foreign key (action_id) references acl_actions(id),
        check (
            (principal_type = 'group' and group_id is not null and actor_id is null)
            or (principal_type in ('actor', 'public')
                and actor_id is not null and group_id is null)
        ),
        -- Closed wildcard set; must stay in sync with utils.PUBLIC_PRINCIPALS.
        -- Adding a fourth wildcard requires a deliberate migration.
        check (
            principal_type != 'public'
            or actor_id in ('*', '_signed_in', '_anonymous')
        )
    );
    CREATE UNIQUE INDEX acl_actor_unique
        ON acl (principal_type, actor_id, resource_id, action_id)
        WHERE actor_id IS NOT NULL;
    CREATE UNIQUE INDEX acl_group_unique
        ON acl (group_id, resource_id, action_id)
        WHERE group_id IS NOT NULL;
    INSERT INTO acl (acl_id, principal_type, actor_id, group_id, resource_id, action_id)
    SELECT
        min(acl_id),
        CASE
            WHEN group_id IS NOT NULL THEN 'group'
            WHEN actor_id IN ('*', '_signed_in', '_anonymous') THEN 'public'
            ELSE 'actor'
        END,
        actor_id, group_id, resource_id, action_id
    FROM acl_old
    GROUP BY actor_id, group_id, resource_id, action_id;
    DROP TABLE acl_old;

    ALTER TABLE acl_audit ADD COLUMN principal_type text;
    UPDATE acl_audit SET principal_type = CASE
        WHEN group_id IS NOT NULL THEN 'group'
        WHEN actor_id IN ('*', '_signed_in', '_anonymous') THEN 'public'
        ELSE 'actor'
    END;
    """)


@internal_migrations()
def m004_public_principal_types(db: Database):
    # Promote the public audiences to first-class principal types. m003 kept
    # the legacy wildcard ids ('*', '_signed_in', '_anonymous') stored in-band
    # as actor_id values under a single 'public' type; this rebuild retires
    # them from the schema entirely: principal_type itself names the audience
    # ('everyone' / 'authenticated' / 'anonymous') and public rows store no id
    # at all. Enforcement and application code match on principal_type alone,
    # so no reserved actor-id namespace exists anywhere outside this migration
    # (which mentions the old strings only to translate rows written before
    # it). An actor literally named '_signed_in' is now just an ordinary actor
    # row -- the collision class m003 guarded against is gone by construction.
    # The old partial unique indexes are dropped by name before recreation
    # (index names are database-global, so they would collide with acl_old's).
    db.executescript("""
    ALTER TABLE acl RENAME TO acl_old;
    DROP INDEX IF EXISTS acl_actor_unique;
    DROP INDEX IF EXISTS acl_group_unique;
    CREATE TABLE acl (
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
    CREATE UNIQUE INDEX acl_actor_unique
        ON acl (actor_id, resource_id, action_id)
        WHERE actor_id IS NOT NULL;
    CREATE UNIQUE INDEX acl_group_unique
        ON acl (group_id, resource_id, action_id)
        WHERE group_id IS NOT NULL;
    CREATE UNIQUE INDEX acl_public_unique
        ON acl (principal_type, resource_id, action_id)
        WHERE actor_id IS NULL AND group_id IS NULL;
    INSERT INTO acl (acl_id, principal_type, actor_id, group_id, resource_id, action_id)
    SELECT
        acl_id,
        CASE
            WHEN principal_type = 'public' AND actor_id = '*' THEN 'everyone'
            WHEN principal_type = 'public' AND actor_id = '_signed_in' THEN 'authenticated'
            WHEN principal_type = 'public' AND actor_id = '_anonymous' THEN 'anonymous'
            ELSE principal_type
        END,
        CASE WHEN principal_type = 'public' THEN NULL ELSE actor_id END,
        group_id, resource_id, action_id
    FROM acl_old;
    DROP TABLE acl_old;

    UPDATE acl_audit SET
        principal_type = CASE actor_id
            WHEN '*' THEN 'everyone'
            WHEN '_signed_in' THEN 'authenticated'
            WHEN '_anonymous' THEN 'anonymous'
            ELSE principal_type
        END,
        actor_id = NULL
    WHERE principal_type = 'public';
    """)
