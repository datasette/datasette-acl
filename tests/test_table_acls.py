from collections import namedtuple
from datasette.app import Datasette
from datasette.resources import TableResource
from datasette_acl import update_dynamic_groups
from datasette_acl.internal_migrations import internal_migrations
from sqlite_utils import Database
import pytest


ManageTableTest = namedtuple(
    "ManageTableTest",
    (
        "description",
        "setup_post_data",
        "post_data",
        "expected_acls",
        "should_fail_then_succeed",
        "expected_audit_rows",
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ManageTableTest._fields,
    (
        ManageTableTest(
            description="Group: add insert-row",
            setup_post_data={},
            post_data={"group_permissions_staff": "insert-row"},
            expected_acls=[
                {
                    "group_name": "staff",
                    "actor_id": None,
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                }
            ],
            should_fail_then_succeed=[
                dict(
                    actor={"id": "simon", "is_staff": True},
                    action="insert-row",
                    resource=TableResource("db", "t"),
                ),
            ],
            expected_audit_rows=[
                {
                    "group_name": "staff",
                    "actor_id": None,
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                }
            ],
        ),
        ManageTableTest(
            description="Group: remove insert-row, add update-row and delete-row",
            setup_post_data={"group_permissions_staff": "insert-row"},
            post_data={
                "group_permissions_staff": ["update-row", "delete-row"],
            },
            expected_acls=[
                {
                    "group_name": "staff",
                    "actor_id": None,
                    "action_name": "delete-row",
                    "database_name": "db",
                    "resource_name": "t",
                },
                {
                    "group_name": "staff",
                    "actor_id": None,
                    "action_name": "update-row",
                    "database_name": "db",
                    "resource_name": "t",
                },
            ],
            should_fail_then_succeed=[
                dict(
                    actor={"id": "simon", "is_staff": True},
                    action="delete-row",
                    resource=TableResource("db", "t"),
                ),
                dict(
                    actor={"id": "simon", "is_staff": True},
                    action="update-row",
                    resource=TableResource("db", "t"),
                ),
            ],
            expected_audit_rows=[
                {
                    "group_name": "staff",
                    "actor_id": None,
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                },
                {
                    "group_name": "staff",
                    "actor_id": None,
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "removed",
                },
                {
                    "group_name": "staff",
                    "actor_id": None,
                    "action_name": "delete-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                },
                {
                    "group_name": "staff",
                    "actor_id": None,
                    "action_name": "update-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                },
            ],
        ),
        ManageTableTest(
            description="New user: set with insert-row and update-row",
            setup_post_data={},
            post_data={
                "new_actor_id": "newbie",
                "new_user_actions": ["insert-row", "update-row"],
            },
            expected_acls=[
                {
                    "action_name": "insert-row",
                    "actor_id": "newbie",
                    "database_name": "db",
                    "group_name": None,
                    "resource_name": "t",
                },
                {
                    "action_name": "update-row",
                    "actor_id": "newbie",
                    "database_name": "db",
                    "group_name": None,
                    "resource_name": "t",
                },
            ],
            should_fail_then_succeed=[
                dict(
                    actor={"id": "newbie"},
                    action="insert-row",
                    resource=TableResource("db", "t"),
                ),
                dict(
                    actor={"id": "newbie"},
                    action="update-row",
                    resource=TableResource("db", "t"),
                ),
            ],
            expected_audit_rows=[
                {
                    "group_name": None,
                    "actor_id": "newbie",
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                },
                {
                    "group_name": None,
                    "actor_id": "newbie",
                    "action_name": "update-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                },
            ],
        ),
        ManageTableTest(
            description="Existing user: remove insert-row, add update-row",
            setup_post_data={
                "new_actor_id": "newbie",
                "new_user_actions": "insert-row",
            },
            post_data={
                "user_permissions_newbie": "update-row",
            },
            expected_acls=[
                {
                    "action_name": "update-row",
                    "actor_id": "newbie",
                    "database_name": "db",
                    "group_name": None,
                    "resource_name": "t",
                }
            ],
            should_fail_then_succeed=[
                dict(
                    actor={"id": "newbie"},
                    action="update-row",
                    resource=TableResource("db", "t"),
                ),
            ],
            expected_audit_rows=[
                {
                    "group_name": None,
                    "actor_id": "newbie",
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                },
                {
                    "group_name": None,
                    "actor_id": "newbie",
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "removed",
                },
                {
                    "group_name": None,
                    "actor_id": "newbie",
                    "action_name": "update-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                },
            ],
        ),
    ),
)
async def test_manage_table_permissions(
    ds,
    description,
    setup_post_data,
    post_data,
    expected_acls,
    should_fail_then_succeed,
    expected_audit_rows,
):
    internal_db = ds.get_internal_database()

    # Staff dynamic group should have been created on startup
    assert (
        await internal_db.execute(
            "select count(*) from acl_groups where name = 'staff'"
        )
    ).single_value() == 1

    if setup_post_data:
        setup_response = await ds.client.post(
            "/db/t/-/acl",
            data={**setup_post_data},
            cookies={
                "ds_actor": ds.client.actor_cookie({"id": "root"}),
            },
        )
        assert setup_response.status_code == 302

    # Permission checks should fail
    for item in should_fail_then_succeed:
        assert not await ds.allowed(
            action=item["action"],
            actor=item.get("actor"),
            resource=item.get("resource"),
        ), f"Should have failed: {repr(item)}"

    # Use the /db/table/-/acl page to update permissions
    response = await ds.client.post(
        "/db/t/-/acl",
        data={**post_data},
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert response.status_code == 302

    # Check ACLs
    acls = [
        dict(r)
        for r in (
            await internal_db.execute(
                """
        select
          acl_groups.name as group_name,
          acl.actor_id,
          acl_actions.name as action_name,
          acl_resources.parent as database_name,
          acl_resources.child as resource_name
        from acl
        left join acl_groups on acl.group_id = acl_groups.id
        join acl_actions on acl.action_id = acl_actions.id
        join acl_resources on acl.resource_id = acl_resources.id
    """
            )
        )
    ]
    assert acls == expected_acls

    # Permission checks should pass now
    for item in should_fail_then_succeed:
        assert await ds.allowed(
            action=item["action"],
            actor=item.get("actor"),
            resource=item.get("resource"),
        ), f"Should have passed: {repr(item)}"

    # Check audit logs
    AUDIT_SQL = """
        select
          acl_groups.name as group_name,
          acl_audit.actor_id,
          acl_actions.name as action_name,
          acl_resources.parent as database_name,
          acl_resources.child as resource_name,
          acl_audit.operation_by,
          acl_audit.operation
        from acl_audit
        left join acl_groups on acl_audit.group_id = acl_groups.id
        join acl_actions on acl_audit.action_id = acl_actions.id
        join acl_resources on acl_audit.resource_id = acl_resources.id
        order by acl_audit.id
    """
    audit_rows = [dict(r) for r in (await internal_db.execute(AUDIT_SQL))]
    assert audit_rows == expected_audit_rows


@pytest.mark.asyncio
async def test_update_dynamic_groups():
    datasette = Datasette(
        config={
            "plugins": {
                "datasette-acl": {
                    "dynamic-groups": {
                        "staff": {"is_staff": True},
                    }
                }
            }
        }
    )
    await datasette.invoke_startup()
    db = datasette.get_internal_database()
    # Should have those tables
    tables = await db.table_names()
    assert {
        "acl_actions",
        "acl_actor_groups",
        "acl_audit",
        "acl_groups_audit",
        "acl_groups",
        "acl_resources",
        "acl",
    }.issubset(tables)
    # Group tables should start populated
    assert (await db.execute("select count(*) from acl_groups")).single_value() == 1
    # But no actor groups
    assert (
        await db.execute("select count(*) from acl_actor_groups")
    ).single_value() == 0
    # An actor with is_staff: True should be added to the group
    await update_dynamic_groups(
        datasette, {"is_staff": True, "id": "staff"}, skip_cache=True
    )
    assert [dict(r) for r in (await db.execute("select * from acl_groups")).rows] == [
        {"id": 1, "name": "staff", "deleted": None},
    ]
    # Should record an added groups audit record
    assert (
        [
            dict(r)
            for r in (
                await db.execute(
                    """
            select operation, operation_by, group_id, actor_id
            from acl_groups_audit
        """
                )
            ).rows
        ]
        == [
            {
                "operation": "added",
                "operation_by": None,
                "group_id": 1,
                "actor_id": "staff",
            },
        ]
    )
    assert [
        dict(r)
        for r in (
            await db.execute(
                "select actor_id, (select name from acl_groups where id = group_id) as group_name from acl_actor_groups"
            )
        ).rows
    ] == [
        {"actor_id": "staff", "group_name": "staff"},
    ]
    # If that user changes they should drop from the group
    await update_dynamic_groups(
        datasette, {"is_staff": False, "id": "staff"}, skip_cache=True
    )
    assert [
        dict(r)
        for r in (
            await db.execute(
                "select actor_id, (select name from acl_groups where id = group_id) as group_name from acl_actor_groups"
            )
        ).rows
    ] == []
    # Should record a removed groups audit record
    assert (
        [
            dict(r)
            for r in (
                await db.execute(
                    """
            select operation, operation_by, group_id, actor_id
            from acl_groups_audit order by id desc limit 1
        """
                )
            ).rows
        ]
        == [
            {
                "operation": "removed",
                "operation_by": None,
                "group_id": 1,
                "actor_id": "staff",
            },
        ]
    )
    # Groups that are not dynamic should not be modified
    await db.execute_write("insert into acl_groups (id, name) values (2, 'static')")
    await db.execute_write(
        "insert into acl_actor_groups (actor_id, group_id) values ('staff', 2)"
    )
    await update_dynamic_groups(
        datasette, {"is_staff": False, "id": "staff"}, skip_cache=True
    )
    assert [dict(r) for r in (await db.execute("select * from acl_groups")).rows] == [
        {"id": 1, "name": "staff", "deleted": None},
        {"id": 2, "name": "static", "deleted": None},
    ]


@pytest.mark.asyncio
async def test_table_creator_permissions():
    datasette = Datasette(
        config={
            "plugins": {
                "datasette-acl": {
                    "table-creator-permissions": [
                        "insert-row",
                        "delete-row",
                    ]
                }
            },
            "permissions": {"create-table": {"id": "*"}},
        }
    )
    await datasette.invoke_startup()
    datasette.add_memory_database("db")
    # Create a table
    actor_cookie = datasette.client.actor_cookie({"id": "simon"})
    create_response = await datasette.client.post(
        "/db/-/create",
        json={
            "table": "new_table",
            "columns": [
                {"name": "id", "type": "integer"},
                {"name": "title", "type": "text"},
            ],
            "pk": "id",
        },
        cookies={"ds_actor": actor_cookie},
    )
    assert create_response.status_code == 201
    # That table should have insert-row and delete-row ACLs
    acls = [
        dict(r)
        for r in (
            await datasette.get_internal_database().execute(
                """
        select
          acl.actor_id,
          acl_actions.name as action_name,
          acl_resources.parent as database_name,
          acl_resources.child as resource_name
        from acl
        join acl_actions on acl.action_id = acl_actions.id
        join acl_resources on acl.resource_id = acl_resources.id
        where acl_resources.parent = 'db'
        and acl_resources.child = 'new_table'
    """
            )
        )
    ]
    assert acls == [
        {
            "actor_id": "simon",
            "action_name": "insert-row",
            "database_name": "db",
            "resource_name": "new_table",
        },
        {
            "actor_id": "simon",
            "action_name": "delete-row",
            "database_name": "db",
            "resource_name": "new_table",
        },
    ]
    # Permission checks too
    assert await datasette.allowed(
        actor={"id": "simon"},
        action="insert-row",
        resource=TableResource("db", "new_table"),
    )
    assert await datasette.allowed(
        actor={"id": "simon"},
        action="delete-row",
        resource=TableResource("db", "new_table"),
    )
    assert not await datasette.allowed(
        actor={"id": "simon"},
        action="update-row",
        resource=TableResource("db", "new_table"),
    )


@pytest.mark.asyncio
async def test_fresh_acl_resources_schema():
    # A fresh internal DB should get the new (resource_type, parent, child) schema.
    datasette = Datasette(memory=True)
    await datasette.invoke_startup()
    db = datasette.get_internal_database()
    cols = [r["name"] for r in (await db.execute("PRAGMA table_info(acl_resources)"))]
    assert cols == ["id", "resource_type", "parent", "child"]


def test_acl_resources_migration():
    # Drive the migrations directly: apply everything up to m002 to get the OLD
    # (database, resource) acl_resources schema, insert rows, then run m002 and
    # assert the data migrates to (resource_type, parent, child), backfilling
    # resource_type='table' and preserving id/parent/child values. Uses a plain
    # sqlite_utils Database (not Datasette's internal db wrapper): the wrapper
    # tracks schema changes and dispatches events, which requires a started-up
    # Datasette, while this test exists precisely to drive the migrations
    # outside the startup hook.
    db = Database(memory=True)
    internal_migrations.apply(db, stop_before="m002_generalize_acl_resources")

    # m001 created acl_resources with the old (database, resource) columns
    cols_before = [r[1] for r in db.execute("PRAGMA table_info(acl_resources)")]
    assert cols_before == ["id", "database", "resource"]

    db.execute(
        "insert into acl_resources (database, resource) values (?, ?)", ["db1", "t1"]
    )
    db.execute(
        "insert into acl_resources (database, resource) values (?, ?)", ["db2", "t2"]
    )

    # Apply the remaining migrations (m002 onwards)
    internal_migrations.apply(db)

    cols_after = [r[1] for r in db.execute("PRAGMA table_info(acl_resources)")]
    assert cols_after == ["id", "resource_type", "parent", "child"]

    rows = list(db["acl_resources"].rows)
    assert rows == [
        {"id": 1, "resource_type": "table", "parent": "db1", "child": "t1"},
        {"id": 2, "resource_type": "table", "parent": "db2", "child": "t2"},
    ]
    # The leftover scratch table must be gone.
    assert "acl_resources_old" not in db.table_names()

    # Re-applying is idempotent: no error, no duplicate rows.
    internal_migrations.apply(db)
    rows_again = list(db["acl_resources"].rows)
    assert rows_again == rows


def test_principal_type_migrations():
    # Apply up to (not including) m003 to get the original acl shape, insert
    # original-shape rows -- an in-band wildcard actor row, a real actor, a
    # group grant and an exact duplicate pair (possible before m003 because
    # the original UNIQUE constraint never fired across NULLs) -- plus audit
    # rows, then run the remaining migrations (m003 + m004). The end state is
    # the audience model: the wildcard row becomes principal_type
    # 'authenticated' with no id, duplicates collapse, ids are preserved.
    db = Database(memory=True)
    internal_migrations.apply(db, stop_before="m003_principal_type")

    cols_before = [r[1] for r in db.execute("PRAGMA table_info(acl)")]
    assert "principal_type" not in cols_before

    db.execute("insert into acl_resources (resource_type, parent) values ('doc', '42')")
    db.execute("insert into acl_actions (name) values ('doc-view')")
    db.execute("insert into acl_groups (name) values ('staff')")
    insert = "insert into acl (actor_id, group_id, resource_id, action_id) values (?, ?, 1, 1)"
    db.execute(insert, ["_signed_in", None])  # (a) in-band wildcard row
    db.execute(insert, ["alice", None])  # (b) real-actor row
    db.execute(insert, [None, 1])  # (c) group row
    db.execute(insert, ["alice", None])  # (d) exact duplicate of (b)
    db.execute(
        """
        insert into acl_audit (operation, actor_id, group_id, resource_id, action_id)
        values ('added', '_signed_in', null, 1, 1),
               ('added', 'alice', null, 1, 1),
               ('added', null, 1, 1, 1)
        """
    )

    internal_migrations.apply(db)

    rows = list(
        db.query(
            "select acl_id, principal_type, actor_id, group_id from acl order by acl_id"
        )
    )
    # Types backfilled, the legacy wildcard translated to its audience type
    # (with no id), the duplicate pair collapsed to one row, ids preserved.
    assert rows == [
        {"acl_id": 1, "principal_type": "authenticated", "actor_id": None, "group_id": None},
        {"acl_id": 2, "principal_type": "actor", "actor_id": "alice", "group_id": None},
        {"acl_id": 3, "principal_type": "group", "actor_id": None, "group_id": 1},
    ]
    assert "acl_old" not in db.table_names()

    # Audit history backfilled with the same classification.
    audit = list(
        db.query("select principal_type, actor_id, group_id from acl_audit order by id")
    )
    assert audit == [
        {"principal_type": "authenticated", "actor_id": None, "group_id": None},
        {"principal_type": "actor", "actor_id": "alice", "group_id": None},
        {"principal_type": "group", "actor_id": None, "group_id": 1},
    ]

    # The partial unique indexes actually dedupe: INSERT OR IGNORE of an
    # existing (actor, resource, action) is a no-op.
    db.execute(
        "insert or ignore into acl (principal_type, actor_id, group_id, resource_id, action_id) "
        "values ('actor', 'alice', null, 1, 1)"
    )
    assert db.execute("select count(*) from acl").fetchone()[0] == 3
    # ...and a duplicate audience row is also a no-op (acl_public_unique).
    db.execute(
        "insert or ignore into acl (principal_type, actor_id, group_id, resource_id, action_id) "
        "values ('authenticated', null, null, 1, 1)"
    )
    assert db.execute("select count(*) from acl").fetchone()[0] == 3
    # An actor whose id merely looks like an old wildcard is an ordinary actor
    # row, coexisting with the audience grant.
    db.execute(
        "insert or ignore into acl (principal_type, actor_id, group_id, resource_id, action_id) "
        "values ('actor', '_signed_in', null, 1, 1)"
    )
    assert db.execute("select count(*) from acl").fetchone()[0] == 4

    # CHECK constraints reject malformed shapes at the SQL layer.
    import sqlite3

    for bad in (
        ("everyone", "bob", None),  # audience with an actor_id
        ("anonymous", None, 1),  # audience with a group_id
        ("actor", None, None),  # actor without an id
        ("actor", "carol", 1),  # actor with a group_id
        ("group", "carol", None),  # group with an actor_id
        ("alien", "dave", None),  # unknown principal_type
    ):
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "insert into acl (principal_type, actor_id, group_id, resource_id, action_id) "
                "values (?, ?, ?, 1, 1)",
                list(bad),
            )

    # Re-applying is idempotent.
    internal_migrations.apply(db)
    assert db.execute("select count(*) from acl").fetchone()[0] == 4


def test_public_principal_types_migration():
    # m004 specifically: start from the intermediate m003 shape (audiences
    # stored in-band as 'public' rows with wildcard actor_ids), insert every
    # wildcard plus a coexisting like-named actor row, then run m004 and
    # assert each 'public' row converts to its audience type with the id
    # dropped -- while actor and group rows pass through untouched.
    db = Database(memory=True)
    internal_migrations.apply(db, stop_before="m004_public_principal_types")

    db.execute("insert into acl_resources (resource_type, parent) values ('doc', '42')")
    db.execute("insert into acl_actions (name) values ('doc-view')")
    db.execute("insert into acl_groups (name) values ('staff')")
    insert = (
        "insert into acl (principal_type, actor_id, group_id, resource_id, action_id) "
        "values (?, ?, ?, 1, 1)"
    )
    db.execute(insert, ["public", "*", None])
    db.execute(insert, ["public", "_signed_in", None])
    db.execute(insert, ["public", "_anonymous", None])
    db.execute(insert, ["actor", "_signed_in", None])  # like-named real actor
    db.execute(insert, ["group", None, 1])
    db.execute(
        """
        insert into acl_audit (operation, principal_type, actor_id, group_id, resource_id, action_id)
        values ('added', 'public', '*', null, 1, 1),
               ('added', 'actor', '_signed_in', null, 1, 1)
        """
    )

    internal_migrations.apply(db)

    rows = list(
        db.query(
            "select acl_id, principal_type, actor_id, group_id from acl order by acl_id"
        )
    )
    assert rows == [
        {"acl_id": 1, "principal_type": "everyone", "actor_id": None, "group_id": None},
        {"acl_id": 2, "principal_type": "authenticated", "actor_id": None, "group_id": None},
        {"acl_id": 3, "principal_type": "anonymous", "actor_id": None, "group_id": None},
        {"acl_id": 4, "principal_type": "actor", "actor_id": "_signed_in", "group_id": None},
        {"acl_id": 5, "principal_type": "group", "actor_id": None, "group_id": 1},
    ]
    assert "acl_old" not in db.table_names()

    audit = list(
        db.query("select principal_type, actor_id from acl_audit order by id")
    )
    assert audit == [
        {"principal_type": "everyone", "actor_id": None},
        {"principal_type": "actor", "actor_id": "_signed_in"},
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("should_work", (True, False))
async def test_table_actions(ds, should_work):
    response = await ds.client.get(
        "/db/t",
        cookies={
            "ds_actor": ds.client.actor_cookie(
                {"id": "root" if should_work else "other"}
            ),
        },
    )
    # 1.0a30 renders menu links with extra attrs (role/tabindex), so match the
    # href + label rather than an exact anchor tag.
    has_link = (
        'href="/db/t/-/acl"' in response.text
        and "Manage table permissions" in response.text
    )
    if should_work:
        assert has_link
    else:
        assert not has_link


@pytest.mark.asyncio
async def test_table_acl_page_actions_are_dynamic(ds):
    # The table permissions page should offer the action set discovered from
    # datasette.actions (every TableResource-scoped action), not a hardcoded
    # subset. Core registers view-table and set-column-type beyond the original
    # five, so their presence proves discovery is dynamic.
    response = await ds.client.get(
        "/db/t/-/acl",
        cookies={"ds_actor": ds.client.actor_cookie({"id": "root"})},
    )
    assert response.status_code == 200
    for action in (
        "insert-row",
        "delete-row",
        "update-row",
        "alter-table",
        "drop-table",
        "view-table",
        "set-column-type",
    ):
        assert action in response.text
