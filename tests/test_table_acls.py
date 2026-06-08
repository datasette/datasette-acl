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


@pytest.mark.asyncio
async def test_acl_resources_migration():
    # Drive the migrations directly: apply everything up to m002 to get the OLD
    # (database, resource) acl_resources schema, insert rows, then run m002 and
    # assert the data migrates to (resource_type, parent, child), backfilling
    # resource_type='table' and preserving id/parent/child values.
    datasette = Datasette(memory=True)
    db = datasette.get_internal_database()

    await db.execute_write_fn(
        lambda conn: internal_migrations.apply(
            Database(conn), stop_before="m002_generalize_acl_resources"
        )
    )

    # m001 created acl_resources with the old (database, resource) columns
    cols_before = [
        r["name"] for r in (await db.execute("PRAGMA table_info(acl_resources)"))
    ]
    assert cols_before == ["id", "database", "resource"]

    await db.execute_write(
        "insert into acl_resources (database, resource) values (?, ?)", ["db1", "t1"]
    )
    await db.execute_write(
        "insert into acl_resources (database, resource) values (?, ?)", ["db2", "t2"]
    )

    # Apply the remaining migrations (m002)
    await db.execute_write_fn(lambda conn: internal_migrations.apply(Database(conn)))

    cols_after = [
        r["name"] for r in (await db.execute("PRAGMA table_info(acl_resources)"))
    ]
    assert cols_after == ["id", "resource_type", "parent", "child"]

    rows = [
        dict(r)
        for r in (await db.execute("select * from acl_resources order by id"))
    ]
    assert rows == [
        {"id": 1, "resource_type": "table", "parent": "db1", "child": "t1"},
        {"id": 2, "resource_type": "table", "parent": "db2", "child": "t2"},
    ]
    # The leftover scratch table must be gone.
    assert "acl_resources_old" not in await db.table_names()

    # Re-applying is idempotent: no error, no duplicate rows.
    await db.execute_write_fn(lambda conn: internal_migrations.apply(Database(conn)))
    rows_again = [
        dict(r)
        for r in (await db.execute("select * from acl_resources order by id"))
    ]
    assert rows_again == rows


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
