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


TABLE_ACL_URL = "/-/acl/resource/table/db/t"


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
            TABLE_ACL_URL,
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

    # Use the generic table resource page to update permissions
    response = await ds.client.post(
        TABLE_ACL_URL,
        data={**post_data},
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert response.status_code == 302

    # Check ACLs
    acls = [dict(r) for r in (await internal_db.execute("""
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
    """))]
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
        [dict(r) for r in (await db.execute("""
            select operation, operation_by, group_id, actor_id
            from acl_groups_audit
        """)).rows]
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
        [dict(r) for r in (await db.execute("""
            select operation, operation_by, group_id, actor_id
            from acl_groups_audit order by id desc limit 1
        """)).rows]
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
    acls = [dict(r) for r in (await datasette.get_internal_database().execute("""
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
    """))]
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
    # A fresh internal DB has the (resource_type, parent, child) schema.
    datasette = Datasette(memory=True)
    await datasette.invoke_startup()
    db = datasette.get_internal_database()
    cols = [r["name"] for r in (await db.execute("PRAGMA table_info(acl_resources)"))]
    assert cols == ["id", "resource_type", "parent", "child"]


def test_acl_schema_constraints():
    # A fresh internal DB enforces the acl shape at the SQL layer: the CHECK
    # constraint rejects malformed principal rows and the partial unique
    # indexes dedupe each principal kind. Uses a plain sqlite_utils Database
    # (not Datasette's internal db wrapper, which needs a started-up Datasette)
    # to drive the migrations outside the startup hook.
    import sqlite3

    db = Database(memory=True)
    internal_migrations.apply(db)

    db.execute("insert into acl_resources (resource_type, parent) values ('doc', '42')")
    db.execute("insert into acl_actions (name) values ('doc-view')")
    db.execute("insert into acl_groups (name) values ('staff')")
    insert = (
        "insert into acl (principal_type, actor_id, group_id, resource_id, action_id) "
        "values (?, ?, ?, 1, 1)"
    )
    db.execute(insert, ["actor", "alice", None])
    db.execute(insert, ["group", None, 1])
    db.execute(insert, ["authenticated", None, None])
    assert db.execute("select count(*) from acl").fetchone()[0] == 3

    # The partial unique indexes dedupe per kind: re-inserting an existing
    # (actor / group / audience) grant with OR IGNORE is a no-op.
    db.execute(
        insert.replace("insert into", "insert or ignore into"), ["actor", "alice", None]
    )
    db.execute(
        insert.replace("insert into", "insert or ignore into"), ["group", None, 1]
    )
    db.execute(
        insert.replace("insert into", "insert or ignore into"),
        ["authenticated", None, None],
    )
    assert db.execute("select count(*) from acl").fetchone()[0] == 3

    # An actor whose id merely looks like an old wildcard is an ordinary actor
    # row -- no reserved id namespace exists, so it coexists with the audience.
    db.execute(insert, ["actor", "_signed_in", None])
    assert db.execute("select count(*) from acl").fetchone()[0] == 4

    # CHECK rejects malformed shapes.
    for bad in (
        ("everyone", "bob", None),  # audience with an actor_id
        ("anonymous", None, 1),  # audience with a group_id
        ("actor", None, None),  # actor without an id
        ("actor", "carol", 1),  # actor with a group_id
        ("group", "carol", None),  # group with an actor_id
        ("alien", "dave", None),  # unknown principal_type
    ):
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(insert, list(bad))


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
        f'href="{TABLE_ACL_URL}"' in response.text
        and "Manage table permissions" in response.text
    )
    if should_work:
        assert has_link
    else:
        assert not has_link


@pytest.mark.asyncio
async def test_table_resource_acl_page_actions_are_dynamic(ds):
    # The generic table resource page should offer the action set discovered
    # from datasette.actions (every TableResource-scoped action), not a
    # hardcoded subset. Core registers view-table and set-column-type beyond
    # the original five, so their presence proves discovery is dynamic.
    response = await ds.client.get(
        TABLE_ACL_URL,
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
