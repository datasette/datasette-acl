from collections import namedtuple
from datasette.app import Datasette
from datasette_acl import update_dynamic_groups
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
            post_data={"group_permissions_staff_insert-row": "on"},
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
                    resource=["db", "t"],
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
            setup_post_data={"group_permissions_staff_insert-row": "on"},
            post_data={
                "group_permissions_staff_update-row": "on",
                "group_permissions_staff_delete-row": "on",
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
                    resource=["db", "t"],
                ),
                dict(
                    actor={"id": "simon", "is_staff": True},
                    action="update-row",
                    resource=["db", "t"],
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
                "new_user_insert-row": "on",
                "new_user_update-row": "on",
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
                    resource=["db", "t"],
                ),
                dict(
                    actor={"id": "newbie"},
                    action="update-row",
                    resource=["db", "t"],
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
                "new_user_insert-row": "on",
            },
            post_data={
                "user_permissions_newbie_update-row": "on",
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
                    resource=["db", "t"],
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

    csrf_token_response = await ds.client.get(
        "/db/t/-/acl",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    csrftoken = csrf_token_response.cookies["ds_csrftoken"]

    if setup_post_data:
        setup_response = await ds.client.post(
            "/db/t/-/acl",
            data={**setup_post_data, "csrftoken": csrftoken},
            cookies={
                "ds_actor": ds.client.actor_cookie({"id": "root"}),
                "ds_csrftoken": csrftoken,
            },
        )
        assert setup_response.status_code == 302

    # Permission checks should fail
    for kwargs in should_fail_then_succeed:
        assert not await ds.permission_allowed(**kwargs), f"Should have failed: {repr}"

    # Use the /db/table/-/acl page to update permissions
    response = await ds.client.post(
        "/db/t/-/acl",
        data={**post_data, "csrftoken": csrftoken},
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
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
          acl_resources.database as database_name,
          acl_resources.resource as resource_name
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
    for kwargs in should_fail_then_succeed:
        assert await ds.permission_allowed(
            **kwargs
        ), f"Should have passed: {repr(kwargs)}"

    # Check audit logs
    AUDIT_SQL = """
        select
          acl_groups.name as group_name,
          acl_audit.actor_id,
          acl_actions.name as action_name,
          acl_resources.database as database_name,
          acl_resources.resource as resource_name,
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
          acl_resources.database as database_name,
          acl_resources.resource as resource_name
        from acl
        join acl_actions on acl.action_id = acl_actions.id
        join acl_resources on acl.resource_id = acl_resources.id
        where acl_resources.database = 'db'
        and acl_resources.resource = 'new_table'
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
    assert await datasette.permission_allowed(
        actor={"id": "simon"}, action="insert-row", resource=["db", "new_table"]
    )
    assert await datasette.permission_allowed(
        actor={"id": "simon"}, action="delete-row", resource=["db", "new_table"]
    )
    assert not await datasette.permission_allowed(
        actor={"id": "simon"}, action="update-row", resource=["db", "new_table"]
    )


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
    fragment = '<a href="/db/t/-/acl">Manage table permissions'
    if should_work:
        assert fragment in response.text
    else:
        assert fragment not in response.text
