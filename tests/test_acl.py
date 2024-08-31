from collections import namedtuple
from datasette.app import Datasette
from datasette_acl import update_dynamic_groups
import pytest

ManageTableTest = namedtuple(
    "ManageTableTest",
    (
        "setup_post_data",
        "post_data",
        "expected_acls",
        "before_should_fail",
        "after_should_succeed",
        "expected_audit_logs",
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ManageTableTest._fields,
    (
        ManageTableTest(
            setup_post_data={},
            post_data={"group_permissions_staff_insert-row": "on"},
            expected_acls=[
                {
                    "group_name": "staff",
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                }
            ],
            before_should_fail=[
                dict(
                    actor={"id": "simon", "is_staff": True},
                    action="insert-row",
                    resource=["db", "t"],
                ),
            ],
            after_should_succeed=[
                dict(
                    actor={"id": "simon", "is_staff": True},
                    action="insert-row",
                    resource=["db", "t"],
                ),
            ],
            expected_audit_logs=[
                {
                    "group_name": "staff",
                    "action_name": "insert-row",
                    "database_name": "db",
                    "resource_name": "t",
                    "operation_by": "root",
                    "operation": "added",
                }
            ],
        ),
    ),
)
async def test_manage_table_permissions(
    setup_post_data,
    post_data,
    expected_acls,
    before_should_fail,
    after_should_succeed,
    expected_audit_logs,
):
    datasette = Datasette(
        config={
            "plugins": {
                "datasette-acl": {
                    "dynamic-groups": {
                        # Users with is_staff: True are in staff group
                        "staff": {"is_staff": True},
                    }
                }
            },
            # Root user can edit permissions
            "permissions": {"datasette-acl": {"id": "root"}},
        }
    )
    db = datasette.add_memory_database("db")
    await db.execute_write("create table t (id primary key)")
    await datasette.invoke_startup()
    internal_db = datasette.get_internal_database()

    # Staff dynamic group should have been created on startup
    assert (
        await internal_db.execute(
            "select count(*) from acl_groups where name = 'staff'"
        )
    ).single_value() == 1

    if setup_post_data:
        setup_response = await datasette.client.post(
            "/db/t/-/acl",
            data={**setup_post_data, "csrftoken": csrftoken},
            cookies={
                "ds_actor": datasette.client.actor_cookie({"id": "root"}),
                "ds_csrftoken": csrftoken,
            },
        )
        assert setup_response.status_code == 302

    # Check before_should_fail conditions
    for condition in before_should_fail:
        assert not await datasette.permission_allowed(**condition)

    assert (
        await internal_db.execute("select count(*) from acl_audit")
    ).single_value() == 0

    # Use the /db/table/-/acl page to update permissions
    csrf_token_response = await datasette.client.get(
        "/db/t/-/acl",
        cookies={
            "ds_actor": datasette.client.actor_cookie({"id": "root"}),
        },
    )
    csrftoken = csrf_token_response.cookies["ds_csrftoken"]
    response = await datasette.client.post(
        "/db/t/-/acl",
        data={**post_data, "csrftoken": csrftoken},
        cookies={
            "ds_actor": datasette.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert response.status_code == 302

    # Check after_should_succeed conditions
    for condition in after_should_succeed:
        assert await datasette.permission_allowed(**condition)

    # Check ACLs
    acls = [
        dict(r)
        for r in (
            await internal_db.execute(
                """
        select
          acl_groups.name as group_name,
          acl_actions.name as action_name,
          acl_resources.database as database_name,
          acl_resources.resource as resource_name
        from acl
        join acl_groups on acl.group_id = acl_groups.id
        join acl_actions on acl.action_id = acl_actions.id
        join acl_resources on acl.resource_id = acl_resources.id
    """
            )
        )
    ]
    assert acls == expected_acls

    # Check audit logs
    AUDIT_SQL = """
        select
          acl_groups.name as group_name,
          acl_actions.name as action_name,
          acl_resources.database as database_name,
          acl_resources.resource as resource_name,
          acl_audit.operation_by,
          acl_audit.operation
        from acl_audit
        join acl_groups on acl_audit.group_id = acl_groups.id
        join acl_actions on acl_audit.action_id = acl_actions.id
        join acl_resources on acl_audit.resource_id = acl_resources.id
        order by acl_audit.id
    """
    audit_rows = [dict(r) for r in (await internal_db.execute(AUDIT_SQL))]
    assert audit_rows == expected_audit_logs

    # Need to manually drop because in-memory databases shared across tests
    await db.execute_write("drop table t")


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
        "acl_resources",
        "acl_actions",
        "acl_groups",
        "acl_actor_groups",
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
        {"id": 1, "name": "staff"},
    ]
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
    # Groups that are not dynamic should not be modified
    await db.execute_write("insert into acl_groups (id, name) values (2, 'static')")
    await db.execute_write(
        "insert into acl_actor_groups (actor_id, group_id) values ('staff', 2)"
    )
    await update_dynamic_groups(
        datasette, {"is_staff": False, "id": "staff"}, skip_cache=True
    )
    assert [dict(r) for r in (await db.execute("select * from acl_groups")).rows] == [
        {"id": 1, "name": "staff"},
        {"id": 2, "name": "static"},
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
    db = datasette.add_memory_database("db")
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
