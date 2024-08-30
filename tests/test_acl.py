from datasette.app import Datasette
from datasette_acl import update_dynamic_groups
import pytest


@pytest.mark.asyncio
async def test_update_dynamic_groups():
    datasette = Datasette(
        config={
            "plugins": {
                "datasette-acl": {
                    "dynamic-groups": {
                        "admin": {"is_admin": True},
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
    # An actor with is_admin: True should be added to the group
    await update_dynamic_groups(
        datasette, {"is_admin": True, "id": "admin"}, skip_cache=True
    )
    assert [dict(r) for r in (await db.execute("select * from acl_groups")).rows] == [
        {"id": 1, "name": "admin"},
    ]
    assert [
        dict(r)
        for r in (
            await db.execute(
                "select actor_id, (select name from acl_groups where id = group_id) as group_name from acl_actor_groups"
            )
        ).rows
    ] == [
        {"actor_id": "admin", "group_name": "admin"},
    ]
    # If that user changes they should drop from the group
    await update_dynamic_groups(
        datasette, {"is_admin": False, "id": "admin"}, skip_cache=True
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
        "insert into acl_actor_groups (actor_id, group_id) values ('admin', 2)"
    )
    await update_dynamic_groups(
        datasette, {"is_admin": False, "id": "admin"}, skip_cache=True
    )
    assert [dict(r) for r in (await db.execute("select * from acl_groups")).rows] == [
        {"id": 1, "name": "admin"},
        {"id": 2, "name": "static"},
    ]


@pytest.mark.asyncio
async def test_permission_allowed():
    datasette = Datasette(
        config={
            "plugins": {
                "datasette-acl": {
                    "dynamic-groups": {
                        "admin": {"is_admin": True},
                    }
                }
            },
            "permissions": {"datasette-acl": {"id": "root"}},
        }
    )
    db = datasette.add_memory_database("db")
    await db.execute_write("create table t (id primary key)")
    await datasette.invoke_startup()
    db = datasette.get_internal_database()
    admin_actor = {"id": "simon", "is_admin": True}
    # That group should exist
    group_id = (
        await db.execute("select id from acl_groups where name = 'admin'")
    ).single_value()
    assert group_id == 1
    allowed = await datasette.permission_allowed(
        actor=admin_actor, action="insert-row", resource=["db", "t"]
    )
    assert not allowed
    # Use the /db/table/-/acl page to insert a permission
    csrf_token_response = await datasette.client.get(
        "/db/t/-/acl",
        cookies={
            "ds_actor": datasette.client.actor_cookie({"id": "root"}),
        },
    )
    csrftoken = csrf_token_response.cookies["ds_csrftoken"]
    response = await datasette.client.post(
        "/db/t/-/acl",
        data={
            "permissions_admin_insert-row": "on",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": datasette.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert response.status_code == 302
    acls = [
        dict(r)
        for r in (
            await db.execute(
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
    assert acls == [
        {
            "group_name": "admin",
            "action_name": "insert-row",
            "database_name": "db",
            "resource_name": "t",
        }
    ]
    allowed = await datasette.permission_allowed(
        actor=admin_actor,
        action="insert-row",
        resource=["db", "t"],
    )
    assert allowed
