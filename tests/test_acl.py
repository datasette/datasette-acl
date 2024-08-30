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
    # Group tables should start empty
    assert (await db.execute("select count(*) from acl_groups")).single_value() == 0
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
