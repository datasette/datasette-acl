from datasette import hookimpl
from datasette_acl.utils import get_acl_valid_actors
from datasette.plugins import pm
import pytest


@pytest.fixture
def register_plugin():
    class TestActorIdsPlugin:
        __name__ = "TestActorIdsPlugin"

        @hookimpl
        def datasette_acl_valid_actors(self, datasette):
            async def inner():
                db = datasette.get_internal_database()
                return (
                    await db.execute(
                        "select username as id, upper(username) as display from users"
                    )
                ).dicts()

            return inner

    pm.register(TestActorIdsPlugin(), name="undo")
    try:
        yield
    finally:
        pm.unregister(name="undo")


@pytest.mark.asyncio
async def test_datasette_acl_valid_actors(ds, csrftoken, register_plugin):
    plugins_response = await ds.client.get("/-/plugins.json")
    assert any(
        plugin
        for plugin in plugins_response.json()
        if plugin["name"] == "TestActorIdsPlugin"
    )
    await ds.get_internal_database().execute_write_script(
        """
        create table if not exists users (username text primary key);
        insert or ignore into users (username) values ('one');
        insert or ignore into users (username) values ('two');
        """
    )
    actors = await get_acl_valid_actors(ds)
    assert actors == [("one", "ONE"), ("two", "TWO")]

    to_test = (
        ("one", True),
        ("three", False),
    )

    # Check these are validated when editing permissions
    for actor_id, should_work in to_test:
        response = await ds.client.post(
            "/db/t/-/acl",
            data={
                "new_actor_id": actor_id,
                "new_user_actions": "insert-row",
                "csrftoken": csrftoken,
            },
            cookies={
                "ds_actor": ds.client.actor_cookie({"id": "root"}),
                "ds_csrftoken": csrftoken,
            },
        )
        assert response.status_code == 302
        messages = ds.unsign(response.cookies["ds_messages"], "messages")
        if should_work:
            # Should be a positive message
            assert messages[0][1] == ds.INFO
        else:
            assert messages[0] == ["That user ID is not valid", ds.ERROR]

    # And when editing group members
    for actor_id, should_work in to_test:
        response = await ds.client.post(
            "/-/acl/groups/dev",
            data={
                "add": actor_id,
                "csrftoken": csrftoken,
            },
            cookies={
                "ds_actor": ds.client.actor_cookie({"id": "root"}),
                "ds_csrftoken": csrftoken,
            },
        )
        assert response.status_code == 302
        messages = ds.unsign(response.cookies["ds_messages"], "messages")
        if should_work:
            # Should be a positive message
            assert messages[0][1] == ds.INFO
        else:
            assert messages[0] == ["That user ID is not valid", ds.ERROR]
