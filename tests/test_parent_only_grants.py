"""Tests for parent-only grants on child-bearing resource types.

A grant on ``(resource_type="table", parent=db, child=NULL)`` means "this
action on every table in the database" — core's permission resolution already
cascades a (parent, child=NULL) allow row to all children, and acl's storage
layer already accepts it. These tests cover the HTTP surface that used to
reject such a resource at the ``resource_exists`` gate: the JSON API
(grant/read/revoke), the manage UI page, and the database_actions menu links
that make the page discoverable.
"""

from datasette import hookimpl
from datasette.app import Datasette
from datasette.permissions import Action, Resource
from datasette.plugins import pm
from datasette.resources import DatabaseResource
from datasette_acl.utils import resource_exists
import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def deny_ds():
    """A default-deny instance: two tables, root holds datasette-acl."""
    datasette = Datasette(
        default_deny=True,
        config={"permissions": {"datasette-acl": {"id": "root"}}},
    )
    db = datasette.add_memory_database("scratch")
    await db.execute_write("create table t1 (id integer primary key)")
    await db.execute_write("create table t2 (id integer primary key)")
    await datasette.invoke_startup()
    await datasette.refresh_schemas()
    yield datasette
    # In-memory databases are shared across tests, so drop everything
    for table in ("t1", "t2"):
        await db.execute_write(f"drop table {table}")
    internal_db = datasette.get_internal_database()
    for table in await internal_db.table_names():
        if table.startswith("acl"):
            await internal_db.execute_write(f"drop table {table}")


def _cookie(datasette, actor_id):
    return {"ds_actor": datasette.client.actor_cookie({"id": actor_id})}


@pytest.mark.asyncio
async def test_resource_exists_parent_only(deny_ds):
    # Parent-only table resource exists iff the database does
    assert await resource_exists(deny_ds, "table", "scratch", None)
    assert not await resource_exists(deny_ds, "table", "nope", None)
    # Concrete children behave as before
    assert await resource_exists(deny_ds, "table", "scratch", "t1")
    assert not await resource_exists(deny_ds, "table", "scratch", "missing")
    # Parent-only resource types (database) are unaffected
    assert await resource_exists(deny_ds, "database", "scratch", None)
    assert not await resource_exists(deny_ds, "database", "nope", None)


@pytest.mark.asyncio
async def test_api_parent_only_grant_read_revoke(deny_ds):
    root = _cookie(deny_ds, "root")
    alice = _cookie(deny_ds, "alice")

    # Baseline: alice sees nothing
    assert (await deny_ds.client.get("/scratch.json", cookies=alice)).status_code == 403
    assert (
        await deny_ds.client.get("/scratch/t1.json", cookies=alice)
    ).status_code == 403

    # view-database on the database, view-table on all its tables
    response = await deny_ds.client.post(
        "/-/acl/api/resource/database/scratch/grant",
        json={"actor_id": "alice", "actions": ["view-database"]},
        cookies=root,
    )
    assert response.status_code == 200
    response = await deny_ds.client.post(
        "/-/acl/api/resource/table/scratch/grant",
        json={"actor_id": "alice", "actions": ["view-table"]},
        cookies=root,
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True

    # Alice now sees every table, individually and in the database listing
    for path in ("/scratch/t1.json", "/scratch/t2.json"):
        assert (await deny_ds.client.get(path, cookies=alice)).status_code == 200
    database_json = (await deny_ds.client.get("/scratch.json", cookies=alice)).json()
    assert {t["name"] for t in database_json["tables"]} == {"t1", "t2"}

    # The read endpoint reports the parent-only grant
    response = await deny_ds.client.get(
        "/-/acl/api/resource/table/scratch", cookies=root
    )
    assert response.status_code == 200
    data = response.json()
    assert data["parent"] == "scratch"
    assert data["child"] is None
    assert data["grants"] == [
        {
            "principal": "actor",
            "id": "alice",
            "role": None,
            "actions": ["view-table"],
            "kind": "user",
        }
    ]

    # Revoke removes access to the tables again
    response = await deny_ds.client.post(
        "/-/acl/api/resource/table/scratch/revoke",
        json={"actor_id": "alice"},
        cookies=root,
    )
    assert response.status_code == 200
    assert response.json()["removed"] == ["view-table"]
    assert (
        await deny_ds.client.get("/scratch/t1.json", cookies=alice)
    ).status_code == 403


@pytest.mark.asyncio
async def test_api_parent_only_unknown_database_still_403(deny_ds):
    response = await deny_ds.client.post(
        "/-/acl/api/resource/table/nope/grant",
        json={"actor_id": "alice", "actions": ["view-table"]},
        cookies=_cookie(deny_ds, "root"),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_ui_parent_only_page(deny_ds):
    root = _cookie(deny_ds, "root")
    alice = _cookie(deny_ds, "alice")

    # Admin sees the page, labelled with its database-wide scope
    response = await deny_ds.client.get("/-/acl/resource/table/scratch", cookies=root)
    assert response.status_code == 200
    assert "Every <strong>table</strong> in database <code>scratch</code>" in response.text

    # Non-admins and made-up databases still get the opaque 403
    assert (
        await deny_ds.client.get("/-/acl/resource/table/scratch", cookies=alice)
    ).status_code == 403
    assert (
        await deny_ds.client.get("/-/acl/resource/table/nope", cookies=root)
    ).status_code == 403

    # Granting view-table to a user through the form cascades to every table
    response = await deny_ds.client.post(
        "/-/acl/resource/table/scratch",
        data={"new_actor_id": "alice", "new_user_actions": "view-table"},
        cookies=root,
    )
    assert response.status_code == 302
    for path in ("/scratch/t1.json", "/scratch/t2.json"):
        assert (await deny_ds.client.get(path, cookies=alice)).status_code == 200


class GadgetResource(Resource):
    """Custom two-level resource type whose parent is a database."""

    name = "gadget"
    parent_class = DatabaseResource

    def __init__(self, database, gadget):
        super().__init__(parent=database, child=gadget)

    @classmethod
    async def resources_sql(cls, datasette, actor=None):
        return """
            SELECT 'scratch' AS parent, 'g1' AS child
            UNION ALL SELECT 'scratch', 'g2'
            UNION ALL SELECT 'elsewhere', 'g3'
        """


class GadgetPlugin:
    __name__ = "GadgetPlugin"

    @hookimpl
    def register_actions(self, datasette):
        return [
            Action(
                name="gadget-view",
                description="View a gadget",
                resource_class=GadgetResource,
            )
        ]


@pytest.mark.asyncio
async def test_custom_two_level_resource_parent_only_grant():
    """Parent-only grants work for custom resource types with a parent class."""
    pm.register(GadgetPlugin(), name="gadget-plugin")
    try:
        datasette = Datasette(
            default_deny=True,
            config={"permissions": {"datasette-acl": {"id": "root"}}},
        )
        datasette.add_memory_database("scratch")
        datasette.add_memory_database("elsewhere")
        await datasette.invoke_startup()
        await datasette.refresh_schemas()
        root = _cookie(datasette, "root")
        alice = {"id": "alice"}

        # The parent-level gadget resource exists iff its database does
        assert await resource_exists(datasette, "gadget", "scratch", None)
        assert not await resource_exists(datasette, "gadget", "nope", None)

        # "alice can gadget-view every gadget in database scratch"
        response = await datasette.client.post(
            "/-/acl/api/resource/gadget/scratch/grant",
            json={"actor_id": "alice", "actions": ["gadget-view"]},
            cookies=root,
        )
        assert response.status_code == 200

        # The grant cascades to every gadget under scratch — and only those
        for gadget, expected in (("g1", True), ("g2", True)):
            assert (
                await datasette.allowed(
                    actor=alice,
                    action="gadget-view",
                    resource=GadgetResource("scratch", gadget),
                )
                is expected
            )
        assert not await datasette.allowed(
            actor=alice,
            action="gadget-view",
            resource=GadgetResource("elsewhere", "g3"),
        )

        # A grant against a made-up parent database is still refused
        response = await datasette.client.post(
            "/-/acl/api/resource/gadget/nope/grant",
            json={"actor_id": "alice", "actions": ["gadget-view"]},
            cookies=root,
        )
        assert response.status_code == 403

        internal_db = datasette.get_internal_database()
        for table in await internal_db.table_names():
            if table.startswith("acl"):
                await internal_db.execute_write(f"drop table {table}")
    finally:
        pm.unregister(name="gadget-plugin")


@pytest.mark.asyncio
async def test_database_actions_menu_links(ds):
    # ds (conftest) is default-allow, so root can render the database page
    response = await ds.client.get("/db", cookies=_cookie(ds, "root"))
    assert response.status_code == 200
    assert "/-/acl/resource/database/db" in response.text
    assert "/-/acl/resource/table/db" in response.text
    # Anonymous users don't see the management links
    response = await ds.client.get("/db")
    assert "/-/acl/resource/database/db" not in response.text
