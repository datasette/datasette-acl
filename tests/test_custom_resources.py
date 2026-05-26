"""
Tests for permission_resources_sql supporting arbitrary resource types (not
just tables). Exercises a throwaway custom resource type registered via a test
plugin and asserts grant resolution through datasette.allowed().
"""

from datasette import hookimpl
from datasette.app import Datasette
from datasette.permissions import Action, Resource
from datasette.plugins import pm
import pytest
import pytest_asyncio


class WidgetResource(Resource):
    """Throwaway two-level resource type used only in these tests."""

    name = "widget"
    parent_class = None  # parent-only; (parent, child) still both stored

    def __init__(self, parent, child=None):
        super().__init__(parent=parent, child=child)

    @classmethod
    async def resources_sql(cls, datasette, actor=None):
        # Advertise the single widget we use in the tests so that
        # allowed_resources()/allowed() have a base resource to match against.
        return "SELECT 'shelf' AS parent, 'gadget' AS child"


class WidgetPlugin:
    __name__ = "WidgetPlugin"

    @hookimpl
    def register_actions(self, datasette):
        return [
            Action(
                name="widget-view",
                description="View a widget",
                resource_class=WidgetResource,
            ),
            Action(
                name="widget-edit",
                description="Edit a widget",
                resource_class=WidgetResource,
            ),
        ]


@pytest_asyncio.fixture
async def widget_ds():
    pm.register(WidgetPlugin(), name="widget-plugin")
    try:
        datasette = Datasette(
            config={
                "permissions": {"datasette-acl": {"id": "root"}},
            }
        )
        db = datasette.add_memory_database("db")
        await db.execute_write("create table t (id primary key)")
        # Plugin is registered before startup so widget-view lands in acl_actions
        await datasette.invoke_startup()
        yield datasette
        internal_db = datasette.get_internal_database()
        for table in await internal_db.table_names():
            if table.startswith("acl"):
                await internal_db.execute_write(f"drop table {table}")
        await db.execute_write("drop table t")
    finally:
        pm.unregister(name="widget-plugin")


async def _grant_actor(datasette, actor_id, resource_type, parent, child, action):
    db = datasette.get_internal_database()
    await db.execute_write(
        "INSERT OR IGNORE INTO acl_resources (resource_type, parent, child) VALUES (?, ?, ?)",
        [resource_type, parent, child],
    )
    await db.execute_write(
        """
        INSERT INTO acl (actor_id, group_id, resource_id, action_id)
        VALUES (
            :actor_id,
            null,
            (SELECT id FROM acl_resources WHERE resource_type = :rt AND parent = :p AND child = :c),
            (SELECT id FROM acl_actions WHERE name = :action)
        )
        """,
        {
            "actor_id": actor_id,
            "rt": resource_type,
            "p": parent,
            "c": child,
            "action": action,
        },
    )


async def _grant_group(datasette, group_name, resource_type, parent, child, action):
    db = datasette.get_internal_database()
    await db.execute_write(
        "INSERT OR IGNORE INTO acl_groups (name) VALUES (?)", [group_name]
    )
    await db.execute_write(
        "INSERT OR IGNORE INTO acl_resources (resource_type, parent, child) VALUES (?, ?, ?)",
        [resource_type, parent, child],
    )
    await db.execute_write(
        """
        INSERT INTO acl (actor_id, group_id, resource_id, action_id)
        VALUES (
            null,
            (SELECT id FROM acl_groups WHERE name = :group_name),
            (SELECT id FROM acl_resources WHERE resource_type = :rt AND parent = :p AND child = :c),
            (SELECT id FROM acl_actions WHERE name = :action)
        )
        """,
        {
            "group_name": group_name,
            "rt": resource_type,
            "p": parent,
            "c": child,
            "action": action,
        },
    )


@pytest.mark.asyncio
async def test_direct_grant_on_custom_resource(widget_ds):
    actor = {"id": "alice"}
    resource = WidgetResource("shelf", "gadget")
    # No grant yet
    assert not await widget_ds.allowed(
        action="widget-view", resource=resource, actor=actor
    )
    # Grant a direct actor permission on the custom resource type
    await _grant_actor(widget_ds, "alice", "widget", "shelf", "gadget", "widget-view")
    assert await widget_ds.allowed(
        action="widget-view", resource=resource, actor=actor
    )
    # A different actor is still denied
    assert not await widget_ds.allowed(
        action="widget-view", resource=resource, actor={"id": "bob"}
    )


@pytest.mark.asyncio
async def test_group_grant_on_custom_resource(widget_ds):
    # Put alice in the widgets group and grant the group access
    db = widget_ds.get_internal_database()
    await db.execute_write("INSERT OR IGNORE INTO acl_groups (name) VALUES ('widgets')")
    await db.execute_write(
        """
        INSERT INTO acl_actor_groups (actor_id, group_id)
        VALUES ('alice', (SELECT id FROM acl_groups WHERE name = 'widgets'))
        """
    )
    await _grant_group(
        widget_ds, "widgets", "widget", "shelf", "gadget", "widget-view"
    )
    resource = WidgetResource("shelf", "gadget")
    assert await widget_ds.allowed(
        action="widget-view", resource=resource, actor={"id": "alice"}
    )
    # An actor not in the group is denied
    assert not await widget_ds.allowed(
        action="widget-view", resource=resource, actor={"id": "carol"}
    )


@pytest.mark.asyncio
async def test_resource_type_does_not_leak(widget_ds):
    # Grant alice access to a *table* resource with the same parent/child
    await _grant_actor(widget_ds, "alice", "table", "shelf", "gadget", "insert-row")
    # That must NOT grant her the widget-view action on the widget resource
    resource = WidgetResource("shelf", "gadget")
    assert not await widget_ds.allowed(
        action="widget-view", resource=resource, actor={"id": "alice"}
    )


@pytest.mark.asyncio
async def test_signed_in_wildcard_grant(widget_ds):
    # Grant _signed_in => any actor with an id is allowed, anonymous is not
    await _grant_actor(
        widget_ds, "_signed_in", "widget", "shelf", "gadget", "widget-view"
    )
    resource = WidgetResource("shelf", "gadget")
    assert await widget_ds.allowed(
        action="widget-view", resource=resource, actor={"id": "anyone"}
    )
    assert not await widget_ds.allowed(
        action="widget-view", resource=resource, actor=None
    )


@pytest.mark.asyncio
async def test_star_wildcard_grant(widget_ds):
    # Grant '*' => literally anyone, including anonymous
    await _grant_actor(widget_ds, "*", "widget", "shelf", "gadget", "widget-view")
    resource = WidgetResource("shelf", "gadget")
    assert await widget_ds.allowed(
        action="widget-view", resource=resource, actor=None
    )
    assert await widget_ds.allowed(
        action="widget-view", resource=resource, actor={"id": "anyone"}
    )


@pytest.mark.asyncio
async def test_anonymous_wildcard_grant(widget_ds):
    # Grant '_anonymous' => only unauthenticated callers; a signed-in actor is not
    # matched by this grant.
    await _grant_actor(
        widget_ds, "_anonymous", "widget", "shelf", "gadget", "widget-view"
    )
    resource = WidgetResource("shelf", "gadget")
    assert await widget_ds.allowed(
        action="widget-view", resource=resource, actor=None
    )
    assert not await widget_ds.allowed(
        action="widget-view", resource=resource, actor={"id": "anyone"}
    )


@pytest.mark.asyncio
async def test_generic_resource_view_lists_dynamic_actions(widget_ds):
    # The generic admin page renders the action set discovered for this resource
    # type (widget-view, widget-edit), not a hardcoded table list.
    response = await widget_ds.client.get(
        "/-/acl/resource/widget/shelf/gadget",
        cookies={"ds_actor": widget_ds.client.actor_cookie({"id": "root"})},
    )
    assert response.status_code == 200
    assert "Permissions for widget: shelf/gadget" in response.text
    assert "widget-view" in response.text
    assert "widget-edit" in response.text
    # Table-only actions must not appear for a widget resource
    assert "insert-row" not in response.text


@pytest.mark.asyncio
async def test_generic_resource_view_requires_permission(widget_ds):
    response = await widget_ds.client.get(
        "/-/acl/resource/widget/shelf/gadget",
        cookies={"ds_actor": widget_ds.client.actor_cookie({"id": "other"})},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_generic_resource_view_unknown_type(widget_ds):
    response = await widget_ds.client.get(
        "/-/acl/resource/nope/shelf/gadget",
        cookies={"ds_actor": widget_ds.client.actor_cookie({"id": "root"})},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_generic_resource_view_grants_via_post(widget_ds):
    actor = {"id": "alice"}
    resource = WidgetResource("shelf", "gadget")
    # No grant yet
    assert not await widget_ds.allowed(
        action="widget-edit", resource=resource, actor=actor
    )
    # Grant widget-edit to alice through the generic admin POST
    response = await widget_ds.client.post(
        "/-/acl/resource/widget/shelf/gadget",
        data={
            "new_actor_id": "alice",
            "new_user_actions": "widget-edit",
        },
        cookies={"ds_actor": widget_ds.client.actor_cookie({"id": "root"})},
    )
    assert response.status_code == 302

    # The acl row exists for the right (resource_type, parent, child)
    internal_db = widget_ds.get_internal_database()
    rows = [
        dict(r)
        for r in (
            await internal_db.execute(
                """
                select
                  acl.actor_id,
                  acl_actions.name as action_name,
                  acl_resources.resource_type,
                  acl_resources.parent,
                  acl_resources.child
                from acl
                join acl_actions on acl.action_id = acl_actions.id
                join acl_resources on acl.resource_id = acl_resources.id
                """
            )
        )
    ]
    assert rows == [
        {
            "actor_id": "alice",
            "action_name": "widget-edit",
            "resource_type": "widget",
            "parent": "shelf",
            "child": "gadget",
        }
    ]

    # And datasette.allowed reflects the new grant
    assert await widget_ds.allowed(
        action="widget-edit", resource=resource, actor=actor
    )
    # The other action is still denied
    assert not await widget_ds.allowed(
        action="widget-view", resource=resource, actor=actor
    )


@pytest.mark.asyncio
async def test_generic_resource_view_revokes_via_post(widget_ds):
    actor = {"id": "alice"}
    resource = WidgetResource("shelf", "gadget")
    await _grant_actor(widget_ds, "alice", "widget", "shelf", "gadget", "widget-edit")
    assert await widget_ds.allowed(
        action="widget-edit", resource=resource, actor=actor
    )
    # POST with the existing user's checkbox unchecked removes the grant
    response = await widget_ds.client.post(
        "/-/acl/resource/widget/shelf/gadget",
        data={
            "user_permissions_alice": "",
        },
        cookies={"ds_actor": widget_ds.client.actor_cookie({"id": "root"})},
    )
    assert response.status_code == 302
    assert not await widget_ds.allowed(
        action="widget-edit", resource=resource, actor=actor
    )
