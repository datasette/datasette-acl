"""Tests for the JSON read endpoint (task 03):

    GET /-/acl/api/resource/{resource_type}/{parent}/{child}

Seeds actor / group / public-audience grants on a mock resource and asserts the
JSON shape: grants grouped by principal with a resolved role, actor enrichment
from a fake ``actors_from_ids`` test plugin (display name / email / avatar /
kind), group ``member_count``, public audiences flagged ``kind:"public"``, and
the ``roles`` registry + ``can_manage`` flag.
"""

from datasette import hookimpl
from datasette.app import Datasette
from datasette.permissions import Action, Resource
from datasette.plugins import pm
from datasette_acl.grants import grant, Principal
from datasette_acl.roles import AclRole
import pytest
import pytest_asyncio


class DocResource(Resource):
    """Parent-only mock resource type used by these tests."""

    name = "mock-doc"
    parent_class = None

    def __init__(self, parent, child=None):
        super().__init__(parent=parent, child=child)

    @classmethod
    async def resources_sql(cls, datasette, actor=None):
        return "SELECT '42' AS parent, NULL AS child"


DOC_ROLES = [
    AclRole("mock-doc", "Viewer", ["doc-view"], rank=1),
    AclRole("mock-doc", "Editor", ["doc-view", "doc-edit"], rank=2),
    AclRole(
        "mock-doc",
        "Manager",
        ["doc-view", "doc-edit", "doc-manage"],
        rank=3,
        manage=True,
    ),
]

# Fake directory the test plugin's actors_from_ids resolves against. Includes a
# user and an agent (with kind) so enrichment + kind passthrough are exercised.
FAKE_ACTORS = {
    "alice": {
        "id": "alice",
        "display_name": "Alice Garcia",
        "email": "alice@example.com",
        "avatar_url": "/-/profile/pic/alice",
        "kind": "user",
    },
    "agent:researcher": {
        "id": "agent:researcher",
        "display_name": "Researcher",
        "avatar_url": "/-/agent/pic/researcher",
        "kind": "agent",
    },
}


class ApiDocPlugin:
    __name__ = "ApiDocPlugin"

    @hookimpl
    def register_actions(self, datasette):
        return [
            Action(name="doc-view", description="View", resource_class=DocResource),
            Action(name="doc-edit", description="Edit", resource_class=DocResource),
            Action(
                name="doc-manage", description="Manage", resource_class=DocResource
            ),
        ]

    @hookimpl
    def datasette_acl_roles(self, datasette):
        return list(DOC_ROLES)

    @hookimpl
    def actors_from_ids(self, datasette, actor_ids):
        # Resolve known ids; unknown ids fall back to {"id": id} (mirrors the
        # core default so the endpoint still returns a usable grant).
        return {
            actor_id: FAKE_ACTORS.get(actor_id, {"id": actor_id})
            for actor_id in actor_ids
        }


@pytest_asyncio.fixture
async def api_ds():
    plugin = ApiDocPlugin()
    pm.register(plugin, name="api-doc-plugin")
    try:
        datasette = Datasette(
            config={"permissions": {"datasette-acl": {"id": "root"}}}
        )
        await datasette.invoke_startup()
        await datasette.get_internal_database().execute_write(
            "INSERT INTO acl_groups (name) VALUES ('staff')"
        )
        yield datasette
        internal_db = datasette.get_internal_database()
        for table in await internal_db.table_names():
            if table.startswith("acl"):
                await internal_db.execute_write(f"drop table {table}")
    finally:
        pm.unregister(name="api-doc-plugin")


async def _group_id(datasette, name):
    return (
        await datasette.get_internal_database().execute(
            "SELECT id FROM acl_groups WHERE name = ?", [name]
        )
    ).single_value()


def _root_cookie(datasette):
    return {"ds_actor": datasette.client.actor_cookie({"id": "root"})}


async def _get(datasette, path, cookies=None):
    return await datasette.client.get(path, cookies=cookies or {})


# --- gating ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_requires_manage(api_ds):
    # Anonymous / non-manager is forbidden.
    response = await _get(api_ds, "/-/acl/api/resource/mock-doc/42")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_read_unknown_resource_type(api_ds):
    response = await _get(
        api_ds, "/-/acl/api/resource/nope/42", cookies=_root_cookie(api_ds)
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_read_nonexistent_resource_forbidden(api_ds):
    # issue #43: mock-doc only advertises parent "42" (DocResource.resources_sql).
    # Reading grants for a made-up parent must 403 (same as an unauthorized
    # resource, so existence is not leaked) and must not conjure an
    # acl_resources row via the list_grants upsert.
    response = await _get(
        api_ds, "/-/acl/api/resource/mock-doc/made-up", cookies=_root_cookie(api_ds)
    )
    assert response.status_code == 403
    rows = await api_ds.get_internal_database().execute(
        "select 1 from acl_resources where resource_type = 'mock-doc' and parent = 'made-up'"
    )
    assert rows.rows == []


@pytest.mark.asyncio
async def test_per_resource_manager_can_read(api_ds):
    # Grant alice the Manager role (which includes the manage action) and prove
    # she can read the endpoint without the global datasette-acl permission.
    await grant(
        api_ds,
        "mock-doc",
        "42",
        principal=Principal.actor("alice"),
        role="Manager",
        by_actor="root",
    )
    cookies = {"ds_actor": api_ds.client.actor_cookie({"id": "alice"})}
    response = await _get(api_ds, "/-/acl/api/resource/mock-doc/42", cookies=cookies)
    assert response.status_code == 200
    assert response.json()["can_manage"] is True


# --- shape ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_full_shape(api_ds):
    gid = await _group_id(api_ds, "staff")
    await grant(
        api_ds,
        "mock-doc",
        "42",
        principal=Principal.actor("alice"),
        role="Manager",
        by_actor="root",
    )
    await grant(
        api_ds,
        "mock-doc",
        "42",
        principal=Principal.actor("agent:researcher"),
        role="Editor",
        by_actor="root",
    )
    await grant(
        api_ds,
        "mock-doc",
        "42",
        principal=Principal.group(gid),
        role="Viewer",
        by_actor="root",
    )
    await grant(
        api_ds,
        "mock-doc",
        "42",
        principal=Principal.public("authenticated"),
        role="Viewer",
        by_actor="root",
    )

    response = await _get(
        api_ds, "/-/acl/api/resource/mock-doc/42", cookies=_root_cookie(api_ds)
    )
    assert response.status_code == 200
    data = response.json()

    assert data["resource_type"] == "mock-doc"
    assert data["parent"] == "42"
    assert data["child"] is None
    assert data["can_manage"] is True

    # roles registry surfaced, in rank order, manage flag preserved.
    assert [r["name"] for r in data["roles"]] == ["Viewer", "Editor", "Manager"]
    assert data["roles"][-1]["manage"] is True
    assert data["roles"][0]["actions"] == ["doc-view"]

    grants = {(g["principal"], g["id"]): g for g in data["grants"]}

    # Actor grant enriched + role resolved.
    alice = grants[("actor", "alice")]
    assert alice["role"] == "Manager"
    assert alice["kind"] == "user"
    assert alice["display_name"] == "Alice Garcia"
    assert alice["email"] == "alice@example.com"
    assert alice["avatar_url"] == "/-/profile/pic/alice"

    # Agent: kind passthrough from actors_from_ids.
    agent = grants[("actor", "agent:researcher")]
    assert agent["role"] == "Editor"
    assert agent["kind"] == "agent"
    assert agent["display_name"] == "Researcher"

    # Group grant: name + member_count + kind group.
    group = grants[("group", str(gid))]
    assert group["role"] == "Viewer"
    assert group["kind"] == "group"
    assert group["display_name"] == "staff"
    assert group["member_count"] == 0

    # Public audience flagged public; its id echoes the audience type and the
    # display name is the friendly label (never looked up via actors_from_ids).
    public = grants[("public", "authenticated")]
    assert public["role"] == "Viewer"
    assert public["kind"] == "public"
    assert public["display_name"] == "Any signed-in user"
    assert "email" not in public


@pytest.mark.asyncio
async def test_group_member_count(api_ds):
    gid = await _group_id(api_ds, "staff")
    db = api_ds.get_internal_database()
    for actor_id in ("a", "b", "c"):
        await db.execute_write(
            "INSERT INTO acl_actor_groups (actor_id, group_id) VALUES (?, ?)",
            [actor_id, gid],
        )
    await grant(
        api_ds,
        "mock-doc",
        "42",
        principal=Principal.group(gid),
        role="Viewer",
        by_actor="root",
    )
    response = await _get(
        api_ds, "/-/acl/api/resource/mock-doc/42", cookies=_root_cookie(api_ds)
    )
    group = response.json()["grants"][0]
    assert group["principal"] == "group"
    assert group["member_count"] == 3


@pytest.mark.asyncio
async def test_read_empty_resource(api_ds):
    response = await _get(
        api_ds, "/-/acl/api/resource/mock-doc/42", cookies=_root_cookie(api_ds)
    )
    assert response.status_code == 200
    data = response.json()
    assert data["grants"] == []
    # roles + can_manage still present.
    assert data["can_manage"] is True
    assert len(data["roles"]) == 3


@pytest.mark.asyncio
async def test_unknown_actor_falls_back(api_ds):
    # An actor with no directory entry still resolves (kind user, no names).
    await grant(
        api_ds,
        "mock-doc",
        "42",
        principal=Principal.actor("ghost"),
        role="Viewer",
        by_actor="root",
    )
    response = await _get(
        api_ds, "/-/acl/api/resource/mock-doc/42", cookies=_root_cookie(api_ds)
    )
    ghost = response.json()["grants"][0]
    assert ghost["id"] == "ghost"
    assert ghost["role"] == "Viewer"
    assert ghost["kind"] == "user"
    assert "display_name" not in ghost
