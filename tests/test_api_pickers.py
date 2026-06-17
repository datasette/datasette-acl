"""Tests for the picker endpoints (task 05):

    GET /-/acl/api/groups
    GET /-/acl/api/actors?q=&kind=

The group picker draws from ``acl_groups`` (active groups + member counts). The
actor picker is a thin proxy: it delegates to the user-profiles search API
(``GET /-/profiles/api/search``) when installed, and otherwise falls back to
``datasette_acl_valid_actors`` filtered by ``q`` in Python. Both endpoints gate
on the global ``datasette-acl`` permission. Public audiences (``everyone``,
``authenticated``, ``anonymous``) need no picker — they are a fixed set named
by ``principal_type`` — so they are exercised through the grant helpers in
``test_custom_resources.py`` rather than here.
"""

from datasette import hookimpl
from datasette import Response
from datasette.app import Datasette
from datasette.permissions import Action, Resource
from datasette.plugins import pm
from datasette_acl.grants import grant
from datasette_acl.roles import AclRole
import pytest
import pytest_asyncio


def _root_cookie(datasette):
    return {"ds_actor": datasette.client.actor_cookie({"id": "root"})}


def _cookie(datasette, actor_id):
    return {"ds_actor": datasette.client.actor_cookie({"id": actor_id})}


# --- groups picker --------------------------------------------------------


@pytest_asyncio.fixture
async def groups_ds():
    datasette = Datasette(config={"permissions": {"datasette-acl": {"id": "root"}}})
    await datasette.invoke_startup()
    db = datasette.get_internal_database()
    await db.execute_write("INSERT INTO acl_groups (name) VALUES ('staff')")
    await db.execute_write("INSERT INTO acl_groups (name) VALUES ('admins')")
    # A soft-deleted group must not appear in the picker.
    await db.execute_write(
        "INSERT INTO acl_groups (name, deleted) VALUES ('old', 1)"
    )
    # Members so member_count is exercised.
    staff_id = (
        await db.execute("SELECT id FROM acl_groups WHERE name = 'staff'")
    ).single_value()
    for actor_id in ("a", "b"):
        await db.execute_write(
            "INSERT INTO acl_actor_groups (actor_id, group_id) VALUES (?, ?)",
            [actor_id, staff_id],
        )
    yield datasette
    for table in await db.table_names():
        if table.startswith("acl"):
            await db.execute_write(f"drop table {table}")


@pytest.mark.asyncio
async def test_groups_requires_permission(groups_ds):
    response = await groups_ds.client.get("/-/acl/api/groups")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_groups_lists_active_with_counts(groups_ds):
    response = await groups_ds.client.get(
        "/-/acl/api/groups", cookies=_root_cookie(groups_ds)
    )
    assert response.status_code == 200
    groups = {g["name"]: g for g in response.json()["groups"]}
    # Soft-deleted group excluded.
    assert set(groups) == {"staff", "admins"}
    assert groups["staff"]["member_count"] == 2
    assert groups["admins"]["member_count"] == 0
    # ids are present and integers.
    assert isinstance(groups["staff"]["id"], int)


# --- actors picker: fallback (no profiles) --------------------------------


class ValidActorsPlugin:
    __name__ = "ValidActorsPlugin"

    @hookimpl
    def datasette_acl_valid_actors(self, datasette):
        return [
            {"id": "alice", "display": "Alice Garcia"},
            {"id": "bob", "display": "Bob Lee"},
            {"id": "carol", "display": "Carol"},
        ]


@pytest_asyncio.fixture
async def fallback_ds():
    pm.register(ValidActorsPlugin(), name="valid-actors-plugin")
    try:
        datasette = Datasette(
            config={"permissions": {"datasette-acl": {"id": "root"}}}
        )
        await datasette.invoke_startup()
        yield datasette
        db = datasette.get_internal_database()
        for table in await db.table_names():
            if table.startswith("acl"):
                await db.execute_write(f"drop table {table}")
    finally:
        pm.unregister(name="valid-actors-plugin")


@pytest.mark.asyncio
async def test_actors_requires_permission(fallback_ds):
    response = await fallback_ds.client.get("/-/acl/api/actors")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_actors_fallback_returns_valid_actors(fallback_ds):
    response = await fallback_ds.client.get(
        "/-/acl/api/actors", cookies=_root_cookie(fallback_ds)
    )
    assert response.status_code == 200
    results = response.json()["results"]
    ids = {r["id"] for r in results}
    assert ids == {"alice", "bob", "carol"}
    alice = next(r for r in results if r["id"] == "alice")
    assert alice["display_name"] == "Alice Garcia"
    assert alice["kind"] == "user"


@pytest.mark.asyncio
async def test_actors_fallback_filters_by_q(fallback_ds):
    # q matches against id OR display_name, case-insensitively.
    response = await fallback_ds.client.get(
        "/-/acl/api/actors?q=garcia", cookies=_root_cookie(fallback_ds)
    )
    results = response.json()["results"]
    assert [r["id"] for r in results] == ["alice"]

    response = await fallback_ds.client.get(
        "/-/acl/api/actors?q=BO", cookies=_root_cookie(fallback_ds)
    )
    results = response.json()["results"]
    assert [r["id"] for r in results] == ["bob"]


# --- actors picker: delegates to profiles search API ----------------------


async def _fake_profiles_search(request, datasette):
    """Stand-in for user-profiles' GET /-/profiles/api/search."""
    q = (request.args.get("q") or "").strip().lower()
    directory = [
        {
            "id": "dora",
            "display_name": "Dora Profile",
            "email": "dora@example.com",
            "avatar_url": "/-/profile/pic/dora",
            "kind": "user",
        },
        {
            "id": "evan",
            "display_name": "Evan Profile",
            "email": "evan@example.com",
            "avatar_url": "/-/profile/pic/evan",
            "kind": "user",
        },
    ]
    if q:
        directory = [
            r
            for r in directory
            if q in r["id"].lower() or q in r["display_name"].lower()
        ]
    return Response.json({"results": directory})


class FakeProfilesPlugin:
    __name__ = "FakeProfilesPlugin"

    @hookimpl
    def register_routes(self):
        return [("^/-/profiles/api/search$", _fake_profiles_search)]

    @hookimpl
    def datasette_acl_valid_actors(self, datasette):
        # If delegation works, these must NOT appear in the results.
        return [{"id": "should-not-appear", "display": "Fallback Only"}]


@pytest_asyncio.fixture
async def profiles_ds():
    pm.register(FakeProfilesPlugin(), name="fake-profiles-plugin")
    try:
        datasette = Datasette(
            config={"permissions": {"datasette-acl": {"id": "root"}}}
        )
        await datasette.invoke_startup()
        yield datasette
        db = datasette.get_internal_database()
        for table in await db.table_names():
            if table.startswith("acl"):
                await db.execute_write(f"drop table {table}")
    finally:
        pm.unregister(name="fake-profiles-plugin")


@pytest.mark.asyncio
async def test_actors_delegates_to_profiles(profiles_ds):
    response = await profiles_ds.client.get(
        "/-/acl/api/actors", cookies=_root_cookie(profiles_ds)
    )
    assert response.status_code == 200
    results = response.json()["results"]
    ids = {r["id"] for r in results}
    # Profiles results used; the valid_actors fallback was NOT consulted.
    assert ids == {"dora", "evan"}
    assert "should-not-appear" not in ids
    dora = next(r for r in results if r["id"] == "dora")
    assert dora["email"] == "dora@example.com"
    assert dora["avatar_url"] == "/-/profile/pic/dora"


@pytest.mark.asyncio
async def test_actors_delegates_q_to_profiles(profiles_ds):
    response = await profiles_ds.client.get(
        "/-/acl/api/actors?q=evan", cookies=_root_cookie(profiles_ds)
    )
    results = response.json()["results"]
    assert [r["id"] for r in results] == ["evan"]


# --- actors picker: the proxy forwards the caller's identity ---------------
#
# The actor picker proxies to profiles' search API via an internal
# ``datasette.client`` request. That request is anonymous by default, so a
# profiles ``profile_access`` gate would 403 it and the proxy would silently
# return no results. The fix forwards ``request.actor`` on the internal call.
# This fake search route enforces the same identity gate so the test fails if
# the caller's actor is not forwarded.


async def _gated_profiles_search(request, datasette):
    """Stand-in for profiles' search API that enforces a ``profile_access`` gate.

    Returns 403 unless the (forwarded) caller is the actor that holds access.
    """
    if not (request.actor and request.actor.get("id") == "root"):
        return Response.json({"error": "forbidden"}, status=403)
    return await _fake_profiles_search(request, datasette)


class GatedProfilesPlugin:
    __name__ = "GatedProfilesPlugin"

    @hookimpl
    def register_routes(self):
        return [("^/-/profiles/api/search$", _gated_profiles_search)]

    @hookimpl
    def datasette_acl_valid_actors(self, datasette):
        # If the gated delegation returns 403, the proxy must NOT silently fall
        # back to these — it returns an empty list. So these never appear.
        return [{"id": "fallback-leak", "display": "Fallback Leak"}]


@pytest_asyncio.fixture
async def gated_profiles_ds():
    pm.register(GatedProfilesPlugin(), name="gated-profiles-plugin")
    try:
        datasette = Datasette(
            config={"permissions": {"datasette-acl": {"id": "root"}}}
        )
        await datasette.invoke_startup()
        yield datasette
        db = datasette.get_internal_database()
        for table in await db.table_names():
            if table.startswith("acl"):
                await db.execute_write(f"drop table {table}")
    finally:
        pm.unregister(name="gated-profiles-plugin")


@pytest.mark.asyncio
async def test_actors_forwards_actor_to_gated_profiles(gated_profiles_ds):
    # root passes the proxy's own datasette-acl admin gate AND the downstream
    # profiles profile_access gate — but only if the internal request carries
    # root's identity. This is the regression test for the identity-forwarding
    # bug: an anonymous internal call would 403 and return an empty list.
    response = await gated_profiles_ds.client.get(
        "/-/acl/api/actors", cookies=_root_cookie(gated_profiles_ds)
    )
    assert response.status_code == 200
    ids = {r["id"] for r in response.json()["results"]}
    assert ids == {"dora", "evan"}
    # The fallback was not consulted (the gated delegation succeeded).
    assert "fallback-leak" not in ids


# --- per-resource authorization (the share-dialog Manager) -----------------
#
# The share dialog is driven by per-resource Managers (a doc owner) who do NOT
# hold the global ``datasette-acl`` permission. They authorize the pickers by
# passing the dialog's resource (resource_type / parent / child); the endpoints
# then run the same per-resource ``can_manage`` gate the read + mutation
# endpoints use. Omitting the resource still requires global admin.


class DocResource(Resource):
    """Parent-only mock resource type for the per-resource picker tests."""

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


class DocPickerPlugin:
    __name__ = "DocPickerPlugin"

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


@pytest_asyncio.fixture
async def resource_ds():
    pm.register(DocPickerPlugin(), name="doc-picker-plugin")
    try:
        datasette = Datasette(
            config={"permissions": {"datasette-acl": {"id": "root"}}}
        )
        await datasette.invoke_startup()
        db = datasette.get_internal_database()
        await db.execute_write("INSERT INTO acl_groups (name) VALUES ('staff')")
        # bruce is a per-resource Manager (no global admin).
        await grant(
            datasette, "mock-doc", "42", actor_id="bruce", role="Manager",
            by_actor="root",
        )
        yield datasette
        for table in await db.table_names():
            if table.startswith("acl"):
                await db.execute_write(f"drop table {table}")
    finally:
        pm.unregister(name="doc-picker-plugin")


_RES = "resource_type=mock-doc&parent=42"


@pytest.mark.asyncio
async def test_manager_can_use_groups_picker_with_resource(resource_ds):
    # bruce is not a global admin but manages mock-doc/42, so passing the
    # resource lets him list groups.
    response = await resource_ds.client.get(
        f"/-/acl/api/groups?{_RES}", cookies=_cookie(resource_ds, "bruce")
    )
    assert response.status_code == 200
    names = {g["name"] for g in response.json()["groups"]}
    assert "staff" in names


@pytest.mark.asyncio
async def test_manager_can_use_actors_picker_with_resource(resource_ds):
    response = await resource_ds.client.get(
        f"/-/acl/api/actors?{_RES}", cookies=_cookie(resource_ds, "bruce")
    )
    assert response.status_code == 200
    assert "results" in response.json()


@pytest.mark.asyncio
async def test_non_manager_cannot_use_pickers_with_resource(resource_ds):
    # mallory holds no manage action on the resource and is not global admin.
    for path in (
        f"/-/acl/api/groups?{_RES}",
        f"/-/acl/api/actors?{_RES}",
    ):
        response = await resource_ds.client.get(
            path, cookies=_cookie(resource_ds, "mallory")
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_anonymous_cannot_use_pickers_with_resource(resource_ds):
    for path in (
        f"/-/acl/api/groups?{_RES}",
        f"/-/acl/api/actors?{_RES}",
    ):
        response = await resource_ds.client.get(path)
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_manager_without_resource_still_requires_global_admin(resource_ds):
    # Without the resource params, the global-admin fallback applies, so a
    # per-resource Manager who lacks global admin is rejected (existing behavior).
    for path in ("/-/acl/api/groups", "/-/acl/api/actors"):
        response = await resource_ds.client.get(
            path, cookies=_cookie(resource_ds, "bruce")
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_global_admin_still_works_without_resource(resource_ds):
    # root holds the global datasette-acl permission → pickers work with no
    # resource params (back-compat).
    for path in ("/-/acl/api/groups", "/-/acl/api/actors"):
        response = await resource_ds.client.get(
            path, cookies=_root_cookie(resource_ds)
        )
        assert response.status_code == 200
