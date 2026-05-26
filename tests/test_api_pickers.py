"""Tests for the picker endpoints (task 05):

    GET /-/acl/api/groups
    GET /-/acl/api/actors?q=&kind=

The group picker draws from ``acl_groups`` (active groups + member counts). The
actor picker is a thin proxy: it delegates to the user-profiles search API
(``GET /-/profiles/api/search``) when installed, and otherwise falls back to
``datasette_acl_valid_actors`` filtered by ``q`` in Python. Both endpoints gate
on the global ``datasette-acl`` permission. Wildcard / public principals
(``*``, ``_signed_in``, ``_anonymous``) need no write path — they are plain
``actor_id`` strings — so they are exercised through the grant helpers in
``test_custom_resources.py`` rather than here.
"""

from datasette import hookimpl
from datasette import Response
from datasette.app import Datasette
from datasette.plugins import pm
import pytest
import pytest_asyncio


def _root_cookie(datasette):
    return {"ds_actor": datasette.client.actor_cookie({"id": "root"})}


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
