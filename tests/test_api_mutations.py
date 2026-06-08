"""Tests for the JSON mutation endpoints (task 04):

    POST /-/acl/api/resource/{resource_type}/{parent}/{child}/grant
    POST .../revoke
    POST .../update

Covers the grant/revoke/update happy paths (they mutate acl + write audit rows
and return the expected JSON), per-resource authorization (a non-manager gets
403; granting them the Manager role — directly or via a group — then lets them
manage), and the datasette 1.0a30 header-based CSRF behavior (a cross-origin
browser POST is rejected; a same-origin / non-browser POST is accepted).
"""

from datasette import hookimpl
from datasette.app import Datasette
from datasette.permissions import Action, Resource
from datasette.plugins import pm
from datasette_acl.grants import grant, list_grants
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

FAKE_ACTORS = {
    "alice": {
        "id": "alice",
        "display_name": "Alice Garcia",
        "email": "alice@example.com",
        "avatar_url": "/-/profile/pic/alice",
        "kind": "user",
    },
}


class ApiMutationPlugin:
    __name__ = "ApiMutationPlugin"

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
        return {
            actor_id: FAKE_ACTORS.get(actor_id, {"id": actor_id})
            for actor_id in actor_ids
        }


@pytest_asyncio.fixture
async def api_ds():
    plugin = ApiMutationPlugin()
    pm.register(plugin, name="api-mutation-plugin")
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
        pm.unregister(name="api-mutation-plugin")


def _cookie(datasette, actor_id):
    return {"ds_actor": datasette.client.actor_cookie({"id": actor_id})}


def _root_cookie(datasette):
    return _cookie(datasette, "root")


async def _group_id(datasette, name):
    return (
        await datasette.get_internal_database().execute(
            "SELECT id FROM acl_groups WHERE name = ?", [name]
        )
    ).single_value()


async def _audit_rows(datasette):
    rows = await datasette.get_internal_database().execute(
        "SELECT operation, actor_id, group_id, operation_by FROM acl_audit ORDER BY id"
    )
    return [dict(r) for r in rows.rows]


async def _post(datasette, path, json=None, cookies=None, headers=None):
    return await datasette.client.post(
        path,
        json=json if json is not None else {},
        cookies=cookies or {},
        headers=headers or {},
    )


GRANT_URL = "/-/acl/api/resource/mock-doc/42/grant"
REVOKE_URL = "/-/acl/api/resource/mock-doc/42/revoke"
UPDATE_URL = "/-/acl/api/resource/mock-doc/42/update"


# --- happy paths ----------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_by_role(api_ds):
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "role": "Editor"},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["grant"]["id"] == "bob"
    assert data["grant"]["role"] == "Editor"
    assert data["grant"]["actions"] == ["doc-edit", "doc-view"]
    assert data["grant"]["kind"] == "user"

    grants = await list_grants(api_ds, "mock-doc", "42")
    bob = [g for g in grants if g["actor_id"] == "bob"][0]
    assert bob["actions"] == ["doc-edit", "doc-view"]

    audit = await _audit_rows(api_ds)
    added = [r for r in audit if r["operation"] == "added" and r["actor_id"] == "bob"]
    assert len(added) == 2
    assert all(r["operation_by"] == "root" for r in added)


@pytest.mark.asyncio
async def test_grant_by_actions(api_ds):
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "carol", "actions": ["doc-view"]},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["grant"]["role"] == "Viewer"
    assert data["grant"]["actions"] == ["doc-view"]


@pytest.mark.asyncio
async def test_grant_enriched_display(api_ds):
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "alice", "role": "Viewer"},
        cookies=_root_cookie(api_ds),
    )
    grant_entry = response.json()["grant"]
    assert grant_entry["display_name"] == "Alice Garcia"
    assert grant_entry["email"] == "alice@example.com"
    assert grant_entry["avatar_url"] == "/-/profile/pic/alice"


@pytest.mark.asyncio
async def test_grant_group(api_ds):
    gid = await _group_id(api_ds, "staff")
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"group_id": gid, "role": "Viewer"},
        cookies=_root_cookie(api_ds),
    )
    data = response.json()
    assert data["grant"]["principal"] == "group"
    assert data["grant"]["id"] == str(gid)
    assert data["grant"]["role"] == "Viewer"
    assert data["grant"]["kind"] == "group"
    assert data["grant"]["display_name"] == "staff"


@pytest.mark.asyncio
async def test_grant_wildcard_principal(api_ds):
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "_signed_in", "role": "Viewer"},
        cookies=_root_cookie(api_ds),
    )
    data = response.json()
    assert data["grant"]["id"] == "_signed_in"
    assert data["grant"]["kind"] == "public"
    assert "display_name" not in data["grant"]


@pytest.mark.asyncio
async def test_update_swaps_role(api_ds):
    await grant(api_ds, "mock-doc", "42", actor_id="bob", role="Manager", by_actor="root")
    response = await _post(
        api_ds,
        UPDATE_URL,
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["grant"]["role"] == "Viewer"
    assert data["grant"]["actions"] == ["doc-view"]

    grants = await list_grants(api_ds, "mock-doc", "42")
    bob = [g for g in grants if g["actor_id"] == "bob"][0]
    assert bob["actions"] == ["doc-view"]

    audit = await _audit_rows(api_ds)
    removed = [r for r in audit if r["operation"] == "removed" and r["actor_id"] == "bob"]
    # Manager -> Viewer drops doc-edit and doc-manage.
    assert {r["operation_by"] for r in removed} == {"root"}
    assert len(removed) == 2


@pytest.mark.asyncio
async def test_revoke_removes_all(api_ds):
    await grant(api_ds, "mock-doc", "42", actor_id="bob", role="Manager", by_actor="root")
    response = await _post(
        api_ds,
        REVOKE_URL,
        json={"actor_id": "bob"},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert sorted(data["removed"]) == ["doc-edit", "doc-manage", "doc-view"]

    grants = await list_grants(api_ds, "mock-doc", "42")
    assert [g for g in grants if g["actor_id"] == "bob"] == []

    audit = await _audit_rows(api_ds)
    removed = [r for r in audit if r["operation"] == "removed" and r["actor_id"] == "bob"]
    assert len(removed) == 3
    assert all(r["operation_by"] == "root" for r in removed)


@pytest.mark.asyncio
async def test_revoke_group(api_ds):
    gid = await _group_id(api_ds, "staff")
    await grant(api_ds, "mock-doc", "42", group_id=gid, role="Viewer", by_actor="root")
    response = await _post(
        api_ds,
        REVOKE_URL,
        json={"group_id": gid},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 200
    grants = await list_grants(api_ds, "mock-doc", "42")
    assert grants == []


# --- per-resource authorization -------------------------------------------


@pytest.mark.asyncio
async def test_non_manager_cannot_grant(api_ds):
    # mallory has no manage action and is not the global admin.
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_cookie(api_ds, "mallory"),
    )
    assert response.status_code == 403
    # Nothing was written.
    assert await list_grants(api_ds, "mock-doc", "42") == []


@pytest.mark.asyncio
async def test_anonymous_cannot_grant(api_ds):
    response = await _post(api_ds, GRANT_URL, json={"actor_id": "bob", "role": "Viewer"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_manager_role_grants_manage_ability(api_ds):
    # Granting mallory the Manager role (which includes doc-manage) lets her
    # re-share, without the global datasette-acl permission.
    await grant(api_ds, "mock-doc", "42", actor_id="mallory", role="Manager", by_actor="root")
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_cookie(api_ds, "mallory"),
    )
    assert response.status_code == 200
    grants = await list_grants(api_ds, "mock-doc", "42")
    assert any(g["actor_id"] == "bob" for g in grants)


@pytest.mark.asyncio
async def test_non_manager_role_cannot_grant(api_ds):
    # Editor is not a manage role, so it must NOT confer re-share ability.
    await grant(api_ds, "mock-doc", "42", actor_id="mallory", role="Editor", by_actor="root")
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_cookie(api_ds, "mallory"),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_group_manager_role_grants_manage_ability(api_ds):
    # mallory is in the staff group; the staff group holds the Manager role.
    gid = await _group_id(api_ds, "staff")
    db = api_ds.get_internal_database()
    await db.execute_write(
        "INSERT INTO acl_actor_groups (actor_id, group_id) VALUES (?, ?)",
        ["mallory", gid],
    )
    await grant(api_ds, "mock-doc", "42", group_id=gid, role="Manager", by_actor="root")
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_cookie(api_ds, "mallory"),
    )
    assert response.status_code == 200
    grants = await list_grants(api_ds, "mock-doc", "42")
    assert any(g["actor_id"] == "bob" for g in grants)


@pytest.mark.asyncio
async def test_unknown_resource_type(api_ds):
    response = await _post(
        api_ds,
        "/-/acl/api/resource/nope/42/grant",
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_grant_nonexistent_resource_forbidden(api_ds):
    # issue #43: mock-doc only advertises parent "42" (DocResource.resources_sql).
    # Granting on a made-up parent must be rejected -- even for the global admin,
    # with the same 403 as an unauthorized resource so existence is not leaked --
    # and must not conjure an acl_resources row.
    response = await _post(
        api_ds,
        "/-/acl/api/resource/mock-doc/made-up/grant",
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 403
    rows = await api_ds.get_internal_database().execute(
        "select 1 from acl_resources where resource_type = 'mock-doc' and parent = 'made-up'"
    )
    assert rows.rows == []


# --- bad input ------------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_requires_exactly_one_principal(api_ds):
    # Neither principal.
    response = await _post(
        api_ds, GRANT_URL, json={"role": "Viewer"}, cookies=_root_cookie(api_ds)
    )
    assert response.status_code == 400
    assert response.json()["ok"] is False
    # Both principals.
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "group_id": 1, "role": "Viewer"},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_grant_unknown_role(api_ds):
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "role": "Nope"},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_update_requires_role(api_ds):
    response = await _post(
        api_ds, UPDATE_URL, json={"actor_id": "bob"}, cookies=_root_cookie(api_ds)
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_get_on_mutation_route_not_allowed(api_ds):
    response = await api_ds.client.get(GRANT_URL, cookies=_root_cookie(api_ds))
    assert response.status_code == 405


# --- CSRF (datasette 1.0a30 header-based protection) ----------------------


@pytest.mark.asyncio
async def test_csrf_cross_origin_browser_post_rejected(api_ds):
    # A browser cross-origin POST sends an Origin that does not match Host and
    # no Sec-Fetch-Site=same-origin; core's CrossOriginProtectionMiddleware
    # rejects it before our handler runs.
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_root_cookie(api_ds),
        headers={"origin": "https://evil.example.com"},
    )
    assert response.status_code == 403
    # The grant did not happen.
    assert await list_grants(api_ds, "mock-doc", "42") == []


@pytest.mark.asyncio
async def test_csrf_same_origin_post_accepted(api_ds):
    # Sec-Fetch-Site: same-origin is the signal a same-origin browser fetch
    # sends; core lets it through. (The non-browser test client with no headers
    # is already exercised by the happy-path tests above.)
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "role": "Viewer"},
        cookies=_root_cookie(api_ds),
        headers={"sec-fetch-site": "same-origin"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True


# --- HTML admin page per-resource authorization (issue #42) ---------------
#
# The /-/acl/resource/... admin page used to gate on the global datasette-acl
# permission only. It now shares the JSON API's per-resource can_manage gate, so
# the owner of an object (an actor holding a manage=True role on that specific
# resource) can administer its sharing without instance-wide permission.

HTML_PAGE_URL = "/-/acl/resource/mock-doc/42"


@pytest.mark.asyncio
async def test_html_page_manager_can_view(api_ds):
    # mallory holds the Manager role on mock-doc/42 but is NOT the global admin.
    await grant(
        api_ds, "mock-doc", "42", actor_id="mallory", role="Manager", by_actor="root"
    )
    response = await api_ds.client.get(HTML_PAGE_URL, cookies=_cookie(api_ds, "mallory"))
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_html_page_manager_can_grant_via_post(api_ds):
    # A per-resource Manager can grant a raw action through the HTML form,
    # without the global datasette-acl permission.
    await grant(
        api_ds, "mock-doc", "42", actor_id="mallory", role="Manager", by_actor="root"
    )
    response = await api_ds.client.post(
        HTML_PAGE_URL,
        data={"new_actor_id": "bob", "new_user_actions": "doc-view"},
        cookies=_cookie(api_ds, "mallory"),
    )
    assert response.status_code == 302
    assert await api_ds.allowed(
        action="doc-view", resource=DocResource("42"), actor={"id": "bob"}
    )


@pytest.mark.asyncio
async def test_html_page_group_manager_can_view(api_ds):
    # The Manager role held via a group also unlocks the HTML page.
    gid = await _group_id(api_ds, "staff")
    db = api_ds.get_internal_database()
    await db.execute_write(
        "INSERT INTO acl_actor_groups (actor_id, group_id) VALUES (?, ?)",
        ["mallory", gid],
    )
    await grant(
        api_ds, "mock-doc", "42", group_id=gid, role="Manager", by_actor="root"
    )
    response = await api_ds.client.get(HTML_PAGE_URL, cookies=_cookie(api_ds, "mallory"))
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_html_page_non_manager_forbidden(api_ds):
    # No role on the resource and not the global admin -> 403.
    response = await api_ds.client.get(HTML_PAGE_URL, cookies=_cookie(api_ds, "mallory"))
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_html_page_non_manage_role_forbidden(api_ds):
    # Editor is not a manage role, so it must NOT unlock the admin page.
    await grant(
        api_ds, "mock-doc", "42", actor_id="mallory", role="Editor", by_actor="root"
    )
    response = await api_ds.client.get(HTML_PAGE_URL, cookies=_cookie(api_ds, "mallory"))
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_html_page_global_admin_can_view(api_ds):
    # The global datasette-acl admin still gets in (back-compat).
    response = await api_ds.client.get(HTML_PAGE_URL, cookies=_root_cookie(api_ds))
    assert response.status_code == 200


# --- raw actions not validated against the resource type (issue #45) -------
#
# SECURITY: grant(..., actions=[...]) used to accept ANY string, and
# _ensure_actions inserted unknown names straight into acl_actions. The
# resource-type filter in permission_resources_sql blocks cross-type leakage,
# but a per-resource Manager could still persist arbitrary or *future* action
# names for their own resource type. If a later plugin/version registered an
# action with that name for the same resource type, the stale grant would
# silently become live -- a privilege-escalation foothold planted ahead of time.
#
# Fixed in _resolve_actions: raw actions are now validated against
# actions_for_resource_type(...) and an unknown name raises ValueError (-> 400).


async def _acl_action_names(datasette):
    rows = await datasette.get_internal_database().execute(
        "SELECT name FROM acl_actions"
    )
    return {r["name"] for r in rows.rows}


@pytest.mark.asyncio
async def test_grant_helper_rejects_unknown_raw_action(api_ds):
    # The Python helper must refuse an action that the resource type does not
    # register, rather than silently inventing it.
    with pytest.raises(ValueError):
        await grant(
            api_ds, "mock-doc", "42", actor_id="bob", actions=["not-real"], by_actor="root"
        )
    # And nothing must have been persisted.
    assert "not-real" not in await _acl_action_names(api_ds)
    assert await list_grants(api_ds, "mock-doc", "42") == []


@pytest.mark.asyncio
async def test_api_grant_rejects_unknown_raw_action(api_ds):
    # The JSON API must return 400 for an unknown raw action, per the issue.
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "actions": ["not-real"]},
        cookies=_root_cookie(api_ds),
    )
    assert response.status_code == 400
    assert await list_grants(api_ds, "mock-doc", "42") == []


@pytest.mark.asyncio
async def test_grant_unknown_action_partial_list_is_atomic(api_ds):
    # A mix of one valid and one bogus action must be rejected wholesale -- the
    # valid action must NOT be written when a sibling is invalid.
    with pytest.raises(ValueError):
        await grant(
            api_ds,
            "mock-doc",
            "42",
            actor_id="bob",
            actions=["doc-view", "not-real"],
            by_actor="root",
        )
    assert await list_grants(api_ds, "mock-doc", "42") == []


@pytest.mark.asyncio
async def test_future_action_name_not_persisted_as_stale_grant(api_ds):
    # The escalation scenario: a per-resource Manager (not a global admin) tries
    # to pre-plant a grant for "doc-superpower" -- a name NOT registered for
    # mock-doc today, but which a future version might add. It must be rejected,
    # and must never reach acl_actions, so it cannot go live later.
    await grant(
        api_ds, "mock-doc", "42", actor_id="mallory", role="Manager", by_actor="root"
    )
    response = await _post(
        api_ds,
        GRANT_URL,
        json={"actor_id": "bob", "actions": ["doc-superpower"]},
        cookies=_cookie(api_ds, "mallory"),
    )
    assert response.status_code == 400
    assert "doc-superpower" not in await _acl_action_names(api_ds)
