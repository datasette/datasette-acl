from datasette.resources import DatabaseResource, QueryResource, TableResource
import pytest


@pytest.mark.asyncio
async def test_manage_resource_groups_json_api(ds, csrftoken):
    create_response = await ds.client.post(
        "/-/acl/resource-groups.json",
        data={
            "slug": "project-alpha",
            "name": "Project Alpha",
            "description": "First project",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert create_response.status_code == 200
    assert create_response.json() == {
        "ok": True,
        "resource_group": {
            "slug": "project-alpha",
            "name": "Project Alpha",
            "description": "First project",
            "deleted": 0,
        },
    }

    list_response = await ds.client.get(
        "/-/acl/resource-groups.json",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert list_response.status_code == 200
    assert list_response.json()["resource_groups"] == [
        {
            "slug": "project-alpha",
            "name": "Project Alpha",
            "description": "First project",
            "resources_count": 0,
            "grants_count": 0,
        }
    ]

    add_resource_response = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/resources.json",
        data={
            "resource_type": "table",
            "resource_key": "db/t",
            "note": "Main table",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert add_resource_response.status_code == 200
    assert add_resource_response.json()["resource"]["resource_type"] == "table"
    assert add_resource_response.json()["resource"]["resource_key"] == "db/t"

    add_grant_response = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/grants.json",
        data={
            "subject_type": "actor",
            "subject": "alice",
            "grant_mode": "role",
            "role_name": "editor",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert add_grant_response.status_code == 200
    assert add_grant_response.json()["grant"] == {
        "id": 1,
        "actor_id": "alice",
        "actor_group": None,
        "role_name": "editor",
        "action_name": None,
        "expires_at": None,
    }

    detail_response = await ds.client.get(
        "/-/acl/resource-groups/project-alpha.json",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert detail_response.status_code == 200
    assert detail_response.json() == {
        "resource_group": {
            "slug": "project-alpha",
            "name": "Project Alpha",
            "description": "First project",
            "deleted": 0,
            "resources": [
                {
                    "id": 1,
                    "resource_type": "table",
                    "resource_key": "db/t",
                    "note": "Main table",
                }
            ],
            "grants": [
                {
                    "id": 1,
                    "actor_id": "alice",
                    "actor_group": None,
                    "role_name": "editor",
                    "action_name": None,
                    "expires_at": None,
                }
            ],
        }
    }

    duplicate_create = await ds.client.post(
        "/-/acl/resource-groups.json",
        data={
            "slug": "project-alpha",
            "name": "Duplicate",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert duplicate_create.status_code == 409
    assert duplicate_create.json() == {
        "ok": False,
        "error": "A resource group with that slug already exists",
    }


@pytest.mark.asyncio
async def test_resource_group_resources_json_validates_query_and_duplicate_membership(
    ds, csrftoken
):
    create_response = await ds.client.post(
        "/-/acl/resource-groups.json",
        data={
            "slug": "project-alpha",
            "name": "Project Alpha",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert create_response.status_code == 200

    valid_query = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/resources.json",
        data={
            "resource_type": "query",
            "resource_key": "db/recent",
            "note": "Recent query",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert valid_query.status_code == 200
    assert valid_query.json()["resource"]["resource_key"] == "db/recent"

    duplicate_query = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/resources.json",
        data={
            "resource_type": "query",
            "resource_key": "db/recent",
            "note": "Duplicate query",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert duplicate_query.status_code == 409
    assert duplicate_query.json() == {
        "ok": False,
        "error": "That resource is already in this resource group",
    }


@pytest.mark.asyncio
async def test_resource_group_grants_json_validates_invalid_inputs_and_duplicates(
    ds, csrftoken
):
    create_response = await ds.client.post(
        "/-/acl/resource-groups.json",
        data={
            "slug": "project-alpha",
            "name": "Project Alpha",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert create_response.status_code == 200

    invalid_group = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/grants.json",
        data={
            "subject_type": "group",
            "subject": "missing-group",
            "grant_mode": "role",
            "role_name": "viewer",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert invalid_group.status_code == 400
    assert invalid_group.json() == {
        "ok": False,
        "error": "Unknown actor group",
    }

    invalid_role = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/grants.json",
        data={
            "subject_type": "actor",
            "subject": "alice",
            "grant_mode": "role",
            "role_name": "made-up-role",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert invalid_role.status_code == 400
    assert invalid_role.json() == {
        "ok": False,
        "error": "Unknown role bundle",
    }

    invalid_action = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/grants.json",
        data={
            "subject_type": "actor",
            "subject": "alice",
            "grant_mode": "action",
            "action_name": "made-up-action",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert invalid_action.status_code == 400
    assert invalid_action.json() == {
        "ok": False,
        "error": "Unknown action",
    }

    first_grant = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/grants.json",
        data={
            "subject_type": "actor",
            "subject": "alice",
            "grant_mode": "role",
            "role_name": "viewer",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert first_grant.status_code == 200

    duplicate_grant = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/grants.json",
        data={
            "subject_type": "actor",
            "subject": "alice",
            "grant_mode": "role",
            "role_name": "viewer",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert duplicate_grant.status_code == 409
    assert duplicate_grant.json() == {
        "ok": False,
        "error": "That grant already exists",
    }


@pytest.mark.asyncio
async def test_resource_group_delete_endpoints(ds, csrftoken):
    create_response = await ds.client.post(
        "/-/acl/resource-groups.json",
        data={
            "slug": "project-alpha",
            "name": "Project Alpha",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert create_response.status_code == 200

    resource_response = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/resources.json",
        data={
            "resource_type": "table",
            "resource_key": "db/t",
            "note": "Main table",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert resource_response.status_code == 200

    grant_response = await ds.client.post(
        "/-/acl/resource-groups/project-alpha/grants.json",
        data={
            "subject_type": "actor",
            "subject": "alice",
            "grant_mode": "role",
            "role_name": "editor",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert grant_response.status_code == 200

    resource_id = resource_response.json()["resource"]["id"]
    grant_id = grant_response.json()["grant"]["id"]

    delete_resource = await ds.client.delete(
        f"/-/acl/resource-groups/project-alpha/resources/{resource_id}.json",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
        headers={"x-csrftoken": csrftoken},
    )
    assert delete_resource.status_code == 200
    assert delete_resource.json() == {"ok": True}

    delete_grant = await ds.client.delete(
        f"/-/acl/resource-groups/project-alpha/grants/{grant_id}.json",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
        headers={"x-csrftoken": csrftoken},
    )
    assert delete_grant.status_code == 200
    assert delete_grant.json() == {"ok": True}

    delete_group = await ds.client.delete(
        "/-/acl/resource-groups/project-alpha.json",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
        headers={"x-csrftoken": csrftoken},
    )
    assert delete_group.status_code == 200
    assert delete_group.json() == {"ok": True}

    detail_response = await ds.client.get(
        "/-/acl/resource-groups/project-alpha.json",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert detail_response.status_code == 404


@pytest.mark.asyncio
async def test_resource_group_html_pages(ds, csrftoken):
    create_page = await ds.client.get(
        "/-/acl/resource-groups",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert create_page.status_code == 200
    assert "Create a resource group" in create_page.text

    create_response = await ds.client.post(
        "/-/acl/resource-groups",
        data={
            "slug": "project-alpha",
            "name": "Project Alpha",
            "description": "First project",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert create_response.status_code == 302
    assert create_response.headers["location"] == "/-/acl/resource-groups/project-alpha"

    add_resource = await ds.client.post(
        "/-/acl/resource-groups/project-alpha",
        data={
            "resource_type": "table",
            "resource_key": "db/t",
            "note": "Main table",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert add_resource.status_code == 302

    add_grant = await ds.client.post(
        "/-/acl/resource-groups/project-alpha",
        data={
            "subject_type": "actor",
            "subject": "alice",
            "grant_mode": "role",
            "role_name": "viewer",
            "csrftoken": csrftoken,
        },
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert add_grant.status_code == 302

    detail_page = await ds.client.get(
        "/-/acl/resource-groups/project-alpha",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert detail_page.status_code == 200
    assert "Project Alpha" in detail_page.text
    assert "db/t" in detail_page.text
    assert "alice" in detail_page.text
    assert "viewer" in detail_page.text


@pytest.mark.asyncio
async def test_resource_group_permission_resolution(ds):
    internal_db = ds.get_internal_database()
    assert not await ds.allowed(
        actor={"id": "alice"},
        action="insert-row",
        resource=TableResource("db", "t"),
    )

    await internal_db.execute_write("""
        insert into acl_resource_groups (slug, name, description, created_by)
        values ('project-alpha', 'Project Alpha', 'First project', 'root')
        """)
    await internal_db.execute_write("""
        insert into acl_resource_group_items (resource_group_id, resource_type, resource_key)
        values (
            (select id from acl_resource_groups where slug = 'project-alpha'),
            'table',
            'db/t'
        )
        """)
    await internal_db.execute_write("""
        insert into acl_resource_group_grants (
            resource_group_id, actor_id, role_name, granted_by
        ) values (
            (select id from acl_resource_groups where slug = 'project-alpha'),
            'alice',
            'editor',
            'root'
        )
        """)

    assert await ds.allowed(
        actor={"id": "alice"},
        action="insert-row",
        resource=TableResource("db", "t"),
    )
    assert await ds.allowed(
        actor={"id": "alice"},
        action="view-table",
        resource=TableResource("db", "t"),
    )
    assert not await ds.allowed(
        actor={"id": "alice"},
        action="drop-table",
        resource=TableResource("db", "t"),
    )


@pytest.mark.asyncio
async def test_resource_group_permission_resolution_supports_builtin_resource_types(ds):
    internal_db = ds.get_internal_database()
    await internal_db.execute_write("""
        insert into acl_resource_groups (slug, name, created_by)
        values ('mixed', 'Mixed resources', 'root')
        """)
    await internal_db.execute_write_many(
        """
        insert into acl_resource_group_items (resource_group_id, resource_type, resource_key)
        values (
            (select id from acl_resource_groups where slug = 'mixed'),
            :resource_type,
            :resource_key
        )
        """,
        [
            {"resource_type": "database", "resource_key": "db"},
            {"resource_type": "query", "resource_key": "db/recent"},
        ],
    )
    await internal_db.execute_write_many(
        """
        insert into acl_resource_group_grants (
            resource_group_id, actor_id, action_name, granted_by
        ) values (
            (select id from acl_resource_groups where slug = 'mixed'),
            'alice',
            :action_name,
            'root'
        )
        """,
        [
            {"action_name": "view-database"},
            {"action_name": "view-query"},
        ],
    )

    assert await ds.allowed(
        actor={"id": "alice"},
        action="view-database",
        resource=DatabaseResource("db"),
    )
    assert await ds.allowed(
        actor={"id": "alice"},
        action="view-query",
        resource=QueryResource("db", "recent"),
    )
