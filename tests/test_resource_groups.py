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
