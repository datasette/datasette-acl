from datasette.app import Datasette
import pytest


@pytest.mark.asyncio
async def test_can_startup_with_no_configuration():
    datasette = Datasette()
    await datasette.invoke_startup()
    assert (await datasette.client.get("/")).status_code == 200


@pytest.mark.asyncio
async def test_startup_creates_resource_group_tables_and_default_role_bundles():
    datasette = Datasette()
    await datasette.invoke_startup()
    internal_db = datasette.get_internal_database()

    for table_name in (
        "acl_resource_groups",
        "acl_resource_group_items",
        "acl_resource_groups_audit",
        "acl_resource_group_grants",
        "acl_resource_group_grants_audit",
        "acl_role_bundles",
        "acl_role_bundle_actions",
    ):
        assert table_name in await internal_db.table_names()

    role_rows = [dict(row) for row in (await internal_db.execute("""
                select
                    acl_role_bundles.name,
                    group_concat(acl_role_bundle_actions.action_name, ',') as actions
                from acl_role_bundles
                join acl_role_bundle_actions
                  on acl_role_bundle_actions.role_bundle_id = acl_role_bundles.id
                group by acl_role_bundles.id
                order by acl_role_bundles.name
                """))]
    assert role_rows == [
        {
            "name": "admin",
            "actions": "alter-table,delete-row,drop-table,insert-row,update-row,view-database,view-instance,view-query,view-table",
        },
        {
            "name": "editor",
            "actions": "delete-row,insert-row,update-row,view-database,view-instance,view-query,view-table",
        },
        {
            "name": "viewer",
            "actions": "view-database,view-instance,view-query,view-table",
        },
    ]
