from collections import namedtuple
import pytest

ManageGroupTest = namedtuple(
    "ManageGroupTest",
    (
        "description",
        "setup_post_data",
        "post_data",
        "expected_members",
        "expected_audit_rows",
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ManageGroupTest._fields,
    (
        ManageGroupTest(
            description="Add user to group",
            setup_post_data={},
            post_data={"add": "terry"},
            expected_members={"terry"},
            expected_audit_rows=[
                {"operation_by": "root", "operation": "added", "actor_id": "terry"}
            ],
        ),
        ManageGroupTest(
            description="Remove user from group",
            setup_post_data={"add": "terry"},
            post_data={"remove": "terry"},
            expected_members=set(),
            expected_audit_rows=[
                {"operation_by": "root", "operation": "removed", "actor_id": "terry"},
                {"operation_by": "root", "operation": "added", "actor_id": "terry"},
            ],
        ),
    ),
)
async def test_manage_table_permissions(
    ds, description, setup_post_data, post_data, expected_members, expected_audit_rows
):
    internal_db = ds.get_internal_database()

    csrf_token_response = await ds.client.get(
        "/-/acl/groups/dev",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert csrf_token_response.status_code == 200
    csrftoken = csrf_token_response.cookies["ds_csrftoken"]

    if setup_post_data:
        setup_response = await ds.client.post(
            "/-/acl/groups/dev",
            data={**setup_post_data, "csrftoken": csrftoken},
            cookies={
                "ds_actor": ds.client.actor_cookie({"id": "root"}),
                "ds_csrftoken": csrftoken,
            },
        )
        assert setup_response.status_code == 302

    response = await ds.client.post(
        "/-/acl/groups/dev",
        data={**post_data, "csrftoken": csrftoken},
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert response.status_code == 302

    # Check group members
    group_members = await get_group_members(internal_db, "dev")
    assert group_members == expected_members

    # Check audit logs
    AUDIT_SQL = """
        select
          operation_by, operation, actor_id
        from acl_groups_audit
        where group_id = (select id from acl_groups where name = 'dev')
        order by id desc
    """
    audit_rows = [dict(r) for r in (await internal_db.execute(AUDIT_SQL))]
    assert audit_rows == expected_audit_rows


@pytest.mark.asyncio
async def test_cannot_edit_dynamic_group(ds):
    db = ds.get_internal_database()
    csrf_token_response = await ds.client.get(
        "/-/acl/groups/staff",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert csrf_token_response.status_code == 200
    csrftoken = csrf_token_response.cookies["ds_csrftoken"]

    # Adding to dev should work, adding to staff should fail
    for group in ("staff", "dev"):
        await ds.client.post(
            f"/-/acl/groups/{group}",
            data={"add": "tony2", "csrftoken": csrftoken},
            cookies={
                "ds_actor": ds.client.actor_cookie({"id": "root"}),
                "ds_csrftoken": csrftoken,
            },
        )
    assert await get_group_members(db, "staff") == set()
    assert await get_group_members(db, "dev") == {"tony2"}


async def get_group_members(db, group):
    return {
        d["actor_id"]
        for d in (
            await db.execute(
                """
        select actor_id from acl_actor_groups
        where group_id = (select id from acl_groups where name = ?)
    """,
                [group],
            )
        ).rows
    }


@pytest.mark.asyncio
async def test_deleted_group(ds):
    db = ds.get_internal_database()
    await db.execute_write(
        "insert into acl_groups (name, deleted) values ('deleted', 1)"
    )
    list_response = await ds.client.get(
        "/-/acl/groups",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    # Should link to staff but not to deleted
    assert "/-/acl/groups/staff" in list_response.text
    assert "/-/acl/groups/deleted" not in list_response.text

    # deleted page should still 200 but it should say it is deleted
    page_response = await ds.client.get(
        "/-/acl/groups/deleted",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    assert page_response.status_code == 200
    assert "has been deleted" in page_response.text


@pytest.mark.asyncio
async def test_create_delete_group(ds):
    csrf_token_response = await ds.client.get(
        "/-/acl/groups",
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
        },
    )
    csrftoken = csrf_token_response.cookies["ds_csrftoken"]
    internal_db = ds.get_internal_database()

    # Create a group
    create_group_response = await ds.client.post(
        "/-/acl/groups",
        data={"new_group": "sales", "csrftoken": csrftoken},
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert create_group_response.status_code == 302
    assert create_group_response.headers["location"] == "/-/acl/groups/sales"

    async def get_members():
        return {
            r[0]
            for r in (
                await internal_db.execute(
                    """
            select actor_id
            from acl_actor_groups
            where group_id = (select id from acl_groups where name = 'sales')
        """
                )
            )
        }

    assert await get_members() == set()

    # Add sally, sam and paulo
    for actor_id in ("sally", "sam", "paulo"):
        add_response = await ds.client.post(
            f"/-/acl/groups/sales",
            data={"add": actor_id, "csrftoken": csrftoken},
            cookies={
                "ds_actor": ds.client.actor_cookie({"id": "root"}),
                "ds_csrftoken": csrftoken,
            },
        )
        assert add_response.status_code == 302
        assert add_response.headers["location"] == "/-/acl/groups/sales#focus-add"
    # Check the group has those members
    assert await get_members() == {"sally", "sam", "paulo"}
    # Deleting this group should first remove the members
    delete_group_response = await ds.client.post(
        "/-/acl/groups/sales",
        data={"delete_group": "1", "csrftoken": csrftoken},
        cookies={
            "ds_actor": ds.client.actor_cookie({"id": "root"}),
            "ds_csrftoken": csrftoken,
        },
    )
    assert delete_group_response.status_code == 302
    assert delete_group_response.headers["location"] == "/-/acl/groups"

    assert await get_members() == set()

    # Should be marked as deleted
    assert (
        await internal_db.execute("select deleted from acl_groups where name = 'sales'")
    ).single_value() == 1

    # Check the audit log
    audit_rows = [
        dict(r)
        for r in (
            await internal_db.execute(
                """
        select
          operation_by, operation, actor_id
        from acl_groups_audit
        where group_id = (select id from acl_groups where name = 'sales')
        order by id desc
    """
            )
        )
    ]
    assert audit_rows == [
        {"operation_by": "root", "operation": "deleted", "actor_id": None},
        {"operation_by": "root", "operation": "removed", "actor_id": "paulo"},
        {"operation_by": "root", "operation": "removed", "actor_id": "sam"},
        {"operation_by": "root", "operation": "removed", "actor_id": "sally"},
        {"operation_by": "root", "operation": "added", "actor_id": "paulo"},
        {"operation_by": "root", "operation": "added", "actor_id": "sam"},
        {"operation_by": "root", "operation": "added", "actor_id": "sally"},
        {"operation_by": "root", "operation": "created", "actor_id": None},
    ]
