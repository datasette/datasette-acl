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
    ),
)
async def test_manage_table_permissions(
    ds, description, setup_post_data, post_data, expected_members, expected_audit_rows
):
    internal_db = ds.get_internal_database()

    csrf_token_response = await ds.client.get(
        "/-/acl/groups",
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
    group_members = {
        d["actor_id"]
        for d in (
            await internal_db.execute(
                """
        select actor_id from acl_actor_groups
        where group_id = (select id from acl_groups where name = 'dev')
    """
            )
        ).rows
    }
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
