from datasette.app import Datasette
import pytest


@pytest.mark.asyncio
async def test_can_startup_with_no_configuration():
    datasette = Datasette()
    await datasette.invoke_startup()
    assert (await datasette.client.get("/")).status_code == 200


@pytest.mark.asyncio
async def test_startup_applies_internal_migrations():
    # Startup should create the ACL tables via sqlite-migrate and record the
    # applied migrations in the _sqlite_migrations tracking table.
    datasette = Datasette(memory=True)
    await datasette.invoke_startup()
    db = datasette.get_internal_database()
    tables = set(await db.table_names())
    assert {"acl", "acl_resources", "acl_actions", "acl_groups"} <= tables
    assert "_sqlite_migrations" in tables
    applied = [
        r["name"]
        for r in await db.execute(
            "select name from _sqlite_migrations where migration_set = ?",
            ["datasette-acl.internal"],
        )
    ]
    assert "m001_initial" in applied

    # Re-running startup is idempotent.
    await datasette.invoke_startup()
