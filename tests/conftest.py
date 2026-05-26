from datasette.app import Datasette
import sys
import pytest_asyncio


def pytest_configure():
    sys._pytest_running = True


@pytest_asyncio.fixture
async def ds():
    datasette = Datasette(
        config={
            "plugins": {
                "datasette-acl": {
                    "dynamic-groups": {
                        # Users with is_staff: True are in staff group
                        "staff": {"is_staff": True},
                    }
                }
            },
            # Root user can edit permissions
            "permissions": {"datasette-acl": {"id": "root"}},
        }
    )
    db = datasette.add_memory_database("db")
    await db.execute_write("create table t (id primary key)")
    await datasette.invoke_startup()
    await datasette.get_internal_database().execute_write(
        "insert into acl_groups (name) values (:name)", {"name": "dev"}
    )
    yield datasette
    # Need to manually drop because in-memory databases shared across tests
    await db.execute_write("drop table t")
    internal_db = datasette.get_internal_database()
    for table in await internal_db.table_names():
        if table.startswith("acl"):
            await internal_db.execute_write(f"drop table {table}")
    for table in await db.table_names():
        await db.execute_write(f"drop table {table}")


@pytest_asyncio.fixture
async def csrftoken(ds):
    # Datasette 1.0a30 replaced token-based asgi-csrf with header-based
    # CrossOriginProtectionMiddleware (Sec-Fetch-Site + Origin). There is no
    # longer a ds_csrftoken cookie. The test client is a non-browser client
    # (sends neither Sec-Fetch-Site nor Origin) so unsafe-method requests pass
    # through unchanged and no token is required. This value is still accepted
    # in form posts but is unused. See datasette/csrf.py.
    return "csrf-not-required-in-datasette-1.0a30"
