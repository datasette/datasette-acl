from datasette.app import Datasette
import pytest


@pytest.mark.asyncio
async def test_can_startup_with_no_configuration():
    datasette = Datasette()
    await datasette.invoke_startup()
    assert (await datasette.client.get("/")).status_code == 200
