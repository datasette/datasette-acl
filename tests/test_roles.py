"""
Tests for the friendly-roles layer: the datasette_acl_roles hook, the startup
registry keyed by resource_type, and the role<->action resolution helpers.
"""

from datasette import hookimpl
from datasette.app import Datasette
from datasette.permissions import Action, Resource
from datasette.plugins import pm
from datasette_acl.roles import (
    AclRole,
    role_for_actions,
    actions_for_role,
    manage_actions,
    manage_only_actions,
)
import pytest
import pytest_asyncio


class DocResource(Resource):
    """Throwaway resource type used only in these tests."""

    name = "mock-doc"
    parent_class = None

    def __init__(self, parent, child=None):
        super().__init__(parent=parent, child=child)


# Roles declared for the mock-doc resource type, deliberately registered out of
# rank order to prove the registry sorts/resolves correctly.
MOCK_ROLES = [
    AclRole("mock-doc", "Manager", ["doc-view", "doc-edit", "doc-manage"],
            rank=3, manage=True),
    AclRole("mock-doc", "Viewer", ["doc-view"], rank=1),
    AclRole("mock-doc", "Editor", ["doc-view", "doc-edit"], rank=2),
]


class MockDocPlugin:
    __name__ = "MockDocPlugin"

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
        return list(MOCK_ROLES)


@pytest_asyncio.fixture
async def doc_ds():
    pm.register(MockDocPlugin(), name="mock-doc-plugin")
    try:
        datasette = Datasette(
            config={"permissions": {"datasette-acl": {"id": "root"}}}
        )
        await datasette.invoke_startup()
        yield datasette
        internal_db = datasette.get_internal_database()
        for table in await internal_db.table_names():
            if table.startswith("acl"):
                await internal_db.execute_write(f"drop table {table}")
    finally:
        pm.unregister(name="mock-doc-plugin")


@pytest.mark.asyncio
async def test_registry_built_and_grouped_by_resource_type(doc_ds):
    registry = doc_ds._acl_roles_registry
    assert set(registry.keys()) == {"mock-doc"}
    roles = registry["mock-doc"]
    # All three roles present, sorted by rank ascending
    assert [r.name for r in roles] == ["Viewer", "Editor", "Manager"]
    assert [r.rank for r in roles] == [1, 2, 3]


def test_role_for_actions_picks_highest_rank_subset():
    roles = list(MOCK_ROLES)
    # Exactly the Editor set => Editor
    assert role_for_actions(roles, {"doc-view", "doc-edit"}).name == "Editor"
    # Just view => Viewer
    assert role_for_actions(roles, {"doc-view"}).name == "Viewer"
    # Superset of Manager => Manager (highest rank whose actions are a subset)
    assert (
        role_for_actions(
            roles, {"doc-view", "doc-edit", "doc-manage", "extra"}
        ).name
        == "Manager"
    )
    # Granted spans Editor but not Manager (no doc-manage) => Editor
    assert (
        role_for_actions(roles, {"doc-view", "doc-edit", "other"}).name
        == "Editor"
    )


def test_role_for_actions_no_match_returns_none():
    roles = list(MOCK_ROLES)
    # No granted actions => no role fits (every role needs at least doc-view)
    assert role_for_actions(roles, set()) is None
    # An unrelated action set matches no role
    assert role_for_actions(roles, {"doc-edit"}) is None


def test_actions_for_role():
    roles = list(MOCK_ROLES)
    assert actions_for_role(roles, "Editor") == ["doc-view", "doc-edit"]
    assert actions_for_role(roles, "Nope") is None


def test_manage_actions_returns_manager_actions():
    roles = list(MOCK_ROLES)
    assert manage_actions(roles) == {"doc-view", "doc-edit", "doc-manage"}


def test_manage_actions_empty_when_no_manage_role():
    roles = [
        AclRole("mock-doc", "Viewer", ["doc-view"], rank=1),
        AclRole("mock-doc", "Editor", ["doc-view", "doc-edit"], rank=2),
    ]
    assert manage_actions(roles) == set()


def test_manage_only_actions_excludes_shared_actions():
    # The manage gate must authorize against only the action(s) exclusive to a
    # manage role; the bundled view/edit actions must NOT count (otherwise any
    # Viewer/Editor would pass the manage check).
    roles = list(MOCK_ROLES)
    assert manage_only_actions(roles) == {"doc-manage"}


def test_manage_only_actions_empty_when_no_manage_role():
    roles = [
        AclRole("mock-doc", "Viewer", ["doc-view"], rank=1),
        AclRole("mock-doc", "Editor", ["doc-view", "doc-edit"], rank=2),
    ]
    assert manage_only_actions(roles) == set()
