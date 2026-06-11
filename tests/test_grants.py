"""Tests for the Python grant helpers (grants.py) and build_resource (utils.py).

These back the JSON API (tasks 03-05) and consumer data-migrations: grant by
role / by raw actions, revoke, atomic update_role, audit rows, the actor/group
CHECK invariant, and building a core Resource for 2-level and parent-only types.
"""

from datasette import hookimpl
from datasette.app import Datasette
from datasette.permissions import Action, Resource
from datasette.plugins import pm
from datasette_acl.grants import (
    grant,
    revoke,
    update_role,
    list_grants,
    principal_type_for,
    _insert_grant,
)
from datasette_acl.roles import AclRole
from datasette_acl.utils import build_resource
import pytest
import pytest_asyncio


class DocResource(Resource):
    """Parent-only resource type (no parent_class)."""

    name = "doc"
    parent_class = None

    def __init__(self, parent, child=None):
        super().__init__(parent=parent, child=child)

    @classmethod
    async def resources_sql(cls, datasette, actor=None):
        return "SELECT '42' AS parent, NULL AS child"


class FolderResource(Resource):
    name = "folder"
    parent_class = None

    def __init__(self, parent, child=None):
        super().__init__(parent=parent, child=child)

    @classmethod
    async def resources_sql(cls, datasette, actor=None):
        return "SELECT 'home' AS parent, NULL AS child"


class FileResource(Resource):
    """Two-level resource type: a file inside a folder."""

    name = "file"
    parent_class = FolderResource

    def __init__(self, parent, child=None):
        super().__init__(parent=parent, child=child)

    @classmethod
    async def resources_sql(cls, datasette, actor=None):
        return "SELECT 'home' AS parent, 'notes.txt' AS child"


DOC_ROLES = [
    AclRole("doc", "Viewer", ["doc-view"], rank=1),
    AclRole("doc", "Editor", ["doc-view", "doc-edit"], rank=2),
    AclRole(
        "doc", "Manager", ["doc-view", "doc-edit", "doc-manage"], rank=3, manage=True
    ),
]


class GrantsPlugin:
    __name__ = "GrantsPlugin"

    @hookimpl
    def register_actions(self, datasette):
        return [
            Action(name="doc-view", description="View", resource_class=DocResource),
            Action(name="doc-edit", description="Edit", resource_class=DocResource),
            Action(name="doc-manage", description="Manage", resource_class=DocResource),
            Action(
                name="file-view", description="View file", resource_class=FileResource
            ),
        ]

    @hookimpl
    def datasette_acl_roles(self, datasette):
        return list(DOC_ROLES)


@pytest_asyncio.fixture
async def grants_ds():
    pm.register(GrantsPlugin(), name="grants-plugin")
    try:
        datasette = Datasette(config={"permissions": {"datasette-acl": {"id": "root"}}})
        await datasette.invoke_startup()
        # A group to grant to
        await datasette.get_internal_database().execute_write(
            "INSERT INTO acl_groups (name) VALUES ('staff')"
        )
        yield datasette
        internal_db = datasette.get_internal_database()
        for table in await internal_db.table_names():
            if table.startswith("acl"):
                await internal_db.execute_write(f"drop table {table}")
    finally:
        pm.unregister(name="grants-plugin")


async def _actions_for(datasette, actor_id):
    """Read the action names granted to actor_id on the doc/42 resource."""
    rows = await datasette.get_internal_database().execute(
        """
        SELECT acl_actions.name AS name
        FROM acl
        JOIN acl_actions ON acl.action_id = acl_actions.id
        JOIN acl_resources ON acl.resource_id = acl_resources.id
        WHERE acl.actor_id = :actor_id
          AND acl_resources.resource_type = 'doc'
          AND acl_resources.parent = '42'
        """,
        {"actor_id": actor_id},
    )
    return sorted(row["name"] for row in rows.rows)


async def _group_id(datasette, name):
    return (
        await datasette.get_internal_database().execute(
            "SELECT id FROM acl_groups WHERE name = ?", [name]
        )
    ).single_value()


async def _audit_ops(datasette):
    rows = await datasette.get_internal_database().execute(
        """
        SELECT acl_audit.operation, acl_audit.actor_id, acl_audit.group_id,
               acl_actions.name AS action_name, acl_audit.operation_by
        FROM acl_audit
        JOIN acl_actions ON acl_audit.action_id = acl_actions.id
        ORDER BY acl_audit.id
        """
    )
    return [dict(r) for r in rows.rows]


# --- build_resource -------------------------------------------------------


@pytest.mark.asyncio
async def test_build_resource_parent_only(grants_ds):
    resource = build_resource(grants_ds, "doc", "42")
    assert isinstance(resource, DocResource)
    assert resource.parent == "42"
    assert resource.child is None


@pytest.mark.asyncio
async def test_build_resource_two_level(grants_ds):
    resource = build_resource(grants_ds, "file", "home", "notes.txt")
    assert isinstance(resource, FileResource)
    assert resource.parent == "home"
    assert resource.child == "notes.txt"


@pytest.mark.asyncio
async def test_build_resource_unknown_type(grants_ds):
    with pytest.raises(ValueError):
        build_resource(grants_ds, "nope", "x")


# --- grant ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_by_role(grants_ds):
    result = await grant(
        grants_ds, "doc", "42", actor_id="alice", role="Editor", by_actor="root"
    )
    assert result == ["doc-edit", "doc-view"]
    assert await _actions_for(grants_ds, "alice") == ["doc-edit", "doc-view"]
    # datasette.allowed reflects it
    assert await grants_ds.allowed(
        action="doc-edit", resource=DocResource("42"), actor={"id": "alice"}
    )


@pytest.mark.asyncio
async def test_grant_by_raw_actions(grants_ds):
    result = await grant(
        grants_ds, "doc", "42", actor_id="bob", actions=["doc-view"], by_actor="root"
    )
    assert result == ["doc-view"]
    assert await _actions_for(grants_ds, "bob") == ["doc-view"]


@pytest.mark.asyncio
async def test_grant_is_idempotent(grants_ds):
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Editor", by_actor="root")
    # Granting again with overlap only inserts the new action
    result = await grant(
        grants_ds, "doc", "42", actor_id="alice", role="Manager", by_actor="root"
    )
    assert result == ["doc-edit", "doc-manage", "doc-view"]
    assert await _actions_for(grants_ds, "alice") == [
        "doc-edit",
        "doc-manage",
        "doc-view",
    ]
    # Only one row per action despite the overlap
    count = (
        await grants_ds.get_internal_database().execute(
            "SELECT count(*) FROM acl WHERE actor_id = 'alice'"
        )
    ).single_value()
    assert count == 3


@pytest.mark.asyncio
async def test_grant_to_group(grants_ds):
    gid = await _group_id(grants_ds, "staff")
    result = await grant(
        grants_ds, "doc", "42", group_id=gid, role="Viewer", by_actor="root"
    )
    assert result == ["doc-view"]
    grants = await list_grants(grants_ds, "doc", "42")
    assert grants == [
        {
            "principal": "group",
            "actor_id": None,
            "group_id": gid,
            "group_name": "staff",
            "actions": ["doc-view"],
        }
    ]


@pytest.mark.asyncio
async def test_grant_unknown_role_raises(grants_ds):
    with pytest.raises(ValueError):
        await grant(grants_ds, "doc", "42", actor_id="alice", role="Nope")


@pytest.mark.asyncio
async def test_grant_requires_exactly_one_principal(grants_ds):
    with pytest.raises(ValueError):
        await grant(grants_ds, "doc", "42", role="Viewer")
    gid = await _group_id(grants_ds, "staff")
    with pytest.raises(ValueError):
        await grant(grants_ds, "doc", "42", actor_id="a", group_id=gid, role="Viewer")


@pytest.mark.asyncio
async def test_grant_requires_exactly_one_of_role_or_actions(grants_ds):
    with pytest.raises(ValueError):
        await grant(grants_ds, "doc", "42", actor_id="a")
    with pytest.raises(ValueError):
        await grant(
            grants_ds, "doc", "42", actor_id="a", role="Viewer", actions=["doc-view"]
        )


# --- revoke ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_removes_all_rows(grants_ds):
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Manager", by_actor="root")
    removed = await revoke(grants_ds, "doc", "42", actor_id="alice", by_actor="root")
    assert removed == ["doc-edit", "doc-manage", "doc-view"]
    assert await _actions_for(grants_ds, "alice") == []


@pytest.mark.asyncio
async def test_revoke_only_targets_principal(grants_ds):
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Editor", by_actor="root")
    await grant(grants_ds, "doc", "42", actor_id="bob", role="Viewer", by_actor="root")
    await revoke(grants_ds, "doc", "42", actor_id="alice", by_actor="root")
    assert await _actions_for(grants_ds, "alice") == []
    assert await _actions_for(grants_ds, "bob") == ["doc-view"]


# --- update_role ----------------------------------------------------------


@pytest.mark.asyncio
async def test_update_role_swaps_atomically(grants_ds):
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Manager", by_actor="root")
    result = await update_role(
        grants_ds, "doc", "42", actor_id="alice", role="Viewer", by_actor="root"
    )
    assert result == ["doc-view"]
    # Only doc-view remains: doc-edit and doc-manage removed
    assert await _actions_for(grants_ds, "alice") == ["doc-view"]


@pytest.mark.asyncio
async def test_update_role_upgrades(grants_ds):
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Viewer", by_actor="root")
    result = await update_role(
        grants_ds, "doc", "42", actor_id="alice", role="Editor", by_actor="root"
    )
    assert result == ["doc-edit", "doc-view"]
    assert await _actions_for(grants_ds, "alice") == ["doc-edit", "doc-view"]


# --- audit ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_rows_written(grants_ds):
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Editor", by_actor="root")
    await update_role(
        grants_ds, "doc", "42", actor_id="alice", role="Viewer", by_actor="admin"
    )
    await revoke(grants_ds, "doc", "42", actor_id="alice", by_actor="root")
    ops = await _audit_ops(grants_ds)
    # grant Editor: +doc-view +doc-edit; update to Viewer: -doc-edit;
    # revoke: -doc-view
    summary = [(o["operation"], o["action_name"], o["operation_by"]) for o in ops]
    assert ("added", "doc-view", "root") in summary
    assert ("added", "doc-edit", "root") in summary
    assert ("removed", "doc-edit", "admin") in summary
    assert ("removed", "doc-view", "root") in summary
    # All audit rows recorded the actor principal, no group
    assert all(o["actor_id"] == "alice" and o["group_id"] is None for o in ops)


# --- list_grants ----------------------------------------------------------


@pytest.mark.asyncio
async def test_list_grants_actor_and_group(grants_ds):
    gid = await _group_id(grants_ds, "staff")
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Editor", by_actor="root")
    await grant(grants_ds, "doc", "42", group_id=gid, role="Viewer", by_actor="root")
    grants = await list_grants(grants_ds, "doc", "42")
    assert grants == [
        {
            "principal": "actor",
            "actor_id": "alice",
            "group_id": None,
            "group_name": None,
            "actions": ["doc-edit", "doc-view"],
        },
        {
            "principal": "group",
            "actor_id": None,
            "group_id": gid,
            "group_name": "staff",
            "actions": ["doc-view"],
        },
    ]


@pytest.mark.asyncio
async def test_list_grants_empty(grants_ds):
    assert await list_grants(grants_ds, "doc", "42") == []


@pytest.mark.asyncio
async def test_list_grants_public_principal_and_ordering(grants_ds):
    # Public-audience grants come back with principal naming the audience,
    # straight from the stored column, with no id; the list is ordered actors,
    # then groups, then audiences.
    gid = await _group_id(grants_ds, "staff")
    await grant(
        grants_ds, "doc", "42", principal_type="everyone", role="Viewer", by_actor="root"
    )
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Editor", by_actor="root")
    await grant(grants_ds, "doc", "42", group_id=gid, role="Viewer", by_actor="root")
    grants = await list_grants(grants_ds, "doc", "42")
    assert [(g["principal"], g["actor_id"], g["group_id"]) for g in grants] == [
        ("actor", "alice", None),
        ("group", None, gid),
        ("everyone", None, None),
    ]


# --- principal_type -------------------------------------------------------


def test_principal_type_for():
    # Resolution from whichever id was supplied
    assert principal_type_for("alice", None) == "actor"
    assert principal_type_for(None, 1) == "group"
    # Redundant explicit types are accepted alongside the matching id
    assert principal_type_for("alice", None, "actor") == "actor"
    assert principal_type_for(None, 1, "group") == "group"
    # Public audiences are named by principal_type alone, with no id
    assert principal_type_for(None, None, "everyone") == "everyone"
    assert principal_type_for(None, None, "authenticated") == "authenticated"
    assert principal_type_for(None, None, "anonymous") == "anonymous"
    # Invalid combinations
    with pytest.raises(ValueError):
        principal_type_for("bob", None, "everyone")  # audience with actor_id
    with pytest.raises(ValueError):
        principal_type_for(None, 1, "anonymous")  # audience with group_id
    with pytest.raises(ValueError):
        principal_type_for("bob", None, "group")  # group needs group_id
    with pytest.raises(ValueError):
        principal_type_for(None, 1, "actor")  # group_id with actor type
    with pytest.raises(ValueError):
        principal_type_for("bob", None, "alien")  # unknown type
    with pytest.raises(ValueError):
        principal_type_for(None, None)  # no principal
    with pytest.raises(ValueError):
        principal_type_for(None, None, "actor")  # actor type without an id
    with pytest.raises(ValueError):
        principal_type_for("bob", 1)  # both ids


@pytest.mark.asyncio
async def test_grant_audience_with_actor_id_raises(grants_ds):
    with pytest.raises(ValueError):
        await grant(
            grants_ds,
            "doc",
            "42",
            actor_id="bob",
            role="Viewer",
            principal_type="everyone",
        )


@pytest.mark.asyncio
async def test_raw_audience_insert_with_actor_id_rejected(grants_ds):
    # The CHECK constraint is the storage-layer backstop behind the Python
    # validation: an audience row carrying an actor_id can never be stored,
    # even by raw SQL.
    import sqlite3

    db = grants_ds.get_internal_database()
    with pytest.raises(sqlite3.IntegrityError):
        await db.execute_write(
            """
            insert into acl (principal_type, actor_id, group_id, resource_id, action_id)
            values ('everyone', 'bob', null,
                (select min(id) from acl_resources),
                (select min(id) from acl_actions))
            """
        )


@pytest.mark.asyncio
async def test_insert_grant_dedupes(grants_ds):
    # Two identical _insert_grant calls -- bypassing grant()'s
    # read-modify-write guard -- yield one row: the partial unique indexes
    # actually enforce non-duplication (the old UNIQUE constraint never fired
    # across its always-NULL columns).
    await grant(grants_ds, "doc", "42", actor_id="alice", role="Viewer", by_actor="root")
    db = grants_ds.get_internal_database()
    resource_id = (
        await db.execute(
            "select id from acl_resources where resource_type = 'doc' and parent = '42'"
        )
    ).single_value()
    for _ in range(2):
        await _insert_grant(
            db, resource_id, "actor", "alice", None, "doc-view", "root"
        )
    count = (
        await db.execute("select count(*) from acl where actor_id = 'alice'")
    ).single_value()
    assert count == 1
    # Same for a public audience (covered by acl_public_unique)
    for _ in range(2):
        await _insert_grant(
            db, resource_id, "everyone", None, None, "doc-view", "root"
        )
    count = (
        await db.execute(
            "select count(*) from acl where principal_type = 'everyone'"
        )
    ).single_value()
    assert count == 1
