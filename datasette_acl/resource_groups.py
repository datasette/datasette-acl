from datasette.plugins import pm
from datasette.utils import await_me_maybe


DEFAULT_ROLE_BUNDLES = [
    {
        "name": "viewer",
        "description": "Read-only access to Datasette resources.",
        "actions": [
            "view-instance",
            "view-database",
            "view-table",
            "view-query",
        ],
    },
    {
        "name": "editor",
        "description": "Read and write access to tables.",
        "actions": [
            "view-instance",
            "view-database",
            "view-table",
            "view-query",
            "insert-row",
            "update-row",
            "delete-row",
        ],
    },
    {
        "name": "admin",
        "description": "Administrative access to tables.",
        "actions": [
            "view-instance",
            "view-database",
            "view-table",
            "view-query",
            "insert-row",
            "update-row",
            "delete-row",
            "alter-table",
            "drop-table",
        ],
    },
]


async def get_role_bundles(datasette):
    bundles_by_name = {bundle["name"]: bundle for bundle in DEFAULT_ROLE_BUNDLES}
    for hook in pm.hook.datasette_acl_role_bundles(datasette=datasette):
        for bundle in await await_me_maybe(hook) or []:
            existing = bundles_by_name.get(bundle["name"])
            if existing and existing != bundle:
                raise ValueError(
                    "Conflicting datasette_acl_role_bundles definition for "
                    f"{bundle['name']!r}"
                )
            bundles_by_name[bundle["name"]] = bundle
    return [bundles_by_name[name] for name in sorted(bundles_by_name)]


async def ensure_role_bundles(datasette):
    db = datasette.get_internal_database()
    for bundle in await get_role_bundles(datasette):
        await db.execute_write(
            """
            insert into acl_role_bundles (name, description, source_plugin, is_system)
            values (:name, :description, :source_plugin, :is_system)
            on conflict(name) do update set
                description = excluded.description,
                source_plugin = excluded.source_plugin,
                is_system = excluded.is_system
            """,
            {
                "name": bundle["name"],
                "description": bundle.get("description"),
                "source_plugin": bundle.get("source_plugin"),
                "is_system": int(bundle.get("is_system", bundle["name"] in {"viewer", "editor", "admin"})),
            },
        )
        role_bundle_id = (
            await db.execute(
                "select id from acl_role_bundles where name = :name",
                {"name": bundle["name"]},
            )
        ).single_value()
        await db.execute_write(
            "delete from acl_role_bundle_actions where role_bundle_id = :role_bundle_id",
            {"role_bundle_id": role_bundle_id},
        )
        await db.execute_write_many(
            """
            insert into acl_role_bundle_actions (role_bundle_id, action_name)
            values (:role_bundle_id, :action_name)
            """,
            [
                {"role_bundle_id": role_bundle_id, "action_name": action_name}
                for action_name in sorted(set(bundle["actions"]))
            ],
        )
