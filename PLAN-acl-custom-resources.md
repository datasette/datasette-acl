# Plan: Support Custom Resource Types in datasette-acl

## Problem Statement

datasette-acl currently only manages permissions for `TableResource`-scoped actions. It explicitly bails out in `permission_resources_sql` for anything else:

```python
if resource_class is None or not issubclass(resource_class, TableResource):
    return None
```

Three sibling plugins define custom resource types with resource-scoped actions that datasette-acl cannot manage today:

- **datasette-kanban**: `KanbanBoardResource(database, board_id)` -- 3 actions
- **datasette-town**: `TownQueryResource(database, query_id)` -- 3 resource-scoped actions (+ 2 global)
- **datasette-comments**: global actions only today, but will add resource-scoped permissions

All custom resources follow datasette's 2-level `Resource(parent, child)` pattern, which is exactly what `acl_resources` already stores with its `(database, resource)` columns.

## Key Insight

The `acl_resources` table's `(database, resource)` columns are semantically `(parent, child)` -- they just happen to have been named for the table case. The SQL in `permission_resources_sql` already returns `parent` and `child` columns. The schema change is essentially a rename plus adding a `resource_type` discriminator so we can tell kanban boards apart from tables apart from town queries.

## Schema Changes

### `acl_resources` table

Current:
```sql
create table if not exists acl_resources (
    id integer primary key,
    database text not null,
    resource text,
    unique(database, resource)
);
```

New:
```sql
create table if not exists acl_resources (
    id integer primary key,
    resource_type text not null,  -- e.g. "table", "kanban-board", "town-query"
    parent text not null,         -- was "database"
    child text,                   -- was "resource"
    unique(resource_type, parent, child)
);
```

`resource_type` is the `Resource.name` class attribute (e.g. `"table"`, `"kanban-board"`, `"town-query"`).

### Migration

Add a migration step in `startup()` that runs after `CREATE_TABLES_SQL`:

```python
# Migration: rename columns and add resource_type
# Check if old schema exists (has "database" column but no "resource_type" column)
try:
    await db.execute("select resource_type from acl_resources limit 0")
except Exception:
    # Old schema -- migrate
    await db.execute_write_script("""
        ALTER TABLE acl_resources RENAME TO acl_resources_old;

        CREATE TABLE acl_resources (
            id integer primary key,
            resource_type text not null,
            parent text not null,
            child text,
            unique(resource_type, parent, child)
        );

        INSERT INTO acl_resources (id, resource_type, parent, child)
        SELECT id, 'table', database, resource
        FROM acl_resources_old;

        DROP TABLE acl_resources_old;
    """)
```

All existing rows are migrated with `resource_type = 'table'` since that is the only type that could have been stored previously.

## Changes to `permission_resources_sql` (in `__init__.py`)

### Remove the `TableResource` gate

Current code:
```python
resource_class = action_obj.resource_class
if resource_class is None or not issubclass(resource_class, TableResource):
    return None
```

New code:
```python
resource_class = action_obj.resource_class
if resource_class is None:
    return None  # Global-only actions -- nothing for ACL to contribute
```

### Update the SQL to filter by `resource_type`

Add `resource_type` to the params and filter on it in the SQL:

```python
return PermissionSQL(
    sql="""
WITH actor_groups AS (
    SELECT ag.group_id
    FROM acl_actor_groups ag
    JOIN acl_groups g ON ag.group_id = g.id
    WHERE ag.actor_id = :actor_id
      AND g.deleted IS NULL
),
matching_permissions AS (
    SELECT
        ar.parent AS parent,
        ar.child AS child,
        CASE
            WHEN a.actor_id IS NOT NULL
                THEN 'actor:' || a.actor_id
            ELSE 'group:' || g.name
        END AS reason_component
    FROM acl a
    JOIN acl_actions aa ON a.action_id = aa.id
    JOIN acl_resources ar ON a.resource_id = ar.id
    LEFT JOIN acl_groups g ON a.group_id = g.id
    WHERE aa.name = :action
      AND ar.resource_type = :resource_type
      AND (
        a.actor_id = :actor_id
        OR a.group_id IN (SELECT group_id FROM actor_groups)
      )
      AND (a.group_id IS NULL OR g.deleted IS NULL)
)
SELECT
    parent,
    child,
    1 AS allow,
    'datasette-acl: ' || GROUP_CONCAT(reason_component, ', ') AS reason
FROM matching_permissions
GROUP BY parent, child
    """,
    params={
        "actor_id": actor["id"],
        "resource_type": resource_class.name,
    },
)
```

The key addition is `AND ar.resource_type = :resource_type` in the WHERE clause, plus the new `:resource_type` param bound to `resource_class.name`.

## Changes to `track_event` (table-creator-permissions)

Update to use the new column names:

```python
await db.execute_write(
    "INSERT OR IGNORE INTO acl_resources (resource_type, parent, child) VALUES (?, ?, ?);",
    ["table", event.database, event.table],
)
resource_id = (
    await db.execute(
        "SELECT id FROM acl_resources WHERE resource_type = ? AND parent = ? AND child = ?",
        ["table", event.database, event.table],
    )
).single_value()
```

## Changes to `views/table_acls.py`

### Update SQL for resource lookup

Replace all occurrences of `database`/`resource` column references:

```python
await internal_db.execute_write(
    "INSERT OR IGNORE INTO acl_resources (resource_type, parent, child) VALUES (?, ?, ?);",
    ["table", database, table],
)
resource_id = (
    await internal_db.execute(
        "SELECT id FROM acl_resources WHERE resource_type = ? AND parent = ? AND child = ?",
        ["table", database, table],
    )
).single_value()
```

### Dynamic action discovery (replace hardcoded action list)

Currently hardcodes `["insert-row", "delete-row", "update-row", "alter-table", "drop-table"]` in two places.

Replace with dynamic lookup from `datasette.actions`:

```python
from datasette.resources import TableResource

# Get all actions that apply to TableResource
table_actions_list = [
    action_obj.name
    for action_obj in datasette.actions.values()
    if action_obj.resource_class is not None
    and issubclass(action_obj.resource_class, TableResource)
]
```

## New Generic Resource ACL View

### New route: `/-/acl/resource/<resource_type>/<parent>/<child>`

Create a new view `views/resource_acls.py` that works for ANY resource type. It mirrors `table_acls.py` but is parameterized by `resource_type`.

The view:
1. Looks up `resource_type` in the URL.
2. Finds all actions from `datasette.actions` whose `resource_class.name == resource_type`.
3. Ensures the resource row exists in `acl_resources`.
4. Renders a generic permissions form (similar to `manage_table_acls.html` but with dynamic action names).

### Keep the existing table route working

The existing `/database/table/-/acl` route can delegate to the generic view internally, or simply be kept as-is but updated to use the new column names. Keeping it preserves backward compatibility for bookmarks/links.

### New template: `manage_resource_acls.html`

A generalized version of `manage_table_acls.html` where:
- Title says "Permissions for {resource_type}: {parent}/{child}" instead of "Permissions for {database}/{table}"
- Action checkboxes are driven by the `actions` list passed from the view (already dynamic)
- Back link is configurable or omitted for non-table resources

## How Plugins Register Resources with the ACL UI

Plugins do NOT need any new hook. The system discovers everything from `datasette.actions`:

1. **Action discovery**: `datasette.actions` (populated by `register_actions()` hooks from all plugins) already contains the `resource_class` for each action.
2. **Resource type discovery**: Iterate `datasette.actions.values()`, collect unique `resource_class` values. Each `resource_class.name` is a resource type that ACL can manage.
3. **Resource enumeration**: Each `Resource` subclass has `resources_sql()` which returns all instances. This is used to populate dropdowns or listing pages.

Plugins can add links to the generic ACL page from their own UI. For example, datasette-kanban could add a "Manage board permissions" link pointing to `/-/acl/resource/kanban-board/{database}/{board_id}`.

## Concrete File Changes Summary

### `datasette_acl/__init__.py`

| Section | Change |
|---|---|
| `CREATE_TABLES_SQL` | Rename `acl_resources` columns: `database` -> `parent`, `resource` -> `child`, add `resource_type` column and update unique constraint |
| `startup()` | Add migration logic to detect old schema and rename columns + backfill `resource_type='table'` |
| `permission_resources_sql()` | Remove `issubclass(resource_class, TableResource)` guard, accept any non-None `resource_class`. Add `resource_type` param. Update SQL to filter by `ar.resource_type` and reference `ar.parent`/`ar.child` |
| `track_event()` | Update `acl_resources` INSERT/SELECT to use `resource_type`, `parent`, `child` columns |
| `register_routes()` | Add route for generic resource ACL view |

### `datasette_acl/views/table_acls.py`

| Section | Change |
|---|---|
| Resource lookup SQL | Use `resource_type`, `parent`, `child` columns |
| Action list | Replace hardcoded 5-action list with dynamic lookup from `datasette.actions` filtered by `TableResource` |

### New file: `datasette_acl/views/resource_acls.py`

Generic resource permissions view, parameterized by `resource_type`, `parent`, `child`. Handles GET (render form) and POST (save changes) for any resource type.

### New file: `datasette_acl/templates/manage_resource_acls.html`

Generic template for resource permissions. Parameterized title, dynamic action list, configurable back link.

### `datasette_acl/views/groups.py`

No changes needed -- groups are resource-type-agnostic.

### `datasette_acl/utils.py`

No changes needed.

### `datasette_acl/hookspecs.py`

No changes needed. The `datasette_acl_valid_actors` hook remains useful for all resource types.

## Phased Implementation Order

### Phase 1: Schema + permission_resources_sql (core functionality)

1. Update `CREATE_TABLES_SQL` with new column names
2. Add migration in `startup()`
3. Update `permission_resources_sql()` to accept any resource type
4. Update `track_event()` for new column names
5. Update `table_acls.py` view for new column names
6. Update tests for new column names
7. Run `uv run pytest` to verify nothing breaks

After Phase 1, datasette-acl can grant/check permissions for any resource type via direct DB manipulation, even though only the table UI exists.

### Phase 2: Generic resource ACL view (UI)

1. Create `views/resource_acls.py`
2. Create `manage_resource_acls.html` template
3. Register the new route
4. Add tests for the generic view with a mock resource type

### Phase 3: Dynamic action discovery in table view

1. Replace hardcoded action lists with dynamic lookup
2. This makes the table ACL page automatically show new table-scoped actions registered by plugins

### Phase 4 (optional): ACL overview page

1. `/-/acl` page listing all resource types with manageable actions
2. Links to per-resource-type listings
