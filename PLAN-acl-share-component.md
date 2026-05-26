# Plan: ACL Share Web Component (Google Docs-style Sharing Dialog)

## Context

Town already has a Google Docs-style `ShareDialog.svelte` for per-query sharing. Kanban has no sharing UI at all. Both manage permissions through their own tables/code. Meanwhile, datasette-acl already has the backend for resource-scoped ACLs with groups, actors, audit logging -- but its UI is a full admin page with action-level checkboxes, not an embeddable sharing dialog.

This plan adds a `<datasette-acl-share>` web component that any plugin can drop into its UI for inline permission management. Town replaces its custom ShareDialog, kanban gains sharing it never had, and all permissions flow through datasette-acl's unified backend.

## Prerequisites

- datasette-acl custom resource support (see PLAN-acl-custom-resources.md) -- so ACL can manage kanban-board, town-query, etc.

## 1. Role Presets Hookspec

The ACL model is per-action, but users think in roles. Plugins declare role mappings:

**File:** `datasette_acl/hookspecs.py`

```python
@hookspec
def datasette_acl_roles(datasette):
    """Return list of AclRole objects mapping friendly names to action bundles."""
```

**File:** `datasette_acl/roles.py`

```python
@dataclass
class AclRole:
    resource_type: str   # "kanban-board", "town-query", etc.
    name: str            # "Viewer", "Editor", "Admin"
    actions: list[str]   # ["kanban-view-board", "kanban-edit-board"]
    description: str = ""
```

**Example implementations:**

```python
# In datasette-kanban/__init__.py
@hookimpl
def datasette_acl_roles(datasette):
    return [
        AclRole("kanban-board", "Viewer", ["kanban-view-board"]),
        AclRole("kanban-board", "Editor", ["kanban-view-board", "kanban-edit-board"]),
        AclRole("kanban-board", "Admin", ["kanban-view-board", "kanban-edit-board", "kanban-admin-board"]),
    ]

# In datasette-town/__init__.py
@hookimpl
def datasette_acl_roles(datasette):
    return [
        AclRole("town-query", "Viewer", ["datasette-town-view"]),
        AclRole("town-query", "Editor", ["datasette-town-view", "datasette-town-edit"]),
    ]
```

If no roles are registered for a resource type, the web component falls back to showing raw action checkboxes (like the current admin page).

Roles are collected at startup into a `{resource_type: [AclRole]}` registry, same pattern as the provider registry in datasette-comments.

## 2. JSON API Endpoints

datasette-acl currently uses form POSTs. Add JSON API endpoints for the web component.

**File:** `datasette_acl/views/api.py` (new)

### `GET /-/acl/api/resource/{resource_type}/{parent}/{child}`

Returns current grants for a resource:

```json
{
  "resource_type": "town-query",
  "parent": "mydb",
  "child": "query-abc",
  "roles": [
    {"name": "Viewer", "actions": ["datasette-town-view"]},
    {"name": "Editor", "actions": ["datasette-town-view", "datasette-town-edit"]}
  ],
  "grants": [
    {"type": "actor", "id": "alice", "display": "Alice", "role": "Editor", "actions": ["datasette-town-view", "datasette-town-edit"]},
    {"type": "group", "id": "2", "display": "staff", "role": "Viewer", "actions": ["datasette-town-view"]}
  ]
}
```

The `role` field is resolved by matching the actor/group's granted actions against the registered roles. If no role matches exactly, `role` is `null` and raw `actions` are shown.

### `POST /-/acl/api/resource/{resource_type}/{parent}/{child}/grant`

```json
{"actor_id": "bob", "role": "Editor"}
// or for raw actions:
{"actor_id": "bob", "actions": ["datasette-town-view"]}
// or for groups:
{"group_id": 3, "role": "Viewer"}
```

Resolves role to actions, upserts ACL rows, records audit log entries.

### `POST /-/acl/api/resource/{resource_type}/{parent}/{child}/revoke`

```json
{"actor_id": "bob"}
// or
{"group_id": 3}
```

Removes all ACL rows for that actor/group on this resource.

### `POST /-/acl/api/resource/{resource_type}/{parent}/{child}/update`

```json
{"actor_id": "bob", "role": "Viewer"}
```

Changes role (revokes old actions, grants new ones atomically). Records audit.

### `GET /-/acl/api/actors?prefix=al`

Actor autocomplete. Calls `datasette_acl_valid_actors` hook, filters by prefix. Returns:

```json
{"actors": [{"id": "alice", "display": "Alice"}]}
```

### `GET /-/acl/api/groups`

List available groups for the group picker:

```json
{"groups": [{"id": 1, "name": "staff", "member_count": 5}]}
```

All endpoints require the `datasette-acl` permission (same gate as the admin pages).

## 3. Web Component

**New Vite entry:** `datasette_acl/frontend/src/web_components/acl_share.tsx`

Note: datasette-acl currently has no frontend build system. This plan adds one (Vite + Preact, same stack as datasette-comments) to build the web component. Alternatively, this could be vanilla JS/lit-element to avoid adding a build step -- but Preact keeps consistency with datasette-comments' web components and is tiny (~3KB).

### `<datasette-acl-share>` Element

```html
<datasette-acl-share
  resource-type="town-query"
  parent="mydb"
  child="query-abc"
  actor-json='{"id":"alice","name":"Alice"}'
></datasette-acl-share>
```

**Attributes:**

| Attribute | Required | Description |
|-----------|----------|-------------|
| `resource-type` | yes | Resource type string |
| `parent` | yes | Parent identifier (usually database name) |
| `child` | yes | Child identifier (board_id, query_id, etc.) |
| `actor-json` | yes | Current user (for "Owner" display, permission gating) |

**Rendered UI** (Google Docs-style dialog content, not the modal wrapper -- the host plugin wraps it in its own modal/popover):

```
┌─────────────────────────────────────────────┐
│  Add people                                 │
│  [actor search input________] [Share]       │
│                                             │
│  People with access                         │
│  ┌─────────────────────────────────────────┐│
│  │ 👤 alice (you)              Owner       ││
│  │ 👤 bob                      [Editor ▾]  ││
│  │ 👥 staff (3 members)        [Viewer ▾] ×││
│  └─────────────────────────────────────────┘│
│                                             │
│  [Copy link]                                │
└─────────────────────────────────────────────┘
```

- Actor input with autocomplete (calls `GET /-/acl/api/actors?prefix=...`)
- Role dropdown per grant (populated from roles API response)
- Remove button (×) per grant
- Groups show member count
- Changing dropdown calls update endpoint
- "Owner" is display-only (determined by host plugin, passed as attribute or derived)

**Events emitted:**

| Event | Detail | Description |
|-------|--------|-------------|
| `grant-added` | `{actor_id, role}` | New grant created |
| `grant-removed` | `{actor_id}` or `{group_id}` | Grant revoked |
| `grant-updated` | `{actor_id, role}` | Role changed |

Host plugins can listen to these for side effects (e.g., town could clear its is_public flag when all shares are removed).

**CSS:** Ships its own scoped styles. No shadow DOM (consistent with datasette-comments components). CSS classes prefixed with `datasette-acl-`.

## 4. Frontend Build Setup for datasette-acl

Add to datasette-acl:
- `frontend/package.json` (Preact, Vite, preact-custom-element)
- `frontend/vite.config.ts` (single entry: `acl_share` web component)
- `frontend/src/web_components/acl_share.tsx`
- Build output: `datasette_acl/static/gen/`

datasette-acl exposes a Python helper (like datasette-comments does) for consuming plugins to include the JS/CSS:

```python
# In datasette_acl/__init__.py
def datasette_acl_share_entry(datasette):
    """Returns vite entry HTML for the share web component."""
    return vite_entry(datasette=datasette, plugin_package="datasette_acl", ...)
```

This adds `datasette-vite` as a dependency of datasette-acl.

## 5. Town Integration

### Remove:
- `datasette_town_shares` table + migrations
- Share CRUD methods from `internal_db.py` (`add_share`, `remove_share`, `update_share`, `list_shares`, `get_share_for_actor`)
- Share API routes from `routes/api.py` (4 endpoints)
- `ShareDialog.svelte` component
- `is_public` field from queries table (public access becomes a grant to a wildcard/anonymous actor, or a separate toggle that maps to an ACL rule)

### Replace in `QueryDetailPage.svelte`:
```svelte
<!-- Before: custom ShareDialog -->
<ShareDialog {shares} {isPublic} ... />

<!-- After: shared web component -->
<datasette-acl-share
  resource-type="town-query"
  parent={database}
  child={queryId}
  actor-json={JSON.stringify(currentActor)}
></datasette-acl-share>
```

### Permission changes:
- Town's `permission_resources_sql` hook (the UNION queries for owner/shared/public) gets removed
- datasette-acl handles all permission checks via its own `permission_resources_sql`
- Town only needs to `register_actions()` with its resource types -- ACL does the rest
- Query creation still inserts initial "owner" grant via ACL API

## 6. Kanban Integration

### Add to board settings or board page:
```svelte
<datasette-acl-share
  resource-type="kanban-board"
  parent={database}
  child={String(boardId)}
  actor-json={JSON.stringify(currentActor)}
></datasette-acl-share>
```

### Permission changes:
- Kanban's existing `check_permission` decorator continues to call `datasette.allowed()` -- no change needed
- datasette-acl's `permission_resources_sql` now handles `kanban-view-board` / `kanban-edit-board` / `kanban-admin-board` (from PLAN-acl-custom-resources.md)
- Board creation auto-grants admin to creator (via ACL API call in the create-board route)

Kanban gains per-board sharing that it never had -- currently permissions are configured in `datasette.yaml` only.

## 7. Public Access Pattern

Town has `is_public` as a query-level flag. In the ACL model, "public" = grant to a well-known actor ID (e.g., `"*"` or `"_anonymous"`). The web component can include a "General access" toggle at the bottom (like town's current UI) that adds/removes a grant for the anonymous actor.

This requires datasette-acl to understand a convention: a grant to actor `"*"` means "anyone, including unauthenticated users." The `permission_resources_sql` query would need a clause like:

```sql
OR a.actor_id = '*'  -- public grant
```

## Implementation Order

1. **Roles hookspec + registry** (datasette-acl)
2. **JSON API endpoints** (datasette-acl)
3. **Frontend build setup** (datasette-acl)
4. **`<datasette-acl-share>` web component** (datasette-acl)
5. **Town integration** (remove shares, use web component)
6. **Kanban integration** (add web component to board UI)

## Dependencies

- Requires PLAN-acl-custom-resources.md to be implemented first (so ACL handles non-table resources)
- datasette-acl gains dependencies: `datasette-vite`, `preact`, `preact-custom-element`
