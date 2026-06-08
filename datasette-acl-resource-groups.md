# `datasette-acl` Resource Groups Specification

## Purpose

Extend `datasette-acl` from:

- actor groups
- table-level permission assignment

to a more general authorization system that can manage permissions for **collections of resources**.

The key new concept is a **resource group**:

- an actor group is a collection of actors
- a resource group is a collection of Datasette resources

Permissions are then granted:

- from an actor
- or from an actor group
- to a resource group
- for one or more actions, or via named role bundles

This turns `datasette-acl` into a general collaboration/authz layer for Datasette applications and plugins.


## Design Goals

### Primary goals

1. Provide one reusable permission engine for collaborative Datasette applications.
2. Keep Datasette’s SQL-based permission system as the enforcement mechanism.
3. Support first-class grouping of resources across tables, queries, files, views, pages, and plugin-defined resources.
4. Allow higher-level plugins, such as `datasette-projects`, to use resource groups as their security boundary.
5. Avoid building a second, parallel ACL system in every application plugin.

### Secondary goals

1. Maintain backward compatibility with current `datasette-acl` actor-group and table-permission features where feasible.
2. Preserve auditability.
3. Make the UI understandable for non-technical administrators.
4. Support plugin-defined resource types and role bundles.

### Non-goals

1. Replace Datasette core permissions.
2. Force all Datasette apps to use resource groups.
3. Model every possible enterprise IAM feature.


## Core Concepts

### Actor

An actor is the Datasette `request.actor` dictionary identity, usually with at least:

- `id`

Actors may come from any auth plugin.

### Actor group

An actor group is a named collection of actors.

Examples:

- `newsroom-staff`
- `students`
- `contractors`

This concept already exists in `datasette-acl`.

### Resource

A resource is anything Datasette can protect using an action/resource check.

Examples:

- a table
- a query
- a database
- a file source
- a single file
- a custom plugin page
- a custom plugin-defined resource such as `ProjectResource("abc")`

### Resource group

A resource group is a named collection of resources.

Examples:

- all resources that belong to a collaboration workspace
- all tables and files associated with a dataset release
- all assets managed by a project

Examples of resources inside a group:

- `TableResource(database="data", table="leads")`
- `QueryResource(database="data", query_name="recent_updates")`
- `FileSourceResource("documents")`
- custom `ProjectFileResource(project_id="p1", file_id="df-...")`

### Grant

A grant associates:

- an actor or actor group
- with an action or role
- against a resource group

Examples:

- actor `alice` has role `admin` on resource group `grp_project_abc`
- actor group `staff` has role `viewer` on resource group `grp_open_data_2026`
- actor `bob` has action `update-row` on resource group `grp_internal_sheet`

### Role bundle

A role bundle is a named set of actions.

Examples:

- `viewer` => `view-table`, `view-query`, `view-database`
- `editor` => viewer actions plus `insert-row`, `update-row`, `delete-row`
- `admin` => editor actions plus `alter-table`, `drop-table`, plugin-specific management actions

Role bundles should be plugin-extensible.


## High-Level Architecture

`datasette-acl` should evolve into four layers:

1. **Identity layer**
   - actors
   - actor groups
2. **Resource layer**
   - resource kinds
   - resource group definitions
   - resource group membership
3. **Grant layer**
   - actor/group to resource-group grants
   - action grants or role grants
4. **Compilation layer**
   - converts grants into `PermissionSQL`
   - answers Datasette permission checks efficiently

The important shift is that table ACLs become a special case of the more general model.


## Data Model

The plugin should continue to use `internal.db`.

### Existing tables to preserve

Current `datasette-acl` tables include:

- `acl_groups`
- `acl_actor_groups`
- `acl_groups_audit`
- `acl_resources`
- `acl_actions`
- `acl`
- `acl_audit`

Those are not sufficient for general resource groups. The cleanest path is to add new tables rather than overloading the current table-permission model too aggressively.

### New tables

#### `acl_resource_groups`

Defines named resource groups.

Columns:

- `id integer primary key`
- `slug text unique not null`
- `name text not null`
- `description text`
- `created_by text`
- `created_at text default (datetime('now'))`
- `updated_at text default (datetime('now'))`
- `deleted integer default 0`

Notes:

- `slug` is the stable identifier used in URLs and APIs.
- `name` is the display label.

#### `acl_resource_group_items`

Membership table connecting concrete resources to resource groups.

Columns:

- `id integer primary key`
- `resource_group_id integer not null references acl_resource_groups(id)`
- `resource_type text not null`
- `resource_key text not null`
- `note text`
- `added_by text`
- `added_at text default (datetime('now'))`
- `unique(resource_group_id, resource_type, resource_key)`

`resource_type` examples:

- `table`
- `query`
- `database`
- `file-source`
- `file`
- `custom`

`resource_key` examples:

- `data/leads`
- `data/recent_updates`
- `documents`
- `df-01abc...`
- plugin-defined opaque key

This table stores normalized references, not serialized Python objects.

#### `acl_resource_groups_audit`

Audit log for resource group lifecycle and membership changes.

Columns:

- `id integer primary key`
- `timestamp text default (datetime('now'))`
- `operation_by text`
- `operation text`
- `resource_group_id integer`
- `resource_type text`
- `resource_key text`
- `metadata text`

`operation` examples:

- `created`
- `updated`
- `deleted`
- `resource-added`
- `resource-removed`

#### `acl_resource_group_grants`

The main grants table.

Columns:

- `id integer primary key`
- `resource_group_id integer not null references acl_resource_groups(id)`
- `actor_id text`
- `actor_group_id integer references acl_groups(id)`
- `role_name text`
- `action_name text`
- `granted_by text`
- `created_at text default (datetime('now'))`
- `expires_at text`
- `check ((actor_id is null) != (actor_group_id is null))`
- `check ((role_name is null) != (action_name is null))`

Uniqueness:

- `unique(resource_group_id, actor_id, actor_group_id, role_name, action_name)`

This allows either:

- a role-based grant
- or a direct single-action grant

#### `acl_resource_group_grants_audit`

Audit log for grants.

Columns:

- `id integer primary key`
- `timestamp text default (datetime('now'))`
- `operation_by text`
- `operation text`
- `resource_group_id integer`
- `actor_id text`
- `actor_group_id integer`
- `role_name text`
- `action_name text`
- `metadata text`

`operation` examples:

- `grant-added`
- `grant-removed`
- `grant-expired`

#### `acl_role_bundles`

Defines named roles.

Columns:

- `id integer primary key`
- `name text unique not null`
- `description text`
- `source_plugin text`
- `is_system integer default 0`

#### `acl_role_bundle_actions`

Maps role bundles to action names.

Columns:

- `role_bundle_id integer not null references acl_role_bundles(id)`
- `action_name text not null`
- `primary key(role_bundle_id, action_name)`


## Resource Representation

### Problem

Datasette permissions operate on Python `Resource` objects, but persistent ACLs need a storage format.

### Solution

Introduce a canonical serialization format for resources.

Suggested built-in mappings:

- `table` => `database/table`
- `query` => `database/query`
- `database` => `database`
- `file-source` => `source_slug`
- `file` => `file_id`

For plugin-defined resources, add hooks.

### New hook: `datasette_acl_resource_types`

Plugins can register resource type adapters.

Proposed hook:

```python
def datasette_acl_resource_types(datasette):
    """
    Return resource adapters capable of:
    - serializing a Resource instance to (resource_type, resource_key)
    - deserializing from (resource_type, resource_key)
    - listing valid resources for autocomplete / UI
    """
```

Each adapter should support:

- `type_name`
- `label`
- `serialize(resource) -> (type, key) | None`
- `deserialize(datasette, key) -> Resource | None`
- `validate(datasette, key) -> error | None`
- optional `suggest(datasette, q) -> list[...]`

This is critical for making resource groups useful outside core table/query/database resources.


## Permission Semantics

### Resolution model

When Datasette asks:

- is actor `A` allowed action `X` on resource `R`?

`datasette-acl` should:

1. serialize `R` to `(resource_type, resource_key)`
2. find all resource groups containing that resource
3. find all applicable grants for:
   - `actor_id = A.id`
   - actor groups containing `A.id`
4. expand any role bundles to actions
5. return allow/deny SQL rows for the matching resource

### Important rule

Resource groups are **allow grants**, not a new deny system by default.

Datasette’s existing deny mechanisms remain authoritative.

This keeps the model simpler:

- grants add permissions
- explicit deny rules still come from Datasette config or future plugin additions if needed

### Multiple resource groups

A resource may belong to multiple resource groups.

That should be allowed.

Permission effect:

- if any applicable grant allows the action, the actor is allowed unless a more specific deny exists elsewhere in Datasette’s normal resolution flow

### Expiring grants

If `expires_at` is present and in the past:

- the grant should not count
- optionally an audit entry should be written lazily or by a maintenance task


## Role Bundles

### Why role bundles are needed

Direct action grants are too low-level for most applications.

Resource groups become much more useful if admins can say:

- viewer
- editor
- admin

instead of hand-selecting actions.

### Built-in default bundles

The plugin should ship with a small default set for common Datasette resources.

Suggested defaults:

#### `viewer`

- `view-instance`
- `view-database`
- `view-table`
- `view-query`

#### `editor`

- all `viewer` actions
- `insert-row`
- `update-row`
- `delete-row`

#### `admin`

- all `editor` actions
- `alter-table`
- `drop-table`

These are only defaults. Applications can define their own bundles.

### New hook: `datasette_acl_role_bundles`

Plugins can register named bundles.

Proposed hook:

```python
def datasette_acl_role_bundles(datasette):
    """
    Return role bundle definitions:
    [
      {
        "name": "viewer",
        "description": "...",
        "actions": ["view-table", "view-query"]
      }
    ]
    """
```

Conflict rules:

- identical names from multiple plugins should be rejected unless definitions match exactly


## Datasette Integration

### Existing integration point

Current `datasette-acl` already uses:

- custom actions
- `permission_resources_sql`

This should remain the enforcement path.

### New behavior

For actions that resource-group grants know about, the plugin should emit `PermissionSQL` rows describing which resources are allowed.

This likely requires:

1. SQL helpers that expand actor group membership
2. SQL helpers that expand role bundles to actions
3. a resource matching layer

### Compilation strategy

At permission-check time, the plugin must be able to answer efficiently:

- which serialized resources are allowed for this actor/action?

Recommended approach:

- maintain normalized tables
- use SQL joins rather than loading grants into Python
- cache actor group membership for the current request if needed

Potential optimization:

- an internal materialized table of effective grants

For example:

- `acl_effective_resource_actions(actor_id, resource_type, resource_key, action_name, reason)`

This could be refreshed on demand or incrementally, but should not be required in the initial implementation.


## UI Specification

### Actor group UI

Keep existing actor-group management pages.

### New resource group pages

#### `/-/acl/resource-groups`

List resource groups.

Features:

- search by name/slug
- create resource group
- show counts:
  - resources
  - grants

#### `/-/acl/resource-groups/{slug}`

Resource group detail page.

Sections:

- metadata
- contained resources
- grants
- audit log

Actions:

- edit metadata
- add resource
- remove resource
- add grant
- remove grant
- delete resource group

#### `/-/acl/resource-groups/{slug}/edit`

Edit metadata form.

#### `/-/acl/resource-groups/{slug}/resources/add`

Add resource to group.

UI requirements:

- resource type selector
- autocomplete or validation field for resource key
- note field

#### `/-/acl/resource-groups/{slug}/grants/add`

Add grant.

UI requirements:

- choose subject type:
  - actor
  - actor group
- choose subject
- choose grant mode:
  - role
  - direct action
- choose role or action
- optional expiry

### Existing table ACL pages

Table ACL UI should either:

1. remain as a compatibility layer
2. or be rebuilt on top of resource groups

Recommended path:

- keep current table ACL page
- internally model a table-specific ACL as grants on an implicit resource group for that table

That preserves backward compatibility while converging on one underlying model.


## JSON API Specification

All HTML pages should have JSON counterparts.

### Resource groups

- `GET /-/acl/resource-groups.json`
- `POST /-/acl/resource-groups.json`
- `GET /-/acl/resource-groups/{slug}.json`
- `POST /-/acl/resource-groups/{slug}.json`
- `DELETE /-/acl/resource-groups/{slug}.json`

### Resource membership

- `POST /-/acl/resource-groups/{slug}/resources.json`
- `DELETE /-/acl/resource-groups/{slug}/resources/{id}.json`

### Grants

- `POST /-/acl/resource-groups/{slug}/grants.json`
- `DELETE /-/acl/resource-groups/{slug}/grants/{id}.json`

### Autocomplete helpers

- `GET /-/acl/actors.json?q=...`
- `GET /-/acl/groups.json?q=...`
- `GET /-/acl/resources.json?type=table&q=...`


## Hooks

### Existing hook to keep

#### `datasette_acl_valid_actors(datasette)`

Continue to support actor autocomplete/validation.

### New hooks

#### `datasette_acl_resource_types(datasette)`

Registers serializable resource adapters.

#### `datasette_acl_role_bundles(datasette)`

Registers named role bundles.

#### `datasette_acl_default_resource_groups(datasette)`

Optional hook for plugins that want to ensure some groups exist at startup.

#### `datasette_acl_grantable_actions(datasette)`

Optional hook to declare which actions should appear in UI pickers.

This avoids overwhelming admins with every Datasette action.


## Compatibility Story

### Current table ACL behavior

Current `datasette-acl` focuses on:

- `insert-row`
- `delete-row`
- `update-row`
- `alter-table`
- `drop-table`

for individual tables.

### Compatibility requirement

That should keep working.

Recommended compatibility approach:

- keep current routes and UI
- map them internally to resource-group grants on an implicit table resource group

For example:

- implicit group slug: `table:data/leads`

This means there is still one underlying permission system.


## Security Model

### Administrative permission

Current plugin permission:

- `datasette-acl`

Keep that, but consider splitting it:

- `datasette-acl-manage-actor-groups`
- `datasette-acl-manage-resource-groups`
- `datasette-acl-manage-grants`

This allows more granular administration if needed.

### Input validation

All writes must validate:

- actor IDs are valid when validation is configured
- actor groups exist
- resource groups exist
- resources are valid for their type
- actions exist
- roles exist

### CSRF

All POST forms must include Datasette CSRF tokens.

### Auditability

Every mutating admin action must write audit rows.


## Plugin Interaction Examples

### `datasette-projects`

`datasette-projects` could:

- create a resource group for each project
- map project tables/files/queries into that group
- add grants:
  - `viewer`
  - `editor`
  - `admin`

Then project UI is just a higher-level presentation over ACL-managed resource groups.

### `datasette-files`

`datasette-files` could register:

- `file-source` resources
- `file` resources

Then file access can be granted through resource groups instead of only source-wide config.

### Custom app plugin

A plugin could register a custom resource type:

- `workspace-page`

and use resource groups to protect both data and custom pages together.


## Recommended Implementation Order

### Phase 1

1. Add `acl_resource_groups`
2. Add `acl_resource_group_items`
3. Add `acl_resource_group_grants`
4. Add role bundle tables
5. Add JSON APIs and basic HTML UI

### Phase 2

1. Add resource type adapters
2. Add role bundle hooks
3. Compile grants into `PermissionSQL`
4. Support built-in resource types:
   - database
   - table
   - query

### Phase 3

1. Make existing table ACL UI work through resource groups
2. Add richer admin UI
3. Add plugin integration examples

### Phase 4

1. Add performance optimizations
2. Add effective-grant caching/materialization if needed
3. Add bulk operations and better autocomplete


## Open Design Questions

### 1. Should resource groups support nesting?

Probably not initially.

Nested groups add a lot of complexity. Flat groups are enough for the first version.

### 2. Should grants support deny rules?

Not initially.

Datasette already has deny mechanisms. Start with allow-only grants.

### 3. Should resource groups be visible as first-class Datasette resources?

Yes in plugin UI and JSON APIs, but not necessarily as browsable tables.

### 4. Should one resource belong to many groups?

Yes.

That makes the system much more flexible and is consistent with collaborative use cases.

### 5. Should roles be global or namespaced?

Initially global by name is fine if role names are small and conventional.

If collisions become a problem, later add:

- `source_plugin`
- or namespaced role names like `projects:viewer`


## Success Criteria

The feature is successful if:

1. A plugin can define a custom resource type and use resource groups without patching Datasette core.
2. An admin can create:
   - an actor group
   - a resource group
   - a role grant between them
3. Datasette permission checks for resources in that group succeed based on those grants.
4. Existing table ACL workflows still work.
5. A higher-level plugin such as `datasette-projects` can treat resource groups as its security boundary instead of building a second permission system.


## Recommendation

This feature would make `datasette-acl` significantly more powerful and more central to the Datasette plugin ecosystem.

It would also create a clean separation of concerns:

- `datasette-acl`
  handles identity groups, resource groups, grants, and permission compilation
- higher-level plugins
  handle metadata, workflows, and domain-specific UI

That is the strongest long-term argument for implementing resource groups in `datasette-acl`.
