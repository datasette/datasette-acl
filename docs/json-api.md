# datasette-acl JSON API

A JSON HTTP API for reading and managing per-resource access grants.

All routes are registered under the `/-/acl/api/` prefix and return JSON.

- [Concepts](#concepts)
  - [Resources](#resources)
  - [Principals](#principals)
  - [Roles vs. actions](#roles-vs-actions)
  - [The grant entry object](#the-grant-entry-object)
- [Authorization](#authorization)
- [API errors](#api-errors)
- [Endpoints](#endpoints)
  - [GET resource grants](#get-resource-grants)
  - [POST grant](#post-grant)
  - [POST update](#post-update)
  - [POST revoke](#post-revoke)
  - [GET groups picker](#get-groups-picker)
  - [GET actors picker](#get-actors-picker)
- [Worked example](#worked-example)

---

## Concepts

### Resources

A [resource](https://docs.datasette.io/en/latest/authentication.html#permissions) is something within Datasette that can be controlled via ACL rules. Examples include tables, queries, and additional concepts introduced by plugins such as [datasette-apps](https://github.com/datasette/datasette-apps).

A resource is addressed by a `(resource_type, parent, child)` triple:

- **`resource_type`** — the `Resource.name` of a registered resource class, e.g. `table`, or a custom type like `mock-doc`. A resource type is "known" only if some registered action declares it via `resource_class`. Requests for an unknown type are rejected (`403`).
- **`parent`** — the first-level identifier (e.g. a database name).
- **`child`** — the optional second-level identifier (e.g. a table name). Two-level types (`parent_class` set, e.g. a table inside a database) use both; parent-only types (`parent_class is None`, e.g. a database) use only `parent`.

In URLs the child segment is **optional** — every resource route is registered in both a `/{parent}/{child}` and a `/{parent}` form. For a parent-only resource, omit the child segment entirely; in JSON responses the absent child is reported as `"child": null`.

All three segments are single path components (no slashes). URL-encode values that contain reserved characters.

### Principals

A grant attaches a set of actions on a resource to exactly **one** principal, which takes one of three forms in a mutation body:

- **Actor** — a [Datasette actor](https://docs.datasette.io/en/latest/authentication.html#actors) identified by a string `actor_id` (e.g. `"alice"`).
- **Group** — an ACL group identified by an integer `group_id` (the `acl_groups.id`).
- **Public audience** — a *class* of caller rather than a specific person, named by `principal_type` alone; do not include either ID field (`actor_id` or `group_id`):

| `principal_type` | Matches                                       |
| ---------------- | --------------------------------------------- |
| `everyone`       | Literally everyone, including anonymous users |
| `authenticated`  | Any signed-in actor (has an `id`)             |
| `anonymous`      | Only unauthenticated callers                  |

Supplying none of these forms — or more than one — is a `400` error. (`principal_type` may also redundantly name `"actor"` / `"group"` alongside the matching id.)

Audience grants store no id at all. Enforcement matches audiences on `principal_type` alone. In responses these audience entries use `"principal": "public"` and `"kind": "public"` to distinguish them from actors and groups, and are never run through actor enrichment (their `display_name` is the fixed UI label).

### Roles vs. actions

Datasette's default permission system is finely-grained: permissions to add, edit, and delete an item are managed separately.

This can be inconvenient for end-users. `datasette-acl` introduces the concept of **roles** to provide a more human-friendly way of managing permissions, as an abstraction over the lower level permissions.

A **role** is a friendly named bundle of actions declared for a resource type via the `datasette_acl_roles` hook (e.g. `Viewer = [doc-view]`, `Editor = [doc-view, doc-edit]`, `Manager = [doc-view, doc-edit, doc-manage]`).

You may grant **by role** (the actions are expanded from the role) or **by raw actions**. In responses, a principal's current action-set is resolved back to the **highest-rank role whose actions are a subset of the granted set**; if no role fits, `"role"` is `null` and the caller should fall back to displaying the raw `actions` array.

### The grant entry object

Both the `GET` endpoint and successful write endpoints describe grants using the same object shapes.

**Actor entry:**

```json
{
  "principal": "actor",
  "id": "alice",
  "role": "Manager",
  "actions": ["doc-edit", "doc-manage", "doc-view"],
  "kind": "user",
  "display_name": "Alice Garcia",
  "email": "alice@example.com",
  "avatar_url": "/-/profile/pic/alice"
}
```

- `actions` is always sorted alphabetically.
- `role` is the resolved role name, or `null` if no role matches.
- `kind` is taken from the actor-resolution layer (`actors_from_ids`) when supplied, defaulting to `"user"`. Other kinds such as `"api_key"` or `"agent"` may be used when an alternative mechanism is acting on behalf of a user.
- `display_name`, `email`, `avatar_url` are present only when the actor-resolution layer supplies them (so unknown actors omit them).

**Group entry:**

```json
{
  "principal": "group",
  "id": "7",
  "role": "Viewer",
  "actions": ["doc-view"],
  "kind": "group",
  "display_name": "staff",
  "member_count": 3
}
```

- `id` is the group id rendered as a **string**.
- `kind` is always `"group"`.
- `display_name` is the group name; `member_count` is the number of actors in the group.

**Public (audience) entry:**

```json
{
  "principal": "public",
  "id": "authenticated",
  "role": "Viewer",
  "actions": ["doc-view"],
  "kind": "public",
  "display_name": "Any signed-in user"
}
```

- `id` echoes the audience's `principal_type` (audiences have no stored id).
- `display_name` is the fixed UI label; audiences are never enriched (no `email` / `avatar_url`).

---

## Authorization

Every endpoint is gated by a **per-resource manage check**, `can_manage`. A caller may manage sharing for a resource if **either**:

1. They hold the global `datasette-acl` permission (acl admin), **or**
2. They are `datasette.allowed` one of the resource type's **manage-only** actions on *that specific resource* — i.e. they hold a `manage=True` role (Manager/Owner) grant. Because this flows through the same acl machinery, it composes with group membership.

The manage check authorizes against the action that is *exclusive* to manage roles (e.g. `doc-manage`), not the whole Manager bundle — otherwise any Viewer or Editor (who also holds `doc-view`) would pass.

If a resource type registers **no** `manage` role, there is no per-resource manager concept for it, so management falls back to the global `datasette-acl` permission only. (This is how table-style resources, which have raw actions but no roles, keep working.)

The **read** endpoint is also manager-only because it returns the full grant list. The **picker** endpoints accept the resource triple as optional query params and apply the same per-resource check when present, falling back to the global permission when absent (see each endpoint).

Failed authorization raises a `403 Forbidden`, rendered by Datasette core (its body is **not** the `{"ok": false}` shape — see below).

---

## API errors

There are two distinct error shapes:

- **`403 Forbidden`** — raised for failed authorization and for unknown resource types. Rendered by Datasette core's forbidden handler (content negotiated; not guaranteed to be the `{"ok": false}` envelope). Treat any `403` as "not allowed / unknown resource."
- **`400` / `405` from the handler** — returned as a JSON envelope:

  ```json
  {
    "ok": false,
    "error": "update requires a role"
  }
  ```

  - `400` — bad/duplicate principal, unparseable body, unknown role, or `update` without a role.
  - `405` — wrong HTTP method on a mutation route (e.g. `GET` on `/grant`).

Successful mutation responses always include `"ok": true`.

| Status | Meaning                                                          |
| ------ | --------------------------------------------------------------- |
| `200`  | Success.                                                        |
| `400`  | Invalid request (principal, body, role). JSON `{ok:false}`.     |
| `403`  | Not authorized, or unknown resource type. Core-rendered.        |
| `405`  | Method not allowed on this route. JSON `{ok:false}`.            |

---

## Endpoints

Path parameters `{resource_type}` / `{parent}` / `{child}` are described under [Resources](#resources). `{child}` is optional in every resource route.

### GET resource grants

```
GET /-/acl/api/resource/{resource_type}/{parent}/{child}
GET /-/acl/api/resource/{resource_type}/{parent}
```

Returns the full share state for one resource: its role catalog, every grant grouped by principal (each enriched and role-resolved), and the caller's `can_manage` flag.

Datasette's default resource types are:

- `database` — `parent` is the database name; omit `child`.
- `table` — `parent` is the database name, `child` is the table or view name.
- `query` — `parent` is the database name, `child` is the stored query name.

Plugins can add additional resource types by registering actions with custom resource classes; use the resource class's `name` as `resource_type`.

**Authorization:** manager-only (`can_manage` must be true).

**Response `200`:**

```json
{
  "resource_type": "query",
  "parent": "content",
  "child": "recent_releases",
  "can_manage": true,
  "roles": [
    {
      "name": "Viewer",
      "actions": ["view-query"],
      "rank": 1
    },
    {
      "name": "Editor",
      "actions": ["update-query", "view-query"],
      "rank": 2
    },
    {
      "name": "Manager",
      "actions": ["delete-query", "update-query", "view-query"],
      "rank": 3,
      "manage": true,
      "description": "Full control"
    }
  ],
  "grants": [
    {
      "principal": "actor",
      "id": "alice",
      "role": "Manager",
      "actions": ["delete-query", "update-query", "view-query"],
      "kind": "user",
      "display_name": "Alice Garcia",
      "email": "alice@example.com",
      "avatar_url": "/-/profile/pic/alice"
    },
    {
      "principal": "group",
      "id": "7",
      "role": "Viewer",
      "actions": ["view-query"],
      "kind": "group",
      "display_name": "staff",
      "member_count": 3
    }
  ]
}
```

Notes:

- `roles` is the resource type's role catalog ordered by ascending `rank`. The `manage` (boolean `true`) and `description` (string) keys appear only when set on the role.
- `grants` is one entry per principal (see [grant entry object](#the-grant-entry-object)). Grants whose group is soft-deleted are omitted. An empty resource returns `"grants": []` but still includes `roles` and `can_manage`.
- `child` is `null` for parent-only resources.

### POST grant

```
POST /-/acl/api/resource/{resource_type}/{parent}/{child}/grant
POST /-/acl/api/resource/{resource_type}/{parent}/grant
```

Adds actions for a principal on the resource.

This endpoint is **idempotent** — actions already held are left unchanged and do not add audit rows. Each newly inserted action is written to the audit log (`operation: "added"`, `operation_by` = the calling actor's id).

Returns the principal's full action-set after the grant.

**Authorization:** `can_manage`.

**Body** — exactly one of `actor_id` / `group_id` / `principal_type`, and exactly one of `role` / `actions`:

| Field      | Type            | Notes                                                |
| ---------- | --------------- | ---------------------------------------------------- |
| `actor_id` | string          | An individual actor. One principal form of three.    |
| `group_id` | integer         | A group. One principal form of three.                |
| `principal_type` | string    | A public audience: `"everyone"` / `"authenticated"` / `"anonymous"`. Do not include `actor_id` or `group_id` (see [Principals](#principals)). |
| `role`     | string          | A role name for this resource type. Expands to its actions. Supply this **or** `actions`. |
| `actions`  | array of string | Raw action names. Supply this **or** `role`.         |

To grant the "Editor" role to "bob":

```json
{
  "actor_id": "bob",
  "role": "Editor"
}
```

To allow members of group 7 the ability to both `doc-view` and `doc-edit`:

```json
{
  "group_id": 7,
  "actions": ["doc-view", "doc-edit"]
}
```

**Response `200`:**

```json
{
  "ok": true,
  "grant": {
    "principal": "actor",
    "id": "bob",
    "role": "Editor",
    "actions": ["doc-edit", "doc-view"],
    "kind": "user"
  }
}
```

`grant.grant` is the enriched [grant entry](#the-grant-entry-object) reflecting the principal's complete action-set (not just the newly-added actions).

**Errors:** `400` for missing/duplicate principal, neither/both of `role`/`actions`, an unknown `role`, or an unparseable body. `403` for authz or unknown resource type.

### POST update

```
POST /-/acl/api/resource/{resource_type}/{parent}/{child}/update
POST /-/acl/api/resource/{resource_type}/{parent}/update
```

Atomically **swaps** a principal's action-set on the resource to exactly the actions of the given role: actions in the new role that are missing are added, and currently-granted actions not in the new role are removed. Each change is audited. Returns the enriched grant.

**Authorization:** `can_manage`.

**Body** — exactly one of `actor_id` / `group_id` / `principal_type`, plus a **required** `role`:

| Field      | Type    | Notes                                    |
| ---------- | ------- | ---------------------------------------- |
| `actor_id` | string  | An individual actor. One principal form of three. |
| `group_id` | integer | A group. One principal form of three.    |
| `principal_type` | string | A public audience. Do not include `actor_id` or `group_id` (see [Principals](#principals)). |
| `role`     | string  | Required. The role to swap the principal to. |

To replace the actor `bob`'s current actions with the "Viewer" role:

```json
{
  "actor_id": "bob",
  "role": "Viewer"
}
```

**Response `200`:** same `{ "ok": true, "grant": <entry> }` shape as [grant](#post-grant).

**Errors:** `400` if `role` is missing/unknown or the principal is invalid; `403` for authz / unknown resource type. Use `update` (not repeated grant/revoke) when you want the principal's actions to end up *exactly* equal to one role. To replace a principal's actions with an arbitrary raw `actions` list, first `revoke` that principal's grant and then `grant` the new `actions`.

### POST revoke

```
POST /-/acl/api/resource/{resource_type}/{parent}/{child}/revoke
POST /-/acl/api/resource/{resource_type}/{parent}/revoke
```

Removes **all** grants for a principal on the resource. Each removal is audited (`operation: "removed"`). Returns the action names that were removed.

**Authorization:** `can_manage`.

**Body** — exactly one of `actor_id` / `group_id` / `principal_type` (no role/actions):

| Field      | Type    | Notes                          |
| ---------- | ------- | ------------------------------ |
| `actor_id` | string  | An individual actor. One principal form of three. |
| `group_id` | integer | A group. One principal form of three. |
| `principal_type` | string | A public audience. Do not include `actor_id` or `group_id` (see [Principals](#principals)). |

To remove all grants for the actor `bob` on this resource:

```json
{
  "actor_id": "bob"
}
```

**Response `200`:**

A successful response lists the action names that were removed:

```json
{
  "ok": true,
  "removed": ["doc-edit", "doc-manage", "doc-view"]
}
```

`removed` is sorted. Revoking a principal with no grants returns `"removed": []`.

**Errors:** `400` for an invalid principal; `403` for authz / unknown resource type.

### GET groups picker

```
GET /-/acl/api/groups
GET /-/acl/api/groups?resource_type={type}&parent={parent}&child={child}
```

Lists every active (non soft-deleted) group with a member count — the source for a group autocomplete. Ordered by group name.

**Authorization:** group names may be sensitive, so this endpoint is only available to callers who are trusted to manage permissions somewhere. There are two ways to qualify:

- Global ACL admins can call `/groups` directly using the `datasette-acl` permission.
- Resource managers can pass `resource_type` and `parent` (`child` is optional). Those query params are used only for the `can_manage` check on that resource; they do not filter the returned groups.

If neither check passes → `403`.

**Response `200`:**

```json
{
  "groups": [
    {
      "id": 7,
      "name": "staff",
      "member_count": 3
    },
    {
      "id": 9,
      "name": "interns",
      "member_count": 0
    }
  ]
}
```

### GET actors picker

```
GET /-/acl/api/actors?q={query}&kind={kind}
GET /-/acl/api/actors?q={query}&resource_type={type}&parent={parent}&child={child}
```

Actor autocomplete. If the Datasette instance also has the [datasette-user-profiles](https://github.com/datasette/datasette-user-profiles) plugin installed, this proxies to its search API (`GET /-/profiles/api/search`), forwarding the caller's identity so the profiles access gate evaluates against the real caller. Otherwise it falls back to acl's own `datasette_acl_valid_actors` list, filtered by `q` as a case-insensitive substring of either the id or the display name.

**Query params:**

| Param           | Notes                                                            |
| --------------- | ---------------------------------------------------------------- |
| `q`             | Search string. Trimmed; empty matches all.                       |
| `kind`          | Optional kind filter, passed through to user-profiles when used. |
| `resource_type` / `parent` / `child` | Optional; authorize as a per-resource Manager (see below). |

**Authorization:** same rule as the groups picker — per-resource `can_manage` when `resource_type` + `parent` are supplied, else the global `datasette-acl` permission. Neither → `403`.

**Response `200`:**

```json
{
  "results": [
    {
      "id": "alice",
      "display_name": "Alice Garcia",
      "avatar_url": "/-/profile/pic/alice",
      "kind": "user"
    }
  ]
}
```

The exact fields depend on the backing source. The user-profiles backend may return richer records (avatar, email, kind such as `agent`). The acl-only fallback returns minimal entries: `{ "id", "display_name", "kind": "user" }` (no avatar/email). The profiles backend degrades gracefully: a missing route, non-200, or unparseable response yields `"results": []` (the picker stays usable) rather than an error.

---

## Worked example

Assume a parent-only resource type `mock-doc`, document id `42`, with roles `Viewer` / `Editor` / `Manager`, called by an admin (cookie `ds_actor`).

Read the current share state:

```bash
curl -s 'https://example.org/-/acl/api/resource/mock-doc/42' \
  -H 'Cookie: ds_actor=...'
```

Grant `bob` the Editor role:

```bash
curl -s -X POST 'https://example.org/-/acl/api/resource/mock-doc/42/grant' \
  -H 'Cookie: ds_actor=...' \
  -H 'Content-Type: application/json' \
  -d '{"actor_id": "bob", "role": "Editor"}'
# -> {"ok": true, "grant": {"principal":"actor","id":"bob","role":"Editor",
#                           "actions":["doc-edit","doc-view"],"kind":"user"}}
```

Demote `bob` to Viewer (atomic swap):

```bash
curl -s -X POST 'https://example.org/-/acl/api/resource/mock-doc/42/update' \
  -H 'Cookie: ds_actor=...' \
  -H 'Content-Type: application/json' \
  -d '{"actor_id": "bob", "role": "Viewer"}'
```

Grant the `staff` group (id 7) view access by raw action:

```bash
curl -s -X POST 'https://example.org/-/acl/api/resource/mock-doc/42/grant' \
  -H 'Cookie: ds_actor=...' \
  -H 'Content-Type: application/json' \
  -d '{"group_id": 7, "actions": ["doc-view"]}'
```

Make the document public to signed-in users — the `authenticated` audience is named by `principal_type` alone:

```bash
curl -s -X POST 'https://example.org/-/acl/api/resource/mock-doc/42/grant' \
  -H 'Cookie: ds_actor=...' \
  -H 'Content-Type: application/json' \
  -d '{"principal_type": "authenticated", "role": "Viewer"}'
# -> {"ok": true, "grant": {"principal":"public","id":"authenticated",
#                           "role":"Viewer","actions":["doc-view"],
#                           "kind":"public",
#                           "display_name":"Any signed-in user"}}
```

Revoke `bob` entirely:

```bash
curl -s -X POST 'https://example.org/-/acl/api/resource/mock-doc/42/revoke' \
  -H 'Cookie: ds_actor=...' \
  -H 'Content-Type: application/json' \
  -d '{"actor_id": "bob"}'
# -> {"ok": true, "removed": ["doc-view"]}
```

Populate the dialog's pickers as a per-resource Manager (no global admin):

```bash
curl -s 'https://example.org/-/acl/api/groups?resource_type=mock-doc&parent=42' \
  -H 'Cookie: ds_actor=...'
curl -s 'https://example.org/-/acl/api/actors?q=ali&resource_type=mock-doc&parent=42' \
  -H 'Cookie: ds_actor=...'
```
