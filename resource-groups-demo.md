# datasette-acl resource groups demo

*2026-03-13T04:45:46Z by Showboat 0.6.0*
<!-- showboat-id: f334ab3d-21da-423b-bff6-2197eb885c93 -->

This walkthrough exercises the new resource-group functionality in a live Datasette dev server on http://127.0.0.1:8041 using curl and direct inspection of the internal database. It starts from a --root login URL, then probes creation, validation, grants, permission behavior, compatibility with legacy table ACLs, and likely holes in the current implementation.

The demo server is running separately in another terminal using http://127.0.0.1:8041/-/auth-token?token=d6fe10b1cfd7bd2514a953112e83bb2d8de1ee47c4af973cd106d8767d0f6cc6. I am leaving all artifacts in  in place.

```bash
curl -s -c /tmp/datasette-acl-showboat/root-cookies.txt 'http://127.0.0.1:8041/-/auth-token?token=fb469bbd929a9d2c3aef6063f685230c9e3020939e1362893183bce4e6e81d78' -D - | sed -n '1,10p'
```

```output
HTTP/1.1 302 Found
date: Fri, 13 Mar 2026 04:49:46 GMT
server: uvicorn
Location: /
content-type: text/plain
set-cookie: ds_actor=eyJhIjp7ImlkIjoicm9vdCJ9fQ.BZFr8wVHyWwDL1mDQOeLn-Vy1l8; Path=/; SameSite=lax
Transfer-Encoding: chunked

```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/plugins.json | uv run python -m json.tool
```

```output
[
    {
        "name": "datasette-acl",
        "static": true,
        "templates": true,
        "version": "0.5a0",
        "hooks": [
            "menu_links",
            "permission_resources_sql",
            "register_actions",
            "register_routes",
            "startup",
            "table_actions",
            "track_event"
        ]
    },
    {
        "name": "datasette-unsafe-actor-debug",
        "static": false,
        "templates": true,
        "version": "0.2",
        "hooks": [
            "menu_links",
            "register_routes"
        ]
    }
]
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/unsafe-actor | sed -n '1,25p'
```

```output
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Unsafe actor</title>
    <link rel="stylesheet" href="/-/static/app.css?005fd3">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

<script>window.datasetteVersion = '1.0a25';</script>
<script src="/-/static/datasette-manager.js" defer></script>
</head>
<body class="">
<div class="not-footer">
<header class="hd"><nav>
  
  
    <p class="crumbs">
      
        <a href="/">home</a>
        
      
    </p>
  

    
    <details class="nav-menu details-menu">
```

```bash
curl -s -c /tmp/datasette-acl-showboat/alice-cookies.txt -X POST http://127.0.0.1:8041/-/unsafe-actor --data-urlencode 'actor={"id":"alice"}' -D - | sed -n '1,10p'
```

```output
HTTP/1.1 302 Found
date: Fri, 13 Mar 2026 04:49:47 GMT
server: uvicorn
Location: /
content-type: text/plain
set-cookie: ds_actor=eyJhIjp7ImlkIjoiYWxpY2UifX0.F8R8nCmialvyAq2yX4dZVZrMuVo; Path=/; SameSite=lax
Transfer-Encoding: chunked

```

```bash
curl -s -c /tmp/datasette-acl-showboat/bob-cookies.txt -X POST http://127.0.0.1:8041/-/unsafe-actor --data-urlencode 'actor={"id":"bob","is_staff":true}' -D - | sed -n '1,10p'
```

```output
HTTP/1.1 302 Found
date: Fri, 13 Mar 2026 04:49:47 GMT
server: uvicorn
Location: /
content-type: text/plain
set-cookie: ds_actor=eyJhIjp7ImlkIjoiYm9iIiwiaXNfc3RhZmYiOnRydWV9fQ.j-DsrMvvtR43vhk3narVZ5CmXo4; Path=/; SameSite=lax
Transfer-Encoding: chunked

```

```bash
printf 'alice ->\n'; curl -s -b /tmp/datasette-acl-showboat/alice-cookies.txt http://127.0.0.1:8041/-/actor.json | uv run python -m json.tool; printf '\nbob ->\n'; curl -s -b /tmp/datasette-acl-showboat/bob-cookies.txt http://127.0.0.1:8041/-/actor.json | uv run python -m json.tool
```

```output
alice ->
{
    "actor": {
        "id": "alice"
    }
}

bob ->
{
    "actor": {
        "id": "bob",
        "is_staff": true
    }
}
```

First I checked the baseline under `--default-deny`. The root user can inspect the system, but `alice` and `bob` should not inherit any database, table, or query visibility until grants are attached.

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups.json | uv run python -m json.tool
```

```output
{
    "resource_groups": []
}
```

```bash
printf 'alice view-database ->\n'; curl -s -b /tmp/datasette-acl-showboat/alice-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=view-database' | uv run python -m json.tool; printf '\n\nbob view-table ->\n'; curl -s -b /tmp/datasette-acl-showboat/bob-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=view-table' | uv run python -m json.tool; printf '\n\nalice view-query ->\n'; curl -s -b /tmp/datasette-acl-showboat/alice-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=view-query' | uv run python -m json.tool
```

```output
alice view-database ->
{
    "action": "view-database",
    "actor_id": "alice",
    "page": 1,
    "page_size": 50,
    "total": 0,
    "items": []
}


bob view-table ->
{
    "action": "view-table",
    "actor_id": "bob",
    "page": 1,
    "page_size": 50,
    "total": 0,
    "items": []
}


alice view-query ->
{
    "action": "view-query",
    "actor_id": "alice",
    "page": 1,
    "page_size": 50,
    "total": 0,
    "items": []
}
```

The creation API works as a root-only JSON endpoint. I tested normal creation, a required-fields error, and the current duplicate-slug behavior.

Write endpoints also need Datasette's CSRF token, even for the JSON routes. I fetched a page that emits `ds_csrftoken` into the root cookie jar and then replayed the writes with `csrftoken=` in the form body.

```bash
cat /tmp/datasette-acl-showboat/root-cookies.txt
```

```output
# Netscape HTTP Cookie File
# https://curl.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

127.0.0.1	FALSE	/	FALSE	0	ds_csrftoken	IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg
127.0.0.1	FALSE	/	FALSE	0	ds_actor	eyJhIjp7ImlkIjoicm9vdCJ9fQ.BZFr8wVHyWwDL1mDQOeLn-Vy1l8
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups.json --data-urlencode 'slug=project-alpha' --data-urlencode 'name=Project Alpha' --data-urlencode 'description=Main collaboration workspace' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": true,
    "resource_group": {
        "slug": "project-alpha",
        "name": "Project Alpha",
        "description": "Main collaboration workspace",
        "deleted": 0
    }
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups.json --data-urlencode 'slug=' --data-urlencode 'name=' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": false,
    "error": "slug and name are required"
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups.json --data-urlencode 'slug=project-alpha' --data-urlencode 'name=Project Alpha v2' --data-urlencode 'description=Second write to the same slug' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": true,
    "resource_group": {
        "slug": "project-alpha",
        "name": "Project Alpha v2",
        "description": "Second write to the same slug",
        "deleted": 0
    }
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups/project-alpha.json | uv run python -m json.tool
```

```output
{
    "resource_group": {
        "slug": "project-alpha",
        "name": "Project Alpha v2",
        "description": "Second write to the same slug",
        "deleted": 0,
        "resources": [],
        "grants": []
    }
}
```

Next I attached concrete resources to the group. The implementation currently knows how to validate built-in `table`, `database`, and `query` resources. I checked the success path, malformed input, unknown queries, and duplicate membership.

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources.json --data-urlencode 'resource_type=table' --data-urlencode 'resource_key=demo/t' --data-urlencode 'note=Main table' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": true,
    "resource": {
        "id": 1,
        "resource_type": "table",
        "resource_key": "demo/t",
        "note": "Main table"
    }
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources.json --data-urlencode 'resource_type=database' --data-urlencode 'resource_key=demo' --data-urlencode 'note=Whole database' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": true,
    "resource": {
        "id": 2,
        "resource_type": "database",
        "resource_key": "demo",
        "note": "Whole database"
    }
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources.json --data-urlencode 'resource_type=query' --data-urlencode 'resource_key=demo/recent' --data-urlencode 'note=Canned query' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": false,
    "error": "Query not found: demo/recent"
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources.json --data-urlencode 'resource_type=file' --data-urlencode 'resource_key=anything' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": false,
    "error": "Unknown resource type: file"
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources.json --data-urlencode 'resource_type=table' --data-urlencode 'resource_key=demo-only' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": false,
    "error": "Table resources must use database/table format"
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources.json --data-urlencode 'resource_type=query' --data-urlencode 'resource_key=demo/missing' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": false,
    "error": "Query not found: demo/missing"
}
```

```bash
curl -s -i -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources.json --data-urlencode 'resource_type=table' --data-urlencode 'resource_key=demo/t' --data-urlencode 'note=Duplicate membership' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | sed -n '1,25p'
```

```output
HTTP/1.1 500 Internal Server Error
date: Fri, 13 Mar 2026 04:52:15 GMT
server: uvicorn
content-type: application/json; charset=utf-8
Transfer-Encoding: chunked

{"ok": false, "error": "UNIQUE constraint failed: acl_resource_group_items.resource_group_id, acl_resource_group_items.resource_type, acl_resource_group_items.resource_key", "status": 500, "title": null}```
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups/project-alpha.json | uv run python -m json.tool
```

```output
{
    "resource_group": {
        "slug": "project-alpha",
        "name": "Project Alpha v2",
        "description": "Second write to the same slug",
        "deleted": 0,
        "resources": [
            {
                "id": 1,
                "resource_type": "table",
                "resource_key": "demo/t",
                "note": "Main table"
            },
            {
                "id": 2,
                "resource_type": "database",
                "resource_key": "demo",
                "note": "Whole database"
            }
        ],
        "grants": []
    }
}
```

With resources in place, I attached grants. I used both actor and actor-group subjects, role-based and direct-action modes, then checked the resulting permissions from the perspective of the signed-in actors.

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants.json --data-urlencode 'subject_type=actor' --data-urlencode 'subject=alice' --data-urlencode 'grant_mode=role' --data-urlencode 'role_name=viewer' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": true,
    "grant": {
        "id": 1,
        "actor_id": "alice",
        "actor_group": null,
        "role_name": "viewer",
        "action_name": null,
        "expires_at": null
    }
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants.json --data-urlencode 'subject_type=actor' --data-urlencode 'subject=alice' --data-urlencode 'grant_mode=action' --data-urlencode 'action_name=insert-row' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": true,
    "grant": {
        "id": 2,
        "actor_id": "alice",
        "actor_group": null,
        "role_name": null,
        "action_name": "insert-row",
        "expires_at": null
    }
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants.json --data-urlencode 'subject_type=group' --data-urlencode 'subject=staff' --data-urlencode 'grant_mode=role' --data-urlencode 'role_name=viewer' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": true,
    "grant": {
        "id": 3,
        "actor_id": null,
        "actor_group": "staff",
        "role_name": "viewer",
        "action_name": null,
        "expires_at": null
    }
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants.json --data-urlencode 'subject_type=group' --data-urlencode 'subject=missing-group' --data-urlencode 'grant_mode=role' --data-urlencode 'role_name=viewer' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": false,
    "error": "",
    "status": 500,
    "title": null
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants.json --data-urlencode 'subject_type=actor' --data-urlencode 'subject=alice' --data-urlencode 'grant_mode=role' --data-urlencode 'role_name=made-up-role' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": false,
    "error": "",
    "status": 500,
    "title": null
}
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants.json --data-urlencode 'subject_type=actor' --data-urlencode 'subject=alice' --data-urlencode 'grant_mode=action' --data-urlencode 'action_name=made-up-action' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | uv run python -m json.tool
```

```output
{
    "ok": false,
    "error": "",
    "status": 500,
    "title": null
}
```

```bash
curl -s -i -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants.json --data-urlencode 'subject_type=actor' --data-urlencode 'subject=alice' --data-urlencode 'grant_mode=role' --data-urlencode 'role_name=viewer' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' | sed -n '1,25p'
```

```output
HTTP/1.1 200 OK
date: Fri, 13 Mar 2026 04:53:55 GMT
server: uvicorn
content-type: application/json; charset=utf-8
Transfer-Encoding: chunked

{"ok": true, "grant": {"id": 4, "actor_id": "alice", "actor_group": null, "role_name": "viewer", "action_name": null, "expires_at": null}}```
```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups/project-alpha.json | uv run python -m json.tool
```

```output
{
    "resource_group": {
        "slug": "project-alpha",
        "name": "Project Alpha v2",
        "description": "Second write to the same slug",
        "deleted": 0,
        "resources": [
            {
                "id": 1,
                "resource_type": "table",
                "resource_key": "demo/t",
                "note": "Main table"
            },
            {
                "id": 2,
                "resource_type": "database",
                "resource_key": "demo",
                "note": "Whole database"
            }
        ],
        "grants": [
            {
                "id": 1,
                "actor_id": "alice",
                "actor_group": null,
                "role_name": "viewer",
                "action_name": null,
                "expires_at": null
            },
            {
                "id": 2,
                "actor_id": "alice",
                "actor_group": null,
                "role_name": null,
                "action_name": "insert-row",
                "expires_at": null
            },
            {
                "id": 3,
                "actor_id": null,
                "actor_group": "staff",
                "role_name": "viewer",
                "action_name": null,
                "expires_at": null
            },
            {
                "id": 4,
                "actor_id": "alice",
                "actor_group": null,
                "role_name": "viewer",
                "action_name": null,
                "expires_at": null
            }
        ]
    }
}
```

```bash
printf 'alice view-database ->\n'; curl -s -b /tmp/datasette-acl-showboat/alice-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=view-database' | uv run python -m json.tool; printf '\n\nalice view-table ->\n'; curl -s -b /tmp/datasette-acl-showboat/alice-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=view-table' | uv run python -m json.tool; printf '\n\nalice insert-row ->\n'; curl -s -b /tmp/datasette-acl-showboat/alice-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=insert-row' | uv run python -m json.tool; printf '\n\nalice drop-table ->\n'; curl -s -b /tmp/datasette-acl-showboat/alice-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=drop-table' | uv run python -m json.tool
```

```output
alice view-database ->
{
    "action": "view-database",
    "actor_id": "alice",
    "page": 1,
    "page_size": 50,
    "total": 1,
    "items": [
        {
            "parent": "demo",
            "child": null,
            "resource": "/demo"
        }
    ]
}


alice view-table ->
{
    "action": "view-table",
    "actor_id": "alice",
    "page": 1,
    "page_size": 50,
    "total": 1,
    "items": [
        {
            "parent": "demo",
            "child": "t",
            "resource": "/demo/t"
        }
    ]
}


alice insert-row ->
{
    "action": "insert-row",
    "actor_id": "alice",
    "page": 1,
    "page_size": 50,
    "total": 1,
    "items": [
        {
            "parent": "demo",
            "child": "t",
            "resource": "/demo/t"
        }
    ]
}


alice drop-table ->
{
    "action": "drop-table",
    "actor_id": "alice",
    "page": 1,
    "page_size": 50,
    "total": 0,
    "items": []
}
```

```bash
printf 'bob view-database ->\n'; curl -s -b /tmp/datasette-acl-showboat/bob-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=view-database' | uv run python -m json.tool; printf '\n\nbob view-table ->\n'; curl -s -b /tmp/datasette-acl-showboat/bob-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=view-table' | uv run python -m json.tool; printf '\n\nbob insert-row ->\n'; curl -s -b /tmp/datasette-acl-showboat/bob-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=insert-row' | uv run python -m json.tool
```

```output
bob view-database ->
{
    "action": "view-database",
    "actor_id": "bob",
    "page": 1,
    "page_size": 50,
    "total": 1,
    "items": [
        {
            "parent": "demo",
            "child": null,
            "resource": "/demo"
        }
    ]
}


bob view-table ->
{
    "action": "view-table",
    "actor_id": "bob",
    "page": 1,
    "page_size": 50,
    "total": 1,
    "items": [
        {
            "parent": "demo",
            "child": "t",
            "resource": "/demo/t"
        }
    ]
}


bob insert-row ->
{
    "action": "insert-row",
    "actor_id": "bob",
    "page": 1,
    "page_size": 50,
    "total": 0,
    "items": []
}
```

```bash
uv run python - <<'PY'
import sqlite3, json
conn = sqlite3.connect('/tmp/datasette-acl-showboat/internal.db')
conn.row_factory = sqlite3.Row
rows = conn.execute('select g.name, ag.actor_id from acl_actor_groups ag join acl_groups g on g.id = ag.group_id order by g.name, ag.actor_id').fetchall()
print(json.dumps([dict(r) for r in rows], indent=4))
PY
```

```output
[
    {
        "name": "staff",
        "actor_id": "bob"
    }
]
```

The legacy `/database/table/-/acl` page is supposed to act as a compatibility layer over the new model. I posted to that HTML form, then checked both the old `acl` tables and the implicit `table:...` resource-group rows that were created alongside it.

```bash
curl -s -c /tmp/datasette-acl-showboat/carol-cookies.txt -X POST http://127.0.0.1:8041/-/unsafe-actor --data-urlencode 'actor={"id":"carol"}' -D - | sed -n '1,10p'
```

```output
HTTP/1.1 302 Found
date: Fri, 13 Mar 2026 04:54:30 GMT
server: uvicorn
Location: /
content-type: text/plain
set-cookie: ds_actor=eyJhIjp7ImlkIjoiY2Fyb2wifX0.nVu8xyqvGFO4RFMwrIHtKM15g6U; Path=/; SameSite=lax
Transfer-Encoding: chunked

```

```bash
curl -s -b /tmp/datasette-acl-showboat/root-cookies.txt -X POST http://127.0.0.1:8041/demo/extra/-/acl --data-urlencode 'group_permissions_staff=insert-row' --data-urlencode 'new_actor_id=carol' --data-urlencode 'new_user_actions=update-row' --data-urlencode 'csrftoken=IlV5NG9BdmplZ21pZXJaMG4i.vjFMCtWpaW4Y2a2ETCBHt6UOXkg' -D - | sed -n '1,12p'
```

```output
HTTP/1.1 302 Found
date: Fri, 13 Mar 2026 04:54:30 GMT
server: uvicorn
Location: /demo/extra/-/acl
content-type: text/plain
set-cookie: ds_messages=.eJyLjlZyTElJTbFSSC_KLy1QUC8uSUxLU1dITsxTyMwrTi0q0S3KL1fSMYzVgassBQorqCcnFuXnQBSWFqQklqTCFMYCAKKuG-I.ZwxrMFITv0A7C_5WIr-ppwcqT00; Path=/; SameSite=lax
Transfer-Encoding: chunked

```

```bash
uv run python - <<'PY'
import sqlite3, json
conn = sqlite3.connect('/tmp/datasette-acl-showboat/internal.db')
conn.row_factory = sqlite3.Row
legacy = conn.execute('''
select a.actor_id, g.name as group_name, aa.name as action_name, ar.database, ar.resource
from acl a
left join acl_groups g on g.id = a.group_id
join acl_actions aa on aa.id = a.action_id
join acl_resources ar on ar.id = a.resource_id
where ar.database = ? and ar.resource = ?
order by a.actor_id, g.name, aa.name
''', ('demo', 'extra')).fetchall()
implicit_group = conn.execute('select slug, name, description from acl_resource_groups where slug = ?', ('table:demo/extra',)).fetchall()
implicit_items = conn.execute('''
select resource_type, resource_key from acl_resource_group_items
where resource_group_id = (select id from acl_resource_groups where slug = 'table:demo/extra')
order by id
''').fetchall()
implicit_grants = conn.execute('''
select rgg.actor_id, g.name as actor_group, rgg.role_name, rgg.action_name
from acl_resource_group_grants rgg
left join acl_groups g on g.id = rgg.actor_group_id
where rgg.resource_group_id = (select id from acl_resource_groups where slug = 'table:demo/extra')
order by rgg.actor_id, g.name, rgg.role_name, rgg.action_name
''').fetchall()
print(json.dumps({
    'legacy_acl': [dict(r) for r in legacy],
    'implicit_group': [dict(r) for r in implicit_group],
    'implicit_items': [dict(r) for r in implicit_items],
    'implicit_grants': [dict(r) for r in implicit_grants],
}, indent=4))
PY
```

```output
{
    "legacy_acl": [
        {
            "actor_id": null,
            "group_name": "staff",
            "action_name": "insert-row",
            "database": "demo",
            "resource": "extra"
        },
        {
            "actor_id": "carol",
            "group_name": null,
            "action_name": "update-row",
            "database": "demo",
            "resource": "extra"
        }
    ],
    "implicit_group": [
        {
            "slug": "table:demo/extra",
            "name": "Table demo/extra",
            "description": "Compatibility resource group for table demo/extra"
        }
    ],
    "implicit_items": [
        {
            "resource_type": "table",
            "resource_key": "demo/extra"
        }
    ],
    "implicit_grants": [
        {
            "actor_id": null,
            "actor_group": "staff",
            "role_name": null,
            "action_name": "insert-row"
        },
        {
            "actor_id": "carol",
            "actor_group": null,
            "role_name": null,
            "action_name": "update-row"
        }
    ]
}
```

```bash
printf 'carol update-row ->\n'; curl -s -b /tmp/datasette-acl-showboat/carol-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=update-row' | uv run python -m json.tool; printf '\n\nbob insert-row ->\n'; curl -s -b /tmp/datasette-acl-showboat/bob-cookies.txt 'http://127.0.0.1:8041/-/allowed.json?action=insert-row' | uv run python -m json.tool
```

```output
carol update-row ->
{
    "action": "update-row",
    "actor_id": "carol",
    "page": 1,
    "page_size": 50,
    "total": 1,
    "items": [
        {
            "parent": "demo",
            "child": "extra",
            "resource": "/demo/extra"
        }
    ]
}


bob insert-row ->
{
    "action": "insert-row",
    "actor_id": "bob",
    "page": 1,
    "page_size": 50,
    "total": 1,
    "items": [
        {
            "parent": "demo",
            "child": "extra",
            "resource": "/demo/extra"
        }
    ]
}
```

I finished with the holes I was most interested in. Some are acceptable “not implemented yet” gaps relative to the spec, while others look like real correctness issues in the current code.

```bash
curl -s -i -b /tmp/datasette-acl-showboat/alice-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups.json | sed -n '1,20p'
```

```output
HTTP/1.1 403 Forbidden
date: Fri, 13 Mar 2026 04:54:50 GMT
server: uvicorn
content-type: text/html; charset=utf-8
vary: Cookie
set-cookie: ds_csrftoken=Iml4VWQ0SVJnOE0yOG9TR2Qi.jiDyx1yNgAiMawMQtHDOENAFwAk; Path=/; SameSite=Lax
Transfer-Encoding: chunked

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Forbidden</title>
    <link rel="stylesheet" href="/-/static/app.css?005fd3">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

<script>window.datasetteVersion = '1.0a25';</script>
<script src="/-/static/datasette-manager.js" defer></script>
</head>
<body class="">
<div class="not-footer">
```

```bash
curl -s -i -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups | sed -n '1,20p'
```

```output
HTTP/1.1 404 Not Found
date: Fri, 13 Mar 2026 04:54:51 GMT
server: uvicorn
content-type: text/html; charset=utf-8
Transfer-Encoding: chunked

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Error 404</title>
    <link rel="stylesheet" href="/-/static/app.css?005fd3">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

<script>window.datasetteVersion = '';</script>
<script src="/-/static/datasette-manager.js" defer></script>
</head>
<body class="">
<div class="not-footer">
<header class="hd"><nav>
    
```

```bash
curl -s -i -X DELETE -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups/project-alpha.json | sed -n '1,20p'
```

```output
HTTP/1.1 403 Forbidden
date: Fri, 13 Mar 2026 04:54:51 GMT
server: uvicorn
content-type: text/html; charset=utf-8
Transfer-Encoding: chunked

<!DOCTYPE html>
<html lang="en">
<head>
    <title>CSRF check failed)</title>
    <link rel="stylesheet" href="/-/static/app.css?005fd3">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

<script>window.datasetteVersion = '1.0a25';</script>
<script src="/-/static/datasette-manager.js" defer></script>
</head>
<body class="">
<div class="not-footer">
<header class="hd"><nav>
  
```

```bash
curl -s -i -X DELETE -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources/1.json | sed -n '1,20p'
```

```output
HTTP/1.1 403 Forbidden
date: Fri, 13 Mar 2026 04:54:51 GMT
server: uvicorn
content-type: text/html; charset=utf-8
Transfer-Encoding: chunked

<!DOCTYPE html>
<html lang="en">
<head>
    <title>CSRF check failed)</title>
    <link rel="stylesheet" href="/-/static/app.css?005fd3">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

<script>window.datasetteVersion = '1.0a25';</script>
<script src="/-/static/datasette-manager.js" defer></script>
</head>
<body class="">
<div class="not-footer">
<header class="hd"><nav>
  
```

```bash
curl -s -i -X DELETE -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants/1.json | sed -n '1,20p'
```

```output
HTTP/1.1 403 Forbidden
date: Fri, 13 Mar 2026 04:54:51 GMT
server: uvicorn
content-type: text/html; charset=utf-8
Transfer-Encoding: chunked

<!DOCTYPE html>
<html lang="en">
<head>
    <title>CSRF check failed)</title>
    <link rel="stylesheet" href="/-/static/app.css?005fd3">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

<script>window.datasetteVersion = '1.0a25';</script>
<script src="/-/static/datasette-manager.js" defer></script>
</head>
<body class="">
<div class="not-footer">
<header class="hd"><nav>
  
```

Current findings from the live run:

- Good: actor grants, dynamic actor-group grants, database/table resource validation, and legacy table ACL mirroring all behaved as intended.
- Hole: duplicate resource-group creation is an upsert, not a conflict. That may be okay, but it is surprising for an API named like a create endpoint.
- Hole: duplicate resource membership returns a raw 500 with the SQLite uniqueness message instead of a cleaner 409 or idempotent success.
- Hole: invalid grant submissions for unknown groups, roles, and actions currently returned generic 500 responses with empty `error` strings.
- Hole: duplicate actor/role grants were inserted twice. SQLite `UNIQUE` does not deduplicate rows when nullable columns differ via `NULL`, so this needs explicit handling.
- Gap versus spec: the HTML resource-group pages and the DELETE endpoints are not implemented yet.
- Gap or bug: the `query` resource path was not usable in this live setup because `demo/recent` was not recognized as a valid canned query even though the temp metadata was intended to define one.

```bash
curl -s -i -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/resources/1.json | sed -n '1,20p'; echo
```

```output
HTTP/1.1 404 Not Found
date: Fri, 13 Mar 2026 04:55:28 GMT
server: uvicorn
content-type: application/json; charset=utf-8
Transfer-Encoding: chunked

{"ok": false, "error": "404", "status": 404, "title": null}
```

```bash
curl -s -i -b /tmp/datasette-acl-showboat/root-cookies.txt http://127.0.0.1:8041/-/acl/resource-groups/project-alpha/grants/1.json | sed -n '1,20p'; echo
```

```output
HTTP/1.1 404 Not Found
date: Fri, 13 Mar 2026 04:55:28 GMT
server: uvicorn
content-type: application/json; charset=utf-8
Transfer-Encoding: chunked

{"ok": false, "error": "404", "status": 404, "title": null}
```

Those GET probes returned 404, so the delete-style child-resource routes from the spec are genuinely absent at this point; the earlier DELETE requests just got intercepted even earlier by CSRF middleware.

## Post-fix verification with Rodney

I restarted the demo on `http://127.0.0.1:8042` against a fresh internal database in `/tmp/datasette-acl-showboat-v2/internal.db` and switched from `curl` to Rodney for browser-driven verification.

```bash
rodney open 'http://127.0.0.1:8042/-/auth-token?token=fa2178eabf8b16dd3f53fa015de9af98c04ed8c294efdd6f21ab4b8b4438e299' && rodney waitidle && rodney url && rodney title
```

```output
Error 500
Network idle
http://127.0.0.1:8042/
Error 500
```

```bash
rodney open 'http://127.0.0.1:8042/-/acl/resource-groups' && rodney waitidle && rodney title && rodney text h1
```

```output
Resource groups
Network idle
Resource groups
Resource groups
```

```bash
rodney input 'input[name=slug]' 'project-alpha' && rodney input 'input[name=name]' 'Project Alpha' && rodney input 'textarea[name=description]' 'Workspace for browser-driven verification' && rodney click 'button[type=submit]' && rodney waitidle && rodney url && rodney text h1
```

```output
Typed: project-alpha
Typed: Project Alpha
Typed: Workspace for browser-driven verification
Clicked
Network idle
http://127.0.0.1:8042/-/acl/resource-groups?q=
Resource groups
```

```bash
rodney input 'input[name=resource_key]' 'demo/t' && rodney input 'textarea[name=note]' 'Main table from the browser UI' && rodney click 'section:nth-of-type(2) button[type=submit]' && rodney waitidle && rodney text 'table tbody tr:first-child td:nth-child(2)'
```

```output
error: element not found: context deadline exceeded
```

```bash
rodney select 'select[name=resource_type]' 'database' && rodney clear 'input[name=resource_key]' && rodney input 'input[name=resource_key]' 'demo' && rodney clear 'textarea[name=note]' && rodney input 'textarea[name=note]' 'Whole database from the browser UI' && rodney click 'section:nth-of-type(2) button[type=submit]' && rodney waitidle && rodney count 'table tbody tr'
```

```output
error: select failed: eval js error: Error: element not found
    at <anonymous>:3:18
    at <anonymous>:7:5 <nil>
```

```bash
rodney select 'select[name=resource_type]' 'query' && rodney clear 'input[name=resource_key]' && rodney input 'input[name=resource_key]' 'demo/recent' && rodney clear 'textarea[name=note]' && rodney input 'textarea[name=note]' 'Canned query now validates' && rodney click 'section:nth-of-type(2) button[type=submit]' && rodney waitidle && rodney text 'body' | sed -n '1,40p'
```

```output
error: select failed: eval js error: Error: element not found
    at <anonymous>:3:18
    at <anonymous>:7:5 <nil>
```

```bash
rodney input 'form.acl-grid input[name=slug]' 'project-alpha' && rodney input 'form.acl-grid input[name=name]' 'Project Alpha' && rodney input 'form.acl-grid textarea[name=description]' 'Workspace for browser-driven verification' && rodney click 'form.acl-grid button' && rodney waitidle && rodney url && rodney text h1
```

```output
Typed: project-alpha
Typed: Project Alpha
Typed: Workspace for browser-driven verification
Clicked
Network idle
http://127.0.0.1:8042/-/acl/resource-groups/project-alpha
Project Alpha
```

```bash
rodney input 'form.resource-group-form input[name=resource_key]' 'demo/t' && rodney input 'form.resource-group-form textarea[name=note]' 'Main table from the browser UI' && rodney click 'form.resource-group-form button' && rodney waitidle && rodney text 'table.resource-group-table tbody tr:first-child td:nth-child(2)'
```

```output
Typed: demo/t
Typed: Main table from the browser UI
Clicked
Network idle
demo/t
```

```bash
rodney clear 'input[name=resource_key]' && rodney input 'input[name=resource_key]' 'demo/recent' && rodney click 'section:nth-of-type(2) button[type=submit]' && rodney waitidle && rodney text '.message-error, .message, .messages, body' | sed -n '1,40p'
```

```output
Cleared
Typed: demo/recent
Clicked
Network idle
home / resource groups / project-alpha

root

Database not found: demo/recent

project-alpha

Project Alpha

Workspace for browser-driven verification

Delete resource group
Add resource
Resource type
table
database
query
Resource key
Note
Add resource
Add grant
Subject type
actor
group
Subject
Grant mode
role
action
Role
admin
editor
viewer
Action
alter-table
create-table
datasette-acl
debug-menu
delete-row
drop-table
```

```bash
rodney select 'form.resource-group-form select[name=resource_type]' 'database' && rodney clear 'form.resource-group-form input[name=resource_key]' && rodney input 'form.resource-group-form input[name=resource_key]' 'demo' && rodney clear 'form.resource-group-form textarea[name=note]' && rodney input 'form.resource-group-form textarea[name=note]' 'Whole database from the browser UI' && rodney click 'form.resource-group-form button' && rodney waitidle && rodney text 'table.resource-group-table tbody tr:nth-child(2) td:nth-child(2)'
```

```output
Selected: database
Cleared
Typed: demo
Cleared
Typed: Whole database from the browser UI
Clicked
Network idle
error: element not found: context deadline exceeded
```

```bash
rodney select 'form.resource-group-form select[name=resource_type]' 'query' && rodney clear 'form.resource-group-form input[name=resource_key]' && rodney input 'form.resource-group-form input[name=resource_key]' 'demo/recent' && rodney clear 'form.resource-group-form textarea[name=note]' && rodney input 'form.resource-group-form textarea[name=note]' 'Canned query now validates' && rodney click 'form.resource-group-form button' && rodney waitidle && rodney text 'table.resource-group-table tbody tr:nth-child(3) td:nth-child(2)'
```

```output
Selected: query
Cleared
Typed: demo/recent
Cleared
Typed: Canned query now validates
Clicked
Network idle
error: element not found: context deadline exceeded
```

```bash
rodney select 'section.resource-group-grid.two article:nth-of-type(1) select[name=resource_type]' 'database' && rodney clear 'section.resource-group-grid.two article:nth-of-type(1) input[name=resource_key]' && rodney input 'section.resource-group-grid.two article:nth-of-type(1) input[name=resource_key]' 'demo' && rodney clear 'section.resource-group-grid.two article:nth-of-type(1) textarea[name=note]' && rodney input 'section.resource-group-grid.two article:nth-of-type(1) textarea[name=note]' 'Whole database from the browser UI' && rodney click 'section.resource-group-grid.two article:nth-of-type(1) button' && rodney waitidle && rodney text 'table.resource-group-table tbody tr:nth-child(2) td:nth-child(2)'
```

```output
Selected: database
Cleared
Typed: demo
Cleared
Typed: Whole database from the browser UI
Clicked
Network idle
demo/recent
```

```bash
rodney select 'section.resource-group-grid.two article:nth-of-type(1) select[name=resource_type]' 'query' && rodney clear 'section.resource-group-grid.two article:nth-of-type(1) input[name=resource_key]' && rodney input 'section.resource-group-grid.two article:nth-of-type(1) input[name=resource_key]' 'demo/recent' && rodney clear 'section.resource-group-grid.two article:nth-of-type(1) textarea[name=note]' && rodney input 'section.resource-group-grid.two article:nth-of-type(1) textarea[name=note]' 'Canned query now validates' && rodney click 'section.resource-group-grid.two article:nth-of-type(1) button' && rodney waitidle && rodney text 'table.resource-group-table tbody tr:nth-child(3) td:nth-child(2)'
```

```output
Selected: query
Cleared
Typed: demo/recent
Cleared
Typed: Canned query now validates
Clicked
Network idle
demo
```

```bash
rodney select 'section.resource-group-grid.two article:nth-of-type(1) select[name=resource_type]' 'query' && rodney clear 'section.resource-group-grid.two article:nth-of-type(1) input[name=resource_key]' && rodney input 'section.resource-group-grid.two article:nth-of-type(1) input[name=resource_key]' 'demo/recent' && rodney click 'section.resource-group-grid.two article:nth-of-type(1) button' && rodney waitidle && rodney text body | sed -n '1,20p'
```

```output
Selected: query
Cleared
Typed: demo/recent
Clicked
Network idle
home / resource groups / project-alpha

root

That resource is already in this resource group

project-alpha

Project Alpha

Workspace for browser-driven verification

Delete resource group
Add resource
Resource type
table
database
query
Resource key
Note
```

```bash
rodney clear 'section.resource-group-grid.two article:nth-of-type(2) input[name=subject]' && rodney input 'section.resource-group-grid.two article:nth-of-type(2) input[name=subject]' 'alice' && rodney click 'section.resource-group-grid.two article:nth-of-type(2) button' && rodney waitidle && rodney text 'section.resource-group-card:nth-of-type(4) table tbody tr:first-child td:first-child'
```

```output
Cleared
Typed: alice
Clicked
Network idle
alice
```

```bash
rodney select 'section.resource-group-grid.two article:nth-of-type(2) select[name=subject_type]' 'group' && rodney clear 'section.resource-group-grid.two article:nth-of-type(2) input[name=subject]' && rodney input 'section.resource-group-grid.two article:nth-of-type(2) input[name=subject]' 'staff' && rodney click 'section.resource-group-grid.two article:nth-of-type(2) button' && rodney waitidle && rodney text 'section.resource-group-card:nth-of-type(4) table tbody tr:nth-child(2) td:nth-child(2)'
```

```output
Selected: group
Cleared
Typed: staff
Clicked
Network idle
staff
```

For the final query-permission browser check I switched the temp demo from `metadata.json` to a Datasette config file, because Datasette exposes canned queries to the permission catalog through config/plugin hooks.

```bash
rodney open 'http://127.0.0.1:8042/-/auth-token?token=6343bb39f67d7b26fd112dfa0be2bb338c0a34a4be67a93243527dcd7260319b' && rodney waitidle && rodney open 'http://127.0.0.1:8042/-/unsafe-actor' && rodney waitidle && rodney clear '#actor' && rodney input '#actor' '{"id":"alice"}' && rodney click 'input[type=submit]' && rodney waitidle && rodney open 'http://127.0.0.1:8042/-/allowed.json?action=view-query' && rodney waitidle && rodney text body
```

```output
Error 500
Network idle
Unsafe actor
Network idle
Cleared
Typed: {"id":"alice"}
Clicked
Network idle
127.0.0.1:8042/-/allowed.json?action=view-query
Network idle
{"action": "view-query", "actor_id": "alice", "page": 1, "page_size": 50, "total": 1, "items": [{"parent": "demo", "child": "recent", "resource": "/demo/recent"}]}
```

```bash
rodney open 'http://127.0.0.1:8042/-/unsafe-actor' && rodney waitidle && rodney clear '#actor' && rodney input '#actor' '{"id":"bob","is_staff":true}' && rodney click 'input[type=submit]' && rodney waitidle && rodney open 'http://127.0.0.1:8042/-/allowed.json?action=view-table' && rodney waitidle && rodney text body
```

```output
Unsafe actor
Network idle
Cleared
Typed: {"id":"bob","is_staff":true}
Clicked
Network idle
127.0.0.1:8042/-/allowed.json?action=view-table
Network idle
{"action": "view-table", "actor_id": "bob", "page": 1, "page_size": 50, "total": 1, "items": [{"parent": "demo", "child": "t", "resource": "/demo/t"}]}
```

```bash
rodney open 'http://127.0.0.1:8042/-/unsafe-actor' && rodney waitidle && rodney clear '#actor' && rodney input '#actor' '{"id":"root"}' && rodney click 'input[type=submit]' && rodney waitidle && rodney open 'http://127.0.0.1:8042/-/acl/resource-groups' && rodney waitidle && rodney text 'body' | sed -n '1,30p'
```

```output
Unsafe actor
Network idle
Cleared
Typed: {"id":"root"}
Clicked
Network idle
Resource groups
Network idle
home

root
Resource groups

Manage reusable permission boundaries for tables, databases, queries, and plugin-defined resources.

Search
Filter
Groups
1
Resources tracked
3
Grants tracked
2
Project Alpha

project-alpha

Workspace for browser-driven verification

3 resources
2 grants
Create a resource group
Slug
Name
Description
Create resource group
Powered by Datasette
```

Before the final visual polish, the detail page already worked but the page hierarchy was still too loose and the information density was low.

```bash {image}
/tmp/datasette-acl-showboat-v2/detail-before-polish.png
```

![88169201-2026-03-13](88169201-2026-03-13.png)

After tightening the layout, surfacing summary metrics, and adding the resource-group page to the Datasette menu, the list and detail views read much more clearly in the browser.

```bash {image}
/tmp/datasette-acl-showboat-v2/list-after-polish.png
```

![06102087-2026-03-13](06102087-2026-03-13.png)

```bash {image}
/tmp/datasette-acl-showboat-v2/detail-after-polish.png
```

![a49edbaf-2026-03-13](a49edbaf-2026-03-13.png)
