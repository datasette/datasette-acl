"""A throwaway sample plugin for exercising datasette-acl end-to-end.

Loaded via ``--plugins-dir tests/sample-plugin`` from ``just dev`` (NOT a
packaged plugin — it is dev/demo scaffolding only). It implements a minimal
"widgets" feature the way a real consumer plugin would:

- A ``widgets`` table in the internal database. Any signed-in actor can create
  widgets from ``/-/widgets``.
- An acl resource type ``widget`` (parent ``widgets``, child = the widget id,
  mirroring e.g. datasette-apps' ``app``/``apps`` shape) with actions
  ``widget-view`` / ``widget-edit`` / ``widget-manage``.
- The canonical Viewer / Editor / Manager triple declared via acl's
  ``standard_roles()`` factory.
- The creator is granted the Manager role on their widget, so they "own" it:
  they can rename it, and — because Manager carries ``manage=True`` — acl's
  ``can_manage`` gate lets them open the admin page at
  ``/-/acl/resource/widget/widgets/<id>`` to share it with other actors,
  groups, or the General access audiences, without holding the global
  ``datasette-acl`` permission.

Pair with datasette-debug-gotham: its actor switcher signs you in as Clark,
Bruce, etc., and its cast feeds the admin page's user picker via the
``datasette_acl_valid_actors`` hook below. The gotham actors carry a
``newsroom`` attribute, which the ``dynamic-groups`` config in the Justfile
turns into daily-planet / gotham-gazette groups for group-grant demos.
"""

from datasette import hookimpl, Forbidden, Response
from datasette.permissions import Action, Resource

from datasette_acl.grants import grant, Principal
from datasette_acl.roles import role_for_actions, roles_for, standard_roles

# datasette-debug-gotham's demo actors (Clark Kent, Bruce Wayne, …). Imported
# softly so this plugin still loads without gotham — the picker just goes
# empty and creators show as raw ids.
try:
    from datasette_debug_gotham import ACTORS as GOTHAM_ACTORS
except Exception:  # pragma: no cover - depends on dev env
    GOTHAM_ACTORS = {}

WIDGETS_PARENT = "widgets"


# --- the resource type -------------------------------------------------------


class WidgetsResource(Resource):
    """The parent container — exists so WidgetResource is a two-level type.

    acl's ``build_resource`` builds two-level types as ``rc(parent, child)``,
    which is what makes the ``/-/acl/resource/widget/widgets/<id>`` admin URL
    resolve.
    """

    name = "widgets"
    parent_class = None

    def __init__(self):
        super().__init__(parent=WIDGETS_PARENT, child=None)

    @classmethod
    async def resources_sql(cls, datasette, actor=None):
        return f"SELECT '{WIDGETS_PARENT}' AS parent, NULL AS child"


class WidgetResource(Resource):
    name = "widget"
    parent_class = WidgetsResource

    def __init__(self, parent=None, child=None):
        # Accept both the ergonomic WidgetResource(widget_id) and acl's
        # positional build_resource convention WidgetResource("widgets", id).
        if child is None:
            child = parent
        super().__init__(
            parent=WIDGETS_PARENT, child=str(child) if child is not None else None
        )

    @classmethod
    async def resources_sql(cls, datasette, actor=None):
        # acl stores resource ids as text; CAST so `child IS :child` matches.
        return (
            f"SELECT '{WIDGETS_PARENT}' AS parent, "
            "CAST(id AS TEXT) AS child FROM widgets"
        )


# --- acl hooks ---------------------------------------------------------------


@hookimpl
def register_actions(datasette):
    return [
        Action(
            name="widget-view",
            description="View a widget",
            resource_class=WidgetResource,
        ),
        Action(
            name="widget-edit",
            description="Edit a widget",
            resource_class=WidgetResource,
        ),
        Action(
            name="widget-manage",
            description="Manage sharing for a widget",
            resource_class=WidgetResource,
        ),
    ]


@hookimpl
def datasette_acl_roles(datasette):
    return standard_roles(
        "widget",
        view="widget-view",
        edit="widget-edit",
        manage="widget-manage",
        descriptions={"Manager": "Full control, including sharing"},
    )


@hookimpl
def datasette_acl_valid_actors(datasette):
    """Feed the gotham cast into the admin page's "Other user" picker."""
    return [
        {"id": actor_id, "display": info.get("name", actor_id)}
        for actor_id, info in GOTHAM_ACTORS.items()
    ]


# --- storage -----------------------------------------------------------------


@hookimpl
def startup(datasette):
    async def inner():
        db = datasette.get_internal_database()
        await db.execute_write("""
            CREATE TABLE IF NOT EXISTS widgets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )
            """)

    return inner


def _creator_name(actor_id):
    return GOTHAM_ACTORS.get(actor_id, {}).get("name", actor_id)


async def _role_name(datasette, widget_id, actor):
    """The actor's highest role on a widget, or None when they have no access.

    Resolved the same way acl does it: collect the actions the actor is
    ``allowed`` on this resource, then map that set to the best-fit role.
    """
    roles = roles_for(datasette, "widget")
    resource = WidgetResource(widget_id)
    granted = set()
    for action in {a for role in roles for a in role.actions}:
        if await datasette.allowed(action=action, resource=resource, actor=actor):
            granted.add(action)
    role = role_for_actions(roles, granted)
    return role.name if role else None


# --- pages -------------------------------------------------------------------


async def widgets_index(request, datasette):
    db = datasette.get_internal_database()

    if request.method == "POST":
        actor_id = (request.actor or {}).get("id")
        if not actor_id:
            raise Forbidden("Sign in to create widgets")
        post_vars = await request.post_vars()
        name = (post_vars.get("name") or "").strip()
        if not name:
            datasette.add_message(request, "A widget needs a name", datasette.ERROR)
            return Response.redirect(request.path)
        widget_id = await db.execute_write_fn(
            lambda conn: conn.execute(
                "INSERT INTO widgets (name, created_by) VALUES (?, ?)",
                [name, actor_id],
            ).lastrowid
        )
        # The creator owns their widget: a Manager grant gives them
        # view + edit + manage, and manage authorizes re-sharing from the
        # /-/acl/resource/widget/widgets/<id> admin page.
        await grant(
            datasette,
            "widget",
            WIDGETS_PARENT,
            str(widget_id),
            principal=Principal.actor(actor_id),
            role="Manager",
            by_actor=actor_id,
        )
        datasette.add_message(request, f"Widget '{name}' created — you are its Manager")
        return Response.redirect(datasette.urls.path(f"/-/widgets/{widget_id}"))

    # Only list widgets the current actor may view, tagged with their role —
    # Viewer already implies widget-view, so a non-None role is the view gate.
    widgets = []
    rows = await db.execute("SELECT * FROM widgets ORDER BY id")
    for row in rows.rows:
        role = await _role_name(datasette, row["id"], request.actor)
        if role is None:
            continue
        widgets.append(
            {
                **dict(row),
                "creator_name": _creator_name(row["created_by"]),
                "role": role,
            }
        )
    return Response.html(
        await datasette.render_template(
            "widgets_index.html",
            {"widgets": widgets, "signed_in": bool(request.actor)},
            request=request,
        )
    )


async def widget_page(request, datasette):
    db = datasette.get_internal_database()
    widget_id = request.url_vars["id"]
    row = (await db.execute("SELECT * FROM widgets WHERE id = ?", [widget_id])).first()
    if row is None:
        return Response.html("Widget not found", status=404)

    resource = WidgetResource(widget_id)
    if not await datasette.allowed(
        action="widget-view", resource=resource, actor=request.actor
    ):
        raise Forbidden("You don't have access to this widget")
    can_edit = await datasette.allowed(
        action="widget-edit", resource=resource, actor=request.actor
    )
    can_manage = await datasette.allowed(
        action="widget-manage", resource=resource, actor=request.actor
    )

    if request.method == "POST":
        if not can_edit:
            raise Forbidden("You cannot edit this widget")
        post_vars = await request.post_vars()
        name = (post_vars.get("name") or "").strip()
        if name:
            await db.execute_write(
                "UPDATE widgets SET name = ? WHERE id = ?", [name, widget_id]
            )
            datasette.add_message(request, f"Renamed to '{name}'")
        return Response.redirect(request.path)

    return Response.html(
        await datasette.render_template(
            "widget.html",
            {
                "widget": {
                    **dict(row),
                    "creator_name": _creator_name(row["created_by"]),
                },
                "role": await _role_name(datasette, widget_id, request.actor),
                "can_edit": can_edit,
                "can_manage": can_manage,
                "acl_url": datasette.urls.path(
                    f"/-/acl/resource/widget/{WIDGETS_PARENT}/{widget_id}"
                ),
            },
            request=request,
        )
    )


@hookimpl
def register_routes():
    return [
        (r"^/-/widgets$", widgets_index),
        (r"^/-/widgets/(?P<id>[0-9]+)$", widget_page),
    ]


@hookimpl
def homepage_actions(datasette, actor, request):
    return [
        {
            "href": datasette.urls.path("/-/widgets"),
            "label": "Widgets",
            "description": "Sample widgets for exercising acl sharing",
        }
    ]
