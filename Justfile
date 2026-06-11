# datasette-acl — dev recipes
#
# `just dev` loads the widgets sample plugin (tests/sample-plugin) +
# datasette-debug-gotham. Visit http://localhost:5172/-/widgets, "log in" as a
# character via the gotham actor switcher, create a widget (you become its
# Manager), then share/restrict it from /-/acl/resource/widget/widgets/<id>.
#
# The gotham actors carry a `newsroom` attribute; the dynamic-groups config
# below turns it into daily-planet / gotham-gazette groups so group grants can
# be exercised too. `root` (via the --root sign-in link) holds the global
# datasette-acl admin permission.

dev *flags:
  DATASETTE_SECRET=abc123 uv run \
    --prerelease=allow \
    --with-editable . \
    --with datasette-debug-gotham \
    datasette \
    --root \
    --plugins-dir tests/sample-plugin \
    --template-dir tests/sample-plugin/templates \
    -s permissions.datasette-acl.id root \
    -s plugins.datasette-acl.dynamic-groups.daily-planet.newsroom daily-planet \
    -s plugins.datasette-acl.dynamic-groups.gotham-gazette.newsroom gotham-gazette \
    tmp.db --create \
    --internal internal.db \
    -p 5172 \
    {{flags}}

# Same as `dev`, but restarts datasette when .py/.html files change.
dev-with-hmr *flags:
  watchexec \
    --stop-signal SIGKILL \
    -e py,html \
    --ignore '*.db' \
    --restart \
    --clear -- \
    just dev {{flags}}

test *options:
  uv run pytest {{options}}
