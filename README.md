# datasette-acl

[![PyPI](https://img.shields.io/pypi/v/datasette-acl.svg)](https://pypi.org/project/datasette-acl/)
[![Changelog](https://img.shields.io/github/v/release/datasette/datasette-acl?include_prereleases&label=changelog)](https://github.com/datasette/datasette-acl/releases)
[![Tests](https://github.com/datasette/datasette-acl/actions/workflows/test.yml/badge.svg)](https://github.com/datasette/datasette-acl/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/datasette/datasette-acl/blob/main/LICENSE)

Advanced permission management for Datasette. **Highly experimental**.

## Installation

Install this plugin in the same environment as Datasette.
```bash
datasette install datasette-acl
```
## Usage

This plugin is under active development. It currently only supports configuring [permissions](https://docs.datasette.io/en/latest/authentication.html#permissions) for individual tables, controlling the following:

- `insert-row`
- `delete-row`
- `update-row`
- `alter-table`
- `drop-table`

Permissions are saved in the internal database. This means you should run Datasette with the `--internal path/to/internal.db` option, otherwise your permissions will be reset every time you restart Datasette.

### Managing permissions for a table

The interface for configuring table permissions lives at `/database-name/table-name/-/acl`. It can be accessed from the table actions menu on the table page.

Permission can be granted for each of the above table actions. They can be assigned to both groups and individual users, who can be added using their `actor["id"]`.

An audit log tracks which permissions were added and removed, displayed at the bottom of the table permissions page.

### Controlling who can edit permissions

Users with the new `datasette-acl` permission will have the ability to access a UI for setting permissions for groups on a table.

To configure the root user to have this permission, add the following to your Datasette configuration:

```yaml
permissions:
  datasette-acl:
    id: root
```
Alternatively you can start Datasette running like this:
```bash
datasette mydata.db --root --internal internal.db \
  -s permissions.datasette-acl.id root
```

### User groups

Users can be assigned to groups, and those groups can then be used to quickly assign permissions to all of those users at once.

To manage your groups, visit `/-/acl/groups` or use the "Manage user groups" item in the Datasette application menu.

Add users to a group by typing in their actor ID. Remove them using the provided remove button.

The page for each group includes an audit log showing changes made to that group's list of members.

When you delete a group its members will all be removed and it will be marked as deleted. Creating a group with the same name will reuse that group's record and display its existing audit log, but will not re-add the members that were removed.

### Dynamic groups

You may wish to define permission rules against groups of actors based on their actor attributes, without needing to manually add those actors to a group. This can be achieved by defining a dynamic group in the `datasette-acl` configuration.

Dynamic groups are defined in terms of [allow blocks](https://docs.datasette.io/en/stable/authentication.html#defining-permissions-with-allow-blocks). The following configuration defines two dynamic groups - one called `admin` that contains all users with `"is_admin": true` in their attributes, and another called `sales` that explicitly lists the users with `"sales"` as one of the values in their `department` array.

```yaml
plugins:
  datasette-acl:
    dynamic-groups:
      admin:
        is_admin: true
      sales:
        department: ["sales"]
```

Any time an actor has their permissions checked they will be dynamically added to or removed from these groups based on the current value of their actor attributes.

Dynamic groups are displayed in the list of groups, but their members cannot be manually added or removed.

### Table creator permissions

If you allow regular users to create tables in Datasette, you may want them to maintain a level of "ownership" over those tables, such that other users are unable to modify those tables without the creator's permission.

The `table-creator-permissions' setting can be used to automatically configure permissions for the actor who created a table.

Enable that like this:
```yaml
plugins:
  datasette-acl:
    table-creator-permissions:
    - alter-table
    - drop-table
    - insert-row
    - update-row
    - delete-row
```
## Development

To set up this plugin locally, first checkout the code. Then create a new virtual environment:
```bash
cd datasette-acl
python -m venv venv
source venv/bin/activate
```
Now install the dependencies and test dependencies:
```bash
pip install -e '.[test]'
```
To run the tests:
```bash
python -m pytest
```

### Tips for local development

Here's how to run the plugin with all of its features enabled.

First, grab a test database:
```bash
wget https://latest.datasette.io/fixtures.db
```
Install the [datasette-unsafe-actor-debug](https://github.com/datasette/datasette-unsafe-actor-debug) plugin, so you can use the `http://127.0.0.1:8001/-/unsafe-actor` page to quickly imitate any actor for testing purposes:
```bash
datasette install datasette-unsafe-actor-debug
```
And [datasette-visible-internal-db](https://github.com/datasette/datasette-visible-internal-db) to make it easy to see what's going on in the internal database:
```bash
datasette install datasette-visible-internal-db
```
Then start Datasette like this:
```bash
datasette fixtures.db --internal internal.db \
  -s permissions.datasette-acl.id root \
  -s plugins.datasette-unsafe-actor-debug.enabled 1 \
  -s plugins.datasette-acl.table-creator-permissions '["insert-row", "update-row"]' \
  -s plugins.datasette-acl.dynamic-groups.staff.is_staff true \
  --root \
  --secret 1 \
  --reload
```
This configures Datasette to provide a URL for you to sign in as root, which will give you access to the permission editing tool.

It ensures that any user who creates a table (which you can test using the `/-/api` API explorer tool) will be granted initial `insert-row` and `update-row` permissions.

It sets up a dynamic group such that any actor with `{"is_staff": true}` in their JSON will be treated as a member of that group.

`--reload` means Datasette will reload on any code changes to the plugin, and `--secret 1` ensures your Datasette authentication cookies will continue to work across server restarts.
