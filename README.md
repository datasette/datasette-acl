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

This plugin is under active development. For the moment, it only supports defining permissions for tables against dynamic groups, described below.

Permissions are saved in the internal database. This means you should run Datasette with the `--internal path/to/internal.db` option, otherwise your permissions will be reset every time you restart Datasette.

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


### Dynamic groups

You may wish to define permission rules against groups of actors based on their actor attributes, without needing to manually add those actors to a group. This can be achieved by defining a dynamic group in the `datasette-acl` configuration.

Dynamic groups are defined in terms of [allow blocks](https://docs.datasette.io/en/stable/authentication.html#defining-permissions-with-allow-blocks). The following configuration defines two dynamic groups - one called `admin` that contains all users with `"is_admin": true` in their attributes, and another called `sales` that explicitly lists the users with `"sales"` as one of the values in their `department` array.

```yaml
plugins:
  datasette-acl:
    dynamic-groups:
      admin:
        is_admin": true
      sales:
        department: ["sales"]
```

Any time an actor has their permissions checked they will be dynamically added to or removed from these groups based on the current value of their actor attributes.

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
