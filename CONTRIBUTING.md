# Contributing to sedg

## Opening Issues

Before you file an issue, please search existing issues to see if there is
already an existing issue. If you file an issue, please ensure you include all
the requested details (e.g. configuration files, python version, platform,
etc).

## Contributing code

### Creating a pull request

1. Open a new issue to discuss the changes you would like to make. This is not
   strictly required but it may help reduce the amount of rework you need to do
   later.
2. Make your changes
3. Ensure you have added proper unit tests and appropriate help documentation
4. Open a new pull request
6. The pull request title needs to follow [conventional commit format](https://www.conventionalcommits.org/en/v1.0.0/#summary)

**Note:** If you have a pull request with only one commit, then that commit
needs to follow the conventional commit format or the `Semantic Pull Request`
check will fail. This is because github will use the pull request title if
there are multiple commits, but if there is only one commit it will use it
instead.

Before opening a pull request you should run the following checks locally to
make sure the CI will pass.

```shell
$ make check
```
