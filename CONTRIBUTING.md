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
$ make install-venv
$ . ./.venv/bin/activate
(.venv) $ make check
(.venv) $ deactivate
$
```

## Dependencies

`sedg` dependencies are managed using standard `pip`:
https://realpython.com/what-is-pip/

### requirements.txt

#### Initial setup

`setup.cfg` lists required top-level required production dependencies in
`[options]`, optional production dependencies in `[options.extras_require]`
'cache'/'edn' and top-level development dependencies in
`[options.extras_require]` 'dev'.

`requirements.txt` is used to lock dependencies to particular versions to make
installations reproducible (and GitHub dependabot understands this format).
Within sedg, this file was initially created with:

```
    $ rm -rf ./.venv                # remove exising virtual environment
    $ python3 -m venv .venv         # create virtual environment '.venv'
    $ . ./.venv/bin/activate        # enter '.venv'
    # create prod requirements.txt by installing prod deps into '.venv' based
    # on setup.cfg [options] then creating the requirements.txt lock file
    $ pip install .
    $ pip install .[cache]
    $ pip install .[dso]
    $ pip freeze | grep -Ev '^(-e|sedg==)' > ./requirements.txt
    # create dev requirements_dev.txt by installing dev deps on top of prod
    # deps based on setup.cfg [options.extras_require], then diff the output
    # with requirements.txt to create the requirements_dev.txt lock file
    $ pip install .[dev]
    $ pip freeze | grep -v '^-e' > ./requirements_dev.tmp
    $ echo "-r requirements.txt" > ./requirements_dev.txt
    $ diff -Nau ./requirements.txt ./requirements_dev.tmp | \
        grep '^+[a-z]' | cut -d '+' -f 2 >> ./requirements_dev.txt
    $ rm -f ./requirements_dev.tmp
```

#### Installing dependencies

Once created, can install production dependencies in a reproducible way with:

```
    $ rm -rf ./.venv                       # remove exising virtual environment
    $ python3 -m venv .venv                # create virtual environment '.venv'
    $ . ./.venv/bin/activate               # enter '.venv'
    $ pip install -r requirements.txt      # install prod deps into '.venv'
    # alternatively
    $ rm -rf ./.venv                       # remove exising virtual environment
    $ make install-venv                    # install prod deps into '.venv'
```

Development dependencies are installed like so:

```
    $ rm -rf ./.venv                         # remove exising virtual environment
    $ python3 -m venv .venv                  # create virtual environment '.venv'
    $ . ./.venv/bin/activate                 # enter '.venv'
    $ pip install -r requirements_dev.txt -e # install prod deps into '.venv'
    # alternatively
    $ rm -rf ./.venv                         # remove exising virtual environment
    $ make install-venv-dev                  # install prod deps into '.venv'
```

Note, `-e` installs the egg file in `.venv` to point to the source directory,
which is convenient for development.

#### Updating dependencies

The process for keeping `requirements.txt` up to date is:

1. verify everything is ok in the current, unchanged environment:
    ```
        $ deactivate                    # only if currently in '.venv'
        $ rm -rf ./.venv                # remove existing '.venv'
        $ make install-venv
        $ . ./.venv/bin/activate
        $ make test                     # unit tests
    ```
2. update `requirements.txt` as desired
3. upgrade the virtual environment to the new versions in `requirement.txt`
    ```
        # assumes '. ./.venv/bin/activate' was run
        $ pip install -U -r ./requirements.txt
    ```
4. verify new dependencies work ok:
    ```
        # assumes '. ./.venv/bin/activate' was run
        $ make test
    ```
5. commit changes to `requirements.txt`

The process is similar for `requirements_dev.txt`:

1. verify everything is ok in the current, unchanged environment:
    ```
        $ deactivate                    # only if currently in '.venv'
        $ rm -rf ./.venv                # remove existing '.venv'
        $ make install-venv-dev
        $ . ./.venv/bin/activate
        $ make check                    # full tests, including unit tests
    ```
2. update `requirements_dev.txt` as desired
3. upgrade the virtual environment to the new versions in `requirement_dev.txt`
    ```
        # assumes '. ./.venv/bin/activate' was run
        $ pip install -U -r ./requirements_dev.txt
    ```
4. verify new dependencies work ok:
    ```
        # assumes '. ./.venv/bin/activate' was run
        $ make check
    ```
5. commit changes to `requirements_dev.txt`


#### Adding dependencies

The process for adding dependencies is:

1. verify everything is ok in the current, unchanged environment:
    ```
        $ deactivate                    # only if currently in '.venv'
        $ rm -rf ./.venv                # remove existing '.venv'
        $ make install-venv
        $ . ./.venv/bin/activate
        $ make test
    ```
2. install top level dependencies with `pip install`. Eg:
    ```
        # assumes '. ./.venv/bin/activate' was run
        $ pip install foo
    ```
3. verify new dependencies work ok:
    ```
        # assumes '. ./.venv/bin/activate' was run
        $ make test
    ```
4. update `requirements.txt`:
    ```
        # assumes '. ./.venv/bin/activate' was run
        $ pip freeze | grep -v '^-e' > ./requirements.txt
    ```
5. add the top level dependency to `setup.cfg`

The process is similar for `requirements_dev.txt` except test with `make check`
and use diff of `requirements.txt` and `requirements_dev.txt` as in 'Initial
setup' (above).
