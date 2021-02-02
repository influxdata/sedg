# Using

 1. Clone this repo (https://github.com/jdstrand/influx-security-tools)

 2. Clone CVE data (https://github.com/jdstrand/influx-security-tools-cve-data)

 3. Create ~/.config/influx-security-tools.conf to have:

    ```
    [Locations]
    cve-data = /path/to/influx-security-tools-cve-data
    ```

 4. Do stuff

    ```
    $ export PYTHONPATH=/path/to/influx-security-tools
    $ export PATH=$PATH:/path/to/influx-security-tools/bin
    $ <work on CVEs in .../influx-security-tools-cve-data>
    $ cve-check-syntax
    ```

 5. (Optional) If vim user, symlink cvelib/cve.vim in ~/.vim/syntax


# Tests

Run all checks:

    $ make check

Run unittests:

    $ make check-deps  # install what it tells you (deb-centric)
    $ make test

or a single test file:

    $ PYTHONPATH=$PWD python3 -m unittest cvelib.tests.cve_test

or a single test:

    $ PYTHONPATH=$PWD python3 -m unittest cvelib.tests.cve_test.TestCve.test_parse_headers
