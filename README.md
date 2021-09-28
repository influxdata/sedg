# Using

 1. Clone this repo (https://github.com/influxdata/influx-security-tools)

 2. Clone CVE data (https://github.com/influxdata/influx-security-tools-cve-data)

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


# CVE File format

The CVE file format follows RFC5322. In essence:

```
    Field1: single-line value
    Field2:
     multi-line values start on the following line with each line always
     preceded by a space
```

This file format is compliant with various language libraries, such as Python's
email.policy.Compat32 (compat since it doesn't conform to Python's shipping
policies). Since RFC5322 doesn't support utf-8, utf-8 is not properly supported
by the file format. The format could be moved to RFC6532 at a future date.

```
    Candidate: CVE-<year>-<number> | CVE-<year>-GH<issue/pull>#<project>
    PublicDate: YYYY-MM-DD [ HH:MM:SS [ TZ|+-N ] ]
    CRD: YYYY-MM-DD [ HH:MM:SS [ TZ|+-N ] ]
    References:
     <url>
     <url> (with comment)
    Description:
     Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
     tempor incididunt ut labore et dolore magna aliqua. Aliquam sem et tortor
     consequat id porta nibh venenatis.
     .
     Tellus orci ac auctor augue mauris augue neque.
    Notes:
     person> One line note
     person> Multi-line note. Lorem ipsum dolor sit amet, consectetur adipiscing
      elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
      Aliquam sem et tortor consequat id porta nibh venenatis.
      .
      Tellus orci ac auctor augue mauris augue neque.
    Mitigation: <mitigation>
    Bugs:
     <url>
     <url>
    Priority: negligible | low | medium | high | critical
    Discovered-by: First Last [ @<slack> | <githubUser> ], ...
    Assigned-to: First Last [ @<slack> | <githubUser> ]
    CVSS:
     <who>: <CVSS string; use https://cvssjs.github.io/ to calculate>

    Patches_<software1>:
     upstream | vendor | debdiff | other: <url>
    [Tags_<software1>: <tag1> <tag2>]
    [Tags_<software1>[_<extra>]: <tag1> <tag2>]
    [Priority_<software1>: negligible | low | medium | high | critical]
    [Priority_<software1>[_<extra>]: negligible | low | medium | high | critical]
    <product1>[/<where>]_<software1>[/<modifier>]: <status> [(<when>)]
    <product2>[/<where>]_<software1>[/<modifier>]: <status> [(<when>)]

    Patches_<software2>:
     upstream | vendor | debdiff | other: <url>
    [Tags_<software2>: <tag1> <tag2>]
    [Tags_<software2>[_<extra>]: <tag1> <tag2>]
    [Priority_<software2>: negligible | low | medium | high | critical]
    [Priority_<software2>[_<extra>]: negligible | low | medium | high | critical]
    <product1>[/<where>]_<software2>[/<modifier>]: <status> [(<when>)]
    <product2>[/<where>]_<software2>[/<modifier>]: <status> [(<when>)]

    ... <additional software> ...
```

Note that the blank line before each software section is not required but is
conventional and easier to read.

For each field in the software section:
 * `<product>` is the supporting technology (eg, `git`, `snap`, `oci`, etc).
   Could also be OS (eg, `ubuntu`, `debian`, `suse`, etc).
 * `<where>` indicates where the software lives or in the case of snaps or
   other technologies with a concept of publishers, who the publisher is. For
   OS (eg, `ubuntu`, `debian`, `suse`, etc), `<where>` indicates the release of
   the distribution (eg, `ubuntu/focal` indicates 20.04 for Ubuntu).
 * `<software>` is the name of the software as dictated by the product (eg, the
   name of the github project, the name of the OCI image, the deb source
   package, the name of the snap, etc)
 * `<modifier>` is an optional key for grouping collections of packages (eg,
   'v1' for the project's `v1` branch, `v2`, etc)
 * `<status>` indicates the status of fixing the issue for this software (eg,
   `needs-triage`, `needed`, `pending`, `released`, `not-affected` and
   `deferred`.
 * `<when>` is optional and when specified occurs within parentheses and
   indicates when the software will be/was fixed when used with the `pending`,
   `released` or `not-affected` status. When may be a version number (for
   software with releases), a git hash (for continuous development), a snap
   revision number or a date (eg, for an OCI image).
   * As a special case for `not-affected` and `deferred` the `<when>`
     parenthetical might give a hint as to why (eg `code not present` with
     `not-affected`).
   * `not-affected` and `released` are similar but convey different things. Eg
     `not-affected (1.2.3)` vs `released (1.2.1+patch1)` is saying that `1.2.3`
     wasn't ever affected (ie, didn't require anything to be done) but
     `1.2.1+patch1` was affected but is now fixed. This can be useful for
     software following a release schedule or tracking updates within a Linux
     distribution.

Typical software stanza examples:
```
    # Simple example for some upstream project
    Patches_foo:
    upstream_foo: released (1.2)

    # github-hosted example
    Patches_bar:
    git/github_bar: needed

    # github-hosted example with different branches for different releases for
    # v1/v2 and continuous development on main
    Patches_baz:
     upstream: https://github.com/org/baz/pull/123
    git/github_baz/v1: pending
    git/github_baz/v2: released (2.0.13)
    git/github_baz/main: released (907e560b)

    # OCI images for different registries
    Patches_norf:
    Tags_norf: pie
    oci/dockerhub_norf: needs-triage

    # Linux distribution
    Patches_corge:
    upstream_corge: released (1.2)
    debian/buster_corge: needed
    ubuntu/xenial_corge: not-affected (code not present)
    ubuntu/bionic_corge: needed
    ubuntu/focal_corge: not-affected (1.2-3)
    ubuntu/groovy_corge: not-affected (1.4-1)

    # Snap for different publishers
    Patches_qux:
    snap/pub1_qux: released (1234)
    snap/pub2_qux: not-affected (code not compiled)
```

The format offers considerable flexibility. For example, to capture the
organization with github, one might use `github/<org>_...` instead of
`git/github_...`.


# Monitoring

## Total unique open issues
```
from(bucket: "sec-issues")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "cveLog" and r["_field"] == "id")
  |> keep(columns: ["_time", "_value", "_field", "priority"])
  |> window(every: 1d)
  |> unique()
  |> group(columns: ["priority"])
  |> aggregateWindow(every: 1d, fn: count)
```

## Open issues in affected software

Grouped by software:
```
import "strings"
from(bucket: "sec-issues")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "cveLog" and (r["_field"] == "id" or r["_field"] == "software"))
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> map(fn: (r) => ({
    r with
    _value: strings.joinStr(arr: [r.software, r.id, r.priority], v: ":")
  }))
  |> drop(columns: ["id", "product", "status"])
  |> group(columns: ["software"])
  |> window(every: 1d)
  |> unique()
  |> aggregateWindow(every: 1d, fn: count)
```

Old (grouped by priority):
```
import "strings"
from(bucket: "sec-issues")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "cveLog" and (r["_field"] == "id" or r["_field"] == "software"))
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> map(fn: (r) => ({
    r with
    _value: strings.joinStr(arr: [r.software, r.id, r.priority], v: ":")
  }))
  |> drop(columns: ["id", "product", "status", "software"])
  |> group(columns: ["priority"])
  |> window(every: 1d)
  |> unique()
  |> aggregateWindow(every: 1d, fn: count)
```

### Open issues by software/priority
```
import "strings"
from(bucket: "sec-issues")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "cveLog" and (r["_field"] == "id" or r["_field"] == "software"))
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> map(fn: (r) => ({
    r with
    tuple: strings.joinStr(arr: [r.software, r.priority], v: ":"),
    _value: strings.joinStr(arr: [r.software, r.priority, r.id], v: ":")
  }))
  |> drop(columns: ["id", "product", "status", "software"])
  |> group(columns: ["tuple"])
  |> window(every: 1d)
  |> unique()
  |> aggregateWindow(every: 1d, fn: count)
```
