# Using

 1. Clone this repo (https://github.com/influxdata/sedg)

 2. Create a venv for it (a venv is recommended to ensure you have the proper
    versions of dependencies to avoid mismatches and bugs (eg, requests_cache
    1.0.1 is known to have issues with system python packages from Ubuntu 20.04
    LTS)):

    ```
    $ cd /path/to/sedg
    $ make install-venv
    ```

    `make install-venv` does the following:
    ```
    $ python3 -m venv .venv
    $ . ./.venv/bin/activate
    (venv) $ pip install ./requirements.txt
    ```

 3. Clone CVE data into `/path/to/cve-data`

 4. Optionally create a shell function to setup your environment for using sedg
    with your CVE data. Eg, in `~/.bashrc`:

    ```
    cve_env() {
        sedgpath="/path/to/sedg"

        test "$VIRTUAL_ENV" = "$sedgpath/.venv" && return  # already activated

        echo "Entering venv for 'sedg' tooling. Use 'deactivate' when done."
        VIRTUAL_ENV_DISABLE_PROMPT=1 . "$sedgpath/.venv/bin/activate"

        cd "/path/to/cve-data"
    }
    ```

 4. Create `~/.config/sedg/sedg.conf` to have:

    ```
    [Locations]
    cve-data = /path/to/cve-data
    ```

    Optionally add any template URLs for GitHub alert template text to the
    `Behavior` section (comma-separated):

    ```
    [Behavior]
    template-urls = https://url1,https://url2
    ```

    Optionally add OCI product overrides. By default, `cve-report gar|quay`
    security scan reports will use `oci/gar-<GAR_LOCATION>.<GAR_PROJECT>` or
    `oci/quay-<QUAY_ORG>` depending on where the security report is coming
    from. Use `oci-cve-override-where` to override this behavior to always use
    `oci/gar-<OCI_WHERE>` or `oci/quay-<OCI_WHERE>`. Eg:

    ```
    [Behavior]
    oci-cve-override-where = myorg
    ```

 5. Do stuff

    ```
    # if added shell function
    $ cve_env
    # otherwise
    $ cd /path/to/cve-data
    $ VIRTUAL_ENV_DISABLE_PROMPT=1 . /path/to/sedg/.venv/bin/activate

    # create a CVE against a particular package
    $ cve-add --cve CVE-2020-1234 -p git/foo-org_foo

    # create a placeholder CVE against a particular package
    $ cve-add -c CVE-2020-NNN1 -p git/foo-org_foo

    # create a new placeholder CVE for this year against a particular package
    # (creates CVE-<YEAR>-NNN1 if it doesn't exist or incremements the highest
    # found for the year and adds it (eg, if CVE-<YEAR>-NNN9 exists,
    # CVE-<YEAR>-NN10 is created))
    $ cve-add -c next -p git/foo-org_foo

    # create a GitHub placholder CVE from the GitHub url using this year
    $ cve-add --cve https://github.com/...

    # create a GitHub placeholder CVE with a particular id and package
    # template
    $ cve-add -c CVE-2020-GH1234#foo -p git/foo-org_foo --package-template=bar

    $ <work on CVEs in .../<cve-data>
    $ cve-check-syntax

    # various reports for humans (add --help to see additional options)
    $ cve-report summary			# summary
    $ cve-report todo           		# todo list

    # various machine reports
    $ cve-report influxdb               	# InfluxDB line protocol

    # GitHub-specific reports
    $ cve-report gh --org <org> --status=active
    $ cve-report gh --org <org> --alerts --since YYYY-MM-DD

    # GAR container security reports
    $ cve-report gar --list <project>/<location>
    $ cve-report gar --list-digest <project>/<location>/<repo>/<name>
    $ cve-report gar --alerts --name <project>/<location>/<repo>/<name>@<digest>

    # quay.io container security reports
    $ cve-report quay --list <org>
    $ cve-report quay --list-digest <org>/<name>
    $ cve-report quay --alerts --name <org>/<name>@<digest>

    # Docker DSO container security reports
    $ cve-report dso --list-digest <repo>[:<tag>|@<sha256>]
    $ cve-report dso --alerts --name <repo>[:<tag>|@<sha256>]

    # if desired, leave the venv
    $ deactivate
    ```

 6. (Optional) If vim user, symlink `extras/vim/syntax/cve.vim` in
    `~/.vim/syntax` or `~/.config/nvim/syntax`, symlink
    `extras/vim/indent/cve.vim` in `~/.vim/indent` or `~/.config/nvim/indent`
    and add to VIMRC:
    ```
    " CVEs
    augroup cve
      autocmd!
      autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9GN]* set ft=cve
      autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9GN]* set syntax=cve
      autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9GN]* set autoindent
      autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9GN]* setlocal indentexpr=GetCVEIndent()
      autocmd BufNewFile,BufRead */path/to/cve-data-dir/templates/* set ft=cve
      autocmd BufNewFile,BufRead */path/to/cve-data-dir/templates/* set syntax=cve
      autocmd BufNewFile,BufRead */path/to/cve-data-dir/templates/* set autoindent
      autocmd BufNewFile,BufRead */path/to/cve-data-dir/templates/* setlocal indentexpr=GetCVEIndent()
    augroup END
    ```

# Staying up to date

Assuming you've setup sedg as described in 'Using', can stay up to date with:

    ```
    $ cd /path/to/sedg
    $ git checkout main
    $ git fetch && git pull --ff-only
    $ make install-venv
    ```

# Uninstalling

Since `sedg` is installed to a venv, uninstall is as simple as:

    ```
    $ rm -rf /path/to/sedg/.venv
    ```

# Tests

Development should be done in a venv, see 'Using' above to set one up. Once
setup, develop like so:

    $ cd /path/to/sedg
    $ VIRTUAL_ENV_DISABLE_PROMPT=1 . ./venv/bin/activate
    $ pip install .[dev]   # install extra development dependencies
    $
    <do stuff>
    $ deactivate

Run all checks:

    $ make check

Run unittests:

    $ make test
    ...
    Ran 116 tests in 0.219s
    OK

or a single test file:

    # template
    $ python3 -m unittest tests.test_foo
    # example
    $ python3 -m unittest tests.test_cve

or a single test:

    # template
    $ python3 -m unittest tests.test_foo.TestFoo.test_bar
    # example
    $ python3 -m unittest tests.test_cve.TestCve.test___init__valid


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
Items within `[]` are optional.

```
    Candidate: CVE-<year>-<number> | CVE-<year>-GH<issue/pull>#<project> | CVE-<year>-NNNX
    OpenDate: YYYY-MM-DD [ HH:MM:SS [ TZ|+-N ] ]
    CloseDate: YYYY-MM-DD [ HH:MM:SS [ TZ|+-N ] ]
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
    [GitHub-Advanced-Security:
     - type: dependabot
       dependency: <3rd party software>
       detectedIn: path/to/file
       advisory: https://github.com/advisories/GHSA-... | unavailable
       severity: low | moderate | high | critical
       status: needs-triage | needed | released | removed | dismissed (<reason>; <who>)
       url: https://github.com/ORG/REPO/security/dependabot/N | unavailable
     - type: secret
       secret: <found secret description>
       detectedIn: path/to/file
       status: needs-triage |needed | released | dismissed (<reason>; <who>)
       url: https://github.com/ORG/REPO/security/secret-scanning/N | unavailable]
    [Scan-Reports:
     - type: oci
       component: <affected software>
       detectedIn: <OCI image name>
       advisory: <url for relevant security advisory> | unavailable
       fixedBy: <version> | unavailable
       severity: low | moderate | high | critical
       status: needs-triage|needed|released|dismissed (<reason>; <who>)
       url: <url to scan report> | unavailable]
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
     <who>: <CVSS string> [(<score> [low|medium|high|critical)]

    Patches_<software1>:
     upstream | vendor | distro | other: <url>
    [CloseDate_<software1>: YYYY-MM-DD [ HH:MM:SS [ TZ|+-N ] ]
    [CloseDate_<software1>[/modifier]: YYYY-MM-DD [ HH:MM:SS [ TZ|+-N ] ]
    [Tags_<software1>: <tag1> <tag2>]
    [Tags_<software1>[/<modifier>]: <tag1> <tag2>]
    [Priority_<software1>: negligible | low | medium | high | critical]
    [Priority_<software1>[/modifier]: negligible | low | medium | high | critical]
    <product1>[/<where>]_<software1>[/<modifier>]: <status> [(<when>)]
    <product2>[/<where>]_<software1>[/<modifier>]: <status> [(<when>)]

    Patches_<software2>:
     upstream | vendor | distro | other: <url>
    [CloseDate_<software2>: YYYY-MM-DD [ HH:MM:SS [ TZ|+-N ] ]
    [CloseDate_<software2>[/modifier]: YYYY-MM-DD [ HH:MM:SS [ TZ|+-N ] ]
    [Tags_<software2>: <tag1> <tag2>]
    [Tags_<software2>[/modifier]: <tag1> <tag2>]
    [Priority_<software2>: negligible | low | medium | high | critical]
    [Priority_<software2>[/<modifier>]: negligible | low | medium | high | critical]
    <product1>[/<where>]_<software2>[/<modifier>]: <status> [(<when>)]
    <product2>[/<where>]_<software2>[/<modifier>]: <status> [(<when>)]

    ... <additional software> ...
```

The CVE format can be thought of in two sections: the global section and the
software section. Since CVE identifiers often apply to more than one product,
software version, etc, the global section is meant to generally apply to all
software declared in the CVE, whereas the software section lists specifics for
each software product, version, etc. In this manner, a single CVE file may
contain all pertinent information for the CVE on the whole with per-software
entries showing status for this issue.


## Global section

For each field in the global section:
 * `Candidate` is the CVE identifier for this issue. 3 formats are supported:
   * `CVE-<year>-<number>` (eg, `CVE-2020-1234`) is used for tracking publicly
     assigned issues
   * `CVE-<year>-NNNX` (eg, `CVE-2020-NNN1` or `CVE-2020-NNN2`) is used for
     tracking non-public issues. This might be useful for tracking before a
     public assignment or when tracking a private issue. By convention, when
     first creating a non-public CVE, choose the current year and increment the
     value of `X` like so: `CVE-2020-NNN1`, `CVE-2020-NNN2`, ...,
     `CVE-2020-NNN9`, `CVE-2020-NN10`, ..., `CVE-2020-N999`, `CVE-2020-N1000`,
     etc)
   * `CVE-<year>-GH<issue/pull>#<project>` (eg, `CVE-2020-GH1234#foo`) is used
     for tracking a non-public or a not-yet-assigned-CVE identifier issue in
     GitHub. It encodes both the GitHub repository and issue number/pull
     request, such that `CVE-2020-GH1234#foo` corresponds with
     `https://github.com/<yourorg>/foo/issues/1234`. This is particularly
     useful for organizations with lots of repositories.
 * `OpenDate` is the date the CVE was created
 * `CloseDate` is the date the CVE was closed (nothing 'need-triage', 'needed'
   or 'pending'). Per-software close date overrides are possible in the
   software section (below).
 * `PublicDate` is the date that a private CVE was made public
 * `CRD` is the Coordinated Release Date. This can be used for coordinating
   with other parties to make a CVE public at a specific time
 * `References` contains a list of URLs, one per line, relevant for the CVE
 * `Description` contains the general description for the CVE. It may contain
   details for a specific piece of software (but typically not details on how
   other software might use it)
 * `GitHub-Advanced-Security` is optional and may be used to track GitHub
   dependabot alerts and secret scanning
 * `Scan-Reports` is optional and may be used to track OCI scan reports
 * `Notes` contains information from triagers, developers, etc to give more
   insight into the vulnerability, particularly how it pertains to individual
   pieces of software, configuration, build artifacts, etc. It will often
   contain rationale for entries in the software section (below), but may
   contain anything that is relevant
 * `Mitigation` contains information on how available mitigations may be
   applied before patching
 * `Bugs` contains a list of Bug tracker URLs, one per line. These may also be
   listed in the References section
 * `Priority` contains the priority for fixing the CVE, typically as it pertains
   to the item described in the `Description` (above). Per-software priority
   overrides are possible in the software section (below). Supported
   priorities are:
   * `negligible`
   * `low`
   * `medium`
   * `high`
   * `critical`
 * `Discovered-by` is a comma-separated list of names, slack handles, GitHub
   usernames, etc and used for attribution. `gh-dependabot` and `gh-secret` are
   used when using `GitHub-Advanced-Security` (above). `quay.io`, `gar` and
   `docker` are used when using `Scan-Reports` (above) with specific
   report URLs.
 * `Assigned-to` contains the name, slack handle, GitHub username, etc of the
   person assigned to this issue
 * `CVSS` contains a list of CVSS scores as assigned by different entities (eg,
   'nvd', 'redhat', 'ubuntu', etc)


## Software section

By convention, the software section is typically divided into stanzas grouped
by software. The blank line before each software section is not required but is
normally used since it makes the CVE easier to read.

For each field in the software section:
 * `Patches_<softwareN>` (eg, `Patches_foo` or `Patches_bar`) contains a list
   of patch URLs, one per line, with provenance prefixed
 * `CloseDate_<softwareN>[/modifier]` (eg, `CloseDate_foo` or
   `CloseDate_bar/v1`) is optional and when specified contains a close date
   override for `<softwareN>[/modifier]`
 * `Tags_<softwareN>[/modifier]` (eg, `Tags_foo` or `Tags_bar/v1`) is optional
   and when specified contains a comma-separated list of tags. Tags have
   historically been used to describe a mitigating factor provided by the OS
   (ie, without user intervention, so different than the `Mitigation` section,
   above). The `limit-report` tag is used to manipulate reports in different
   ways. Currently supported tags are:
   * `apparmor`
   * `fortify-source`
   * `hardlink-restriction`
   * `heap-protector`
   * `limit-report`
   * `pie`
   * `stack-protector`
   * `symlink-restriction`
 * `Priority_<softwareN>[/modifier]` (eg, `Priority_foo` or `Priority_bar/v1`)
   is optional and when specified contains a priority override for
   `<softwareN>[/modifier]`
 * `<product>` is the supporting technology (eg, a VCS system, build artifact
   or operating system) or simply `upstream`. Supported `<product>`s:
   * VCS: bzr, cvs, git, hg or svn
   * build artifacts: appimage, archive, deb, dmg, exe, flatpak, oci, rpm,
     shell, snap
   * OS: alpine, android, centos, debian, distroless, flatcar, ios, opensuse,
     osx, rhel, suse, ubuntu, windows
 * `<where>` indicates where the software lives or in the case of technologies
   with a concept of publishers, who the publisher is. For OS (eg, `ubuntu`,
   `debian`, `suse`, etc), `<where>` indicates the release of the distribution
   (eg, `ubuntu/focal` indicates 20.04 for Ubuntu where `ubuntu` is the
   `<product>` (distro) and `focal` is the `<where>` (distro release)). For
   `git`, `<where>` could indicate the source code hosting provider (eg,
   `github`, `gitlab`, `launchpad`, etc) or could be used to indicate the
   organization/user in a hosting provider. Eg, `git/github_foo` indicates that
   `foo` is somewhere in GitHub whereas `git/bar_foo` could be used to indicate
   that `foo` is in some provider's organization/user. How `<where>` is used is
   not prescribed and the `<product>/<where>` combination is not meant to
   capture everything where the software lives. It is meant to be flexible to
   allow triagers a means to discern these differences as appropriate for their
   requirements (eg, perhaps the triager wants to track the status of the
   `targz` vs `zip`, one might use `archive/targz` and `archive/zip`).
 * `<software>` is the name of the software as dictated by the product (eg, the
   name of the github project, the name of the OCI image, the deb source
   package, the name of the build artifact, etc)
 * `<modifier>` is an optional key for grouping collections of packages (eg,
   'v1' for the project's `v1` branch, `v2`, etc)
 * `<status>` indicates the status of fixing the issue for this software (eg,
   `needs-triage`, `needed`, `pending`, `released`, `not-affected` and
   `deferred`).
 * `<when>` is optional and when specified occurs within parentheses and
   indicates when the software will be/was fixed when used with the `pending`,
   `released` or `not-affected` status. When may be a version number (for
   software with releases), a git hash (for continuous development), a revision
   number or a date (eg, for an OCI image).
   * As a special case for `not-affected` and `deferred` the `<when>`
     parenthetical might give a hint as to why (eg `code-not-present` with
     `not-affected`). Typical hints for 'not-affected':
     * `code-not-present`: project does not contain the vulnerable code path
     * `code-not-compiled`: project does not compile the vulnerable code path
     * `code-not-imported`: project does not import the vulnerable code path
     * `code-not-used`: project contains/imports/etc the code but does use it
     * YYYY-MM-DD with deferred: date when entry was put into the deferred
       status
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

    # github-hosted example for https://github.com/barproj/bar
    Patches_bar:
    git/barprog_bar: needed

    # github-hosted example for https://github.com/barproj/baz with different
    # branches for different releases for v1/v2 and continuous development on
    # main
    Patches_baz:
     upstream: https://github.com/org/baz/pull/123
    git/barproj_baz/v1: pending
    git/barproj_baz/v2: released (2.0.13)
    git/barproj_baz/main: released (907e560b)

    # OCI images for different registries
    Patches_norf:
    Tags_norf: pie
    oci/dockerhub_norf: needs-triage

    # Linux distribution
    Patches_corge:
    upstream_corge: released (1.2)
    debian/buster_corge: needed
    ubuntu/xenial_corge: not-affected (code-not-present)
    ubuntu/bionic_corge: needed
    ubuntu/focal_corge: not-affected (1.2-3)
    ubuntu/groovy_corge: not-affected (1.4-1)

    # Snap for different publishers
    Patches_qux:
    snap/pub1_qux: released (1234)
    snap/pub2_qux: not-affected (code-not-compiled)
```

The format offers considerable flexibility. For example, to capture upstream vs
GitLab vs GitHub (where, for example, GitHub and GitLab might be forks of
upstream), one might use:

```
    Patches_foo:
    upstream_foo: needed
    github/someacct_foo: needed
    gitlab/otheracct_foo: needed
```


## Ubuntu compatibility
The file format was initially defined in Ubuntu and the syntax above is largely
compatible with the Ubuntu CVE tracker (UCT) and a longer term goal of this
project is to push this tooling to UCT. The above format is more generalized,
strict and applicable to other projects. If using this tooling with UCT data,
then adjust `~/.config/sedg_ubuntu.conf` to contain:

```
    [Behavior] compat-ubuntu = yes
```

When specifying compat mode:
* `CVSS` is single line instead of multiline list. Eg:
  `CVSS: <CVSS string> [\[<score> LOW|MEDIUM|HIGH|CRITICAL\]]`
* `<product>` may specify Ubuntu releases as a shorthand (eg, `focal` instead
  of `ubuntu/focal`)
* patches can specify various other types (eg, in addition to `distro`,
  `other`, `upstream` and `vendor`, allow `debdiff`, `diff`, `fork`, `merge`,
  etc)
* For `Tags...` and `Priority...`, disallow `_` in `<software>`, allow `/` in
  `<modifier>` and allow `_` as the delimiter for their use of
  `_<release>[/<modifier>]` (eg, `Tags_foo_precise/esm`)

Package stanzas then become:
```
    Patches_<software>:
     upstream | vendor | debdiff | other | debdiff | diff | ...: <url>
    [Tags_<software>: <tag1> <tag2>]
    [Tags_<software>[_<ubuntu release>[/<modifier>]]: <tag1> <tag2>]
    [Priority_<software>: negligible | low | medium | high | critical]
    [Priority_<software>[_<ubuntu release>[/<modifier>]]: negligible | low | medium | high | critical]
    <ubuntu release>_<software>[/<modifier>]: <status> [(<when>)]
    <product>[/<where>]_<software>[/<modifier>]: <status> [(<when>)]
```

# Monitoring

`bin/cve-report` can be used to generate human-readable output or line protocol
suitable for sending to InfluxDB. Eg:

```
$ cve-report influxdb
cvelog,priority=medium,status=needed,product=git id="CVE-2020-1234",software="foo",modifier="" 1633040641675003246
...

# or pipe into 'influx write' (InfluxData Cloud 2 or InfluxDB 2.x):
$ cve-report influxdb | influx write --host $URL --org-id $ORGID --bucket-id $BUCKETID --token $TOKEN

# or pipe into 'curl' (omit '&org=$INFLUX_ORG' when not using InfluxData Cloud
# 2 and InfluxDB 2.x (eg, InfluxData Cloud Dedicated))
$ export INFLUX_URL=https://...
$ export INFLUX_BUCKET=...
$ export INFLUX_ORG=...
$  export INFLUX_TOKEN=...
$ cve-report influxdb | curl --header "Authorization: Bearer $INFLUX_TOKEN" --header "Content-Type: text/plain; charset=utf-8" --header "Accept: application/json" --request POST "$INFLUX_HOST/api/v2/write?bucket=$INFLUX_BUCKET&org=$INFLUX_ORG" --data-binary @-
```

For now, paste this into 'Add Data/Line Protocol' whenever you make relevant
changes to the CVE data. A tool will eventually be provided to make this
easier.

This line protocol can then be queried in various ways. Since CVE data is not
expected to be updated on a daily basis, the following techniques of using two
`aggregateWindow()` functions, the first with `createEmpty: false` and the
second with `createEmpty: true` (the default) and a `noop`, allows for graphs
to be filled in for any days that are missing (both in the middle and at the
end). The start time must necessarily have at least one point to work. If
sending data in daily, you can skip the `noop()` function and at the end use a
single `aggregateWindow(every: 1d, count)` without a `fill()`.

It is possible to backfill by checking out a commit and running `cve-report`
with `--starttime`. Eg:
```
$ cve-report influxdb --starttime $(date --date "8 days ago" "+%s")
```

TODO: there is also a telegraf/github plugin that could be investigated.

## Total unique open issues
```
from(bucket: "sec-issues")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "cvelog" and r["_field"] == "id")
  |> keep(columns: ["_time", "_value", "_field", "priority"])
  |> window(every: 1d)
  |> unique()
  |> group(columns: ["priority"])
  // https://community.influxdata.com/t/advice-how-to-carry-forward-data-from-the-previous-day/21895
  // get all the counts, but don't create any empty data since count() has the
  // side-effect of turning nulls to 0s
  |> aggregateWindow(every: 1d, createEmpty: false, fn: count)
  // create the empty data with nulls intact
  |> aggregateWindow(every: 1d, fn: (tables=<-, column="_value") => tables)
  // convert nulls in "_value" to the previous row
  |> fill(usePrevious: true)
```

Best viewed as stacked graph with static legend.

## Open issues in affected software

Grouped by software:
```
import "strings"
from(bucket: "sec-issues")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "cvelog" and (r["_field"] == "id" or r["_field"] == "software"))
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> map(fn: (r) => ({
    r with
    _value: strings.joinStr(arr: [r.software, r.id, r.priority], v: ":")
  }))
  |> drop(columns: ["id", "product", "status"])
  |> group(columns: ["software"])
  |> window(every: 1d)
  |> unique()
  // https://community.influxdata.com/t/advice-how-to-carry-forward-data-from-the-previous-day/21895
  |> aggregateWindow(every: 1d, createEmpty: false, fn: count)
  |> aggregateWindow(every: 1d, fn: (tables=<-, column="_value") => tables)
  |> fill(usePrevious: true)
```

Best viewed as stacked graph with static legend.

Old (grouped by priority):
```
import "strings"
from(bucket: "sec-issues")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "cvelog" and (r["_field"] == "id" or r["_field"] == "software"))
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
  |> filter(fn: (r) => r["_measurement"] == "cvelog" and (r["_field"] == "id" or r["_field"] == "software"))
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
  // https://community.influxdata.com/t/advice-how-to-carry-forward-data-from-the-previous-day/21895
  |> aggregateWindow(every: 1d, createEmpty: false, fn: count)
  |> aggregateWindow(every: 1d, fn: (tables=<-, column="_value") => tables)
  |> fill(usePrevious: true)
```

Best viewed as stacked graph with static legend.


### Alert on open issues
```
import "influxdata/influxdb/secrets"
import "slack"

// secret is https://hooks.slack.com/services/X/Y/Z
webhook_url = secrets.get(key: "my-webhook-url")
endpoint = slack.endpoint(url: webhook_url)

mapFnCrit = (r) => ({
  text: if r._value == 1 then "${r._value} open critical security issue" else "${r._value} open critical security issues",
  color: "danger",
  channel: "",
})
toSlackCrit = endpoint(mapFn: mapFnCrit)

mapFnHigh = (r) => ({
  text: if r._value == 1 then "${r._value} open high security issue" else "${r._value} open high security issues",
  color: "danger",
  channel: "",
})
toSlackHigh = endpoint(mapFn: mapFnHigh)

critlvl = 0
highlvl = 0

// grab everything from the last 30 days and filter down once so we don't
// have to keep doing it. We'll filter down more as we go.
data = from(bucket: "jdstrand-sec-stats")
  |> range(start: -30d, stop: now())
  |> filter(fn: (r) => r["_measurement"] == "cvelog" and r["_field"] == "id")

getLatest = (tables=<-) => {
  row = tables
    |> group(columns: ["_time"])
    |> aggregateWindow(every: 1d, createEmpty: false, fn: count)
    |> group(columns: ["_time"], mode: "except")
    |> last()
    |> limit(n: 1)
    // we only have 1 row at this point, but fn must be specified
    |> findRecord(fn: (key) => true, idx: 0)
  return row._time
}

latest = data
  |> getLatest()

// check for statuses for the 24 hour period before time of the latest entry
checkStatus = (tables=<-, priority, threshold) =>
  tables
    |> range(start: -24h, stop: latest)
    |> filter(fn: (r) => r["priority"] == priority)
    |> group(columns: ["priority"])
    |> window(every: 1d)
    |> unique()
    |> aggregateWindow(every: 1d, createEmpty: false, fn: count)
    |> last()
    |> limit(n: 1)
    |> filter(fn: (r) => r["_value"] > threshold)

crit = data
  |> checkStatus(priority: "critical", threshold: critlvl)
  |> toSlackCrit()
  |> yield(name: "critical")

high = data
  |> checkStatus(priority: "high", threshold: highlvl)
  |> toSlackHigh()
  |> yield(name: "high")
```

# GitHub and CVE data
GitHub does not provide easy mechanisms to subscribe to labels in repos or
across the org and also doesn't provide issue label information in their email
headers for bug comments. Combined, we must poll GitHub for information to
detect new issues or issues that have received updates. The
`cve-report` tool aims to address this gap. Example usage:
```
    # first export a GitHub Personal Access Token that can read issues:
    $  export GHTOKEN=...

    # Show issues that are referenced in open CVE data that have been
    # updated since last week
    $ cve-report gh --updated --org foo --since $(date --date "7 days ago" "+%s")
    Updated issues:
     https://github.com/foo/bar/issues/123
     https://github.com/foo/baz/issues/234

    # Show list of issues for specific repos in an org with different
    # labels, but without label 'skipme'
    $ cve-report gh --missing \
        --org foo \
        --labels="bar:baz" \
        --excluded-labels="skipme" \
        --repos=norf,corge,qux
    Fetching list of repos: ...... done!
    Fetching list of issues for:
     foo/corge: .. done!
     foo/norf: .. done!
     foo/qux: . done!
     ...
    Issues missing from CVE data:
     https://github.com/foo/corge/issues/345
     https://github.com/foo/quz/issues/456

    # Show dependabot alerts since last stamp file update (does not filter on
    # 'active' status)
    $ cve-report gh --alerts \
        --org foo \
        --since-stamp /path/to/stamp
    Collecting repo status: [#########################################] 100%
    Collecting alerts: [##############################################] 100%
    Updated vulnerability alerts:
     bar (https://github.com/foo/bar/security/dependabot):
      lodash
      - severity: high
      - yarn.lock
      - https://github.com/advisories/GHSA-35jh-r3h4-6jhm
```

`cve-report gh --updated` also supports `--since-stamp` as a convenience and
will set the since time to the `mtime` of the specified file. Eg, to bootstrap
and then just use the stamp file, use:
```
    # first time only
    $ cve-report gh --updated --org foo --since $(date --date "7 days ago" "+%s")

    # hereafter
    $ cve-report gh --updated \
        --org foo \
        --since-stamp /path/to/stamp
```

The `cve-report` script can also be used to show a few things about GitHub
repos. Eg, to show archived repos:

```
$ cve-report gh --org foo --status=archived
norf
```

To show active repos:
```
$ cve-report gh --org foo --status=active
bar
baz
```

This can, for example, by used to manage a file of active repos that can be fed
into other tools. Eg:
```
# for private repos
$  export GHUSER=...
$  export GHTOKEN=...
$ cve-report gh --org foo --status=active | sort -f > foo-repos.txt
$ cve-report summary --software="foo-repos.txt"
```
