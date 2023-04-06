#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import configparser
import copy
import datetime
import os
import re
import shutil
import sys
import tempfile
import time
from typing import Dict, List, Optional, Pattern, Set, Tuple, Union

from email.message import Message
from email.parser import HeaderParser, Parser
from email.policy import Compat32


# cache of config
configCache: Optional[configparser.ConfigParser] = None

cve_priorities: List[str] = ["critical", "high", "medium", "low", "negligible"]
cve_statuses: List[str] = [
    "needs-triage",
    "needed",
    "pending",
    "released",
    "deferred",
    "ignored",
    "DNE",
    "not-affected",
]

# TODO: pull these out into dictionaries and move to membership checks (where
# the value of the dict could be a description of the thing (eg, for tags):
# - pkg-product
# - pkg-status
# - priorities
# - pkg-patch
# - pkg-tags
#
# In addition, tooling could augment the dictionaries for things it's
# interested in.
#

# Various configurable lengths used in the regexes
_patLengths: Dict[str, int] = {
    "pkg-product-ubuntu": 40,
    "pkg-where": 40,
    "pkg-software": 50,
    "pkg-modifier": 40,
    "pkg-when": 100,
}

# Compile common regex on import
rePatterns: Dict[str, Pattern[str]] = {
    # foo, foo1, foo-bar, foo.bar, for-bar-1.0, foo_bar, FOO
    "pkg-software": re.compile(
        r"^[a-zA-Z0-9+._-]{1,%(software_len)d}$"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    # foo, foo1, foo-bar, foo.bar, for-bar-1.0
    "pkg-software-ubuntu": re.compile(
        r"^[a-z0-9+.-]{1,%(software_len)d}$"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    # add others distros and build artifacts (oci, etc) as desired
    "pkg-product": re.compile(
        r"^(git|snap|oci|upstream|alpine|centos|debian|opensuse|rhel|suse|ubuntu)$"
    ),
    "pkg-product-build-artifact": re.compile(r"^(snap|oci)$"),
    "pkg-product-ubuntu": re.compile(
        r"^[a-z0-9+.-]{1,%(product_len)d}$"
        % ({"product_len": _patLengths["pkg-product-ubuntu"]})
    ),
    "pkg-status": re.compile(r"^(%s)$" % "|".join(cve_statuses)),
    # free form text
    "pkg-when": re.compile(
        r"^[a-zA-Z0-9 +.,/'\":~\[\]_()<>#=|`-]{1,%(when_len)d}$"
        % ({"when_len": _patLengths["pkg-when"]})
    ),
    # the string form
    "pkg-full": re.compile(
        r"^(git|snap|oci|upstream|alpine|debian|suse|ubuntu)(/[a-z0-9+.-]{1,%(where_len)d})?_[a-zA-Z0-9+._-]{1,%(software_len)d}(/[a-z0-9+.-]{1,%(modifier_len)d})?: (needs-triage|needed|pending|released|deferred|ignored|DNE|not-affected)( \([a-zA-Z0-9 +.,/'\":~\[\]_()<>#=|`-]{1,%(when_len)d}\))?$"
        % (
            {
                "where_len": _patLengths["pkg-where"],
                "software_len": _patLengths["pkg-software"],
                "when_len": _patLengths["pkg-when"],
                "modifier_len": _patLengths["pkg-modifier"],
            }
        )
    ),
    "pkg-full-ubuntu": re.compile(
        r"^[a-z0-9+.-]{1,%(product_len)d}(/[a-z0-9+.-]{1,%(where_len)d})?_[a-z0-9+.-]{1,%(software_len)d}(/[a-z0-9+.-]{1,%(modifier_len)d})?: (needs-triage|needed|pending|released|deferred|ignored|DNE|not-affected)( \([a-zA-Z0-9 +.,'\"/:~\[\]()<>#=|`_-]{1,%(when_len)d}\))?$"
        % (
            {
                "software_len": _patLengths["pkg-software"],
                "where_len": _patLengths["pkg-where"],
                "when_len": _patLengths["pkg-when"],
                "product_len": _patLengths["pkg-product-ubuntu"],
                "modifier_len": _patLengths["pkg-modifier"],
            }
        )
    ),
    # CVE-YYYY-XXXX (1-12 X's)
    # CVE-YYYY-NNNX (1-3 N's, 1-11 X's (ie, NNN1 through N99999999999))
    # CVE-YYYY-GHXXXX#AAAA (1-12 X's, 1-40 A's)
    "CVE": re.compile(
        r"^CVE-[0-9]{4}-([0-9]{4,12}|N{3}[0-9]|N{2}[0-9]{2}|N[0-9]{1,11}|GH[0-9]{1,12}#[a-zA-Z0-9+._-]{1,%(software_len)d})$"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    # CVE-YYYY-NNNX (NNN1 through N99999999999)
    "CVE-placeholder": re.compile(
        r"^CVE-[0-9]{4}-(N{3}[0-9]|N{2}[0-9]{2}|N[0-9]{1,11})$"
    ),
    "CVE-next-placeholder": re.compile(
        r"^CVE-%d-(N{3}[0-9]|N{2}[0-9]{2}|N[0-9]{1,11})$" % datetime.datetime.now().year
    ),
    # CVE priorities
    "priorities": re.compile(r"^(%s)$" % "|".join(cve_priorities)),
    # date only: YYYY-MM-DD
    # date and time: YYYY-MM-DD HH:MM:SS
    # date and time with timezone: YYYY-MM-DD HH:MM:SS TZ|+-N
    "date-only": re.compile(r"20[0-9][0-9]-[01][0-9]-[0-3][0-9]$"),
    "date-time": re.compile(
        r"20[0-9][0-9]-[01][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]$"
    ),
    "date-full-offset": re.compile(
        r"20[0-9][0-9]-[01][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] [+-][01][0-9]+$"
    ),
    "date-full-tz": re.compile(
        r"20[0-9][0-9]-[01][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] [A-Z]+$"
    ),
    "date-full": re.compile(
        r"20[0-9][0-9]-[01][0-9]-[0-3][0-9](| [0-2][0-9]:[0-5][0-9]:[0-5][0-9](| ([+-][01][0-9]+|[A-Z]+)))$"
    ),
    # https://github.com/<org>/<project>/issues/<num>
    "github-issue": re.compile(
        r"^https://github.com/[a-z0-9+.-]{1,40}/[a-zA-Z0-9+._-]{1,%(software_len)d}/issues/[0-9]{1,12}"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    # https://github.com/advisories/GHSA-...
    "github-advisory": re.compile(
        r"^(unavailable|https://github.com/advisories/GHSA-[a-zA-Z0-9\-]+)$"
    ),
    "github-dependabot-severity": re.compile(r"^(low|moderate|high|critical)$"),
    # dismissed requires a reason and github username
    "github-dependabot-status": re.compile(
        r"^(needs-triage|needed|released|removed|dismissed \((started|no-bandwidth|tolerable|inaccurate|code-not-used); [a-zA-Z0-9\-]+\))$",
    ),
    "github-dependabot-alert": re.compile(
        r"^(unavailable$|https://github.com/[a-z0-9+.-]{1,40}/[a-zA-Z0-9+._-]{1,%(software_len)d}/security/dependabot/[0-9]{1,12})"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    "github-secret-alert": re.compile(
        r"^(unavailable$|https://github.com/[a-z0-9+.-]{1,40}/[a-zA-Z0-9+._-]{1,%(software_len)d}/security/secret-scanning/[0-9]{1,12})"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    "github-code-alert": re.compile(
        r"^(unavailable$|https://github.com/[a-z0-9+.-]{1,40}/[a-zA-Z0-9+._-]{1,%(software_len)d}/security/code-scanning/[0-9]{1,12})"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    # dismissed requires a reason and github username
    "github-secret-status": re.compile(
        r"^(needs-triage|needed|released|dismissed \((revoked|false-positive|used-in-tests|wont-fix); [a-zA-Z0-9\-]+\))$",
    ),
    # dismissed requires a reason and github username
    "github-code-status": re.compile(
        r"^(needs-triage|needed|released|dismissed \((false-positive|used-in-tests|wont-fix); [a-zA-Z0-9\-]+\))$",
    ),
    # upstream: something
    # vendor: something
    # other: something
    # break-fix: - -
    # break-fix: - hash
    # break-fix: hash -
    # break-fix: hash hash|local-*
    # break-fix: local-*-break local-*-fix
    "pkg-patch": re.compile(
        r"^((distro|other|upstream|vendor): I?[a-z0-9+.-].*|break-fix: +((-|I?[0-9a-f]+) +(-|I?[0-9a-f]+)|(-|I?[0-9a-f|]+|(I?[0-9a-f|]+)?local[a-zA-X0-9|-]+)? +(-|I?[0-9a-f|]+|(I?[0-9a-f|]+)?local[a-zA-X0-9|-]+)|(-|(cvs|ftp|git|https?|sftp|shttp|svn)://[^ ]+) (-|(cvs|ftp|git|https?|sftp|shttp|svn)://[^ ]+))$)"
    ),
    # The above, plus some Ubuntu-specific (eg, older releases)
    "pkg-patch-ubuntu": re.compile(
        r"^((distro|other|upstream|vendor|debdiff|diff|fork|merge|proposed|unknown|alpine|android|debian|fedora|opensuse|redhat|dapper|hardy|jaunty|karmic|lucid|maverick): I?[a-z0-9+.-].*|break-fix: +((-|I?[0-9a-f]+) +(-|I?[0-9a-f]+)|(-|I?[0-9a-f|]+|(I?[0-9a-f|]+)?local[a-zA-X0-9|-]+)? +(-|I?[0-9a-f|]+|(I?[0-9a-f|]+)?local[a-zA-X0-9|-]+)|(-|(cvs|ftp|git|https?|sftp|shttp|svn)://[^ ]+) (-|(cvs|ftp|git|https?|sftp|shttp|svn)://[^ ]+))$)"
    ),
    # TODO: break out Ubuntu-specific tags
    "pkg-patch-key": re.compile(
        r"^Patches_[a-zA-Z0-9+.-][a-zA-Z0-9+._-]{0,%(software_len)d}[a-zA-Z0-9+.-]$"
        % ({"software_len": _patLengths["pkg-software"] - 2})
    ),
    "pkg-patch-key-ubuntu": re.compile(
        r"^Patches_[a-z0-9+.-]{1,%(software_len)d}$"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    # TODO: break out Ubuntu-specific tags
    "pkg-tags": re.compile(
        r"^(apparmor|stack-protector|fortify-source|symlink-restriction|hardlink-restriction|heap-protector|limit-report|pie|universe-binary|not-ue)$"
    ),
    # TODO: reuse product/where
    "pkg-tags-key": re.compile(
        r"^Tags_[a-zA-Z0-9+.-][a-zA-Z0-9+._-]{0,%(software_len1)d}[a-zA-Z0-9+.-](/[a-z0-9+.-]{1,%(software_len2)d})?$"
        % (
            {
                "software_len1": _patLengths["pkg-software"] - 2,
                "software_len2": _patLengths["pkg-software"],
            }
        )
    ),
    "pkg-tags-key-ubuntu": re.compile(
        r"^Tags_[a-z0-9+.-]{1,%(software_len)d}(_[a-z0-9+./-]{1,%(software_len)d})?$"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    "pkg-priority-key": re.compile(
        r"^Priority_[a-zA-Z0-9+.-][a-zA-Z0-9+._-]{0,%(software_len1)d}[a-zA-Z0-9+.-](/[a-z0-9+.-]{1,%(software_len2)d})?$"
        % (
            {
                "software_len1": _patLengths["pkg-software"] - 2,
                "software_len2": _patLengths["pkg-software"],
            }
        )
    ),
    "pkg-priority-key-ubuntu": re.compile(
        r"^Priority_[a-z0-9+.-]{1,%(software_len)d}(_[a-z0-9+./-]{1,%(software_len)d})?$"
        % ({"software_len": _patLengths["pkg-software"]})
    ),
    # urls
    "url-schemes": re.compile(r"^(cvs|ftp|git|https?|sftp|shttp|svn)://."),
    # People. We accept utf-8 so this is broad
    # Some One
    # Some One (someone-handle)
    # Some One (someone-handle), Some One Else
    # Some "Nickname" One (someone-handle), Some One Else
    # Another Náme
    # Another Náme (someone-handle)
    # Another Náme (someone-handle), Some One Else
    "attribution": re.compile(
        r"^[^()@]+( \(@?[a-zA-Z0-9._-]+\))?(, [^()@]+( \(@?[a-zA-Z0-9._-]+\))?){0,10}$"
    ),
    # http://www.unicode.org/Public/security/revision-03/confusablesSummary.txt
    # patterns for subset of confusable quotes and dashes which pass
    # isprintable()
    "confusable-utf8": re.compile(r"[“”‟＂‘’‛＇˗‐‒–−‑﹘]"),
}

# Subdirectories of CVEs in config["Locations"]["cve-data"]
cve_reldirs: List[str] = ["active", "retired", "ignored", "templates"]


#
# Utility functions
#
def msg(out: str) -> None:
    """Print message"""
    try:
        print("%s" % (out), file=sys.stdout, flush=True)
    except IOError:  # pragma: nocover
        pass


def warn(out: str) -> None:
    """Print warning message"""
    try:
        print("WARN: %s" % (out), file=sys.stderr, flush=True)
    except IOError:  # pragma: nocover
        pass


def error(out: str, exitCode: int = 1, do_exit: bool = True) -> None:
    """Print error message"""
    try:
        print("ERROR: %s" % (out), file=sys.stderr, flush=True)
    except IOError:  # pragma: nocover
        pass

    if do_exit:  # pragma: nocover
        sys.exit(exitCode)


def recursive_rm(dirPath: str, contents_only: bool = False, top: bool = True) -> None:
    """Recursively remove directory"""
    if top:
        os.chmod(dirPath, 0o0755)  # ensure the top dir is always removable

    try:
        names: List[str] = os.listdir(dirPath)
    except PermissionError:
        # If directory has weird permissions (eg, 000), just try to remove the
        # directory if we can. If it is non-empty, we'll legitimately fail
        # here. This allows us to remove empty directories with weird
        # permissions.
        os.rmdir(dirPath)
        return

    for name in names:
        path: str = os.path.join(dirPath, name)
        if os.path.islink(path) or not os.path.isdir(path):
            os.unlink(path)
        else:
            try:
                recursive_rm(path, top=False)
            except PermissionError:
                os.chmod(path, 0o0755)  # LP: #1712476
                recursive_rm(path, top=False)

    if contents_only is False:
        os.rmdir(dirPath)


# Simple progress bar with no external dependencies besides sys. Based on:
# https://stackoverflow.com/a/15860757
def updateProgress(
    progress: Union[float, int], barLength: int = 0, prefix: str = ""
) -> None:
    """Display/update console progress bar
    - progress: float between 0 and 1 (ints converted to float). < 0
      or > 0 stops progress (for descending or acsending)
    - barLength: 0 for auto or > 0 specific bar length
    - prefix: what to display before the bar. With barLength=0 (auto)
      the barLength is calculated (roughly) as 'termwidth - len(prefix)
    """
    status: str = ""
    if isinstance(progress, int):
        progress = float(progress)

    if progress < 0:  # descending done
        progress = 0
        status = "\n"
    elif progress >= 1:  # ascending done
        progress = 1
        status = "\n"

    if barLength == 0:
        max: int = 75
        cur: int = shutil.get_terminal_size((max, 20))[0]  # define fallback
        tw: int = max if cur > max else cur
        # make sure prefix isn't too big for the window size (use 'pad * 2'
        # as a convenience for leaving room for the bar and status)
        pad: int = 10
        if len(prefix) > tw - pad * 2:
            if (sys.stdout.isatty() and "TEST_UPDATE_PROGRESS" not in os.environ) or (
                "TEST_UPDATE_PROGRESS" in os.environ
                and os.environ["TEST_UPDATE_PROGRESS"] != "0"
            ):
                print("%s...\r" % prefix[: max - 8], end="")
            return
        barLength = tw - len(prefix) - pad

    block: int = int(round(barLength * progress))
    bar: str = "[{0}] {1}% {2}".format(
        "#" * block + "-" * (barLength - block), int(progress * 100), status
    )
    if (sys.stdout.isatty() and "TEST_UPDATE_PROGRESS" not in os.environ) or (
        "TEST_UPDATE_PROGRESS" in os.environ
        and os.environ["TEST_UPDATE_PROGRESS"] != "0"
    ):
        print("%s%s\r" % (prefix, bar), end="")


def epochToISO8601(since: int) -> str:
    """Convert epoch seconds to ISO 8601 YYYY-MM-DDTHH:MM:SSZ"""
    if not isinstance(since, int) or since < 0:
        raise ValueError
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since))


def readFile(fn: str) -> Optional[Set[str]]:
    """Read lines from file"""
    # Use a relative filename for warnings and errors
    rel_fn: str = os.path.basename(fn)
    parent: str = os.path.basename(os.path.dirname(fn))
    if parent in cve_reldirs:
        rel_fn = "%s/%s" % (parent, rel_fn)

    if not os.path.isfile(fn):
        error("'%s' is not a regular file" % rel_fn)
        return None

    # Encode to to utf-8 since we might want to do isprintable() checks
    # elsewhere
    with open(fn, "r", encoding="utf-8", errors="backslashreplace") as fp:
        return copy.deepcopy(set(fp.read().splitlines()))


def readCve(fn: str) -> Dict[str, str]:
    """Read raw CVE data from file"""
    # Read in the data, but let callers do any specific formatting
    d: Dict[str, str] = {}

    # Use a relative filename for warnings
    rel_fn: str = os.path.basename(fn)
    parent: str = os.path.basename(os.path.dirname(fn))
    if parent in cve_reldirs:
        rel_fn = "%s/%s" % (parent, rel_fn)

    # Encode to to utf-8 since we do isprintable() checks elsewhere
    with open(fn, "r", encoding="utf-8", errors="backslashreplace") as fp:
        policy: Compat32 = Compat32()

        # Obtain the header content
        headers: Message = Parser(policy=policy).parse(fp)
        for k in headers:
            if k in d:
                warn("duplicate key '%s' in %s" % (k, rel_fn))
            d[k] = headers[k]

        # Obtain the header content for any other stanzas (stanzas are
        # separated by newlines so we need to grab the stanza'a headers from
        # the payload in a loop.
        last: Optional[str] = None
        while True:
            s: str = headers.get_payload()
            if s == last:
                break
            last = s
            headers: Message = HeaderParser(policy=policy).parsestr(s)
            for k in headers:
                if k in d:
                    warn("duplicate key '%s' in %s" % (k, rel_fn))
                d[k] = headers[k]

    return copy.deepcopy(d)


def setCveHeader(headers: Message, key: str, val: Optional[str]) -> None:
    """Set header for CVE"""
    if val is None:
        headers.__delitem__(key)  # no exception if missing
    elif key in headers:
        headers.replace_header(key, val)
    else:
        headers.add_header(key, val)


def getConfigFilePath() -> str:
    """Return the path to sedg.conf"""
    if "XDG_CONFIG_HOME" in os.environ:
        return os.path.expandvars("$XDG_CONFIG_HOME/sedg/sedg.conf")
    return os.path.expandvars("$HOME/.config/sedg/sedg.conf")


def readConfig() -> Tuple[configparser.ConfigParser, str]:
    """Read configuration for the tools"""
    global configCache
    configFilePath: str = getConfigFilePath()
    config: configparser.ConfigParser

    if configCache is not None:
        config = configCache
    else:
        config = configparser.ConfigParser()
        if os.path.exists(configFilePath):
            config.read(configFilePath)
        else:
            parent: str = os.path.dirname(configFilePath)
            grandparent: str = os.path.dirname(parent)
            if not os.path.isdir(grandparent):
                os.mkdir(grandparent, 0o0700)
            if not os.path.isdir(parent):
                os.mkdir(parent, 0o0700)
            config["Locations"] = {
                "cve-data": "/set/to/path/for/sedg-cve-data",
            }
            config["Behavior"] = {
                "compat-ubuntu": "no",
            }
            orig: int = os.umask(0o027)
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                config.write(f)
                f.flush()
                shutil.copyfile(f.name, configFilePath, follow_symlinks=False)
                os.unlink(f.name)
                os.umask(orig)
            msg("Created default config in %s" % configFilePath)

        configCache = config

    return (config, configFilePath)


def getConfigCveDataPaths() -> Dict[str, str]:
    """Find the configured CVE data directories"""
    config: configparser.ConfigParser
    configFilePath: str
    top: Optional[str] = None

    (config, configFilePath) = readConfig()
    if "Locations" in config and "cve-data" in config["Locations"]:
        path: str = config["Locations"]["cve-data"]
        if not os.path.isdir(path):
            error(
                "Please configure %s to\nset 'cve-data' in "
                "'[Locations]' to a valid path" % configFilePath
            )
            return {}  # needed by pyright since it doesn't know error() exits

        top = config["Locations"]["cve-data"]
    else:
        error(
            "Please configure %s to\nset 'cve-data' in '[Locations]'" % configFilePath
        )
        return {}  # needed by pyright since it doesn't know error() exits

    cveDirs: Dict[str, str] = {}
    for d in cve_reldirs:
        tmp: str = os.path.join(top, d)
        if not os.path.isdir(tmp):
            error("Could not find '%s' in '%s'" % (d, top))
            return {}  # needed by pyright since it doesn't know error() exits
        cveDirs[d] = tmp

    return cveDirs


def getConfigCompatUbuntu() -> bool:
    """Read Ubuntu compat configuration from config"""
    config: configparser.ConfigParser
    (config, _) = readConfig()
    if "Behavior" in config and "compat-ubuntu" in config["Behavior"]:
        if config["Behavior"]["compat-ubuntu"].lower() == "yes":
            return True

        if config["Behavior"]["compat-ubuntu"].lower() not in ["yes", "no"]:
            warn("'compat-ubuntu' in '[Behavior]' should be 'yes' or 'no'")
    return False


def verifyDate(
    key: str, date: str, required: bool = False, compatUbuntu: Optional[bool] = False
) -> Optional[datetime.date]:
    """Verify a date"""
    unspecified: str = ""
    if not required:
        unspecified = "empty or "
        if compatUbuntu:
            unspecified = "'unknown' or "

    err: str = "invalid %s: '%s' (use %sYYYY-MM-DD [HH:MM:SS [TIMEZONE]])" % (
        key,
        date,
        unspecified,
    )

    dObj: Optional[datetime.date] = None
    # quick and dirty
    if not rePatterns["date-full"].search(date):
        raise CveException(err)

    # Use datetime.datetime.strptime to avoid external dependencies
    if rePatterns["date-only"].search(date):
        try:
            dObj = datetime.datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            raise CveException(err)
    if rePatterns["date-time"].search(date):
        try:
            dObj = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            raise CveException(err)
    if rePatterns["date-full-offset"].search(date):
        try:
            dObj = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %z")
        except ValueError:
            raise CveException(err)
    if rePatterns["date-full-tz"].search(date):
        try:
            # Unfortunately, %Z doesn't work reliably, so just strip it off
            # https://bugs.python.org/issue22377
            # datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %Z")
            dObj = datetime.datetime.strptime(
                " ".join(date.split()[:-1]), "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:  # pragma: nocover
            raise CveException(err)

    return dObj


#
# Utility classes
#
class CveException(Exception):
    """This class represents CVE exceptions"""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value
