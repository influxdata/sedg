#!/usr/bin/env python3

import configparser
import copy
import os
import re
import shutil
import sys
import tempfile

from email.parser import HeaderParser, Parser
from email.policy import Compat32

# cache of config
configCache = None

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
# Compile common regex on import
rePatterns = {
    # foo, foo1, foo-bar, foo.bar, for-bar-1.0
    "pkg-software": re.compile(r"^[a-z0-9+.-]{1,40}$"),
    # we can do 'ubuntu', 'suse', 'debian', etc for this for other distros
    "pkg-product": re.compile(r"^(git|snap|oci|upstream|ubuntu|debian|suse)$"),
    "pkg-product-ubuntu": re.compile(r"^[a-z0-9+.-]{1,40}$"),
    "pkg-status": re.compile(
        r"^(needs-triage|needed|pending|released|deferred|ignored|DNE|not-affected)$"
    ),
    # free form text
    "pkg-when": re.compile(r"^[a-zA-Z0-9 +.,/'\":~\[\]_()<>#=|`-]{1,80}$"),
    # the string form
    "pkg-full": re.compile(
        r"^(git|snap|oci|upstream|ubuntu|debian|suse)(/[a-z0-9+.-]{1,40})?_[a-z0-9+.-]{1,40}(/[a-z0-9+.-]{1,40})?: (needs-triage|needed|pending|released|deferred|ignored|DNE|not-affected)( \([a-zA-Z0-9 +.,/'\":~\[\]_()<>#=|`-]{1,80}\))?$"
    ),
    "pkg-full-ubuntu": re.compile(
        r"^[a-z0-9+.-]{1,40}(/[a-z0-9+.-]{1,40})?_[a-z0-9+.-]{1,40}(/[a-z0-9+.-]{1,40})?: (needs-triage|needed|pending|released|deferred|ignored|DNE|not-affected)( \([a-zA-Z0-9 +.,'\"/:~\[\]()<>#=|`_-]{1,80}\))?$"
    ),
    # CVE-YYYY-XXXX (1-12 X's)
    # CVE-YYYY-NNNX (1-11 N's)
    # CVE-YYYY-GHXXXX#AAAA (1-12 X's, 1-40 A's)
    "CVE": re.compile(
        r"^CVE-[0-9]{4}-([0-9N]{3,11}[0-9]|GH[0-9]{1,12}#[a-z0-9+.-]{1,40})$"
    ),
    # CVE priorities
    "priorities": re.compile(r"^(negligible|low|medium|high|critical)$"),
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
        r"^https://github.com/[a-z0-9+.-]{1,40}/[a-z0-9+.-]{1,40}/issues/[0-9]{1,12}"
    ),
    # upstream: something
    # vendor: something
    # debdiff: something
    # other: something
    # break-fix: - -
    # break-fix: - hash
    # break-fix: hash -
    # break-fix: hash hash|local-*
    # break-fix: local-*-break local-*-fix
    "pkg-patch": re.compile(
        r"^((upstream|debdiff|vendor|other): [a-z0-9+.-].*|break-fix: +((-|[0-9a-f]+) +(-|[0-9a-f]+)|(-|[0-9a-f|]+|([0-9a-f|]+)?local[a-zA-X0-9|-]+)? +(-|[0-9a-f|]+|([0-9a-f|]+)?local[a-zA-X0-9|-]+))$)"
    ),
    "pkg-patch-key": re.compile(r"^Patches_[a-z0-9+.-]{1,40}$"),
    # TODO: break out Ubuntu-specific tags
    "pkg-tags": re.compile(
        r"^(apparmor|stack-protector|fortify-source|symlink-restriction|hardlink-restriction|heap-protector|pie|universe-binary|not-ue)$"
    ),
    "pkg-tags-key": re.compile(r"^Patches_[a-z0-9+.-]{1,40}(_[a-z0-9+.-]{1,40})?$"),
    # urls
    "url-schemes": re.compile(r"^(cvs|ftp|git|https?|sftp|shttp|svn)://."),
    # People. We aren't accepting utf-8 elsewhere so only ascii here
    # Some One
    # Some One (someone-handle)
    # Some One (someone-handle), Some One Else
    # Some "Nickname" One (someone-handle), Some One Else
    "attribution": re.compile(
        r"^[a-zA-Z0-9'\"_ .-]+( \(@?[a-zA-Z0-9._-]+\))?(, [a-zA-Z0-9'\"_ .-]+( \(@?[a-zA-Z0-9._-]+\))?)*$"
    ),
}

# Subdirectories of CVEs in config["Locations"]["cve-data"]
cve_reldirs = ["active", "retired", "ignored"]


#
# Utility functions
#
def msg(out):
    """Print message"""
    try:
        print("%s" % (out), file=sys.stdout)
    except IOError:  # pragma: nocover
        pass


def warn(out):
    """Print warning message"""
    try:
        print("WARN: %s" % (out), file=sys.stderr)
    except IOError:  # pragma: nocover
        pass


def error(out, exitCode=1, do_exit=True):
    """Print error message"""
    try:
        print("ERROR: %s" % (out), file=sys.stderr)
    except IOError:  # pragma: nocover
        pass

    if do_exit:  # pragma: nocover
        sys.exit(exitCode)


def recursive_rm(dirPath, contents_only=False, top=True):
    """recursively remove directory"""
    if top:
        os.chmod(dirPath, 0o0755)  # ensure the top dir is always removable

    try:
        names = os.listdir(dirPath)
    except PermissionError:
        # If directory has weird permissions (eg, 000), just try to remove the
        # directory if we can. If it is non-empty, we'll legitimately fail
        # here. This allows us to remove empty directories with weird
        # permissions.
        os.rmdir(dirPath)
        return

    for name in names:
        path = os.path.join(dirPath, name)
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


def readCve(fn):
    """Read raw CVE data from file"""
    # Read in the data, but let callers do any specific formatting
    d = {}

    # Use a relative filename for warnings
    rel_fn = os.path.basename(fn)
    parent = os.path.basename(os.path.dirname(fn))
    if parent in cve_reldirs:
        rel_fn = "%s/%s" % (parent, rel_fn)

    # Always encode to ascii (since we use strip() elsewhere), but don't lose
    # data and escape
    with open(fn, "r", encoding="ascii", errors="backslashreplace") as fp:
        policy = Compat32()

        # Obtain the header content
        headers = Parser(policy=policy).parse(fp)
        for k in headers:
            if k in d:
                warn("duplicate key '%s' in %s" % (k, rel_fn))
            d[k] = headers[k]

        # Obtain the header content for any other stanzas (stanzas are
        # separated by newlines so we need to grab the stanza'a headers from
        # the payload in a loop.
        last = None
        while True:
            s = headers.get_payload()
            if s == last:
                break
            last = s
            headers = HeaderParser(policy=policy).parsestr(s)
            for k in headers:
                if k in d:
                    warn("duplicate key '%s' in %s" % (k, rel_fn))
                d[k] = headers[k]

    return copy.deepcopy(d)


def setCveHeader(headers, key, val):
    """Set header for CVE"""
    if val is None:
        headers.__delitem__(key)  # no exception if missing
    elif key in headers:
        headers.replace_header(key, val)
    else:
        headers.add_header(key, val)


def getConfigFilePath():
    """Return the path to influx-security-tools.conf"""
    if "XDG_CONFIG_HOME" in os.environ:
        return os.path.expandvars("$XDG_CONFIG_HOME/influx-security-tools.conf")
    return os.path.expandvars("$HOME/.config/influx-security-tools.conf")


def readConfig():
    """Read configuration for the tools"""
    global configCache
    configFilePath = getConfigFilePath()
    if configCache is not None:
        config = configCache
    else:
        config = configparser.ConfigParser()
        if os.path.exists(configFilePath):
            config.read(configFilePath)
        else:
            parent = os.path.dirname(configFilePath)
            if not os.path.isdir(parent):
                os.mkdir(parent, 0o0700)
            config["Locations"] = {
                "cve-data": "/set/to/path/for/influx-security-tools-cve-data",
            }
            config["Behavior"] = {
                "compat-ubuntu": "no",
            }
            orig = os.umask(0o027)
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                config.write(f)
                f.flush()
                shutil.copyfile(f.name, configFilePath, follow_symlinks=False)
                os.unlink(f.name)
                os.umask(orig)
            msg("Created default config in %s" % configFilePath)

        configCache = config

    return (config, configFilePath)


def getConfigCveDataPaths():
    (config, configFilePath) = readConfig()
    top = None
    if "Locations" in config and "cve-data" in config["Locations"]:
        path = config["Locations"]["cve-data"]
        if not os.path.isdir(path):
            error(
                "Please configure %s to\nset 'cve-data' in "
                "'[Locations]' to a valid path" % configFilePath
            )

        top = config["Locations"]["cve-data"]
    else:
        error(
            "Please configure %s to\nset 'cve-data' in '[Locations]'" % configFilePath
        )

    cveDirs = {}
    for d in cve_reldirs:
        tmp = os.path.join(top, d)
        if not os.path.isdir(top):
            error("Could not find '%s' in '%s'" % (d, top))
        cveDirs[d] = tmp

    return cveDirs


def getConfigCompatUbuntu():
    (config, configFilePath) = readConfig()
    if "Behavior" in config and "compat-ubuntu" in config["Behavior"]:
        if config["Behavior"]["compat-ubuntu"].lower() == "yes":
            return True

        if config["Behavior"]["compat-ubuntu"].lower() not in ["yes", "no"]:
            warn("'compat-ubuntu' in '[Behavior]' should be 'yes' or 'no'")
    return False


#
# Utility classes
#
class CveException(Exception):
    """This class represents CVE exceptions"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
