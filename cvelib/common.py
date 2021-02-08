#!/usr/bin/env python3

import configparser
import os
import re
import shutil
import sys
import tempfile

# The CVE file format follows RFC6532 (UTF-8 of RFC5322)
from email.parser import BytesHeaderParser

# TODO: we want RFC6532
from email.policy import default


# Compile common regex on import
rePatterns = {
    # CVE-YYYY-XXXX (1-12 X's)
    # CVE-YYYY-NNNX (1-11 N's)
    # CVE-YYYY-GHXXXX#AAAA (1-12 X's, 1-40 A's)
    "CVE": re.compile(
        r"^CVE-[0-9]{4}-([0-9N]{3,11}[0-9]|GH[0-9]{1,12}#[a-z0-9+.-]{1,40})$"
    ),
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
}


#
# Utility functions
#
def msg(out, output=sys.stdout):
    """Print message"""
    try:
        print("%s" % (out), file=output)
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


def readCveHeaders(fn):
    """Read CVE data from file"""
    with open(fn, "rb") as fp:
        return BytesHeaderParser(policy=default).parse(fp)


def getConfigFilePath():
    """Return the path to influx-security-tools.conf"""
    if "XDG_CONFIG_HOME" in os.environ:
        return os.path.expandvars("$XDG_CONFIG_HOME/influx-security-tools.conf")
    return os.path.expandvars("$HOME/.config/influx-security-tools.conf")


def readConfig():
    """Read configuration for the tools"""
    config = configparser.ConfigParser()
    configFilePath = getConfigFilePath()
    if os.path.exists(configFilePath):
        config.read(configFilePath)
    else:
        parent = os.path.dirname(configFilePath)
        if not os.path.isdir(parent):
            os.mkdir(parent, 0o0700)
        config["Locations"] = {
            "cve-data": "/set/to/path/for/influx-security-tools-cve-data",
        }
        orig = os.umask(0o027)
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            config.write(f)
            f.flush()
            shutil.copyfile(f.name, configFilePath, follow_symlinks=False)
            os.unlink(f.name)
            os.umask(orig)
        msg("Created default config in %s" % configFilePath)

    return (config, configFilePath)


def getConfigCveDataPath():
    (config, configFilePath) = readConfig()
    if "Locations" in config and "cve-data" in config["Locations"]:
        path = config["Locations"]["cve-data"]
        if not os.path.isdir(path):
            error(
                "Please configure %s to\nset 'cve-data' in "
                "'[Locations]' to a valid path" % configFilePath
            )

        return config["Locations"]["cve-data"]


#
# Utility classes
#
class CveException(Exception):
    """This class represents CVE exceptions"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
