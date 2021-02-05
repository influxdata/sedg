#!/usr/bin/env python3

import re
import sys

# The CVE file format follows RFC6532 (UTF-8 of RFC5322)
from email.parser import BytesHeaderParser

# TODO: we want RFC6532
from email.policy import default


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


def readCveHeaders(fn):
    """Read CVE data from file"""
    with open(fn, "rb") as fp:
        return BytesHeaderParser(policy=default).parse(fp)


# Compile common regex on import
rePatterns = {
    # CVE-YYYY-XXXX (1-12 X's)
    # CVE-YYYY-NNNX (1-11 N's)
    # CVE-YYYY-GHXXXX#AAAA (1-12 X's, 1-40 A's)
    "CVE": re.compile(r"^CVE-[0-9]{4}-([0-9N]{3,11}[0-9]|GH[0-9]{1,12}#[a-z0-9+.-]{1,40})$"),
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
}


#
# Utility classes
#
class CveException(Exception):
    """This class represents CVE exceptions"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
