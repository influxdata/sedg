#!/usr/bin/env python3

import datetime
import re
import sys

# The CVE file format follows RFC6532 (UTF-8 of RFC5322)
from email.message import EmailMessage
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
    except IOError:
        pass


def warn(out):
    """Print warning message"""
    try:
        print("WARN: %s" % (out), file=sys.stderr)
    except IOError:
        pass


def error(out, exitCode=1, do_exit=True):
    """Print error message"""
    try:
        print("ERROR: %s" % (out), file=sys.stderr)
    except IOError:
        pass

    if do_exit:
        sys.exit(exitCode)


def readCveHeaders(fn):
    """Read CVE data from file"""
    with open(fn, "rb") as fp:
        return BytesHeaderParser(policy=default).parse(fp)


# Compile common regex on import
pats = {
    # CVE-YYYY-XXXX, CVE-YYYY-NNNX or longer
    "CVE": re.compile(r"^CVE-[0-9]{4}-[0-9N]{3}[0-9N]*[0-9]+$"),
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


class CVE(object):
    cve_required = [
        "Candidate",
        "PublicDate",
        "References",
        "Description",
        "Notes",
        "Mitigation",
        "Bugs",
        "Priority",
        "Discovered-by",
        "Assigned-to",
        "CVSS",
    ]
    cve_optional = [
        "CRD",
    ]
    priorities = set(
        [
            "negligible",
            "low",
            "medium",
            "high",
            "critical",
        ]
    )

    def __str__(self):
        s = []
        # XXX
        for key in self.headers:
            s.append("  %s=%s" % (key, self.headers[key]))
        return self.candidate + "\n" + "\n".join(s)

    def __repr__(self):
        return self.__str__()

    def __init__(self, fn=None):
        # XXX
        if fn is None:
            return

        headers = readCveHeaders(fn)
        self.verifyCve(headers)

        # members
        self.candidate = headers["Candidate"]
        self.publicDate = headers["PublicDate"]
        self.references = headers["References"]
        self.description = headers["Description"]
        self.notes = headers["Notes"]
        self.mitigation = headers["Mitigation"]
        self.bugs = headers["Bugs"]
        self.priority = headers["Priority"]
        self.discoveredBy = headers["Discovered-by"]
        self.assignedTo = headers["Assigned-to"]
        self.cvss = headers["CVSS"]
        self.headers = {}  # convert to common dict()
        for field in headers:
            self.headers[field] = headers[field]

    def _isPresent(self, headers, key, canBeEmpty=False):
        """Ensure headers has key"""
        if not isinstance(headers, EmailMessage):
            raise CveException("headers not of type 'EmailMessage'")
        if key not in headers:
            raise CveException("missing field '%s'" % key)
        if not canBeEmpty and headers[key] == "":
            raise CveException("empty field '%s'" % key)

    # TODO: use schema/templates
    def verifyCve(self, headers):
        """Verify the CVE"""
        self._verifyRequired(headers)
        self._verifyCandidate(headers)
        self._verifyPublicDate(headers)
        self._verifyPriority(headers)

        # optional
        if "CRD" in headers:
            self._verifyCRD(headers)

    def _verifyRequired(self, headers):
        """Verify have all required fields"""
        for field in self.cve_required:
            if field not in headers:
                raise CveException("missing required field '%s'" % field)

    def _verifyCandidate(self, headers):
        """Verify CVE candidate number"""
        key = "Candidate"
        self._isPresent(headers, key)
        val = headers[key]
        if not pats["CVE"].search(val):
            raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyDate(self, key, date):
        """Verify a date"""
        err = "invalid %s: '%s' (use empty, YYYY-MM-DD [HH:MM:SS [TIMEZONE]]" % (
            key,
            date,
        )
        # quick and dirty
        if not pats["date-full"].search(date):
            raise CveException(err)

        # Use datetime.datetime.strptime to avoid external dependencies
        if pats["date-only"].search(date):
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                raise CveException(err)
        if pats["date-time"].search(date):
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                raise CveException(err)
        if pats["date-full-offset"].search(date):
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %z")
            except ValueError:
                raise CveException(err)
        if pats["date-full-tz"].search(date):
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %Z")
            except ValueError:
                raise CveException(err)

    def _verifyPublicDate(self, headers):
        """Verify CVE public date"""
        key = "PublicDate"
        self._isPresent(headers, key, canBeEmpty=True)
        val = headers[key]
        if val != "":  # empty is ok
            self._verifyDate(key, val)

    def _verifyCRD(self, headers):
        """Verify CVE CRD"""
        key = "CRD"
        self._isPresent(headers, key, canBeEmpty=True)
        val = headers[key]
        if val != "":  # empty is ok
            self._verifyDate(key, val)

    def _verifyPriority(self, headers):
        """Verify CVE Priority"""
        for key in headers:
            val = headers[key]
            if key == "Priority" or key.startswith("Priority_"):
                if val not in self.priorities:
                    raise CveException("invalid %s: '%s'" % (key, val))
