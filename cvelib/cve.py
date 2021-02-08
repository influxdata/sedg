#!/usr/bin/env python3

import datetime

# The CVE file format follows RFC6532 (UTF-8 of RFC5322)
from email.message import EmailMessage

from cvelib.common import CveException, rePatterns
import cvelib.common


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

    def __str__(self):
        s = []
        for key in self.headers:
            s.append("  %s=%s" % (key, self.headers[key]))
        return self.candidate + "\n" + "\n".join(s)

    def __repr__(self):
        return self.__str__()

    def onDiskFormat(self):
        s = """Candidate:%(candidate)s
PublicDate:%(publicDate)s
CRD:%(crd)s
References:%(references)s
Description:%(description)s
Notes:%(notes)s
Mitigation:%(mitigation)s
Bugs:%(bugs)s
Priority:%(priority)s
Discovered-by:%(discoveredBy)s
Assigned-to:%(assignedTo)s
CVSS:%(cvss)s
""" % (
            {
                "candidate": " %s" % self.candidate if self.candidate else "",
                "publicDate": " %s" % self.publicDate if self.publicDate else "",
                "crd": " %s" % self.crd if self.crd else "",
                "references": "\n %s" % "\n ".join(self.references)
                if self.references
                else "",
                "description": "\n %s" % "\n ".join(self.description)
                if self.description
                else "",
                "notes": "\n %s" % "\n ".join(self.notes) if self.notes else "",
                "mitigation": " %s" % self.mitigation if self.mitigation else "",
                "bugs": "\n %s" % "\n ".join(self.bugs) if self.bugs else "",
                "priority": " %s" % self.priority if self.priority else "",
                "discoveredBy": " %s" % self.discoveredBy if self.discoveredBy else "",
                "assignedTo": " %s" % self.assignedTo if self.assignedTo else "",
                "cvss": " %s" % self.cvss if self.cvss else "",
            }
        )
        return s

    def __init__(self, fn=None, untriagedOk=False):
        # XXX
        self.headers = {}
        if fn is None:
            return

        headers = cvelib.common.readCveHeaders(fn)
        self._setFromHeaders(headers, untriagedOk=untriagedOk)

    # set methods
    def _setFromHeaders(self, headers, untriagedOk=False):
        """Set members from headers"""
        self._verifyCve(headers, untriagedOk=untriagedOk)
        # members
        self.setCandidate(headers["Candidate"])
        self.setPublicDate(headers["PublicDate"])
        self.setReferences(headers["References"])
        self.setDescription(headers["Description"])
        self.setNotes(headers["Notes"])
        self.setMitigation(headers["Mitigation"])
        self.setBugs(headers["Bugs"])
        self.setPriority(headers["Priority"])
        self.setDiscoveredBy(headers["Discovered-by"])
        self.setAssignedTo(headers["Assigned-to"])
        self.setCVSS(headers["CVSS"])

        if "CRD" in headers:
            self.setCRD(headers["CRD"])
        else:
            self.setCRD("")

        for field in headers:  # convert to common dict()
            self.headers[field] = headers[field]

    def setCandidate(self, s):
        """Set candidate"""
        self._verifyCandidate("Candidate", s)
        self.candidate = s
        self.headers["Candidate"] = self.candidate

    def setPublicDate(self, s):
        """Set PublicDate"""
        self._verifyPublicDate("PublicDate", s)
        self.publicDate = s
        self.headers["PublicDate"] = self.publicDate

    def setCRD(self, s):
        """Set CRD"""
        self._verifyCRD("CRD", s)
        self.crd = s
        self.headers["CRD"] = self.crd

    def setReferences(self, s):
        """Set References"""
        self.references = s.splitlines()
        self.headers["References"] = self.references

    def setDescription(self, s):
        """Set Description"""
        self.description = s.splitlines()
        self.headers["Description"] = self.description

    def setNotes(self, s):
        """Set Notes"""
        self.notes = s.splitlines()
        self.headers["Notes"] = self.notes

    def setMitigation(self, s):
        """Set Mitigation"""
        self.mitigation = s
        self.headers["Mitigation"] = self.mitigation

    def setBugs(self, s):
        """Set Bugs"""
        self.bugs = s.splitlines()
        self.headers["Bugs"] = self.bugs

    def setPriority(self, s):
        """Set Priority"""
        self._verifyPriority("Priority", s, untriagedOk=True)
        self.priority = s
        self.headers["Priority"] = self.priority

    def setDiscoveredBy(self, s):
        """Set Discovered-by"""
        self.discoveredBy = s
        self.headers["Discovered-by"] = self.discoveredBy

    def setAssignedTo(self, s):
        """Set Assigned-to"""
        self.assignedTo = s
        self.headers["Assigned-to"] = self.assignedTo

    def setCVSS(self, s):
        """Set CVSS"""
        self.cvss = s
        self.headers["CVSS"] = self.cvss

    def _isPresent(self, headers, key, canBeEmpty=False):
        """Ensure headers has key"""
        if not isinstance(headers, EmailMessage):
            raise CveException("headers not of type 'EmailMessage'")
        if key not in headers:
            raise CveException("missing field '%s'" % key)

    # TODO: use schema/templates
    def _verifyCve(self, headers, untriagedOk=False):
        """Verify the CVE"""
        self._verifyRequired(headers)

        for key in self.cve_required:
            self._isPresent(headers, key)
            val = headers[key]
            if key == "Candidate":
                self._verifyCandidate(key, val)
            elif key == "PublicDate":
                self._verifyPublicDate(key, val)
            elif key == "Priority":
                self._verifyPriority(key, val, untriagedOk=untriagedOk)

        # optional
        for key in self.cve_optional:
            if key not in headers:
                continue
            val = headers[key]
            if key == "CRD":
                self._verifyCRD(key, val)

        # namespaced keys
        for key in headers:
            val = headers[key]
            if key.startswith("Priority_"):
                self._verifyPriority(key, val)

    def _verifyRequired(self, headers):
        """Verify have all required fields"""
        for field in self.cve_required:
            if field not in headers:
                raise CveException("missing required field '%s'" % field)

    def _verifyCandidate(self, key, val):
        """Verify CVE candidate number"""
        if not rePatterns["CVE"].search(val):
            raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyDate(self, key, date):
        """Verify a date"""
        err = "invalid %s: '%s' (use empty, YYYY-MM-DD [HH:MM:SS [TIMEZONE]]" % (
            key,
            date,
        )
        # quick and dirty
        if not rePatterns["date-full"].search(date):
            raise CveException(err)

        # Use datetime.datetime.strptime to avoid external dependencies
        if rePatterns["date-only"].search(date):
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                raise CveException(err)
        if rePatterns["date-time"].search(date):
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                raise CveException(err)
        if rePatterns["date-full-offset"].search(date):
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %z")
            except ValueError:
                raise CveException(err)
        if rePatterns["date-full-tz"].search(date):
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %Z")
            except ValueError:
                raise CveException(err)

    def _verifyPublicDate(self, key, val):
        """Verify CVE public date"""
        if val != "":  # empty is ok
            self._verifyDate(key, val)

    def _verifyCRD(self, key, val):
        """Verify CVE CRD"""
        if val != "":  # empty is ok
            self._verifyDate(key, val)

    def _verifyPriority(self, key, val, untriagedOk=False):
        """Verify CVE Priority"""
        if untriagedOk and val == "untriaged":
            return
        if not rePatterns["priorities"].search(val):
            raise CveException("invalid %s: '%s'" % (key, val))

    def cveFromUrl(self, url):
        """Return a CVE based on the url"""
        if not url.startswith("https://github.com/"):
            raise CveException("unsupported url: '%s' (only support github)" % url)

        if not rePatterns["github-issue"].match(url):
            raise CveException("invalid url: '%s' (only support github issues)" % url)

        year = datetime.datetime.now().year
        tmp = url.split("/")  # based on rePatterns, we know we have 7 elements
        return "CVE-%s-GH%s#%s" % (year, tmp[6], tmp[4])
