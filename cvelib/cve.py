#!/usr/bin/env python3

import datetime

from cvelib.common import CveException, rePatterns
import cvelib.common
from cvelib.pkg import CvePkg


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
        for key in self.data:
            s.append("  %s=%s" % (key, self.data[key]))
        return self.candidate + "\n" + "\n".join(s)

    def __repr__(self):
        return self.__str__()

    def onDiskFormat(self):
        """Return format suitable for writing out to disk"""
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

        for pkg in self.pkgs:
            s += "\nPatches_%s:\n" % pkg.software
            s += "%s\n" % pkg

        return s

    def __init__(self, fn=None, untriagedOk=False):
        # XXX
        self.data = {}
        self.pkgs = []
        if fn is None:
            return

        data = cvelib.common.readCve(fn)
        self._setFromData(data, untriagedOk=untriagedOk)

    # set methods
    def _setFromData(self, data, untriagedOk=False):
        """Set members from data"""
        self._verifyCve(data, untriagedOk=untriagedOk)
        # members
        self.setCandidate(data["Candidate"])
        self.setPublicDate(data["PublicDate"])
        self.setReferences(data["References"])
        self.setDescription(data["Description"])
        self.setNotes(data["Notes"])
        self.setMitigation(data["Mitigation"])
        self.setBugs(data["Bugs"])
        self.setPriority(data["Priority"])
        self.setDiscoveredBy(data["Discovered-by"])
        self.setAssignedTo(data["Assigned-to"])
        self.setCVSS(data["CVSS"])

        if "CRD" in data:
            self.setCRD(data["CRD"])
        else:
            self.setCRD("")

        for field in data:  # convert to common dict()
            self.data[field] = data[field]

    def setCandidate(self, s):
        """Set candidate"""
        self._verifyCandidate("Candidate", s)
        self.candidate = s
        self.data["Candidate"] = self.candidate

    def setPublicDate(self, s):
        """Set PublicDate"""
        self._verifyPublicDate("PublicDate", s)
        self.publicDate = s
        self.data["PublicDate"] = self.publicDate

    def setCRD(self, s):
        """Set CRD"""
        self._verifyCRD("CRD", s)
        self.crd = s
        self.data["CRD"] = self.crd

    def setReferences(self, s):
        """Set References"""
        self.references = s.splitlines()
        self.data["References"] = self.references

    def setDescription(self, s):
        """Set Description"""
        self.description = s.splitlines()
        self.data["Description"] = self.description

    def setNotes(self, s):
        """Set Notes"""
        self.notes = s.splitlines()
        self.data["Notes"] = self.notes

    def setMitigation(self, s):
        """Set Mitigation"""
        self.mitigation = s
        self.data["Mitigation"] = self.mitigation

    def setBugs(self, s):
        """Set Bugs"""
        self.bugs = s.splitlines()
        self.data["Bugs"] = self.bugs

    def setPriority(self, s):
        """Set Priority"""
        self._verifyPriority("Priority", s, untriagedOk=True)
        self.priority = s
        self.data["Priority"] = self.priority

    def setDiscoveredBy(self, s):
        """Set Discovered-by"""
        self.discoveredBy = s
        self.data["Discovered-by"] = self.discoveredBy

    def setAssignedTo(self, s):
        """Set Assigned-to"""
        self.assignedTo = s
        self.data["Assigned-to"] = self.assignedTo

    def setCVSS(self, s):
        """Set CVSS"""
        self.cvss = s
        self.data["CVSS"] = self.cvss

    def setPackages(self, pkgs):
        """Set pkgs"""
        if not isinstance(pkgs, list):
            raise CveException("pkgs is not a list")
        for p in pkgs:
            if not isinstance(p, CvePkg):
                raise CveException("package is not of type cvelib.pkg.CvePkg")
            self.pkgs.append(p)

    def _isPresent(self, data, key, canBeEmpty=False):
        """Ensure data has key"""
        if not isinstance(data, dict):
            raise CveException("data not of type dict")
        if key not in data:
            raise CveException("missing field '%s'" % key)

    # TODO: use schema/templates
    def _verifyCve(self, data, untriagedOk=False):
        """Verify the CVE"""
        self._verifyRequired(data)

        for key in self.cve_required:
            self._isPresent(data, key)
            val = data[key]
            if key == "Candidate":
                self._verifyCandidate(key, val)
            elif key == "PublicDate":
                self._verifyPublicDate(key, val)
            elif key == "Priority":
                self._verifyPriority(key, val, untriagedOk=untriagedOk)

        # optional
        for key in self.cve_optional:
            if key not in data:
                continue
            val = data[key]
            if key == "CRD":
                self._verifyCRD(key, val)

        # namespaced keys
        for key in data:
            val = data[key]
            if key.startswith("Priority_"):
                self._verifyPriority(key, val)

    def _verifyRequired(self, data):
        """Verify have all required fields"""
        for field in self.cve_required:
            if field not in data:
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
