#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import copy
import datetime
import functools
import glob
import hashlib
import os
import re
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple, Union

from cvelib.common import (
    CveException,
    cve_priorities,
    cve_statuses,
    getConfigCveDataPaths,
    getConfigCompatUbuntu,
    error,
    rePatterns,
    readFile,
    verifyDate,
)
import cvelib.common
from cvelib.pkg import CvePkg, parse, cmp_pkgs
import cvelib.github
import cvelib.scan


class CVE(object):
    cve_required: List[str] = [
        "Candidate",
        "OpenDate",
        "CloseDate",
        "PublicDate",
        "References",
        "Description",
        "Notes",
        "Bugs",
        "Priority",
        "Discovered-by",
        "Assigned-to",
        "CVSS",
    ]
    # Tags_*, Patches_* and software are handled special
    cve_optional: List[str] = [
        "CRD",
        "GitHub-Advanced-Security",
        "Scan-Reports",
        "Mitigation",
    ]

    def __str__(self) -> str:
        s: List[str] = []
        for key in self.data:
            s.append("%s=%s" % (key, self.data[key]))
        return "# %s\n%s\n" % (self.candidate, "\n".join(s))

    def __repr__(self) -> str:
        return self.__str__()

    def __init__(
        self,
        fn: Optional[str] = None,
        untriagedOk: bool = False,
        compatUbuntu: bool = False,
    ) -> None:
        # types and defaults
        self.fn: str = ""
        self.candidate: str = ""
        self.openDate: str = ""
        self.closeDate: str = ""
        self.publicDate: str = ""
        self.crd: str = ""
        self.references: List[str] = []
        self.description: List[str] = []
        self.notes: List[str] = []
        self.ghas: List[
            Union[
                cvelib.github.GHDependabot, cvelib.github.GHSecret, cvelib.github.GHCode
            ]
        ] = []

        self.scan_reports: List[cvelib.scan.ScanOCI] = []
        self.mitigation: List[str] = []
        self.bugs: List[str] = []
        self.priority: str = ""
        self.discoveredBy: str = ""
        self.assignedTo: str = ""
        self.cvss: str = ""
        self.pkgs: List[CvePkg] = []

        self.data: Dict[str, Union[str, List[str]]] = {}
        self._pkgs_list: List[str] = []  # what is in self.pkgs

        # set things
        self.compatUbuntu: bool = compatUbuntu
        self.untriagedOk: bool = untriagedOk
        if fn is None:
            return
        self.fn = "%s/%s" % (
            os.path.basename(os.path.dirname(fn)),
            os.path.basename(fn),
        )

        data: Dict[str, str] = cvelib.common.readCve(fn)
        self.setData(data)

    # set methods
    def setData(self, data: Dict[str, str]) -> None:
        """Set members from data"""
        self._verifyCve(data, untriagedOk=self.untriagedOk)
        # members
        self.setCandidate(data["Candidate"])
        self.setOpenDate(data["OpenDate"])
        self.setCloseDate(data["CloseDate"])
        self.setPublicDate(data["PublicDate"])
        self.setReferences(data["References"])
        self.setDescription(data["Description"])
        self.setNotes(data["Notes"])
        self.setBugs(data["Bugs"])
        self.setPriority(data["Priority"])
        self.setDiscoveredBy(data["Discovered-by"])
        self.setAssignedTo(data["Assigned-to"])
        self.setCVSS(data["CVSS"])

        if "CRD" in data:
            self.setCRD(data["CRD"])
        else:
            self.setCRD("")

        if "Mitigation" in data:
            self.setMitigation(data["Mitigation"])
        else:
            self.setMitigation("")

        if "GitHub-Advanced-Security" in data:
            self.setGHAS(data["GitHub-Advanced-Security"])

        if "Scan-Reports" in data:
            self.setScanReports(data["Scan-Reports"])

        # Any field with '_' is a package or patch. Since these could be out of
        # order, collect them separately, then call setPackages()
        pkgs: List[CvePkg] = []
        patches: Dict[str, str] = {}
        tags: Dict[str, str] = {}
        priorities: Dict[str, str] = {}
        closeDates: Dict[str, str] = {}
        for k in data:
            if k not in self.data:  # copy raw data for later
                self.data[k] = data[k]
            if "_" not in k or k.startswith("#"):
                continue
            if k.startswith("Patches_"):
                if self.compatUbuntu:
                    if not rePatterns["pkg-patch-key-ubuntu"].search(k):
                        raise CveException("invalid compat Patches_ key: '%s'" % (k))
                elif not rePatterns["pkg-patch-key"].search(k):
                    raise CveException("invalid Patches_ key: '%s'" % (k))
                pkg = k.split("_")[1]
                patches[pkg] = data[k]
            elif k.startswith("Tags_"):
                if self.compatUbuntu:
                    if not rePatterns["pkg-tags-key-ubuntu"].search(k):
                        raise CveException("invalid compat Tags_ key: '%s'" % (k))
                elif not rePatterns["pkg-tags-key"].search(k):
                    raise CveException("invalid Tags_ key: '%s'" % (k))
                # both Tags_foo and Tags_foo_bar
                pkg = k.split("_", 1)[1]
                tags[pkg] = data[k]
            elif k.startswith("Priority_"):
                if self.compatUbuntu:
                    if not rePatterns["pkg-priority-key-ubuntu"].search(k):
                        raise CveException("invalid compat Priority_ key: '%s'" % (k))
                elif not rePatterns["pkg-priority-key"].search(k):
                    raise CveException("invalid Priority_ key: '%s'" % (k))
                # both Priority_foo and Priority_foo_bar
                pkg = k.split("_", 1)[1]
                priorities[pkg] = data[k]
            elif k.startswith("CloseDate_"):
                self._verifySingleline(k, data[k])
                if not self.compatUbuntu or data[k] != "unknown":
                    verifyDate(k, data[k], compatUbuntu=self.compatUbuntu)
                # both CloseDate_foo and CloseDate_foo_bar
                pkg = k.split("_", 1)[1]
                closeDates[pkg] = data[k]
            else:
                s: str = "%s: %s" % (k, data[k])
                pkgs.append(parse(s, compatUbuntu=self.compatUbuntu))

        self.setPackages(
            pkgs,
            patches=patches,
            tags=tags,
            priorities=priorities,
            closeDates=closeDates,
        )

    def setCandidate(self, s: str) -> None:
        """Set candidate"""
        self._verifyCandidate("Candidate", s)
        self.candidate = s
        self.data["Candidate"] = self.candidate

    def setPublicDate(self, s: str) -> None:
        """Set PublicDate"""
        self._verifyPublicDate("PublicDate", s)
        self.publicDate = s
        self.data["PublicDate"] = self.publicDate

    def setCRD(self, s: str) -> None:
        """Set CRD"""
        self._verifyCRD("CRD", s)
        self.crd = s
        self.data["CRD"] = self.crd

    def setOpenDate(self, s: str) -> None:
        """Set OpenDate"""
        self._verifyOpenDate("OpenDate", s)
        self.openDate = s
        self.data["OpenDate"] = self.openDate

    def setCloseDate(self, s: str) -> None:
        """Set CloseDate"""
        self._verifyCloseDate("CloseDate", s)
        self.closeDate = s
        self.data["CloseDate"] = self.closeDate

    def setReferences(self, s: str) -> None:
        """Set References"""
        self.references = []
        for r in s.splitlines():
            r = r.strip()
            if r != "":
                if r in self.references:
                    raise CveException("duplicate reference '%s'" % r)
                self.references.append(r)
        self.data["References"] = self.references

    def setDescription(self, s: str) -> None:
        """Set Description"""
        # strip newline off the front then strip whitespace from every line
        self.description = [item.strip() for item in s.lstrip().splitlines()]
        self.data["Description"] = self.description

    def setNotes(self, s: str) -> None:
        """Set Notes"""
        # strip newline off the front, strip whitespace off end and then strip
        # one space from the beginning of the line in order to preserve
        # formatting of:
        # Notes:
        #  foo> blah blah blah blah blah blah blah
        #   blah
        self.notes = []
        for line in [item.rstrip() for item in s.lstrip().splitlines()]:
            if line.startswith(" "):
                line = line[1:]
            self.notes.append(line)

        self.data["Notes"] = self.notes

    def setGHAS(self, s: str) -> None:
        """Set GitHub-Advanced-Security"""
        self.ghas = cvelib.github.parse(s)

    def setScanReports(self, s: str) -> None:
        """Set GitHub-Advanced-Security"""
        self.scan_reports = cvelib.scan.parse(s)

    def setMitigation(self, s: str) -> None:
        """Set Mitigation"""
        # strip newline off the front then strip whitespace from every line
        self.mitigation = [item.strip() for item in s.lstrip().splitlines()]
        self.data["Mitigation"] = self.mitigation

    def setBugs(self, s: str) -> None:
        """Set Bugs"""
        self.bugs = []
        for b in s.splitlines():
            b = b.strip()
            if b != "":
                if b in self.bugs:
                    raise CveException("duplicate bug '%s'" % b)
                self.bugs.append(b)
        self.data["Bugs"] = self.bugs

    def setPriority(self, s: str) -> None:
        """Set Priority"""
        self._verifyPriority("Priority", s, untriagedOk=True)
        self.priority = s
        self.data["Priority"] = self.priority

    def setDiscoveredBy(self, s: str) -> None:
        """Set Discovered-by"""
        self.discoveredBy = s
        self.data["Discovered-by"] = self.discoveredBy

    def setAssignedTo(self, s: str) -> None:
        """Set Assigned-to"""
        self.assignedTo = s
        self.data["Assigned-to"] = self.assignedTo

    def setCVSS(self, s: str) -> None:
        """Set CVSS"""
        self.cvss = s
        self.data["CVSS"] = self.cvss

    def setPackages(
        self,
        pkgs: List[CvePkg],
        patches: Dict[str, str] = {},
        tags: Dict[str, str] = {},
        priorities: Dict[str, str] = {},
        closeDates: Dict[str, str] = {},
        append: bool = False,
    ):
        """Set pkgs"""
        if not append:
            self.pkgs = []

        for p in pkgs:
            what: str = p.what()
            if what in self._pkgs_list:
                continue

            if p.software in patches:
                tmp: List[str] = []
                for patch in patches[p.software].splitlines():
                    patch: str = patch.strip()
                    if patch != "" and patch not in tmp:
                        tmp.append(patch)
                p.setPatches(tmp, self.compatUbuntu)

            # Since we want store Tags_<pkg> and Tags_<pkg>_* under <pkg>, give
            # setTags a list of tuples of form:
            # [(<pkg>, <tag>), (<pkg_a>, <tag2>)]
            pkgTags: List[Tuple[str, str]] = [
                (x, tags[x])
                for x in tags
                if (x == p.software or x.startswith("%s_" % p.software))
            ]
            if pkgTags:
                p.setTags(pkgTags)

            pkgPriorities: List[Tuple[str, str]] = [
                (x, priorities[x])
                for x in priorities
                if (x == p.software or x.startswith("%s_" % p.software))
            ]
            if pkgPriorities:
                # XXX: Priority_foo_trusty
                p.setPriorities(pkgPriorities)

            pkgCloseDates: List[Tuple[str, str]] = [
                (x, closeDates[x])
                for x in closeDates
                if (x == p.software or x.startswith("%s_" % p.software))
            ]
            if pkgCloseDates:
                p.setCloseDates(pkgCloseDates)

            self.pkgs.append(p)
            self._pkgs_list.append(what)

    # various other methods
    def onDiskFormat(self) -> str:
        """Return format suitable for writing out to disk"""
        # helpers

        # Since patches can be per pkg object, but we want to list them in a
        # shared Patches_<software> section, pre-create the patches snippets
        def _collectPatches(pkgs: List[CvePkg]) -> Dict[str, List[str]]:
            patches: Dict[str, List[str]] = {}
            for pkg in pkgs:
                # build artifacts come from projects and shouldn't have their
                # own Patches_... entries
                if rePatterns["pkg-product-build-artifact"].search(pkg.product):
                    continue

                if pkg.software not in patches:
                    patches[pkg.software] = []
                for p in pkg.patches:
                    if p not in patches[pkg.software]:
                        patches[pkg.software].append(p)
            return patches

        # Do the same with tags. Tags may be of form Tags_foo or Tags_foo_bar
        # so create this dict which will format within the pkg.software stanza:
        #   tags = {
        #     pkg.software: {
        #       "Tags_foo": [tags],
        #       "Tags_foo_bar": [tags],
        #     },
        #     ...
        #   }
        def _collectTags(pkgs: List[CvePkg]) -> Dict[str, Dict[str, List[str]]]:
            tags: Dict[str, Dict[str, List[str]]] = {}
            for pkg in pkgs:
                if pkg.software not in tags:
                    tags[pkg.software] = {}
                for pkgKey in pkg.tags:
                    if pkgKey not in tags[pkg.software]:
                        tags[pkg.software][pkgKey] = []
                    for p in pkg.tags[pkgKey]:
                        if p not in tags[pkg.software][pkgKey]:
                            tags[pkg.software][pkgKey].append(p)
            return tags

        # Do the same with priorities, where the Priority is a string rather
        # than a list, like with Tags. Eg:
        #   priorities = {
        #     pkg.software: {
        #       "Priority_foo": <priority>,
        #       "Priority_foo_bar": <priority>,
        #     },
        #     ...
        #   }
        def _collectPriorities(pkgs) -> Dict[str, Dict[str, List[str]]]:
            priorities: Dict[str, Dict[str, List[str]]] = {}
            for pkg in pkgs:
                if pkg.software not in priorities:
                    priorities[pkg.software] = {}
                for pkgKey in pkg.priorities:
                    priorities[pkg.software][pkgKey] = pkg.priorities[pkgKey]
            return priorities

        # Do the same with closeDates, where the CloseDate is a string. Eg:
        #   closeDates = {
        #     pkg.software: {
        #       "CloseDate_foo": <date>,
        #       "CloseDate_foo_bar": <date>,
        #     },
        #     ...
        #   }
        def _collectCloseDates(pkgs) -> Dict[str, Dict[str, List[str]]]:
            closeDates: Dict[str, Dict[str, List[str]]] = {}
            for pkg in pkgs:
                if pkg.software not in closeDates:
                    closeDates[pkg.software] = {}
                for pkgKey in pkg.closeDates:
                    closeDates[pkg.software][pkgKey] = pkg.closeDates[pkgKey]
            return closeDates

        def _collectGHAS(ghas) -> List[str]:
            s = []
            for g in ghas:
                s.append("%s" % g)
            return s

        def _collectScanReports(scans) -> List[str]:
            s = []
            for m in scans:
                s.append("%s" % m)
            return s

        s: str = (
            """Candidate:%(candidate)s
OpenDate:%(openDate)s
CloseDate:%(closeDate)s
PublicDate:%(publicDate)s
CRD:%(crd)s
References:%(references)s
Description:%(description)s
%(ghas)s%(scans)sNotes:%(notes)s
Mitigation:%(mitigation)s
Bugs:%(bugs)s
Priority:%(priority)s
Discovered-by:%(discoveredBy)s
Assigned-to:%(assignedTo)s
CVSS:%(cvss)s
"""
            % (
                {
                    "candidate": " %s" % self.candidate if self.candidate else "",
                    "openDate": " %s" % self.openDate if self.openDate else "",
                    "closeDate": " %s" % self.closeDate if self.closeDate else "",
                    "publicDate": " %s" % self.publicDate if self.publicDate else "",
                    "crd": " %s" % self.crd if self.crd else "",
                    "references": (
                        "\n %s" % "\n ".join(self.references) if self.references else ""
                    ),
                    "description": (
                        "\n %s" % "\n ".join(self.description)
                        if self.description
                        else ""
                    ),
                    "ghas": (
                        "GitHub-Advanced-Security:\n%s\n"
                        % "\n".join(_collectGHAS(self.ghas))
                        if len(self.ghas) > 0
                        else ""
                    ),
                    "scans": (
                        "Scan-Reports:\n%s\n"
                        % "\n".join(_collectScanReports(self.scan_reports))
                        if len(self.scan_reports) > 0
                        else ""
                    ),
                    "notes": "\n %s" % "\n ".join(self.notes) if self.notes else "",
                    "mitigation": (
                        "\n %s" % "\n ".join(self.mitigation) if self.mitigation else ""
                    ),
                    "bugs": "\n %s" % "\n ".join(self.bugs) if self.bugs else "",
                    "priority": " %s" % self.priority if self.priority else "",
                    "discoveredBy": (
                        " %s" % self.discoveredBy if self.discoveredBy else ""
                    ),
                    "assignedTo": " %s" % self.assignedTo if self.assignedTo else "",
                    "cvss": " %s" % self.cvss if self.cvss else "",
                }
            )
        )

        # The package stanzas should be grouped and sorted by software, with
        # patches unsorted (to maintain author's intent), tags sorted followed
        # by list sorted by software, then product, then where (status,
        # modifier and when not considered). Eg:
        #   Patches_bar:
        #    vendor: http://b
        #    upstream: http://c
        #    vendor: http://a
        #   Tags_bar: <tag1> <tag2>
        #   Tags_bar_buster: <tag3> <tag4>
        #   Priority_bar: medium
        #   Priority_bar_buster: low
        #   debian/buster_bar: needed
        #   debian/squeeze_bar: needed
        #   git/github_bar: needs-triage
        #   ubuntu/bionic_bar: needed
        #   ubuntu/focal_bar: needed
        #   upstream_bar: needed
        #
        #   Patches_baz:
        #   git/github_baz: needs-triage
        #   ...

        patches = _collectPatches(self.pkgs)
        tags = _collectTags(self.pkgs)
        priorities = _collectPriorities(self.pkgs)
        closeDates = _collectCloseDates(self.pkgs)

        last_software: str = ""
        for pkg in sorted(self.pkgs, key=functools.cmp_to_key(cmp_pkgs)):
            # since we are sorted, can add these once, unconditionally at the
            # start of the software stanza
            pre_s: str = ""
            if last_software != pkg.software:
                if pkg.software in patches:
                    pre_s += "\nPatches_%s:\n" % pkg.software
                    if patches[pkg.software]:
                        pre_s += " " + "\n ".join(patches[pkg.software]) + "\n"
                if pkg.software in closeDates and closeDates[pkg.software]:
                    for pkgKey in sorted(closeDates[pkg.software]):
                        pre_s += "%sCloseDate_%s: %s\n" % (
                            "" if pre_s else "\n",
                            pkgKey,
                            closeDates[pkg.software][pkgKey],
                        )
                if pkg.software in tags and tags[pkg.software]:
                    for pkgKey in sorted(tags[pkg.software]):
                        pre_s += "%sTags_%s: %s\n" % (
                            "" if pre_s else "\n",
                            pkgKey,
                            " ".join(sorted(tags[pkg.software][pkgKey])),
                        )
                if pkg.software in priorities and priorities[pkg.software]:
                    for pkgKey in sorted(priorities[pkg.software]):
                        pre_s += "%sPriority_%s: %s\n" % (
                            "" if pre_s else "\n",
                            pkgKey,
                            priorities[pkg.software][pkgKey],
                        )

            if not last_software and not pre_s:
                pre_s = "\n"

            last_software = pkg.software

            s += "%s%s\n" % (pre_s, pkg)

        return s

    def _isPresent(self, data: Dict[str, Any], key: str) -> None:
        """Ensure data has key"""
        if key not in data:
            raise CveException("missing field '%s'" % key)

    # Verifiers
    # XXX: is there a sensible way to do this via schemas (since we aren't
    # json)?
    def _verifyCve(self, data: Dict[str, str], untriagedOk: bool = False) -> None:
        """Verify the CVE"""
        # verify input is correct type at runtime so we can rely on IDE type
        # hints elsewhere
        for key in data:
            if not isinstance(data[key], str):
                raise CveException("field '%s' is not str" % key)

        self._verifyRequired(data)

        for key in self.cve_required:
            self._isPresent(data, key)
            val: Union[str, List[str]] = data[key]
            if key == "Candidate":
                self._verifyCandidate(key, val)
            elif key == "PublicDate":
                self._verifyPublicDate(key, val)
            elif key == "References":
                self._verifyReferences(key, val)
            elif key == "Description":
                self._verifyDescription(key, val)
            elif key == "Notes":
                self._verifyNotes(key, val)
            elif key == "Bugs":
                self._verifyBugs(key, val)
            elif key == "Priority":
                self._verifyPriority(key, val, untriagedOk=untriagedOk)
            elif key == "Discovered-by":
                self._verifyDiscoveredBy(key, val)
            elif key == "Assigned-to":
                self._verifyAssignedTo(key, val)
            elif key == "CVSS":
                self._verifyCVSS(key, val)

        # optional
        for key in self.cve_optional:
            if key not in data:
                continue
            val = data[key]
            if key == "CRD":
                self._verifyCRD(key, val)
            elif key == "Mitigation":
                self._verifyMitigation(key, val)
            elif key == "GitHub-Advanced-Security":
                self._verifyGHAS(key, val)
            elif key == "Scan-Reports":
                self._verifyScanReports(key, val)

        # namespaced keys
        for key in data:
            val = data[key]
            if key.startswith("Priority_"):
                self._verifyPriority(key, val)

    def _verifySingleline(
        self, key: str, val: str, allow_utf8: Optional[bool] = False
    ) -> None:
        """Verify single-line value"""
        if val != "":
            if "\n" in val:
                raise CveException(
                    "invalid %s: '%s' (expected single line)" % (key, val)
                )
            if rePatterns["confusable-utf8"].search(val):
                raise CveException(
                    "invalid %s (contains confusable UTF-8 quotes and/or hyphens)" % key
                )
            if not val.isprintable():
                raise CveException("invalid %s (contains unprintable characters)" % key)
            if not allow_utf8:
                try:
                    val.encode("ascii")
                except UnicodeEncodeError:
                    raise CveException(
                        "invalid %s: '%s' (contains non-ASCII characters)" % (key, val)
                    )

    def _verifyMultiline(
        self, key: str, val: str, allow_utf8: Optional[bool] = False
    ) -> List[str]:
        """Verify multiline value"""
        strippedList: List[str] = []
        lines: List[str] = val.splitlines()
        if not lines:
            # empty is ok
            return strippedList

        if lines[0] != "":
            # first line must be a newline
            raise CveException(
                "invalid %s: '%s' (missing leading newline)" % (key, val)
            )
        elif len(lines) == 1:
            # but must have more than one line
            raise CveException("invalid %s (empty)" % (key))

        for line in lines[1:]:
            if not line:
                raise CveException("invalid %s: '%s' (empty line)" % (key, val))
            if line[0] != " ":
                raise CveException(
                    "invalid %s: '%s' (missing leading space)" % (key, val)
                )
            if rePatterns["confusable-utf8"].search(line):
                raise CveException(
                    "invalid %s (contains confusable UTF-8 quotes and/or hyphens)" % key
                )
            if not line.isprintable():
                raise CveException("invalid %s (contains unprintable characters)" % key)
            if not allow_utf8:
                try:
                    line.encode("ascii")
                except UnicodeEncodeError:
                    raise CveException(
                        "invalid %s: '%s' (contains non-ASCII characters)" % (key, val)
                    )
            strippedList.append(line.strip())

        return strippedList

    def _verifyRequired(self, data: Dict[str, Any]) -> None:
        """Verify have all required fields"""
        for field in self.cve_required:
            if field not in data:
                raise CveException("missing required field '%s'" % field)

    def _verifyCandidate(self, key: str, val: str) -> None:
        """Verify CVE candidate number"""
        self._verifySingleline(key, val)
        if not rePatterns["CVE"].search(val):
            raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyPublicDate(self, key: str, val: str) -> None:
        """Verify CVE public date"""
        self._verifySingleline(key, val)
        # empty is ok unless self.compatUbuntu is set (then use 'unknown')
        if val != "":
            if not self.compatUbuntu or val != "unknown":
                verifyDate(key, val, compatUbuntu=self.compatUbuntu)

    def _verifyCRD(self, key: str, val: str) -> None:
        """Verify CVE CRD"""
        self._verifySingleline(key, val)
        # empty is ok unless self.compatUbuntu is set (then use 'unknown')
        if val != "":
            if not self.compatUbuntu or val != "unknown":
                verifyDate(key, val, compatUbuntu=self.compatUbuntu)

    def _verifyOpenDate(self, key: str, val: str) -> None:
        """Verify CVE OpenDate"""
        self._verifySingleline(key, val)
        if not self.compatUbuntu or val != "unknown":
            verifyDate(key, val, required=True, compatUbuntu=self.compatUbuntu)

    def _verifyCloseDate(self, key: str, val: str) -> None:
        """Verify CVE CloseDate"""
        self._verifySingleline(key, val)
        # empty is ok unless self.compatUbuntu is set (then use 'unknown')
        if val != "":
            if not self.compatUbuntu or val != "unknown":
                verifyDate(key, val, compatUbuntu=self.compatUbuntu)

    def _verifyUrl(self, key: str, url: str) -> None:
        """Verify url"""
        # This is intentionally dumb to avoid external dependencies
        if not rePatterns["url-schemes"].search(url):
            raise CveException("invalid url in %s: '%s'" % (key, url))

    def _verifyReferences(self, key: str, val: str) -> None:
        """Verify CVE References"""
        if val != "":  # empty is ok
            for line in self._verifyMultiline(key, val):
                self._verifyUrl(key, line)

    def _verifyDescription(self, key: str, val: str) -> None:
        """Verify CVE Description"""
        if val != "":  # empty is ok
            self._verifyMultiline(key, val, allow_utf8=True)

    def _verifyNotes(self, key: str, val: str) -> None:
        """Verify CVE Notes"""
        # Notes:
        #  handle> blah
        #   blah
        #  @handle>
        #   blah
        #   .
        #   blah
        if val != "":  # empty is ok
            self._verifyMultiline(key, val, allow_utf8=True)

        # extended validation
        lines: List[str] = val.splitlines()

        # first is newline, 2nd is start of notes. If no notes, no extended
        # validation
        if len(lines) < 2:
            return

        handle: str = "@?[a-zA-Z0-9._-]+>"

        # first entry must start with a handle
        pat_handle: Pattern = re.compile(r"^ %s" % handle)
        if not pat_handle.search(lines[1]):
            raise CveException(
                "invalid Notes: '%s' (first line should conform to ' handle> text...')"
                % lines[1]
            )

        pat_either: Pattern = re.compile(r"^ (%s| [^\n])" % handle)
        for line in lines[2:]:
            if not pat_either.search(line):
                raise CveException(
                    "invalid Notes: '%s' (line should conform to ' handle> text...' or '  text...')"
                    % line
                )

    def _verifyMitigation(self, key: str, val: str) -> None:
        """Verify CVE Mitigation"""
        if val != "":  # empty is ok
            self._verifyMultiline(key, val, allow_utf8=True)

    def _verifyBugs(self, key: str, val: str) -> None:
        """Verify CVE Bugs"""
        if val != "":  # empty is ok
            for line in self._verifyMultiline(key, val):
                self._verifyUrl(key, line)

    def _verifyPriority(self, key: str, val: str, untriagedOk: bool = False) -> None:
        """Verify CVE Priority"""
        self._verifySingleline(key, val)
        if untriagedOk and val == "untriaged":
            return
        if not rePatterns["priorities"].search(val):
            raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyDiscoveredBy(self, key: str, val: str) -> None:
        """Verify CVE Discovered-by"""
        self._verifySingleline(key, val, allow_utf8=True)
        if val != "":
            if not rePatterns["attribution"].search(val):
                raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyAssignedTo(self, key: str, val: str) -> None:
        """Verify CVE Assigned-to"""
        self._verifySingleline(key, val, allow_utf8=True)
        if val != "":
            if not rePatterns["attribution"].search(val):
                raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyCVSS(self, key: str, val: str) -> None:
        """Verify CVE CVSS"""
        if val != "":
            if self.compatUbuntu:
                self._verifySingleline(key, val)
                if not rePatterns["cvss-ubuntu"].search(val):
                    raise CveException("invalid %s: '%s'" % (key, val))
            else:
                for line in self._verifyMultiline(key, val):
                    if not rePatterns["cvss-entry"].search(line):
                        raise CveException(
                            "invalid %s: '%s' (use who: CVSS:...)" % (key, line)
                        )

    def _verifyGHAS(self, key: str, val: str) -> None:
        """Verify CVE GitHub-Advanced-Security"""
        # only verify multi-line here as the parse() function in setGHAS() will
        # handle this more fully
        if val != "":  # empty is ok
            self._verifyMultiline(key, val)

    def _verifyScanReports(self, key: str, val: str) -> None:
        """Verify CVE Scan-Reports"""
        # only verify multi-line here as the parse() function in
        # setScanReports() will handle this more fully
        if val != "":  # empty is ok
            self._verifyMultiline(key, val)


# Utility functions that work on CVE files
def checkSyntaxFile(
    f: str, rel: str, compatUbuntu: bool, untriagedOk: bool = False
) -> Tuple[Optional[CVE], bool]:
    """Perform syntax check on one CVE"""
    cve: Optional[CVE] = None
    try:
        cve = CVE(fn=f, compatUbuntu=compatUbuntu, untriagedOk=untriagedOk)
    except Exception as e:
        cvelib.common.warn("%s parse error: %s" % (rel, str(e)))
        return cve, False

    ok: bool = True

    # make sure the name of the file matches the candidate
    bn: str = os.path.basename(f)
    if bn != cve.candidate:
        ok = False
        cvelib.common.warn("%s has non-matching candidate '%s'" % (rel, cve.candidate))

    # make sure References is non-empty for non-placeholder CVEs
    if (
        not rePatterns["CVE-placeholder"].match(cve.candidate)
        and len(cve.references) == 0
    ):
        ok = False
        cvelib.common.warn("%s has missing references" % rel)

    cve_pkgs_only_pending_or_closed: bool = True

    seen_oci_where: List[str] = []

    # ensure pkgs is populated
    if len(cve.pkgs) == 0:
        ok = False
        cvelib.common.warn("%s has missing affected software" % rel)
    else:
        # check package status against reldir (noting the pkg.where for later)
        open = False
        for p in cve.pkgs:
            if p.when != "":
                if (
                    p.when == "code-not-used"
                    or p.when == "code-not-imported"
                    or p.when == "code-not-present"
                ) and p.status != "not-affected":
                    ok = False
                    cvelib.common.warn(
                        "%s specifies '%s' with '%s' (should use 'not-affected')"
                        % (rel, p.when, p.status)
                    )
                elif p.when.startswith("code not "):
                    ok = False
                    cvelib.common.warn(
                        "%s specifies '%s' (should use '%s')"
                        % (rel, p.when, p.when.replace(" ", "-"))
                    )
                elif p.status == "deferred" and not rePatterns["date-only"].match(
                    p.when
                ):
                    ok = False
                    cvelib.common.warn(
                        "%s specifies non-date with '%s' (should be unspecified or YYYY-MM-DD))"
                        % (rel, p.status)
                    )
                elif p.status != "deferred" and rePatterns["date-only"].match(p.when):
                    ok = False
                    cvelib.common.warn("%s specifies date with '%s')" % (rel, p.status))

            if p.status.split()[0] in ["needed", "needs-triage", "pending", "deferred"]:
                if p.status.startswith("need"):
                    cve_pkgs_only_pending_or_closed = False
                open = True

            # will use this in another check
            if p.product == "oci" and p.where != "" and p.where not in seen_oci_where:
                seen_oci_where.append(p.where)

        if open and "retired" in rel:
            ok = False
            cvelib.common.warn("%s is retired but has software with open status" % rel)
        elif not open and "active" in rel:
            ok = False
            cvelib.common.warn(
                "%s is active but has software with only closed status" % rel
            )

    # make sure CloseDate is set if retired
    if "retired" in rel and cve.closeDate == "":
        ok = False
        cvelib.common.warn("%s is retired but CloseDate is not set" % rel)
    elif "active" in rel and cve.closeDate != "":
        ok = False
        cvelib.common.warn("%s is active but CloseDate is set" % rel)

    # make sure CloseDate is same or after OpenDate
    if cve.openDate != "" and cve.closeDate != "":
        d1 = verifyDate("OpenDate", cve.openDate)
        d2 = verifyDate("CloseDate", cve.closeDate)
        if d1 and d2 and d2 < d1:
            ok = False
            cvelib.common.warn(
                "%s CloseDate is before OpenDate (%s < %s)"
                % (rel, cve.closeDate, cve.openDate)
            )

    # GHAS
    seen: List[str] = []
    open_ghas = False
    for item in cve.ghas:
        if item.status.startswith("need"):
            open_ghas = True
        needle: str = ""
        if isinstance(item, cvelib.github.GHDependabot):
            needle = "gh-dependabot"
        elif isinstance(item, cvelib.github.GHSecret):
            needle = "gh-secret"
        elif isinstance(item, cvelib.github.GHCode):
            needle = "gh-code"

        if needle not in seen:
            if (
                not cve.discoveredBy == needle
                and not cve.discoveredBy.startswith("%s," % needle)
                and not ", %s," % needle in cve.discoveredBy
                and not cve.discoveredBy.endswith(", %s" % needle)
            ):
                seen.append(needle)
                ok = False
                cvelib.common.warn(
                    "%s has '%s' missing from Discovered-by" % (rel, needle)
                )

    if len(cve.ghas) > 0 and open_ghas and "retired" in rel:
        ok = False
        cvelib.common.warn(
            "%s is retired but has open GitHub Advanced Security entries" % rel
        )
    elif (
        len(cve.ghas) > 0
        and not open_ghas
        and "active" in rel
        and not cve_pkgs_only_pending_or_closed
    ):
        # We only alert on this if all the alerts are closed, it's still and
        # active and if at least one package is not closed or pending. We don't
        # alert with pending to account for times when the alert is staged in a
        # branch but not yet in a release (ie, the alert is closed, but the
        # issue is still open)
        ok = False
        cvelib.common.warn(
            "%s is active but has only closed GitHub Advanced Security entries" % rel
        )

    # scan reports
    seen: List[str] = []
    where_needles: List[str] = []
    open_scans = False
    for item in cve.scan_reports:
        if item.status.startswith("need"):
            open_scans = True
        needle: str = ""
        whr_needle: str = ""
        if isinstance(item, cvelib.scan.ScanOCI):
            if item.url.startswith("https://quay.io/"):
                needle = "quay.io"
                whr_needle = "quay-"
            elif item.url.startswith("https://console.cloud.google.com/"):
                needle = "gar"
                whr_needle = "gar-"
            elif item.url.startswith("https://dso.docker.com/"):
                needle = "dso"
                whr_needle = "dockerhub"

        if whr_needle != "" and whr_needle not in where_needles:
            where_needles.append(whr_needle)

        if needle != "" and needle not in seen:
            if (
                not cve.discoveredBy == needle
                and not cve.discoveredBy.startswith("%s," % needle)
                and not ", %s," % needle in cve.discoveredBy
                and not cve.discoveredBy.endswith(", %s" % needle)
            ):
                seen.append(needle)
                ok = False
                cvelib.common.warn(
                    "%s has '%s' missing from Discovered-by" % (rel, needle)
                )

    # check if have oci/<where> present for all ocis
    where_missing: List[str] = []
    for n in where_needles:
        found: bool = False
        for where in seen_oci_where:
            if where.startswith(n):
                found = True
                break
        if not found:
            where_missing.append("oci/%s" % n)

    if len(where_missing) > 0:
        ok = False
        cvelib.common.warn(
            "%s missing package entries starting with '%s'"
            % (rel, ", ".join(sorted(where_missing)))
        )

    if len(cve.scan_reports) > 0 and open_scans and "retired" in rel:
        ok = False
        cvelib.common.warn("%s is retired but has open scan report entries" % rel)
    elif (
        len(cve.scan_reports) > 0
        and not open_scans
        and "active" in rel
        and not cve_pkgs_only_pending_or_closed
    ):
        # We only alert on this if all the alerts are closed, it's still and
        # active and if at least one package is not closed or pending. We don't
        # alert with pending to account for times when the alert is staged in a
        # branch but not yet in a release (ie, the alert is closed, but the
        # issue is still open)
        ok = False
        cvelib.common.warn("%s is active but has only closed scan report entries" % rel)

    return cve, ok


def checkSyntax(
    cveDirs: Dict[str, str],
    compatUbuntu: bool,
    untriagedOk: bool = False,
    cveFiles: Optional[List[str]] = None,
) -> bool:
    """Perform syntax checks on CVEs"""
    # TODO: make configurable
    seen: Dict[str, List[str]] = {}
    cves: List[str] = []
    if cveFiles is not None:
        cves = cveFiles
    else:
        cves = _getCVEPaths(cveDirs)
    ok = True
    for f in cves:
        tmp: List[str] = os.path.realpath(f).split("/")
        rel: str = tmp[-2] + "/" + tmp[-1]
        cve: Optional[CVE]
        cveOk: bool
        cve, cveOk = checkSyntaxFile(f, rel, compatUbuntu, untriagedOk)
        if cve is None:
            continue

        if not cveOk:
            ok = False

        if cve.candidate not in seen:
            seen[cve.candidate] = [rel]
        else:
            seen[cve.candidate].append(rel)
            ok = False
            cvelib.common.warn(
                "%s has multiple entries: %s"
                % (cve.candidate, ", ".join(seen[cve.candidate]))
            )

    # These cross-CVE checks require having all the data and should be done
    # separately from individual checks (though it does mean we do a 2nd pass)
    try:
        cveData: List[CVE] = collectCVEData(
            cveDirs, compatUbuntu, untriagedOk=untriagedOk
        )
    except CveException:
        # This shouldn't happen without previous warnings, so if it does, just
        # return and let the user fix the warnings
        return False

    # check for duplicate dependabot alert urls
    dupes: Set[str]
    _, dupes = collectGHAlertUrls(cveData)
    for cve in cveData:
        for item in cve.ghas:
            if item.url in dupes:
                rel: str = ""
                fn: str = cve.candidate
                for dir in [cveDirs["retired"], cveDirs["active"], cveDirs["ignored"]]:
                    fn: str = dir + "/" + cve.candidate
                    if os.path.exists(fn):
                        tmp: List[str] = os.path.realpath(fn).split("/")
                        rel = tmp[-2] + "/" + tmp[-1]
                ok = False
                cvelib.common.warn("%s has duplicate alert URL '%s'" % (rel, item.url))

    return ok


def cveFromUrl(url: str) -> Tuple[str, str]:
    """Return a CVE based on the url"""
    if not url.startswith("https://github.com/"):
        raise CveException("unsupported url: '%s' (only support github)" % url)

    if not rePatterns["github-issue"].match(url):
        raise CveException("invalid url: '%s' (only support github issues)" % url)

    year: int = datetime.datetime.now().year
    tmp: List[str] = url.split("/")  # based on rePatterns, we know we have 7 elements
    # ['https:', '', 'github.com', '<org>', '<repo>', 'issues', 'N']
    return "CVE-%d-GH%s#%s" % (year, tmp[6], tmp[4]), tmp[3]


def pkgFromCandidate(cand: str, where: str) -> Optional[str]:
    """Find pkg name from url"""
    pkg: Optional[str] = None
    if "-GH" in cand:
        if cand.count("#") != 1:
            raise CveException("invalid candidate: '%s'" % cand)

        if cand.endswith("#"):
            raise CveException("invalid candidate: '%s' (empty package)" % cand)

        if where == "":
            where = "github"
        pkg = "git/%s_%s" % (where, cand.split("#")[1])

    return pkg


# Helpers for addCve()
def _genReferencesAndBugs(cve: str) -> Tuple[List[str], List[str]]:
    """Generate references and bugs for _createCve()"""
    refs: List[str] = []
    bugs: List[str] = []
    if cve.startswith("http"):
        refs.append(cve)
        bugs.append(cve)
    else:
        refs.append("https://www.cve.org/CVERecord?id=%s" % cve)

    return refs, bugs


def _createCve(
    cveDirs: Dict[str, str],
    cve_path: str,
    cve: str,
    args_pkgs: List[str],
    compatUbuntu: bool,
    withReferences: bool = False,
    retired: bool = False,
    discovered_by: Optional[str] = None,
    assigned_to: Optional[str] = None,
) -> None:
    """Create or append CVE"""
    data: Dict[str, str] = {}

    append: bool = False
    if os.path.isfile(cve_path):
        append = True
        data = cvelib.common.readCve(cve_path)
    else:
        # find generic template
        template: str = os.path.join(cveDirs["templates"], "_base")
        ubuntuTemplate: str = os.path.join(cveDirs["templates"], "_base.ubuntu")
        if compatUbuntu:
            template = ubuntuTemplate
        if not os.path.isfile(template):
            raise CveException(
                "could not find 'templates/%s'" % os.path.basename(template)
            )
        data = cvelib.common.readCve(template)

        if template == ubuntuTemplate:
            # update args_pkgs using Ubuntu's template format
            tmp: List[str] = copy.deepcopy(args_pkgs)
            pat: Pattern = re.compile(r"^#(.*_)PKG$")
            for k in data:
                if not pat.search(k) or k == "#Patches_PKG":
                    continue
                for p in tmp:
                    if "_" not in p:
                        uPkg: str = pat.sub("\\1%s" % p, k)
                        if uPkg not in args_pkgs:
                            args_pkgs.append(uPkg)

            # remove the original args_pkgs since we have the updated ones
            for p in tmp:
                args_pkgs.remove(p)

        # unconditionally add references when generating from template
        withReferences = True

    if withReferences:
        # References and bugs only need filling in with new CVEs
        refs: List[str]
        bugs: List[str]
        refs, bugs = _genReferencesAndBugs(cve)
        # put our generated references before templated ones
        data["References"] = "\n %s" % " ".join(refs) + data["References"]
        if bugs:
            data["Bugs"] = "\n %s" % (" ".join(bugs) + data["Bugs"])

    # fill in the CVE candidate (needed with new and per-package template, but
    # re-setting it for existing is harmless and makes the logic simpler)
    data["Candidate"] = os.path.basename(cve_path)

    if not append or "OpenDate" not in data or data["OpenDate"] == "":
        now: datetime.datetime = datetime.datetime.now()
        data["OpenDate"] = "%d-%0.2d-%0.2d" % (now.year, now.month, now.day)

    if not append or "CloseDate" not in data:
        # set empty CloseDate if not appending
        data["CloseDate"] = ""

    if retired and not append and data["CloseDate"] == "":
        # set CloseDate if retired and not appending
        now: datetime.datetime = datetime.datetime.now()
        data["CloseDate"] = "%d-%0.2d-%0.2d" % (now.year, now.month, now.day)

    pkgObjs: List[CvePkg] = []
    for p in args_pkgs:
        # mock up an entry
        pkgObjs.append(parse("%s: needs-triage" % p, compatUbuntu))

    cveObj: CVE = CVE(untriagedOk=True, compatUbuntu=compatUbuntu)
    cveObj.setData(data)
    cveObj.setPackages(pkgObjs, append=append)

    if discovered_by is not None:
        cveObj.setDiscoveredBy(discovered_by)

    if assigned_to is not None:
        cveObj.setAssignedTo(assigned_to)

    # Now write it out. Note, cveObj.onDiskFormat() sorts and loses the
    # formatting of the package template (if this is a problem, consider
    # may not using onDiskFormat() with package templates)
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(cveObj.onDiskFormat())
        f.flush()
        shutil.copyfile(f.name, cve_path, follow_symlinks=False)
        os.unlink(f.name)


def _findNextPlaceholder(cveDirs: Dict[str, str]) -> str:
    """Find next placeholder CVE-YYYY-NNN#"""
    cves: List[str] = _getCVEPaths(cveDirs)
    year: int = datetime.datetime.now().year
    highest: int = 0
    next: str = "CVE-%d-NNN1" % year
    for cve in sorted(cves):
        bn: str = os.path.basename(cve)
        if rePatterns["CVE-next-placeholder"].match(bn):
            n: str
            _, n = bn.rsplit("N", 1)
            if int(n) > highest:
                highest = int(n)
                # leading 'N' is required, but pad out to at least 4 chars
                next = "CVE-%d-N%s" % (year, str(highest + 1).rjust(3, "N"))
                if not rePatterns["CVE-next-placeholder"].match(next):
                    raise CveException("could not calculate next placeholder")

    return next


def _cveExists(cveDirs: Dict[str, str], cand: str) -> str:
    """Check existence of CVE"""
    cves: List[str] = _getCVEPaths(cveDirs)
    for cve in sorted(cves):
        bn: str = os.path.basename(cve)
        dn: str = os.path.basename(os.path.dirname(cve))
        if cand == bn:
            return "%s/%s" % (dn, bn)

    nfu_fn: str = os.path.join(cveDirs["ignored"], "not-for-us.txt")
    if os.path.exists(nfu_fn):
        lines: Optional[Set[str]] = readFile(nfu_fn)
        if lines is not None:
            for line in lines:
                if line.startswith("%s:" % cand):
                    return "ignored/not-for-us.txt"

    return ""


def addCve(
    cveDirs: Dict[str, str],
    compatUbuntu: bool,
    orig_cve: str,
    orig_pkgs: List[str],
    template: Optional[str] = None,
    retired: bool = False,
    discovered_by: Optional[str] = None,
    assigned_to: Optional[str] = None,
) -> None:
    """Add/modify CVE"""
    pkgs: List[str] = []
    if orig_pkgs is not None:
        pkgs = copy.deepcopy(orig_pkgs)

    # See if we can parse
    cand: Optional[str] = None
    where: str = ""
    if orig_cve.startswith("http"):
        cand, where = cveFromUrl(orig_cve)  # raises an error
    elif orig_cve == "next":
        cand = _findNextPlaceholder(cveDirs)
    else:
        cand = orig_cve

    cve_fn: str
    if retired:
        cve_fn = os.path.join(cveDirs["retired"], cand)
    else:
        cve_fn = os.path.join(cveDirs["active"], cand)

    # check if the CVE exists in somewhere other than where we specified
    found: str = _cveExists(cveDirs, cand)
    if found != "" and found not in cve_fn:
        error("%s already exists in %s" % (cand, found))
        return

    cvefn_hash: str = ""
    if os.path.exists(cve_fn):
        with open(cve_fn, "rb") as f:
            cvefn_hash = hashlib.md5(f.read()).hexdigest()

    # For a new CVE (where the path doesn't already exist), if we can determine
    # a pkg from the candidate, then add it to the list if we haven't specified
    # any packages with --package already
    p: Optional[str] = pkgFromCandidate(cand, where)
    if cvefn_hash == "" and p and len(pkgs) == 0:
        pkgs.append(p)
    if not pkgs:
        raise CveException("could not find usable packages for '%s'" % orig_cve)

    # Find template if we have one
    pkgTemplate: Optional[str] = None
    if template is not None:
        pkgTemplate = template
    elif "_" in pkgs[0]:  # product/where_software/modifer
        pkgTemplate = pkgs[0].split("_")[1].split("/")[0]
    elif compatUbuntu:  # software/modifier
        pkgTemplate = pkgs[0].split("/")[0]

    if pkgTemplate is not None:
        pkgTemplate = os.path.join(cveDirs["templates"], pkgTemplate)

    # if we have a per-package template but don't have the cve, then copy
    # the template into place as the CVE
    fromPkgTemplate: bool = False
    if (
        pkgTemplate is not None
        and os.path.isfile(pkgTemplate)
        and not os.path.isfile(cve_fn)
    ):
        shutil.copyfile(pkgTemplate, cve_fn, follow_symlinks=False)
        fromPkgTemplate = True

    _createCve(
        cveDirs,
        cve_fn,
        orig_cve,
        pkgs,
        compatUbuntu,
        fromPkgTemplate,
        retired,
        discovered_by,
        assigned_to,
    )

    rel: str = "active/%s" % cand
    if retired:
        rel = "retired/%s" % cand

    if cvefn_hash == "":
        cvelib.common.msg("%s created" % rel)
    else:
        with open(cve_fn, "rb") as f:
            if hashlib.md5(f.read()).hexdigest() != cvefn_hash:
                cvelib.common.msg("%s updated" % rel)
            else:
                cvelib.common.msg("%s unmodified" % rel)


# misc helpers
def _getCVEPaths(cveDirs: Dict[str, str]) -> List[str]:
    """Return the list of sorted CVE paths"""
    cves: List[str] = (
        glob.glob(cveDirs["active"] + "/CVE*")
        + glob.glob(cveDirs["retired"] + "/CVE-*")
        + glob.glob(cveDirs["ignored"] + "/CVE-*")
    )
    cves.sort()
    return cves


def _commonParseFilter(default: List[str], filt: str, errText: str) -> List[str]:
    """Common helper to return a list of filtered items based on default"""
    items: List[str] = copy.deepcopy(default)
    if filt != "":
        skipping: bool = False
        if filt.startswith("-") or ",-" in filt:
            skipping = True
        else:
            items = []

        for f in filt.split(","):
            if skipping and not f.startswith("-"):
                raise CveException(
                    "invalid filter: cannot mix %s and skipped %s" % (errText, errText)
                )

            tmp: str = f[1:] if f.startswith("-") else f
            if tmp not in default:
                raise CveException("invalid filter: %s" % f)

            if not f.startswith("-") and tmp not in items:
                items.append(tmp)
            elif f.startswith("-") and tmp in items:
                items.remove(tmp)

    return items


def _parseFilterPriorities(filt: str) -> List[str]:
    """Return a list of filtered priorities"""
    return _commonParseFilter(cve_priorities, filt, "priorities")


def _parseFilterStatuses(filt: str) -> List[str]:
    """Return a list of filtered statuses"""
    return _commonParseFilter(cve_statuses, filt, "statuses")


# _parseFilterTags() is sufficiently different from _parseFilterPriorities()
# and _parseFilterStatuses() that we implement it separately.
def _parseFilterTags(filt: str) -> Tuple[List[str], bool]:
    """Return a list of filtered tags"""
    tags: List[str] = []
    skipping: bool = False

    if filt != "":
        if filt.startswith("-") or ",-" in filt:
            skipping = True
        else:
            tags = []

        for t in filt.split(","):
            if skipping and not t.startswith("-"):
                raise CveException(
                    "invalid filter-tag: cannot mix tags and skipped tags"
                )

            tmp_t: str = t[1:] if t.startswith("-") else t
            if tmp_t not in tags:
                tags.append(tmp_t)

    return tags, skipping


def collectCVEData(
    cveDirs: Dict[str, str],
    compatUbuntu: bool,
    untriagedOk: bool = True,
    filter_status: Optional[str] = None,
    filter_product: Optional[str] = None,
    filter_priority: Optional[str] = None,
    filter_tag: Optional[str] = None,
) -> List[CVE]:
    """Read in all CVEs"""
    cves: List[CVE] = []
    cve_fn: str

    # if no status filter, default to all statuses
    statuses: List[str] = cve_statuses
    if filter_status is not None:
        statuses = _parseFilterStatuses(filter_status)

    # if no priority filter, default to all priorities
    priorities: List[str] = cve_priorities
    if filter_priority is not None:
        priorities = _parseFilterPriorities(filter_priority)

    # if no tags filter, default to any tag
    tags: List[str] = []
    skip_tags: bool = False
    if filter_tag is not None:
        tags, skip_tags = _parseFilterTags(filter_tag)

    for cve_fn in _getCVEPaths(cveDirs):
        cve: CVE = CVE(fn=cve_fn, compatUbuntu=compatUbuntu, untriagedOk=untriagedOk)

        # Check if the CVE has package data that meets our search criteria
        pkgs: List[CvePkg] = copy.deepcopy(cve.pkgs)
        remove_indexes: List[int] = []
        idx: int
        pkg: CvePkg
        for idx, pkg in enumerate(pkgs):
            # TODO: treat filter_product like other filter_*
            if filter_product is not None:
                found: bool = False
                filter: str
                for filter in filter_product.split(","):
                    tmp: List[str] = filter.split("/", maxsplit=1)
                    if tmp[0] != pkg.product:
                        continue
                    elif len(tmp) == 2 and tmp[1] != pkg.where:
                        continue
                    found = True
                    break
                if not found:
                    remove_indexes.append(idx)
                    continue

            if pkg.status not in statuses:
                remove_indexes.append(idx)
                continue

            priority: str = cve.priority
            if pkg.software in pkg.priorities:
                priority = pkg.priorities[pkg.software]

            # filter by priority
            if priority not in priorities:
                remove_indexes.append(idx)
                continue

            # filter by tags
            if len(tags) > 0:
                # if user specified a required tag ('not skip_tags') but there
                # are no package tags, skip
                if not skip_tags and pkg.software not in pkg.tags:
                    remove_indexes.append(idx)
                    continue

                # search the package tags
                if pkg.software in pkg.tags:
                    found: bool = False
                    sw_tag: str
                    for sw_tag in pkg.tags[pkg.software]:
                        if sw_tag in tags:
                            found = True
                            break

                    # if found user-specified tag in package tags and supposed
                    # to skip, then skip. Or, if didn't find a user-specified
                    # required tag in packages tags, skip.
                    if (found and skip_tags) or (not found and not skip_tags):
                        remove_indexes.append(idx)
                        continue

        # things went very wrong if we have duplicate indexes...
        assert len(remove_indexes) == len(set(remove_indexes))

        # now remove any packages that didn't meet the search critieria
        for idx in sorted(remove_indexes, reverse=True):
            del cve.pkgs[idx]

        # By now, the CVE should only have package data that meets our search
        # criteria. If there are any packages left, add it to the list
        if len(cve.pkgs) > 0:
            cves.append(copy.deepcopy(cve))

    return cves


def collectGHAlertUrls(cves: List[CVE]) -> Tuple[Set[str], Set[str]]:
    """Collect all known alerts urls"""
    urls: List[str] = []
    dupes: List[str] = []
    for cve in cves:
        a: Union[
            cvelib.github.GHDependabot, cvelib.github.GHSecret, cvelib.github.GHCode
        ]
        for a in cve.ghas:
            if a.url not in urls:
                urls.append(a.url)
            elif a.url != "unavailable" and a.url not in dupes:
                dupes.append(a.url)
    return set(urls), set(dupes)


#
# CLI mains
#
def main_cve_add():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="cve-add",
        description="Add CVE to tracker",
    )
    parser.add_argument(
        "-c",
        "--cve",
        dest="cve",
        help="CVE entry",
        metavar="CVE-YYYY-NNNN|CVE-YYYY-GHNNNN#PROJECT|https://github.com/.../issues/NNN|next",
    )
    parser.add_argument(
        "--assigned-to",
        dest="assigned_to",
        help="Assigned to entity",
        metavar="NAME[ (nick)]",
    )
    parser.add_argument(
        "--discovered-by",
        dest="discovered_by",
        help="Discovered by entity",
        metavar="NAME[ (nick)]",
    )
    parser.add_argument(
        "-p",
        "--package",
        dest="pkgs",
        help="Package (project) name",
        metavar="PKGNAME|git/github_PKGNAME|CVE-YYYY-GHNNNN#PROJECT",
        action="append",
    )
    parser.add_argument(
        "--package-template",
        dest="template",
        help="Use template for PKGNAME instead of auto-detecting",
        metavar="PKGNAME",
        default=None,
    )
    parser.add_argument(
        "-r",
        "--retired",
        dest="retired",
        help="add to retired/ instead of active/",
        action="store_true",
    )
    args: argparse.Namespace = parser.parse_args()

    if not args.cve:
        error("missing required argument: --cve")
        return  # for tests

    # If given a url, we'll try to determine the package name, otherwise we
    # need to be given one
    if not args.cve.startswith("http") and not args.pkgs:
        error("missing required argument: --package")
        return  # for tests

    addCve(
        getConfigCveDataPaths(),
        getConfigCompatUbuntu(),
        args.cve,
        args.pkgs,
        template=args.template,
        retired=args.retired,
        discovered_by=args.discovered_by,
        assigned_to=args.assigned_to,
    )


def main_cve_check_syntax():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="cve-check-syntax",
        description="Verify syntax of CVEs",
    )

    parser.add_argument(
        "--untriaged-ok",
        dest="untriagedOk",
        help="'priority' can be 'untriaged'",
        action="store_true",
    )

    parser.add_argument(
        "-f",
        dest="fns",
        help="CVE file(s) to check",
        metavar="FILENAME1 FILENAME2... FILENAMEN",
        nargs="+",
    )

    args: argparse.Namespace = parser.parse_args()

    ok: bool
    if args.fns:
        ok = checkSyntax(
            getConfigCveDataPaths(),
            getConfigCompatUbuntu(),
            args.untriagedOk,
            cveFiles=args.fns,
        )
    else:
        ok = checkSyntax(
            getConfigCveDataPaths(), getConfigCompatUbuntu(), args.untriagedOk
        )

    if not ok:  # pragma: nocover
        sys.exit(1)
