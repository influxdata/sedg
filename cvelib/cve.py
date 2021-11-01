#!/usr/bin/env python3

import copy
import datetime
import glob
from operator import attrgetter
import os
import re
import shutil
import tempfile

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
        "Bugs",
        "Priority",
        "Discovered-by",
        "Assigned-to",
        "CVSS",
    ]
    # Tags_*, Patches_* and software are handled special
    cve_optional = [
        "CRD",
        "Mitigation",
    ]

    def __str__(self):
        s = []
        for key in self.data:
            s.append("%s=%s" % (key, self.data[key]))
        return "# %s\n%s\n" % (self.candidate, "\n".join(s))

    def __repr__(self):
        return self.__str__()

    def __init__(self, fn=None, untriagedOk=False, compatUbuntu=False):
        # XXX
        self.data = {}
        self.pkgs = []
        self._pkgs_list = []  # what is in self.pkgs
        self.compatUbuntu = compatUbuntu
        self.untriagedOk = untriagedOk
        if fn is None:
            return

        data = cvelib.common.readCve(fn)
        self.setData(data)

    # set methods
    def setData(self, data):
        """Set members from data"""
        self._verifyCve(data, untriagedOk=self.untriagedOk)
        # members
        self.setCandidate(data["Candidate"])
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

        # Any field with '_' is a package or patch. Since these could be out of
        # order, collect them separately, then call setPackages()
        pkgs = []
        patches = {}
        tags = {}
        priorities = {}
        for k in data:
            if k not in self.data:  # copy raw data for later
                self.data[k] = data[k]
            if "_" not in k or k.startswith("#"):
                continue
            if k.startswith("Patches_"):
                if not rePatterns["pkg-patch-key"].search(k):
                    raise CveException("invalid Patches_ key: '%s'" % (k))
                pkg = k.split("_")[1]
                patches[pkg] = data[k]
            elif k.startswith("Tags_"):
                if self.compatUbuntu:
                    if not rePatterns["pkg-tags-key-ubuntu"].search(k):
                        raise CveException("invalid Ubuntu Tags_ key: '%s'" % (k))
                elif not rePatterns["pkg-tags-key"].search(k):
                    raise CveException("invalid Tags_ key: '%s'" % (k))
                # both Tags_foo and Tags_foo_bar
                pkg = k.split("_", 1)[1]
                tags[pkg] = data[k]
            elif k.startswith("Priority_"):
                if self.compatUbuntu:
                    if not rePatterns["pkg-priority-key-ubuntu"].search(k):
                        raise CveException("invalid Ubuntu Priority_ key: '%s'" % (k))
                elif not rePatterns["pkg-priority-key"].search(k):
                    raise CveException("invalid Priority_ key: '%s'" % (k))
                # both Priority_foo and Priority_foo_bar
                pkg = k.split("_", 1)[1]
                priorities[pkg] = data[k]
            else:
                s = "%s: %s" % (k, data[k])
                pkgs.append(cvelib.pkg.parse(s, compatUbuntu=self.compatUbuntu))

        self.setPackages(pkgs, patches=patches, tags=tags, priorities=priorities)

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
        self.references = []
        for r in s.splitlines():
            r = r.strip()
            if r != "" and r not in self.references:
                self.references.append(r)
        self.data["References"] = self.references

    def setDescription(self, s):
        """Set Description"""
        # strip newline off the front then strip whitespace from every line
        self.description = [item.strip() for item in s.lstrip().splitlines()]
        self.data["Description"] = self.description

    def setNotes(self, s):
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

    def setMitigation(self, s):
        """Set Mitigation"""
        # strip newline off the front then strip whitespace from every line
        self.mitigation = [item.strip() for item in s.lstrip().splitlines()]
        self.data["Mitigation"] = self.mitigation

    def setBugs(self, s):
        """Set Bugs"""
        self.bugs = []
        for b in s.splitlines():
            b = b.strip()
            if b != "" and b not in self.bugs:
                self.bugs.append(b)
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

    def setPackages(self, pkgs, patches=[], tags=[], priorities=[], append=False):
        """Set pkgs"""
        if not isinstance(pkgs, list):
            raise CveException("pkgs is not a list")
        if not append:
            self.pkgs = []
        for p in pkgs:
            if not isinstance(p, CvePkg):
                raise CveException("package is not of type cvelib.pkg.CvePkg")
            what = p.what()
            if what in self._pkgs_list:
                continue

            if p.software in patches:
                tmp = []
                for patch in patches[p.software].splitlines():
                    patch = patch.strip()
                    if patch != "" and patch not in tmp:
                        tmp.append(patch)
                p.setPatches(tmp, self.compatUbuntu)

            # Since we want store Tags_<pkg> and Tags_<pkg>_* under <pkg>, give
            # setTags a list of tuples of form:
            # [(<pkg>, <tag>), (<pkg_a>, <tag2>)]
            pkgTags = [
                (x, tags[x])
                for x in tags
                if (x == p.software or x.startswith("%s_" % p.software))
            ]
            if pkgTags:
                p.setTags(pkgTags)

            pkgPriorities = [
                (x, priorities[x])
                for x in priorities
                if (x == p.software or x.startswith("%s_" % p.software))
            ]
            if pkgPriorities:
                # XXX: Priority_foo_trusty
                p.setPriorities(pkgPriorities)

            self.pkgs.append(p)
            self._pkgs_list.append(what)

    # various other methods
    def onDiskFormat(self):
        """Return format suitable for writing out to disk"""
        # helpers

        # Since patches can be per pkg object, but we want to list them in a
        # shared Patches_<software> section, pre-create the patches snippets
        def _collectPatches(pkgs):
            patches = {}
            for pkg in pkgs:
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
        def _collectTags(pkgs):
            tags = {}
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
        def _collectPriorities(pkgs):
            priorities = {}
            for pkg in self.pkgs:
                if pkg.software not in priorities:
                    priorities[pkg.software] = {}
                for pkgKey in pkg.priorities:
                    priorities[pkg.software][pkgKey] = pkg.priorities[pkgKey]
            return priorities

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
                "mitigation": "\n %s" % "\n ".join(self.mitigation)
                if self.mitigation
                else "",
                "bugs": "\n %s" % "\n ".join(self.bugs) if self.bugs else "",
                "priority": " %s" % self.priority if self.priority else "",
                "discoveredBy": " %s" % self.discoveredBy if self.discoveredBy else "",
                "assignedTo": " %s" % self.assignedTo if self.assignedTo else "",
                "cvss": " %s" % self.cvss if self.cvss else "",
            }
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

        last_software = ""
        # Sort the list by software, then product, then where so everything
        # looks pretty. XXX: Ubuntu likes to have 'upstream' first, should we
        # consider that with compatUbuntu?
        for pkg in sorted(self.pkgs, key=attrgetter("software", "product", "where")):
            # since we are sorted, can add these once, unconditionally at the
            # start of the software stanza
            if last_software != pkg.software:
                s += "\nPatches_%s:\n" % pkg.software
                if pkg.software in patches and patches[pkg.software]:
                    s += " " + "\n ".join(patches[pkg.software]) + "\n"
                if pkg.software in tags and tags[pkg.software]:
                    for pkgKey in sorted(tags[pkg.software]):
                        s += "Tags_%s: %s\n" % (
                            pkgKey,
                            " ".join(sorted(tags[pkg.software][pkgKey])),
                        )
                if pkg.software in priorities and priorities[pkg.software]:
                    for pkgKey in sorted(priorities[pkg.software]):
                        s += "Priority_%s: %s\n" % (
                            pkgKey,
                            priorities[pkg.software][pkgKey],
                        )
            last_software = pkg.software

            s += "%s\n" % pkg

        return s

    def _isPresent(self, data, key, canBeEmpty=False):
        """Ensure data has key"""
        if not isinstance(data, dict):
            raise CveException("data not of type dict")
        if key not in data:
            raise CveException("missing field '%s'" % key)

    # Verifiers
    # XXX: is there a sensible way to do this via schemas (since we aren't
    # json)?
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
            elif key == "References":
                self._verifyReferences(key, val)
            elif key == "Description":
                self._verifyDescription(key, val)
            elif key == "Notes":
                self._verifyDescription(key, val)
            elif key == "Bugs":
                self._verifyBugs(key, val)
            elif key == "Priority":
                self._verifyPriority(key, val, untriagedOk=untriagedOk)
            elif key == "Discovered-by":
                self._verifyDiscoveredBy(key, val)
            elif key == "Assigned-to":
                self._verifyAssignedTo(key, val)

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

    def _verifySingleline(self, key, val):
        """Verify multiline value"""
        if val != "":
            if "\n" in val:
                raise CveException(
                    "invalid %s: '%s' (expected single line)" % (key, val)
                )

    def _verifyMultiline(self, key, val):
        """Verify multiline value"""
        strippedList = []
        lines = val.splitlines()
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
            strippedList.append(line.strip())

        return strippedList

    def _verifyRequired(self, data):
        """Verify have all required fields"""
        for field in self.cve_required:
            if field not in data:
                raise CveException("missing required field '%s'" % field)

    def _verifyCandidate(self, key, val):
        """Verify CVE candidate number"""
        self._verifySingleline(key, val)
        if not rePatterns["CVE"].search(val):
            raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyDate(self, key, date):
        """Verify a date"""
        unspecified = "empty"
        if self.compatUbuntu:
            unspecified = "'unknown'"
        err = "invalid %s: '%s' (use %s or YYYY-MM-DD [HH:MM:SS [TIMEZONE]])" % (
            key,
            date,
            unspecified,
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
                # Unfortunately, %Z doesn't work reliably, so just strip it off
                # https://bugs.python.org/issue22377
                # datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %Z")
                datetime.datetime.strptime(
                    " ".join(date.split()[:-1]), "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                raise CveException(err)

    def _verifyPublicDate(self, key, val):
        """Verify CVE public date"""
        self._verifySingleline(key, val)
        # empty is ok unless self.compatUbuntu is set (then use 'unknown')
        if val != "":
            if not self.compatUbuntu or val != "unknown":
                self._verifyDate(key, val)

    def _verifyCRD(self, key, val):
        """Verify CVE CRD"""
        self._verifySingleline(key, val)
        # empty is ok unless self.compatUbuntu is set (then use 'unknown')
        if val != "":
            if not self.compatUbuntu or val != "unknown":
                self._verifyDate(key, val)

    def _verifyUrl(self, key, url):
        """Verify url"""
        # This is intentionally dumb to avoid external dependencies
        if not rePatterns["url-schemes"].search(url):
            raise CveException("invalid url in %s: '%s'" % (key, url))

    def _verifyReferences(self, key, val):
        """Verify CVE References"""
        if val != "":  # empty is ok
            for line in self._verifyMultiline(key, val):
                self._verifyUrl(key, line)

    def _verifyDescription(self, key, val):
        """Verify CVE Description"""
        if val != "":  # empty is ok
            self._verifyMultiline(key, val)

    def _verifyNotes(self, key, val):
        """Verify CVE Notes"""
        if val != "":  # empty is ok
            self._verifyMultiline(key, val)

    def _verifyMitigation(self, key, val):
        """Verify CVE Mitigation"""
        if val != "":  # empty is ok
            self._verifyMultiline(key, val)

    def _verifyBugs(self, key, val):
        """Verify CVE Bugs"""
        if val != "":  # empty is ok
            for line in self._verifyMultiline(key, val):
                self._verifyUrl(key, line)

    def _verifyPriority(self, key, val, untriagedOk=False):
        """Verify CVE Priority"""
        self._verifySingleline(key, val)
        if untriagedOk and val == "untriaged":
            return
        if not rePatterns["priorities"].search(val):
            raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyDiscoveredBy(self, key, val):
        """Verify CVE Discovered-by"""
        self._verifySingleline(key, val)
        if val != "":
            if not rePatterns["attribution"].search(val):
                raise CveException("invalid %s: '%s'" % (key, val))

    def _verifyAssignedTo(self, key, val):
        self._verifySingleline(key, val)
        """Verify CVE Assigned-to"""
        if val != "":
            if not rePatterns["attribution"].search(val):
                raise CveException("invalid %s: '%s'" % (key, val))


# Utility functions that work on CVE files
def checkSyntax(cveDirs, compatUbuntu, untriagedOk=False):
    """Perform syntax checks on CVEs"""
    # TODO: make configurable
    seen = {}
    cves = _getCVEPaths(cveDirs)
    for f in cves:
        tmp = os.path.realpath(f).split("/")
        rel = tmp[-2] + "/" + tmp[-1]
        try:
            cve = None
            cve = cvelib.cve.CVE(
                fn=f, compatUbuntu=compatUbuntu, untriagedOk=untriagedOk
            )
        except Exception as e:
            cvelib.common.warn("%s: %s" % (rel, str(e)))
            continue

        # make sure the name of the file matches the candidate
        bn = os.path.basename(f)
        if bn != cve.candidate:
            cvelib.common.warn("%s: non-matching candidate '%s'" % (rel, cve.candidate))

        if cve.candidate not in seen:
            seen[cve.candidate] = [rel]
        else:
            seen[cve.candidate].append(rel)
            cvelib.common.warn(
                "multiple entries for %s: %s"
                % (cve.candidate, ", ".join(seen[cve.candidate]))
            )


def cveFromUrl(url):
    """Return a CVE based on the url"""
    if not url.startswith("https://github.com/"):
        raise CveException("unsupported url: '%s' (only support github)" % url)

    if not rePatterns["github-issue"].match(url):
        raise CveException("invalid url: '%s' (only support github issues)" % url)

    year = datetime.datetime.now().year
    tmp = url.split("/")  # based on rePatterns, we know we have 7 elements
    return "CVE-%s-GH%s#%s" % (year, tmp[6], tmp[4])


def pkgFromCandidate(cand):
    """Find pkg name from url"""
    pkg = None
    if "-GH" in cand:
        if cand.count("#") != 1:
            raise CveException("invalid candidate: '%s'" % cand)

        if cand.endswith("#"):
            raise CveException("invalid candidate: '%s' (empty package)" % cand)
        pkg = "git/github_%s" % cand.split("#")[1]

    return pkg


# Helpers for addCve()
def _genReferencesAndBugs(cve):
    """Generate references and bugs for _createCve()"""
    refs = []
    bugs = []
    if cve.startswith("http"):
        refs.append(cve)
        bugs.append(cve)
    else:
        refs.append("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" % cve)

    return refs, bugs


def _createCve(cveDirs, cve_path, cve, args_pkgs, compatUbuntu, withReferences=False):
    """Create or append CVE"""
    data = {}

    append = False
    if os.path.isfile(cve_path):
        append = True
        data = cvelib.common.readCve(cve_path)
    else:
        # find generic boiler
        boiler = os.path.join(cveDirs["active"], "00boilerplate")
        ubuntuBoiler = os.path.join(cveDirs["active"], "00boilerplate.ubuntu")
        if compatUbuntu:
            boiler = ubuntuBoiler
        if not os.path.isfile(boiler):
            raise CveException("could not find 'active/%s'" % os.path.basename(boiler))
        data = cvelib.common.readCve(boiler)

        if boiler == ubuntuBoiler:
            # update args_pkgs using Ubuntu's boiler format
            tmp = copy.deepcopy(args_pkgs)
            pat = re.compile(r"^#(.*_)PKG$")
            for k in data:
                if not pat.search(k) or k == "#Patches_PKG":
                    continue
                for p in tmp:
                    if "_" not in p:
                        uPkg = pat.sub("\\1%s" % p, k)
                        if uPkg not in args_pkgs:
                            args_pkgs.append(uPkg)

            # remove the original args_pkgs since we have the updated ones
            for p in tmp:
                args_pkgs.remove(p)

        # unconditionally add references when generating from boiler
        withReferences = True

    if withReferences:
        # References and bugs only need filling in with new CVEs
        refs, bugs = _genReferencesAndBugs(cve)
        data["References"] = "\n %s" % " ".join(refs)
        data["Bugs"] = "\n %s" % " ".join(bugs) if bugs else ""

    # fill in the CVE candidate (needed with new and per-package boiler, but
    # re-setting it for existing is harmless and makes the logic simpler)
    data["Candidate"] = os.path.basename(cve_path)

    pkgObjs = []
    for p in args_pkgs:
        # mock up an entry
        pkgObjs.append(cvelib.pkg.parse("%s: needs-triage" % p, compatUbuntu))

    cveObj = cvelib.cve.CVE(untriagedOk=True, compatUbuntu=compatUbuntu)
    cveObj.setData(data)
    cveObj.setPackages(pkgObjs, append=append)

    # now write it out
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(cveObj.onDiskFormat())
        f.flush()
        shutil.copyfile(f.name, cve_path, follow_symlinks=False)
        os.unlink(f.name)


def addCve(cveDirs, compatUbuntu, orig_cve, orig_pkgs, boiler=None):
    """Add/modify CVE"""
    pkgs = []
    if orig_pkgs is not None:
        pkgs = copy.deepcopy(orig_pkgs)

    # See if we can parse
    cand = None
    if orig_cve.startswith("http"):
        cand = cvelib.cve.cveFromUrl(orig_cve)  # raises an error
    else:
        cand = orig_cve
    cve_fn = os.path.join(cveDirs["active"], cand)  # TODO: check retired, ...

    # If we can determine a pkg from the candidate, then add it to the
    # front of the list, removing it from the pkgs if it is already there
    p = cvelib.cve.pkgFromCandidate(cand)
    if p:
        if p in pkgs:
            pkgs.remove(p)
        pkgs.insert(0, p)
    if not pkgs:
        raise CveException("could not find usable packages for '%s'" % orig_cve)

    # Find boilerplate if we have one
    pkgBoiler = None
    if boiler is not None:
        pkgBoiler = boiler
    elif "_" in pkgs[0]:  # product/where_software/modifer
        pkgBoiler = pkgs[0].split("_")[1].split("/")[0]
    elif compatUbuntu:  # software/modifier
        pkgBoiler = pkgs[0].split("/")[0]

    if pkgBoiler is not None:
        pkgBoiler = os.path.join(cveDirs["active"], "00boilerplate.%s" % pkgBoiler)

    # if we have a per-package boiler but don't have the cve, then copy
    # the boiler into place as the CVE
    fromPkgBoiler = False
    if (
        pkgBoiler is not None
        and os.path.isfile(pkgBoiler)
        and not os.path.isfile(cve_fn)
    ):
        shutil.copyfile(pkgBoiler, cve_fn, follow_symlinks=False)
        fromPkgBoiler = True

    _createCve(cveDirs, cve_fn, orig_cve, pkgs, compatUbuntu, fromPkgBoiler)


# misc helpers
def _getCVEPaths(cveDirs):
    """Return the list of sorted CVE paths"""
    cves = (
        glob.glob(cveDirs["active"] + "/CVE*")
        + glob.glob(cveDirs["retired"] + "/CVE-*")
        + glob.glob(cveDirs["ignored"] + "/CVE-*")
    )
    cves.sort()
    return cves
