#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import abc
import datetime
import re
from typing import Dict, List, Optional, Pattern, Tuple
from yaml import load, CSafeLoader

from cvelib.common import CveException, cve_priorities, rePatterns, _experimental

# Scan-Reports:
#  - type: oci
#    component: ...
#    detectedIn: <image name@sha256:...>
#    advisory: https://.../CVE-... (relevant security advisory)
#    version: <version>
#    fixedBy: <version>
#    severity: negligible|low|medium|high|critical
#    status: needs-triage|needed|released|dismissed (tolerable|code-not-used; name)
#    url: https://quay.io/..., https://...-docker.pkg.dev/, ... (scan report)


class ScanOCI(object):
    required: List[str] = [
        "component",
        "detectedIn",
        "severity",
        "version",
        "fixedBy",
        "status",
        "advisory",
        "url",
    ]

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        # the prefixed spacing is currently important for onDiskFormat()
        s: str = " - type: oci\n"
        s += "   component: %s\n" % self.component
        s += "   detectedIn: %s\n" % self.detectedIn
        s += "   advisory: %s\n" % self.advisory
        s += "   version: %s\n" % self.versionAffected
        s += "   fixedBy: %s\n" % self.versionFixed
        s += "   severity: %s\n" % self.severity
        s += "   status: %s\n" % self.status
        s += "   url: %s" % self.url
        return s

    def __init__(self, data: Dict[str, str]) -> None:
        _experimental()

        self.component: str = ""
        self.detectedIn: str = ""
        self.advisory: str = ""
        self.versionAffected: str = ""
        self.versionFixed: str = ""
        self.severity: str = ""
        self.status: str = ""
        self.url: str = ""

        self._verifyRequired(data)

        self.setComponent(data["component"])
        self.setDetectedIn(data["detectedIn"])
        self.setSeverity(data["severity"])
        self.setVersionAffected(data["version"])
        self.setVersionFixed(data["fixedBy"])
        self.setStatus(data["status"])
        self.setAdvisory(data["advisory"])
        self.setUrl(data["url"])

    def _verifyRequired(self, data: Dict[str, str]) -> None:
        """Verify have all required fields"""
        for field in self.required:
            if field not in data:
                raise CveException("missing required field '%s'" % field)
            if data[field] == "":
                raise CveException("empty required field '%s'" % field)
            if "\n" in data[field]:
                raise CveException("field '%s' should be single line" % field)

    def setComponent(self, s: str) -> None:
        """Set component"""
        self.component = s

    def setDetectedIn(self, s: str) -> None:
        """Set detectedIn"""
        self.detectedIn = s

    def setSeverity(self, s: str) -> None:
        """Set severity"""
        if s not in cve_priorities and s != "unknown":
            raise CveException("invalid severity: %s" % s)
        self.severity = s

    def setVersionAffected(self, s: str) -> None:
        """Set version"""
        self.versionAffected = s

    def setVersionFixed(self, s: str) -> None:
        """Set fixedBy"""
        self.versionFixed = s

    def setStatus(self, s: str) -> None:
        """Set status"""
        if not rePatterns["scan-oci-status"].search(s):
            if "dismissed" in s:
                raise CveException(
                    "invalid status: %s. Use 'dismissed (tolerable|code-not-used; <username>)'"
                    % s
                )
            raise CveException(
                "invalid status: %s. Use 'needs-triage|needed|released|dismissed (...)'"
                % s
            )
        self.status = s

    def setAdvisory(self, s: str) -> None:
        """Set advisory"""
        if not s.startswith("https://") and s != "unavailable":
            raise CveException("invalid advisory url: %s" % s)
        self.advisory = s

    def setUrl(self, s: str) -> None:
        """Set url"""
        if not s.startswith("https://") and s != "unavailable":
            raise CveException("invalid url: %s" % s)
        self.url = s


def parse(s: str) -> List[ScanOCI]:
    """Parse a string and return a list of ScanOCIs"""
    if s == "":
        return []

    yml: List[Dict[str, str]]
    try:
        # Use yaml.load(s, Loader=yaml.CSafeLoader) instead of
        # yaml.safe_load(s) since the C implementation is so much faster
        # yml = yaml.load(s, Loader=yaml.CSafeLoader)
        yml = load(s, Loader=CSafeLoader)
    except Exception:
        raise CveException("invalid yaml:\n'%s'" % s)

    mans: List[ScanOCI] = []
    for item in yml:
        if "type" not in item:
            raise CveException("invalid Scan-Reports document: 'type' missing for item")

        if item["type"] == "oci":
            mans.append(ScanOCI(item))
        else:
            raise CveException(
                "invalid Scan-Reports document: unknown type '%s'" % item["type"]
            )

    return mans


#
# common report output for list of ScanOCIs
#
def getScanOCIsReport(ocis: List[ScanOCI], fixable: Optional[bool] = False) -> str:
    """Show list of ScanOCIs objects"""
    max_name: int = 0
    max_vers: int = 0
    grouped = {}
    for i in ocis:
        if len(i.component) > max_name:
            max_name = len(i.component)
        if len(i.versionAffected) > max_vers:
            max_vers = len(i.versionAffected)

        if i.component not in grouped:
            grouped[i.component] = {}
            grouped[i.component]["version"] = i.versionAffected
            grouped[i.component]["status"] = [i.status]
            grouped[i.component]["severity"] = [i.severity]
            continue
        if i.status not in grouped[i.component]["status"]:
            grouped[i.component]["status"].append(i.status)
        if i.severity not in grouped[i.component]["severity"]:
            grouped[i.component]["severity"].append(i.severity)

    tableStr: str = "{name:%d} {vers:%d} {status}" % (max_name, max_vers)
    table_f: object = tableStr.format
    s: str = ""
    for g in sorted(grouped.keys()):
        status = "n/a"
        if "needed" in grouped[g]["status"]:
            status = "needed"
        elif "unavailable" in grouped[g]["status"]:
            status = "unavailable"
        elif "released" in grouped[g]["status"]:
            status = "released"

        if fixable and status != "needed":
            continue

        if len(grouped[g]["severity"]) > 0:
            status += " (%s)" % ",".join(sorted(grouped[g]["severity"]))

        s += table_f(name=g, vers=grouped[g]["version"], status=status) + "\n"

    return s.rstrip()


def _parseScanURL(url: str) -> Tuple[str, str, str, str]:
    """Find CVE 'product', 'where', 'software' and 'modifier' from url"""
    if url == "":
        return ("", "", "", "")

    product: str = "oci"
    where: str
    software: str
    modifier: str = ""

    tmp = url.split("@")[0].split("/")
    # https://cloud.google.com/artifact-registry/docs/repositories/repo-locations
    pat: Pattern[str] = re.compile(r"^https://[a-z\-]+-docker\.pkg\.dev/")
    if pat.search(url):
        # https://us-docker.pkg.dev/PROJECT/REPO/IMGNAME@sha256:...
        where = tmp[3]
        software = tmp[4]
        modifier = tmp[5]
    elif url.startswith("https://quay.io/repository/"):  # quay.io
        # https://quay.io/repository/ORG/IMGNAME/manifest/sha256:...
        where = tmp[4]
        software = tmp[5]
    else:
        where = "TBD"
        software = "TBD"

    return (product, where, software, modifier)


def getScanOCIsReportTemplates(
    registry: str,
    name: str,
    ocis: List[ScanOCI],
    template_urls: List[str] = [],
) -> str:
    """Get the reports templates"""
    if len(ocis) == 0:
        return ""

    sev: List[str] = ["unknown", "negligible", "low", "medium", "high", "critical"]
    oci_references: List[str] = []
    iss_checklist: List[str] = []
    cve_items: Dict[str, int] = {}
    scan_reports: str = ""
    highest: int = 0
    for oci in sorted(ocis, key=lambda i: (i.component, i.advisory)):
        cur: int = sev.index(oci.severity)
        if cur > highest:
            highest = cur

        if oci.url != "unavailable" and oci.url not in oci_references:
            oci_references.append(oci.url)

        if oci.advisory == "unavailable":
            iss_checklist.append("- [ ] %s (%s)" % (oci.component, oci.severity))
        else:
            iss_checklist.append(
                "- [ ] [%s](%s) (%s)" % (oci.component, oci.advisory, oci.severity)
            )

        c: str = "- [ ] %s (%s)" % (oci.component, oci.severity)
        if c not in cve_items:
            cve_items[c] = 1
        else:
            cve_items[c] += 1

        scan_reports += "%s\n" % oci

    plural: bool = len(ocis) > 1

    priority: str = sev[highest]
    if priority == "unknown":
        priority = "medium"

    iss_template: str = """## %s %s template
Please address %s alert%s in %s:

The following alert%s %s issued:
%s

Since a '%s' severity issue is present, tentatively adding the 'security/%s' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * %s%s
""" % (
        name.split("@")[0],
        registry,
        registry,
        "s" if plural else "",
        name.split("@")[0],
        "s" if plural else "",
        "were" if plural else "was",
        "\n".join(sorted(iss_checklist)),
        sev[highest],
        priority,
        "" if len(template_urls) == 0 else "%s\n * " % "\n * ".join(template_urls),
        "\n * ".join(sorted(oci_references)),
    )
    iss_template += "\n## end template"

    cve_checklist: str = ""
    for i in sorted(cve_items.keys()):
        if cve_items[i] > 1:
            cve_checklist += " %s\n" % (i.replace("(", "(%d " % (cve_items[i])))
        else:
            cve_checklist += " %s\n" % i

    pkg_stanzas: List[str] = []
    for url in oci_references:
        # TODO: where override
        (prod, where, soft, mod) = _parseScanURL(url)
        s: str = "Patches_%s:\n%s/%s_%s%s: needs-triage" % (
            soft,
            prod,
            where,
            soft,
            ("" if mod == "" else "/%s" % mod),
        )
        pkg_stanzas.append(s)

    now: datetime.datetime = datetime.datetime.now()
    cve_template: str = """## %s CVE template
Candidate: %s
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 %s
Description:
 Please address alert%s in %s
%sScan-Reports:
%s
Notes:
Mitigation:
Bugs:
Priority: %s
Discovered-by: %s
Assigned-to:
CVSS:

%s
""" % (
        name.split("@")[0],
        "CVE-%d-NNNN" % now.year,
        "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
        # "\n ".join(references + sorted(advisories)),
        "\n ".join(oci_references),
        "s" if plural else "",
        name.split("@")[0],
        cve_checklist,
        scan_reports.rstrip(),
        priority,
        registry.lower(),
        "\n".join(pkg_stanzas),
    )

    cve_template += "\n## end CVE template"

    return "%s\n\n%s" % (iss_template, cve_template)


# Interface for work with different OCI scan report objects
class SecurityReportInterface(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):  # pragma: nocover
        return (
            hasattr(subclass, "getDigestForImage")
            and callable(subclass.getDigestForImage)
            and hasattr(subclass, "parseImageDigest")
            and callable(subclass.parseImageDigest)
            and hasattr(subclass, "getOCIsForNamespace")
            and callable(subclass.getOCIsForNamespace)
            and hasattr(subclass, "getReposForNamespace")
            and callable(subclass.getReposForNamespace)
            and hasattr(subclass, "getSecurityReport")
            and callable(subclass.getSecurityReport)
            or NotImplementedError
        )

    @abc.abstractmethod
    def getDigestForImage(self, repo_full: str) -> str:  # pragma: nocover
        """Obtain the digest for the specified repo"""
        raise NotImplementedError

    @abc.abstractmethod
    def parseImageDigest(self, digest: str) -> Tuple[str, str, str]:  # pragma: nocover
        """Parse the image digest into a (namespace, repo, sha256) tuple"""
        raise NotImplementedError

    @abc.abstractmethod
    def getOCIsForNamespace(
        self, namespace: str
    ) -> List[Tuple[str, int]]:  # pragma: nocover
        """Obtain the list of OCIs with modification time in seconds for the specified namespace"""
        raise NotImplementedError

    @abc.abstractmethod
    def getReposForNamespace(self, namespace: str) -> List[str]:  # pragma: nocover
        """Obtain the list of repos for the specified namespace"""
        raise NotImplementedError

    @abc.abstractmethod
    def getSecurityReport(
        self,
        repo_full: str,
        raw: bool = False,
        fixable: bool = True,
        with_templates: bool = False,
        template_urls: List[str] = [],
        priorities: List[str] = [],
    ) -> str:  # pragma: nocover
        """Obtain the security manifest for the specified repo"""
        raise NotImplementedError
