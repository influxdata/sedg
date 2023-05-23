#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

from typing import Dict, List
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
#    url: https://quay.io/..., https://...cloud.google.com, ... (scan report)


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
        if s not in cve_priorities:
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
