#!/usr/bin/env python3

import re
from typing import Dict, List, Union
import yaml

from cvelib.common import CveException, rePatterns


class GHDependabot(object):
    required: List[str] = [
        "dependency",
        "detectedIn",
        "advisory",
        "severity",
        "status",
    ]

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        # the prefixed spacing is currently important for onDiskFormat()
        s: str = " - type: dependabot\n"
        s += "   dependency: %s\n" % self.dependency
        s += "   detectedIn: %s\n" % self.detectedIn
        s += "   advisory: %s\n" % self.advisory
        s += "   severity: %s\n" % self.severity
        s += "   status: %s" % self.status
        return s

    def __init__(self, data: Dict[str, str]) -> None:
        self.dependency: str = ""
        self.detectedIn: str = ""
        self.advisory: str = ""
        self.severity: str = ""
        self.status: str = ""

        self._verifyRequired(data)

        self.setDependency(data["dependency"])
        self.setDetectedIn(data["detectedIn"])
        self.setAdvisory(data["advisory"])
        self.setSeverity(data["severity"])
        self.setStatus(data["status"])

    # verify methods
    def _verifyRequired(self, data: Dict[str, str]) -> None:
        """Verify have all required fields"""
        for field in self.required:
            if field not in data:
                raise CveException("missing required field '%s'" % field)
            if not _isNonEmptyStr(data[field]):
                raise CveException("empty required field '%s'" % field)
            if "\n" in data[field]:
                raise CveException("field '%s' should be single line" % field)

    # set methods
    def setDependency(self, s: str) -> None:
        """Set dependency"""
        if re.search(r"\s", s):
            raise CveException("invalid dependabot dependency: %s" % s)
        self.dependency = s

    def setDetectedIn(self, s: str) -> None:
        """Set detectedIn"""
        self.detectedIn = s

    def setAdvisory(self, s: str) -> None:
        """Set advisory"""
        if not rePatterns["github-advisory"].search(s):
            raise CveException("invalid dependabot advisory: %s" % s)
        self.advisory = s

    def setSeverity(self, s: str) -> None:
        """Set severity"""
        if not rePatterns["github-dependabot-severity"].search(s):
            raise CveException("invalid dependabot severity: %s" % s)
        self.severity = s

    def setStatus(self, s: str) -> None:
        """Set status"""
        if not rePatterns["github-dependabot-status"].search(s):
            if "dismissed" in s:
                raise CveException(
                    "invalid dependabot status: %s. Use 'dismissed (started|no-bandwidth|tolerable|inaccurate|code-not-used; <github username>)"
                    % s
                )
            raise CveException(
                "invalid dependabot status: %s. Use 'needs-triage|needed|released|dismissed (...)'"
                % s
            )
        self.status = s


class GHSecret(object):
    required: List[str] = [
        "secret",
        "detectedIn",
        "status",
    ]

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        # the prefixed spacing is currently important for onDiskFormat()
        s: str = " - type: secret\n"
        s += "   secret: %s\n" % self.secret
        s += "   detectedIn: %s\n" % self.detectedIn
        s += "   status: %s" % self.status
        return s

    def __init__(self, data: Dict[str, str]) -> None:
        self.secret: str = ""
        self.detectedIn: str = ""
        self.status: str = ""

        self._verifyRequired(data)

        self.setSecret(data["secret"])
        self.setDetectedIn(data["detectedIn"])
        self.setStatus(data["status"])

    # verify methods
    def _verifyRequired(self, data: Dict[str, str]) -> None:
        """Verify have all required fields"""
        for field in self.required:
            if field not in data:
                raise CveException("missing required field '%s'" % field)
            if not _isNonEmptyStr(data[field]):
                raise CveException("empty required field '%s'" % field)
            if "\n" in data[field]:
                raise CveException("field '%s' should be single line" % field)

    # set methods
    def setSecret(self, s: str) -> None:
        self.secret = s

    def setDetectedIn(self, s: str) -> None:
        self.detectedIn = s

    def setStatus(self, s: str) -> None:
        if not rePatterns["github-secret-status"].search(s):
            if "dismissed" in s:
                raise CveException(
                    "invalid secret status: %s. Use 'dismissed (revoked|false-positive|used-in-tests|wont-fix; <github username>)"
                    % s
                )
            raise CveException(
                "invalid secret status: %s. Use 'needs-triage|needed|released|dismissed (...)'"
                % s
            )
        self.status = s


def _isNonEmptyStr(s: str) -> bool:
    return s != ""


def parse(s: str) -> List[Union[GHDependabot, GHSecret]]:
    """Parse a string and return a GHDependabot"""
    yml: List[Dict[str, str]]
    try:
        yml = yaml.safe_load(s)
    except Exception:
        raise CveException("invalid yaml:\n'%s'" % s)

    ghas: List[Union[GHDependabot, GHSecret]] = []
    for item in yml:
        if "type" not in item:
            raise CveException("invalid GHAS document: 'type' missing for item")

        if item["type"] == "dependabot":
            ghas.append(GHDependabot(item))
        elif item["type"] == "secret":
            ghas.append(GHSecret(item))
        else:
            raise CveException(
                "invalid GHAS document: unknown GHAS type '%s'" % item["type"]
            )

    return ghas
