#!/usr/bin/env python3

import re
from typing import Dict, List, Union
from yaml import load, CSafeLoader

from cvelib.common import CveException, rePatterns


class GHDependabot(object):
    required: List[str] = [
        "dependency",
        "detectedIn",
        "advisory",
        "severity",
        "status",
        "url",
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
        s += "   status: %s\n" % self.status
        s += "   url: %s" % self.url
        return s

    def __init__(self, data: Dict[str, str]) -> None:
        self.dependency: str = ""
        self.detectedIn: str = ""
        self.advisory: str = ""
        self.severity: str = ""
        self.status: str = ""
        self.url: str = ""

        self._verifyRequired(data)

        self.setDependency(data["dependency"])
        self.setDetectedIn(data["detectedIn"])
        self.setAdvisory(data["advisory"])
        self.setSeverity(data["severity"])
        self.setStatus(data["status"])
        self.setUrl(data["url"])

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
                "invalid dependabot status: %s. Use 'needs-triage|needed|released|removed|dismissed (...)'"
                % s
            )
        self.status = s

    def setUrl(self, s: str) -> None:
        """Set url"""
        if not rePatterns["github-dependabot-alert"].search(s):
            raise CveException("invalid dependabot alert url: %s" % s)
        self.url = s


class GHSecret(object):
    required: List[str] = [
        "secret",
        "detectedIn",
        "status",
        "url",
    ]

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        # the prefixed spacing is currently important for onDiskFormat()
        s: str = " - type: secret\n"
        s += "   secret: %s\n" % self.secret
        s += "   detectedIn: %s\n" % self.detectedIn
        s += "   status: %s\n" % self.status
        s += "   url: %s" % self.url
        return s

    def __init__(self, data: Dict[str, str]) -> None:
        self.secret: str = ""
        self.detectedIn: str = ""
        self.status: str = ""
        self.url: str = ""

        self._verifyRequired(data)

        self.setSecret(data["secret"])
        self.setDetectedIn(data["detectedIn"])
        self.setStatus(data["status"])
        self.setUrl(data["url"])

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
        """Set secret"""
        self.secret = s

    def setDetectedIn(self, s: str) -> None:
        """Set detectedIn"""
        self.detectedIn = s

    def setStatus(self, s: str) -> None:
        """Set status"""
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

    def setUrl(self, s: str) -> None:
        """Set url"""
        if not rePatterns["github-secret-alert"].search(s):
            raise CveException("invalid secret alert url: %s" % s)
        self.url = s


def _isNonEmptyStr(s: str) -> bool:
    """Check if string is non-empty"""
    return s != ""


def parse(s: str) -> List[Union[GHDependabot, GHSecret]]:
    """Parse a string and return a list of GHDependabots and/or GHSecrets"""
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
