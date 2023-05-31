#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import copy
import datetime
import json
import os
import re
import textwrap
from typing import Any, Dict, List, Union
from yaml import load, CSafeLoader

from cvelib.common import CveException, rePatterns, error, warn, _experimental
from cvelib.net import ghAPIGetList


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
        # https://yaml.org/spec/1.2.2/#chapter-2-language-overview section 5.3,
        # "The '@' (x40, at) and '`' (x60, grave accent) are reserved for
        # future use.". Since they're reserved, just quote them ('@' is common
        # with nodejs dependencies)
        if s.startswith("`"):
            raise CveException(
                "invalid dependabot dependency: %s ('`' is reserved)" % s
            )

        if s.startswith("@"):
            s = '"%s"' % s
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
        if not rePatterns["github-severity"].search(s):
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
    # Note, GitHub doesn't provide a severity for secrets in its json, but we
    # want to assign one for tracking, so we include it here
    required: List[str] = [
        "secret",
        "detectedIn",
        "severity",
        "status",
        "url",
    ]

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        # the prefixed spacing is currently important for onDiskFormat()
        s: str = " - type: secret-scanning\n"
        s += "   secret: %s\n" % self.secret
        s += "   detectedIn: %s\n" % self.detectedIn
        s += "   severity: %s\n" % self.severity
        s += "   status: %s\n" % self.status
        s += "   url: %s" % self.url
        return s

    def __init__(self, data: Dict[str, str]) -> None:
        self.secret: str = ""
        self.detectedIn: str = ""
        self.severity: str = ""
        self.status: str = ""
        self.url: str = ""

        self._verifyRequired(data)

        self.setSecret(data["secret"])
        self.setDetectedIn(data["detectedIn"])
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
    def setSecret(self, s: str) -> None:
        """Set secret"""
        self.secret = s

    def setDetectedIn(self, s: str) -> None:
        """Set detectedIn"""
        self.detectedIn = s

    def setSeverity(self, s: str) -> None:
        """Set severity"""
        if not rePatterns["github-severity"].search(s):
            raise CveException("invalid secret severity: %s" % s)
        self.severity = s

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


class GHCode(object):
    required: List[str] = [
        "description",
        "detectedIn",
        "severity",
        "status",
        "url",
    ]

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        # the prefixed spacing is currently important for onDiskFormat()
        s: str = " - type: code-scanning\n"
        s += "   description: %s\n" % self.description
        s += "   detectedIn: %s\n" % self.detectedIn
        s += "   severity: %s\n" % self.severity
        s += "   status: %s\n" % self.status
        s += "   url: %s" % self.url
        return s

    def __init__(self, data: Dict[str, str]) -> None:
        self.description: str = ""
        self.detectedIn: str = ""
        self.severity: str = ""
        self.status: str = ""
        self.url: str = ""

        self._verifyRequired(data)

        self.setDescription(data["description"])
        self.setDetectedIn(data["detectedIn"])
        self.setStatus(data["status"])
        self.setSeverity(data["severity"])
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
    def setDescription(self, s: str) -> None:
        """Set description"""
        self.description = s

    def setDetectedIn(self, s: str) -> None:
        """Set detectedIn"""
        self.detectedIn = s

    def setSeverity(self, s: str) -> None:
        """Set severity"""
        if not rePatterns["github-severity"].search(s):
            raise CveException("invalid code severity: %s" % s)
        self.severity = s

    def setStatus(self, s: str) -> None:
        """Set status"""
        if not rePatterns["github-code-status"].search(s):
            if "dismissed" in s:
                raise CveException(
                    "invalid code status: %s. Use 'dismissed (false-positive|used-in-tests|wont-fix; <github username>)"
                    % s
                )
            raise CveException(
                "invalid code status: %s. Use 'needs-triage|needed|released|dismissed (...)'"
                % s
            )
        self.status = s

    def setUrl(self, s: str) -> None:
        """Set url"""
        if not rePatterns["github-code-alert"].search(s):
            raise CveException("invalid code alert url: %s" % s)
        self.url = s


def _isNonEmptyStr(s: str) -> bool:
    """Check if string is non-empty"""
    return s != ""


def parse(s: str) -> List[Union[GHDependabot, GHSecret, GHCode]]:
    """Parse a string and return a list of GHDependabots, GHSecrets and/or GHCodes"""
    if s == "":
        return []

    yml: List[Dict[str, str]]
    try:
        # Use yaml.load(s, Loader=yaml.CSafeLoader) instead of
        # yaml.safe_load(s) since the C implementation is so much faster
        # yml = yaml.load(s, Loader=yaml.CSafeLoader)
        yml = load(s, Loader=CSafeLoader)
    except Exception:
        if s is not None and " - type: dependabot\n   dependency: @" in s:
            raise CveException("invalid yaml: uses unquoted 'dependency: @...'")
        raise CveException("invalid yaml:\n'%s'" % s)

    ghas: List[Union[GHDependabot, GHSecret, GHCode]] = []
    for item in yml:
        if "type" not in item:
            raise CveException("invalid GHAS document: 'type' missing for item")

        if item["type"] == "dependabot":
            ghas.append(GHDependabot(item))
        elif item["type"] == "secret-scanning":
            ghas.append(GHSecret(item))
        elif item["type"] == "code-scanning":
            ghas.append(GHCode(item))
        else:
            raise CveException(
                "invalid GHAS document: unknown GHAS type '%s'" % item["type"]
            )

    return ghas


#
# CLI mains
#
def main_dump_alerts():
    # EXPERIMENTAL: this is subject to change
    _experimental()

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="gh-dump-alerts",
        description="Fetch alerts and save locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
gh-dump-alerts pulls GitHub security alerts for repos in the GitHub org and
outputs them to:

  /path/to/alerts/YY/MM/DD/ALERT_TYPE/ORG/REPO/ALERT_NUM.json

Eg, to pull all GitHub security alerts for org 'foo':

  $ gh-dump-alerts --path /path/to/alerts --org foo

Optionally specify a particular alert type:

  $ gh-dump-alerts --path /path/to/alerts --org foo --alert-type dependabot
        """
        ),
    )
    parser.add_argument(
        "-p",
        "--path",
        dest="path",
        type=str,
        help="local PATH to save alerts",
        default=None,
        required=True,
    )
    parser.add_argument(
        "--org",
        dest="org",
        type=str,
        help="GitHub ORG",
        default=None,
        required=True,
    )
    parser.add_argument(
        "--alert-type",
        default=None,
        dest="alert_type",
        help="alert type to fetch. If omitted, default to all",
        type=str,
        choices=["code-scanning", "dependabot", "secret-scanning"],
    )

    args: argparse.Namespace = parser.parse_args()

    if "GHTOKEN" not in os.environ:  # pragma: nocover
        error("Please export GitHub personal access token as GHTOKEN")

    alert_types: List[str] = ["code-scanning", "secret-scanning", "dependabot"]
    if args.alert_type is not None:
        alert_types = [args.alert_type]

    jsons: Dict[str, List[Any]] = {}
    for alert_type in alert_types:
        _, tmp = ghAPIGetList(
            "https://api.github.com/orgs/%s/%s/alerts" % (args.org, alert_type)
        )
        if alert_type not in jsons:
            jsons[alert_type] = []
        jsons[alert_type] += copy.deepcopy(tmp)

    dir: str = args.path
    if not os.path.exists(dir):
        os.mkdir(dir)
    if not os.path.isdir(dir):  # pragma: nocover
        error("'%s' is not a directory" % dir)

    for alert_type in jsons:
        for j in jsons[alert_type]:
            # GitHub API should guarantee this...
            ok = True
            for i in ["created_at", "number", "repository"]:
                if i not in j:
                    warn("Could not find '%s' in: %s" % (i, j))
                    ok = False
            if not ok:
                continue

            if "name" not in j["repository"]:
                warn("Could not find 'name' in: %s" % j["repository"])
                continue

            # create the directory hierarchy as we go
            dobj = datetime.datetime.strptime(j["created_at"], "%Y-%m-%dT%H:%M:%S%z")
            dir = args.path
            for subdir in [
                str(dobj.year),
                str(dobj.month),
                str(dobj.day),
                alert_type,
                args.org,
                j["repository"]["name"],
            ]:
                dir = os.path.join(dir, subdir)
                if not os.path.exists(dir):
                    os.mkdir(dir)
                if not os.path.isdir(dir):  # pragma: nocover
                    error("'%s' is not a directory" % dir)

            created: bool = False
            fn = os.path.join(dir, "%d.json" % j["number"])
            if not os.path.exists(fn):
                with open(fn, "w") as fh:
                    print("Created: %s" % os.path.relpath(fn, args.path))
                    json.dump(j, fh, indent=2)
                    # json.dump() doesn't put a newline at the end, so add it
                    fh.seek(os.SEEK_SET, os.SEEK_END)
                    fh.write("\n")
                    created = True
            if not os.path.isfile(fn):
                warn("'%s' is not a file" % os.path.relpath(fn, args.path))
                continue

            # if the updated_at in the existing file is earlier than
            # updated_at of the downloaded alert, update the file
            if not created and "updated_at" in j:
                with open(fn, "r") as fh:
                    orig = json.load(fh)
                updated_orig = datetime.datetime.strptime(
                    orig["updated_at"], "%Y-%m-%dT%H:%M:%S%z"
                )
                updated_cur = datetime.datetime.strptime(
                    j["updated_at"], "%Y-%m-%dT%H:%M:%S%z"
                )

                if updated_cur > updated_orig:
                    os.unlink(fn)
                    with open(fn, "w") as fh:
                        print("Updated: %s" % os.path.relpath(fn, args.path))
                        json.dump(j, fh, indent=2)
                        # json.dump() doesn't put a newline at the end, so add
                        # it
                        fh.seek(os.SEEK_SET, os.SEEK_END)
                        fh.write("\n")
