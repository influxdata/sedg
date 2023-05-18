#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import copy
from datetime import datetime
import json
import os
import requests
import sys
import textwrap
from typing import Dict, List, Optional

from cvelib.common import (
    error,
    warn,
    _experimental,
)
from cvelib.net import requestGetRaw


def _createQuayHeaders() -> Dict[str, str]:
    """Create request headers for a Quay.io request"""
    if "QUAY_COOKIE" not in os.environ and "QUAY_TOKEN" not in os.environ:
        error("Please export either QUAY_COOKIE or QUAY_TOKEN")

    headers: Dict[str, str] = {}
    if "QUAY_COOKIE" in os.environ:
        headers["cookie"] = os.environ["QUAY_COOKIE"]
    elif "QUAY_TOKEN" in os.environ:
        headers["Authorization"] = "Bearer %s" % os.environ["QUAY_TOKEN"]

    return copy.deepcopy(headers)


# https://docs.quay.io/api/swagger


def _getQuayRepos(namespace: str) -> List[str]:
    """Obtain the list of Quay repos for the specified namespace"""
    url: str = "https://quay.io/api/v1/repository"
    headers: Dict[str, str] = _createQuayHeaders()
    params: Dict[str, str] = {
        "namespace": namespace,
        "last_modified": "true",
    }

    repos: List[str] = []

    if sys.stdout.isatty():
        print("Fetching list of repos: ", end="", flush=True)
    while True:
        if sys.stdout.isatty():
            print(".", end="", flush=True)

        try:
            r: requests.Response = requestGetRaw(url, headers=headers, params=params)
        except requests.exceptions.RequestException as e:
            warn("Skipping %s (request error: %s)" % (url, str(e)))
            return []

        if r.status_code >= 300:
            warn("Could not fetch %s" % url)
            return []

        resj = r.json()
        if "repositories" not in resj:
            warn("Could not find 'repositories' in response: %s" % resj)
            return []

        for repo in resj["repositories"]:
            if "name" not in repo:
                warn("Could not find 'name' in response for repo: %s" % repo)
                continue

            name: str = repo["name"]
            if name not in repos:
                repos.append(repo["name"])

        if "next_page" not in resj:
            if sys.stdout.isatty():
                print(" done!")
            break

        params["next_page"] = resj["next_page"]

    return copy.deepcopy(repos)


def _getQuayRepo(namespace: str, name: str, tagsearch: str = "") -> str:
    """Obtain the list of Quay repos for the specified namespace"""
    repo: str = "%s/%s" % (namespace, name)
    url: str = "https://quay.io/api/v1/repository/%s" % repo
    headers: Dict[str, str] = _createQuayHeaders()
    params: Dict[str, str] = {"includeTags": "true"}

    try:
        r: requests.Response = requestGetRaw(url, headers=headers, params=params)
    except requests.exceptions.RequestException as e:
        warn("Skipping %s (request error: %s)" % (url, str(e)))
        return ""

    if r.status_code >= 300:
        warn("Could not fetch %s" % url)
        return ""

    resj = r.json()
    if "tags" not in resj:
        warn("Could not find 'tags' in response: %s" % resj)
        return ""

    if len(resj["tags"]) == 0:
        warn("No 'tags' found for %s" % repo)
        return ""

    digest: str = ""
    if tagsearch != "" and tagsearch in resj["tags"]:
        digest = resj["tags"][tagsearch]["manifest_digest"]

    if digest == "":
        latest_d: Optional[datetime] = None
        for tag in resj["tags"]:
            if "last_modified" not in resj["tags"][tag]:
                warn(
                    "Could not find 'last_modified' in response: %s" % resj["tags"][tag]
                )
                return ""

            cur: datetime = datetime.strptime(
                resj["tags"][tag]["last_modified"], "%a, %d %b %Y %H:%M:%S %z"
            )
            if latest_d is None or cur > latest_d:
                latest_d = cur
                digest = resj["tags"][tag]["manifest_digest"]

    return digest


# TODO: document the format
def _getQuaySecurityManifest(
    repo_full: str, raw: Optional[bool] = False, fixable: Optional[bool] = False
) -> str:
    """Obtain the security manifest for the specified repo@sha256:..."""
    repo: str
    sha256: str
    if repo_full.count("@") == 0:
        error("Please specify <namespace>/<repo>@sha256:<sha256>")

    repo, sha256 = repo_full.split("@", 2)
    url: str = "https://quay.io/api/v1/repository/%s/manifest/%s/security" % (
        repo,
        sha256,
    )
    headers: Dict[str, str] = _createQuayHeaders()
    params: Dict[str, str] = {"vulnerabilities": "true"}

    try:
        r: requests.Response = requestGetRaw(url, headers=headers, params=params)
    except requests.exceptions.RequestException as e:
        warn("Skipping %s (request error: %s)" % (url, str(e)))
        return ""

    if r.status_code >= 300:
        warn("Could not fetch %s" % url)
        return ""

    resj = r.json()
    if raw:
        return json.dumps(resj)

    if "status" not in resj:
        error("Cound not find 'status' in response: %s" % resj)
    elif resj["status"] != "scanned":
        error("Could not process report due to status: %s" % resj["status"])

    if "data" not in resj:
        error("Could not find 'data' in %s" % resj)
    elif resj["data"] is None:
        error("Could not process report due to no data in %s" % resj)

    if "Layer" not in resj["data"]:
        error("Could not find 'Layer' in %s" % resj["data"])
    if "Features" not in resj["data"]["Layer"]:
        error("Could not find 'Features' in %s" % resj["data"]["Layer"])

    features: Dict[str, Dict[str, str]] = {}
    max_name: int = 0
    max_vers: int = 0
    for feature in resj["data"]["Layer"]["Features"]:
        if "Name" not in feature:
            error("Could not find 'Name' in %s" % feature)
        elif "Version" not in feature:
            error("Could not find 'Version' in %s" % feature)
        elif "Vulnerabilities" not in feature:
            error("Could not find 'Vulnerabilities' in %s" % feature)

        features[feature["Name"]] = {"version": feature["Version"]}

        if len(feature["Name"]) > max_name:
            max_name = len(feature["Name"])
        if len(feature["Version"]) > max_vers:
            max_vers = len(feature["Version"])

        # n/a, unavailable, needed, released
        severities: List[str] = []
        statuses: List[str] = []

        for vuln in feature["Vulnerabilities"]:
            if vuln["FixedBy"] == "":
                s = "unavailable"
            elif (
                vuln["FixedBy"] == feature["Version"]
            ):  # TODO: >= (needs dpkg, rpm, alpine, etc)
                s = "released"
            else:
                s = "needed"

            if s not in statuses:
                statuses.append(s)

            if vuln["Severity"].lower() not in severities:
                severities.append(vuln["Severity"].lower())

        # XXX: clean this up
        status = "n/a"
        if "needed" in statuses:
            status = "needed"
        elif "unavailable" in statuses:
            status = "unavailable"
        elif "released" in statuses:
            status = "released"

        if len(severities) > 0:
            status += " (%s)" % ",".join(sorted(severities))
        features[feature["Name"]]["status"] = status

    tableStr: str = "{name:%d} {vers:%d} {status}" % (max_name, max_vers)
    table_f: object = tableStr.format
    s: str = ""
    for f in sorted(features.keys()):
        if fixable and "needed" not in features[f]["status"]:
            continue
        s += (
            table_f(name=f, vers=features[f]["version"], status=features[f]["status"])
            + "\n"
        )
    return s.rstrip()


#
# CLI mains
#
def main_quay_report():
    # EXPERIMENTAL: this script and APIs subject to change
    _experimental()

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="quay-report",
        description="Generate reports on security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
Example usage:

$ quay-report
...
        """
        ),
    )
    parser.add_argument(
        "--list-repos",
        dest="list_repos",
        type=str,
        help="output quay.io repos for ORG",
        default=None,
    )
    parser.add_argument(
        "--get-repo-latest-digest",
        dest="get_repo_latest_digest",
        type=str,
        help="output quay.io repo digest for ORG/REPO",
        default=None,
    )
    parser.add_argument(
        "--get-security-manifest",
        dest="get_security_manifest",
        type=str,
        help="output quay.io security report for ORG/REPO@sha256:SHA256",
        default=None,
    )
    parser.add_argument(
        "--get-security-manifest-raw",
        dest="get_security_manifest_raw",
        type=str,
        help="output quay.io raw security report for ORG/REPO@sha256:SHA256",
        default=None,
    )
    parser.add_argument(
        "--fixable",
        dest="fixable",
        help="show only fixables issues",
        action="store_true",
    )
    args: argparse.Namespace = parser.parse_args()

    # send to a report
    if args.list_repos:
        repos: List[str] = _getQuayRepos(args.list_repos)
        for r in sorted(repos):
            print(r)
    elif args.get_repo_latest_digest:
        ns: str = ""
        name: str = ""
        tag: str = ""
        if "/" not in args.get_repo_latest_digest:
            error("please use ORG/NAME")

        ns, name = args.get_repo_latest_digest.split("/", 2)
        if ":" in name:
            name, tag = name.split(":", 2)
        digest: str = _getQuayRepo(ns, name, tagsearch=tag)
        print(digest)
    elif args.get_security_manifest:
        if "/" not in args.get_security_manifest:
            error("please use ORG/NAME")
        s: str = _getQuaySecurityManifest(
            args.get_security_manifest, fixable=args.fixable
        )
        print("# %s report" % args.get_security_manifest)
        print(s)
    elif args.get_security_manifest_raw:
        if "/" not in args.get_security_manifest_raw:
            error("please use ORG/NAME")
        s: str = _getQuaySecurityManifest(args.get_security_manifest_raw, raw=True)
        print(s)
