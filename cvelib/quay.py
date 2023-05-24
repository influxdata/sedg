#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import copy
from datetime import datetime
import json
import os
import requests
import sys
from typing import Any, Dict, List, Optional

from cvelib.common import error, warn
from cvelib.net import requestGetRaw
from cvelib.scan import ScanOCI, getScanOCIsReport


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


def getQuayOCIsForOrg(namespace: str) -> List[str]:
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


# def _getQuayRepo(namespace: str, name: str, tagsearch: str = "") -> str:
def getQuayDigestForImage(repo_full: str) -> str:
    """Obtain the list of Quay repos for the specified namespace"""
    if "/" not in repo_full:
        error("please use ORG/NAME", do_exit=False)
        return ""

    ns: str = ""
    name: str = ""
    tagsearch: str = ""
    ns, name = repo_full.split("/", 2)
    if ":" in name:
        name, tagsearch = name.split(":", 2)

    repo: str = "%s/%s" % (ns, name)
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


# {
#   "status": "scanned",
#   "data": {
#     "Layer": {
#       "Features": [
#         {
#           "Name": "<component name>",
#           "Version": "<affected version>",
#           "Vulnerabilities": [
#             {
#               "Severity": "...",
#               "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-...",
#               "FixedBy": "<fixed version>",
#               "MetaData":
#                 {
#                   "RepoName": "...",
#                   "DistroName": "...",
#                   "DistroVersion": "...",
#                 },
#               ...
def parse(resj: Dict[str, Any], url_prefix: str) -> List[ScanOCI]:
    """Parse report JSON and return a list of ScanOCIs"""
    ocis: List[ScanOCI] = []

    for feature in resj["data"]["Layer"]["Features"]:
        scan_data: Dict[str, str] = {}

        if "Name" not in feature:
            warn("Could not find 'Name' in %s" % feature)
            continue
        elif "Version" not in feature:
            warn("Could not find 'Version' in %s" % feature)
            continue
        elif "Vulnerabilities" not in feature:
            warn("Could not find 'Vulnerabilities' in %s" % feature)
            continue

        # One ScanOCI per vuln
        for v in feature["Vulnerabilities"]:
            scan_data["component"] = feature["Name"]
            scan_data["version"] = feature["Version"]
            scan_data["url"] = "%s?tab=vulnerabilities" % url_prefix

            status: str = "needed"
            if v["FixedBy"] == "" or v["FixedBy"] == "0:0":
                status = "needs-triage"
            elif v["FixedBy"] == feature["Version"]:
                # TODO: >= (needs dpkg, rpm, alpine, etc)
                status = "released"
            scan_data["status"] = status

            # detectedIn
            detectedIn: str = "unknown"
            if "MetaData" in v:
                if (
                    "RepoName" in v["Metadata"]
                    and v["Metadata"]["RepoName"] is not None
                ):
                    detectedIn = "%s" % v["Metadata"]["RepoName"]
                elif (
                    "DistroName" in v["Metadata"]
                    and v["Metadata"]["DistroName"] is not None
                ):
                    detectedIn = "%s" % v["Metadata"]["DistroName"]
                    if (
                        "DistroVersion" in v["Metadata"]
                        and v["Metadata"]["DistroVersion"] is not None
                    ):
                        detectedIn += " %s" % v["Metadata"]["DistroVersion"]
            scan_data["detectedIn"] = detectedIn

            # severity
            severity: str = "unknown"
            if "Severity" in v:
                severity = v["Severity"].lower()
            scan_data["severity"] = severity

            # fixedBy
            fixedBy = "unavailable"
            if v["FixedBy"] != "" and v["FixedBy"] != "0:0":
                fixedBy = v["FixedBy"]
            scan_data["fixedBy"] = fixedBy

            # adv url
            adv: str = "unknown"
            if "Link" in v:
                # Link may be a space-separated list
                adv = v["Link"].split()[0]
            scan_data["advisory"] = adv

            ocis.append(ScanOCI(scan_data))

    return ocis


def getQuaySecurityReport(
    repo_full: str, raw: Optional[bool] = False, fixable: Optional[bool] = False
) -> str:
    """Obtain the security manifest for the specified repo@sha256:..."""
    if "/" not in repo_full or "@sha256:" not in repo_full:
        error("please use ORG/NAME@sha256:<sha256>", do_exit=False)
        return ""

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

    url_prefix: str = "https://quay.io/repository/%s/manifest/%s" % (repo, sha256)

    ocis: List[ScanOCI] = parse(resj, url_prefix)
    s: str = getScanOCIsReport(ocis, fixable=fixable)
    return s
