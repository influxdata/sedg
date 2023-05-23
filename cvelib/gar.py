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
from typing import Any, Dict, List, Optional

from cvelib.common import error, warn, rePatterns, _experimental
from cvelib.net import requestGetRaw
from cvelib.scan import ScanOCI


def _createGARHeaders() -> Dict[str, str]:
    """Create request headers for a GAR request"""
    if "GCLOUD_TOKEN" not in os.environ:
        error(
            "Please export either GCLOUD_TOKEN (eg: export GCLOUD_TOKEN=$(gcloud auth print-access-token)"
        )

    headers: Dict[str, str] = {}
    if "GCLOUD_TOKEN" in os.environ:
        headers["Authorization"] = "Bearer %s" % os.environ["GCLOUD_TOKEN"]

    return copy.deepcopy(headers)


# https://cloud.google.com/artifact-registry/docs/reference/rest
# https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories/list
def _getGARRepos(project: str, location: str) -> List[str]:
    """Obtain the list of GAR repos for the specified project and location"""
    url: str = (
        "https://artifactregistry.googleapis.com/v1/projects/%s/locations/%s/repositories"
        % (project, location)
    )
    headers: Dict[str, str] = _createGARHeaders()
    params: Dict[str, str] = {"pageSize": "1000"}

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
            warn("Could not fetch %s (%d)" % (url, r.status_code))
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

        if "nextPageToken" not in resj:
            if sys.stdout.isatty():
                print(" done!")
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    return copy.deepcopy(repos)


# https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.dockerImages
def _getGAROCIs(project: str, location: str) -> List[str]:
    """Obtain the list of GAR OCIs for the specified project and location"""
    repos: List[str] = _getGARRepos(project, location)
    ocis: List[str] = []
    for repo in repos:
        tmp: List[str] = _getGAROCIForRepo(project, location, repo.split("/")[-1])
        oci: str = ""
        for oci in tmp:
            ocis.append("%s/%s" % (repo, oci))

    return sorted(ocis)


def _getGAROCIForRepo(project: str, location: str, repo: str) -> List[str]:
    """Obtain the list of GAR OCIs for the specified project, location and repo"""
    url: str = (
        "https://artifactregistry.googleapis.com/v1/projects/%s/locations/%s/repositories/%s/dockerImages"
        % (project, location, repo)
    )
    headers: Dict[str, str] = _createGARHeaders()
    params: Dict[str, str] = {"pageSize": "1000"}

    ocis: List[str] = []
    while True:
        try:
            r: requests.Response = requestGetRaw(url, headers=headers, params=params)
        except requests.exceptions.RequestException as e:
            warn("Skipping %s (request error: %s)" % (url, str(e)))
            return []

        if r.status_code >= 300:
            warn("Could not fetch %s (%d)" % (url, r.status_code))
            return []

        resj = r.json()
        if "dockerImages" not in resj:
            warn("Could not find 'dockerImages' in response: %s" % resj)
            return []

        for img in resj["dockerImages"]:
            if "name" not in img:
                continue

            name: str = img["name"].split("/")[-1].split("@")[0]
            if name not in ocis:
                ocis.append(name)

        if "nextPageToken" not in resj:
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    return ocis


# https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.dockerImages
# XXX: can we filter here?
def _getGARRepo(repo_full: str) -> str:
    """Obtain the GAR digest for the specified project, location and repo"""
    project, location, repo, name = repo_full.split("/", 4)
    tagsearch: str = ""
    if ":" in name:
        name, tagsearch = name.split(":", 2)

    url: str = (
        "https://artifactregistry.googleapis.com/v1/projects/%s/locations/%s/repositories/%s/dockerImages"
        % (project, location, repo)
    )
    headers: Dict[str, str] = _createGARHeaders()
    params: Dict[str, str] = {"pageSize": "1000"}

    digest: str = ""
    latest_d: Optional[datetime] = None
    while True:
        try:
            r: requests.Response = requestGetRaw(url, headers=headers, params=params)
        except requests.exceptions.RequestException as e:
            warn("Skipping %s (request error: %s)" % (url, str(e)))
            return ""

        if r.status_code >= 300:
            warn("Could not fetch %s (%d)" % (url, r.status_code))
            return ""

        resj = r.json()
        if "dockerImages" not in resj:
            warn("Could not find 'dockerImages' in response: %s" % resj)
            return ""

        for img in resj["dockerImages"]:
            if "tags" not in img or len(img["tags"]) == 0:
                continue

            if "name" not in img or not img["name"].split("/")[-1].startswith(
                "%s@" % name
            ):
                continue

            # if searching by tag, just return the first one
            if tagsearch != "":
                for t in img["tags"]:
                    if tagsearch in t:
                        return img["name"]
            elif "updateTime" in img:
                # 2022-10-24T19:09:15.357727Z. Discard 'Z' since %Z doesn't
                # work reliably, so just strip it off (it is in UTC anyway)
                # https://bugs.python.org/issue22377
                cur: datetime = datetime.strptime(
                    img["updateTime"][:-1], "%Y-%m-%dT%H:%M:%S.%f"
                )
                if latest_d is None or cur > latest_d:
                    latest_d = cur
                    digest = img["name"]

        if "nextPageToken" not in resj:
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    return digest


# {
#   "occurrences": [
#     {
#       "resourceUri": "https://LOCATION-docker.pkg.dev/PROJECT/REPO/IMGNAME@sha256...",
#       "vulnerability": {
#         "severity": "...",
#         "packageIssue": [
#           {
#             "packageType": "OS|GO_STDLIB",
#             "affectedCpeUri": "<detectedIn for OS>",
#             "affectedPackage": "<component name>",
#             "affectedVersion": {
#               "fullName": "<affected version>",
#               ...
#             },
#             "fixedVersion": {
#               "fullName": "<fixed version>",
#               ...
#             },
#             "fileLocation": [
#               {
#                 "filePath": "<detectedIn of GO_STDLIB>",
#               },
#               ...
#             ],
#             ...
#           },
#           ...
#         ],
#         "shortDescription": "<if CVE..., used for advisory url>",
#         ...
#       },
#       ...
#     },
#     ...
#   ]
# }
def parse(vulns: List[Dict[str, Any]]) -> List[ScanOCI]:
    """Parse report JSON and return a list of ScanOCIs"""
    # Parse 'notes' (vulnerabilities)
    # https://cloud.google.com/container-analysis/docs/reference/rest/v1/projects.notes#Note
    # https://cloud.google.com/container-analysis/docs/reference/rest/v1/projects.notes#VulnerabilityNote

    ocis: List[ScanOCI] = []

    # createTime, updateTime
    for v in vulns:
        scan_data: Dict[str, str] = {}

        if "vulnerability" not in v:
            warn("Could not find 'vulnerability' in %s" % v)
            continue

        # https://cloud.google.com/container-analysis/docs/reference/rest/v1/projects.notes#Detail
        # 'details' is not a thing in v1 and instead it is listed as
        # 'packageIssue'). XXX: look for 'details' and 'windowsDetails'?
        details_key: str = "packageIssue"
        if details_key not in v["vulnerability"]:
            warn("Could not find '%s' in %s" % (v["vulnerability"], details_key))
            continue
        if len(v["vulnerability"][details_key]) == 0:
            warn("'%s' is empty in %s" % (details_key, v["vulnerability"]))
            continue

        # XXX: just use the first issue for now (anecdotally, seems to always
        # only be a list of 1 anyway)
        iss: Dict[str, Any] = v["vulnerability"][details_key][0]

        if iss["packageType"] not in ["OS", "GO_STDLIB"]:
            warn("unrecognized packageType '%s'" % iss["packageType"])
            continue

        if "affectedPackage" not in iss:
            warn("Could not find 'affectedPackage' in %s" % iss)
            continue

        scan_data["component"] = iss["affectedPackage"]
        scan_data["version"] = iss["affectedVersion"]["fullName"]
        scan_data["url"] = v["resourceUri"]

        # status
        status: str = "needed"
        if "fixedVersion" in iss:
            if "fullName" not in iss["fixedVersion"]:
                status = "needs-triage"
            elif iss["fixedVersion"] == iss["affectedVersion"]:
                status = "released"
        scan_data["status"] = status

        # detectedIn
        detectedIn: str = "unknown"
        if iss["packageType"] == "OS":
            detectedIn = iss["affectedCpeUri"]
        elif iss["packageType"] == "GO_STDLIB":
            if "fileLocation" in iss and len(iss["fileLocation"]) > 0:
                detectedIn = iss["fileLocation"][0]
        scan_data["detectedIn"] = detectedIn

        # severity - prefer distro severity over CVE priority
        severity: str = "unknown"
        if "effectiveSeverity" in iss:
            severity = iss["effectiveSeverity"].lower()
        elif "severity" in v["vulnerability"]:
            severity = v["vulnerability"]["severity"].lower()
        scan_data["severity"] = severity

        # fixedBy
        fixedBy: str = "unknown"
        if "fixedVersion" in iss and "fullName" in iss["fixedVersion"]:
            fixedBy = iss["fixedVersion"]["fullName"]
        scan_data["fixedBy"] = fixedBy

        # adv url
        adv: str = "unknown"
        if rePatterns["CVE"].search(v["vulnerability"]["shortDescription"]):
            adv = (
                "https://www.cve.org/CVERecord?id=%s"
                % v["vulnerability"]["shortDescription"]
            )
        scan_data["advisory"] = adv

        ocis.append(ScanOCI(scan_data))

    return ocis


# https://cloud.google.com/container-analysis/docs/investigate-vulnerabilities
# https://cloud.google.com/container-analysis/docs/reference/rest
def _getGARSecurityManifest(
    repo_full: str,
    raw: Optional[bool] = False,
    fixable: Optional[bool] = False,
) -> str:
    """Obtain the security manifest for the specified repo@sha256:..."""
    project, location, repo, name = repo_full.split("/", 4)

    url: str = (
        "https://containeranalysis.googleapis.com/v1/projects/%s/occurrences" % project
    )
    resource_url: str = "https://%s-docker.pkg.dev/%s/%s/%s" % (
        location,
        project,
        repo,
        name,
    )
    headers: Dict[str, str] = _createGARHeaders()
    headers["Content-Type"] = "application/json"
    params: Dict[str, str] = {
        "filter": '(kind="VULNERABILITY" AND resourceUrl="%s")' % resource_url,
    }

    # the v1 format is (<noteN> is a vulnerability note):
    # {
    #   "occurrences": [
    #     { note1 },
    #     { note2 },
    #   ],
    #   "nextPageToken": "..."
    # }
    #
    # Create a list of dictionaries with all the different pages added to a
    # single list
    vulns: List[Dict[str, Any]] = []
    while True:
        try:
            r: requests.Response = requestGetRaw(url, headers=headers, params=params)
        except requests.exceptions.RequestException as e:
            warn("Skipping %s (request error: %s)" % (url, str(e)))
            return ""

        if r.status_code >= 300:
            warn("Could not fetch %s" % url)
            return ""

        resj = r.json()
        if "occurrences" not in resj:
            error("Could not find 'occurrences' in response: %s" % resj)

        vulns += resj["occurrences"]

        if "nextPageToken" not in resj:
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    # If raw format, output a unified JSON document that has all the
    # vulns in one doc but otherwise looks like that the API returned
    if raw:
        return "%s" % json.dumps({"occurrences": vulns})

    # parse the vulns into ScanOCIs and then group them for the report
    max_name: int = 0
    max_vers: int = 0
    grouped = {}
    for i in parse(vulns):
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


#
# CLI mains
#
def main_gar_report():
    # EXPERIMENTAL: this script and APIs subject to change
    _experimental()

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="gar-report",
        description="Generate reports on security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
Example usage:

# List all repos for the 'foo' PROJECT and 'us' LOCATION
$ gar-report --list-repos foo/us
bar
baz

# List all OCIs for the 'foo' PROJECT and 'us' LOCATION
$ gar-report --list-ocis foo/us
bar/norf
bar/corge
baz/qux

# Get the latest digest for the 'foo' PROJECT, 'us' LOCATION, 'bar'
# repository and 'norf' image name
$ gar-report --get-repo-latest-digest foo/us/bar/norf
norf@sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03

# Get the latest digest for the 'foo' PROJECT, 'us' LOCATION, 'bar' repository
# and 'norf' image name with a particular tag
$ gar-report --get-repo-latest-digest foo/us/bar/norf:some-tag
norf@sha256:4993b5edd6b6f0b8361b85ba34f0c3595f95be62d086634247eca5982c8a8b26

# Get the security report for the 'foo' PROJECT, 'us' LOCATION, 'bar'
# repository, norf image name with a specific digest
$ gar-report --get-security-manifest foo/us/bar/norf@sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
        """
        ),
    )
    parser.add_argument(
        "--list-repos",
        dest="list_repos",
        type=str,
        help="output GAR repos for PROJECT/LOCATION",
        default=None,
    )
    parser.add_argument(
        "--list-ocis",
        dest="list_ocis",
        type=str,
        help="output GAR OCIs for PROJECT/LOCATION",
        default=None,
    )
    parser.add_argument(
        "--get-repo-latest-digest",
        dest="get_repo_latest_digest",
        type=str,
        help="output GAR repo digest for PROJECT/LOCATION/REPO/IMGNAME",
        default=None,
    )
    parser.add_argument(
        "--get-security-manifest",
        dest="get_security_manifest",
        type=str,
        help="output GAR security report for PROJECT/LOCATION/REPO/IMGNAME@sha256:<sha256>",
        default=None,
    )
    parser.add_argument(
        "--get-security-manifest-raw",
        dest="get_security_manifest_raw",
        type=str,
        help="output GAR raw security report for PROJECT/LOCATION/REPO/IMGNAME@sha256:<sha256>",
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
        if "/" not in args.list_repos:
            error("please use PROJECT/LOCATION")

        proj, loc = args.list_repos.split("/", 2)
        repos: List[str] = _getGARRepos(proj, loc)
        for r in sorted(repos):
            print(r.split("/")[-1])  # trim off the proj/loc
    elif args.list_ocis:
        if "/" not in args.list_ocis:
            error("please use PROJECT/LOCATION")

        proj, loc = args.list_ocis.split("/", 2)
        repos: List[str] = _getGAROCIs(proj, loc)
        for r in sorted(repos):
            print(r.split("/", maxsplit=5)[-1])  # trim off the proj/loc
    elif args.get_repo_latest_digest:
        if (
            "/" not in args.get_repo_latest_digest
            or args.get_repo_latest_digest.count("/") != 3
        ):
            error("please use PROJECT/LOCATION/REPO/IMGNAME")
        digest: str = _getGARRepo(args.get_repo_latest_digest)
        print(digest.split("/")[-1])  # trim off the proj/loc/repo
    elif args.get_security_manifest or args.get_security_manifest_raw:
        arg: str
        raw: bool = False
        if args.get_security_manifest:
            arg = args.get_security_manifest
        else:
            arg = args.get_security_manifest_raw
            raw = True

        if "/" not in arg or arg.count("/") != 3 or "@sha256:" not in arg:
            error("please use PROJECT/LOCATION/REPO/IMGNAME@sha256:<sha256>")

        s: str = _getGARSecurityManifest(arg, raw=raw, fixable=args.fixable)
        print(s)
