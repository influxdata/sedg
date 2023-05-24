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

from cvelib.common import error, warn, rePatterns
from cvelib.net import requestGetRaw
from cvelib.scan import ScanOCI, getScanOCIsReport


def _createGARHeaders() -> Dict[str, str]:
    """Create request headers for a GAR request"""
    if "GCLOUD_TOKEN" not in os.environ:
        error(
            "Please export GCLOUD_TOKEN (eg: export GCLOUD_TOKEN=$(gcloud auth print-access-token)"
        )

    headers: Dict[str, str] = {}
    if "GCLOUD_TOKEN" in os.environ:
        headers["Authorization"] = "Bearer %s" % os.environ["GCLOUD_TOKEN"]

    return copy.deepcopy(headers)


# $ export GCLOUD_TOKEN=$(gcloud auth print-access-token)
# $ curl -H "Content-Type: application/json"
#        -H "Authorization: Bearer $GCLOUD_TOKEN"
#        -G
#        https://artifactregistry.googleapis.com/v1/projects/PROJECT/locations/LOCATION/repositories
# {
#   "repositories": [
#     {
#       "name": "projects/PROJECT/locations/LOCATION/repositories/REPO",
#       "format": "DOCKER",
#       "description": "some description",
#       "labels": {
#         "environment": "blah",
#         "managed": "blah",
#         "owner": "some-team"
#       },
#       "createTime": "2022-09-08T09:37:11.523595Z",
#       "updateTime": "2023-03-15T15:05:30.392141Z",
#       "mode": "STANDARD_REPOSITORY",
#       "sizeBytes": "9210399480"
#     }
#   }
# ]
#
# https://cloud.google.com/artifact-registry/docs/reference/rest
# https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories/list
def getGARReposForProjectLoc(proj_loc: str) -> List[str]:
    """Obtain the list of GAR repos for the specified project and location"""
    if "/" not in proj_loc:
        error("Please use PROJECT/LOCATION", do_exit=False)
        return []
    project, location = proj_loc.split("/", 2)

    url: str = (
        "https://artifactregistry.googleapis.com/v1/projects/%s/locations/%s/repositories"
        % (project, location)
    )
    headers: Dict[str, str] = _createGARHeaders()
    params: Dict[str, str] = {"pageSize": "1000"}

    repos: List[str] = []

    if sys.stdout.isatty():  # pragma: nocover
        print("Fetching list of repos: ", end="", flush=True)

    while True:
        if sys.stdout.isatty():  # pragma: nocover
            print(".", end="", flush=True)

        try:
            r: requests.Response = requestGetRaw(url, headers=headers, params=params)
        except requests.exceptions.RequestException as e:  # pragma: nocover
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
            if sys.stdout.isatty():  # pragma: nocover
                print(" done!")
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    return copy.deepcopy(repos)


# $ export GCLOUD_TOKEN=$(gcloud auth print-access-token)
# $ curl -H "Content-Type: application/json"
#        -H "Authorization: Bearer $GCLOUD_TOKEN"
#        -G https://artifactregistry.googleapis.com/v1/projects/PROJECT/locations/LOCATION/repositories/REPO/packages
# {
#   "packages": [
#     {
#       "name": "projects/PROJECT/locations/LOCATION/repositories/REPO/packages/IMGNAME",
#       "createTime": "2023-04-11T15:07:35.322255Z",
#       "updateTime": "2023-04-11T15:07:35.322255Z"
#     },
#     {
#       "name": "projects/PROJECT/locations/LOCATION/repositories/REPO/packages/IMGNAME",
#       "createTime": "2023-04-11T15:07:35.322255Z",
#       "updateTime": "2023-04-11T15:07:35.322255Z"
#     },
#     ...
#   ]
# }
#
# https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.packages
def getGAROCIForRepo(repo_full: str) -> List[str]:
    """Obtain the list of GAR OCIs for the specified project, location and repo"""
    if "/" not in repo_full or repo_full.count("/") != 2:
        error("Please use PROJECT/LOCATION/REPO", do_exit=False)
        return []

    project, location, repo = repo_full.split("/", 3)
    url: str = (
        "https://artifactregistry.googleapis.com/v1/projects/%s/locations/%s/repositories/%s/packages"
        % (project, location, repo)
    )
    headers: Dict[str, str] = _createGARHeaders()
    params: Dict[str, str] = {"pageSize": "1000"}

    ocis: List[str] = []
    while True:
        try:
            r: requests.Response = requestGetRaw(url, headers=headers, params=params)
        except requests.exceptions.RequestException as e:  # pragma: nocover
            warn("Skipping %s (request error: %s)" % (url, str(e)))
            return []

        if r.status_code >= 300:
            warn("Could not fetch %s (%d)" % (url, r.status_code))
            return []

        resj = r.json()
        if "packages" not in resj:
            warn("Could not find 'packages' in response: %s" % resj)
            return []

        for img in resj["packages"]:
            if "name" not in img:
                continue

            name: str = img["name"].split("/")[-1]
            if name not in ocis:
                ocis.append(name)

        if "nextPageToken" not in resj:
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    return ocis


# $ export GCLOUD_TOKEN=$(gcloud auth print-access-token)
# $ curl -H "Content-Type: application/json"
#        -H "Authorization: Bearer $GCLOUD_TOKEN"
#        -G
#        https://artifactregistry.googleapis.com/v1/projects/PROJECT/locations/LOCATION/repositories/REPO/dockerImages
# {
#   "dockerImages": [
#     {
#       "name":
#       "projects/PROJECT/locations/LOCATION/repositories/REPO/dockerImages/NAME@sha256:SHA256",
#       "uri": "LOCATION-docker.pkg.dev/PROJECT/REPO/NAME@sha256:SHA256",
#       "tags": [
#         "some-tag"
#       ],
#       "imageSizeBytes": "29256171",
#       "uploadTime": "2023-04-24T12:27:36.896655Z",
#       "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
#       "buildTime": "2023-04-24T12:27:31.712824072Z",
#       "updateTime": "2023-04-24T12:27:36.896655Z"
#     },
#     ...
#   ]
# }
#
# https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.dockerImages
def getGARDigestForImage(repo_full: str) -> str:
    """Obtain the GAR digest for the specified project, location and repo"""
    if "/" not in repo_full or repo_full.count("/") != 3:
        error("Please use PROJECT/LOCATION/REPO/IMGNAME", do_exit=False)
        return ""

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
        except requests.exceptions.RequestException as e:  # pragma: nocover
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
            if "name" not in img:
                continue
            elif not img["name"].split("/")[-1].startswith("%s@" % name):
                # NOTE: the v1 API does not have a 'filter' query parameter so
                # we need to fetch all the dockerImages and filter by "name"
                # ourselves
                continue

            # if searching by tag, just return the first one (note, "tags" is
            # optional in the json output)
            if tagsearch != "" and "tags" in img:
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
            warn("Could not find '%s' in %s" % (details_key, v["vulnerability"]))
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
        scan_data["url"] = v["resourceUri"]

        version: str = "unknown"
        if "affectedVersion" in iss and "fullName" in iss["affectedVersion"]:
            version = iss["affectedVersion"]["fullName"]
        scan_data["version"] = version

        # status
        status: str = "needed"
        if "fixedVersion" in iss:
            if "fullName" not in iss["fixedVersion"]:
                status = "needs-triage"
            elif (
                "affectedVersion" in iss
                and "fullName" in iss["affectedVersion"]
                and iss["fixedVersion"]["fullName"]
                == iss["affectedVersion"]["fullName"]
            ):
                status = "released"
        scan_data["status"] = status

        # detectedIn
        detectedIn: str = "unknown"
        if iss["packageType"] == "OS":
            detectedIn = iss["affectedCpeUri"]
        elif iss["packageType"] == "GO_STDLIB":
            if (
                "fileLocation" in iss
                and len(iss["fileLocation"]) > 0
                and "filePath" in iss["fileLocation"][0]
            ):
                detectedIn = iss["fileLocation"][0]["filePath"]
        scan_data["detectedIn"] = detectedIn

        # severity - prefer distro effectiveSeverity over GAR effectiveSeverity
        # over CVE severity
        severity: str = "unknown"
        if "effectiveSeverity" in iss:
            severity = iss["effectiveSeverity"].lower()
        elif "effectiveSeverity" in v["vulnerability"]:
            severity = v["vulnerability"]["effectiveSeverity"].lower()
        elif "severity" in v["vulnerability"]:
            severity = v["vulnerability"]["severity"].lower()
        scan_data["severity"] = severity

        # fixedBy
        fixedBy: str = "unknown"
        if "fixedVersion" in iss and "fullName" in iss["fixedVersion"]:
            fixedBy = iss["fixedVersion"]["fullName"]
        scan_data["fixedBy"] = fixedBy

        # adv url
        adv: str = "unavailable"
        if rePatterns["CVE"].search(v["vulnerability"]["shortDescription"]):
            adv = (
                "https://www.cve.org/CVERecord?id=%s"
                % v["vulnerability"]["shortDescription"]
            )
        scan_data["advisory"] = adv

        ocis.append(ScanOCI(scan_data))

    return ocis


# $ export GCLOUD_TOKEN=$(gcloud auth print-access-token)
# $ curl -H "Content-Type: application/json" \
#        -H "Authorization: Bearer $GCLOUD_TOKEN"
#        -G https://containeranalysis.googleapis.com/v1/projects/PROJECT/occurrences
#        --data-urlencode "filter=(kind=\"VULNERABILITY\" AND resourceUrl=\"https://LOCATION-docker.pkg.dev/PROJECT/REPO/IMGNAME@sha256:SHA256\")"
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
#
# https://cloud.google.com/container-analysis/docs/investigate-vulnerabilities
# https://cloud.google.com/container-analysis/docs/reference/rest
def getGARSecurityReport(
    repo_full: str,
    raw: Optional[bool] = False,
    fixable: Optional[bool] = False,
) -> str:
    """Obtain the security manifest for the specified repo@sha256:..."""
    if "/" not in repo_full or repo_full.count("/") != 3 or "@sha256:" not in repo_full:
        error("Please use PROJECT/LOCATION/REPO/IMGNAME@sha256:<sha256>", do_exit=False)
        return ""

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
        except requests.exceptions.RequestException as e:  # pragma: nocover
            warn("Skipping %s (request error: %s)" % (url, str(e)))
            return ""

        if r.status_code >= 300:
            warn("Could not fetch %s" % url)
            return ""

        resj = r.json()
        if len(resj) == 0 or ("occurrences" in resj and len(resj["occurrences"]) == 0):
            warn("no scan results for image")
            return ""
        elif "occurrences" not in resj:
            error("Could not find 'occurrences' in response: %s" % resj, do_exit=False)
            return ""

        vulns += resj["occurrences"]

        if "nextPageToken" not in resj:
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    # If raw format, output a unified JSON document that has all the
    # vulns in one doc but otherwise looks like that the API returned
    if raw:
        return "%s" % json.dumps({"occurrences": vulns})

    ocis: List[ScanOCI] = parse(vulns)
    s: str = getScanOCIsReport(ocis, fixable=fixable)
    return s


def getGAROCIsForProjectLoc(proj_loc: str) -> List[str]:
    """Obtain the list of GAR OCIs for the specified project and location"""
    if "/" not in proj_loc:
        error("Please use PROJECT/LOCATION", do_exit=False)
        return []

    repos: List[str] = getGARReposForProjectLoc(proj_loc)
    ocis: List[str] = []

    if sys.stdout.isatty():  # pragma: nocover
        print("Fetching list of images for each repo: ", end="", flush=True)

    for repo in repos:
        if sys.stdout.isatty():  # pragma: nocover
            print(".", end="", flush=True)

        tmp: List[str] = getGAROCIForRepo("%s/%s" % (proj_loc, repo.split("/")[-1]))
        oci: str = ""
        for oci in tmp:
            ocis.append("%s/%s" % (repo, oci))

    if sys.stdout.isatty():  # pragma: nocover
        print(" done!")

    return sorted(ocis)
