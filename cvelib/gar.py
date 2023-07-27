#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import copy
import datetime
import hashlib
import json
import os
import requests
import sys
import textwrap
from typing import Any, Dict, List, Tuple

from cvelib.common import error, warn, rePatterns, _sorted_json_deep, _experimental
from cvelib.net import requestGetRaw
from cvelib.scan import ScanOCI, SecurityReportInterface


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
def getGAROCIForRepo(repo_full: str) -> List[Tuple[str, int]]:
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

    ocis: List[Tuple[str, int]] = []
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
            dobj = datetime.datetime.strptime(
                img["updateTime"], "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            if name not in ocis:
                ocis.append((name, int(dobj.strftime("%s"))))

        if "nextPageToken" not in resj:
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    return ocis


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

        if iss["packageType"] not in ["OS", "GO_STDLIB", "NPM", "PYPI"]:
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
        elif iss["packageType"] in ["GO_STDLIB", "NPM", "PYPI"]:
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
#        --data-urlencode "filter=(kind=\"DISCOVERY\" AND resourceUrl=\"https://LOCATION-docker.pkg.dev/PROJECT/REPO/IMGNAME@sha256:SHA256\")"
# {
#   "occurrences": [
#     {
#       "name": "projects/PROJECT/occurrences/aed05ee4-bf2a-43f8-aad6-22b6bca41e01",
#       "resourceUri": "https://LOCATION-docker.pkg.dev/PROJECT/REPO/IMGNAME@sha256:SHA256",
#       "noteName": "projects/goog-analysis/notes/PACKAGE_VULNERABILITY",
#       "kind": "DISCOVERY",
#       "createTime": "2023-03-22T16:11:54.010888Z",
#       "updateTime": "2023-05-06T19:16:00.813976Z",
#       "discovery": {
#         "continuousAnalysis": "INACTIVE",
#         "analysisStatus": "FINISHED_SUCCESS",
#         "analysisCompleted": {
#           "analysisType": [
#             ...
#           ]
#         }
#       }
#     }
#   ]
# }
# https://cloud.google.com/container-analysis/docs/reference/rest
def getGARDiscovery(repo_full: str) -> str:
    """Obtain the container discovery info for the specified repo@sha256:..."""
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
        "filter": '(kind="DISCOVERY" AND resourceUrl="%s")' % resource_url,
    }

    # the v1 format is (<noteN> is a discovery note):
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
    discs: List[Dict[str, Any]] = []
    sr = GARSecurityReportNew()
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
        if len(resj) == 0:
            # does the image exist at all?
            if sr.getDigestForImage(repo_full) == "":
                return "NONEXISTENT"
            return "UNSCANNED"
        elif "occurrences" not in resj or len(resj["occurrences"]) == 0:
            return "invalid json format"

        discs += resj["occurrences"]

        if "nextPageToken" not in resj:
            break

        params["pageToken"] = resj["nextPageToken"]
        # time.sleep(2)  # in case nextPageToken isn't valid yet

    s: str = "reason not detected"
    status: str = ""
    continuous: str = ""

    # just look at the first one for now
    if "discovery" in discs[0] and "analysisStatus" in discs[0]["discovery"]:
        status: str = discs[0]["discovery"]["analysisStatus"]
    if "continuousAnalysis" in discs[0]["discovery"]:
        continuous = discs[0]["discovery"]["continuousAnalysis"]

    # Look for things like:
    # - the image is clean
    # - the image is stale (ie, it hasn't been pulled in 30 days)
    #   https://cloud.google.com/artifact-analysis/docs/enable-container-scanning
    # - the image is unsupported in some way (eg, layers with only
    # application/vnd.dev.cosign.simplesigning.v1+json, etc)
    # - the image hasn't been scanned yet
    if status == "FINISHED_SUCCESS" and continuous == "ACTIVE":
        s = "CLEAN"
    elif status == "FINISHED_SUCCESS" and continuous != "":
        s = continuous
    elif status == "FINISHED_UNSUPPORTED":
        s = "UNSUPPORTED"
    elif status != "":
        s = status

    return s


class GARSecurityReportNew(SecurityReportInterface):
    name = "gar"

    # find all versions
    # $ export GCLOUD_TOKEN=$(gcloud auth print-access-token)
    # $ curl -H "Content-Type: application/json"
    #        -H "Authorization: Bearer $GCLOUD_TOKEN"
    #        -G https://artifactregistry.googleapis.com/v1/projects/PROJECT/locations/LOCATION/repositories/REPO/packages/IMGNAME/versions
    #        --data "orderBy=UPDATE_TIME+desc&view=FULL"
    # {
    #   "versions": [
    #     "name": "projects/PROJECT/locations/LOCATION/repositories/REPO/packages/IMGNAME/versions/sha256:SHA256",
    #      "createTime": "2023-05-30T17:24:37.757487Z",
    #      "updateTime": "2023-05-31T14:33:21.360319Z",
    #      "relatedTags": [
    #        {
    #          "name": "projects/PROJECT/locations/LOCATION/repositories/REPO/packages/IMGNAME/tags/some-tag",
    #          "version": "projects/PROJECT/locations/LOCATION/repositories/REPO/packages/IMGNAME/versions/sha256:SHA256"
    #        },
    #        ...
    #      ],
    #      "metadata": {
    #        "imageSizeBytes": "38636295",
    #        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    #        "buildTime": "2023-05-30T17:24:30.935114729Z",
    #        "name": "projects/PROJECT/locations/LOCATION/repositories/REPO/dockerImages/IMGNAME@sha256:SHA256"
    #      }
    #    },
    #
    # check specific version
    # $ export GCLOUD_TOKEN=$(gcloud auth print-access-token)
    # $ curl -H "Content-Type: application/json"
    #        -H "Authorization: Bearer $GCLOUD_TOKEN"
    #        -G https://artifactregistry.googleapis.com/v1/projects/PROJECT/locations/LOCATION/repositories/REPO/packages/IMGNAME/versions/sha256:SHA256
    # {
    #   "name": "projects/PROJECT/locations/LOCATION/repositories/REPO/packages/IMGNAME/versions/sha256:SHA256",
    #   "createTime": "2023-06-01T19:02:27.563679Z",
    #   "updateTime": "2023-06-01T19:02:28.780575Z",
    #   "metadata": {
    #     "buildTime": "2023-06-01T19:02:24.623978679Z",
    #     "name": "projects/PROJECT/locations/LOCATION/repositories/REPO/dockerImages/IMGNAME@sha256:SHA256",
    #     "imageSizeBytes": "35064515",
    #     "mediaType": "application/vnd.docker.distribution.manifest.v2+json"
    #   }
    # }
    #
    # https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.packages.versions
    def getDigestForImage(self, repo_full: str) -> str:
        """Obtain the GAR digest for the specified project, location and repo"""
        if "/" not in repo_full or repo_full.count("/") != 3:
            error("Please use PROJECT/LOCATION/REPO/IMGNAME", do_exit=False)
            return ""

        project, location, repo, name = repo_full.split("/", 4)
        tagsearch: str = ""
        sha256: str = ""
        if "@sha256:" in name:
            name, sha256 = name.split("@", 2)
        elif ":" in name:
            name, tagsearch = name.split(":", 2)

        # Ordering by update time sorts the results in descending order with newest
        # first. This helps optimize the search for the digest. FULL view includes
        # relatedTags.
        url: str
        params: Dict[str, str] = {}
        if sha256 == "":
            url = (
                "https://artifactregistry.googleapis.com/v1/projects/%s/locations/%s/repositories/%s/packages/%s/versions?orderBy=UPDATE_TIME+desc&view=FULL"
                % (project, location, repo, name)
            )
            params["pageSize"] = "100"
        else:
            url = (
                "https://artifactregistry.googleapis.com/v1/projects/%s/locations/%s/repositories/%s/packages/%s/versions/%s"
                % (project, location, repo, name, sha256)
            )

        headers: Dict[str, str] = _createGARHeaders()
        headers["Content-Type"] = "application/json"

        max_attempts: int = 10
        count: int = 0
        only_stale: bool = True
        while True:
            try:
                r: requests.Response = requestGetRaw(
                    url, headers=headers, params=params
                )
            except requests.exceptions.RequestException as e:  # pragma: nocover
                warn("Skipping %s (request error: %s)" % (url, str(e)))
                return ""

            if r.status_code >= 300:
                warn("Could not fetch %s (%d)" % (url, r.status_code))
                return ""

            resj: Dict[str, Any] = {}
            tmp: Dict[str, Any] = r.json()
            if sha256 == "":
                resj = tmp
            else:
                # when searching by specific sha256, we get back the specific entry
                # and not a list of versions, so create a list of one versions
                resj["versions"] = []
                resj["versions"].append(tmp)

            if "versions" not in resj:
                warn("Could not find 'versions' in response: %s" % resj)
                return ""

            for img in resj["versions"]:
                count += 1
                # malformed json
                if "name" not in img:
                    warn("Could not find 'name' in %s" % img)
                    return ""
                elif "metadata" not in img:
                    warn("Could not find 'metadata' in %s" % img)
                    return ""
                elif "mediaType" not in img["metadata"]:
                    warn("Could not find 'mediaType' in 'metadata' in %s" % img)
                    return ""
                elif "name" not in img["metadata"]:
                    warn("Could not find 'name' in 'metadata' in %s" % img)
                    return ""

                # https://github.com/opencontainers/image-spec/blob/main/manifest.md
                known_types: List[str] = [
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                ]
                if img["metadata"]["mediaType"] not in known_types:
                    warn(
                        "Skipping %s (mediaType not in '%s')"
                        % (
                            ",".join(known_types),
                            img["metadata"]["name"].split("/")[-1],
                        )
                    )
                    continue

                # if searching by tag, just return the first one (note, "tags" is
                # optional in the json output)
                if tagsearch != "" and "relatedTags" in img:
                    for t in img["relatedTags"]:
                        if t["name"].endswith("/%s" % tagsearch):
                            return img["metadata"]["name"]
                elif sha256 != "":
                    return img["metadata"]["name"]
                elif tagsearch == "":
                    # When not searching by a tag name, we are searching for the
                    # latest digest. Since we used 'orderBy=UPDATE_TIME+desc', we
                    # we can assume that the first image we see with a matching
                    # name is the latest one. The latest image may not have valid
                    # scan results (not completed, is a cosign image, etc), so try
                    # up to 'max_attempts' times to find an image with usable scan
                    # results.
                    why: str = getGARDiscovery(
                        "%s/%s/%s/%s@%s"
                        % (
                            project,
                            location,
                            repo,
                            name,
                            img["metadata"]["name"].split("@")[-1],
                        )
                    )
                    if only_stale and why not in ["INACTIVE", "UNSCANNED"]:
                        only_stale = False
                    if why not in ["INACTIVE", "PENDING", "UNSUPPORTED", "UNSCANNED"]:
                        if why not in ["CLEAN", "ACTIVE"]:
                            # in case we missed something
                            warn("unexpected result from getGARDiscovery(): %s" % why)
                        return img["metadata"]["name"]
                    if count > max_attempts:
                        break

            if tagsearch == "" and count > max_attempts:
                break

            if "nextPageToken" not in resj:
                break

            params["pageToken"] = resj["nextPageToken"]
            # time.sleep(2)  # in case nextPageToken isn't valid yet

        if tagsearch == "":
            extra = ""
            if only_stale:
                extra = " (images are stale)"
            warn(
                "Could not find digest for %s/%s with scan results for in %d most recent images%s"
                % (repo, name.split("@")[0], max_attempts, extra)
            )
        else:
            warn("Could not find digest for %s" % name)

        return ""

    def parseImageDigest(self, digest: str) -> Tuple[str, str, str]:
        """Parse the image digest into a (namespace, repo, sha256) tuple"""
        if "@sha256:" not in digest:
            error("Malformed digest '%s' (does not contain '@sha256:')" % digest)
            return ("", "", "")
        elif digest.count("@") != 1:
            error("Malformed digest '%s' (should have 1 '@')" % digest)
            return ("", "", "")

        pre: str = ""
        sha256: str = ""
        pre, sha256 = digest.split("@")
        if pre.count("/") != 7:
            error("Malformed digest '%s' (should have 7 '/')" % digest)
            return ("", "", "")

        tmp: List[str]
        tmp = pre.split("/")
        ns: str = "%s/%s" % (tmp[1], tmp[3])
        repo: str = "%s/%s" % (tmp[5], tmp[7])
        return (ns, repo, sha256)

    def getOCIsForNamespace(self, proj_loc: str) -> List[Tuple[str, int]]:
        """Obtain the list of GAR OCIs for the specified project and location"""
        if "/" not in proj_loc:
            error("Please use PROJECT/LOCATION", do_exit=False)
            return []

        repos: List[str] = self.getReposForNamespace(proj_loc)
        ocis: List[Tuple[str, int]] = []

        if len(repos) > 0 and sys.stdout.isatty():  # pragma: nocover
            print("Fetching list of images for each repo: ", end="", flush=True)

        for repo in repos:
            if sys.stdout.isatty():  # pragma: nocover
                print(".", end="", flush=True)

            tmp: List[Tuple[str, int]] = getGAROCIForRepo(
                "%s/%s" % (proj_loc, repo.split("/")[-1])
            )
            oci: str = ""
            for (oci, last_modified) in tmp:
                ocis.append(("%s/%s" % (repo, oci), last_modified))

        if len(repos) > 0 and sys.stdout.isatty():  # pragma: nocover
            print(" done!", flush=True)

        return sorted(ocis)

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
    def fetchScanReport(
        self,
        repo_full: str,
        raw: bool = False,
        fixable: bool = True,
        quiet: bool = False,
        priorities: List[str] = [],
    ) -> Tuple[List[ScanOCI], str]:
        """Obtain the security manifest for the specified repo@sha256:..."""
        if (
            "/" not in repo_full
            or repo_full.count("/") != 3
            or "@sha256:" not in repo_full
        ):
            error(
                "Please use PROJECT/LOCATION/REPO/IMGNAME@sha256:<sha256>",
                do_exit=False,
            )
            return [], ""

        project, location, repo, name = repo_full.split("/", 4)

        url: str = (
            "https://containeranalysis.googleapis.com/v1/projects/%s/occurrences"
            % project
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
                r: requests.Response = requestGetRaw(
                    url, headers=headers, params=params
                )
            except requests.exceptions.RequestException as e:  # pragma: nocover
                warn("Skipping %s (request error: %s)" % (url, str(e)))
                return [], ""

            if r.status_code >= 300:
                warn("Could not fetch %s" % url)
                return [], ""

            # An empty scan result can be due to several reasons so lookup why if
            # we fail to get a scan result
            resj = r.json()
            if (
                len(resj) == 0
                or "occurrences" not in resj
                or len(resj["occurrences"]) == 0
            ):
                why: str = getGARDiscovery(repo_full)
                if not quiet and why != "CLEAN":
                    warn(
                        "no scan results for %s/%s: %s"
                        % (repo, name.split("@")[0], why)
                    )
                if raw:
                    return [], ""
                if why == "CLEAN":
                    return [], "No problems found"
                return [], "No scan results for this %s image" % why.lower()

            vulns += resj["occurrences"]

            if "nextPageToken" not in resj:
                break

            params["pageToken"] = resj["nextPageToken"]
            # time.sleep(2)  # in case nextPageToken isn't valid yet

        # If raw format, output a unified JSON document that has all the
        # vulns in one doc but otherwise looks like that the API returned
        if raw:
            return [], "%s" % json.dumps(
                _sorted_json_deep({"occurrences": vulns}), sort_keys=True, indent=2
            )

        ocis: List[ScanOCI] = []
        # do a subset of this with created?
        for oci in sorted(parse(vulns), key=lambda i: (i.component, i.advisory)):
            if fixable and oci.versionFixed == "unknown":
                continue
            if len(priorities) > 0 and oci.severity not in priorities:
                continue
            ocis.append(oci)

        return ocis, ""

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
    def getReposForNamespace(self, proj_loc: str) -> List[str]:
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
                r: requests.Response = requestGetRaw(
                    url, headers=headers, params=params
                )
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
                    print(" done!", flush=True)
                break

            params["pageToken"] = resj["nextPageToken"]
            # time.sleep(2)  # in case nextPageToken isn't valid yet

        return copy.deepcopy(repos)


#
# CLI mains
#
def main_gar_dump_reports():
    # EXPERIMENTAL: this is subject to change
    _experimental()

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="gar-dump-reports",
        description="Fetch GAR reports and save locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
gar-dump-reports pulls all the latest security reports for OCI images in
PROJECT/LOCATION and outputs them to:

  /path/to/reports/YY/MM/DD/gar/PROJECT/LOCATION/REPO/IMGNAME/SHA256.json

Eg, to pull all GAR security scan reports for project 'foo' at location 'us':

  $ gar-dump-reports --path /path/to/reports --name foo/us
        """
        ),
    )
    parser.add_argument(
        "-p",
        "--path",
        dest="path",
        type=str,
        help="local PATH to save reports",
        default=None,
        required=True,
    )
    parser.add_argument(
        "--name",
        dest="name",
        help="fetch GAR security report for PROJECT/LOC",
        metavar="PROJECT/LOC",
        type=str,
    )

    args: argparse.Namespace = parser.parse_args()

    sr = GARSecurityReportNew()

    if "/" not in args.name:
        error("Please use PROJECT/LOC (eg foo/us) with --name")
        return ""  # for tests

    # Find latest digest for all images
    oci_names: List[Tuple[str, int]] = sr.getOCIsForNamespace(args.name)
    if len(oci_names) == 0:
        error("Could not enumerate any OCI image names")
        return  # for tests

    ocis: List[str] = []
    if sys.stdout.isatty():  # pragma: nocover
        print("Fetching digests for OCI names: ", end="", flush=True)
    for (oci, _) in oci_names:
        if sys.stdout.isatty():  # pragma: nocover
            print(".", end="", flush=True)

        name: str = "%s/%s" % (args.name, oci.split("/", maxsplit=5)[-1])
        digest: str = sr.getDigestForImage(name)
        if digest == "":
            continue
        ocis.append("%s@%s" % (name, digest.split("@")[1]))

    if sys.stdout.isatty():  # pragma: nocover
        print(" done!", flush=True)

    if len(ocis) == 0:
        error("Could not find any OCI image digests")
        return  # for tests

    dir: str = args.path
    if not os.path.exists(dir):
        os.mkdir(dir)
    if not os.path.isdir(dir):  # pragma: nocover
        error("'%s' is not a directory" % dir)

    count: int = 0
    for full_name in ocis:
        j: Dict[str, Any] = {}
        _, tmp = sr.fetchScanReport(full_name, raw=True, quiet=True)
        if "occurrences" in tmp:
            j = json.loads(tmp)
        else:
            continue

        # GAR API should guarantee this...
        ok = True

        # look at the first vuln occurrence for details that are shared across
        # all vuln occurrences
        for i in ["createTime", "resourceUri"]:
            if i not in j["occurrences"][0]:
                warn("Could not find '%s' in: %s" % (i, j))
                ok = False
        if not ok:
            continue

        repo_name: str = j["occurrences"][0]["resourceUri"].split("@")[0].split("/")[-2]
        img_name: str = j["occurrences"][0]["resourceUri"].split("@")[0].split("/")[-1]
        sha256: str = j["occurrences"][0]["resourceUri"].split("@")[-1].split(":")[-1]

        # use the createTime as part of the hierarchy since it is not expected
        # to change
        dobj = datetime.datetime.strptime(
            j["occurrences"][0]["createTime"], "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        # create the directory hierarchy as we go
        dir = args.path
        for subdir in [
            str(dobj.year),
            "%0.2d" % dobj.month,
            "%0.2d" % dobj.day,
            "gar",
            args.name.split("/")[0],
            args.name.split("/")[1],
            repo_name,
            img_name,
        ]:
            dir = os.path.join(dir, subdir)
            if not os.path.exists(dir):
                os.mkdir(dir)
            if not os.path.isdir(dir):  # pragma: nocover
                error("'%s' is not a directory" % dir)

        created: bool = False
        fn = os.path.join(dir, "%s.json" % sha256)
        if not os.path.exists(fn):
            with open(fn, "w") as fh:
                print("Created: %s" % os.path.relpath(fn, args.path))
                # sort_keys to make visual comparisons a bit easier
                json.dump(_sorted_json_deep(j), fh, sort_keys=True, indent=2)
                # json.dump() doesn't put a newline at the end, so add it
                fh.seek(os.SEEK_SET, os.SEEK_END)
                fh.write("\n")
                created = True
                count += 1
        if not os.path.isfile(fn):
            warn("'%s' is not a file" % os.path.relpath(fn, args.path))
            continue

        # if the sha256 of the original file is different than what we
        # downloaded, then update the file
        if not created and os.path.exists(fn):
            # calculate sha256 of orig file
            orig_hash: str
            with open(fn, "r") as fh:
                orig_hash = hashlib.sha256(fh.read().encode("UTF-8")).hexdigest()

            # sort_keys to make visual comparisons a bit easier
            s: str = json.dumps(_sorted_json_deep(j), sort_keys=True, indent=2) + "\n"
            hash: str = hashlib.sha256(s.encode("UTF-8")).hexdigest()
            if orig_hash != hash:
                os.unlink(fn)
                with open(fn, "w") as fh:
                    print("Updated: %s" % os.path.relpath(fn, args.path))
                    fh.write(s)
                count += 1

    if count == 0:
        error("No new security reports", do_exit=False)
