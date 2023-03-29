#!/usr/bin/env python3
#
# Copyright (c) 2021-2023 InfluxData
#
# Permission is hereby granted, free of charge, to any
# person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the
# Software without restriction, including without
# limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice
# shall be included in all copies or substantial portions
# of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
# ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

# EXPERIMENTAL: this script and APIs subject to change

import copy
from datetime import datetime
import os
import requests
import sys
from typing import Dict, List, Optional

from cvelib.common import (
    error,
    warn,
)
from cvelib.net import requestGetRaw


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
def _getGARRepo(
    project: str, location: str, repo: str, name: str, tagsearch: str = ""
) -> str:
    """Obtain the GAR digest for the specified project, location and repo"""
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
