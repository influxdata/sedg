#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import copy
from datetime import datetime
import os
import requests
import sys
import textwrap
from typing import Dict, List, Optional

from cvelib.common import error, warn, _experimental
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

$ gar-report --list-repos foo/us
bar
baz

$ gar-report --list-ocis foo/us
bar/norf
bar/corge
baz/qux

$ gar-report --get-repo-latest-digest foo/us/bar/norf
norf@sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
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
        help="output GAR repo digest for PROJECT/LOCATION/REPO/NAME[:<tagsearch>]",
        default=None,
    )
    #    parser.add_argument(
    #        "--get-security-manifest",
    #        dest="get_security_manifest",
    #        type=str,
    #        help="output GAR security report for ORG/REPO@sha256:SHA256",
    #        default=None,
    #    )
    #    parser.add_argument(
    #        "--get-security-manifest-raw",
    #        dest="get_security_manifest_raw",
    #        type=str,
    #        help="output GAR raw security report for ORG/REPO@sha256:SHA256",
    #        default=None,
    #    )
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
        proj: str = ""
        loc: str = ""
        repo: str = ""
        name: str = ""
        tag: str = ""
        if "/" not in args.get_repo_latest_digest:
            error("please use PROJECT/LOCATION/REPO/NAME[:<tagsearch>]")

        proj, loc, repo, name = args.get_repo_latest_digest.split("/", 4)
        if ":" in name:
            name, tag = name.split(":", 2)
        digest: str = _getGARRepo(proj, loc, repo, name, tagsearch=tag)
        print(digest.split("/")[-1])  # trim off the proj/loc/repo


#    elif args.get_security_manifest:
#        if "/" not in args.get_security_manifest:
#            error("please use ORG/NAME")
#        s: str = _getGARSecurityManifest(args.get_security_manifest)
#        print("# %s report" % args.get_security_manifest)
#        print(s)
#    elif args.get_security_manifest_raw:
#        if "/" not in args.get_security_manifest_raw:
#            error("please use ORG/NAME")
#        s: str = _getGARSecurityManifest(args.get_security_manifest_raw, raw=True)
#        print(s)
