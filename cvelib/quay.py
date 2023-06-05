#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import copy
from datetime import datetime
import hashlib
import json
import os
import requests
import sys
import textwrap
from typing import Any, Dict, List, Optional

from cvelib.common import error, warn, _experimental
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


# $ curl -H "Authorization: Bearer $QUAY_TOKEN" \
#        -G "https://quay.io/api/v1/repository?last_modified=true&namespace=ORG"
# {
#   "repositories": [
#     {
#       "namespace": "foo",
#       "name": "bar",
#       "description": null,
#       "is_public": false,
#       "kind": "image",
#       "state": "NORMAL",
#       "last_modified": 1684472852,
#       "is_starred": false
#     },
#     ...
#   ],
#   "next_page": "gAAAAA..."
# }
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
        except requests.exceptions.RequestException as e:  # pragma: nocover
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


# $ curl -H "Authorization: Bearer $QUAY_TOKEN" \
#        -G "https://quay.io/api/v1/repository/ORG/IMGNAME?includeTags=true"
# {
#   "namespace": "valid-org",
#   "name": "valid-repo",
#   "kind": "image",
#   "description": "",
#   "is_public": true,
#   "is_organization": true,
#   "is_starred": false,
#   "status_token": "",
#   "trust_enabled": false,
#   "tag_expiration_s": 1209600,
#   "is_free_account": false,
#   "state": "NORMAL",
#   "tags": {
#     "latest": {
#       "name": "latest",
#       "size": 270353940,
#       "last_modified": "Wed, 15 Mar 2023 15:05:28 -0000",
#       "manifest_digest": "sha256:3fa5256ad34b31901ca30021c722fc7ba11a66ca070c8442862205696b908ddb"
#     },
#     "f7d94bbcf4f202b9f9d8f72c37d5650d7756f188": {
#       "name": "f7d94bbcf4f202b9f9d8f72c37d5650d7756f188",
#       "size": 573662556,
#       "last_modified": "Tue, 14 Jun 2022 12:07:42 -0000",
#       "manifest_digest": "sha256:2536a15812ba685df76e835aefdc7f512941c12c561e0aed152d17aa025cc820"
#     },
#   },
#   "can_write": false,
#   "can_admin": false
# }
def getQuayDigestForImage(repo_full: str) -> str:
    """Obtain the digest for the the specified repo"""
    if "/" not in repo_full:
        error("Please use ORG/NAME", do_exit=False)
        return ""

    ns: str = ""
    name: str = ""
    sha256: str = ""
    tagsearch: str = ""
    ns, name = repo_full.split("/", 2)
    if "@sha256:" in name:
        name, sha256 = name.split("@", 2)
    elif ":" in name:
        name, tagsearch = name.split(":", 2)

    repo: str = "%s/%s" % (ns, name)
    url: str = "https://quay.io/api/v1/repository/%s" % repo
    headers: Dict[str, str] = _createQuayHeaders()
    params: Dict[str, str] = {"includeTags": "true"}

    try:
        r: requests.Response = requestGetRaw(url, headers=headers, params=params)
    except requests.exceptions.RequestException as e:  # pragma: nocover
        warn("Skipping %s (request error: %s)" % (url, str(e)))
        return ""

    if r.status_code >= 300:
        warn("Could not fetch %s" % url)
        return ""

    resj = r.json()
    if "tags" not in resj:
        warn("Could not find 'tags' in response: %s" % resj)
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

            if sha256 == "":
                cur: datetime = datetime.strptime(
                    resj["tags"][tag]["last_modified"], "%a, %d %b %Y %H:%M:%S %z"
                )
                if latest_d is None or cur > latest_d:
                    latest_d = cur
                    digest = resj["tags"][tag]["manifest_digest"]
            elif sha256 == resj["tags"][tag]["manifest_digest"]:
                digest = sha256
                break

    if digest != "":
        return "%s/%s@%s" % (ns, name, digest)

    return ""


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
#               "Metadata":
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
            if "Metadata" in v:
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
            fixedBy = "unknown"
            if v["FixedBy"] != "" and v["FixedBy"] != "0:0":
                fixedBy = v["FixedBy"]
            scan_data["fixedBy"] = fixedBy

            # adv url
            adv: str = "unavailable"
            if "Link" in v and len(v["Link"]) != 0:
                # Link may be a space-separated list
                adv = v["Link"].split()[0]
            scan_data["advisory"] = adv

            ocis.append(ScanOCI(scan_data))

    return ocis


# $ curl -H "Authorization: Bearer $QUAY_TOKEN" \
#        -G
#        "https://quay.io/api/v1/repository/ORG/IMGNAME/manifest/sha256:SHA256/security?vulnerabilities=true"
# {
def getQuaySecurityReport(
    repo_full: str, raw: Optional[bool] = False, fixable: Optional[bool] = False
) -> str:
    """Obtain the security manifest for the specified repo@sha256:..."""
    if "/" not in repo_full or "@sha256:" not in repo_full:
        error("Please use ORG/NAME@sha256:<sha256>", do_exit=False)
        return ""

    repo: str
    sha256: str
    repo, sha256 = repo_full.split("@", 2)
    url: str = "https://quay.io/api/v1/repository/%s/manifest/%s/security" % (
        repo,
        sha256,
    )
    headers: Dict[str, str] = _createQuayHeaders()
    params: Dict[str, str] = {"vulnerabilities": "true"}

    try:
        r: requests.Response = requestGetRaw(url, headers=headers, params=params)
    except requests.exceptions.RequestException as e:  # pragma: nocover
        warn("Skipping %s (request error: %s)" % (url, str(e)))
        return ""

    if r.status_code >= 300:
        warn("Could not fetch %s" % url)
        return ""

    resj = r.json()
    if raw:
        return json.dumps(resj, sort_keys=True)

    if "status" not in resj:
        error("Cound not find 'status' in response: %s" % resj, do_exit=False)
        return ""
    elif resj["status"] != "scanned":
        error(
            "Could not process report due to status: %s" % resj["status"], do_exit=False
        )
        return ""

    if "data" not in resj:
        error("Could not find 'data' in %s" % resj, do_exit=False)
        return ""
    elif resj["data"] is None:
        error("Could not process report due to no data in %s" % resj, do_exit=False)
        return ""

    if "Layer" not in resj["data"]:
        error("Could not find 'Layer' in %s" % resj["data"], do_exit=False)
        return ""
    if "Features" not in resj["data"]["Layer"]:
        error("Could not find 'Features' in %s" % resj["data"]["Layer"], do_exit=False)
        return ""

    url_prefix: str = "https://quay.io/repository/%s/manifest/%s" % (repo, sha256)

    ocis: List[ScanOCI] = parse(resj, url_prefix)
    s: str = getScanOCIsReport(ocis, fixable=fixable)
    return s


#
# CLI mains
#
def main_quay_dump_reports():
    # EXPERIMENTAL: this is subject to change
    _experimental()

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="quay-dump-reports",
        description="Fetch quay.io reports and save locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
quay-dump-reports pulls all the latest security reports for OCI images in
ORG and outputs them to:

  /path/to/reports/YY/MM/DD/quay/ORG/IMGNAME/SHA256.json

Eg, to pull all quay.io security scan reports for org 'foo':

  $ quay-dump-reports --path /path/to/reports --name org
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
        help="fetch quay.io security report for ORG",
        metavar="ORG",
        type=str,
    )

    args: argparse.Namespace = parser.parse_args()

    # Find latest digest for all images
    oci_names: List[str] = getQuayOCIsForOrg(args.name)
    if len(oci_names) == 0:
        error("Could not enumerate any OCI image names")
        return  # for tests

    ocis: List[str] = []
    if sys.stdout.isatty():  # pragma: nocover
        print("Fetching digests for OCI names: ", end="", flush=True)
    for oci in oci_names:
        if sys.stdout.isatty():  # pragma: nocover
            print(".", end="", flush=True)

        name: str = "%s/%s" % (args.name, oci.split("/", maxsplit=5)[-1])
        digest: str = getQuayDigestForImage(name)
        if digest == "":
            warn("Could not find digest for %s" % name)
            continue
        ocis.append("%s@%s" % (name, digest.split("@")[1]))

    if sys.stdout.isatty():  # pragma: nocover
        print(" done!", flush=True)

    if len(ocis) == 0:
        error("Could not find any OCI image digests")
        return  # for tests

    # gather security reports
    jsons: Dict[str, Dict[str, Any]] = {}
    if sys.stdout.isatty():  # pragma: nocover
        print("Fetching security reports: ", end="", flush=True)

    # quay.io doesn't have dates or times in the security report, so we will
    # store them in a folder under today's date. Since the report path comes
    # from the date the report was fetched, we'll first search for the report
    # by the quay/IMGNAME/SHA256.json to see if we previously downloaded it.

    # gather a list of potentially matching filenames
    json_files: Dict[str, str] = {}
    for root, _, files in os.walk(args.path):
        if "/quay/%s/" % args.name not in root:  # quick prune
            continue
        for f in files:
            if f.endswith(".json"):
                tmp: str = os.path.join(root, f)
                if f.split(".")[0] in json_files:
                    # since the filename is the sha256 sum, there shouldn't be
                    # any collisions but report if the report is in multiple
                    # locations
                    warn("Found duplicate '%s'" % os.path.relpath(args.path, tmp))
                    continue
                json_files[f.split(".")[0]] = tmp

    for name in ocis:
        if sys.stdout.isatty():  # pragma: nocover
            print(".", end="", flush=True)

        tmp: str = getQuaySecurityReport(name, raw=True)
        if '"status":' in tmp:
            j: Dict[str, Any] = json.loads(tmp)
            if j["status"] in ["queued", "scanned", "unsupported"]:
                if j["status"] == "scanned":
                    jsons[name] = j
            else:
                warn("unexpected scan status: %s" % j["status"])

    if sys.stdout.isatty():  # pragma: nocover
        print(" done!", flush=True)

    if len(jsons) == 0:
        error("No new security reports", do_exit=False)
        return

    dir: str = args.path
    if not os.path.exists(dir):
        os.mkdir(dir)
    if not os.path.isdir(dir):  # pragma: nocover
        error("'%s' is not a directory" % dir)

    for full_name in jsons.keys():
        j = jsons[full_name]

        repo_name: str = full_name.split("@")[0].split("/")[-1]
        sha256: str = full_name.split("@")[1].split(":")[-1]

        if sha256 not in json_files:  # create under dir with today's date
            dobj: datetime = datetime.now()
            dir = args.path
            for subdir in [
                str(dobj.year),
                "%0.2d" % dobj.month,
                "%0.2d" % dobj.day,
                "quay",
                args.name,
                repo_name,
            ]:
                dir = os.path.join(dir, subdir)
                if not os.path.exists(dir):
                    os.mkdir(dir)
                if not os.path.isdir(dir):  # pragma: nocover
                    error("'%s' is not a directory" % dir)

            fn = os.path.join(dir, "%s.json" % sha256)
            if not os.path.exists(fn):
                with open(fn, "w") as fh:
                    print("Created: %s" % os.path.relpath(fn, args.path))
                    json.dump(j, fh, sort_keys=True, indent=2)
                    # json.dump() doesn't put a newline at the end, so add it
                    fh.seek(os.SEEK_SET, os.SEEK_END)
                    fh.write("\n")
        else:  # compare existing report to what we downloaded
            fn: str = json_files[sha256]
            orig_hash: str
            with open(fn, "r") as fh:
                orig_hash = hashlib.sha256(fh.read().encode("UTF-8")).hexdigest()

            s: str = json.dumps(j, sort_keys=True, indent=2) + "\n"
            hash: str = hashlib.sha256(s.encode("UTF-8")).hexdigest()
            if orig_hash != hash:
                os.unlink(fn)
                with open(fn, "w") as fh:
                    print("Updated: %s" % os.path.relpath(fn, args.path))
                    fh.write(s)
