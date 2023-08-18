#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import copy
from datetime import datetime, timedelta
import hashlib
import json
import os
import requests
import sys
import textwrap
from typing import Any, Dict, List, Tuple, Union

from cvelib.common import error, warn, _sorted_json_deep, _experimental
from cvelib.net import requestPostRaw
from cvelib.scan import ScanOCI, SecurityReportInterface, SecurityReportFetchResult


def _createDockerDSOHeaders() -> Dict[str, str]:
    """Create request headers for api.dso.docker.com request"""
    # Now do the actual headers
    headers: Dict[str, str] = {}

    return copy.deepcopy(headers)


# {
#   "data": {
#     "vulnerabilitiesByPackage": [
#      {
#        "purl": "pkg:golang/golang.org/x/net@0.0.0-20211112202133-69e39bad7dc2",
#        "vulnerabilities": [
#          {
#            "cvss": {
#              "score": 7.5,
#              "severity": "HIGH"
#            },
#            "cwes": [],
#            "description": "An attacker can cause...",
#            "fixedBy": "0.0.0-20211209124913-491a49abca63",
#            "publishedAt": "2022-07-15T23:08:33.000Z",
#            "source": "golang",
#            "sourceId": "CVE-2021-44716",
#            "vulnerableRange": "<0.0.0-20211209124913-491a49abca63"
#          },
#          {
#            "cvss": {
#              "score": 7.5,
#              "severity": "HIGH"
#            },
#            "cwes": [],
#            "description": "In net/http in Go before 1.18.6 and 1.19.x before 1.19.1, attackers can cause a denial of service because an HTTP/2 connection can hang during closing if shutdown were preempted by a fatal error.",
#            "fixedBy": None,
#            "publishedAt": "2022-09-07T00:01:51.000Z",
#            "source": "github",
#            "sourceId": "CVE-2022-27664",
#            "vulnerableRange": "<0.0.0-20220906165146-f3363e06e74c"
#          }
#        ]
#      },
#      ...
#     ]
#   },
#   "extensions": {
#     "correlation_id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
#   }
# }
def parse(purls: Dict[str, List[str]], resj: Dict[str, Any], url: str) -> List[ScanOCI]:
    """Parse report JSON and return a list of ScanOCIs"""
    ocis: List[ScanOCI] = []

    for pkg in resj["data"]["vulnerabilitiesByPackage"]:
        if "purl" not in pkg:
            warn("Could not find 'purl' in %s" % pkg)
            continue
        elif "vulnerabilities" not in pkg:
            warn("Could not find 'vulnerabilities' in %s" % pkg)
            continue

        component, version = pkg["purl"].rsplit("@", maxsplit=1)

        for v in pkg["vulnerabilities"]:
            # One ScanOCI per vuln
            scan_data: Dict[str, str] = {}
            scan_data["component"] = component
            scan_data["version"] = version
            scan_data["url"] = url

            status: str = "needed"
            if v["fixedBy"] is None:
                status = "needs-triage"
            elif v["fixedBy"] == version:
                status = "released"
            scan_data["status"] = status

            # severity
            severity: str = "unknown"
            if (
                "cvss" in v
                and "severity" in v["cvss"]
                and v["cvss"]["severity"].lower() != "unspecified"
            ):
                severity = v["cvss"]["severity"].lower()
            scan_data["severity"] = severity

            # fixedBy
            fixedBy = "unknown"
            if v["fixedBy"] is not None:
                fixedBy = v["fixedBy"]
            scan_data["fixedBy"] = fixedBy

            # adv url
            adv: str = "unavailable"
            if "sourceId" in v:
                if v["sourceId"].startswith("CVE-"):
                    adv = "https://www.cve.org/CVERecord?id=%s" % v["sourceId"]
                elif v["sourceId"].startswith("GHSA-"):
                    adv = "https://github.com/advisories/%s" % v["sourceId"]
                elif v["sourceId"].startswith("GMS-"):
                    adv = "https://advisories.gitlab.com/?search=%s" % v["sourceId"]
                else:
                    warn("unsupported sourceId: %s" % v["sourceId"])

            scan_data["advisory"] = adv

            # detectedIn - do one ScanOCI per detected in
            if pkg["purl"] in purls:
                for det in purls[pkg["purl"]]:
                    tmp = copy.deepcopy(scan_data)
                    tmp["detectedIn"] = det
                    ocis.append(ScanOCI(tmp))
            else:
                scan_data["detectedIn"] = "unknown"
                ocis.append(ScanOCI(scan_data))

    return ocis


class DockerDSOSecurityReportNew(SecurityReportInterface):
    name = "dso"

    # $ curl -X POST https://api.dso.docker.com/datalog/shared-vulnerability/queries
    #        --data-binary '_getListEDN()'
    # {
    #   "docker-repository-tags": {
    #     "data": [
    #       {
    #         "image": {
    #           "docker.image/digest": "sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
    #           "docker.image/created-at": "2022-12-16 00:23:40+00:00",
    #           "docker.image/tags": [
    #             "1.0-foo",
    #             "1-foo",
    #             "foo"
    #           ]
    #         }
    #       }
    #     ],
    #     "basis-t": "12345678",
    #     "tx": "12345678901234"
    #   },
    #   "extensions": {
    #     "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
    #   }
    # }
    def getDigestForImage(self, repo_full: str) -> str:
        """Obtain the digest for the the specified repo"""
        name = repo_full
        sha256: str = ""
        tagsearch: str = ""
        if "@sha256:" in name:
            name, sha256 = name.split("@", 2)
        elif ":" in name:
            name, tagsearch = name.split(":", 2)

        rese = _getListEDN(name)
        if len(rese) < 1:  # error condition from _getListEDN()
            return ""

        digest: str = ""
        latest_d: Union[None, datetime] = None
        for img in rese["docker-repository-tags"]["data"]:
            if "image" in img and "docker.image/tags" in img["image"]:
                if sha256 != "" and sha256 == img["image"]["docker.image/digest"]:
                    digest = sha256
                    break
                elif (
                    tagsearch != "" and tagsearch in img["image"]["docker.image/tags"]
                ) or tagsearch == "":
                    if (
                        latest_d is None
                        or img["image"]["docker.image/created-at"] > latest_d
                    ):
                        digest = img["image"]["docker.image/digest"]
                        latest_d = img["image"]["docker.image/created-at"]

        if digest != "":
            return "%s@%s" % (name, digest)

        return ""

    def parseImageDigest(self, digest: str) -> Tuple[str, str, str]:
        """Parse the image digest into a (namespace, repo, sha256) tuple"""
        if "@sha256:" not in digest:
            error("Malformed digest '%s' (does not contain '@sha256:')" % digest)
            return ("", "", "")
        elif digest.count("@") != 1:
            error("Malformed digest '%s' (should have 1 '@')" % digest)
            return ("", "", "")

        sha256: str = ""
        repo, sha256 = digest.split("@")

        return ("", repo, sha256)

    def getOCIsForNamespace(self, _: str) -> List[Tuple[str, int]]:  # pragma: nocover
        """Obtain the list of DockerDSO repos for the specified namespace"""
        # dso doesn't have a concept of namespaces
        raise NotImplementedError

    def fetchScanReport(
        self,
        repo_full: str,
        raw: bool = False,
        fixable: bool = True,
        quiet: bool = False,  # remove?
        priorities: List[str] = [],
    ) -> Tuple[List[ScanOCI], str]:
        """Obtain the security manifest for the specified repo@sha256:..."""
        if "@sha256:" not in repo_full:
            error("Please use REPO@sha256:SHA256", do_exit=False)
            return [], ""

        purls: Dict[str, List[str]] = _fetchPackageURLs(repo_full.split("@")[-1])
        resj = _fetchVulnReports(list(purls.keys()))
        if raw:
            return [], json.dumps(_sorted_json_deep(resj), sort_keys=True, indent=2)

        if "data" not in resj or resj["data"] is None:
            error("Could not find 'data' in %s" % resj, do_exit=False)
            return [], ""

        if "vulnerabilitiesByPackage" not in resj["data"]:
            error(
                "Could not find 'vulnerabilitiesByPackage' in %s" % resj["data"],
                do_exit=False,
            )
            return [], ""

        url: str = "https://dso.docker.com/images/%s/digests/%s" % (
            repo_full.split("@")[0],
            repo_full.split("@")[1],
        )

        ocis: List[ScanOCI] = []
        # do a subset of this with created?
        for oci in sorted(
            parse(purls, resj, url), key=lambda i: (i.component, i.advisory)
        ):
            if fixable and oci.versionFixed == "unknown":
                continue
            if len(priorities) > 0 and oci.severity not in priorities:
                continue
            ocis.append(oci)

        if len(ocis) == 0:
            return [], self.errors[SecurityReportFetchResult.CLEAN]

        return ocis, ""

    def getReposForNamespace(self, _: str) -> List[str]:  # pragma: nocover
        # dso doesn't have a concept of repos within namespaces
        raise NotImplementedError


# $ curl -X POST "https://api.dso.docker.com/v1/graphql"
#        --data-binary ...
# {
#   "data": {
#     "imagePackagesByDigest": {
#       "digest": "sha256:c445197c39fd9bb3bad57d899e672bbdde186379963d678a939561bac3528466",
#       "imagePackages": {
#         "packages": [
#           {
#             "package": {
#               "purl": "pkg:deb/debian/acl@2.2.53-10?os_distro=bullseye&os_name=debian&os_version=11"
#             },
#             "locations": [
#               {
#                 "diffId": "sha256:ebc3dc5a2d72427c585c8cda7574a75d96e04b9a37572bd3af0bff905abefbb9",
#                 "path": "/usr/share/doc/libacl1/copyright"
#               },
#               {
#                 "diffId": "sha256:ebc3dc5a2d72427c585c8cda7574a75d96e04b9a37572bd3af0bff905abefbb9",
#                 "path": "/var/lib/dpkg/info/libacl1:arm64.md5sums"
#               },
#               ...
#             ]
#           }
#         ]
#       }
#     }
#   },
#   "extensions": {
#     "correlation_id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
#   }
# }
def _fetchPackageURLs(sha256: str) -> Dict[str, List[str]]:
    headers: Dict[str, str] = _createDockerDSOHeaders()
    headers["Accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    url: str = "https://api.dso.docker.com/v1/graphql"
    data: Dict[str, Any] = {
        "query": """
query web_ImagePackagesByDigest($digest: String!, $context: Context!) {
  imagePackagesByDigest(context: $context, digest: $digest) {
    digest
    imagePackages {
      packages {
        package {
          purl
        }
        locations {
          diffId
          path
        }
      }
    }
  }
}
""",
        "variables": {
            "context": {},
            "digest": sha256,
        },
    }

    try:
        r: requests.Response = requestPostRaw(
            url, headers=headers, data=json.dumps(data)
        )
    except requests.exceptions.RequestException as e:  # pragma: nocover
        warn("Skipping %s (request error: %s)" % (url, str(e)))
        return {}

    if r.status_code >= 300:
        warn("Could not fetch %s" % url)
        return {}

    resj: Dict[str, Any] = r.json()

    if (
        not isinstance(resj, dict)
        or "data" not in resj
        or not isinstance(resj["data"], dict)
    ):
        warn("Could not find 'data' as dict in response: %s" % resj)
        return {}

    if "imagePackagesByDigest" not in resj["data"] or not isinstance(
        resj["data"]["imagePackagesByDigest"], dict
    ):
        warn(
            "Could not find 'imagePackagesByDigest' as dict in response: %s (wrong digest?)"
            % resj
        )
        return {}

    if "imagePackages" not in resj["data"]["imagePackagesByDigest"] or not isinstance(
        resj["data"]["imagePackagesByDigest"]["imagePackages"], dict
    ):
        warn("Could not find 'imagePackages' as dict in response: %s" % resj)
        return {}

    if "packages" not in resj["data"]["imagePackagesByDigest"][
        "imagePackages"
    ] or not isinstance(
        resj["data"]["imagePackagesByDigest"]["imagePackages"]["packages"], list
    ):
        warn("Could not find 'packages' as list in response: %s" % resj)
        return {}

    purls: Dict[str, List[str]] = {}
    for pkg in resj["data"]["imagePackagesByDigest"]["imagePackages"]["packages"]:
        if pkg["package"]["purl"] not in purls:
            purls[pkg["package"]["purl"]] = []
        for loc in pkg["locations"]:
            if loc["path"] not in purls[pkg["package"]["purl"]]:
                purls[pkg["package"]["purl"]].append(loc["path"])

    return copy.deepcopy(purls)


# $ curl -X POST "https://api.dso.docker.com/v1/graphql"
#        --data-binary ...
# <see parse()> comment
def _fetchVulnReports(purls: List[str]) -> Dict[str, Any]:
    headers: Dict[str, str] = _createDockerDSOHeaders()
    headers["Accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    url: str = "https://api.dso.docker.com/v1/graphql"

    # This is trimmed down version from what the developer tools showed when
    # going to:
    # https://dso.docker.com/images/REPO/digests/sha256:DIGEST
    data: Dict[str, Any] = {
        "query": """
query web_VulnerabilitiesByPackage($packageUrls: [String!]!, $context: Context!) {
  vulnerabilitiesByPackage(context: $context, packageUrls: $packageUrls) {
    purl
    vulnerabilities {
      cvss {
        score
        severity
      }
      cwes {
        cweId
        description
      }
      description
      fixedBy
      publishedAt
      source
      sourceId
      vulnerableRange
    }
  }
}
""",
        "variables": {"packageUrls": purls, "context": {}},
    }

    try:
        r: requests.Response = requestPostRaw(
            url, headers=headers, data=json.dumps(data)
        )
    except requests.exceptions.RequestException as e:  # pragma: nocover
        warn("Skipping %s (request error: %s)" % (url, str(e)))
        return {}

    if r.status_code >= 300:
        warn("Could not fetch %s" % url)
        return {}

    return r.json()


def ednLoadAsDict(edn: bytes) -> Dict:
    """Convert an EDN document to a dictionary"""

    # for now, make the edn_format optional
    msg: str = "Please install the 'edn_format' module for 'dso' support"
    try:
        import edn_format
    except ModuleNotFoundError:  # pragma: nocover
        error(msg)
        return {}  # for pyright

    if not hasattr(edn_format, "loads"):  # pragma: nocover
        error(msg)
        return {}  # for pyright

    def convertItem(item) -> str:
        # If we found a Keyword, return its name, otherwise return the item
        return item.name if isinstance(item, edn_format.Keyword) else item

    # This makes some assumptions, but is good enough for what we get back from
    # dso.docker.com
    def convertEDN(edn) -> Union[dict, list, str]:
        if isinstance(edn, (dict, edn_format.immutable_dict.ImmutableDict)):
            return {convertItem(k): convertEDN(v) for k, v in edn.items()}
        elif isinstance(edn, (list, tuple, edn_format.immutable_list.ImmutableList)):
            return [convertEDN(i) for i in edn]
        else:
            return convertItem(edn)

    tmp: Union[dict, list, str] = convertEDN(edn_format.loads(edn))
    if not isinstance(tmp, dict):
        error("EDN document is not a dictionary: %s" % str(edn))
        return {}  # for pyright

    return copy.deepcopy(tmp)


def _getListEDN(namespace: str, days: int = 365) -> Dict:
    """Return a URL and EDN-formatted string for querying the namespace"""
    url: str = "https://api.dso.docker.com/datalog/shared-vulnerability/queries"

    # only query this many days from now
    before: datetime = datetime.now() - timedelta(days=days)

    # This is trimmed down version from what the developer tools showed when
    # going to:
    # https://dso.docker.com/images/REPO?platform=linux%2Famd64
    data = """
{
  :queries [
    {
      :query [
        :find (pull ?docker-image [
          :docker.image/digest :docker.image/created-at :docker.image/tags {
          }
        ])
      :keys image :in $ $before-db %% ?ctx [
        ?docker-repository-host
        ?docker-repository-name
        ?created-since
      ]
      :where (rules ?rules) [
        ?docker-repo
        :docker.repository/host
        ?docker-repository-host
      ]
      [
        ?docker-repo
        :docker.repository/repository
        ?docker-repository-name
      ]
      [
        ?docker-tag
        :docker.tag/repository
        ?docker-repo
      ]
      [
        (q
          (quote [
            :find ?docker-image :in $ ?docker-repo ?docker-tag ?created-since :where (or-join [
              ?docker-repo
              ?docker-tag
            ]
            [
              (missing? $ ?docker-repo :docker.repository/supported-tags)
            ]
            (and [
              ?docker-tag
              :docker.tag/name
              ?tag-name
            ]
            [
              ?docker-repo
              :docker.repository/supported-tags
              ?tag-name
            ]))
            (or-join [
              ?docker-tag
              ?docker-repo
              ?docker-image
              ?created-since
            ]
            (and [
              ?docker-tag
              :docker.tag/image
              ?docker-image
            ]
            [
              ?docker-image
              :docker.image/created-at
              ?created-at
            ]
            [
              (< ?created-since ?created-at)
            ])
            )
          ])
        $ ?docker-repo ?docker-tag ?created-since) ?docker-images
      ]
      (or-join [
        ?docker-repo
        ?docker-tag
        ?docker-images
        ?docker-image
        ?created-since
      ]
      [
        (untuple ?docker-images)
        [
          [
            ?docker-image
          ]
        ]
      ]
      (and [
        (empty? ?docker-images)
      ]
      [
        ?docker-tag
        :docker.tag/latest-scanned
        ?docker-image
      ]
      [
        ?docker-image
        :docker.image/created-at
        ?created-at
      ]
      [
        (< ?created-since ?created-at)
      ]
      [
        ?docker-image
        :docker.image/digest
        _
      ])
      (and [
        (empty? ?docker-images)
      ]
      [
        ?docker-tag
        :docker.tag/latest-scanned
        ?manifest
      ]
      [
        ?manifest
        :docker.manifest-list/images
        ?docker-image
      ]
      [
        ?docker-image
        :docker.image/created-at
        ?created-at
      ]
      [
        (< ?created-since ?created-at)
      ]
      ))
      [
        ?docker-image
        :docker.image/repository
        ?docker-repo
      ]
      [
        (q (quote [
          :find (pull ?tag [
            :docker.tag/name
            :docker.tag/digest
          ])
          :in
          $
          ?docker-repo
          ?docker-image
          :where
          (or-join [
            ?docker-image
            ?tag
          ]
          [?tag
            :docker.tag/image
            ?docker-image
          ]
          (and [
            ?manifest
            :docker.manifest-list/images
            ?docker-image
          ]
          [?tag
            :docker.tag/manifest-list
            ?manifest
          ]))
          [
            ?tag
            :docker.tag/repository
            ?docker-repo
          ]
        ])
        $
        ?docker-repo
        ?docker-image)
        ?tags
      ]
      [
        (not-empty ?tags)
      ]
    ],
    :name
    :docker-repository-tags,
    :args [
      "hub.docker.com"
      "%s"
      #inst "%d-%0.2d-%0.2dT00:00:00.000-00:00"
    ]
  }
]}""" % (
        namespace,
        before.year,
        before.month,
        before.day,
    )

    headers: Dict[str, str] = _createDockerDSOHeaders()
    headers["Content-Type"] = "application/edn"

    try:
        r: requests.Response = requestPostRaw(url, headers=headers, data=data)
    except requests.exceptions.RequestException as e:  # pragma: nocover
        warn("Skipping %s (request error: %s)" % (url, str(e)))
        return {}

    if r.status_code >= 300:
        warn("Could not fetch %s" % url)
        return {}

    rese = ednLoadAsDict(r.content)

    if (
        not isinstance(rese, dict)
        or "docker-repository-tags" not in rese
        or not isinstance(rese["docker-repository-tags"], dict)
    ):
        warn("Could not find 'docker-repository-tags' as dict in response: %s" % rese)
        return {}

    if "data" not in rese["docker-repository-tags"] or not isinstance(
        rese["docker-repository-tags"]["data"], list
    ):
        warn("Could not find 'data' as list in response: %s" % rese)
        return {}

    for img in rese["docker-repository-tags"]["data"]:
        if "image" not in img:
            warn("Could not find 'image' in response for image: %s" % img)
            continue

        if "docker.image/tags" not in img["image"]:
            warn("Could not find 'docker.image/tags' in response for image: %s" % img)
            continue

    return copy.deepcopy(rese)


# $ curl -X POST https://api.dso.docker.com/datalog/shared-vulnerability/queries
#        --data-binary '_getListEDN()'
# {
#   "docker-repository-tags": {
#     "data": [
#       {
#         "image": {
#           "docker.image/digest": "sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
#           "docker.image/created-at": "2022-12-16 00:23:40+00:00",
#           "docker.image/tags": [
#             "1.0-foo",
#             "1-foo",
#             "foo"
#           ]
#         }
#       }
#     ],
#     "basis-t": "12345678",
#     "tx": "12345678901234"
#   },
#   "extensions": {
#     "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
#   }
# }
def _getOCIsForRepo(repo_name: str) -> List[Tuple[str, int]]:
    """Obtain the list of DockerDSO tags for the specified repo"""
    if ":" in repo_name or "@" in repo_name or "/" in repo_name:
        error("Please use REPO (without :TAG or @sha256:SHA256)")
        return []  # for tests

    if sys.stdout.isatty():
        print("Fetching list of repos:", end="", flush=True)

    rese = _getListEDN(repo_name)
    if len(rese) < 1:  # error condition from _getListEDN()
        return []

    # gather all the tags and add the ones with the latest date
    repos: List[Tuple[str, int]] = []
    tmp: Dict[str, int] = {}
    for img in rese["docker-repository-tags"]["data"]:
        if "image" in img and "docker.image/tags" in img["image"]:
            name: str = ""
            # For now, take the longest tag, assuming it is the most accurate
            # name (eg, 8 vs 8.1 vs 8.1.2). This may need to be adjusted...
            for tagname in img["image"]["docker.image/tags"]:
                if len(tagname) > len(name):
                    name = tagname

            m: int = 0
            if (
                "docker.image/created-at" in img["image"]
                and img["image"]["docker.image/created-at"] is not None
            ):
                # convert to expected format (epoch)
                m = int(img["image"]["docker.image/created-at"].strftime("%s"))

            if name not in tmp or m > tmp[name]:
                tmp[name] = m

    for name in tmp:
        repos.append((name, tmp[name]))

    if sys.stdout.isatty():
        print(" done!")

    return copy.deepcopy(repos)


#
# CLI mains
#
def main_dso_dump_reports():
    # EXPERIMENTAL: this is subject to change
    _experimental()

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="dso-dump-reports",
        description="Fetch dso reports and save locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
dso-dump-reports pulls all the latest security reports for OCI images in
REPO and outputs them to:

  /path/to/reports/YY/MM/DD/dso/REPO/TAG/SHA256.json

Eg, to pull all dso security scan reports for org 'foo':

  $ dso-dump-reports --path /path/to/reports --name org
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
        help="fetch dso security report for REPO",
        metavar="REPO",
        type=str,
    )

    args: argparse.Namespace = parser.parse_args()

    sr = DockerDSOSecurityReportNew()

    # Find latest digest for all images
    oci_names: List[Tuple[str, int]] = _getOCIsForRepo(args.name)
    if len(oci_names) == 0:
        error("Could not enumerate any OCI image names")
        return  # for tests

    ocis: List[str] = []
    if sys.stdout.isatty():  # pragma: nocover
        print("Fetching digests for OCI names: ", end="", flush=True)
    for (oci, _) in oci_names:
        if sys.stdout.isatty():  # pragma: nocover
            print(".", end="", flush=True)

        name: str = "%s:%s" % (args.name, oci)
        digest: str = sr.getDigestForImage(name)
        if digest == "":
            warn("Could not find digest for %s" % name)
            continue
        ocis.append("%s@%s" % (args.name, digest.split("@")[1]))

    if sys.stdout.isatty():  # pragma: nocover
        print(" done!", flush=True)

    if len(ocis) == 0:
        error("Could not find any OCI image digests")
        return  # for tests

    # dso doesn't have dates or times in the security report, so we will
    # store them in a folder under today's date. Since the report path comes
    # from the date the report was fetched, we'll first search for the report
    # by the dso/TAG/SHA256.json to see if we previously downloaded it.

    # gather a list of potentially matching filenames
    json_files: Dict[str, str] = {}
    for root, _, files in os.walk(args.path):
        if not root.endswith("/dso/%s" % args.name):  # quick prune
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

    dir: str = args.path
    if not os.path.exists(dir):
        os.mkdir(dir)
    if not os.path.isdir(dir):  # pragma: nocover
        error("'%s' is not a directory" % dir)

    count: int = 0
    for full_name in ocis:
        j: Dict[str, Any] = {}
        _, tmp = sr.fetchScanReport(full_name, raw=True, quiet=True)
        if tmp != "":
            j = json.loads(tmp)
            if (
                "data" not in j
                or not isinstance(j["data"], dict)
                or "vulnerabilitiesByPackage" not in j["data"]
            ):
                warn("unexpected format of report for '%s'" % full_name)
                j = {}

        if len(j) == 0:
            continue

        repo_name: str = full_name.split("@")[0]
        sha256: str = full_name.split("@")[1].split(":")[-1]

        if sha256 not in json_files:  # create under dir with today's date
            dobj: datetime = datetime.now()
            dir = args.path
            for subdir in [
                str(dobj.year),
                "%0.2d" % dobj.month,
                "%0.2d" % dobj.day,
                "dso",
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
                    # sort_keys to make visual comparisons a bit easier
                    json.dump(_sorted_json_deep(j), fh, sort_keys=True, indent=2)
                    # json.dump() doesn't put a newline at the end, so add it
                    fh.seek(os.SEEK_SET, os.SEEK_END)
                    fh.write("\n")
                count += 1
        else:  # compare existing report to what we downloaded
            fn: str = json_files[sha256]
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
