#!/usr/bin/env python3

import copy
import os
import requests
from typing import Dict, Mapping, Union

from cvelib.common import error


def requestGetRaw(
    url: str, headers: Dict[str, str] = {}, params: Mapping[str, Union[str, int]] = {}
) -> requests.Response:
    """Wrapper around requests.get()"""
    hdrs: Dict[str, str] = copy.deepcopy(headers)
    if len(hdrs) == 0:
        if "GHTOKEN" in os.environ:
            hdrs["Authorization"] = "token %s" % os.getenv("GHTOKEN")

    # print("DEBUG: url=%s, headers=%s, params=%s" % (url, hdrs, params))
    return requests.get(url, headers=hdrs, params=params)


# TODO: type hint the return value (it's tricky)
def requestGet(
    url: str, headers: Dict[str, str] = {}, params: Mapping[str, Union[str, int]] = {}
):
    """Wrapper around requests.get() for json"""
    r: requests.Response = requestGetRaw(url, headers, params)
    if r.status_code >= 400:
        error("Problem fetching %s:\n%d - %s" % (url, r.status_code, r.json()))

    return r.json()


# https://docs.github.com/en/graphql/reference/objects#repositoryvulnerabilityalert
#
# GraphQL can be used on repos that have dependabot enabled. Oddly, there
# doesn't seem to be a way to see 'active' alerts. It seems that one would
# have to pull down the dependency graph (DependencyGraphDependency?) then
# see if anything in the RepositoryVulnerabilityAlerts are affected by looking
# at the versions....
#
# Eg:
# query = '''
# {
#   repository(name: "%s", owner: "%s") {
#     vulnerabilityAlerts(first: 100) {
#       nodes {
#         createdAt
#         dismissedAt
#         dismissReason
#         dismisser {
#           name
#         }
#         securityVulnerability {
#           package {
#             name
#           }
#           severity
#           advisory {
#             description
#           }
#         }
#         vulnerableManifestPath
#         securityAdvisory {
#           permalink
#         }
#       }
#     }
#   }
# }
# ''' % (repo, org)
# TODO: type hint the return value (it's tricky)
def queryGraphQL(query: str, headers: Dict[str, str] = {}):
    """Wrapper around requests.post() for graphql"""
    url = "https://api.github.com/graphql"
    hdrs: Dict[str, str] = copy.deepcopy(headers)
    if len(hdrs) == 0:
        if "GHTOKEN" in os.environ:
            hdrs["Authorization"] = "token %s" % os.getenv("GHTOKEN")

    # TODO: handle rate limits:
    # https://docs.github.com/en/graphql/overview/resource-limitations
    r: requests.Response = requests.post(url, json={"query": query}, headers=hdrs)
    if r.status_code != 200:
        error("Problem querying %s. %d - %s" % (url, r.status_code, query))

    return r.json()
