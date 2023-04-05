#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import copy
import os
import requests
import sys
from typing import Any, Dict, List, Mapping, MutableMapping, Tuple, Union

from cvelib.common import error, warn


def requestGetRaw(
    url: str, headers: Dict[str, str] = {}, params: Mapping[str, Union[str, int]] = {}
) -> requests.Response:
    """Wrapper around requests.get()"""
    hdrs: Dict[str, str] = copy.deepcopy(headers)
    if (
        url.startswith("https://api.github.com/")
        and "Authorization" not in hdrs
        and "GHTOKEN" in os.environ
    ):
        hdrs["Authorization"] = "token %s" % os.getenv("GHTOKEN")

    # print("DEBUG: url=%s, headers=%s, params=%s" % (url, hdrs, params))
    return requests.get(url, headers=hdrs, params=params)


# TODO: type hint the return value (it's tricky)
def requestGet(
    url: str, headers: Dict[str, str] = {}, params: Mapping[str, Union[str, int]] = {}
):
    """Wrapper around requests.get() for json"""
    r: requests.Response = requestGetRaw(url, headers, params)
    if r.status_code >= 400:  # pragma: nocover
        error("Problem fetching %s:\n%d - %s" % (url, r.status_code, r.json()))

    return r.json()


# TODO: type hint the return value (it's tricky)
def queryGHGraphQL(query: str, headers: Dict[str, str] = {}):
    """Wrapper around requests.post() for graphql"""
    url = "https://api.github.com/graphql"
    hdrs: Dict[str, str] = copy.deepcopy(headers)
    if "Authorization" not in hdrs and "GHTOKEN" in os.environ:
        hdrs["Authorization"] = "token %s" % os.getenv("GHTOKEN")

    # TODO: handle rate limits:
    # https://docs.github.com/en/graphql/overview/resource-limitations
    r: requests.Response = requests.post(url, json={"query": query}, headers=hdrs)
    if r.status_code != 200:  # pragma: nocover
        error("Problem querying %s. %d - %s" % (url, r.status_code, query))

    return r.json()


# https://docs.github.com/en/rest/guides/using-pagination-in-the-rest-api?apiVersion=2022-11-28#using-link-headers
def ghAPIGetList(
    url: str,
    headers: Dict[str, str] = {},
    params: MutableMapping[str, Union[str, int]] = {},
    progress: bool = True,
    do_exit: bool = True,
) -> Tuple[int, List[Any]]:
    """Convenience functions to fetch paginated json documents of lists from GitHub"""
    if not url.startswith("https://api.github.com/"):
        error("ghAPIGet() only supports https://api.github.com/ URLs", do_exit=do_exit)
        return 1, []

    hdrs: Dict[str, str] = copy.deepcopy(headers)
    if "Authorization" not in hdrs and "GHTOKEN" in os.environ:
        hdrs["Authorization"] = "token %s" % os.getenv("GHTOKEN")
    if "Accept" not in hdrs:
        hdrs["Accept"] = "application/vnd.github+json"
    if "X-GitHub-Api-Version" not in hdrs:
        hdrs["X-GitHub-Api-Version"] = "2022-11-28"

    parms: MutableMapping[str, Union[str, int]] = copy.deepcopy(params)
    if "per_page" not in parms:
        parms["per_page"] = 100

    if sys.stdout.isatty() and progress:
        print("Fetching %s: " % url, end="", flush=True)

    jsons: List[Any] = []
    while url != "":
        if sys.stdout.isatty() and progress:
            print(".", end="", flush=True)

        try:
            r: requests.Response = requestGetRaw(url, headers=headers, params=params)
        except requests.exceptions.RequestException as e:  # pragma: nocover
            if do_exit:
                raise
            warn("Skipping %s (request error: %s)" % (url, str(e)))
            return 1, []

        if r.status_code >= 400:  # pragma: nocover
            error(
                "Problem fetching %s:\n%d - %s" % (url, r.status_code, r.json()),
                do_exit=do_exit,
            )
            return r.status_code, []

        found_link: bool = False
        if "Link" in r.headers:
            tmp: List[str] = r.headers["Link"].split(",")
            for i in tmp:
                # '<https://.../alerts?per_page=100&after=Y3Vyc29yOnYyOpHO0RA03w%3D%3D>; rel="next"'
                if '>; rel="next"' in i:
                    last: str = url
                    url = i.split("<")[1].split(">")[0]
                    if url == last:
                        # shouldn't happen, but if it does, don't loop forever
                        break
                    found_link = True
                    break
        if not found_link:
            url = ""  # nothing more to do

        # This assumes that the paginated responses are lists of something.
        # Since we want to return a singled list and not lists of lists,
        # concatenate the response json to jsons.
        jsons += r.json()

    if sys.stdout.isatty() and progress:
        print(" done!")

    return 0, jsons
