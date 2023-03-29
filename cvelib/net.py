#!/usr/bin/env python3
#
# Copyright (c) 2023 InfluxData
# Author: Jamie Strandboge <jamie@influxdata.com>
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
    if r.status_code >= 400:  # pragma: nocover
        error("Problem fetching %s:\n%d - %s" % (url, r.status_code, r.json()))

    return r.json()


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
    if r.status_code != 200:  # pragma: nocover
        error("Problem querying %s. %d - %s" % (url, r.status_code, query))

    return r.json()
