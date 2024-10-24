#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import copy
import os
import requests
import sys
from typing import Any, Dict, List, Mapping, MutableMapping, Tuple, Union

from cvelib.common import error, warn, getCacheDirPath


def _install_request_cache(url: str):
    # use the requests-cache module only if it is installed. Disable caching
    # with SEDG_REQUESTS_CACHE=none
    requests_cache = None
    if (
        "SEDG_REQUESTS_CACHE" not in os.environ
        or os.environ["SEDG_REQUESTS_CACHE"] != "none"
    ):  # pragma: nocover
        try:
            # if "requests_cache" not in sys.modules:
            import requests_cache

            # require version 1 for match_headers (0.9 seems ok too)
            # pip install "requests-cache>=1.0"
            if "requests_cache" in sys.modules and (
                int(requests_cache.__version__.split(".")[0]) > 0
                or int(requests_cache.__version__.split(".")[1]) >= 9
            ):
                cache_dir: str = getCacheDirPath()
                if not os.path.exists(os.path.dirname(cache_dir)):
                    os.mkdir(os.path.dirname(cache_dir), 0o700)
                if not os.path.exists(cache_dir):
                    os.mkdir(cache_dir, 0o700)
                cache_fn: str = os.path.join(cache_dir, "sedg-cache")

                expiry: int = 3600  # 1 hour
                allowable_codes = [200]
                if url.startswith("https://api.github.com/"):
                    # 200 and 204 are used with GitHub and 403 and 404 with
                    # GitHub Advanced Security
                    allowable_codes = [200, 204, 403, 404]

                requests_cache.patcher.install_cache(
                    cache_name=cache_fn,
                    backend="sqlite",
                    expire_after=expiry,
                    allowable_codes=allowable_codes,
                    allowable_methods=["GET", "POST"],
                    match_headers=True,
                    ignored_parameters=["Authorization", "cookie"],
                )
                # for some reason, it's written with world read
                if os.path.exists(cache_fn + ".sqlite"):
                    os.chmod(cache_fn + ".sqlite", 0o0600)
        except Exception:
            # print("DEBUG: requests_cache could not be imported")
            pass

    return requests_cache


def requestRaw(
    method: str,
    url: str,
    headers: Dict[str, str] = {},
    params: Mapping[str, Union[str, int]] = {},
    data=None,
) -> requests.Response:
    """Wrapper around requests.get() and requests.post()"""
    reqc = _install_request_cache(url)
    hdrs: Dict[str, str] = copy.deepcopy(headers)
    if (
        url.startswith("https://api.github.com/")
        and "Authorization" not in hdrs
        and "GHTOKEN" in os.environ
    ):
        hdrs["Authorization"] = "Bearer %s" % os.getenv("GHTOKEN")

    # print("DEBUG: url=%s, headers=%s, params=%s, data=%s" % (url, hdrs, params, data))
    res: requests.Response
    try:
        if method == "post":
            res = requests.post(url, headers=hdrs, params=params, data=data)
        else:
            res = requests.get(url, headers=hdrs, params=params)
    except AttributeError as e:  # pragma: nocover
        # For some reason, requests to GitHub sometimes traceback with
        # AttributeError: 'dict' object has no attribute 'raw' when
        # requests_cache is in use. Let's try to work around that by retrying
        # without the cache
        if reqc is None:
            raise
        warn("requests_cache errored with AttributeError: %s" % e)
        warn("Retrying %s without caching" % url)
        hdrs["Cache-Control"] = "no-cache"
        if method == "post":
            res = requests.post(url, headers=hdrs, params=params, data=data)
        else:
            res = requests.get(url, headers=hdrs, params=params)

    return res


def requestGetRaw(
    url: str, headers: Dict[str, str] = {}, params: Mapping[str, Union[str, int]] = {}
) -> requests.Response:
    """Wrapper around requests.get()"""
    return requestRaw("get", url, headers, params)


# TODO: type hint the return value (it's tricky)
def requestGet(
    url: str, headers: Dict[str, str] = {}, params: Mapping[str, Union[str, int]] = {}
):
    """Wrapper around requests.get() for json"""
    r: requests.Response = requestGetRaw(url, headers, params)
    if r.status_code >= 400:  # pragma: nocover
        error("Problem fetching %s:\n%d - %s" % (url, r.status_code, str(r.content)))

    return r.json()


def requestPostRaw(
    url: str,
    headers: Dict[str, str] = {},
    params: Mapping[str, Union[str, int]] = {},
    data=None,
) -> requests.Response:
    """Wrapper around requests.post()"""
    return requestRaw("post", url, headers, params, data)


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
        hdrs["Authorization"] = "Bearer %s" % os.getenv("GHTOKEN")
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
            r: requests.Response = requestGetRaw(url, headers=hdrs, params=parms)
        except requests.exceptions.RequestException as e:  # pragma: nocover
            if do_exit:
                raise
            warn("Skipping %s (request error: %s)" % (url, str(e)))
            return 1, []

        if r.status_code >= 400:  # pragma: nocover
            error(
                "Problem fetching %s:\n%d - %s" % (url, r.status_code, str(r.content)),
                do_exit=do_exit,
            )
            return r.status_code, []

        found_link: bool = False
        link_header: Union[str, None] = r.headers.get("Link")
        if link_header is not None:
            tmp: List[str] = link_header.split(",")
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
