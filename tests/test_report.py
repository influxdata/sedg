"""test_report.py: tests for report.py module"""
#
# SPDX-License-Identifier: MIT

from unittest import TestCase, mock
import copy
import datetime
import os
import tempfile

import cvelib.common
import cvelib.cve
import cvelib.github
import cvelib.report
import cvelib.scan
import tests.testutil


def mocked_requests_get__getGHReposAll(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}
            self.content = ""

        def json(self):
            return self.json_data

    # https://docs.github.com/en/rest/repos/repos#list-organization-repositories
    # The GitHub json for https://api.github.com/orgs/ORG/repos is:
    #   [
    #     {
    #       "archived": True|False,
    #       ...
    #       "id": N,
    #       ...
    #       "license": {
    #         "key": "mit",
    #         ...
    #       },
    #       ...
    #       "mirror_url": None,
    #       "name": "<name1>",
    #       ...
    #       "security_and_analysis": {
    #         "secret_scanning": {
    #           "status": "disabled"
    #         },
    #         ...
    #       },
    #       ...
    #       "topics": [
    #         "<topic1>",
    #         "<topic2>"
    #       ],
    #       ...
    #     },
    #     ...
    #   ]
    #
    # but _getGHReposAll() only cares about "name" and "archived". We mock up a
    # subset of the GitHub response.
    #
    # _getGHReposAll() uses ghAPIGetList() which has tests for pagination. For
    # simplicity, return only single pages here
    if args[0] == "https://api.github.com/orgs/valid-org/repos":
        return MockResponse(
            [
                {
                    "archived": False,
                    "name": "foo",
                    "id": 1000,
                    "license": {"key": "mit"},
                    "mirror_url": False,
                    "topics": ["topic1", "topic2"],
                    "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
                },
                {
                    "archived": True,
                    "name": "bar",
                    "id": 1001,
                    "license": {"key": "mit"},
                    "mirror_url": False,
                    "topics": ["topic2"],
                    "security_and_analysis": {
                        "secret_scanning": {"status": "disabled"}
                    },
                },
                {
                    "archived": False,
                    "private": True,
                    "name": "baz",
                    "id": 1002,
                    "license": {"key": "mit"},
                    "mirror_url": False,
                    "topics": ["topic1"],
                    "security_and_analysis": {
                        "secret_scanning": {"status": "disabled"}
                    },
                },
            ],
            200,
        )

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def mocked_requests_get__getGHIssuesForRepo(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}
            self.content = ""

        def json(self):
            return self.json_data

    # https://docs.github.com/en/rest/issues/issues#list-repository-issues
    # The GitHub json for https://api.github.com/repos/ORG/REPO/issues is:
    #   [
    #     {
    #       "url": "<url>",
    #       "html_url": "<url>",
    #       ...
    #       "id": N,
    #       ...
    #       "user": {
    #         "login": "<user>",
    #         ...
    #       },
    #       ...
    #       "labels": [
    #         {"id": N, "name": "<name>", ... }
    #       ],
    #       ...
    #       "locked": False,
    #       ...
    #       "pull_requests": { ... },  // optional
    #       ...
    #       "state_reason": None
    #       ...
    #       "updated_at": "2022-07-08T18:27:30Z"
    #     },
    #     ...
    #   ]
    #
    # but _getGHIssuesForRepo() only cares about this from the GitHub response:
    #   {
    #     "html_url": "<url>"
    #     "labels": [{"name": "<name>"],
    #     "pull_request": {...},
    #   }
    #
    # _getGHIssuesForRepo() uses _getGHReposAll() to fetch issues and it
    # handles pagination (and is tested elsewhere), so keep these mocks simple
    # and return only a single page.
    if args[0] == "https://api.github.com/repos/valid-org/410-repo/issues":
        return MockResponse(None, 410)
    elif args[0] == "https://api.github.com/repos/valid-org/404-repo/issues":
        return MockResponse(None, 404)
    elif args[0] == "https://api.github.com/repos/valid-org/400-repo/issues":
        return MockResponse(None, 400)
    elif args[0] == "https://api.github.com/repos/valid-org/empty-repo/issues":
        return MockResponse([], 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/repos":
        return MockResponse(
            [
                {
                    "archived": False,
                    "name": "valid-repo",
                    "id": 1000,
                    "license": {"key": "mit"},
                    "mirror_url": False,
                    "topics": ["topic1", "topic2"],
                    "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
                },
                {
                    "archived": True,
                    "name": "other-repo",
                    "id": 1001,
                    "license": {"key": "mit"},
                    "mirror_url": False,
                    "topics": ["topic2"],
                    "security_and_analysis": {
                        "secret_scanning": {"status": "disabled"}
                    },
                },
            ],
            200,
        )
    elif args[0] == "https://api.github.com/repos/valid-org/other-repo/issues":
        return MockResponse(
            [
                {
                    "html_url": "https://github.com/valid-org/other-repo/issues/77",
                    "labels": [
                        {"name": "label1", "id": 5001},
                        {"name": "label2", "id": 5002},
                    ],
                    "locked": False,
                    "id": 77,
                    "state_reason": None,
                    "user": {"login": "user1", "id": 3000},
                    "updated_at": "2022-07-03T18:27:30Z",
                },
            ],
            200,
        )
    elif args[0] == "https://api.github.com/repos/valid-org/valid-repo/issues":
        if "since" in kwargs["params"]:
            if kwargs["params"]["since"] == "2022-06-22T12:33:47Z":
                return MockResponse(
                    [
                        {
                            "html_url": "https://github.com/valid-org/valid-repo/issues/1",
                            "labels": [{"name": "label1", "id": 2001}],
                            "locked": False,
                            "id": 1,
                            "state_reason": None,
                            "user": {"login": "user1", "id": 3000},
                            "updated_at": "2022-07-01T18:27:30Z",
                        },
                        {
                            "html_url": "https://github.com/valid-org/valid-repo/issues/2",
                            "labels": [{"name": "label2", "id": 2002}],
                            "locked": False,
                            "id": 2,
                            "state_reason": None,
                            "user": {"login": "user1", "id": 3000},
                            "updated_at": "2022-07-02T18:27:30Z",
                        },
                        {
                            "html_url": "https://github.com/valid-org/valid-repo/issues/3",
                            "labels": [
                                {"name": "label1", "id": 2001},
                                {"name": "label2", "id": 2002},
                            ],
                            "locked": False,
                            "id": 3,
                            "state_reason": None,
                            "user": {"login": "user1", "id": 3000},
                            "updated_at": "2022-07-03T18:27:30Z",
                        },
                        {
                            "html_url": "https://github.com/valid-org/valid-repo/issues/4",
                            "labels": [],
                            "locked": False,
                            "id": 4,
                            "state_reason": None,
                            "user": {"login": "user1", "id": 3000},
                            "updated_at": "2022-07-04T18:27:30Z",
                        },
                    ],
                    200,
                )
            elif kwargs["params"]["since"] == "2022-07-02T20:04:31Z":
                return MockResponse(
                    [
                        {
                            "html_url": "https://github.com/valid-org/valid-repo/issues/3",
                            "labels": [
                                {"name": "label1", "id": 2001},
                                {"name": "label2", "id": 2002},
                            ],
                            "locked": False,
                            "id": 3,
                            "state_reason": None,
                            "user": {"login": "user1", "id": 3000},
                            "updated_at": "2022-07-03T18:27:30Z",
                        },
                        {
                            "html_url": "https://github.com/valid-org/valid-repo/issues/4",
                            "labels": [],
                            "locked": False,
                            "id": 4,
                            "state_reason": None,
                            "user": {"login": "user1", "id": 3000},
                            "updated_at": "2022-07-04T18:27:30Z",
                        },
                    ],
                    200,
                )
            elif kwargs["params"]["since"] == "2022-07-07T20:06:38Z":
                return MockResponse([], 200)
        elif "labels" in kwargs["params"] and kwargs["params"]["labels"] == "label1":
            # return things with only 'label1'
            return MockResponse(
                [
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/1",
                        "labels": [{"name": "label1", "id": 2001}],
                        "locked": False,
                        "id": 1,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-01T18:27:30Z",
                    },
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/3",
                        "labels": [
                            {"name": "label1", "id": 2001},
                            {"name": "label2", "id": 2002},
                        ],
                        "locked": False,
                        "id": 3,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-03T18:27:30Z",
                    },
                ],
                200,
            )
        else:
            return MockResponse(
                [
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/1",
                        "labels": [{"name": "label1", "id": 2001}],
                        "locked": False,
                        "id": 1,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-01T18:27:30Z",
                    },
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/2",
                        "labels": [{"name": "label2", "id": 2002}],
                        "locked": False,
                        "id": 2,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-02T18:27:30Z",
                    },
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/3",
                        "labels": [
                            {"name": "label1", "id": 2001},
                            {"name": "label2", "id": 2002},
                        ],
                        "locked": False,
                        "id": 3,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-03T18:27:30Z",
                    },
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/4",
                        "labels": [],
                        "locked": False,
                        "id": 4,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-04T18:27:30Z",
                    },
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/5",
                        "labels": [],
                        "locked": False,
                        "id": 5,
                        "pull_request": {"url": "..."},
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-05T18:27:30Z",
                    },
                ],
                200,
            )

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def mocked_requests_get__getGHAlertsEnabled(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}
            self.content = ""

        def json(self):  # pragma: nocover
            return self.json_data

    if (
        args[0]
        == "https://api.github.com/repos/valid-org/valid-repo/vulnerability-alerts"
    ):
        # this is for dependabot alerts
        return MockResponse(None, 204)
    elif (
        args[0]
        == "https://api.github.com/repos/valid-org/disabled-repo/vulnerability-alerts"
    ):
        # this is for dependabot alerts
        return MockResponse(None, 404)
    elif args[0] == "https://api.github.com/orgs/valid-org/repos":
        # this is for the _getGHReposAll(org) for secret_scanning
        return MockResponse(
            [
                {
                    "archived": False,
                    "name": "valid-repo",
                    "id": 1000,
                    "license": {"key": "mit"},
                    "mirror_url": False,
                    "topics": ["topic1", "topic2"],
                    "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
                },
                {
                    "archived": True,
                    "name": "disabled-repo",
                    "id": 1001,
                    "license": {"key": "mit"},
                    "mirror_url": False,
                    "topics": ["topic2"],
                    "security_and_analysis": {
                        "secret_scanning": {"status": "disabled"}
                    },
                },
            ],
            200,
        )
    elif (
        args[0]
        == "https://api.github.com/repos/valid-org/valid-repo/code-scanning/alerts"
    ):
        # this is for dependabot alerts
        return MockResponse(None, 204)
    elif (
        args[0]
        == "https://api.github.com/repos/valid-org/disabled-repo/code-scanning/alerts"
    ):
        # this is for dependabot alerts
        return MockResponse(None, 404)

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def _getMockedAlertsJSON(alert_type="all"):
    dependabot = [
        {
            "created_at": "2022-07-01T18:27:30Z",
            "dependency": {
                "manifest_path": "go.sum",
                "package": {
                    "name": "github.com/foo/bar",
                },
            },
            "dismissed_at": "2022-07-02T18:27:30Z",
            "dismissed_by": {"login": "ghuser1"},
            "dismissed_comment": "some comment",
            "dismissed_reason": "tolerable",
            "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/1",
            "repository": {"name": "valid-repo", "private": False},
            "security_advisory": {
                "ghsa_id": "GHSA-a",
                "severity": "low",
            },
        },
        {
            "created_at": "2022-07-03T18:27:30Z",
            "dependency": {
                "manifest_path": "path/yarn.lock",
                "package": {
                    "name": "baz",
                },
            },
            "dismissed_at": None,
            "dismissed_by": None,
            "dismissed_comment": None,
            "dismissed_reason": None,
            "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/3",
            "repository": {"name": "valid-repo", "private": False},
            "security_advisory": {
                "ghsa_id": "GHSA-b",
                "severity": "medium",
            },
        },
        {
            "created_at": "2022-07-04T18:27:30Z",
            "dependency": {
                "manifest_path": "path/yarn.lock",
                "package": {
                    "name": "baz",
                },
            },
            "dismissed_at": None,
            "dismissed_by": None,
            "dismissed_comment": None,
            "dismissed_reason": None,
            "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/4",
            "repository": {"name": "valid-repo", "private": False},
            "security_advisory": {
                "ghsa_id": "GHSA-c",
                "severity": "medium",
            },
        },
        {
            "created_at": "2022-07-05T18:27:30Z",
            "dependency": {
                "manifest_path": "path/yarn.lock",
                "package": {
                    "name": "@norf/quz",
                },
            },
            "dismissed_at": None,
            "dismissed_by": None,
            "dismissed_comment": None,
            "dismissed_reason": None,
            "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/5",
            "repository": {"name": "valid-repo", "private": False},
            "security_advisory": {
                "ghsa_id": "GHSA-d",
                "severity": "unknown",
            },
        },
    ]

    secret = [
        {
            "created_at": "2022-07-01T18:15:30Z",
            "secret_type_display_name": "Some Leaked Secret",
            "resolved_at": "2022-07-02T18:15:30Z",
            "resolved_by": {"login": "ghuser2"},
            "resolution_comment": "some secret comment",
            "resolution": "revoked",
            "html_url": "https://github.com/valid-org/valid-repo/security/secret-scanning/20",
            "repository": {"name": "valid-repo", "private": False},
        },
        {
            "created_at": "2022-07-05T18:15:30Z",
            "secret_type_display_name": "Some Other Leaked Secret",
            "resolved_at": None,
            "resolved_by": None,
            "resolution_comment": None,
            "resolution": None,
            "html_url": "https://github.com/valid-org/valid-repo/security/secret-scanning/21",
            "repository": {"name": "valid-repo", "private": False},
        },
    ]

    code = [
        {
            "created_at": "2022-07-01T17:15:30Z",
            "dismissed_at": "2022-07-02T17:15:30Z",
            "dismissed_by": {"login": "ghuser3"},
            "dismissed_comment": "some code comment",
            "dismissed_reason": "false positive",
            "html_url": "https://github.com/valid-org/valid-repo/security/code-scanning/30",
            "repository": {"name": "valid-repo", "private": False},
            "rule": {
                "description": "Some Code Finding",
                "security_severity_level": "high",
            },
        },
        {
            "created_at": "2022-07-05T17:15:30Z",
            "dismissed_at": None,
            "dismissed_by": None,
            "dismissed_comment": None,
            "dismissed_reason": None,
            "html_url": "https://github.com/valid-org/valid-repo/security/code-scanning/31",
            "repository": {"name": "valid-repo", "private": False},
            "rule": {
                "description": "Some Other Code Finding",
                "security_severity_level": "medium",
            },
        },
    ]

    if alert_type == "dependabot":
        return dependabot
    if alert_type == "secret-scanning":
        return secret
    if alert_type == "secret-scanning-private":
        tmp = copy.deepcopy(secret)
        tmp[0]["repository"]["private"] = True
        tmp[1]["repository"]["private"] = True
        return tmp
    if alert_type == "code-scanning":
        return code
    return dependabot + secret + code


def mocked_requests_get__getGHAlertsAllFull(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}
            self.content = ""

        def json(self):  # pragma: no cover
            return self.json_data

    if args[0] == "https://api.github.com/orgs/valid-org/dependabot/alerts":
        return MockResponse(_getMockedAlertsJSON("dependabot"), 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/secret-scanning/alerts":
        return MockResponse(_getMockedAlertsJSON("secret-scanning"), 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/code-scanning/alerts":
        return MockResponse(_getMockedAlertsJSON("code-scanning"), 200)

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def mocked_requests_get__getGHAlertsAllCode(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}

        def json(self):  # pragma: no cover
            return self.json_data

    if args[0] == "https://api.github.com/orgs/valid-org/code-scanning/alerts":
        return MockResponse(_getMockedAlertsJSON("code-scanning"), 200)

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def mocked_requests_get__getGHAlertsAllDependabot(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}

        def json(self):  # pragma: no cover
            return self.json_data

    if args[0] == "https://api.github.com/orgs/valid-org/dependabot/alerts":
        return MockResponse(_getMockedAlertsJSON("dependabot"), 200)

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def mocked_requests_get__getGHAlertsAllSecret(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}

        def json(self):  # pragma: no cover
            return self.json_data

    if args[0] == "https://api.github.com/orgs/valid-org/secret-scanning/alerts":
        return MockResponse(_getMockedAlertsJSON("secret-scanning"), 200)

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def mocked_requests_get__getGHAlertsAllSecretPrivate(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}

        def json(self):  # pragma: no cover
            return self.json_data

    if args[0] == "https://api.github.com/orgs/valid-org/secret-scanning/alerts":
        return MockResponse(_getMockedAlertsJSON("secret-scanning-private"), 200)

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


class TestReport(TestCase):
    """Tests for the report functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        self.orig_ghtoken = None
        self.maxDiff = None
        self.tmpdir = None
        self.orig_xdg_config_home = None

        if "GHTOKEN" in os.environ:
            self.orig_ghtoken = os.getenv("GHTOKEN")
        os.environ["GHTOKEN"] = "fake-test-token"
        os.environ["TEST_UPDATE_PROGRESS"] = "0"

        tests.testutil.disableRequestsCache()

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.orig_ghtoken is not None:
            os.environ["GHTOKEN"] = self.orig_ghtoken
            self.orig_ghtoken = None

        # TODO: when pass these around, can remove this
        cvelib.report.repos_all = {}
        cvelib.report.issues_ind = {}
        if "TEST_UPDATE_PROGRESS" in os.environ:
            del os.environ["TEST_UPDATE_PROGRESS"]

        if self.orig_xdg_config_home is None:
            if "XDG_CONFIG_HOME" in os.environ:
                del os.environ["XDG_CONFIG_HOME"]
        else:
            os.environ["XDG_CONFIG_HOME"] = self.orig_xdg_config_home
            self.orig_xdg_config_home = None
        cvelib.common.configCache = None

        if self.tmpdir is not None:
            cvelib.common.recursive_rm(self.tmpdir)

        if "SEDG_EXPERIMENTAL" in os.environ:
            del os.environ["SEDG_EXPERIMENTAL"]

    def _cve_template(self, cand="", references=[]):
        """Generate a valid CVE to mimic what readCve() might see"""
        d = {
            "Candidate": cand,
            "OpenDate": "2020-06-29",
            "CloseDate": "",
            "PublicDate": "",
            "References": "\n %s" % " \n".join(references)
            if len(references) > 0
            else "",
            "Description": "\n Some description\n more desc",
            "Notes": "\n person> some notes\n  more notes\n person2> blah",
            "Mitigation": "",
            "Bugs": "",
            "Priority": "medium",
            "Discovered-by": "",
            "Assigned-to": "",
            "CVSS": "",
        }
        return copy.deepcopy(d)

    def _mock_cve_list_basic(self):
        """Generate a List[cvelib.cve.CVE]"""
        cves = []
        for n in [1, 2, 3]:
            d = self._cve_template(
                cand="CVE-2022-GH100%d#valid-repo" % n,
                references=["https://github.com/valid-org/valid-repo/issues/%d" % n],
            )
            cve = cvelib.cve.CVE()
            cve.setData(d)
            cves.append(cve)
        return copy.deepcopy(cves)

    def _mock_cve_data_mixed(self):
        """Generate a List[cvelib.cve.CVE]"""

        def _write_cve(cve_fn, d):
            content = tests.testutil.cveContentFromDict(d)
            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")
        content = (
            """[Locations]
cve-data = %s
"""
            % self.tmpdir
        )
        self.orig_xdg_config_home, self.tmpdir = tests.testutil._newConfigFile(
            content, self.tmpdir
        )

        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        # regular CVE - foo
        d = self._cve_template(
            cand="CVE-2022-0001",
            references=["https://www.cve.org/CVERecord?id=CVE-2022-0001"],
        )
        d["upstream_foo"] = "needs-triage"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # regular CVE - bar
        d = self._cve_template(
            cand="CVE-2022-0002",
            references=["https://www.cve.org/CVERecord?id=CVE-2022-0002"],
        )
        d["Priority"] = "low"
        d["upstream_bar"] = "needs-triage"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # regular CVE - baz and baz/v1
        d = self._cve_template(
            cand="CVE-2022-0003",
            references=["https://www.cve.org/CVERecord?id=CVE-2022-0003"],
        )
        d["Priority"] = "low"
        d["upstream_baz"] = "needs-triage"
        d["upstream_baz/v1"] = "needs-triage"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # placeholder with priority override
        d = self._cve_template(
            cand="CVE-2022-NNN1",
            references=["https://www.cve.org/CVERecord?id=CVE-2022-NNN1"],
        )
        d["upstream_foo"] = "needed"
        d["Priority_foo"] = "low"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # github placeholder with tag
        d = self._cve_template(
            cand="CVE-2022-GH1#foo",
            references=["https://github.com/org/foo/issues/1"],
        )
        d["git/org_foo"] = "pending"
        d["Tags_foo"] = "limit-report"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # github placeholder with gh-dependabot and gh-secrets discovered-by
        d = self._cve_template(
            cand="CVE-2022-GH2#bar",
            references=["https://github.com/org/bar/issues/2"],
        )
        d["Priority"] = "high"
        d["git/org_bar"] = "needed"
        d["Discovered-by"] = "gh-secrets, gh-dependabot"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # regular CVE, closed
        d = self._cve_template(
            cand="CVE-2021-9991",
            references=["https://www.cve.org/CVERecord?id=CVE-2021-9991"],
        )
        d["upstream_foo"] = "released"
        d["Priority"] = "critical"
        d["CloseDate"] = "2021-06-27"
        _write_cve(os.path.join(cveDirs["retired"], d["Candidate"]), d)

        # regular CVE, closed
        d = self._cve_template(
            cand="CVE-2021-9992",
            references=["https://www.cve.org/CVERecord?id=CVE-2021-9992"],
        )
        d["git/org_bar"] = "released"
        d["Priority"] = "negligible"
        d["CloseDate"] = "2021-06-28"
        _write_cve(os.path.join(cveDirs["retired"], d["Candidate"]), d)

        # regular CVE, ignored
        d = self._cve_template(
            cand="CVE-2021-9993",
            references=["https://www.cve.org/CVERecord?id=CVE-2021-9993"],
        )
        d["upstream_bar"] = "ignored"
        d["Priority"] = "negligible"
        d["CloseDate"] = "2021-06-29"
        _write_cve(os.path.join(cveDirs["retired"], d["Candidate"]), d)

        return cveDirs

    def _mock_cve_data_ghas_mixed(self):
        """Generate a List[cvelib.cve.CVE] with ghas"""

        def _write_cve(cve_fn, d):
            content = tests.testutil.cveContentFromDict(d)
            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")
        content = (
            """[Locations]
cve-data = %s
"""
            % self.tmpdir
        )
        self.orig_xdg_config_home, self.tmpdir = tests.testutil._newConfigFile(
            content, self.tmpdir
        )

        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        # regular CVE - foo
        d = self._cve_template(
            cand="CVE-2022-0001",
            references=["https://www.cve.org/CVERecord?id=CVE-2022-0001"],
        )
        d["upstream_foo"] = "needs-triage"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # github placeholder with tag
        d = self._cve_template(
            cand="CVE-2022-GH1#foo",
            references=["https://github.com/org/foo/issues/1"],
        )
        d["git/org_foo"] = "pending"
        d["Tags_foo"] = "limit-report"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # github for dependabot, secret-scanning and code-scanning
        d = self._cve_template(
            cand="CVE-2022-GH2#bar",
            references=["https://github.com/org/bar/issues/2"],
        )
        d["Priority"] = "high"
        d["git/org_bar"] = "needed"
        d["Discovered-by"] = "gh-secrets, gh-dependabot, gh-code"
        d[
            "GitHub-Advanced-Security"
        ] = """
 - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-a
   severity: medium
   status: needed
   url: https://github.com/org/bar/security/dependabot/1
 - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-b
   severity: high
   status: needed
   url: https://github.com/org/bar/security/dependabot/2
 - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-b
   severity: high
   status: needed
   url: https://github.com/org/bar/security/dependabot/2
 - type: dependabot
   dependency: corge
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-c
   severity: high
   status: dismissed (tolerable; who)
   url: https://github.com/org/bar/security/dependabot/3
 - type: secret-scanning
   secret: baz
   detectedIn: path/to/file
   severity: high
   status: needed
   url: https://github.com/org/bar/security/secret-scanning/1
 - type: secret-scanning
   secret: baz
   detectedIn: path/to/file
   severity: high
   status: needed
   url: https://github.com/org/bar/security/secret-scanning/2
 - type: code-scanning
   description: quxx
   detectedIn: path/to/file
   severity: low
   status: needed
   url: https://github.com/org/bar/security/code-scanning/1"""
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # 2nd dependabot
        d = self._cve_template(
            cand="CVE-2022-GH3#bar",
            references=["https://github.com/org/bar/issues/3"],
        )
        d["Priority"] = "medium"
        d["git/org_bar"] = "needed"
        d["Discovered-by"] = "gh-dependabot"
        d[
            "GitHub-Advanced-Security"
        ] = """
 - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-d
   severity: medium
   status: needed
   url: https://github.com/org/bar/security/dependabot/4"""
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # released dependabot
        d = self._cve_template(
            cand="CVE-2022-GH4#bar",
            references=["https://github.com/org/bar/issues/4"],
        )
        d["Priority"] = "low"
        d["git/org_bar"] = "released"
        d["Discovered-by"] = "gh-dependabot"
        d[
            "GitHub-Advanced-Security"
        ] = """
 - type: dependabot
   dependency: corge
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-e
   severity: low
   status: released
   url: https://github.com/org/bar/security/dependabot/5"""
        _write_cve(os.path.join(cveDirs["retired"], d["Candidate"]), d)

        # per-pkg priority override dependabot
        d = self._cve_template(
            cand="CVE-2022-GH5#bar",
            references=["https://github.com/org/bar/issues/5"],
        )
        d["Priority"] = "critical"
        d["Priority_bar"] = "negligible"
        d["git/org_bar"] = "needed"
        d["Discovered-by"] = "gh-dependabot"
        d[
            "GitHub-Advanced-Security"
        ] = """
 - type: dependabot
   dependency: qux
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-f
   severity: critical
   status: needed
   url: https://github.com/org/bar/security/dependabot/6"""
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # regular CVE, closed
        d = self._cve_template(
            cand="CVE-2021-9991",
            references=["https://www.cve.org/CVERecord?id=CVE-2021-9991"],
        )
        d["upstream_foo"] = "released"
        d["Priority"] = "critical"
        d["CloseDate"] = "2021-06-27"
        _write_cve(os.path.join(cveDirs["retired"], d["Candidate"]), d)

        # regular CVE, ignored
        d = self._cve_template(
            cand="CVE-2021-9993",
            references=["https://www.cve.org/CVERecord?id=CVE-2021-9993"],
        )
        d["upstream_bar"] = "ignored"
        d["Priority"] = "negligible"
        d["CloseDate"] = "2021-06-29"
        _write_cve(os.path.join(cveDirs["retired"], d["Candidate"]), d)

        return cveDirs

    def _mock_cve_data_scans_mixed(self):
        """Generate a List[cvelib.cve.CVE] with scan reports"""

        def _write_cve(cve_fn, d):
            content = tests.testutil.cveContentFromDict(d)
            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")
        content = (
            """[Locations]
cve-data = %s
"""
            % self.tmpdir
        )
        self.orig_xdg_config_home, self.tmpdir = tests.testutil._newConfigFile(
            content, self.tmpdir
        )

        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        # regular CVE - foo
        d = self._cve_template(
            cand="CVE-2022-0001",
            references=["https://www.cve.org/CVERecord?id=CVE-2022-0001"],
        )
        d["upstream_foo"] = "needs-triage"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # scan-report
        d = self._cve_template(
            cand="CVE-2022-GH2#foo",
            references=["https://github.com/org/foo/issues/2"],
        )
        d["Priority"] = "medium"
        d["oci/gar-us.valid-proj_valid-repo/valid-name"] = "needed"
        d["Discovered-by"] = "gar"
        d[
            "Scan-Reports"
        ] = """
 - type: oci
   component: curl
   detectedIn: cpe:/o:debian:debian_linux:11
   advisory: https://www.cve.org/CVERecord?id=CVE-2022-32221
   version: 7.74.0-1.3+deb11u2
   fixedBy: 7.74.0-1.3+deb11u5
   severity: critical
   status: needed
   url: https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef
 - type: oci
   component: libtasn1-6
   detectedIn: cpe:/o:debian:debian_linux:11
   advisory: https://www.cve.org/CVERecord?id=CVE-2021-46848
   version: 4.16.0-2
   fixedBy: 4.16.0-2+deb11u1
   severity: critical
   status: needed
   url: https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef"""
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        return cveDirs

    #
    # _getGHReposAll() tests
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHReposAll)
    def test__getGHReposAll(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHReposAll()"""
        r = cvelib.report._getGHReposAll("valid-org")
        self.assertEqual(3, len(r))

        self.assertTrue("foo" in r)
        self.assertTrue("archived" in r["foo"])
        self.assertFalse(r["foo"]["archived"])
        self.assertTrue("secret_scanning" in r["foo"])
        self.assertTrue(r["foo"]["secret_scanning"])

        self.assertTrue("bar" in r)
        self.assertTrue("archived" in r["bar"])
        self.assertTrue(r["bar"]["archived"])
        self.assertTrue("secret_scanning" in r["bar"])
        self.assertFalse(r["bar"]["secret_scanning"])

        self.assertTrue("baz" in r)
        self.assertTrue("archived" in r["baz"])
        self.assertFalse(r["baz"]["archived"])
        self.assertTrue("private" in r["baz"])
        self.assertTrue(r["baz"]["private"])
        self.assertTrue("secret_scanning" in r["baz"])
        self.assertFalse(r["baz"]["secret_scanning"])

        # do it a second time to use repos_all
        r = cvelib.report._getGHReposAll("valid-org")
        self.assertEqual(3, len(r))

        self.assertTrue("foo" in r)
        self.assertTrue("archived" in r["foo"])
        self.assertFalse(r["foo"]["archived"])
        self.assertTrue("secret_scanning" in r["foo"])
        self.assertTrue(r["foo"]["secret_scanning"])

        self.assertTrue("bar" in r)
        self.assertTrue("archived" in r["bar"])
        self.assertTrue(r["bar"]["archived"])
        self.assertTrue("secret_scanning" in r["bar"])
        self.assertFalse(r["bar"]["secret_scanning"])

        self.assertTrue("baz" in r)
        self.assertTrue("archived" in r["baz"])
        self.assertFalse(r["baz"]["archived"])
        self.assertTrue("secret_scanning" in r["baz"])
        self.assertFalse(r["baz"]["secret_scanning"])

    #
    # _repoArchived() tests
    #
    def test__repoArchived(self):
        """Test _repoArchived()"""
        self.assertFalse(cvelib.report._repoArchived({"archived": False}))
        self.assertFalse(cvelib.report._repoArchived({}))
        self.assertTrue(cvelib.report._repoArchived({"archived": True}))

    #
    # _repoSecretsScanning() tests
    #
    def test__repoSecretsScanning(self):
        """Test _repoSecretsScanning()"""
        self.assertFalse(cvelib.report._repoSecretsScanning({"secret_scanning": False}))
        self.assertFalse(cvelib.report._repoSecretsScanning({}))
        self.assertTrue(cvelib.report._repoSecretsScanning({"secret_scanning": True}))

    #
    # getReposReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHReposAll)
    def test_getReposReport(self, _):  # 2nd arg is 'mock_get'
        """Test test_getReposReport - active"""
        # default args
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getReposReport("valid-org")
        self.assertEqual("", error.getvalue().strip())
        exp = """baz
foo"""
        self.assertEqual(exp, output.getvalue().strip())

        # explicit active
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getReposReport("valid-org", archived=False)
        self.assertEqual("", error.getvalue().strip())
        exp = """baz
foo"""
        self.assertEqual(exp, output.getvalue().strip())

        # default args
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getReposReport("valid-org", archived=True)
        self.assertEqual("", error.getvalue().strip())
        exp = """bar"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # _getGHIssuesForRepo() tests
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test__getGHIssuesForRepo(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo()"""
        r = cvelib.report._getGHIssuesForRepo("valid-repo", "valid-org")
        self.assertEqual(4, len(r))
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/1" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/2" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/3" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/4" in r)

        r = cvelib.report._getGHIssuesForRepo(
            "valid-repo", "valid-org", labels=["label1"]
        )
        self.assertEqual(2, len(r))
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/1" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/3" in r)

        r = cvelib.report._getGHIssuesForRepo(
            "valid-repo", "valid-org", labels=["label1"], skip_labels=["label2"]
        )
        self.assertEqual(1, len(r))
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/1" in r)

        with tests.testutil.capturedOutput() as (output, error):
            r = cvelib.report._getGHIssuesForRepo("404-repo", "valid-org")
        self.assertEqual(0, len(r))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Skipping" in error.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            r = cvelib.report._getGHIssuesForRepo("400-repo", "valid-org")
        self.assertEqual(0, len(r))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Problem fetching" in error.getvalue().strip())

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test__getGHIssuesForRepoSince(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo() since 2022-06-22T12:33:47Z"""
        r = cvelib.report._getGHIssuesForRepo(
            "valid-repo", "valid-org", since=1655901227
        )
        self.assertEqual(4, len(r))
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/1" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/2" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/3" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/4" in r)

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test__getGHIssuesForRepoLabel1(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo() - with label1"""
        r = cvelib.report._getGHIssuesForRepo(
            "valid-repo", "valid-org", labels=["label1"]
        )
        self.assertEqual(2, len(r))
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/1" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/3" in r)

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test__getGHIssuesForRepoSkipLabel1(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo()"""
        r = cvelib.report._getGHIssuesForRepo(
            "valid-repo", "valid-org", skip_labels=["label1"]
        )
        self.assertEqual(2, len(r))
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/2" in r)
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/4" in r)

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test__getGHIssuesForRepo410(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo() - 410 status"""
        r = cvelib.report._getGHIssuesForRepo("410-repo", "valid-org")
        self.assertEqual(0, len(r))

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test__getGHIssuesForRepo404(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo() - 404 status"""
        r = cvelib.report._getGHIssuesForRepo("404-repo", "valid-org")
        self.assertEqual(0, len(r))

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test__getGHIssuesForRepo400(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo() - 400 status"""
        r = cvelib.report._getGHIssuesForRepo("400-repo", "valid-org")
        self.assertEqual(0, len(r))

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test__getGHIssuesForRepoEmpty(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo() - empty repo"""
        r = cvelib.report._getGHIssuesForRepo("empty-repo", "valid-org")
        self.assertEqual(0, len(r))

    #
    # _getKnownIssues()
    #
    def test__getKnownIssues(self):
        """Test _getKnownIssues()"""

        cves = self._mock_cve_list_basic()
        cve = cvelib.cve.CVE()
        cve.setData(
            self._cve_template(
                cand="CVE-2022-GH9999#valid-repo",
                references=[
                    "https://github.com/valid-org/valid-repo/issues/9999#issuecomment"
                ],
            )
        )
        cves.append(cve)

        cve = cvelib.cve.CVE()
        cve.setData(
            self._cve_template(
                cand="CVE-2022-7777",
                references=[
                    "https://www.cve.org/CVERecord?id=CVE-2022-7777",
                ],
            )
        )
        cves.append(cve)

        res = cvelib.report._getKnownIssues(cves)
        self.assertEqual(4, len(res))
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/1" in res)
        self.assertTrue(
            "CVE-2022-GH1001#valid-repo"
            in res["https://github.com/valid-org/valid-repo/issues/1"]
        )
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/2" in res)
        self.assertTrue(
            "CVE-2022-GH1002#valid-repo"
            in res["https://github.com/valid-org/valid-repo/issues/2"]
        )
        self.assertTrue("https://github.com/valid-org/valid-repo/issues/3" in res)
        self.assertTrue(
            "CVE-2022-GH1003#valid-repo"
            in res["https://github.com/valid-org/valid-repo/issues/3"]
        )
        self.assertTrue(
            "CVE-2022-GH9999#valid-repo"
            in res["https://github.com/valid-org/valid-repo/issues/9999"]
        )

        res = cvelib.report._getKnownIssues(cves, filter_url="other-repo")
        self.assertEqual(0, len(res))

    #
    # getMissingReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test_getMissingReport(self, _):  # 2nd arg is mock_get
        """Test getMissingReport()"""
        cves = self._mock_cve_list_basic()
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getMissingReport(cves, "valid-org", repos=["valid-repo"])
        self.assertEqual("", error.getvalue().strip())
        exp = """Issues missing from CVE data:
 https://github.com/valid-org/valid-repo/issues/4"""
        self.assertEqual(exp, output.getvalue().strip())

        # excluded
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getMissingReport(
                cves, "valid-org", repos=["valid-repo"], excluded_repos=["valid-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """No missing issues."""
        self.assertEqual(exp, output.getvalue().strip())

        # archived
        cves = self._mock_cve_list_basic()
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getMissingReport(cves, "valid-org")
        self.assertEqual("", error.getvalue().strip())
        exp = """Issues missing from CVE data:
 https://github.com/valid-org/valid-repo/issues/4"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # _getGHAlertsEnabled()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsEnabled)
    def test__getGHAlertsEnabled(self, _):  # 2nd arg is mock_get
        """Test _getGHAlertsEnabled()"""

        # dependabot
        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org", "dependabot", repos=["valid-repo", "disabled-repo"]
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(1, len(disabled))
        self.assertTrue("disabled-repo" in disabled)

        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org",
            "dependabot",
            repos=["valid-repo", "disabled-repo"],
            excluded_repos=["disabled-repo"],
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(0, len(disabled))

        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org",
            "dependabot",
            repos=["valid-repo", "disabled-repo"],
            excluded_repos=["valid-repo"],
        )
        self.assertEqual(0, len(enabled))
        self.assertEqual(1, len(disabled))
        self.assertTrue("disabled-repo" in disabled)

        enabled, disabled = cvelib.report._getGHAlertsEnabled("valid-org", "dependabot")
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(0, len(disabled))

        # code-scanning
        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org", "code-scanning", repos=["valid-repo", "disabled-repo"]
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(1, len(disabled))
        self.assertTrue("disabled-repo" in disabled)

        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org",
            "code-scanning",
            repos=["valid-repo", "disabled-repo"],
            excluded_repos=["disabled-repo"],
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(0, len(disabled))

        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org",
            "code-scanning",
            repos=["valid-repo", "disabled-repo"],
            excluded_repos=["valid-repo"],
        )
        self.assertEqual(0, len(enabled))
        self.assertEqual(1, len(disabled))
        self.assertTrue("disabled-repo" in disabled)

        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org", "code-scanning"
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(0, len(disabled))

    #
    # _getGHSecretsScanningEnabled()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsEnabled)
    def test__getGHSecretsScanningEnabled(self, _):  # 2nd arg is mock_get
        """Test _getGHSecretsScanningEnabled()"""
        enabled, disabled = cvelib.report._getGHSecretsScanningEnabled(
            "valid-org", repos=["valid-repo", "disabled-repo"]
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(1, len(disabled))
        self.assertTrue("disabled-repo" in disabled)

        enabled, disabled = cvelib.report._getGHSecretsScanningEnabled(
            "valid-org",
            repos=["valid-repo", "disabled-repo"],
            excluded_repos=["disabled-repo"],
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(0, len(disabled))

        enabled, disabled = cvelib.report._getGHSecretsScanningEnabled(
            "valid-org",
            repos=["valid-repo", "disabled-repo"],
            excluded_repos=["valid-repo"],
        )
        self.assertEqual(0, len(enabled))
        self.assertEqual(1, len(disabled))
        self.assertTrue("disabled-repo" in disabled)

        enabled, disabled = cvelib.report._getGHSecretsScanningEnabled("valid-org")
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(0, len(disabled))

        enabled, disabled = cvelib.report._getGHSecretsScanningEnabled(
            "valid-org", repos=["nonexistent"]
        )
        self.assertEqual(0, len(enabled))
        self.assertEqual(0, len(disabled))

    #
    # getGHAlertsStatusReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsEnabled)
    def test_getGHAlertsStatusReport(self, _):  # 2nd arg is mock_get
        """Test _getGHAlertsStatusReport()"""
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsStatusReport(
                "valid-org", repos=["valid-repo", "disabled-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """code-scanning,disabled,disabled-repo,https://github.com/valid-org/disabled-repo/settings/security_analysis
code-scanning,enabled,valid-repo,https://github.com/valid-org/valid-repo/settings/security_analysis
dependabot,disabled,disabled-repo,https://github.com/valid-org/disabled-repo/settings/security_analysis
dependabot,enabled,valid-repo,https://github.com/valid-org/valid-repo/settings/security_analysis
secret-scanning,disabled,disabled-repo,https://github.com/valid-org/disabled-repo/settings/security_analysis
secret-scanning,enabled,valid-repo,https://github.com/valid-org/valid-repo/settings/security_analysis"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # getUpdatedReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test_getUpdatedReport(self, _):  # 2nd arg is mock_get
        """Test _getUpdatedReport()"""
        cves = self._mock_cve_list_basic()

        # all updated since
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org")
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
Updated issues:
 https://github.com/valid-org/valid-repo/issues/1 (CVE-2022-GH1001#valid-repo)
 https://github.com/valid-org/valid-repo/issues/2 (CVE-2022-GH1002#valid-repo)
 https://github.com/valid-org/valid-repo/issues/3 (CVE-2022-GH1003#valid-repo)"""
        self.assertEqual(exp, output.getvalue().strip())

        # excluded
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(
                cves, "valid-org", excluded_repos=["valid-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
No updated issues."""
        self.assertEqual(exp, output.getvalue().strip())

        # some updated since 1656792271 (2022-07-02)
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org", since=1656792271)
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
Updated issues:
 https://github.com/valid-org/valid-repo/issues/3 (CVE-2022-GH1003#valid-repo)"""
        self.assertEqual(exp, output.getvalue().strip())

        # none updated since 1657224398 (2022-07-07)
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org", since=1657224398)
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
No updated issues."""
        self.assertEqual(exp, output.getvalue().strip())

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test_getUpdatedReportWithOther(self, _):  # 2nd arg is mock_get
        """Test _getUpdatedReportWithOther()"""
        cves = self._mock_cve_list_basic()
        d = self._cve_template(
            cand="CVE-2022-GH77#other-repo",
            references=["https://github.com/valid-org/other-repo/issues/77"],
        )
        cve = cvelib.cve.CVE()
        cve.setData(d)
        cves.append(cve)

        # all updated since with other-repo in the mix
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org", excluded_repos=[])
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
Updated issues:
 https://github.com/valid-org/other-repo/issues/77 (CVE-2022-GH77#other-repo)
 https://github.com/valid-org/valid-repo/issues/1 (CVE-2022-GH1001#valid-repo)
 https://github.com/valid-org/valid-repo/issues/2 (CVE-2022-GH1002#valid-repo)
 https://github.com/valid-org/valid-repo/issues/3 (CVE-2022-GH1003#valid-repo)"""
        self.assertEqual(exp, output.getvalue().strip())

        # other-repo updated when excluding valid-repo
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(
                cves, "valid-org", excluded_repos=["valid-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
Updated issues:
 https://github.com/valid-org/other-repo/issues/77 (CVE-2022-GH77#other-repo)"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # _printGHAlertsSummary()
    #
    def test__printGHAlertsSummary(self):
        """Test _printGHAlertsSummary()"""
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsSummary(
                "valid-org", "valid-repo", [], "updated"
            )
        self.assertEqual("", error.getvalue().strip())
        exp = "valid-repo updated alerts: 0"
        self.assertEqual(exp, output.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsSummary(
                "valid-org", "valid-repo", [], "resolved"
            )
        self.assertEqual("", error.getvalue().strip())
        exp = "valid-repo resolved alerts: 0"
        self.assertEqual(exp, output.getvalue().strip())

        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.report._printGHAlertsSummary(
                    "valid-org", "valid-repo", [], "invalid"
                )
            self.assertEqual("", output.getvalue().strip())
            exp = "ERROR: Unsupported alert status: invalid"
            self.assertEqual(exp, error.getvalue().strip())

        # these alerts are the ones after _parseAlert
        alerts = []
        for g in _getMockedAlertsJSON():
            alerts.append(cvelib.report._parseAlert(g)[1])
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsSummary(
                "valid-org", "valid-repo", alerts, "resolved"
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """valid-repo resolved alerts: 8
  Some Code Finding
    - severity: high
    - created: 2022-07-01T17:15:30Z
    - dismissed: 2022-07-02T17:15:30Z
    - reason: false positive
    - comment: some code comment
    - by: ghuser3
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/30

  Some Other Code Finding
    - severity: medium
    - created: 2022-07-05T17:15:30Z
    - dismissed: None
    - reason: None
    - comment: None
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/31

  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - comment: some comment
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1

  baz
    - severity: medium
    - created: 2022-07-03T18:27:30Z
    - dismissed: None
    - reason: None
    - comment: None
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: medium
    - created: 2022-07-04T18:27:30Z
    - dismissed: None
    - reason: None
    - comment: None
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  @norf/quz
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - dismissed: None
    - reason: None
    - comment: None
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

  Some Leaked Secret
    - severity: high
    - created: 2022-07-01T18:15:30Z
    - resolved: 2022-07-02T18:15:30Z
    - reason: revoked
    - comment: some secret comment
    - by: ghuser2
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/20

  Some Other Leaked Secret
    - severity: high
    - created: 2022-07-05T18:15:30Z
    - resolved: None
    - reason: None
    - comment: None
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/21

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning
  - https://github.com/valid-org/valid-repo/security/dependabot
  - https://github.com/valid-org/valid-repo/security/secret-scanning"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # _parseAlert()
    #
    def test__parseAlert(self):
        """Test _parseAlert()"""
        tsts = [
            # input, expRepo, expK, expV
            (
                {
                    "created_at": "2022-07-01T18:27:30Z",
                    "dependency": {
                        "manifest_path": "go.sum",
                        "package": {
                            "name": "github.com/foo/bar",
                        },
                    },
                    "dismissed_at": "2022-07-02T18:27:30Z",
                    "dismissed_by": {"login": "ghuser1"},
                    "dismissed_comment": "some comment",
                    "dismissed_reason": "tolerable",
                    "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/1",
                    "repository": {"name": "valid-repo", "private": False},
                    "security_advisory": {
                        "ghsa_id": "GHSA-a",
                        "severity": "low",
                    },
                },
                "valid-repo",
                "dismissed_by",
                "ghuser1",
            ),
            (
                {
                    "created_at": "2022-07-01T17:15:30Z",
                    "dismissed_at": "2022-07-02T17:15:30Z",
                    "dismissed_by": {"login": "ghuser3"},
                    "dismissed_comment": "some code comment",
                    "dismissed_reason": "false positive",
                    "html_url": "https://github.com/valid-org/valid-repo/security/code-scanning/30",
                    "repository": {"name": "valid-repo", "private": False},
                    "rule": {
                        "description": "Some Code Finding",
                        "security_severity_level": "high",
                    },
                },
                "valid-repo",
                "severity",
                "high",
            ),
            (
                {
                    "created_at": "2022-07-01T17:15:30Z",
                    "dismissed_at": "2022-07-02T17:15:30Z",
                    "dismissed_by": {"login": "ghuser3"},
                    "dismissed_comment": "some code comment",
                    "dismissed_reason": "false positive",
                    "html_url": "https://github.com/valid-org/valid-repo/security/code-scanning/30",
                    "repository": {"name": "valid-repo", "private": False},
                    "rule": {
                        "description": "Some Code Finding",
                        "security_severity_level": None,
                    },
                },
                "valid-repo",
                "severity",
                "unknown",
            ),
            (
                {
                    "created_at": "2022-07-01T18:15:30Z",
                    "secret_type_display_name": "Some Leaked Secret",
                    "resolved_at": "2022-07-02T18:15:30Z",
                    "resolved_by": {"login": "ghuser2"},
                    "resolution_comment": "some secret comment",
                    "resolution": "revoked",
                    "html_url": "https://github.com/valid-org/valid-repo/security/secret-scanning/20",
                    "repository": {"name": "valid-repo", "private": True},
                },
                "valid-repo",
                "severity",
                "medium",
            ),
        ]

        for alert, expRepo, expK, expV in tsts:
            (resRepo, resAlert) = cvelib.report._parseAlert(alert)
            self.assertEqual(expRepo, resRepo)
            self.assertTrue(len(resAlert) > 0)
            if expK is not None:
                self.assertTrue(expK in resAlert)
                self.assertEqual(expV, resAlert[expK])

    #
    # getGHAlertsReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsAllFull)
    def test_getGHAlertsReport(self, _):  # 2nd arg is mock_get
        """Test getGHAlertsReport()"""
        self.maxDiff = 16384

        # bad
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.report.getGHAlertsReport([], "valid-org", alert_types=["bad"])
            self.assertTrue("Unsupported alert type: bad" in error.getvalue().strip())

        # specify non-existent repo
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport([], "valid-org", repos=["nonexistent"])
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual(
            "No alerts for the specified repos.", output.getvalue().strip()
        )

        # specify excluded repo
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", excluded_repos=["valid-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual(
            "No alerts for the specified repos.", output.getvalue().strip()
        )

        # with_templates = false
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport([], "valid-org", repos=["valid-repo"])
        self.assertEqual("", error.getvalue().strip())
        exp = """Alerts:
valid-repo updated alerts: 5
  Some Other Code Finding
    - severity: medium
    - created: 2022-07-05T17:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/31

  baz
    - severity: medium
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: medium
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  @norf/quz
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

  Some Other Leaked Secret
    - severity: high
    - created: 2022-07-05T18:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/21

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning
  - https://github.com/valid-org/valid-repo/security/dependabot
  - https://github.com/valid-org/valid-repo/security/secret-scanning

Resolved alerts:

valid-repo resolved alerts: 3
  Some Code Finding
    - severity: high
    - created: 2022-07-01T17:15:30Z
    - dismissed: 2022-07-02T17:15:30Z
    - reason: false positive
    - comment: some code comment
    - by: ghuser3
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/30

  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - comment: some comment
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1

  Some Leaked Secret
    - severity: high
    - created: 2022-07-01T18:15:30Z
    - resolved: 2022-07-02T18:15:30Z
    - reason: revoked
    - comment: some secret comment
    - by: ghuser2
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/20

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning
  - https://github.com/valid-org/valid-repo/security/dependabot
  - https://github.com/valid-org/valid-repo/security/secret-scanning"""
        self.assertEqual(exp, output.getvalue().strip())

        # with_templates = false and one known CVE
        cves = []
        cve = cvelib.cve.CVE()
        c = self._cve_template(
            cand="CVE-2022-GH1001#valid-repo",
            references=["https://github.com/advisories/GHSA-a"],
        )
        c[
            "GitHub-Advanced-Security"
        ] = """
 - type: dependabot
   dependency: github.com/foo/bar
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-a
   severity: low
   status: dismissed (tolerable; ghuser1)
   url: https://github.com/valid-org/valid-repo/security/dependabot/1"""
        cve.setData(c)
        cves.append(cve)
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(cves, "valid-org", repos=["valid-repo"])
        self.assertEqual("", error.getvalue().strip())
        exp = """Alerts:
valid-repo updated alerts: 5
  Some Other Code Finding
    - severity: medium
    - created: 2022-07-05T17:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/31

  baz
    - severity: medium
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: medium
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  @norf/quz
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

  Some Other Leaked Secret
    - severity: high
    - created: 2022-07-05T18:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/21

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning
  - https://github.com/valid-org/valid-repo/security/dependabot
  - https://github.com/valid-org/valid-repo/security/secret-scanning

Resolved alerts:

valid-repo resolved alerts: 3
  Some Code Finding
    - severity: high
    - created: 2022-07-01T17:15:30Z
    - dismissed: 2022-07-02T17:15:30Z
    - reason: false positive
    - comment: some code comment
    - by: ghuser3
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/30

  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - comment: some comment
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1

  Some Leaked Secret
    - severity: high
    - created: 2022-07-01T18:15:30Z
    - resolved: 2022-07-02T18:15:30Z
    - reason: revoked
    - comment: some secret comment
    - by: ghuser2
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/20

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning
  - https://github.com/valid-org/valid-repo/security/dependabot
  - https://github.com/valid-org/valid-repo/security/secret-scanning"""
        self.assertEqual(exp, output.getvalue().strip())

        # with_templates = true
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                cves, "valid-org", repos=["valid-repo"], with_templates=True
            )
        self.assertEqual("", error.getvalue().strip())

        now: datetime.datetime = datetime.datetime.now()
        exp = """Alerts:
## valid-repo template
Please address alerts (code-scanning, dependabot, secret-scanning) in valid-repo

The following alerts were issued:
- [ ] [@norf/quz](https://github.com/valid-org/valid-repo/security/dependabot/5) (unknown)
- [ ] [Some Other Code Finding](https://github.com/valid-org/valid-repo/security/code-scanning/31) (medium)
- [ ] [Some Other Leaked Secret](https://github.com/valid-org/valid-repo/security/secret-scanning/21) (high)
- [ ] [baz](https://github.com/valid-org/valid-repo/security/dependabot/3) (medium)
- [ ] [baz](https://github.com/valid-org/valid-repo/security/dependabot/4) (medium)

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Code scanning only reported against the default branch so please be sure to check any other supported branches when researching/fixing. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing. While any secrets should be removed from the repo, they will live forever in git history so please remember to rotate the secret too.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/code-scanning
 * https://github.com/valid-org/valid-repo/security/dependabot
 * https://github.com/valid-org/valid-repo/security/secret-scanning

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/code-scanning/31
 https://github.com/valid-org/valid-repo/security/dependabot/3
 https://github.com/valid-org/valid-repo/security/dependabot/4
 https://github.com/valid-org/valid-repo/security/dependabot/5
 https://github.com/valid-org/valid-repo/security/secret-scanning/21
 https://github.com/advisories/GHSA-b (baz)
 https://github.com/advisories/GHSA-c (baz)
 https://github.com/advisories/GHSA-d (@norf/quz)
Description:
 Please address alerts in valid-repo
 - [ ] @norf/quz (unknown)
 - [ ] Some Other Code Finding (medium)
 - [ ] Some Other Leaked Secret (high)
 - [ ] baz (2 medium)
GitHub-Advanced-Security:
 - type: code-scanning
   description: Some Other Code Finding
   severity: medium
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/code-scanning/31
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   severity: medium
   advisory: https://github.com/advisories/GHSA-b
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/3
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   severity: medium
   advisory: https://github.com/advisories/GHSA-c
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/4
 - type: dependabot
   dependency: "@norf/quz"
   detectedIn: path/yarn.lock
   severity: unknown
   advisory: https://github.com/advisories/GHSA-d
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/5
 - type: secret-scanning
   secret: Some Other Leaked Secret
   detectedIn: tbd
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/secret-scanning/21
Notes:
Mitigation:
Bugs:
Priority: high
Discovered-by: gh-code, gh-dependabot, gh-secret
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template

valid-repo updated alerts: 5
  Some Other Code Finding
    - severity: medium
    - created: 2022-07-05T17:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/31

  baz
    - severity: medium
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: medium
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  @norf/quz
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

  Some Other Leaked Secret
    - severity: high
    - created: 2022-07-05T18:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/21

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning
  - https://github.com/valid-org/valid-repo/security/dependabot
  - https://github.com/valid-org/valid-repo/security/secret-scanning

Resolved alerts:

## valid-repo template
Please address alerts (code-scanning, dependabot, secret-scanning) in valid-repo

The following alerts were issued:
- [ ] [Some Code Finding](https://github.com/valid-org/valid-repo/security/code-scanning/30) (high)
- [ ] [Some Leaked Secret](https://github.com/valid-org/valid-repo/security/secret-scanning/20) (high)
- [ ] [github.com/foo/bar](https://github.com/valid-org/valid-repo/security/dependabot/1) (low)

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Code scanning only reported against the default branch so please be sure to check any other supported branches when researching/fixing. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing. While any secrets should be removed from the repo, they will live forever in git history so please remember to rotate the secret too.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/code-scanning
 * https://github.com/valid-org/valid-repo/security/dependabot
 * https://github.com/valid-org/valid-repo/security/secret-scanning

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/code-scanning/30
 https://github.com/valid-org/valid-repo/security/dependabot/1
 https://github.com/valid-org/valid-repo/security/secret-scanning/20
 https://github.com/advisories/GHSA-a (github.com/foo/bar)
Description:
 Please address alerts in valid-repo
 - [ ] Some Code Finding (high)
 - [ ] Some Leaked Secret (high)
 - [ ] github.com/foo/bar (low)
GitHub-Advanced-Security:
 - type: code-scanning
   description: Some Code Finding
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/code-scanning/30
 - type: dependabot
   dependency: github.com/foo/bar
   detectedIn: go.sum
   severity: low
   advisory: https://github.com/advisories/GHSA-a
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/1
 - type: secret-scanning
   secret: Some Leaked Secret
   detectedIn: tbd
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/secret-scanning/20
Notes:
Mitigation:
Bugs:
Priority: high
Discovered-by: gh-code, gh-dependabot, gh-secret
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template

valid-repo resolved alerts: 3
  Some Code Finding
    - severity: high
    - created: 2022-07-01T17:15:30Z
    - dismissed: 2022-07-02T17:15:30Z
    - reason: false positive
    - comment: some code comment
    - by: ghuser3
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/30

  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - comment: some comment
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1

  Some Leaked Secret
    - severity: high
    - created: 2022-07-01T18:15:30Z
    - resolved: 2022-07-02T18:15:30Z
    - reason: revoked
    - comment: some secret comment
    - by: ghuser2
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/20

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning
  - https://github.com/valid-org/valid-repo/security/dependabot
  - https://github.com/valid-org/valid-repo/security/secret-scanning""" % (
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
        )
        self.assertEqual(exp, output.getvalue().strip())

        # some updated since 1656792271 (2022-07-02)
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", repos=["valid-repo"], since=1656792271
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Alerts:
valid-repo updated alerts: 5
  Some Other Code Finding
    - severity: medium
    - created: 2022-07-05T17:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/31

  baz
    - severity: medium
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: medium
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  @norf/quz
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

  Some Other Leaked Secret
    - severity: high
    - created: 2022-07-05T18:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/21

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning
  - https://github.com/valid-org/valid-repo/security/dependabot
  - https://github.com/valid-org/valid-repo/security/secret-scanning"""
        self.assertEqual(exp, output.getvalue().strip())

        # none updated since 1657224398 (2022-07-07)
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", repos=["valid-repo"], since=1657224398
            )
        self.assertEqual("", error.getvalue().strip())
        exp = "No alerts for the specified repos."
        self.assertEqual(exp, output.getvalue().strip())

        # error
        with self.assertRaises(ValueError):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", repos=["valid-repo"], since=-1
            )

    @mock.patch(
        "requests.get", side_effect=mocked_requests_get__getGHAlertsAllDependabot
    )
    def test_getGHAlertsReportDependabot(self, _):  # 2nd arg is mock_get
        """Test getGHAlertsReport() - dependabot"""
        self.maxDiff = 16384

        # with_templates = false
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", repos=["valid-repo"], alert_types=["dependabot"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Alerts:
valid-repo updated alerts: 3
  baz
    - severity: medium
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: medium
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  @norf/quz
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

  References:
  - https://github.com/valid-org/valid-repo/security/dependabot

Resolved alerts:

valid-repo resolved alerts: 1
  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - comment: some comment
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1

  References:
  - https://github.com/valid-org/valid-repo/security/dependabot"""
        self.assertEqual(exp, output.getvalue().strip())

        # with_templates = true
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [],
                "valid-org",
                repos=["valid-repo"],
                with_templates=True,
                alert_types=["dependabot"],
            )
        self.assertEqual("", error.getvalue().strip())

        now: datetime.datetime = datetime.datetime.now()
        exp = """Alerts:
## valid-repo template
Please address alerts (dependabot) in valid-repo

The following alerts were issued:
- [ ] [@norf/quz](https://github.com/valid-org/valid-repo/security/dependabot/5) (unknown)
- [ ] [baz](https://github.com/valid-org/valid-repo/security/dependabot/3) (medium)
- [ ] [baz](https://github.com/valid-org/valid-repo/security/dependabot/4) (medium)

Since a 'medium' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/dependabot

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/dependabot/3
 https://github.com/valid-org/valid-repo/security/dependabot/4
 https://github.com/valid-org/valid-repo/security/dependabot/5
 https://github.com/advisories/GHSA-b (baz)
 https://github.com/advisories/GHSA-c (baz)
 https://github.com/advisories/GHSA-d (@norf/quz)
Description:
 Please address alerts in valid-repo
 - [ ] @norf/quz (unknown)
 - [ ] baz (2 medium)
GitHub-Advanced-Security:
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   severity: medium
   advisory: https://github.com/advisories/GHSA-b
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/3
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   severity: medium
   advisory: https://github.com/advisories/GHSA-c
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/4
 - type: dependabot
   dependency: "@norf/quz"
   detectedIn: path/yarn.lock
   severity: unknown
   advisory: https://github.com/advisories/GHSA-d
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/5
Notes:
Mitigation:
Bugs:
Priority: medium
Discovered-by: gh-dependabot
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template

valid-repo updated alerts: 3
  baz
    - severity: medium
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: medium
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  @norf/quz
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

  References:
  - https://github.com/valid-org/valid-repo/security/dependabot

Resolved alerts:

## valid-repo template
Please address alert (dependabot) in valid-repo

The following alert was issued:
- [ ] [github.com/foo/bar](https://github.com/valid-org/valid-repo/security/dependabot/1) (low)

Since a 'low' severity issue is present, tentatively adding the 'security/low' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/dependabot

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/dependabot/1
 https://github.com/advisories/GHSA-a (github.com/foo/bar)
Description:
 Please address alert in valid-repo
 - [ ] github.com/foo/bar (low)
GitHub-Advanced-Security:
 - type: dependabot
   dependency: github.com/foo/bar
   detectedIn: go.sum
   severity: low
   advisory: https://github.com/advisories/GHSA-a
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/1
Notes:
Mitigation:
Bugs:
Priority: low
Discovered-by: gh-dependabot
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template

valid-repo resolved alerts: 1
  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - comment: some comment
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1

  References:
  - https://github.com/valid-org/valid-repo/security/dependabot""" % (
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
        )
        self.assertEqual(exp, output.getvalue().strip())

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsAllCode)
    def test_getGHAlertsReportCode(self, _):  # 2nd arg is mock_get
        """Test getGHAlertsReport() - code-scanning"""
        self.maxDiff = 16384

        # with_templates = false
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", repos=["valid-repo"], alert_types=["code-scanning"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Alerts:
valid-repo updated alerts: 1
  Some Other Code Finding
    - severity: medium
    - created: 2022-07-05T17:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/31

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning

Resolved alerts:

valid-repo resolved alerts: 1
  Some Code Finding
    - severity: high
    - created: 2022-07-01T17:15:30Z
    - dismissed: 2022-07-02T17:15:30Z
    - reason: false positive
    - comment: some code comment
    - by: ghuser3
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/30

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning"""
        self.assertEqual(exp, output.getvalue().strip())

        # with_templates = true
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [],
                "valid-org",
                repos=["valid-repo"],
                with_templates=True,
                alert_types=["code-scanning"],
            )
        self.assertEqual("", error.getvalue().strip())

        now: datetime.datetime = datetime.datetime.now()
        exp = """Alerts:
## valid-repo template
Please address alert (code-scanning) in valid-repo

The following alert was issued:
- [ ] [Some Other Code Finding](https://github.com/valid-org/valid-repo/security/code-scanning/31) (medium)

Since a 'medium' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Code scanning only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/code-scanning

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/code-scanning/31
Description:
 Please address alert in valid-repo
 - [ ] Some Other Code Finding (medium)
GitHub-Advanced-Security:
 - type: code-scanning
   description: Some Other Code Finding
   severity: medium
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/code-scanning/31
Notes:
Mitigation:
Bugs:
Priority: medium
Discovered-by: gh-code
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template

valid-repo updated alerts: 1
  Some Other Code Finding
    - severity: medium
    - created: 2022-07-05T17:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/31

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning

Resolved alerts:

## valid-repo template
Please address alert (code-scanning) in valid-repo

The following alert was issued:
- [ ] [Some Code Finding](https://github.com/valid-org/valid-repo/security/code-scanning/30) (high)

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Code scanning only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/code-scanning

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/code-scanning/30
Description:
 Please address alert in valid-repo
 - [ ] Some Code Finding (high)
GitHub-Advanced-Security:
 - type: code-scanning
   description: Some Code Finding
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/code-scanning/30
Notes:
Mitigation:
Bugs:
Priority: high
Discovered-by: gh-code
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template

valid-repo resolved alerts: 1
  Some Code Finding
    - severity: high
    - created: 2022-07-01T17:15:30Z
    - dismissed: 2022-07-02T17:15:30Z
    - reason: false positive
    - comment: some code comment
    - by: ghuser3
    - url: https://github.com/valid-org/valid-repo/security/code-scanning/30

  References:
  - https://github.com/valid-org/valid-repo/security/code-scanning""" % (
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
        )
        self.assertEqual(exp, output.getvalue().strip())

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsAllSecret)
    def test_getGHAlertsReportSecret(self, _):  # 2nd arg is mock_get
        """Test getGHAlertsReport() - secret-scanning"""
        self.maxDiff = 16384

        # with_templates = false
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", repos=["valid-repo"], alert_types=["secret-scanning"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Alerts:
valid-repo updated alerts: 1
  Some Other Leaked Secret
    - severity: high
    - created: 2022-07-05T18:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/21

  References:
  - https://github.com/valid-org/valid-repo/security/secret-scanning

Resolved alerts:

valid-repo resolved alerts: 1
  Some Leaked Secret
    - severity: high
    - created: 2022-07-01T18:15:30Z
    - resolved: 2022-07-02T18:15:30Z
    - reason: revoked
    - comment: some secret comment
    - by: ghuser2
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/20

  References:
  - https://github.com/valid-org/valid-repo/security/secret-scanning"""
        self.assertEqual(exp, output.getvalue().strip())

        # with_templates = true
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [],
                "valid-org",
                repos=["valid-repo"],
                with_templates=True,
                alert_types=["secret-scanning"],
            )
        self.assertEqual("", error.getvalue().strip())

        now: datetime.datetime = datetime.datetime.now()
        exp = """Alerts:
## valid-repo template
Please address alert (secret-scanning) in valid-repo

The following alert was issued:
- [ ] [Some Other Leaked Secret](https://github.com/valid-org/valid-repo/security/secret-scanning/21) (high)

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. While any secrets should be removed from the repo, they will live forever in git history so please remember to rotate the secret too.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/secret-scanning

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/secret-scanning/21
Description:
 Please address alert in valid-repo
 - [ ] Some Other Leaked Secret (high)
GitHub-Advanced-Security:
 - type: secret-scanning
   secret: Some Other Leaked Secret
   detectedIn: tbd
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/secret-scanning/21
Notes:
Mitigation:
Bugs:
Priority: high
Discovered-by: gh-secret
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template

valid-repo updated alerts: 1
  Some Other Leaked Secret
    - severity: high
    - created: 2022-07-05T18:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/21

  References:
  - https://github.com/valid-org/valid-repo/security/secret-scanning

Resolved alerts:

## valid-repo template
Please address alert (secret-scanning) in valid-repo

The following alert was issued:
- [ ] [Some Leaked Secret](https://github.com/valid-org/valid-repo/security/secret-scanning/20) (high)

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. While any secrets should be removed from the repo, they will live forever in git history so please remember to rotate the secret too.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/secret-scanning

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/secret-scanning/20
Description:
 Please address alert in valid-repo
 - [ ] Some Leaked Secret (high)
GitHub-Advanced-Security:
 - type: secret-scanning
   secret: Some Leaked Secret
   detectedIn: tbd
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/secret-scanning/20
Notes:
Mitigation:
Bugs:
Priority: high
Discovered-by: gh-secret
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template

valid-repo resolved alerts: 1
  Some Leaked Secret
    - severity: high
    - created: 2022-07-01T18:15:30Z
    - resolved: 2022-07-02T18:15:30Z
    - reason: revoked
    - comment: some secret comment
    - by: ghuser2
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/20

  References:
  - https://github.com/valid-org/valid-repo/security/secret-scanning""" % (
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
        )
        self.assertEqual(exp, output.getvalue().strip())

    @mock.patch(
        "requests.get", side_effect=mocked_requests_get__getGHAlertsAllSecretPrivate
    )
    def test_getGHAlertsReportSecretPrivate(self, _):  # 2nd arg is mock_get
        """Test getGHAlertsReport() - secret-scanning (private repo)"""
        self.maxDiff = 16384

        # with_templates = false
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", repos=["valid-repo"], alert_types=["secret-scanning"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Alerts:
valid-repo updated alerts: 1
  Some Other Leaked Secret
    - severity: medium
    - created: 2022-07-05T18:15:30Z
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/21

  References:
  - https://github.com/valid-org/valid-repo/security/secret-scanning

Resolved alerts:

valid-repo resolved alerts: 1
  Some Leaked Secret
    - severity: medium
    - created: 2022-07-01T18:15:30Z
    - resolved: 2022-07-02T18:15:30Z
    - reason: revoked
    - comment: some secret comment
    - by: ghuser2
    - url: https://github.com/valid-org/valid-repo/security/secret-scanning/20

  References:
  - https://github.com/valid-org/valid-repo/security/secret-scanning"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # _printGHAlertsTemplates()
    #
    def test__printGHAlertsTemplates(self):
        """Test _printGHAlertsTemplates()"""
        # these alerts are the ones after _parseAlert
        alerts = []
        for g in _getMockedAlertsJSON():
            alerts.append(cvelib.report._parseAlert(g)[1])
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsTemplates("valid-org", "valid-repo", alerts)
        self.assertEqual("", error.getvalue().strip())
        now: datetime.datetime = datetime.datetime.now()
        exp = """## valid-repo template
Please address alerts (code-scanning, dependabot, secret-scanning) in valid-repo

The following alerts were issued:
- [ ] [@norf/quz](https://github.com/valid-org/valid-repo/security/dependabot/5) (unknown)
- [ ] [Some Code Finding](https://github.com/valid-org/valid-repo/security/code-scanning/30) (high)
- [ ] [Some Leaked Secret](https://github.com/valid-org/valid-repo/security/secret-scanning/20) (high)
- [ ] [Some Other Code Finding](https://github.com/valid-org/valid-repo/security/code-scanning/31) (medium)
- [ ] [Some Other Leaked Secret](https://github.com/valid-org/valid-repo/security/secret-scanning/21) (high)
- [ ] [baz](https://github.com/valid-org/valid-repo/security/dependabot/3) (medium)
- [ ] [baz](https://github.com/valid-org/valid-repo/security/dependabot/4) (medium)
- [ ] [github.com/foo/bar](https://github.com/valid-org/valid-repo/security/dependabot/1) (low)

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Code scanning only reported against the default branch so please be sure to check any other supported branches when researching/fixing. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing. While any secrets should be removed from the repo, they will live forever in git history so please remember to rotate the secret too.

Thanks!

References:
 * https://github.com/valid-org/valid-repo/security/code-scanning
 * https://github.com/valid-org/valid-repo/security/dependabot
 * https://github.com/valid-org/valid-repo/security/secret-scanning

## end template

## valid-repo CVE template
Candidate: CVE-%s-NNNN
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 https://github.com/valid-org/valid-repo/security/code-scanning/30
 https://github.com/valid-org/valid-repo/security/code-scanning/31
 https://github.com/valid-org/valid-repo/security/dependabot/1
 https://github.com/valid-org/valid-repo/security/dependabot/3
 https://github.com/valid-org/valid-repo/security/dependabot/4
 https://github.com/valid-org/valid-repo/security/dependabot/5
 https://github.com/valid-org/valid-repo/security/secret-scanning/20
 https://github.com/valid-org/valid-repo/security/secret-scanning/21
 https://github.com/advisories/GHSA-a (github.com/foo/bar)
 https://github.com/advisories/GHSA-b (baz)
 https://github.com/advisories/GHSA-c (baz)
 https://github.com/advisories/GHSA-d (@norf/quz)
Description:
 Please address alerts in valid-repo
 - [ ] @norf/quz (unknown)
 - [ ] Some Code Finding (high)
 - [ ] Some Leaked Secret (high)
 - [ ] Some Other Code Finding (medium)
 - [ ] Some Other Leaked Secret (high)
 - [ ] baz (2 medium)
 - [ ] github.com/foo/bar (low)
GitHub-Advanced-Security:
 - type: code-scanning
   description: Some Code Finding
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/code-scanning/30
 - type: code-scanning
   description: Some Other Code Finding
   severity: medium
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/code-scanning/31
 - type: dependabot
   dependency: github.com/foo/bar
   detectedIn: go.sum
   severity: low
   advisory: https://github.com/advisories/GHSA-a
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/1
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   severity: medium
   advisory: https://github.com/advisories/GHSA-b
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/3
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   severity: medium
   advisory: https://github.com/advisories/GHSA-c
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/4
 - type: dependabot
   dependency: "@norf/quz"
   detectedIn: path/yarn.lock
   severity: unknown
   advisory: https://github.com/advisories/GHSA-d
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/5
 - type: secret-scanning
   secret: Some Leaked Secret
   detectedIn: tbd
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/secret-scanning/20
 - type: secret-scanning
   secret: Some Other Leaked Secret
   detectedIn: tbd
   severity: high
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/secret-scanning/21
Notes:
Mitigation:
Bugs:
Priority: high
Discovered-by: gh-code, gh-dependabot, gh-secret
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template""" % (
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
        )
        self.assertEqual(exp, output.getvalue().strip())

        alerts = [
            {
                "alert_type": "dependabot",
                "created": "2022-07-01T18:27:30Z",
                "dependabot_manifest_path": "a/b/c",
                "dependabot_package_name": "foo",
                "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/1",
                "security_advisory_ghsa_url": "https://github.com/advisories/GHSA-bbb",
                "severity": "bad",
            },
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsTemplates("valid-org", "valid-repo", alerts)
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue("Since an 'unknown' severity" in output.getvalue().strip())

    def test__printGHAlertsTemplates_with_template_urls(self):
        """Test _printGHAlertsTemplates() - template_urls"""
        # these alerts are the ones after _parseAlert
        alerts = []
        for g in _getMockedAlertsJSON():
            alerts.append(cvelib.report._parseAlert(g)[1])
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsTemplates("valid-org", "valid-repo", alerts)
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(
            "## valid-repo template\nPlease address alerts" in output.getvalue().strip()
        )
        self.assertTrue(
            "References:\n * https://github.com/valid-org/valid-repo/security/code-scanning"
            in output.getvalue().strip()
        )
        self.assertTrue(
            "## valid-repo CVE template\nCandidate: CVE-" in output.getvalue().strip()
        )

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsTemplates(
                "valid-org",
                "valid-repo",
                alerts,
                template_urls=["https://url1", "https://url2"],
            )
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(
            "## valid-repo template\nPlease address alerts" in output.getvalue().strip()
        )
        self.assertTrue(
            "References:\n * https://url1\n * https://url2\n * https://github.com/valid-org/valid-repo/security/code-scanning"
            in output.getvalue().strip()
        )
        self.assertTrue(
            "## valid-repo CVE template\nCandidate: CVE-" in output.getvalue().strip()
        )
        self.assertFalse("https://url3" in output.getvalue().strip())

        # adjust the config file for template-urls
        self._mock_cve_data_mixed()  # this creates self.tmpdir and a config

    #
    # getHumanSoftwareInfo()
    #
    def test_getHumanSoftwareInfo(self):
        """Test getHumanSoftwareInfo()"""
        # mock some data by calling collectCVEData() like bin/cve-report
        cveDirs = self._mock_cve_data_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs, False, filter_status="needs-triage,needed,pending,released"
        )

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSoftwareInfo(cves, "")
        self.assertEqual("", error.getvalue().strip())
        exp = """bar:
  high:
    CVE-2022-GH2#bar
  low:
    CVE-2022-0002
  negligible:
    CVE-2021-9992
baz:
  low:
    CVE-2022-0003
foo:
  critical:
    CVE-2021-9991
  medium:
    CVE-2022-0001
    CVE-2022-GH1#foo
  low:
    CVE-2022-NNN1"""
        self.assertEqual(exp, output.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSoftwareInfo(cves, "baz")
        self.assertEqual("", error.getvalue().strip())
        exp = """baz:
  low:
    CVE-2022-0003"""
        self.assertEqual(exp, output.getvalue().strip())

        fn = os.path.join(cveDirs["active"], "../", "repos")
        content = "baz"
        with open(fn, "w") as fp:
            fp.write("%s" % content)
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSoftwareInfo(cves, fn)
        self.assertEqual("", error.getvalue().strip())
        exp = """baz:
  low:
    CVE-2022-0003"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # getHumanSummary()
    #
    def test_getHumanSummary(self):
        """Test getHumanSummary()"""
        # empty cve list
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                [], "", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos


# Closed

Priority   Repository                     Issue
--------   ----------                     -----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        # mock some data by calling collectCVEData() like bin/cve-report
        cveDirs = self._mock_cve_data_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs, False, filter_status="needs-triage,needed,pending,released"
        )

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (dependabot, secret-scanning)
medium     foo                            CVE-2022-0001
medium     foo                            CVE-2022-GH1#foo          (limit-report)
low        bar                            CVE-2022-0002
low        baz                            CVE-2022-0003
low        foo                            CVE-2022-NNN1

Totals:
- critical: 0 in 0 repos
- high: 1 in 1 repos
- medium: 2 in 1 repos
- low: 3 in 3 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        expClosed = (
            exp
            + """


# Closed

Priority   Repository                     Issue
--------   ----------                     -----
critical   foo                            CVE-2021-9991
negligible bar                            CVE-2021-9992

Totals:
- critical: 1 in 1 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 1 in 1 repos"""
        )
        self.assertEqual(expClosed, output.getvalue().strip())

    def test_getHumanSummaryWithPkgFn(self):
        """Test getHumanSummary() with pkg_fn"""
        # mock some data by calling collectCVEData() like bin/cve-report
        cveDirs = self._mock_cve_data_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs, False, filter_status="needs-triage,needed,pending,released"
        )

        pkg_fn = "%s/pkgs" % self.tmpdir
        content = "bar\n"
        with open(pkg_fn, "w") as fp:
            fp.write("%s" % content)

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, pkg_fn, report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (dependabot, secret-scanning)
low        bar                            CVE-2022-0002

Totals:
- critical: 0 in 0 repos
- high: 1 in 1 repos
- medium: 0 in 0 repos
- low: 1 in 1 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, pkg_fn, report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        expClosed = (
            exp
            + """


# Closed

Priority   Repository                     Issue
--------   ----------                     -----
negligible bar                            CVE-2021-9992

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 1 in 1 repos"""
        )
        self.assertEqual(expClosed, output.getvalue().strip())

    def test_getHumanSummaryWithFilterProduct(self):
        """Test getHumanSummary() with filter_product"""
        # mock some data by calling collectCVEData() like bin/cve-report
        cveDirs = self._mock_cve_data_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs,
            False,
            filter_status="needs-triage,needed,pending,released",
            filter_product="git/org",
        )

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (dependabot, secret-scanning)
medium     foo                            CVE-2022-GH1#foo          (limit-report)

Totals:
- critical: 0 in 0 repos
- high: 1 in 1 repos
- medium: 1 in 1 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        expClosed = (
            exp
            + """


# Closed

Priority   Repository                     Issue
--------   ----------                     -----
negligible bar                            CVE-2021-9992

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 1 in 1 repos"""
        )
        self.assertEqual(expClosed, output.getvalue().strip())

    def test_getHumanSummaryWithFilterPriority(self):
        """Test getHumanSummary() with filter_priority"""
        # mock some data by calling collectCVEData() like bin/cve-report
        cveDirs = self._mock_cve_data_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs,
            False,
            filter_status="needs-triage,needed,pending,released",
            filter_priority="high,critical",
        )

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (dependabot, secret-scanning)

Totals:
- critical: 0 in 0 repos
- high: 1 in 1 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        expClosed = (
            exp
            + """


# Closed

Priority   Repository                     Issue
--------   ----------                     -----
critical   foo                            CVE-2021-9991

Totals:
- critical: 1 in 1 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        )
        self.assertEqual(expClosed, output.getvalue().strip())

    def test_getHumanSummaryWithFilterTag(self):
        """Test getHumanSummary() with filter_tag"""
        # mock some data by calling collectCVEData() like bin/cve-report
        cveDirs = self._mock_cve_data_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs,
            False,
            filter_status="needs-triage,needed,pending,released",
            filter_tag="-limit-report",
        )

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (dependabot, secret-scanning)
medium     foo                            CVE-2022-0001
low        bar                            CVE-2022-0002
low        baz                            CVE-2022-0003
low        foo                            CVE-2022-NNN1

Totals:
- critical: 0 in 0 repos
- high: 1 in 1 repos
- medium: 1 in 1 repos
- low: 3 in 3 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        expClosed = (
            exp
            + """


# Closed

Priority   Repository                     Issue
--------   ----------                     -----
critical   foo                            CVE-2021-9991
negligible bar                            CVE-2021-9992

Totals:
- critical: 1 in 1 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 1 in 1 repos"""
        )
        self.assertEqual(expClosed, output.getvalue().strip())

        cves = cvelib.cve.collectCVEData(
            cveDirs,
            False,
            filter_status="needs-triage,needed,pending,released",
            filter_tag="limit-report",
        )
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
medium     foo                            CVE-2022-GH1#foo          (limit-report)

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 1 in 1 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        expClosed = (
            exp
            + """


# Closed

Priority   Repository                     Issue
--------   ----------                     -----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        )
        self.assertEqual(expClosed, output.getvalue().strip())

    #
    # getHumanSummaryGHAS()
    #
    def test_getHumanSummaryGHAS(self):
        """Test getHumanSummaryGHAS()"""
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummaryGHAS(
                [], "", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository           Affected                            CVEs
--------   ----------           --------                            ----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos


# Closed

Priority   Repository           Affected                            CVEs
--------   ----------           --------                            ----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        # mock some data by calling collectCVEData() like bin/cve-report
        cveDirs = self._mock_cve_data_ghas_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs, False, filter_status="needs-triage,needed,pending,released"
        )
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummaryGHAS(
                cves, "", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository           Affected                            CVEs
--------   ----------           --------                            ----
high       bar                  baz (2)                             CVE-2022-GH2#bar          (secret-scanning)
high       bar                  foo (2)                             CVE-2022-GH2#bar          (dependabot)
high       bar                  quxx                                CVE-2022-GH2#bar          (code-scanning)
medium     bar                  foo (2)                             CVE-2022-GH2#bar, CVE-2022-GH3#bar (dependabot)
negligible bar                  qux                                 CVE-2022-GH5#bar          (dependabot)

Totals:
- critical: 0 in 0 repos
- high: 5 in 1 repos
- medium: 2 in 0 repos
- low: 0 in 0 repos
- negligible: 1 in 0 repos


# Closed

Priority   Repository           Affected                            CVEs
--------   ----------           --------                            ----
low        bar                  corge                               CVE-2022-GH4#bar          (dependabot)

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 1 in 1 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        # mock some data by calling collectCVEData() like bin/cve-report and
        # filter out software
        cveDirs = self._mock_cve_data_ghas_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs, False, filter_status="needs-triage,needed,pending,released"
        )
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummaryGHAS(
                cves, "nonexistent", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository           Affected                            CVEs
--------   ----------           --------                            ----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos


# Closed

Priority   Repository           Affected                            CVEs
--------   ----------           --------                            ----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        # mock some data by calling collectCVEData() like bin/cve-report and
        # filter out priority
        cveDirs = self._mock_cve_data_ghas_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs, False, filter_status="needs-triage,needed,pending,released"
        )
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummaryGHAS(
                cves, "nonexistent", report_output=cvelib.report.ReportOutput.BOTH
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository           Affected                            CVEs
--------   ----------           --------                            ----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos


# Closed

Priority   Repository           Affected                            CVEs
--------   ----------           --------                            ----

Totals:
- critical: 0 in 0 repos
- high: 0 in 0 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

    def test__main_report_parse_args(self):
        """Test _main_report_parse_args"""
        # invalid invocations
        tsts = [
            # no args
            ([], "Please specify a report command"),
            # summary
            (
                ["summary", "--unique", "--open"],
                "--open, --closed and --all not supported with 'summary --unique'",
            ),
            (
                ["summary", "--all", "--closed"],
                "Please use only one of --all, --closed or --open with 'summary'",
            ),
            (
                ["summary", "--software", "foo", "--ghas"],
                "--software is not supported with 'summary --ghas'",
            ),
            (
                ["summary", "--software", "foo", "--unique"],
                "--software is not supported with 'summary --unique'",
            ),
            # todo
            (["todo", "--software", "foo"], "--software is not supported with 'todo'"),
            # gh
            (
                ["gh"],
                "Please specify one of --alerts, --missing, --updates or --status with 'gh'",
            ),
            (
                ["gh", "--alerts"],
                "Please specify --since and/or --since-stamp with --missing/--updated/--alerts",
            ),
            (
                ["gh", "--missing", "--with-templates", "--since", "1"],
                "Please specify --alerts with --with-templates",
            ),
            (
                ["gh", "--updated", "--since", "1", "--software", "foo"],
                "Unsupported option --software with --updated",
            ),
            (["gh", "--alerts", "--since", "1"], "Please specify --org"),
            (
                ["gh", "--alerts", "--since", "1", "--org", "foo"],
                "Please export GitHub personal access token as GHTOKEN",
            ),
            (
                ["gh", "--alerts", "--since", "bad", "--org", "foo"],
                "Please specify seconds since epoch or YYYY-MM-DD with --since",
            ),
            # quay
            (
                ["quay"],
                "Please specify one of --alerts, --list or --list-digest with 'quay'",
            ),
            (
                ["quay", "--list", "--namespace", "foo/bad"],
                "--namespace 'foo/bad' should not contain '/'",
            ),
            (
                ["quay", "--list", "--namespace", "foo", "--raw"],
                "Please specify --alerts with --raw",
            ),
            (
                ["quay", "--list", "--namespace", "foo", "--all"],
                "Please specify --alerts with --all",
            ),
            (
                ["quay", "--list", "--namespace", "foo", "--with-templates"],
                "Please specify --alerts with --with-templates",
            ),
            (
                [
                    "quay",
                    "--alerts",
                    "--namespace",
                    "foo",
                    "--images",
                    "img@sha256:deadbeef",
                    "--list",
                ],
                "Unsupported option --list with --alerts",
            ),
            (
                [
                    "quay",
                    "--alerts",
                    "--namespace",
                    "foo",
                    "--images",
                    "img@sha256:deadbeef",
                    "--list-digest",
                    "foo/img",
                ],
                "Unsupported option --list-digest with --alerts",
            ),
            (
                ["quay", "--alerts"],
                "Please specify --namespace with 'quay'",
            ),
            (
                [
                    "quay",
                    "--alerts",
                    "--namespace",
                    "foo",
                    "--images",
                    "img@sha256:deadbeef",
                    "--raw",
                    "--all",
                ],
                "--raw not supported with --all or --with-templates",
            ),
            (
                [
                    "quay",
                    "--alerts",
                    "--namespace",
                    "foo",
                    "--images",
                    "img@sha256:deadbeef",
                    "--raw",
                    "--with-templates",
                ],
                "--raw not supported with --all or --with-templates",
            ),
            (
                [
                    "quay",
                    "--alerts",
                    "--namespace",
                    "foo",
                ],
                "Please specify --images or --excluded-images with --alerts",
            ),
            # gar
            (
                ["gar"],
                "Please specify one of --alerts, --list, --list-repos or --list-digest with 'gar'",
            ),
            (
                ["gar", "--list", "--namespace", "foo"],
                "--namespace 'foo' should contain one '/'",
            ),
            (
                ["gar", "--list", "--namespace", "foo/us/bad"],
                "--namespace 'foo/us/bad' should contain one '/'",
            ),
            (
                ["gar", "--list", "--namespace", "foo/us", "--raw"],
                "Please specify --alerts with --raw",
            ),
            (
                ["gar", "--list", "--namespace", "foo/us", "--all"],
                "Please specify --alerts with --all",
            ),
            (
                ["gar", "--list", "--namespace", "foo/us", "--with-templates"],
                "Please specify --alerts with --with-templates",
            ),
            (
                ["gar", "--list", "--namespace", "foo/us", "--filter-priority=high"],
                "Please specify --alerts with --filter-priority",
            ),
            (
                [
                    "gar",
                    "--alerts",
                    "--namespace",
                    "foo/us",
                    "--images",
                    "repo/img@sha256:deadbeef",
                    "--list",
                ],
                "Unsupported option --list with --alerts",
            ),
            (
                [
                    "gar",
                    "--alerts",
                    "--namespace",
                    "foo/us",
                    "--images",
                    "repo/img@sha256:deadbeef",
                    "--list-digest",
                    "foo/us/repo/img",
                ],
                "Unsupported option --list-digest with --alerts",
            ),
            (
                [
                    "gar",
                    "--alerts",
                    "--namespace",
                    "foo/us",
                    "--images",
                    "repo/img@sha256:deadbeef",
                    "--list-repos",
                ],
                "Unsupported option --list-repos with --alerts",
            ),
            (
                ["gar", "--alerts"],
                "Please specify --namespace with 'gar'",
            ),
            (
                [
                    "gar",
                    "--alerts",
                    "--namespace",
                    "foo/us",
                    "--images",
                    "repo/img@sha256:deadbeef",
                    "--raw",
                    "--all",
                ],
                "--raw not supported with --all or --with-templates",
            ),
            (
                [
                    "gar",
                    "--alerts",
                    "--namespace",
                    "foo/us",
                    "--images",
                    "repo/img@sha256:deadbeef",
                    "--raw",
                    "--with-templates",
                ],
                "--raw not supported with --all or --with-templates",
            ),
            (
                [
                    "gar",
                    "--alerts",
                    "--namespace",
                    "foo/us",
                ],
                "Please specify --images or --excluded-images with --alerts",
            ),
        ]
        for args, expErr in tsts:
            with mock.patch.object(
                cvelib.common.error,
                "__defaults__",
                (
                    1,
                    False,
                ),
            ):
                if "GHTOKEN" in expErr:
                    del os.environ["GHTOKEN"]
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.report._main_report_parse_args(args)
                if "GHTOKEN" in expErr:
                    os.environ["GHTOKEN"] = "fake-test-token"
                self.assertEqual("", output.getvalue().strip())
                errout = error.getvalue()
                self.assertTrue(
                    expErr in errout.strip(),
                    msg="Could not find '%s' in: %s" % (expErr, errout),
                )

    def test_main_report(self):
        """Test main_report"""
        self._mock_cve_data_mixed()

        tsts = [
            (["summary"], "- high: 1 in 1 repos"),
            (["summary", "--open"], "- high: 1 in 1 repos"),
            (["summary", "--closed"], "- critical: 1 in 1 repos"),
            (["summary", "--all"], "- high: 1 in 1 repos"),
            (["summary", "--all"], "- critical: 1 in 1 repos"),
            (["summary", "--ghas"], "- critical: 0 in 0 repos"),
            (
                ["summary", "--unique"],
                "Total:                                  1          1          2          3          1",
            ),
            (
                ["influxdb"],
                'cvelog,priority=high,status=needed,product=git,where=org id="CVE-2022-GH2#bar",software="bar",modifier="" ',
            ),
            (["influxdb", "--software='nonexistent'"], ""),
            (
                ["influxdb", "--starttime", "1"],
                'cvelog,priority=high,status=needed,product=git,where=org id="CVE-2022-GH2#bar",software="bar",modifier="" ',
            ),
            (["sw"], "bar:\n  high:\n    CVE-2022-GH2#bar\n  low:\n    CVE-2022-0002"),
            (
                ["todo"],
                "110      bar: 1 high, 1 low\n110      foo: 2 medium, 1 low\n10       baz: 1 low",
            ),
        ]
        for args, exp in tsts:
            with mock.patch.object(
                cvelib.common.error,
                "__defaults__",
                (
                    1,
                    False,
                ),
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.report.main_report(args)
                self.assertEqual("", error.getvalue().strip())
                out = output.getvalue()
                self.assertTrue(
                    exp in out.strip(),
                    msg="Could not find '%s' in: %s" % (exp, out),
                )

        # for coverage, handle main_report without setting args
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.report.main_report()
            self.assertEqual("", output.getvalue().strip())
            errout = error.getvalue()
            self.assertTrue("Please specify a report command" in errout.strip())

            # bad args
            with self.assertRaises(ValueError):
                cvelib.report.main_report(["influxdb", "--starttime", "-1"])

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsAllFull)
    def test_main_report_gh_alerts(self, _):  # 2nd arg is mock_get
        """Test main_report - gh --alerts"""
        self._mock_cve_data_mixed()  # this creates self.tmpdir
        since_stamp_fn = os.path.join(str(self.tmpdir), "since")
        with open(since_stamp_fn, "w"):  # touch the file
            pass

        # adjust the config file for template-urls
        with open(os.path.join(str(self.tmpdir), ".config/sedg/sedg.conf"), "a") as fh:
            fh.write(
                """
[Behavior]
template-urls = https://url1,https://url2
"""
            )

        tsts = [
            (
                [
                    "gh",
                    "--alerts",
                    "--since",
                    "1",
                    "--org",
                    "valid-org",
                    "-s",
                    "valid-repo",
                ],
                "valid-repo updated alerts:",
            ),
            (
                [
                    "gh",
                    "--alerts",
                    "--since",
                    "1",
                    "--org",
                    "valid-org",
                    "-s",
                    "valid-repo",
                    "--with-templates",
                ],
                "https://url1\n * https://url2\n *",
            ),
            (
                [
                    "gh",
                    "--alerts",
                    "--since",
                    "2000-01-01",
                    "--org",
                    "valid-org",
                    "-s",
                    "valid-repo",
                ],
                "valid-repo updated alerts:",
            ),
            (
                [
                    "gh",
                    "--alerts",
                    "--since",
                    "1",
                    "--org",
                    "valid-org",
                    "--excluded-software",
                    "other-repo",
                ],
                "valid-repo updated alerts:",
            ),
            (
                [
                    "gh",
                    "--alerts=dependabot",
                    "--since",
                    "1",
                    "--org",
                    "valid-org",
                    "-s",
                    "valid-repo",
                ],
                "valid-repo updated alerts:",
            ),
            (
                [
                    "gh",
                    "--alerts",
                    "--since-stamp",
                    since_stamp_fn,
                    "--org",
                    "valid-org",
                    "-s",
                    "valid-repo",
                ],
                "valid-repo updated alerts:",
            ),
        ]
        for args, exp in tsts:
            # set the access and modification time to 2000-01-01
            os.utime(since_stamp_fn, (946706400, 946706400))

            with tests.testutil.capturedOutput() as (output, error):
                cvelib.report.main_report(args)
            self.assertEqual("", error.getvalue().strip())
            out = output.getvalue()
            self.assertTrue(
                exp in out.strip(),
                msg="Could not find '%s' in: %s" % (exp, out),
            )

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsAllFull)
    def test_main_report_gh_alerts_has_previous(self, _):  # 2nd arg is mock_get
        """Test main_report - gh --alerts - has previous"""
        cveDirs = self._mock_cve_data_mixed()  # this creates self.tmpdir

        # create a file with a dupe of something in self._mock_cve_data_mixed()
        d = self._cve_template(
            cand="CVE-2022-GH9998#bar",
            references=["https://github.com/org/bar/issues/9998"],
        )
        d["Priority"] = "medium"
        d["git/valid-org_valid-repo"] = "needed"
        d["Discovered-by"] = "gh-dependabot"
        d[
            "GitHub-Advanced-Security"
        ] = """
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   advisory: https://github.com/advisories/GHSA-b
   severity: medium
   status: needed
   url: https://github.com/valid-org/valid-repo/security/dependabot/3"""
        cve_fn = os.path.join(cveDirs["active"], d["Candidate"])
        content = tests.testutil.cveContentFromDict(d)
        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(
                [
                    "gh",
                    "--alerts",
                    "--since",
                    "1",
                    "--org",
                    "valid-org",
                    "-s",
                    "valid-repo",
                ],
            )
            self.assertEqual(
                "WARN: found previously known url with newer createdAt: https://github.com/valid-org/valid-repo/security/dependabot/3 (skipping)",
                error.getvalue().strip(),
            )
            out = output.getvalue()
            exp = "valid-repo updated alerts:"
            self.assertTrue(
                exp in out.strip(),
                msg="Could not find '%s' in: %s" % (exp, out),
            )

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test_main_report_gh_missing(self, _):  # 2nd arg is mock_get
        """Test main_report - gh --missing"""
        self._mock_cve_data_mixed()
        args = [
            "gh",
            "--missing",
            "--org",
            "valid-org",
            "--software",
            "empty-repo",
            "--labels",
            "blah1:blah2",
            "--excluded-labels",
            "blah3:blah4",
            "--since",
            "1",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        out = output.getvalue()
        exp = "No missing issues."
        self.assertTrue(
            exp in out.strip(), msg="Could not find '%s' in: %s" % (exp, out)
        )

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test_main_report_gh_updated(self, _):  # 2nd arg is mock_get
        """Test main_report - gh --updated"""
        self._mock_cve_data_mixed()
        args = ["gh", "--updated", "--org", "valid-org", "--since", "1"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        out = output.getvalue()
        exp = "No updated issues."
        self.assertTrue(
            exp in out.strip(), msg="Could not find '%s' in: %s" % (exp, out)
        )

    @mock.patch("cvelib.report.getMissingReport")
    @mock.patch("cvelib.report.getUpdatedReport")
    @mock.patch("cvelib.report.getGHAlertsReport")
    def test_main_report_gh_multiple(
        self, mock_getGHAlertsReport, mock_getUpdatedReport, mock_getMissingReport
    ):  # 2nd arg is mock_get
        """Test main_report - gh --alerts --updated --missing"""
        mock_getGHAlertsReport.return_value = None
        mock_getUpdatedReport.return_value = None
        mock_getMissingReport.return_value = None
        self._mock_cve_data_mixed()
        args = [
            "gh",
            "--alerts",
            "--updated",
            "--missing",
            "--org",
            "valid-org",
            "--software",
            "empty-repo",
            "--since",
            "1",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        out = output.getvalue()
        exp = "# Alerts"
        self.assertTrue(
            exp in out.strip(), msg="Could not find '%s' in: %s" % (exp, out)
        )
        exp = "# Missing"
        self.assertTrue(
            exp in out.strip(), msg="Could not find '%s' in: %s" % (exp, out)
        )
        exp = "# Updates"
        self.assertTrue(
            exp in out.strip(), msg="Could not find '%s' in: %s" % (exp, out)
        )

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHReposAll)
    def test_main_report_gh_status_active(self, _):  # 2nd arg is mock_get
        """Test main_report - gh --status=active"""
        self._mock_cve_data_mixed()
        args = ["gh", "--org", "valid-org", "--status", "active"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        out = output.getvalue()
        exp = "foo"
        self.assertTrue(
            exp in out.strip(), msg="Could not find '%s' in: %s" % (exp, out)
        )
        exp = "baz"
        self.assertTrue(
            exp in out.strip(), msg="Could not find '%s' in: %s" % (exp, out)
        )

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsEnabled)
    def test_main_report_gh_status_alerts(self, _):  # 2nd arg is mock_get
        """Test main_report - gh --status=alerts"""
        self._mock_cve_data_mixed()
        args = ["gh", "--org", "valid-org", "--status", "alerts"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        out = output.getvalue()
        exp = "dependabot,enabled,valid-repo"
        self.assertTrue(
            exp in out.strip(), msg="Could not find '%s' in: %s" % (exp, out)
        )

    @mock.patch("cvelib.quay.QuaySecurityReportNew.getOCIsForNamespace")
    def test_main_report_quay_list(self, mock_getOCIsForNamespace):
        """Test main_report - quay --list"""
        self._mock_cve_data_mixed()  # for cveDirs
        os.environ["SEDG_EXPERIMENTAL"] = "1"
        mock_getOCIsForNamespace.return_value = [("valid-repo", 1684472852)]
        args = ["quay", "--list", "--namespace", "valid-org"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual(
            "valid-org/valid-repo (last updated: 2023-05-19 05:07:32)",
            output.getvalue().strip(),
        )

        mock_getOCIsForNamespace.return_value = [("empty-repo", 0)]
        args = ["quay", "--list", "--namespace", "valid-org"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual(
            "valid-org/empty-repo (last updated: unknown)",
            output.getvalue().strip(),
        )

    @mock.patch("cvelib.quay.QuaySecurityReportNew.getDigestForImage")
    def test_main_report_quay_list_digest(self, mock_getDigestForImage):
        """Test main_report - quay --list-digest"""
        self._mock_cve_data_mixed()  # for cveDirs
        os.environ["SEDG_EXPERIMENTAL"] = "1"
        mock_getDigestForImage.return_value = "valid-org/valid-repo@sha256:deadbeef"
        args = ["quay", "--list-digest", "valid-repo", "--namespace", "valid-org"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual("sha256:deadbeef", output.getvalue().strip())

    def _getValidScanOCI(self, quay=False, gar=False):
        """Returns a ScanOCI"""
        url = "https://blah.com/BAR-a"
        if quay:
            url = "https://quay.io/repository/valid-org/valid-repo/manifest/sha256:deadbeef"
        elif gar:
            url = "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef"

        data = {
            "component": "foo",
            "detectedIn": "Some Distro",
            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
            "version": "1.2.2",
            "fixedBy": "1.2.3",
            "severity": "medium",
            "status": "needed",
            "url": url,
        }
        return cvelib.scan.ScanOCI(data)

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.quay.QuaySecurityReportNew.getDigestForImage")
    @mock.patch("cvelib.quay.QuaySecurityReportNew.fetchScanReport")
    def test_main_report_quay_alerts(
        self, mock_fetchScanReport, mock_getDigestForImage
    ):
        """Test main_report - quay --alerts"""
        self._mock_cve_data_mixed()  # for cveDirs
        os.environ["SEDG_EXPERIMENTAL"] = "1"

        # with image digest
        mock_fetchScanReport.return_value = [self._getValidScanOCI(quay=True)], ""
        args = [
            "quay",
            "--alerts",
            "--namespace",
            "valid-org",
            "--images",
            "valid-repo@sha256:deadbeef",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(
            "# New reports\n\nvalid-org/valid-repo report: 1" in output.getvalue(),
            msg="output is:\n%s" % output.getvalue().strip(),
        )

        # without image digest
        mock_fetchScanReport.return_value = [self._getValidScanOCI(quay=True)], ""
        mock_getDigestForImage.return_value = "valid-org/valid-repo@sha256:deadbeef0123"
        args = [
            "quay",
            "--alerts",
            "--namespace",
            "valid-org",
            "--images",
            "valid-repo",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(
            "# New reports\n\nvalid-org/valid-repo report: 1" in output.getvalue(),
            msg="output is:\n%s" % output.getvalue().strip(),
        )

        # with image digest, bad
        mock_fetchScanReport.return_value = [], "Test error"
        args = [
            "quay",
            "--alerts",
            "--namespace",
            "valid-org",
            "--images",
            "valid-repo@sha256:deadbeef",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("WARN: Test error", error.getvalue().strip())

        # without image digest, bad result
        mock_fetchScanReport.return_value = [], ""
        mock_getDigestForImage.return_value = "bad"
        args = [
            "quay",
            "--alerts",
            "--namespace",
            "valid-org",
            "--images",
            "valid-repo",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "WARN: Could not find digest for valid-repo", error.getvalue().strip()
        )

        # --excluded-images
        mock_fetchScanReport.return_value = [], ""
        args = [
            "quay",
            "--alerts",
            "--namespace",
            "valid-org",
            "--images",
            "valid-repo@sha256:deadbeef",
            "--excluded-images",
            "valid-repo",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual("", output.getvalue().strip())

        mock_fetchScanReport.return_value = [self._getValidScanOCI(quay=True)], ""
        args = [
            "quay",
            "--alerts",
            "--namespace",
            "valid-org",
            "--images",
            "valid-repo@sha256:deadbeef,other-repo@sha256:deadbeef",
            "--excluded-images",
            "other-repo",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(
            "# New reports\n\nvalid-org/valid-repo report: 1" in output.getvalue(),
            msg="output is:\n%s" % output.getvalue().strip(),
        )

        # --filter-priority parsing
        mock_fetchScanReport.return_value = [self._getValidScanOCI(quay=True)], ""
        args = [
            "quay",
            "--alerts",
            "--filter-priority",
            "critical,high",
            "--namespace",
            "valid-org",
            "--images",
            "valid-repo@sha256:deadbeef",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(
            "# New reports\n\nvalid-org/valid-repo report: 1" in output.getvalue(),
            msg="output is:\n%s" % output.getvalue().strip(),
        )

        # raw
        mock_fetchScanReport.return_value = [], "{}"
        args = [
            "quay",
            "--alerts",
            "--namespace",
            "valid-org",
            "--images",
            "valid-name@sha256:deadbeef",
            "--raw",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual("[{}]", output.getvalue().strip())

        # bad image name
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            mock_fetchScanReport.return_value = ""
            args = [
                "quay",
                "--alerts",
                "--namespace",
                "valid-org",
                "--images",
                "valid-repo/bad@sha256:deadbeef",
            ]
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.report.main_report(args)
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "ERROR: image name 'valid-repo/bad@sha256:deadbeef' should not contain '/'",
            error.getvalue().strip(),
        )

    @mock.patch("cvelib.gar.GARSecurityReportNew.getOCIsForNamespace")
    def test_main_report_gar_list(self, mock_getOCIsForNamespace):
        """Test main_report - gar --list"""
        self._mock_cve_data_mixed()  # for cveDirs
        os.environ["SEDG_EXPERIMENTAL"] = "1"
        mock_getOCIsForNamespace.return_value = [
            (
                "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
                1684472852,
            ),
        ]
        args = ["gar", "--list", "--namespace", "valid-proj/us"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual(
            "valid-proj/us/valid-repo/valid-name (last updated: 2023-05-19 05:07:32)",
            output.getvalue().strip(),
        )

    @mock.patch("cvelib.gar.GARSecurityReportNew.getReposForNamespace")
    def test_main_report_gar_list_repos(self, mock_getReposForNamespace):
        """Test main_report - gar --list-repos"""
        self._mock_cve_data_mixed()  # for cveDirs
        os.environ["SEDG_EXPERIMENTAL"] = "1"
        mock_getReposForNamespace.return_value = [
            "projects/valid-proj/locations/us/repositories/valid-repo"
        ]
        args = ["gar", "--list-repos", "--namespace", "valid-proj/us"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual("valid-proj/us/valid-repo", output.getvalue().strip())

    @mock.patch("cvelib.gar.GARSecurityReportNew.getDigestForImage")
    def test_main_report_gar_list_digest(self, mock_getDigestForImage):
        """Test main_report - gar --list-digest"""
        self._mock_cve_data_mixed()  # for cveDirs
        os.environ["SEDG_EXPERIMENTAL"] = "1"
        mock_getDigestForImage.return_value = "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:deadbeef"
        args = [
            "gar",
            "--namespace",
            "valid-proj/us",
            "--list-digest",
            "valid-repo/valid-name",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual("sha256:deadbeef", output.getvalue().strip())

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.gar.GARSecurityReportNew.getDigestForImage")
    @mock.patch("cvelib.gar.GARSecurityReportNew.fetchScanReport")
    def test_main_report_gar_alerts(self, mock_fetchScanReport, mock_getDigestForImage):
        """Test main_report - gar --alerts"""
        self._mock_cve_data_mixed()  # for cveDirs
        os.environ["SEDG_EXPERIMENTAL"] = "1"

        # with image digest
        mock_fetchScanReport.return_value = [self._getValidScanOCI(gar=True)], ""
        args = [
            "gar",
            "--alerts",
            "--namespace",
            "valid-proj/us",
            "--images",
            "valid-repo/valid-name@sha256:deadbeef",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(
            "# New reports\n\nvalid-proj/us/valid-repo/valid-name report: 1"
            in output.getvalue(),
            msg="output is:\n%s" % output.getvalue().strip(),
        )

        # without image digest
        mock_fetchScanReport.return_value = [self._getValidScanOCI(gar=True)], ""
        mock_getDigestForImage.return_value = "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:deadbeef0123"
        args = [
            "gar",
            "--alerts",
            "--namespace",
            "valid-proj/us",
            "--images",
            "valid-repo/valid-name",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(
            "# New reports\n\nvalid-proj/us/valid-repo/valid-name report: 1"
            in output.getvalue(),
            msg="output is:\n%s" % output.getvalue().strip(),
        )

        # without image digest, bad result
        mock_fetchScanReport.return_value = [], ""
        mock_getDigestForImage.return_value = "bad"
        args = [
            "gar",
            "--alerts",
            "--namespace",
            "valid-proj/us",
            "--images",
            "valid-repo/valid-name",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "WARN: Could not find digest for valid-repo/valid-name",
            error.getvalue().strip(),
        )

        # raw
        mock_fetchScanReport.return_value = [], "{}"
        args = [
            "gar",
            "--alerts",
            "--namespace",
            "valid-proj/us",
            "--images",
            "valid-repo/valid-name@sha256:deadbeef",
            "--raw",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual("[{}]", output.getvalue().strip())

        # bad image name
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            mock_fetchScanReport.return_value = ""
            args = [
                "gar",
                "--alerts",
                "--namespace",
                "valid-proj/us",
                "--images",
                "valid-name@sha256:deadbeef",
            ]
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.report.main_report(args)
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "ERROR: image name 'valid-name@sha256:deadbeef' should contain one '/'",
            error.getvalue().strip(),
        )

    @mock.patch("cvelib.gar.GARSecurityReportNew.fetchScanReport")
    def test_main_report_gar_alerts_existing(self, mock_fetchScanReport):
        """Test main_report - gar --alerts - existing"""
        self._mock_cve_data_scans_mixed()  # for cveDirs
        os.environ["SEDG_EXPERIMENTAL"] = "1"

        # 1 new, 2 exist with precise oci match
        ocis = [
            cvelib.scan.ScanOCI(
                {
                    "component": "curl",
                    "detectedIn": "cpe:/o:debian:debian_linux:11",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2022-32221",
                    "version": "7.74.0-1.3+deb11u2",
                    "fixedBy": "7.74.0-1.3+deb11u5",
                    "severity": "critical",
                    "status": "needed",
                    "url": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef",
                }
            ),
            cvelib.scan.ScanOCI(
                {
                    "component": "libtasn1-6",
                    "detectedIn": "cpe:/o:debian:debian_linux:11",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2021-46848",
                    "version": "4.16.0-2",
                    "fixedBy": "4.16.0-2+deb11u1",
                    "severity": "critical",
                    "status": "needed",
                    "url": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef",
                }
            ),
            cvelib.scan.ScanOCI(
                {
                    "component": "foo",
                    "detectedIn": "Some Distro",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef",
                }
            ),
        ]

        mock_fetchScanReport.return_value = ocis, ""
        args = [
            "gar",
            "--alerts",
            "--namespace",
            "valid-proj/us",
            "--images",
            "valid-repo/valid-name@sha256:deadbeef0001",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        res = output.getvalue().strip()
        self.assertTrue(
            "# New reports\n\nvalid-proj/us/valid-repo/valid-name report: 1" in res,
            msg="output is:\n%s" % res,
        )
        self.assertFalse(
            "   advisory: https://www.cve.org/CVERecord?id=CVE-2022-32221" in res,
            msg="output is:\n%s" % res,
        )
        self.assertFalse(
            "   advisory: https://www.cve.org/CVERecord?id=CVE-2021-46848" in res,
            msg="output is:\n%s" % res,
        )
        self.assertTrue(
            "   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001" in res,
            msg="output is:\n%s" % res,
        )
        self.assertTrue(
            "   url: https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef"
            in res,
            msg="output is:\n%s" % res,
        )

        # 0 new, 2 exist with precise oci match
        ocis = [
            cvelib.scan.ScanOCI(
                {
                    "component": "curl",
                    "detectedIn": "cpe:/o:debian:debian_linux:11",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2022-32221",
                    "version": "7.74.0-1.3+deb11u2",
                    "fixedBy": "7.74.0-1.3+deb11u5",
                    "severity": "critical",
                    "status": "needed",
                    "url": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef",
                }
            ),
            cvelib.scan.ScanOCI(
                {
                    "component": "libtasn1-6",
                    "detectedIn": "cpe:/o:debian:debian_linux:11",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2021-46848",
                    "version": "4.16.0-2",
                    "fixedBy": "4.16.0-2+deb11u1",
                    "severity": "critical",
                    "status": "needed",
                    "url": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef",
                }
            ),
        ]

        mock_fetchScanReport.return_value = ocis, ""
        args = [
            "gar",
            "--alerts",
            "--namespace",
            "valid-proj/us",
            "--images",
            "valid-repo/valid-name@sha256:deadbeef0001",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        res = output.getvalue().strip()
        self.assertFalse("# New report" in res, msg="output is:\n%s" % res)
        self.assertFalse("# Updated report" in res, msg="output is:\n%s" % res)
        self.assertFalse(
            "   advisory: https://www.cve.org/CVERecord?id=CVE-2022-32221" in res,
            msg="output is:\n%s" % res,
        )
        self.assertFalse(
            "   advisory: https://www.cve.org/CVERecord?id=CVE-2021-46848" in res,
            msg="output is:\n%s" % res,
        )

        # 0 new, 2 exist with fuzzy oci match for one
        ocis = [
            cvelib.scan.ScanOCI(
                {
                    "component": "curl",
                    "detectedIn": "cpe:/o:debian:debian_linux:11",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2022-32221",
                    "version": "7.74.0-1.3+deb11u2",
                    "fixedBy": "7.74.0-1.3+deb11u5",
                    "severity": "high",
                    "status": "needed",
                    "url": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef",
                }
            ),
            cvelib.scan.ScanOCI(
                {
                    "component": "libtasn1-6",
                    "detectedIn": "cpe:/o:debian:debian_linux:11",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2021-46848",
                    "version": "4.16.0-2",
                    "fixedBy": "4.16.0-2+deb11u1",
                    "severity": "critical",
                    "status": "needed",
                    "url": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef",
                }
            ),
        ]

        mock_fetchScanReport.return_value = ocis, ""
        args = [
            "gar",
            "--alerts",
            "--namespace",
            "valid-proj/us",
            "--images",
            "valid-repo/valid-name@sha256:deadbeef0001",
        ]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.report.main_report(args)
        self.assertEqual("", error.getvalue().strip())
        res = output.getvalue().strip()
        exp = """# Updated reports

valid-proj/us/valid-repo/valid-name report: 1

 active/CVE-2022-GH2#foo:
 - type: oci
   component: curl
   detectedIn: cpe:/o:debian:debian_linux:11
   advisory: https://www.cve.org/CVERecord?id=CVE-2022-32221
   version: 7.74.0-1.3+deb11u2
   fixedBy: 7.74.0-1.3+deb11u5
-  severity: critical
+  severity: high
   status: needed
   url: https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:deadbeef"""
        self.assertEqual(res, exp)
