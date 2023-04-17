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
import cvelib.testutil


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

    if args[0] == "https://api.github.com/orgs/valid-org/dependabot/alerts":
        return MockResponse([], 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/secret-scanning/alerts":
        return MockResponse([], 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/code-scanning/alerts":
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
    elif args[0] == "https://api.github.com/orgs/valid-org/secret-scanning/alerts":
        return MockResponse([], 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/code-scanning/alerts":
        return MockResponse([], 200)

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

    if args[0] == "https://api.github.com/orgs/valid-org/dependabot/alerts":
        return MockResponse([], 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/secret-scanning/alerts":
        return MockResponse(_getMockedAlertsJSON("secret-scanning"), 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/code-scanning/alerts":
        return MockResponse([], 200)

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

    if args[0] == "https://api.github.com/orgs/valid-org/dependabot/alerts":
        return MockResponse([], 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/secret-scanning/alerts":
        return MockResponse(_getMockedAlertsJSON("secret-scanning-private"), 200)
    elif args[0] == "https://api.github.com/orgs/valid-org/code-scanning/alerts":
        return MockResponse([], 200)

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

        if "GHTOKEN" in os.environ:
            self.orig_ghtoken = os.getenv("GHTOKEN")
        os.environ["GHTOKEN"] = "fake-test-token"
        os.environ["TEST_UPDATE_PROGRESS"] = "0"

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

        if self.tmpdir is not None:
            cvelib.common.recursive_rm(self.tmpdir)

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
            content = cvelib.testutil.cveContentFromDict(d)
            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")
        content = (
            """[Location]
cve-data = %s
"""
            % self.tmpdir
        )
        self.orig_xdg_config_home, self.tmpdir = cvelib.testutil._newConfigFile(
            content, self.tmpdir
        )

        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        # regular CVE - foo
        d = self._cve_template(cand="CVE-2022-0001")
        d["upstream_foo"] = "needs-triage"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # regular CVE - bar
        d = self._cve_template(cand="CVE-2022-0002")
        d["Priority"] = "low"
        d["upstream_bar"] = "needs-triage"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # regular CVE - baz
        d = self._cve_template(cand="CVE-2022-0003")
        d["Priority"] = "low"
        d["upstream_baz"] = "needs-triage"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # placeholder with priority override
        d = self._cve_template(cand="CVE-2022-NNN1")
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
        d = self._cve_template(cand="CVE-2021-9991")
        d["upstream_foo"] = "released"
        d["Priority"] = "critical"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # regular CVE, closed
        d = self._cve_template(cand="CVE-2021-9992")
        d["git/org_bar"] = "released"
        d["Priority"] = "negligible"
        _write_cve(os.path.join(cveDirs["active"], d["Candidate"]), d)

        # regular CVE, ignored
        d = self._cve_template(cand="CVE-2021-9993")
        d["upstream_bar"] = "ignored"
        d["Priority"] = "negligible"
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
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getReposReport("valid-org")
        self.assertEqual("", error.getvalue().strip())
        exp = """baz
foo"""
        self.assertEqual(exp, output.getvalue().strip())

        # explicit active
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getReposReport("valid-org", archived=False)
        self.assertEqual("", error.getvalue().strip())
        exp = """baz
foo"""
        self.assertEqual(exp, output.getvalue().strip())

        # default args
        with cvelib.testutil.capturedOutput() as (output, error):
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
        res = cvelib.report._getKnownIssues(self._mock_cve_list_basic())
        self.assertEqual(3, len(res))
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

    #
    # getMissingReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test_getMissingReport(self, _):  # 2nd arg is mock_get
        """Test getMissingReport()"""
        cves = self._mock_cve_list_basic()
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getMissingReport(cves, "valid-org", repos=["valid-repo"])
        self.assertEqual("", error.getvalue().strip())
        exp = """Issues missing from CVE data:
 https://github.com/valid-org/valid-repo/issues/4"""
        self.assertEqual(exp, output.getvalue().strip())

        # excluded
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getMissingReport(
                cves, "valid-org", repos=["valid-repo"], excluded_repos=["valid-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """No missing issues for the specified repos."""
        self.assertEqual(exp, output.getvalue().strip())

        # archived
        cves = self._mock_cve_list_basic()
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getMissingReport(cves, "valid-org")
        self.assertEqual("", error.getvalue().strip())
        exp = """Issues missing from CVE data:
 https://github.com/valid-org/valid-repo/issues/4"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # _getGHAlertsEnabled()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsEnabled)
    def test_getGHAlertsEnabled(self, _):  # 2nd arg is mock_get
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
    def test_getGHSecretsScanningEnabled(self, _):  # 2nd arg is mock_get
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

    #
    # getGHAlertsStatusReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsEnabled)
    def test_getGHAlertsStatusReport(self, _):  # 2nd arg is mock_get
        """Test _getGHAlertsStatusReport()"""
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsStatusReport(
                "valid-org", repos=["valid-repo", "disabled-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Dependabot:
 Enabled:
  valid-repo
 Disabled:
  disabled-repo

Secret Scanning:
 Enabled:
  valid-repo
 Disabled:
  disabled-repo

Code Scanning:
 Enabled:
  valid-repo
 Disabled:
  disabled-repo"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # getUpdatedReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssuesForRepo)
    def test_getUpdatedReport(self, _):  # 2nd arg is mock_get
        """Test _getUpdatedReport()"""
        cves = self._mock_cve_list_basic()

        # all updated since
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org")
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
Updated issues:
 https://github.com/valid-org/valid-repo/issues/1 (CVE-2022-GH1001#valid-repo)
 https://github.com/valid-org/valid-repo/issues/2 (CVE-2022-GH1002#valid-repo)
 https://github.com/valid-org/valid-repo/issues/3 (CVE-2022-GH1003#valid-repo)"""
        self.assertEqual(exp, output.getvalue().strip())

        # some updated since 1656792271 (2022-07-02)
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org", since=1656792271)
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
Updated issues:
 https://github.com/valid-org/valid-repo/issues/3 (CVE-2022-GH1003#valid-repo)"""
        self.assertEqual(exp, output.getvalue().strip())

        # none updated since 1657224398 (2022-07-07)
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org", since=1657224398)
        self.assertEqual("", error.getvalue().strip())
        exp = """Collecting known issues:
No updated issues for the specified repos."""
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsSummary(
                "valid-org", "valid-repo", [], "updated"
            )
        self.assertEqual("", error.getvalue().strip())
        exp = "valid-repo updated alerts: 0"
        self.assertEqual(exp, output.getvalue().strip())

        with cvelib.testutil.capturedOutput() as (output, error):
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
            with cvelib.testutil.capturedOutput() as (output, error):
                cvelib.report._printGHAlertsSummary(
                    "valid-org", "valid-repo", [], "invalid"
                )
            self.assertEqual("", output.getvalue().strip())
            exp = "ERROR: Unsupported alert status: invalid"
            self.assertEqual(exp, error.getvalue().strip())

    #
    # getGHAlertsReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsAllFull)
    def test_getGHAlertsReport(self, _):  # 2nd arg is mock_get
        """Test getGHAlertsReport()"""
        self.maxDiff = 16384

        # with_templates = false
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsReport(
                [], "valid-org", repos=["valid-repo"], with_templates=True
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

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
Discovered-by: gh-dependabot
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

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
Discovered-by: gh-dependabot
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
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

Since a 'medium' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
Discovered-by: gh-dependabot
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

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
Discovered-by: gh-dependabot
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
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

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
Discovered-by: gh-dependabot
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

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
Discovered-by: gh-dependabot
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
        with cvelib.testutil.capturedOutput() as (output, error):
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
        alerts = [
            {
                "alert_type": "dependabot",
                "created": "2022-07-01T18:27:30Z",
                "dependabot_manifest_path": "a/b/c",
                "dependabot_package_name": "foo",
                "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/1",
                "security_advisory_ghsa_url": "https://github.com/advisories/GHSA-bbb",
                "severity": "medium",
            },
            {
                "alert_type": "dependabot",
                "created": "2022-07-02T18:27:30Z",
                "dependabot_manifest_path": "a/b/c",
                "dependabot_package_name": "foo",
                "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/2",
                "security_advisory_ghsa_url": "https://github.com/advisories/GHSA-aaa",
                "severity": "high",
            },
            {
                "alert_type": "dependabot",
                "created": "2022-07-03T18:27:30Z",
                "dependabot_manifest_path": "d/e/f",
                "dependabot_package_name": "foo",
                "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/3",
                "security_advisory_ghsa_url": "https://github.com/advisories/GHSA-bbb",
                "severity": "medium",
            },
        ]
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsTemplates("valid-org", "valid-repo", alerts)
        self.assertEqual("", error.getvalue().strip())
        now: datetime.datetime = datetime.datetime.now()
        exp = """## valid-repo template
Please address alerts (dependabot) in valid-repo

The following alerts were issued:
- [ ] [foo](https://github.com/valid-org/valid-repo/security/dependabot/1) (medium)
- [ ] [foo](https://github.com/valid-org/valid-repo/security/dependabot/2) (high)
- [ ] [foo](https://github.com/valid-org/valid-repo/security/dependabot/3) (medium)

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
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
 https://github.com/valid-org/valid-repo/security/dependabot/2
 https://github.com/valid-org/valid-repo/security/dependabot/3
 https://github.com/advisories/GHSA-aaa (foo)
 https://github.com/advisories/GHSA-bbb (foo)
Description:
 Please address alerts in valid-repo
 - [ ] foo (high)
 - [ ] foo (2 medium)
GitHub-Advanced-Security:
 - type: dependabot
   dependency: foo
   detectedIn: a/b/c
   severity: medium
   advisory: https://github.com/advisories/GHSA-bbb
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/1
 - type: dependabot
   dependency: foo
   detectedIn: a/b/c
   severity: high
   advisory: https://github.com/advisories/GHSA-aaa
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/2
 - type: dependabot
   dependency: foo
   detectedIn: d/e/f
   severity: medium
   advisory: https://github.com/advisories/GHSA-bbb
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/3
Notes:
Mitigation:
Bugs:
Priority: high
Discovered-by: gh-dependabot
Assigned-to:
CVSS:

Patches_valid-repo:
git/valid-org_valid-repo: needs-triage
## end CVE template""" % (
            "%d" % (now.year),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
        )
        self.assertEqual(exp, output.getvalue().strip())

    #
    # getHumanSummary()
    #
    def test_getHumanSummary(self):
        """Test getHumanSummary()"""
        # empty cve list
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                [], "", report_output=cvelib.report.ReportOutput.OPEN
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
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        # mock some data by calling collectCVEData() like bin/cve-report
        cveDirs = self._mock_cve_data_mixed()
        cves = cvelib.cve.collectCVEData(
            cveDirs, False, filter_status="needs-triage,needed,pending,released"
        )

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (gh-dependabot, gh-secrets)
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

        with cvelib.testutil.capturedOutput() as (output, error):
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

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, pkg_fn, report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (gh-dependabot, gh-secrets)
low        bar                            CVE-2022-0002

Totals:
- critical: 0 in 0 repos
- high: 1 in 1 repos
- medium: 0 in 0 repos
- low: 1 in 1 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with cvelib.testutil.capturedOutput() as (output, error):
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

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (gh-dependabot, gh-secrets)
medium     foo                            CVE-2022-GH1#foo          (limit-report)

Totals:
- critical: 0 in 0 repos
- high: 1 in 1 repos
- medium: 1 in 1 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with cvelib.testutil.capturedOutput() as (output, error):
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

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (gh-dependabot, gh-secrets)

Totals:
- critical: 0 in 0 repos
- high: 1 in 1 repos
- medium: 0 in 0 repos
- low: 0 in 0 repos
- negligible: 0 in 0 repos"""
        self.assertEqual(exp, output.getvalue().strip())

        with cvelib.testutil.capturedOutput() as (output, error):
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

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getHumanSummary(
                cves, "", report_output=cvelib.report.ReportOutput.OPEN
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """# Open

Priority   Repository                     Issue
--------   ----------                     -----
high       bar                            CVE-2022-GH2#bar          (gh-dependabot, gh-secrets)
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

        with cvelib.testutil.capturedOutput() as (output, error):
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
        with cvelib.testutil.capturedOutput() as (output, error):
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

        with cvelib.testutil.capturedOutput() as (output, error):
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
