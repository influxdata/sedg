"""test_report.py: tests for report.py module"""

from unittest import TestCase, mock
import copy
import datetime
import os

import cvelib.cve
import cvelib.github
import cvelib.report
import cvelib.testutil


def mocked_requests_get__getGHReposAll(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

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
    #       "topics": [
    #         "<topic1>",
    #         "<topic2>"
    #       ],
    #       ...
    #     },
    #     ...
    #   ]
    #
    # but _getGHReposAll() only cares about "name". We mock up a subset of the
    # GitHub response.
    #
    # _getGHReposAll() iterates through page=N parameters until it gets an
    # empty response. Mock that by putting two repos in page=1, one in page=2
    # and none in page=3.
    if args[0] == "https://api.github.com/orgs/valid-org/repos":
        if "page" not in kwargs["params"] or kwargs["params"]["page"] == 1:
            return MockResponse(
                [
                    {
                        "archived": False,
                        "name": "foo",
                        "id": 1000,
                        "license": {"key": "mit"},
                        "mirror_url": False,
                        "topics": ["topic1", "topic2"],
                    },
                    {
                        "archived": True,
                        "name": "bar",
                        "id": 1001,
                        "license": {"key": "mit"},
                        "mirror_url": False,
                        "topics": ["topic2"],
                    },
                ],
                200,
            )
        elif kwargs["params"]["page"] == 2:
            return MockResponse(
                [
                    {
                        "archived": False,
                        "name": "baz",
                        "id": 1002,
                        "license": {"key": "mit"},
                        "mirror_url": False,
                        "topics": ["topic1"],
                    },
                ],
                200,
            )
        else:
            return MockResponse([], 200)

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
    # _getGHIssuesForRepo() iterates through page=N parameters until it gets an
    # empty response. Mock that by putting two repos in page=1, one in page=2
    # and none in page=3.
    # The GitHub json for https://api.github.com/repos/ORG/REPO/issues is:
    if args[0] == "https://api.github.com/repos/valid-org/410-repo/issues":
        return MockResponse(None, 410)
    elif args[0] == "https://api.github.com/repos/valid-org/404-repo/issues":
        return MockResponse(None, 404)
    elif args[0] == "https://api.github.com/repos/valid-org/400-repo/issues":
        return MockResponse(None, 400)
    elif args[0] == "https://api.github.com/repos/valid-org/empty-repo/issues":
        return MockResponse([], 200)
    elif args[0] == "https://api.github.com/repos/valid-org/valid-repo/issues":
        if "labels" in kwargs["params"] and kwargs["params"]["labels"] == "label1":
            # return things with only 'label1'
            if "page" not in kwargs["params"] or kwargs["params"]["page"] == 1:
                return MockResponse(
                    [
                        {
                            "html_url": "https://github.com/valid-org/valid-repo/issues/1",
                            "labels": [{"name": "label1", "id": 2001}],
                            "locked": False,
                            "id": 1001,
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
                            "id": 1000,
                            "state_reason": None,
                            "user": {"login": "user1", "id": 3000},
                            "updated_at": "2022-07-03T18:27:30Z",
                        },
                    ],
                    200,
                )
            else:
                return MockResponse([], 200)
        elif "page" not in kwargs["params"] or kwargs["params"]["page"] == 1:
            return MockResponse(
                [
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/1",
                        "labels": [{"name": "label1", "id": 2001}],
                        "locked": False,
                        "id": 1001,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-01T18:27:30Z",
                    },
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/2",
                        "labels": [{"name": "label2", "id": 2002}],
                        "locked": False,
                        "id": 1002,
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
                        "id": 1000,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-03T18:27:30Z",
                    },
                ],
                200,
            )
        elif kwargs["params"]["page"] == 2:
            return MockResponse(
                [
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/4",
                        "labels": [],
                        "locked": False,
                        "id": 1000,
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-04T18:27:30Z",
                    },
                    {
                        "html_url": "https://github.com/valid-org/valid-repo/issues/5",
                        "labels": [],
                        "locked": False,
                        "id": 1000,
                        "pull_request": {"url": "..."},
                        "state_reason": None,
                        "user": {"login": "user1", "id": 3000},
                        "updated_at": "2022-07-05T18:27:30Z",
                    },
                ],
                200,
            )
        else:
            return MockResponse([], 200)

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def mocked_requests_get__getGHIssue(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    # https://docs.github.com/en/rest/issues/issues#get-an-issue
    # The GitHub json for https://api.github.com/repos/ORG/REPO/issues/NUM is:
    #   {
    #     "url": "<url>",
    #     "html_url": "<url>",
    #     ...
    #     "id": N,
    #     ...
    #     "user": {
    #       "login": "<user>",
    #       ...
    #     },
    #     ...
    #     "labels": [
    #       {"id": N, "name": "<name>", ... }
    #     ],
    #     ...
    #     "locked": False,
    #     ...
    #     "pull_requests": { ... },  // optional
    #     ...
    #     "state_reason": None
    #     ...
    #     "updated_at": "2022-07-08T18:27:30Z"
    #   }
    #
    # but consumers of _getGHIssue() only care about this from the GitHub
    # response:
    #   {
    #     "updated_at": "<time>"
    #   }
    #
    if args[0] == "https://api.github.com/repos/valid-org/410-repo/issues/1":
        return MockResponse(None, 410)
    elif args[0] == "https://api.github.com/repos/valid-org/404-repo/issues/1":
        return MockResponse(None, 404)
    elif args[0] == "https://api.github.com/repos/valid-org/400-repo/issues/1":
        return MockResponse(None, 400)
    elif args[0] == "https://api.github.com/repos/valid-org/valid-repo/issues/1":
        return MockResponse(
            {
                "html_url": "https://github.com/valid-org/valid-repo/issues/1",
                "labels": [{"name": "label1", "id": 2001}],
                "locked": False,
                "id": 1001,
                "state_reason": None,
                "user": {"login": "user1", "id": 3000},
                "updated_at": "2022-07-01T18:27:30Z",
            },
            200,
        )
    elif args[0] == "https://api.github.com/repos/valid-org/valid-repo/issues/2":
        return MockResponse(
            {
                "html_url": "https://github.com/valid-org/valid-repo/issues/2",
                "labels": [{"name": "label2", "id": 2002}],
                "locked": False,
                "id": 1002,
                "state_reason": None,
                "user": {"login": "user1", "id": 3000},
                "updated_at": "2022-07-02T18:27:30Z",
            },
            200,
        )
    elif args[0] == "https://api.github.com/repos/valid-org/valid-repo/issues/3":
        return MockResponse(
            {
                "html_url": "https://github.com/valid-org/valid-repo/issues/3",
                "labels": [
                    {"name": "label1", "id": 2001},
                    {"name": "label2", "id": 2002},
                ],
                "locked": False,
                "id": 1000,
                "state_reason": None,
                "user": {"login": "user1", "id": 3000},
                "updated_at": "2022-07-03T18:27:30Z",
            },
            200,
        )
    elif args[0] == "https://api.github.com/repos/valid-org/valid-repo/issues/4":
        return MockResponse(
            {
                "html_url": "https://github.com/valid-org/valid-repo/issues/4",
                "labels": [],
                "locked": False,
                "id": 1000,
                "state_reason": None,
                "user": {"login": "user1", "id": 3000},
                "updated_at": "2022-07-04T18:27:30Z",
            },
            200,
        )
    elif args[0] == "https://api.github.com/repos/valid-org/valid-repo/issues/5":
        return MockResponse(
            {
                "html_url": "https://github.com/valid-org/valid-repo/issues/5",
                "labels": [],
                "locked": False,
                "id": 1000,
                "pull_request": {"url": "..."},
                "state_reason": None,
                "user": {"login": "user1", "id": 3000},
                "updated_at": "2022-07-05T18:27:30Z",
            },
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

        def json(self):
            return self.json_data

    # https://docs.github.com/en/rest/issues/issues#get-an-issue
    # The GitHub json for https://api.github.com/repos/ORG/REPO/issues/NUM is:

    if (
        args[0]
        == "https://api.github.com/repos/valid-org/valid-repo/vulnerability-alerts"
    ):
        return MockResponse(None, 204)
    elif (
        args[0]
        == "https://api.github.com/repos/valid-org/disabled-repo/vulnerability-alerts"
    ):
        return MockResponse(None, 404)

    # catch-all
    print(
        "DEBUG: should be unreachable: args='%s', kwargs='%s'" % (args, kwargs)
    )  # pragma: nocover
    assert False  # pragma: nocover


def mocked_requests_post_getGHAlertsUpdatedReport(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    if (
        "json" in kwargs
        and "query" in kwargs["json"]
        and "vulnerabilityAlerts" in kwargs["json"]["query"]
    ):
        return MockResponse(
            {
                "data": {
                    "repository": {
                        "vulnerabilityAlerts": {
                            "nodes": [
                                {
                                    "createdAt": "2022-07-01T18:27:30Z",
                                    "dismissedAt": "2022-07-02T18:27:30Z",
                                    "dismissReason": "tolerable",
                                    "dismisser": {
                                        "name": "ghuser1",
                                    },
                                    "number": 1,
                                    "securityVulnerability": {
                                        "package": {
                                            "name": "github.com/foo/bar",
                                        },
                                        "severity": "low",
                                    },
                                    "vulnerableManifestPath": "go.sum",
                                    "securityAdvisory": {
                                        "permalink": "https://github.com/advisories/GHSA-a",
                                    },
                                },
                                {
                                    "createdAt": "2022-07-03T18:27:30Z",
                                    "dismissedAt": None,
                                    "number": 3,
                                    "securityVulnerability": {
                                        "package": {
                                            "name": "baz",
                                        },
                                        "severity": "moderate",
                                    },
                                    "vulnerableManifestPath": "path/yarn.lock",
                                    "securityAdvisory": {
                                        "permalink": "https://github.com/advisories/GHSA-b",
                                    },
                                },
                                {
                                    "createdAt": "2022-07-04T18:27:30Z",
                                    "dismissedAt": None,
                                    "number": 4,
                                    "securityVulnerability": {
                                        "package": {
                                            "name": "baz",
                                        },
                                        "severity": "moderate",
                                    },
                                    "vulnerableManifestPath": "path/yarn.lock",
                                    "securityAdvisory": {
                                        "permalink": "https://github.com/advisories/GHSA-c",
                                    },
                                },
                                {
                                    "createdAt": "2022-07-05T18:27:30Z",
                                    "dismissedAt": None,
                                    "number": 5,
                                    "securityVulnerability": {
                                        "package": {
                                            "name": "norf",
                                        },
                                        "severity": "unknown",
                                    },
                                    "vulnerableManifestPath": "path/yarn.lock",
                                    "securityAdvisory": {
                                        "permalink": "https://github.com/advisories/GHSA-d",
                                    },
                                },
                            ],
                            "pageInfo": {
                                "startCursor": 1,
                                "endCursor": 1,
                                "hasNextPage": False,
                            },
                        },
                    },
                },
            },
            200,
        )

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

        if "GHTOKEN" in os.environ:
            self.orig_ghtoken = os.getenv("GHTOKEN")
        os.environ["GHTOKEN"] = "fake-test-token"
        os.environ["TEST_NO_UPDATE_PROGRESS"] = "1"

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.orig_ghtoken is not None:
            os.environ["GHTOKEN"] = self.orig_ghtoken
            self.orig_ghtoken = None

        # TODO: when pass these around, can remove this
        cvelib.report.repos_all = []
        cvelib.report.issues_all = {}
        cvelib.report.issues_ind = {}

    def _cve_template(self, cand="", references=[]):
        """Generate a valid CVE to mimic what readCve() might see"""
        d = {
            "Candidate": cand,
            "OpenDate": "2020-06-29",
            "PublicDate": "",
            "References": "\n %s" % " \n".join(references),
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

    def _mock_cve_list(self):
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

    #
    # _getGHReposAll() tests
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHReposAll)
    def test__getGHReposAll(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHReposAll()"""
        r = cvelib.report._getGHReposAll("valid-org")
        self.assertEqual(3, len(r))
        self.assertTrue("foo" in r)
        self.assertTrue("bar" in r)
        self.assertTrue("baz" in r)

        # do it a second time to use repos_all
        r = cvelib.report._getGHReposAll("valid-org")
        self.assertEqual(3, len(r))
        self.assertTrue("foo" in r)
        self.assertTrue("bar" in r)
        self.assertTrue("baz" in r)

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

        # do it a second time to use issues_all
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

        # do it a second time to use issues_all
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
    # _getGHIssue() tests
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssue)
    def test__getGHIssue(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssuesForRepo() - empty repo"""
        r = cvelib.report._getGHIssue("valid-repo", "valid-org", 1)
        self.assertTrue("html_url" in r)
        self.assertEqual(
            "https://github.com/valid-org/valid-repo/issues/1", r["html_url"]
        )

        # do it a second time to use issue_ind
        r = cvelib.report._getGHIssue("valid-repo", "valid-org", 1)
        self.assertTrue("html_url" in r)
        self.assertEqual(
            "https://github.com/valid-org/valid-repo/issues/1", r["html_url"]
        )

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssue)
    def test__getGHIssue410(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssue() - 410 status"""
        r = cvelib.report._getGHIssue("410-repo", "valid-org", 1)
        self.assertEqual(0, len(r))

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssue)
    def test__getGHIssue404(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssue() - 404 status"""
        r = cvelib.report._getGHIssue("404-repo", "valid-org", 1)
        self.assertEqual(0, len(r))

    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssue)
    def test__getGHIssue400(self, _):  # 2nd arg is 'mock_get'
        """Test _getGHIssue() - 400 status"""
        r = cvelib.report._getGHIssue("400-repo", "valid-org", 1)
        self.assertEqual(0, len(r))

    #
    # _getKnownIssues()
    #
    def test__getKnownIssues(self):
        """Test _getKnownIssues()"""
        res = cvelib.report._getKnownIssues(self._mock_cve_list())
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
        cves = self._mock_cve_list()
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getMissingReport(cves, "valid-org", repos=["valid-repo"])
        self.assertEqual("", error.getvalue().strip())
        exp = """Fetching list of issues for:
 valid-org/valid-repo: ... done!
Issues missing from CVE data:
 https://github.com/valid-org/valid-repo/issues/4"""
        self.assertEqual(exp, output.getvalue().strip())

        # excluded
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getMissingReport(
                cves, "valid-org", repos=["valid-repo"], excluded_repos=["valid-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Fetching list of issues for:
No missing issues for the specified repos."""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # _getGHAlertsEnabled()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsEnabled)
    def test_getGHAlertsEnabled(self, _):  # 2nd arg is mock_get
        """Test _getGHAlertsEnabled()"""
        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org", repos=["valid-repo", "disabled-repo"]
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(1, len(disabled))
        self.assertTrue("disabled-repo" in disabled)

        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org",
            repos=["valid-repo", "disabled-repo"],
            excluded_repos=["disabled-repo"],
        )
        self.assertEqual(1, len(enabled))
        self.assertTrue("valid-repo" in enabled)
        self.assertEqual(0, len(disabled))

        enabled, disabled = cvelib.report._getGHAlertsEnabled(
            "valid-org",
            repos=["valid-repo", "disabled-repo"],
            excluded_repos=["valid-repo"],
        )
        self.assertEqual(0, len(enabled))
        self.assertEqual(1, len(disabled))
        self.assertTrue("disabled-repo" in disabled)

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
        exp = """Enabled:
 valid-repo
Disabled:
 disabled-repo"""
        self.assertEqual(exp, output.getvalue().strip())

    #
    # getUpdatedReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHIssue)
    def test_getUpdatedReport(self, _):  # 2nd arg is mock_get
        """Test _getUpdatedReport()"""
        cves = self._mock_cve_list()

        # all updated since
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org")
        self.assertEqual("", error.getvalue().strip())
        exp = """Updated issues:
 https://github.com/valid-org/valid-repo/issues/1 (CVE-2022-GH1001#valid-repo)
 https://github.com/valid-org/valid-repo/issues/2 (CVE-2022-GH1002#valid-repo)
 https://github.com/valid-org/valid-repo/issues/3 (CVE-2022-GH1003#valid-repo)"""
        self.assertEqual(exp, output.getvalue().strip())

        # some updated since 1656792271 (2022-07-02) (with pre-fetched)
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org", since=1656792271)
        self.assertEqual("", error.getvalue().strip())
        exp = """Using previously fetched issue for valid-repo/1
Using previously fetched issue for valid-repo/2
Using previously fetched issue for valid-repo/3
Updated issues:
 https://github.com/valid-org/valid-repo/issues/3 (CVE-2022-GH1003#valid-repo)"""
        self.assertEqual(exp, output.getvalue().strip())

        # none updated since 1657224398 (2022-07-07) (with pre-fetched)
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getUpdatedReport(cves, "valid-org", since=1657224398)
        self.assertEqual("", error.getvalue().strip())
        exp = """Using previously fetched issue for valid-repo/1
Using previously fetched issue for valid-repo/2
Using previously fetched issue for valid-repo/3
No updated issues for the specified repos."""
        self.assertEqual(exp, output.getvalue().strip())

        # error
        with self.assertRaises(ValueError):
            cvelib.report.getUpdatedReport(cves, "valid-org", since=-1)

    #
    # _printGHAlertsUpdatedSummary()
    #
    def test__printGHAlertsUpdatedSummary(self):
        """Test _printGHAlertsUpdatedSummary()"""
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report._printGHAlertsUpdatedSummary("valid-org", "valid-repo", [])
        self.assertEqual("", error.getvalue().strip())
        exp = "valid-repo alerts: 0 (https://github.com/valid-org/valid-repo/security/dependabot)"
        self.assertEqual(exp, output.getvalue().strip())

    #
    # getGHAlertsUpdatedReport()
    #
    @mock.patch("requests.get", side_effect=mocked_requests_get__getGHAlertsEnabled)
    @mock.patch(
        "requests.post", side_effect=mocked_requests_post_getGHAlertsUpdatedReport
    )
    def test_getGHAlertsUpdatedReport(self, _, __):  # 2nd arg is mock_post and args
        """Test getGHAlertsUpdatedReport()"""
        self.maxDiff = 8192

        # with_templates = false
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsUpdatedReport(
                [], "valid-org", repos=["valid-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Vulnerability alerts:
valid-repo alerts: 3 (https://github.com/valid-org/valid-repo/security/dependabot)
  baz
    - severity: moderate
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: moderate
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  norf
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

Dismissed vulnerability alerts:

valid-repo dismissed alerts: 1 (https://github.com/valid-org/valid-repo/security/dependabot)
  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1"""
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
            cvelib.report.getGHAlertsUpdatedReport(
                cves, "valid-org", repos=["valid-repo"]
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Vulnerability alerts:
valid-repo alerts: 3 (https://github.com/valid-org/valid-repo/security/dependabot)
  baz
    - severity: moderate
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: moderate
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  norf
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

Dismissed vulnerability alerts:

valid-repo dismissed alerts: 1 (https://github.com/valid-org/valid-repo/security/dependabot)
  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1"""
        self.assertEqual(exp, output.getvalue().strip())

        # with_templates = true
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsUpdatedReport(
                [], "valid-org", repos=["valid-repo"], with_templates=True
            )
        self.assertEqual("", error.getvalue().strip())

        now: datetime.datetime = datetime.datetime.now()
        exp = """Vulnerability alerts:
## valid-repo template
Please update dependabot flagged dependencies in valid-repo

https://github.com/valid-org/valid-repo/security/dependabot lists the following updates:
- [ ] [baz](https://github.com/valid-org/valid-repo/security/dependabot/3) (moderate)
- [ ] [baz](https://github.com/valid-org/valid-repo/security/dependabot/4) (moderate)
- [ ] [norf](https://github.com/valid-org/valid-repo/security/dependabot/5) (unknown)

Since a 'moderate' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers

## end template

## valid-repo CVE template
Candidate: CVE-2022-NNNN
OpenDate: %s
PublicDate: %s
CRD:
References:
 https://github.com/valid-org/valid-repo/security/dependabot/3
 https://github.com/valid-org/valid-repo/security/dependabot/4
 https://github.com/valid-org/valid-repo/security/dependabot/5
 https://github.com/advisories/GHSA-b (baz)
 https://github.com/advisories/GHSA-c (baz)
 https://github.com/advisories/GHSA-d (norf)
Description:
 Please update dependabot flagged dependencies in valid-repo
 - [ ] baz (2 moderate)
 - [ ] norf (unknown)
GitHub-Advanced-Security:
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   severity: moderate
   advisory: https://github.com/advisories/GHSA-b
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/3
 - type: dependabot
   dependency: baz
   detectedIn: path/yarn.lock
   severity: moderate
   advisory: https://github.com/advisories/GHSA-c
   status: needs-triage
   url: https://github.com/valid-org/valid-repo/security/dependabot/4
 - type: dependabot
   dependency: norf
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

valid-repo alerts: 3 (https://github.com/valid-org/valid-repo/security/dependabot)
  baz
    - severity: moderate
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: moderate
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  norf
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5

Dismissed vulnerability alerts:

## valid-repo template
Please update dependabot flagged dependencies in valid-repo

https://github.com/valid-org/valid-repo/security/dependabot lists the following updates:
- [ ] [github.com/foo/bar](https://github.com/valid-org/valid-repo/security/dependabot/1) (low)

Since a 'low' severity issue is present, tentatively adding the 'security/low' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers

## end template

## valid-repo CVE template
Candidate: CVE-2022-NNNN
OpenDate: %s
PublicDate: %s
CRD:
References:
 https://github.com/valid-org/valid-repo/security/dependabot/1
 https://github.com/advisories/GHSA-a (github.com/foo/bar)
Description:
 Please update dependabot flagged dependencies in valid-repo
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

valid-repo dismissed alerts: 1 (https://github.com/valid-org/valid-repo/security/dependabot)
  github.com/foo/bar
    - severity: low
    - created: 2022-07-01T18:27:30Z
    - dismissed: 2022-07-02T18:27:30Z
    - reason: tolerable
    - by: ghuser1
    - go.sum
    - advisory: https://github.com/advisories/GHSA-a
    - url: https://github.com/valid-org/valid-repo/security/dependabot/1""" % (
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
        )
        self.assertEqual(exp, output.getvalue().strip())

        # some updated since 1656792271 (2022-07-02)
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsUpdatedReport(
                [], "valid-org", repos=["valid-repo"], since=1656792271
            )
        self.assertEqual("", error.getvalue().strip())
        exp = """Vulnerability alerts:
valid-repo alerts: 3 (https://github.com/valid-org/valid-repo/security/dependabot)
  baz
    - severity: moderate
    - created: 2022-07-03T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-b
    - url: https://github.com/valid-org/valid-repo/security/dependabot/3

  baz
    - severity: moderate
    - created: 2022-07-04T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-c
    - url: https://github.com/valid-org/valid-repo/security/dependabot/4

  norf
    - severity: unknown
    - created: 2022-07-05T18:27:30Z
    - path/yarn.lock
    - advisory: https://github.com/advisories/GHSA-d
    - url: https://github.com/valid-org/valid-repo/security/dependabot/5"""
        self.assertEqual(exp, output.getvalue().strip())

        # none updated since 1657224398 (2022-07-07) (with pre-fetched)
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.report.getGHAlertsUpdatedReport(
                [], "valid-org", repos=["valid-repo"], since=1657224398
            )
        self.assertEqual("", error.getvalue().strip())
        exp = "No vulnerability alerts for the specified repos."
        self.assertEqual(exp, output.getvalue().strip())

        # error
        with self.assertRaises(ValueError):
            cvelib.report.getGHAlertsUpdatedReport(
                [], "valid-org", repos=["valid-repo"], since=-1
            )
