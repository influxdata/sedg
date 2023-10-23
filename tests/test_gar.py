"""test_gar.py: tests for gar.py module"""
#
# SPDX-License-Identifier: MIT

import datetime
import json
import os
import tempfile
from typing import Any, Dict
from unittest import TestCase, mock

import cvelib.common
import cvelib.gar
import cvelib.scan
import tests.testutil


class TestGAR(TestCase):
    """Tests for the gar functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        self.orig_gar_token = None
        self.tmpdir = None

        if "GCLOUD_TOKEN" in os.environ:
            self.orig_ghtoken = os.getenv("GCLOUD_TOKEN")
        os.environ["GCLOUD_TOKEN"] = "fake-test-token"

        tests.testutil.disableRequestsCache()

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.tmpdir is not None:
            cvelib.common.recursive_rm(self.tmpdir)

    def test__createGARHeaders(self):
        """Test _createGARHeaders()"""
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with tests.testutil.capturedOutput() as (output, error):
                res = cvelib.gar._createGARHeaders()
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual("", error.getvalue().strip())

            # test cookie
            exp = {"Authorization": "Bearer fake-test-token"}
            self.assertDictEqual(exp, res)

            # error
            del os.environ["GCLOUD_TOKEN"]
            with tests.testutil.capturedOutput() as (output, error):
                res = cvelib.gar._createGARHeaders()
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual(
                "ERROR: Please export GCLOUD_TOKEN (eg: export GCLOUD_TOKEN=$(gcloud auth print-access-token))",
                error.getvalue().strip(),
            )

    def _validGARReport(self):
        """Return a valid gar report as python object"""
        s = """
{
  "occurrences": [
    {
      "name": "projects/valid-proj/occurrences/95f969f5-48e0-4183-85eb-311c0cf1949d",
      "resourceUri": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:3fa5256ad34b31901ca30021c722fc7ba11a66ca070c8442862205696b908ddb",
      "noteName": "projects/goog-vulnz/notes/CVE-2022-29458",
      "kind": "VULNERABILITY",
      "createTime": "2023-03-15T14:49:29.339644Z",
      "updateTime": "2023-04-29T12:44:44.093997Z",
      "vulnerability": {
        "severity": "HIGH",
        "cvssScore": 7.1,
        "packageIssue": [
          {
            "affectedCpeUri": "cpe:/o:debian:debian_linux:11",
            "affectedPackage": "ncurses",
            "affectedVersion": {
              "name": "6.2+20201114",
              "revision": "2",
              "kind": "NORMAL",
              "fullName": "6.2+20201114-2"
            },
            "fixedCpeUri": "cpe:/o:debian:debian_linux:11",
            "fixedPackage": "ncurses",
            "fixedVersion": {
              "name": "6.2+20201114",
              "revision": "2+deb11u1",
              "kind": "NORMAL",
              "fullName": "6.2+20201114-2+deb11u1"
            },
            "fixAvailable": true,
            "packageType": "OS",
            "effectiveSeverity": "MEDIUM"
          }
        ],
        "shortDescription": "CVE-2022-29458",
        "longDescription": "NIST vectors: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H",
        "relatedUrls": [
          {
            "url": "https://security-tracker.debian.org/tracker/CVE-2022-29458",
            "label": "More Info"
          }
        ],
        "effectiveSeverity": "MEDIUM",
        "fixAvailable": true,
        "cvssv3": {
          "baseScore": 7.1,
          "exploitabilityScore": 1.8,
          "impactScore": 5.2,
          "attackVector": "ATTACK_VECTOR_LOCAL",
          "attackComplexity": "ATTACK_COMPLEXITY_LOW",
          "privilegesRequired": "PRIVILEGES_REQUIRED_NONE",
          "userInteraction": "USER_INTERACTION_REQUIRED",
          "scope": "SCOPE_UNCHANGED",
          "confidentialityImpact": "IMPACT_HIGH",
          "integrityImpact": "IMPACT_NONE",
          "availabilityImpact": "IMPACT_HIGH"
        },
        "cvssVersion": "CVSS_VERSION_3",
        "cvssV2": {
          "baseScore": 5.8,
          "attackVector": "ATTACK_VECTOR_NETWORK",
          "attackComplexity": "ATTACK_COMPLEXITY_MEDIUM",
          "authentication": "AUTHENTICATION_NONE",
          "confidentialityImpact": "IMPACT_PARTIAL",
          "integrityImpact": "IMPACT_NONE",
          "availabilityImpact": "IMPACT_PARTIAL"
        }
      }
    }
  ]
}
"""
        return json.loads(s)

    def test_parse(self):
        """Test parse()"""
        d = self._validGARReport()
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("os/debian:ncurses", res[0].component)
        self.assertEqual("cpe:/o:debian:debian_linux:11", res[0].detectedIn)
        self.assertEqual(
            "https://www.cve.org/CVERecord?id=CVE-2022-29458",
            res[0].advisory,
        )
        self.assertEqual("6.2+20201114-2", res[0].versionAffected)
        self.assertEqual("6.2+20201114-2+deb11u1", res[0].versionFixed)
        self.assertEqual("medium", res[0].severity)
        self.assertEqual("needed", res[0].status)
        self.assertEqual(
            "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:3fa5256ad34b31901ca30021c722fc7ba11a66ca070c8442862205696b908ddb",
            res[0].url,
        )

        # needs-triage
        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fixedVersion"][
            "fullName"
        ]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("needs-triage", res[0].status)
        self.assertEqual("unknown", res[0].versionFixed)

        # released
        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fixedVersion"][
            "fullName"
        ] = d["occurrences"][0]["vulnerability"]["packageIssue"][0]["affectedVersion"][
            "fullName"
        ]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("released", res[0].status)

        # version
        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]["packageIssue"][0]["affectedVersion"]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual("unknown", res[0].versionAffected)

        # detectedIn - GO
        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["packageType"] = "GO"
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fileLocation"] = [
            {"filePath": "/first"},
            {"filePath": "/second"},
        ]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("/first", res[0].detectedIn)

        # detectedIn - GO_STDLIB
        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"][0][
            "packageType"
        ] = "GO_STDLIB"
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fileLocation"] = [
            {"filePath": "/first"},
            {"filePath": "/second"},
        ]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("/first", res[0].detectedIn)

        # detectedIn - MAVEN
        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["packageType"] = "MAVEN"
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fileLocation"] = [
            {"filePath": "/first"},
            {"filePath": "/second"},
        ]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("/first", res[0].detectedIn)

        # detectedIn - NPM
        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["packageType"] = "NPM"
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fileLocation"] = [
            {"filePath": "/first"},
            {"filePath": "/second"},
        ]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("/first", res[0].detectedIn)

        # detectedIn - PYPI
        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["packageType"] = "PYPI"
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fileLocation"] = [
            {"filePath": "/first"},
            {"filePath": "/second"},
        ]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("/first", res[0].detectedIn)

        # severity
        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]["packageIssue"][0]["effectiveSeverity"]
        d["occurrences"][0]["vulnerability"]["effectiveSeverity"] = "low"
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("low", res[0].severity)

        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]["packageIssue"][0]["effectiveSeverity"]
        del d["occurrences"][0]["vulnerability"]["effectiveSeverity"]
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("high", res[0].severity)

        # advisory
        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["shortDescription"] = ""
        res = cvelib.gar.parse(d["occurrences"])
        self.assertEqual(1, len(res))
        self.assertEqual("unavailable", res[0].advisory)

    def test_parse_bad(self):
        """Test parse() - bad"""
        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.parse(d["occurrences"])
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'vulnerability' in" in error.getvalue().strip())

        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]["packageIssue"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.parse(d["occurrences"])
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'packageIssue' in" in error.getvalue().strip())

        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"] = []
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.parse(d["occurrences"])
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("'packageIssue' is empty in" in error.getvalue().strip())

        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"][0]["packageType"] = "BAD"
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.parse(d["occurrences"])
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("unrecognized packageType 'BAD'" in error.getvalue().strip())

        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]["packageIssue"][0]["affectedPackage"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.parse(d["occurrences"])
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'affectedPackage' in" in error.getvalue().strip()
        )

    def _mock_response_for_gar(self, json_data, status=200):
        """Build a mocked requests response

        Example:

          @mock.patch('requests.get')
          def test_...(self, mock_get):
              mr = self._mock_response_for_gar({"foo": "bar"})
              mock_get.return_value = mr
              res = foo('good')
              self.assertEqual(res, "...")
        """
        # mock up a one page link for simplicity
        mr = mock.Mock()
        mr.status_code = status
        mr.json = mock.Mock(return_value=json_data)

        return mr

    def _validGARReposForProjectLoc(self) -> Dict[str, Any]:
        """Return valid gar v1/projects.locations.repositories/list as python object"""
        return {
            "repositories": [
                {
                    "name": "projects/valid-proj/locations/us/repositories/valid-repo",
                    "format": "DOCKER",
                    "description": "some description",
                    "labels": {
                        "environment": "blah",
                        "managed": "blah",
                        "owner": "some-team",
                    },
                    "createTime": "2022-09-08T09:37:11.523595Z",
                    "updateTime": "2023-03-15T15:05:30.392141Z",
                    "mode": "STANDARD_REPOSITORY",
                    "sizeBytes": "9210399480",
                }
            ]
        }

    @mock.patch("requests.get")
    def test_getReposForNamespace(self, mock_get):
        """Test getReposForNamespace()"""
        mr = self._mock_response_for_gar(self._validGARReposForProjectLoc())
        mock_get.return_value = mr
        gsr = cvelib.gar.GARSecurityReportNew()
        res = gsr.getReposForNamespace("valid-proj/us")
        self.assertEqual(1, len(res))
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo", res[0]
        )

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            gsr.getReposForNamespace("blah")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Please use PROJECT/LOCATION" in error.getvalue().strip())

        # bad status
        mr = self._mock_response_for_gar({}, status=401)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getReposForNamespace("valid-proj/us")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # bad response
        d = self._validGARReposForProjectLoc()
        del d["repositories"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getReposForNamespace("valid-proj/us")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'repositories' in response" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        d = self._validGARReposForProjectLoc()
        del d["repositories"][0]["name"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getReposForNamespace("valid-proj/us")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'name' in response for repo" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

    def _validGAROCIForRepo(self) -> Dict[str, Any]:
        """Return valid gar v1/projects.locations.repositories.packages as python object"""
        return {
            "packages": [
                {
                    "name": "projects/valid-proj/locations/us/repositories/valid-repo/packages/valid-name",
                    "createTime": "2023-04-11T15:07:35.322255Z",
                    "updateTime": "2023-04-11T15:07:35.322255Z",
                },
                {
                    "name": "projects/valid-proj/locations/us/repositories/valid-repo/packages/other-name",
                    "createTime": "2023-03-13T14:59:02.415743Z",
                    "updateTime": "2023-04-11T16:34:44.792867Z",
                },
            ]
        }

    @mock.patch("requests.get")
    def test_getGAROCIForRepo(self, mock_get):
        """Test getGAROCIForRepo()"""
        mr = self._mock_response_for_gar(self._validGAROCIForRepo())
        mock_get.return_value = mr
        res = cvelib.gar.getGAROCIForRepo("valid-proj/us/valid-repo")
        self.assertEqual(2, len(res))
        self.assertEqual("valid-name", res[0][0])
        self.assertEqual(
            int(
                datetime.datetime.strptime(
                    "2023-04-11T15:07:35.322255Z", "%Y-%m-%dT%H:%M:%S.%fZ"
                ).strftime("%s")
            ),
            res[0][1],
        )
        self.assertEqual("other-name", res[1][0])
        self.assertEqual(
            int(
                datetime.datetime.strptime(
                    "2023-04-11T16:34:44.792867Z", "%Y-%m-%dT%H:%M:%S.%fZ"
                ).strftime("%s")
            ),
            res[1][1],
        )

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.getGAROCIForRepo("valid-proj/us")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Please use PROJECT/LOCATION/REPO" in error.getvalue().strip())

        # bad status
        mr = self._mock_response_for_gar({}, status=401)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGAROCIForRepo("valid-proj/us/valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # bad response
        d = self._validGAROCIForRepo()
        del d["packages"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGAROCIForRepo("valid-proj/us/valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'packages' in response" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        d = self._validGAROCIForRepo()
        del d["packages"][0]["name"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        res = cvelib.gar.getGAROCIForRepo("valid-proj/us/valid-repo")
        self.assertEqual(1, len(res))
        self.assertEqual("other-name", res[0][0])
        self.assertEqual(
            int(
                datetime.datetime.strptime(
                    "2023-04-11T16:34:44.792867Z", "%Y-%m-%dT%H:%M:%S.%fZ"
                ).strftime("%s")
            ),
            res[0][1],
        )

    def _validGARDigestForImage(self) -> Dict[str, Any]:
        """Return valid gar v1/projects.locations.repositories.packages.versions as python object"""
        return {
            "versions": [
                {
                    "name": "projects/valid-proj/locations/us/repositories/valid-repo/packages/valid-name/versions/sha256:fbed39525f7c06f6b83c0e8da65f434c6dffba7b7f09917d5a8a31299ed12f0a",
                    "createTime": "2023-03-10T11:52:25.232897621Z",
                    "updateTime": "2023-03-10T11:52:30.111583Z",
                    "relatedTags": [],
                    "metadata": {
                        "imageSizeBytes": "26782679",
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "buildTime": "2023-03-10T11:52:25.232897621Z",
                        "name": "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fbed39525f7c06f6b83c0e8da65f434c6dffba7b7f09917d5a8a31299ed12f0a",
                    },
                },
                {
                    "name": "projects/valid-proj/locations/us/repositories/valid-repo/packages/valid-name/versions/sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
                    "createTime": "2023-03-08T13:42:27.277646198Z",
                    "updateTime": "2023-03-08T13:42:32.039631Z",
                    "relatedTags": [
                        {
                            "name": "projects/valid-proj/locations/us/repositories/valid-repo/packages/valid-name/tags/some-tag",
                            "version": "projects/valid-proj/locations/us/repositories/valid-repo/packages/valid-name/versions/sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
                        },
                    ],
                    "metadata": {
                        "imageSizeBytes": "26857843",
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "buildTime": "2023-03-08T13:42:27.277646198Z",
                        "name": "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
                    },
                },
            ]
        }

    @mock.patch("requests.get")
    def test_getDigestForImage(self, mock_get):
        """Test getDigestForImage()"""
        mr = self._mock_response_for_gar(self._validGARDigestForImage())
        mock_get.return_value = mr
        gsr = cvelib.gar.GARSecurityReportNew()
        res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fbed39525f7c06f6b83c0e8da65f434c6dffba7b7f09917d5a8a31299ed12f0a",
            res,
        )

        # search by sha256
        mr = self._mock_response_for_gar(self._validGARDigestForImage()["versions"][1])
        mock_get.return_value = mr
        res = gsr.getDigestForImage(
            "valid-proj/us/valid-repo/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a"
        )
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
            res,
        )

        # search by tag
        mr = self._mock_response_for_gar(self._validGARDigestForImage())
        mock_get.return_value = mr
        res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name:some-tag")
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
            res,
        )

        # bad mediaType
        d = self._validGARDigestForImage()
        d["versions"][0]["metadata"]["mediaType"] = "something-else"
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name:some-tag")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("mediaType 'something-else' not in" in error.getvalue().strip())
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
            res,
        )

        d = self._validGARDigestForImage()
        d["versions"][1]["metadata"]["mediaType"] = "something-else"
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name:some-tag")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("mediaType 'something-else' not in" in error.getvalue().strip())
        self.assertEqual("", res)

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            gsr.getDigestForImage("valid-proj")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Please use PROJECT/LOCATION/REPO/IMGNAME" in error.getvalue().strip()
        )

        # bad status
        mr = self._mock_response_for_gar({}, status=404)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # bad response
        d = self._validGARDigestForImage()
        del d["versions"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'versions' in response" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        # missing elements
        d = self._validGARDigestForImage()
        del d["versions"][0]["name"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'name' in" in error.getvalue().strip())
        self.assertEqual("", res)

        d = self._validGARDigestForImage()
        del d["versions"][0]["metadata"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'metadata' in" in error.getvalue().strip())
        self.assertEqual("", res)

        d = self._validGARDigestForImage()
        del d["versions"][0]["metadata"]["mediaType"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'mediaType' in 'metadata' in" in error.getvalue().strip()
        )
        self.assertEqual("", res)

        d = self._validGARDigestForImage()
        del d["versions"][0]["metadata"]["name"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'name' in 'metadata' in" in error.getvalue().strip()
        )
        self.assertEqual("", res)

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.gar.getGARDiscovery")
    @mock.patch("requests.get")
    def test_getDigestForImage_multiple_no_scan_results(
        self, mock_get, mock_getGARDiscovery
    ):
        """Test getDigestForImage() - multiple no scan results"""
        # valid gar v1/projects.locations.repositories.packages.versions as
        # python object
        v = {"versions": []}
        for i in range(11):
            v["versions"].append(
                {
                    "name": "projects/valid-proj/locations/us/repositories/valid-repo/packages/valid-name/versions/sha256:%0.2d"
                    % i,
                    "createTime": "2023-03-%0.2dT11:52:25.232897621Z" % i,
                    "updateTime": "2023-03-%0.2dT11:52:30.111583Z" % i,
                    "relatedTags": [],
                    "metadata": {
                        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                        "name": "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:%0.2d"
                        % i,
                    },
                }
            )

        # unscanned
        mr = self._mock_response_for_gar(v)
        mock_get.return_value = mr
        mock_getGARDiscovery.return_value = "UNSCANNED"

        gsr = cvelib.gar.GARSecurityReportNew()
        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find digest for valid-repo/valid-name with scan results for in 10 most recent images"
            in error.getvalue().strip()
        )
        self.assertEqual("", res)

        # stale
        mr = self._mock_response_for_gar(v)
        mock_get.return_value = mr
        mock_getGARDiscovery.return_value = "INACTIVE"

        with tests.testutil.capturedOutput() as (output, error):
            res = gsr.getDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find digest for valid-repo/valid-name with scan results for in 10 most recent images (images are stale)"
            in error.getvalue().strip()
        )
        self.assertEqual("", res)

    def test_parseImageDigest(self):
        """Test parseImageDigest"""
        tsts = [
            # project, location, repo, imgname, sha256, expErr
            (
                "valid-proj",
                "valid-loc",
                "valid-repo",
                "valid-img",
                "sha256:deadbeef",
                "",
            ),
            (
                "valid-proj",
                "valid-loc",
                "valid-repo",
                "valid-img",
                "bad",
                "does not contain '@sha256:",
            ),
            (
                "valid-proj",
                "valid-loc",
                "valid-repo",
                "valid-img",
                "@sha256:@",
                "should have 1 '@'",
            ),
            (
                "valid-proj",
                "valid-loc",
                "valid-repo",
                "valid-img/bad",
                "sha256:deadbeef",
                "should have 7 '/'",
            ),
        ]
        gsr = cvelib.gar.GARSecurityReportNew()
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            for proj, loc, repo, img, sha, expErr in tsts:
                digest = (
                    "projects/%s/locations/%s/repositories/%s/dockerImages/%s@%s"
                    % (proj, loc, repo, img, sha)
                )
                with tests.testutil.capturedOutput() as (output, error):
                    r1, r2, r3 = gsr.parseImageDigest(digest)

                self.assertEqual("", output.getvalue().strip())
                if expErr != "":
                    self.assertEqual("", r1)
                    self.assertEqual("", r2)
                    self.assertEqual("", r3)
                    self.assertTrue(expErr in error.getvalue().strip())
                else:
                    self.assertEqual("", output.getvalue().strip())
                    self.assertEqual("", error.getvalue().strip())
                    self.assertEqual("%s/%s" % (proj, loc), r1)
                    self.assertEqual("%s/%s" % (repo, img), r2)
                    self.assertEqual(sha, r3)

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.gar.GARSecurityReportNew.getDigestForImage")
    @mock.patch("requests.get")
    def test_getGARDiscovery(self, mock_get, mock_getDigestForImage):
        """Test getGARDiscovery()"""
        # clean
        mr = self._mock_response_for_gar(
            json.loads(
                """{
  "occurrences": [
    {
      "kind": "DISCOVERY",
      "discovery": {
        "continuousAnalysis": "ACTIVE",
        "analysisStatus": "FINISHED_SUCCESS"
      }
    }
  ]
}
"""
            )
        )
        mock_get.return_value = mr
        res = cvelib.gar.getGARDiscovery(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("CLEAN", res)

        # inactive
        mr = self._mock_response_for_gar(
            json.loads(
                """{
  "occurrences": [
    {
      "kind": "DISCOVERY",
      "discovery": {
        "continuousAnalysis": "INACTIVE",
        "analysisStatus": "FINISHED_SUCCESS"
      }
    }
  ]
}
"""
            )
        )
        mock_get.return_value = mr
        res = cvelib.gar.getGARDiscovery(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("INACTIVE", res)

        # unsupported
        mr = self._mock_response_for_gar(
            json.loads(
                """{
  "occurrences": [
    {
      "kind": "DISCOVERY",
      "discovery": {
        "analysisStatus": "FINISHED_UNSUPPORTED"
      }
    }
  ]
}
"""
            )
        )
        mock_get.return_value = mr
        res = cvelib.gar.getGARDiscovery(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("UNSUPPORTED", res)

        # other
        mr = self._mock_response_for_gar(
            json.loads(
                """{
  "occurrences": [
    {
      "kind": "DISCOVERY",
      "discovery": {
        "analysisStatus": "OTHER_STATUS"
      }
    }
  ]
}
"""
            )
        )
        mock_get.return_value = mr
        res = cvelib.gar.getGARDiscovery(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("OTHER_STATUS", res)

        # nonexistent
        mr = self._mock_response_for_gar({})
        mock_get.return_value = mr
        mock_getDigestForImage.return_value = ""
        res = cvelib.gar.getGARDiscovery(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("NONEXISTENT", res)

        # unscanned
        mr = self._mock_response_for_gar({})
        mock_get.return_value = mr
        mock_getDigestForImage.return_value = "sha256:deadbeef"
        res = cvelib.gar.getGARDiscovery(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("UNSCANNED", res)

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.getGARDiscovery("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Please use PROJECT/LOCATION/REPO/IMGNAME@sha256:<sha256>"
            in error.getvalue().strip()
        )

        # bad status
        mr = self._mock_response_for_gar({}, status=404)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARDiscovery(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # bad response
        mr = self._mock_response_for_gar({"bad": "format"})
        mock_get.return_value = mr
        res = cvelib.gar.getGARDiscovery(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("invalid json format", res)

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.gar.getGARDiscovery")
    @mock.patch("requests.get")
    def test_fetchScanReport(self, mock_get, mock_getGARDiscovery):
        """Test fetchScanReport()"""
        self.maxDiff = 2048

        mr = self._mock_response_for_gar(self._validGARReport())
        mock_get.return_value = mr
        gsr = cvelib.gar.GARSecurityReportNew()
        res, resMsg = gsr.fetchScanReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("", resMsg)
        self.assertEqual(1, len(res))
        self.assertEqual(1, len(res))
        self.assertEqual(res[0].component, "os/debian:ncurses")
        self.assertEqual(res[0].detectedIn, "cpe:/o:debian:debian_linux:11")
        self.assertEqual(
            res[0].advisory,
            "https://www.cve.org/CVERecord?id=CVE-2022-29458",
        )
        self.assertEqual(res[0].versionAffected, "6.2+20201114-2")
        self.assertEqual(res[0].versionFixed, "6.2+20201114-2+deb11u1")
        self.assertEqual(res[0].severity, "medium")
        self.assertEqual(res[0].status, "needed")
        self.assertEqual(
            res[0].url,
            "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@sha256:3fa5256ad34b31901ca30021c722fc7ba11a66ca070c8442862205696b908ddb",
        )

        # fixable=False
        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fixedVersion"][
            "fullName"
        ]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        res, resMsg = gsr.fetchScanReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef", fixable=False
        )
        self.assertEqual("", resMsg)
        self.assertEqual(1, len(res))
        self.assertEqual(res[0].component, "os/debian:ncurses")
        self.assertEqual(res[0].versionAffected, "6.2+20201114-2")
        self.assertEqual(res[0].versionFixed, "unknown")

        # fixable=True
        res, resMsg = gsr.fetchScanReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef", fixable=True
        )
        self.assertEqual("", resMsg)
        self.assertEqual(0, len(res))

        # priorities - not present
        d = self._validGARReport()
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        res, resMsg = gsr.fetchScanReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef",
            priorities=["negligible"],
        )
        self.assertEqual("", resMsg)
        self.assertEqual(0, len(res))

        # priorities - present
        d = self._validGARReport()
        d["occurrences"][0]["vulnerability"]["packageIssue"][0][
            "effectiveSeverity"
        ] = "NEGLIGIBLE"
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        res, resMsg = gsr.fetchScanReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef",
            priorities=["negligible"],
        )
        self.assertEqual("", resMsg)
        self.assertEqual(1, len(res))
        self.assertEqual(res[0].component, "os/debian:ncurses")
        self.assertEqual(res[0].versionAffected, "6.2+20201114-2")
        self.assertEqual(res[0].versionFixed, "6.2+20201114-2+deb11u1")
        self.assertEqual(res[0].severity, "negligible")

        # clean
        mr = self._mock_response_for_gar("{}")
        mock_get.return_value = mr
        mock_getGARDiscovery.return_value = "CLEAN"
        res, resMsg = gsr.fetchScanReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual(0, len(res))
        self.assertTrue("No problems found" in resMsg)

        # inactive
        mr = self._mock_response_for_gar("{}")
        mock_get.return_value = mr
        mock_getGARDiscovery.return_value = "INACTIVE"
        res, resMsg = gsr.fetchScanReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        self.assertEqual("No scan results for this inactive image", resMsg)
        self.assertEqual(0, len(res))

        # raw
        mr = self._mock_response_for_gar(self._validGARReport())
        mock_get.return_value = mr
        res, resMsg = gsr.fetchScanReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef", raw=True
        )
        exp = '"occurrences":'
        self.assertTrue(exp in resMsg)
        self.assertEqual(0, len(res))

        # raw no scan results
        mr = self._mock_response_for_gar("{}")
        mock_get.return_value = mr
        mock_getGARDiscovery.return_value = "UNSUPPORTED"
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = gsr.fetchScanReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef", raw=True
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "no scan results for valid-repo/valid-name: UNSUPPORTED"
            in error.getvalue().strip()
        )
        self.assertEqual("", resMsg)
        self.assertEqual(0, len(res))

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = gsr.fetchScanReport("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Please use PROJECT/LOCATION/REPO/IMGNAME@sha256:<sha256>"
            in error.getvalue().strip()
        )
        self.assertEqual("", resMsg)
        self.assertEqual(0, len(res))

        # bad status
        mr = self._mock_response_for_gar({}, status=404)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = gsr.fetchScanReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual("", resMsg)
        self.assertEqual(0, len(res))

        # bad responses
        d = self._validGARReport()
        del d["occurrences"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        mock_getGARDiscovery.return_value = "UNSUPPORTED"
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = gsr.fetchScanReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "no scan results for valid-repo/valid-name: UNSUPPORTED"
            in error.getvalue().strip()
        )
        self.assertEqual("No scan results for this unsupported image", resMsg)
        self.assertEqual(0, len(res))

        d = self._validGARReport()
        d["occurrences"] = []
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = gsr.fetchScanReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "no scan results for valid-repo/valid-name" in error.getvalue().strip()
        )
        self.assertEqual("No scan results for this unsupported image", resMsg)
        self.assertEqual(0, len(res))

        d = self._validGARReport()
        del d["occurrences"]
        d["some-key"] = "blah"
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = gsr.fetchScanReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "no scan results for valid-repo/valid-name" in error.getvalue().strip(),
            msg="error=%s" % error.getvalue().strip(),
        )
        self.assertEqual("No scan results for this unsupported image", resMsg)
        self.assertEqual(0, len(res))

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.gar.getGAROCIForRepo")
    @mock.patch("cvelib.gar.GARSecurityReportNew.getReposForNamespace")
    def test_getOCIsForNamespace(
        self, mock_getReposForNamespace, mock_getGAROCIForRepo
    ):
        """Test getOCIsForNamespace()"""
        mock_getReposForNamespace.return_value = [
            "projects/valid-proj/locations/us/repositories/valid-repo"
        ]
        mock_getGAROCIForRepo.return_value = [
            ("valid-name", 1684472852),
            ("other-name", 1681248884),
        ]

        gsr = cvelib.gar.GARSecurityReportNew()
        res = gsr.getOCIsForNamespace("valid-proj/us")
        self.assertEqual(2, len(res))
        # these are sorted
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/other-name",
            res[0][0],
        )
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
            res[1][0],
        )

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            gsr.getOCIsForNamespace("valid-proj")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Please use PROJECT/LOCATION" in error.getvalue().strip())

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.gar.GARSecurityReportNew.fetchScanReport")
    @mock.patch("cvelib.gar.GARSecurityReportNew.getDigestForImage")
    @mock.patch("cvelib.gar.GARSecurityReportNew.getOCIsForNamespace")
    def test_main_gar_dump_reports(
        self,
        mock_getOCIsForNamespace,
        mock_getDigestForImage,
        mock_fetchScanReport,
    ):
        """Test test_main_gar_dump_reports()"""
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")

        mock_getOCIsForNamespace.return_value = [
            (
                "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
                1684472852,
            ),
        ]
        mock_getDigestForImage.return_value = "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@deadbeef"
        mock_fetchScanReport.return_value = (
            [],
            """{
  "occurrences": [
    {
      "resourceUri": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@deadbeef",
      "createTime": "2023-03-15T14:49:29.714201Z",
      "updateTime": "2023-03-15T14:49:29.714201Z",
      "vulnerability": {}
    }
  ]
}
""",
        )

        fn = (
            self.tmpdir
            + "/subdir/2023/03/15/gar/valid-proj/us/valid-repo/valid-name/deadbeef.json"
        )
        relfn = os.path.relpath(fn, self.tmpdir + "/subdir")

        # create
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-proj/us",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.gar.main_gar_dump_reports()
        self.assertEqual("Created: %s" % relfn, output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

        # update
        with open(fn, "w") as fh:
            fh.write("changed")
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-proj/us",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.gar.main_gar_dump_reports()
        self.assertEqual("Updated: %s" % relfn, output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

        # no occurences
        mock_getOCIsForNamespace.return_value = [
            (
                "projects/valid-proj/locations/us/repositories/valid-repo/valid-name2",
                1684472852,
            ),
        ]
        mock_getDigestForImage.return_value = "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name2@deadbeef"
        mock_fetchScanReport.return_value = ([], "{}")
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-proj/us",
            ],
        ):
            cvelib.gar.main_gar_dump_reports()
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.gar.main_gar_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("ERROR: No new security reports", error.getvalue().strip())

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.gar.GARSecurityReportNew.fetchScanReport")
    @mock.patch("cvelib.gar.GARSecurityReportNew.getDigestForImage")
    @mock.patch("cvelib.gar.GARSecurityReportNew.getOCIsForNamespace")
    def test_main_gar_dump_reports_bad(
        self,
        mock_getOCIsForNamespace,
        mock_getDigestForImage,
        mock_fetchScanReport,
    ):
        """Test test_gar_main_dump_reports()"""
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")

        # bad
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with mock.patch(
                "argparse._sys.argv",
                [
                    "_",
                    "--path",
                    self.tmpdir + "/subdir",
                    "--name",
                    "valid-proj",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.gar.main_gar_dump_reports()
            self.assertEqual("", output.getvalue().strip())
            self.assertTrue("Please use PROJECT/LOC" in error.getvalue().strip())

        # no image names
        mock_getOCIsForNamespace.return_value = []
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with mock.patch(
                "argparse._sys.argv",
                [
                    "_",
                    "--path",
                    self.tmpdir + "/subdir",
                    "--name",
                    "valid-proj/us",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.gar.main_gar_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not enumerate any OCI image names" in error.getvalue().strip()
        )

        # no digests
        mock_getOCIsForNamespace.return_value = [
            (
                "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
                1684472852,
            ),
        ]
        mock_getDigestForImage.return_value = ""
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with mock.patch(
                "argparse._sys.argv",
                [
                    "_",
                    "--path",
                    self.tmpdir + "/subdir",
                    "--name",
                    "valid-proj/us",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.gar.main_gar_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find any OCI image digests" in error.getvalue().strip(),
        )

        # no security reports
        mock_getOCIsForNamespace.return_value = [
            (
                "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
                1684472852,
            ),
        ]
        mock_getDigestForImage.return_value = "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@deadbeef"
        mock_fetchScanReport.return_value = "{}"
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with mock.patch(
                "argparse._sys.argv",
                [
                    "_",
                    "--path",
                    self.tmpdir + "/subdir",
                    "--name",
                    "valid-proj/us",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.gar.main_gar_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("No new security reports" in error.getvalue().strip())

        # bad report
        mock_getOCIsForNamespace.return_value = [
            (
                "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
                1684472852,
            ),
        ]
        mock_getDigestForImage.return_value = "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@deadbeef"
        mock_fetchScanReport.return_value = (
            [],
            """{
  "occurrences": [
    {
      "resourceUri": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@deadbeef",
      "updateTime": "2023-03-15T14:49:29.714201Z",
      "vulnerability": {}
    }
  ]
}
""",
        )
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-proj/us",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.gar.main_gar_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "WARN: Could not find 'createTime' in" in error.getvalue().strip()
        )

        # bad report (no occurrences)
        mock_getOCIsForNamespace.return_value = [
            (
                "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
                1684472852,
            ),
        ]
        mock_getDigestForImage.return_value = "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@deadbeef"
        mock_fetchScanReport.return_value = "{}"
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-proj/us",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.gar.main_gar_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("No new security reports" in error.getvalue().strip())

        # path exists but isn't a file
        mock_getOCIsForNamespace.return_value = [
            (
                "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
                1684472852,
            ),
        ]
        mock_getDigestForImage.return_value = "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@deadbeef"
        mock_fetchScanReport.return_value = (
            [],
            """{
  "occurrences": [
    {
      "resourceUri": "https://us-docker.pkg.dev/valid-proj/valid-repo/valid-name@deadbeef",
      "createTime": "2023-03-15T14:49:29.714201Z",
      "updateTime": "2023-03-15T14:49:29.714201Z",
      "vulnerability": {}
    }
  ]
}
""",
        )
        fn = (
            self.tmpdir
            + "/subdir/2023/03/15/gar/valid-proj/us/valid-repo/valid-name/deadbeef.json"
        )
        os.makedirs(fn)
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-proj/us",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.gar.main_gar_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("is not a file" in error.getvalue().strip())
