"""test_gar.py: tests for gar.py module"""
#
# SPDX-License-Identifier: MIT

import json
import os
from typing import Any, Dict
from unittest import TestCase, mock

import cvelib.common
import cvelib.gar
import tests.testutil


class TestGAR(TestCase):
    """Tests for the gar functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        os.environ["SEDG_EXPERIMENTAL"] = "1"
        self.orig_gar_token = None

        if "GCLOUD_TOKEN" in os.environ:
            self.orig_ghtoken = os.getenv("GCLOUD_TOKEN")
        os.environ["GCLOUD_TOKEN"] = "fake-test-token"

        tests.testutil.disableRequestsCache()

    def tearDown(self):
        """Teardown functions common for all tests"""
        if "SEDG_EXPERIMENTAL" in os.environ:
            del os.environ["SEDG_EXPERIMENTAL"]

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
                "ERROR: Please export GCLOUD_TOKEN (eg: export GCLOUD_TOKEN=$(gcloud auth print-access-token)",
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
        self.assertEqual("ncurses", res[0].component)
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

        # detectedIn
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
    def test_getGARReposForProjectLoc(self, mock_get):
        """Test getGARReposForProjectLoc()"""
        mr = self._mock_response_for_gar(self._validGARReposForProjectLoc())
        mock_get.return_value = mr
        res = cvelib.gar.getGARReposForProjectLoc("valid-proj/us")
        self.assertEqual(1, len(res))
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo", res[0]
        )

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.getGARReposForProjectLoc("blah")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Please use PROJECT/LOCATION" in error.getvalue().strip())

        # bad status
        mr = self._mock_response_for_gar({}, status=401)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARReposForProjectLoc("valid-proj/us")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # bad response
        d = self._validGARReposForProjectLoc()
        del d["repositories"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARReposForProjectLoc("valid-proj/us")
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
            res = cvelib.gar.getGARReposForProjectLoc("valid-proj/us")
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
        self.assertEqual("valid-name", res[0])
        self.assertEqual("other-name", res[1])

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
        self.assertEqual("other-name", res[0])

    def _validGARDigestForImage(self) -> Dict[str, Any]:
        """Return valid gar v1/projects.locations.repositories.dockerImages as python object"""
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
    def test_getGARDigestForImage(self, mock_get):
        """Test getGARDigestForImage()"""
        mr = self._mock_response_for_gar(self._validGARDigestForImage())
        mock_get.return_value = mr
        res = cvelib.gar.getGARDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fbed39525f7c06f6b83c0e8da65f434c6dffba7b7f09917d5a8a31299ed12f0a",
            res,
        )

        # search by tag
        mock_get.return_value = mr
        res = cvelib.gar.getGARDigestForImage(
            "valid-proj/us/valid-repo/valid-name:some-tag"
        )
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
            res,
        )

        # not an OCI
        d = self._validGARDigestForImage()
        d["versions"][1]["metadata"][
            "mediaType"
        ] = "application/vnd.oci.image.manifest.v1+json"
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARDigestForImage(
                "valid-proj/us/valid-repo/valid-name:some-tag"
            )
            self.assertEqual("", res)
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("not an OCI" in error.getvalue().strip())

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.getGARDigestForImage("valid-proj")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Please use PROJECT/LOCATION/REPO/IMGNAME" in error.getvalue().strip()
        )

        # bad status
        mr = self._mock_response_for_gar({}, status=404)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # bad response
        d = self._validGARDigestForImage()
        del d["versions"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARDigestForImage("valid-proj/us/valid-repo/valid-name")
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
        res = cvelib.gar.getGARDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
            res,
        )

        d = self._validGARDigestForImage()
        del d["versions"][0]["metadata"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        res = cvelib.gar.getGARDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
            res,
        )

        d = self._validGARDigestForImage()
        del d["versions"][0]["metadata"]["mediaType"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        res = cvelib.gar.getGARDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
            res,
        )

        d = self._validGARDigestForImage()
        del d["versions"][0]["metadata"]["name"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        res = cvelib.gar.getGARDigestForImage("valid-proj/us/valid-repo/valid-name")
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/dockerImages/valid-name@sha256:fedcc66faa91b235c6cf3e74139eefccb4b783e3d3b5415e3660de792029083a",
            res,
        )

    @mock.patch("requests.get")
    def test_getGARSecurityReport(self, mock_get):
        """Test getGARSecurityReport()"""
        mr = self._mock_response_for_gar(self._validGARReport())
        mock_get.return_value = mr
        res = cvelib.gar.getGARSecurityReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
        )
        exp = "ncurses 6.2+20201114-2 needed (medium)"
        self.assertEqual(exp, res)

        # fixable
        d = self._validGARReport()
        del d["occurrences"][0]["vulnerability"]["packageIssue"][0]["fixedVersion"][
            "fullName"
        ]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        res = cvelib.gar.getGARSecurityReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef", fixable=False
        )
        exp = "ncurses 6.2+20201114-2 n/a (medium)"
        self.assertEqual(exp, res)

        res = cvelib.gar.getGARSecurityReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef", fixable=True
        )
        self.assertEqual(0, len(res))

        # raw
        mr = self._mock_response_for_gar(self._validGARReport())
        mock_get.return_value = mr
        res = cvelib.gar.getGARSecurityReport(
            "valid-proj/us/valid-repo/valid-name@sha256:deadbeef", raw=True
        )
        exp = '"occurrences":'
        self.assertTrue(exp in res)

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.getGARSecurityReport("valid-proj/us/valid-repo/valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Please use PROJECT/LOCATION/REPO/IMGNAME@sha256:<sha256>"
            in error.getvalue().strip()
        )

        # bad status
        mr = self._mock_response_for_gar({}, status=404)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARSecurityReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # bad responses
        d = self._validGARReport()
        del d["occurrences"]
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARSecurityReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("no scan results for image" in error.getvalue().strip())

        d = self._validGARReport()
        d["occurrences"] = []
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARSecurityReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("no scan results for image" in error.getvalue().strip())

        d = self._validGARReport()
        del d["occurrences"]
        d["some-key"] = "blah"
        mr = self._mock_response_for_gar(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.gar.getGARSecurityReport(
                "valid-proj/us/valid-repo/valid-name@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'occurrences' in response" in error.getvalue().strip()
        )

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.gar.getGAROCIForRepo")
    @mock.patch("cvelib.gar.getGARReposForProjectLoc")
    def test_getGAROCIsForProjectLoc(
        self, mock_getGARReposForProjectLoc, mock_getGAROCIForRepo
    ):
        """Test getGAROCIsForProjectLoc()"""
        mock_getGARReposForProjectLoc.return_value = [
            "projects/valid-proj/locations/us/repositories/valid-repo"
        ]
        mock_getGAROCIForRepo.return_value = ["valid-name", "other-name"]

        res = cvelib.gar.getGAROCIsForProjectLoc("valid-proj/us")
        self.assertEqual(2, len(res))
        # these are sorted
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/other-name",
            res[0],
        )
        self.assertEqual(
            "projects/valid-proj/locations/us/repositories/valid-repo/valid-name",
            res[1],
        )

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.gar.getGAROCIsForProjectLoc("valid-proj")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Please use PROJECT/LOCATION" in error.getvalue().strip())
