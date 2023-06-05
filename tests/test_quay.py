"""test_quay.py: tests for quay.py module"""
#
# SPDX-License-Identifier: MIT

import datetime
import json
import os
import tempfile
from unittest import TestCase, mock

import cvelib.common
import cvelib.quay
import tests.testutil


class TestQuay(TestCase):
    """Tests for the quay functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        os.environ["SEDG_EXPERIMENTAL"] = "1"
        self.orig_quay_cookie = None
        self.orig_quay_token = None

        if "QUAY_COOKIE" in os.environ:
            self.orig_ghcookie = os.getenv("QUAY_COOKIE")
        os.environ["QUAY_COOKIE"] = "fake-test-cookie"

        if "QUAY_TOKEN" in os.environ:
            self.orig_ghtoken = os.getenv("QUAY_TOKEN")
        os.environ["QUAY_TOKEN"] = "fake-test-token"

        tests.testutil.disableRequestsCache()

    def tearDown(self):
        """Teardown functions common for all tests"""
        if "SEDG_EXPERIMENTAL" in os.environ:
            del os.environ["SEDG_EXPERIMENTAL"]

    def test__createQuayHeaders(self):
        """Test _createQuayHeaders()"""
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with tests.testutil.capturedOutput() as (output, error):
                res = cvelib.quay._createQuayHeaders()
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual("", error.getvalue().strip())

            # test cookie
            exp = {"cookie": "fake-test-cookie"}
            self.assertDictEqual(exp, res)

            # test token
            del os.environ["QUAY_COOKIE"]
            with tests.testutil.capturedOutput() as (output, error):
                res = cvelib.quay._createQuayHeaders()
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual("", error.getvalue().strip())
            exp = {"Authorization": "Bearer fake-test-token"}
            self.assertDictEqual(exp, res)

            # error
            del os.environ["QUAY_TOKEN"]
            with tests.testutil.capturedOutput() as (output, error):
                res = cvelib.quay._createQuayHeaders()
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual(
                "ERROR: Please export either QUAY_COOKIE or QUAY_TOKEN",
                error.getvalue().strip(),
            )

    def _validQuayReport(self):
        """Return a valid quay report as python object"""
        s = """
{
  "status": "scanned",
  "data": {
    "Layer": {
      "Name": "sha256:3fa5256ad34b31901ca30021c722fc7ba11a66ca070c8442862205696b908ddb",
      "ParentName": "",
      "NamespaceName": "",
      "IndexedByVersion": 4,
      "Features": [
        {
          "Name": "libncurses6",
          "VersionFormat": "",
          "NamespaceName": "",
          "AddedBy": "sha256:bf2c0807fa72ed4fe548329a2daecf4412bfe8496dd07e12142c023d357e2559",
          "Version": "6.2+20201114-2",
          "Vulnerabilities": [
            {
              "Severity": "High",
              "NamespaceName": "debian/updater/bullseye",
              "Link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29458",
              "FixedBy": "0:6.2+20201114-2+deb11u1",
              "Description": "ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings in tinfo/read_entry.c in the terminfo library.",
              "Name": "CVE-2022-29458 ncurses",
              "Metadata": {
                "UpdatedBy": "debian/updater/bullseye",
                "RepoName": null,
                "RepoLink": null,
                "DistroName": "Debian GNU/Linux",
                "DistroVersion": "11 (bullseye)",
                "NVD": {
                  "CVSSv3": {
                    "Vectors": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H",
                    "Score": 7.1
                  }
                }
              }
            }
          ]
        }
      ]
    }
  }
}
"""
        return json.loads(s)

    def test_parse(self):
        """Test parse()"""
        d = self._validQuayReport()
        res = cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual(1, len(res))
        self.assertEqual("libncurses6", res[0].component)
        self.assertEqual("Debian GNU/Linux 11 (bullseye)", res[0].detectedIn)
        self.assertEqual(
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29458",
            res[0].advisory,
        )
        self.assertEqual("6.2+20201114-2", res[0].versionAffected)
        self.assertEqual("0:6.2+20201114-2+deb11u1", res[0].versionFixed)
        self.assertEqual("high", res[0].severity)
        self.assertEqual("needed", res[0].status)
        self.assertEqual(
            "https://quay.io/repository/foo/manifest/bar?tab=vulnerabilities",
            res[0].url,
        )

        # needs-triage
        d = self._validQuayReport()
        d["data"]["Layer"]["Features"][0]["Vulnerabilities"][0]["FixedBy"] = ""
        res = cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual(1, len(res))
        self.assertEqual("needs-triage", res[0].status)
        self.assertEqual("unknown", res[0].versionFixed)

        d = self._validQuayReport()
        d["data"]["Layer"]["Features"][0]["Vulnerabilities"][0]["FixedBy"] = "0:0"
        res = cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual(1, len(res))
        self.assertEqual("needs-triage", res[0].status)
        self.assertEqual("unknown", res[0].versionFixed)

        # released
        d = self._validQuayReport()
        d["data"]["Layer"]["Features"][0]["Vulnerabilities"][0]["FixedBy"] = d["data"][
            "Layer"
        ]["Features"][0]["Version"]
        res = cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual(1, len(res))
        self.assertEqual("released", res[0].status)

        # detectedIn
        d = self._validQuayReport()
        d["data"]["Layer"]["Features"][0]["Vulnerabilities"][0]["Metadata"][
            "RepoName"
        ] = "needle"
        d["data"]["Layer"]["Features"][0]["Vulnerabilities"][0]["Metadata"][
            "DistroName"
        ] = None
        d["data"]["Layer"]["Features"][0]["Vulnerabilities"][0]["Metadata"][
            "DistroVersion"
        ] = None
        res = cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual(1, len(res))
        self.assertEqual("needle", res[0].detectedIn)

        # advisory
        d = self._validQuayReport()
        d["data"]["Layer"]["Features"][0]["Vulnerabilities"][0]["Link"] = ""
        res = cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual(1, len(res))
        self.assertEqual("unavailable", res[0].advisory)

    def test_parse_bad(self):
        """Test parse() - bad"""
        d = self._validQuayReport()
        del d["data"]["Layer"]["Features"][0]["Name"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'Name' in" in error.getvalue().strip())

        d = self._validQuayReport()
        del d["data"]["Layer"]["Features"][0]["Version"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'Version' in" in error.getvalue().strip())

        d = self._validQuayReport()
        del d["data"]["Layer"]["Features"][0]["Vulnerabilities"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.quay.parse(d, "https://quay.io/repository/foo/manifest/bar")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'Vulnerabilities' in" in error.getvalue().strip()
        )

    def _mock_response_for_quay(self, json_data, ns=None, status=200):
        """Build a mocked requests response

        Example:

          @mock.patch('requests.get')
          def test_...(self, mock_get):
              mr = self._mock_response_for_quay({"foo": "bar"})
              mock_get.return_value = mr
              res = foo('good')
              self.assertEqual(res, "...")
        """
        # mock up a one page link for simplicity
        mr = mock.Mock()
        mr.status_code = status
        mr.json = mock.Mock(return_value=json_data)
        if ns is not None:
            mr.headers = {"namespace": ns}

        return mr

    @mock.patch("requests.get")
    def test_getQuayOCIsForOrg(self, mock_get):
        """Test getQuayOCIsForOrg()"""
        mr = self._mock_response_for_quay(
            {
                "repositories": [
                    {
                        "namespace": "valid-org",
                        "name": "valid-repo",
                        "description": "some desc",
                        "is_public": False,
                        "kind": "image",
                        "state": "NORMAL",
                        "last_modified": 1684472852,
                        "is_starred": False,
                    },
                ]
            },
            ns="valid-org",
        )
        mock_get.return_value = mr
        res = cvelib.quay.getQuayOCIsForOrg("valid-org")
        self.assertEqual(1, len(res))
        self.assertEqual("valid-repo", res[0])

        # empty
        mr = self._mock_response_for_quay({}, ns="valid-org")
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuayOCIsForOrg("valid-org")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'repositories' in response" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        # bad status
        mr = self._mock_response_for_quay({}, ns="valid-org", status=404)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuayOCIsForOrg("valid-org")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # no name
        mr = self._mock_response_for_quay(
            {
                "repositories": [
                    {
                        "namespace": "valid-org",
                        "description": "some desc",
                        "is_public": False,
                        "kind": "image",
                        "state": "NORMAL",
                        "last_modified": 1684472852,
                        "is_starred": False,
                    },
                ]
            },
            ns="valid-org",
        )
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuayOCIsForOrg("valid-org")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'name' in response for repo" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

    @mock.patch("requests.get")
    def test_getQuayDigestForImage(self, mock_get):
        """Test getQuayDigestForImage()"""
        mr = self._mock_response_for_quay(
            {
                "namespace": "valid-org",
                "name": "valid-repo",
                "kind": "image",
                "description": "",
                "is_public": True,
                "is_organization": True,
                "is_starred": False,
                "status_token": "",
                "trust_enabled": False,
                "tag_expiration_s": 1209600,
                "is_free_account": False,
                "state": "NORMAL",
                "tags": {
                    "latest": {
                        "name": "latest",
                        "size": 270353940,
                        "last_modified": "Wed, 15 Mar 2023 15:05:28 -0000",
                        "manifest_digest": "sha256:3fa5256ad34b31901ca30021c722fc7ba11a66ca070c8442862205696b908ddb",
                    },
                    "some-tag": {
                        "name": "f7d94bbcf4f202b9f9d8f72c37d5650d7756f188",
                        "size": 573662556,
                        "last_modified": "Tue, 14 Jun 2022 12:07:42 -0000",
                        "manifest_digest": "sha256:2536a15812ba685df76e835aefdc7f512941c12c561e0aed152d17aa025cc820",
                    },
                },
                "can_write": False,
                "can_admin": False,
            },
        )
        mock_get.return_value = mr
        res = cvelib.quay.getQuayDigestForImage("valid-org/valid-repo")
        self.assertEqual(
            "valid-org/valid-repo@sha256:3fa5256ad34b31901ca30021c722fc7ba11a66ca070c8442862205696b908ddb",
            res,
        )

        # search by tag
        mock_get.return_value = mr
        res = cvelib.quay.getQuayDigestForImage("valid-org/valid-repo:some-tag")
        self.assertEqual(
            "valid-org/valid-repo@sha256:2536a15812ba685df76e835aefdc7f512941c12c561e0aed152d17aa025cc820",
            res,
        )

        # search by sha256
        mock_get.return_value = mr
        res = cvelib.quay.getQuayDigestForImage(
            "valid-org/valid-repo@sha256:2536a15812ba685df76e835aefdc7f512941c12c561e0aed152d17aa025cc820"
        )
        self.assertEqual(
            "valid-org/valid-repo@sha256:2536a15812ba685df76e835aefdc7f512941c12c561e0aed152d17aa025cc820",
            res,
        )

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.quay.getQuayDigestForImage("valid-org")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Please use ORG/NAME" in error.getvalue().strip())

        # bad status
        mr = self._mock_response_for_quay({}, status=404)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuayDigestForImage("valid-org/valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # missing tags
        mr = self._mock_response_for_quay(
            {"namespace": "valid-org", "name": "valid-repo"},
        )
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuayDigestForImage("valid-org/valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'tags' in response" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # empty tags
        mr = self._mock_response_for_quay(
            {"namespace": "valid-org", "name": "valid-repo", "tags": {}},
        )
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuayDigestForImage("valid-org/valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual(0, len(res))

        # tags missing last_modified
        mr = self._mock_response_for_quay(
            {
                "namespace": "valid-org",
                "name": "valid-repo",
                "kind": "image",
                "description": "",
                "is_public": True,
                "is_organization": True,
                "is_starred": False,
                "status_token": "",
                "trust_enabled": False,
                "tag_expiration_s": 1209600,
                "is_free_account": False,
                "state": "NORMAL",
                "tags": {
                    "latest": {
                        "name": "latest",
                        "size": 270353940,
                        "manifest_digest": "sha256:3fa5256ad34b31901ca30021c722fc7ba11a66ca070c8442862205696b908ddb",
                    },
                    "some-tag": {
                        "name": "f7d94bbcf4f202b9f9d8f72c37d5650d7756f188",
                        "size": 573662556,
                        "last_modified": "Tue, 14 Jun 2022 12:07:42 -0000",
                        "manifest_digest": "sha256:2536a15812ba685df76e835aefdc7f512941c12c561e0aed152d17aa025cc820",
                    },
                },
                "can_write": False,
                "can_admin": False,
            },
        )
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuayDigestForImage("valid-org/valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'last_modified' in response" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

    @mock.patch("requests.get")
    def test_getQuaySecurityReport(self, mock_get):
        """Test getQuaySecurityReport()"""
        mr = self._mock_response_for_quay(self._validQuayReport())
        mock_get.return_value = mr
        res = cvelib.quay.getQuaySecurityReport("valid-org/valid-repo@sha256:deadbeef")
        exp = "libncurses6 6.2+20201114-2 needed (high)"
        self.assertEqual(exp, res)

        # fixable
        d = self._validQuayReport()
        d["data"]["Layer"]["Features"][0]["Vulnerabilities"][0]["FixedBy"] = ""
        mr = self._mock_response_for_quay(d)
        mock_get.return_value = mr
        res = cvelib.quay.getQuaySecurityReport(
            "valid-org/valid-repo@sha256:deadbeef", fixable=False
        )
        exp = "libncurses6 6.2+20201114-2 n/a (high)"
        self.assertEqual(exp, res)

        res = cvelib.quay.getQuaySecurityReport(
            "valid-org/valid-repo@sha256:deadbeef", fixable=True
        )
        self.assertEqual(0, len(res))

        # raw
        mr = self._mock_response_for_quay(self._validQuayReport())
        mock_get.return_value = mr
        res = cvelib.quay.getQuaySecurityReport(
            "valid-org/valid-repo@sha256:deadbeef", raw=True
        )
        exp = '"status": "scanned"'
        self.assertTrue(exp in res)

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.quay.getQuaySecurityReport("valid-org/valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Please use ORG/NAME@sha256:<sha256>" in error.getvalue().strip()
        )

        # bad status
        mr = self._mock_response_for_quay({}, status=404)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuaySecurityReport(
                "valid-org/valid-repo@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # bad responses
        d = self._validQuayReport()
        del d["status"]
        mr = self._mock_response_for_quay(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuaySecurityReport(
                "valid-org/valid-repo@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Cound not find 'status' in response" in error.getvalue().strip()
        )

        d = self._validQuayReport()
        d["status"] = "wrong"
        mr = self._mock_response_for_quay(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuaySecurityReport(
                "valid-org/valid-repo@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not process report due to status: wrong" in error.getvalue().strip()
        )

        d = self._validQuayReport()
        del d["data"]
        mr = self._mock_response_for_quay(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuaySecurityReport(
                "valid-org/valid-repo@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'data' in" in error.getvalue().strip())

        d = self._validQuayReport()
        d["data"] = None
        mr = self._mock_response_for_quay(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuaySecurityReport(
                "valid-org/valid-repo@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not process report due to no data in" in error.getvalue().strip()
        )

        d = self._validQuayReport()
        del d["data"]["Layer"]
        mr = self._mock_response_for_quay(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuaySecurityReport(
                "valid-org/valid-repo@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'Layer' in" in error.getvalue().strip())

        d = self._validQuayReport()
        del d["data"]["Layer"]["Features"]
        mr = self._mock_response_for_quay(d)
        mock_get.return_value = mr
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.quay.getQuaySecurityReport(
                "valid-org/valid-repo@sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'Features' in" in error.getvalue().strip())

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.quay.getQuaySecurityReport")
    @mock.patch("cvelib.quay.getQuayDigestForImage")
    @mock.patch("cvelib.quay.getQuayOCIsForOrg")
    def test_main_quay_dump_reports(
        self,
        mock_getQuayOCIsForOrg,
        mock_getQuayDigestForImage,
        mock_getQuaySecurityReport,
    ):
        """Test test_main_quay_dump_reports()"""
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")
        os.environ["SEDG_EXPERIMENTAL"] = "1"

        mock_getQuayOCIsForOrg.return_value = ["valid-repo"]
        mock_getQuayDigestForImage.return_value = "valid-org/valid-repo@sha256:deadbeef"
        mock_getQuaySecurityReport.return_value = '{"status": "scanned", "data": {}}'

        # create
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-org",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.quay.main_quay_dump_reports()

        today = datetime.datetime.now()
        fn = (
            self.tmpdir
            + "/subdir/%d/%0.2d/%0.2d/quay/valid-org/valid-repo/deadbeef.json"
            % (today.year, today.month, today.day)
        )
        relfn = os.path.relpath(fn, self.tmpdir + "/subdir")
        self.assertEqual("Created: %s" % relfn, output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

        # updated
        with open(fn, "w") as fh:
            fh.write('{"status": "scanned", "data": {}}')
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-org",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.quay.main_quay_dump_reports()
        today = datetime.datetime.now()
        fn = (
            self.tmpdir
            + "/subdir/%d/%0.2d/%0.2d/quay/valid-org/valid-repo/deadbeef.json"
            % (today.year, today.month, today.day)
        )
        relfn = os.path.relpath(fn, self.tmpdir + "/subdir")
        self.assertEqual("Updated: %s" % relfn, output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

        # duplicate
        fn = self.tmpdir + "/subdir/YYYY/MM/DD/quay/valid-org/valid-repo/deadbeef.json"
        os.makedirs(os.path.dirname(fn))
        with open(fn, "w") as fh:
            fh.write('{"status": "scanned", "data": {}}')
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-org",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.quay.main_quay_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Found duplicate" in error.getvalue().strip())

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.quay.getQuaySecurityReport")
    @mock.patch("cvelib.quay.getQuayDigestForImage")
    @mock.patch("cvelib.quay.getQuayOCIsForOrg")
    def test_main_quay_dump_reports_bad(
        self,
        mock_getQuayOCIsForOrg,
        mock_getQuayDigestForImage,
        mock_getQuaySecurityReport,
    ):
        """Test test_gar_main_dump_reports()"""
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")
        os.environ["SEDG_EXPERIMENTAL"] = "1"

        # no image names
        mock_getQuayOCIsForOrg.return_value = []
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
                    "valid-org",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.quay.main_quay_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not enumerate any OCI image names" in error.getvalue().strip()
        )

        # no digests
        mock_getQuayOCIsForOrg.return_value = ["valid-repo"]
        mock_getQuayDigestForImage.return_value = ""
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
                    "valid-org",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.quay.main_quay_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "WARN: Could not find digest for valid-org/valid-repo"
            in error.getvalue().strip(),
        )
        self.assertTrue(
            "Could not find any OCI image digests" in error.getvalue().strip(),
        )

        mock_getQuayOCIsForOrg.return_value = ["valid-repo"]
        mock_getQuayDigestForImage.return_value = "valid-org/valid-repo@sha256:deadbeef"
        mock_getQuaySecurityReport.return_value = "{}"
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
                    "valid-org",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.quay.main_quay_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("No new security reports" in error.getvalue().strip())

        # unsupported scan status
        mock_getQuayOCIsForOrg.return_value = ["valid-repo"]
        mock_getQuayDigestForImage.return_value = "valid-org/valid-repo@sha256:deadbeef"
        mock_getQuaySecurityReport.return_value = (
            '{"status": "supported", "data": null}'
        )
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
                    "valid-org",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.quay.main_quay_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("No new security reports" in error.getvalue().strip())

        # unknown scan status
        mock_getQuayOCIsForOrg.return_value = ["valid-repo"]
        mock_getQuayDigestForImage.return_value = "valid-org/valid-repo@sha256:deadbeef"
        mock_getQuaySecurityReport.return_value = '{"status": "bad", "data": null}'
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
                    "valid-org",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.quay.main_quay_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("unexpected scan status: bad" in error.getvalue().strip())
