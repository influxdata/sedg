"""test_dso.py: tests for dso.py module"""

#
# SPDX-License-Identifier: MIT

import datetime
import json
import os
import tempfile
from unittest import TestCase, mock, skipIf

import cvelib.common
import cvelib.dso
import cvelib.scan
import tests.testutil


# Use with: @skipIf(not _edn_format_available(), "edn_format not available")
def _edn_format_available():  # pragma: nocover
    """Check if edn_format module is available"""
    try:
        import edn_format

        if hasattr(edn_format, "loads"):
            return True
    except Exception:
        pass
    return False


class TestDockerDSO(TestCase):
    """Tests for the dso functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        self.tmpdir = None

        tests.testutil.disableRequestsCache()

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.tmpdir is not None:
            cvelib.common.recursive_rm(self.tmpdir)

    def test__createDockerDSOHeaders(self):
        """Test _createDockerDSOHeaders()"""
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._createDockerDSOHeaders()
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())
        self.assertDictEqual({}, res)

    def _validDockerDSOReport(self):
        """Return a valid dso report as python object"""
        d = {
            "data": {
                "vulnerabilitiesByPackage": [
                    {
                        "purl": "pkg:something@1.0.0",
                        "vulnerabilities": [
                            {
                                "cvss": {"score": 7.5, "severity": "HIGH"},
                                "cwes": [],
                                "description": "An attacker can cause...",
                                "fixedBy": "1.0.1",
                                "publishedAt": "2022-07-15T23:08:33.000Z",
                                "source": "golang",
                                "sourceId": "CVE-2021-44716",
                                "vulnerableRange": "<1.0.1",
                            }
                        ],
                    }
                ]
            }
        }
        p = {
            "pkg:something@1.0.0": [
                "/path/1",
                "/path/2",
            ]
        }

        return p, d

    def _validDockerDSOPackageURLs(self):
        """Return a valid dso report as python object"""
        d = {
            "data": {
                "imagePackagesByDigest": {
                    "digest": "sha256:deadbeef",
                    "imagePackages": {
                        "packages": [
                            {
                                "package": {
                                    "purl": "pkg:something@1.0.0",
                                },
                                "locations": [
                                    {
                                        "diffId": "sha256:beeffeed1",
                                        "path": "/path/1",
                                    },
                                    {
                                        "diffId": "sha256:beeffeed2",
                                        "path": "/path/2",
                                    },
                                ],
                            }
                        ]
                    },
                }
            }
        }

        return d

    def test_parse(self):
        """Test parse()"""
        p, d = self._validDockerDSOReport()
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(2, len(res))
        self.assertEqual("pkg:something", res[0].component)
        self.assertEqual("/path/1", res[0].detectedIn)
        self.assertEqual(
            "https://www.cve.org/CVERecord?id=CVE-2021-44716",
            res[0].advisory,
        )
        self.assertEqual("1.0.0", res[0].versionAffected)
        self.assertEqual("1.0.1", res[0].versionFixed)
        self.assertEqual("high", res[0].severity)
        self.assertEqual("needed", res[0].status)
        self.assertEqual(
            "https://dso.docker.com/images/foo/digests/sha256:deadbeef",
            res[0].url,
        )
        self.assertEqual("pkg:something", res[1].component)
        self.assertEqual("/path/2", res[1].detectedIn)
        self.assertEqual(
            "https://www.cve.org/CVERecord?id=CVE-2021-44716",
            res[1].advisory,
        )
        self.assertEqual("1.0.0", res[1].versionAffected)
        self.assertEqual("1.0.1", res[1].versionFixed)
        self.assertEqual("high", res[1].severity)
        self.assertEqual("needed", res[1].status)
        self.assertEqual(
            "https://dso.docker.com/images/foo/digests/sha256:deadbeef",
            res[1].url,
        )

        # parse with ? in purl
        p, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0][
            "purl"
        ] = "pkg:something@1.0.0?os_distro=bullseye&os_name=debian&os_version=11"
        p = {"pkg:something@1.0.0?os_distro=bullseye&os_name=debian&os_version=11": []}
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual("pkg:something", res[0].component)
        self.assertEqual("1.0.0", res[0].versionAffected)
        self.assertEqual(
            "os_distro=bullseye&os_name=debian&os_version=11", res[0].detectedIn
        )

        # needs-triage
        p, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0]["fixedBy"] = None
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(2, len(res))
        self.assertEqual("needs-triage", res[0].status)
        self.assertEqual("unknown", res[0].versionFixed)

        # released
        p, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0]["fixedBy"] = d[
            "data"
        ]["vulnerabilitiesByPackage"][0]["purl"].split("@")[1]
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(2, len(res))
        self.assertEqual("released", res[0].status)

        # severity
        p, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0]["cvss"][
            "severity"
        ] = "unknown"
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(2, len(res))
        self.assertEqual("unknown", res[0].severity)

        # detectedIn
        p, d = self._validDockerDSOReport()
        p["pkg:something@1.0.0"].append("needle")
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(3, len(res))
        self.assertEqual("/path/1", res[0].detectedIn)
        self.assertEqual("/path/2", res[1].detectedIn)
        self.assertEqual("needle", res[2].detectedIn)

        # detectedIn - missing purl
        p, d = self._validDockerDSOReport()
        del p["pkg:something@1.0.0"]
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(1, len(res))
        self.assertEqual("unknown", res[0].detectedIn)

        # advisory
        p, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0][
            "sourceId"
        ] = "other"
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(2, len(res))
        self.assertEqual("unavailable", res[0].advisory)

        p, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0][
            "sourceId"
        ] = "GHSA-abcd"
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(2, len(res))
        self.assertEqual("https://github.com/advisories/GHSA-abcd", res[0].advisory)

        p, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0][
            "sourceId"
        ] = "GMS-abcd"
        res = cvelib.dso.parse(
            p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
        )
        self.assertEqual(2, len(res))
        self.assertEqual(
            "https://advisories.gitlab.com/?search=GMS-abcd", res[0].advisory
        )

    def test_parse_bad(self):
        """Test parse() - bad"""
        p, d = self._validDockerDSOReport()
        del d["data"]["vulnerabilitiesByPackage"][0]["purl"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.dso.parse(
                p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'purl' in" in error.getvalue().strip())

        p, d = self._validDockerDSOReport()
        del d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"]
        with tests.testutil.capturedOutput() as (output, error):
            cvelib.dso.parse(
                p, d, "https://dso.docker.com/images/foo/digests/sha256:deadbeef"
            )
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'vulnerabilities' in" in error.getvalue().strip()
        )

    def _mock_response_for_dso(self, content=None, json_data=None, status=200):
        """Build a mocked requests response

        Example:

          @mock.patch('requests.post')
          def test_...(self, mock_post):
              mr = self._mock_response_for_dso({"foo": "bar"})
              mock_post.return_value = mr
              res = foo('good')
              self.assertEqual("...", res)
        """
        # mock up a one page link for simplicity
        mr = mock.Mock()
        mr.status_code = status
        if json_data is not None:
            mr.json = mock.Mock(return_value=json_data)
        if content is not None:
            mr.content = bytes(content, "utf-8")

        return mr

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.dso.ednLoadAsDict")
    @mock.patch("requests.post")
    def test__getListEDN(self, mock_post, mock_ednLoadAsDict):
        """Test _getListEDN()"""
        # empty
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {}
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._getListEDN("valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'docker-repository-tags' as dict in response"
            in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        # bad status
        mock_post.return_value = self._mock_response_for_dso(content="", status=404)
        mock_ednLoadAsDict.return_value = {}
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._getListEDN("valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())
        self.assertEqual(0, len(res))

        # no data
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._getListEDN("valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'data' as list in response" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        # no image
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "data": [{}],
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._getListEDN("valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'image' in response for image" in error.getvalue().strip()
        )

        # no docker.image/tags
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "data": [
                    {
                        "image": {
                            "docker.image/digest": "sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
                            "docker.image/created-at": datetime.datetime(
                                2023, 8, 8, 9, 9, 9, tzinfo=datetime.timezone.utc
                            ),
                        }
                    }
                ],
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._getListEDN("valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'docker.image/tags' in response for image"
            in error.getvalue().strip()
        )

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.dso.ednLoadAsDict")
    @mock.patch("requests.post")
    def test__getTagsForRepo(self, mock_post, mock_ednLoadAsDict):
        """Test _getTagsForRepo()"""
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "data": [
                    {
                        "image": {
                            "docker.image/digest": "sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
                            "docker.image/created-at": datetime.datetime(
                                2023, 8, 7, 6, 5, 4, tzinfo=datetime.timezone.utc
                            ),
                            "docker.image/tags": [
                                "1.0-valid-name",
                                "1-valid-name",
                                "valid-name",
                            ],
                        }
                    }
                ],
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }
        res = cvelib.dso._getTagsForRepo("valid-repo")
        self.assertEqual(1, len(res))
        self.assertEqual("1.0-valid-name", res[0][0])

        # should be able to do #self.assertEqual(1691503749, res[0][1]) but
        # circleci's python gives different epoch (weird). Confirm the datetime
        # object is correct
        resdt = datetime.datetime.fromtimestamp(res[0][1])
        self.assertEqual(2023, resdt.year)
        self.assertEqual(8, resdt.month)
        self.assertEqual(7, resdt.day)
        self.assertEqual(6, resdt.hour)
        self.assertEqual(5, resdt.minute)
        self.assertEqual(4, resdt.second)

        # no date
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "data": [
                    {
                        "image": {
                            "docker.image/digest": "sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
                            "docker.image/created-at": None,
                            "docker.image/tags": [
                                "1.0-valid-name",
                                "1-valid-name",
                                "valid-name",
                            ],
                        }
                    }
                ],
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }
        res = cvelib.dso._getTagsForRepo("valid-repo")
        self.assertEqual(1, len(res))
        self.assertEqual(0, res[0][1])

        # empty
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {}
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._getTagsForRepo("valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'docker-repository-tags' as dict in response"
            in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        # no image
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "data": [{}],
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._getTagsForRepo("valid-repo")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'image' in response for image" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        # bad invocation
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with tests.testutil.capturedOutput() as (output, error):
                res = cvelib.dso._getTagsForRepo("valid-repo:dont-use-tag")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Please use REPO (without :TAG or @sha256:SHA256)"
            in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.dso.ednLoadAsDict")
    @mock.patch("requests.post")
    def test_getDigestForImage(self, mock_post, mock_ednLoadAsDict):
        """Test getDigestForImage()"""
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "data": [
                    {
                        "image": {
                            "docker.image/digest": "sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
                            "docker.image/created-at": datetime.datetime(
                                2023, 8, 8, 9, 9, 9, tzinfo=datetime.timezone.utc
                            ),
                            "docker.image/tags": [
                                "1.0-valid-name",
                                "1-valid-name",
                                "valid-name",
                            ],
                        }
                    }
                ],
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }

        # with tag
        dsr = cvelib.dso.DockerDSOSecurityReportNew()
        res = dsr.getDigestForImage("valid-repo:valid-name")
        self.assertEqual(
            "valid-repo@sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
            res,
        )

        # with sha256
        dsr = cvelib.dso.DockerDSOSecurityReportNew()
        res = dsr.getDigestForImage(
            "valid-repo@sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9"
        )
        self.assertEqual(
            "valid-repo@sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
            res,
        )

        # bare
        dsr = cvelib.dso.DockerDSOSecurityReportNew()
        res = dsr.getDigestForImage("valid-repo")
        self.assertEqual(
            "valid-repo@sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
            res,
        )

        # empty
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {}
        dsr = cvelib.dso.DockerDSOSecurityReportNew()
        with tests.testutil.capturedOutput() as (output, error):
            res = dsr.getDigestForImage("valid-repo:valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'docker-repository-tags' as dict in response"
            in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        # no image
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "data": [{}],
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }
        dsr = cvelib.dso.DockerDSOSecurityReportNew()
        with tests.testutil.capturedOutput() as (output, error):
            res = dsr.getDigestForImage("valid-repo:valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'image' in response for image" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))

        # empty tags
        mock_post.return_value = self._mock_response_for_dso(content="edn-doc")
        mock_ednLoadAsDict.return_value = {
            "docker-repository-tags": {
                "data": [
                    {
                        "image": {
                            "docker.image/digest": "sha256:af27abadb0a5e58b01e58806a02aca8c46d4c2b0823d6077d13de7ade017e9a9",
                            "docker.image/created-at": datetime.datetime(
                                2023, 8, 8, 9, 9, 9, tzinfo=datetime.timezone.utc
                            ),
                            "docker.image/tags": [],
                        }
                    }
                ],
                "basis-t": "12345678",
                "tx": "12345678901234",
            },
            "extensions": {
                "x-atomist-correlation-id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"
            },
        }
        with tests.testutil.capturedOutput() as (output, error):
            res = dsr.getDigestForImage("valid-repo:valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())
        self.assertEqual(0, len(res))

    def test_parseImageDigest(self):
        """Test parseImageDigest"""
        tsts = [
            # org, repo, sha256, expErr
            ("", "valid-name", "sha256:deadbeef", ""),
            ("ignored", "valid-name", "sha256:deadbeef", ""),
            ("", "valid-name", "bad", "does not contain '@sha256:"),
            ("", "valid-name", "@sha256:@", "should have 1 '@'"),
        ]
        dsr = cvelib.dso.DockerDSOSecurityReportNew()
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            for org, repo, sha, expErr in tsts:
                digest = "%s@%s" % (repo, sha)
                with tests.testutil.capturedOutput() as (output, error):
                    r1, r2, r3 = dsr.parseImageDigest(digest)

                self.assertEqual("", output.getvalue().strip())
                if expErr != "":
                    self.assertEqual("", r1)
                    self.assertEqual("", r2)
                    self.assertEqual("", r3)
                    self.assertTrue(expErr in error.getvalue().strip())
                else:
                    self.assertEqual("", output.getvalue().strip())
                    self.assertEqual("", error.getvalue().strip())
                    self.assertEqual("", r1)
                    self.assertEqual(repo, r2)
                    self.assertEqual(sha, r3)

    def test_getFetchResult(self):
        """Test getFetchResult()"""
        # good
        tsts = [
            # msg, exp
            ("No scan results", cvelib.scan.SecurityReportFetchResult.EMPTY),
            ("No problems found", cvelib.scan.SecurityReportFetchResult.CLEAN),
        ]

        dsr = cvelib.dso.DockerDSOSecurityReportNew()
        for msg, exp in tsts:
            res = dsr.getFetchResult(msg)
            self.assertEqual(exp, res)

        with self.assertRaises(ValueError) as context:
            dsr.getFetchResult("nonexistent")
        self.assertEqual(
            "unsupported error message: nonexistent", str(context.exception)
        )

    @mock.patch("requests.post")
    def test__fetchPackageURLs(self, mock_post):
        """Test _fetchPackageURLs()"""
        self.maxDiff = 2048

        mock_post.return_value = self._mock_response_for_dso(
            json_data=self._validDockerDSOPackageURLs()
        )
        res = cvelib.dso._fetchPackageURLs("deadbeef")
        self.assertEqual(1, len(res))
        expKey = "pkg:something@1.0.0"
        self.assertEqual(list(res.keys())[0], expKey)
        self.assertEqual(2, len(res[expKey]))
        self.assertTrue("/path/1" in res[expKey])
        self.assertTrue("/path/2" in res[expKey])

        # empty
        d = self._validDockerDSOPackageURLs()
        del d["data"]
        mock_post.return_value = self._mock_response_for_dso(json_data=d)
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._fetchPackageURLs("deadbeef")
        self.assertEqual(0, len(res))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'data' as dict in response" in error.getvalue().strip()
        )

        # no imagePackagesByDigest
        d = self._validDockerDSOPackageURLs()
        del d["data"]["imagePackagesByDigest"]
        mock_post.return_value = self._mock_response_for_dso(json_data=d)
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._fetchPackageURLs("deadbeef")
        self.assertEqual(0, len(res))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'imagePackagesByDigest' as dict in response"
            in error.getvalue().strip()
        )

        # no imagePackages
        d = self._validDockerDSOPackageURLs()
        del d["data"]["imagePackagesByDigest"]["imagePackages"]
        mock_post.return_value = self._mock_response_for_dso(json_data=d)
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._fetchPackageURLs("deadbeef")
        self.assertEqual(0, len(res))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'imagePackages' as dict in response"
            in error.getvalue().strip()
        )

        # no packages
        d = self._validDockerDSOPackageURLs()
        del d["data"]["imagePackagesByDigest"]["imagePackages"]["packages"]
        mock_post.return_value = self._mock_response_for_dso(json_data=d)
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._fetchPackageURLs("deadbeef")
        self.assertEqual(0, len(res))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'packages' as list in response" in error.getvalue().strip()
        )

        # bad status
        mock_post.return_value = self._mock_response_for_dso(status=404)
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._fetchPackageURLs("deadbeef")
        self.assertEqual(0, len(res))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())

    @mock.patch("requests.post")
    def test__fetchVulnReports(self, mock_post):
        """Test _fetchVulnReports()"""
        self.maxDiff = 2048
        purls, d = self._validDockerDSOReport()
        mock_post.return_value = self._mock_response_for_dso(json_data=d)
        res = cvelib.dso._fetchVulnReports(list(purls.keys()))
        self.assertEqual(1, len(res["data"]["vulnerabilitiesByPackage"]))
        self.assertEqual(
            "pkg:something@1.0.0", res["data"]["vulnerabilitiesByPackage"][0]["purl"]
        )
        self.assertEqual(
            1, len(res["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"])
        )
        self.assertEqual(
            "1.0.1",
            res["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0]["fixedBy"],
        )

        # bad request
        mock_post.return_value = self._mock_response_for_dso(status=404)
        with tests.testutil.capturedOutput() as (output, error):
            res = cvelib.dso._fetchVulnReports(list(purls.keys()))
        self.assertEqual(0, len(res))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not fetch" in error.getvalue().strip())

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.dso._fetchVulnReports")
    @mock.patch("requests.post")
    def test_fetchScanReport(self, mock_post, mock_fetchVulnReports):
        """Test fetchScanReport()"""
        mock_post.return_value = self._mock_response_for_dso(
            json_data=self._validDockerDSOPackageURLs()
        )
        _, d = self._validDockerDSOReport()
        mock_fetchVulnReports.return_value = d
        dsr = cvelib.dso.DockerDSOSecurityReportNew()
        res, resMsg = dsr.fetchScanReport("valid-name@sha256:deadbeef")
        self.assertEqual("", resMsg)
        self.assertEqual(2, len(res))
        self.assertEqual("pkg:something", res[0].component)
        self.assertEqual("/path/1", res[0].detectedIn)
        self.assertEqual(
            "https://www.cve.org/CVERecord?id=CVE-2021-44716",
            res[0].advisory,
        )
        self.assertEqual("1.0.0", res[0].versionAffected)
        self.assertEqual("1.0.1", res[0].versionFixed)
        self.assertEqual("high", res[0].severity)
        self.assertEqual("needed", res[0].status)
        self.assertEqual(
            "https://dso.docker.com/images/valid-name/digests/sha256:deadbeef",
            res[0].url,
        )
        self.assertEqual("pkg:something", res[1].component)
        self.assertEqual("/path/2", res[1].detectedIn)
        self.assertEqual(
            "https://www.cve.org/CVERecord?id=CVE-2021-44716",
            res[1].advisory,
        )
        self.assertEqual("1.0.0", res[1].versionAffected)
        self.assertEqual("1.0.1", res[1].versionFixed)
        self.assertEqual("high", res[1].severity)
        self.assertEqual("needed", res[1].status)
        self.assertEqual(
            "https://dso.docker.com/images/valid-name/digests/sha256:deadbeef",
            res[1].url,
        )

        # fixable=False
        mock_post.return_value = self._mock_response_for_dso(
            json_data=self._validDockerDSOPackageURLs()
        )
        _, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0]["fixedBy"] = None
        mock_fetchVulnReports.return_value = d
        res, resMsg = dsr.fetchScanReport("valid-name@sha256:deadbeef", fixable=False)
        self.assertEqual("", resMsg)
        self.assertEqual(2, len(res))
        self.assertEqual("pkg:something", res[0].component)
        self.assertEqual("1.0.0", res[0].versionAffected)
        self.assertEqual("unknown", res[0].versionFixed)
        self.assertEqual("/path/1", res[0].detectedIn)
        self.assertEqual("pkg:something", res[1].component)
        self.assertEqual("1.0.0", res[1].versionAffected)
        self.assertEqual("unknown", res[1].versionFixed)
        self.assertEqual("/path/2", res[1].detectedIn)

        # fixable=True
        res, resMsg = dsr.fetchScanReport("valid-name@sha256:deadbeef", fixable=True)
        self.assertEqual(0, len(res))
        self.assertEqual("No problems found", resMsg)

        # priorities
        _, d = self._validDockerDSOReport()
        mock_fetchVulnReports.return_value = d
        res, resMsg = dsr.fetchScanReport(
            "valid-name@sha256:deadbeef",
            priorities=["negligible"],
        )
        self.assertEqual(0, len(res))
        self.assertEqual("No problems found", resMsg)

        # priorities - present
        mock_post.return_value = self._mock_response_for_dso(
            json_data=self._validDockerDSOPackageURLs()
        )
        _, d = self._validDockerDSOReport()
        d["data"]["vulnerabilitiesByPackage"][0]["vulnerabilities"][0]["cvss"][
            "severity"
        ] = "NEGLIGIBLE"
        mock_fetchVulnReports.return_value = d
        res, resMsg = dsr.fetchScanReport(
            "valid-name@sha256:deadbeef",
            priorities=["negligible"],
        )
        self.assertEqual("", resMsg)
        self.assertEqual(2, len(res))
        self.assertEqual("pkg:something", res[0].component)
        self.assertEqual("negligible", res[0].severity)
        self.assertEqual("pkg:something", res[1].component)
        self.assertEqual("negligible", res[1].severity)

        # raw
        mock_post.return_value = self._mock_response_for_dso(
            json_data=self._validDockerDSOPackageURLs()
        )
        _, d = self._validDockerDSOReport()
        res, resMsg = dsr.fetchScanReport("valid-name@sha256:deadbeef", raw=True)
        exp = '"purl": "pkg:something@1.0.0",'
        self.assertEqual(0, len(res))
        self.assertTrue(exp in resMsg)

        # bad invocation
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = dsr.fetchScanReport("valid-name")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Please use REPO@sha256:SHA256" in error.getvalue().strip())
        self.assertEqual(0, len(res))
        self.assertEqual("", resMsg)

        # bad responses
        mock_post.return_value = self._mock_response_for_dso(
            json_data=self._validDockerDSOPackageURLs()
        )
        _, d = self._validDockerDSOReport()
        del d["data"]
        mock_fetchVulnReports.return_value = d
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = dsr.fetchScanReport("valid-name@sha256:deadbeef")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Could not find 'data' in" in error.getvalue().strip())
        self.assertEqual(0, len(res))
        self.assertEqual("", resMsg)

        mock_post.return_value = self._mock_response_for_dso(
            json_data=self._validDockerDSOPackageURLs()
        )
        _, d = self._validDockerDSOReport()
        del d["data"]["vulnerabilitiesByPackage"]
        mock_fetchVulnReports.return_value = d
        with tests.testutil.capturedOutput() as (output, error):
            res, resMsg = dsr.fetchScanReport("valid-name@sha256:deadbeef")
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not find 'vulnerabilitiesByPackage' in" in error.getvalue().strip()
        )
        self.assertEqual(0, len(res))
        self.assertEqual("", resMsg)

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.dso.DockerDSOSecurityReportNew.fetchScanReport")
    @mock.patch("cvelib.dso.DockerDSOSecurityReportNew.getDigestForImage")
    @mock.patch("cvelib.dso._getTagsForRepo")
    def test_main_dso_dump_reports(
        self,
        mock__getTagsForRepo,
        mock_getDigestForImage,
        mock_fetchScanReport,
    ):
        """Test test_main_dso_dump_reports()"""
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")

        mock__getTagsForRepo.return_value = [("valid-name", 1684472852)]
        mock_getDigestForImage.return_value = "valid-name@sha256:deadbeef"
        mock_fetchScanReport.return_value = (
            [],
            '{"data": {"vulnerabilitiesByPackage": []}, "extensions": {"correlation_id": "81e2aee7-13d1-4097-93aa-90841e5bd43b"}}',
        )

        # create
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-repo",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.dso.main_dso_dump_reports()

        today = datetime.datetime.now()
        fn = self.tmpdir + "/subdir/%d/%0.2d/%0.2d/dso/valid-repo/deadbeef.json" % (
            today.year,
            today.month,
            today.day,
        )
        relfn = os.path.relpath(fn, self.tmpdir + "/subdir")
        self.assertEqual("Created: %s" % relfn, output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())
        self.assertTrue(os.path.exists(fn))
        with open(fn, "r") as fh:
            j = json.load(fh)
            self.assertTrue("extensions" in j)
            self.assertFalse("correlation_id" in j)

        # updated
        with open(fn, "w") as fh:
            fh.write('{"data": {"vulnerabilitiesByPackage": []}, "some": "thing"}')
        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-repo",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.dso.main_dso_dump_reports()
        relfn = os.path.relpath(fn, self.tmpdir + "/subdir")
        self.assertEqual("Updated: %s" % relfn, output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())
        os.unlink(fn)

        # duplicate (write out equivalent of json.dumps(..., sort_keys=True))
        fn = self.tmpdir + "/subdir/YYYY/MM/DD/dso/valid-repo/deadbeef.json"
        os.makedirs(os.path.dirname(fn))
        with open(fn, "w") as fh:
            fh.write(
                '{\n  "data": {\n    "vulnerabilitiesByPackage": []\n  },\n  "extensions": {}\n}\n'
            )
        fn2 = self.tmpdir + "/subdir/YYYY/MM/dd/dso/valid-repo/deadbeef.json"
        os.makedirs(os.path.dirname(fn2))
        with open(fn2, "w") as fh:
            fh.write(
                '{\n  "data": {\n    "vulnerabilitiesByPackage": []\n  },\n  "extensions": {}\n}\n'
            )

        with mock.patch(
            "argparse._sys.argv",
            [
                "_",
                "--path",
                self.tmpdir + "/subdir",
                "--name",
                "valid-repo",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.dso.main_dso_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("Found duplicate" in error.getvalue().strip())

    # Note, these are listed in reverse order ot the arguments to test_...
    @mock.patch("cvelib.dso.DockerDSOSecurityReportNew.fetchScanReport")
    @mock.patch("cvelib.dso.DockerDSOSecurityReportNew.getDigestForImage")
    @mock.patch("cvelib.dso._getTagsForRepo")
    def test_main_dso_dump_reports_bad(
        self,
        mock__getTagsForRepo,
        mock_getDigestForImage,
        mock_fetchScanReport,
    ):
        """Test test_dso_main_dump_reports()"""
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")

        # no image names
        mock__getTagsForRepo.return_value = []
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
                    "valid-repo",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.dso.main_dso_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "Could not enumerate any OCI image names" in error.getvalue().strip()
        )

        # no digests
        mock__getTagsForRepo.return_value = [("valid-name", 1684472852)]
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
                    "valid-repo",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.dso.main_dso_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            "WARN: Could not find digest for valid-repo" in error.getvalue().strip(),
        )
        self.assertTrue(
            "Could not find any OCI image digests" in error.getvalue().strip(),
        )

        mock__getTagsForRepo.return_value = [("valid-name", 1684472852)]
        mock_getDigestForImage.return_value = "valid-name@sha256:deadbeef"
        mock_fetchScanReport.return_value = [], ""
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
                    "valid-repo",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.dso.main_dso_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("No new security reports" in error.getvalue().strip())

        # unsupported scan status
        mock__getTagsForRepo.return_value = [("valid-name", 1684472852)]
        mock_getDigestForImage.return_value = "valid-name@sha256:deadbeef"
        mock_fetchScanReport.return_value = ([], '{"data": null}')
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
                    "valid-repo",
                ],
            ):
                with tests.testutil.capturedOutput() as (output, error):
                    cvelib.dso.main_dso_dump_reports()
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("No new security reports" in error.getvalue().strip())
        self.assertTrue("unexpected format of report for" in error.getvalue().strip())

    @skipIf(not _edn_format_available(), "edn_format not available")
    def test_ednLoadAsDict(self):
        """Test ednLoadAsDict()"""
        # good
        res = cvelib.dso.ednLoadAsDict(bytes('{ :foo [ "bar" 3 ] }', "utf-8"))
        self.assertTrue("foo" in res)
        self.assertEqual(2, len(res["foo"]))
        self.assertTrue("bar" in res["foo"])
        self.assertTrue(3 in res["foo"])

        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with tests.testutil.capturedOutput() as (output, error):
                res = cvelib.dso.ednLoadAsDict(bytes('[ "bar" 3 ]', "utf-8"))
        self.assertEqual("", output.getvalue().strip())
        self.assertTrue("EDN document is not a dictionary" in error.getvalue().strip())
