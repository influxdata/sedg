"""test_scan.py: tests for scan.py module"""

#
# SPDX-License-Identifier: MIT

import copy
import datetime
from unittest import TestCase

import cvelib.common
import cvelib.github
import cvelib.scan


class TestScanOCI(TestCase):
    """Tests for the scan report OCI data and functions"""

    def setUp(self):
        """Setup functions common for all tests"""

    def tearDown(self):
        """Teardown functions common for all tests"""

    def _getValid(self):
        """Returns a valid data structure"""
        return {
            "component": "foo",
            "detectedIn": "Distro 1.0",
            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
            "version": "1.2.2",
            "fixedBy": "1.2.3",
            "severity": "medium",
            "status": "needed",
            "url": "https://blah.com/BAR-a",
        }

    def test___repr__(self):
        """Test __repr__()"""
        self.maxDiff = 2048
        data = self._getValid()
        exp = """ - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a"""

        sm = cvelib.scan.ScanOCI(data)
        self.assertEqual(exp, sm.__repr__())

    def test___str__(self):
        """Test __str__()"""
        data = self._getValid()
        exp = """ - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a"""

        sm = cvelib.scan.ScanOCI(data)
        self.assertEqual(exp, sm.__str__())

    def test__verifyRequired(self):
        """Test _verifyRequired()"""
        tsts = [
            # valid
            (self._getValid(), None),
            # invalid
            (
                {
                    "cmponent": "foo",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "missing required field 'component'",
            ),
            (
                {
                    "component": "foo",
                    "dtectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "missing required field 'detectedIn'",
            ),
            (
                {
                    "component": "foo",
                    "detectedIn": "Distro 1.0",
                    "avisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "missing required field 'advisory'",
            ),
            (
                {
                    "component": "foo",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "vrsion": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "missing required field 'version'",
            ),
            (
                {
                    "component": "foo",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fxedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "missing required field 'fixedBy'",
            ),
            (
                {
                    "component": "foo",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "sverity": "medium",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "missing required field 'severity'",
            ),
            (
                {
                    "component": "foo",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "satus": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "missing required field 'status'",
            ),
            (
                {
                    "component": "foo",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "rl": "https://blah.com/BAR-a",
                },
                "missing required field 'url'",
            ),
            (
                {
                    "component": "",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "empty required field 'component'",
            ),
            (
                {
                    "component": "foo\nbar",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                },
                "field 'component' should be single line",
            ),
        ]

        for data, expErr in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            if expErr is None:
                sm._verifyRequired(data)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    sm._verifyRequired(data)
                self.assertEqual(expErr, str(context.exception))

    def test_setComponent(self):
        """Test setComponent()"""
        tsts = [
            # valid, exp
            ("foo", "foo"),
            ("foo trailing ", "foo trailing"),
        ]

        for s, exp in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            sm.setComponent(s)
            self.assertEqual(exp, sm.component)

    def test_setDetectedIn(self):
        """Test setDetectedIn()"""
        tsts = [
            # valid, exp
            ("foo", "foo"),
            ("foo trailing ", "foo trailing"),
        ]

        for s, exp in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            sm.setDetectedIn(s)
            self.assertEqual(exp, sm.detectedIn)

    def test_setSeverity(self):
        """Test setSeverity()"""
        tsts = [
            # valid
            ("critical", None),
            ("high", None),
            ("medium", None),
            ("low", None),
            ("negligible", None),
            ("unknown", None),
            # invalid
            ("foo", "invalid severity: foo"),
        ]

        for s, expErr in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            if expErr is None:
                sm.setSeverity(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    sm.setSeverity(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setVersionAffected(self):
        """Test setVersionAffected()"""
        tsts = [
            # valid, exp
            ("foo", "foo"),
            ("foo trailing ", "foo trailing"),
        ]

        for s, exp in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            sm.setVersionAffected(s)
            self.assertEqual(exp, sm.versionAffected)

    def test_setVersionFixed(self):
        """Test setVersionFixed()"""
        tsts = [
            # valid, exp
            ("foo", "foo"),
            ("foo trailing ", "foo trailing"),
        ]

        for s, exp in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            sm.setVersionFixed(s)
            self.assertEqual(exp, sm.versionFixed)

    def test_setStatus(self):
        """Test setStatus()"""
        tsts = [
            # valid
            ("needs-triage", None),
            ("needed", None),
            ("released", None),
            ("dismissed (tolerable; baz)", None),
            ("dismissed (code-not-used; baz)", None),
            # invalid
            (
                "foo",
                "invalid status: foo. Use 'needs-triage|needed|released|dismissed (...)'",
            ),
            (
                "dismissed",
                "invalid status: dismissed. Use 'dismissed (tolerable|code-not-used; <username>)'",
            ),
        ]

        for s, expErr in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            if expErr is None:
                sm.setStatus(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    sm.setStatus(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setAdvisory(self):
        """Test setAdvisory()"""
        tsts = [
            # valid, exp, expErr
            ("https://foo", "https://foo", None),
            ("https://foo ", "https://foo", None),
            ("unavailable", "unavailable", None),
            # invalid
            ("foo", "", "invalid advisory url: foo"),
        ]

        for s, exp, expErr in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            if expErr is None:
                sm.setAdvisory(s)
                self.assertEqual(exp, sm.advisory)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    sm.setAdvisory(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setUrl(self):
        """Test setUrl()"""
        tsts = [
            # valid, exp, expErr
            ("https://foo", "https://foo", None),
            ("https://foo ", "https://foo", None),
            ("unavailable", "unavailable", None),
            # invalid
            ("foo", "", "invalid url: foo"),
        ]

        for s, exp, expErr in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            if expErr is None:
                sm.setUrl(s)
                self.assertEqual(exp, sm.url)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    sm.setUrl(s)
                self.assertEqual(expErr, str(context.exception))


class TestScanCommon(TestCase):
    """Tests for the scan report common functions"""

    def setUp(self):
        """Setup functions common for all tests"""

    def tearDown(self):
        """Teardown functions common for all tests"""

    def _getValidYaml(self):
        """Returns a valid data structure"""
        return """ - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
 - type: oci
   component: baz
   detectedIn: Distro 2.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0002
   version: 2.3.3
   fixedBy: 2.3.4
   severity: medium
   status: needed
   url: https://blah.com/NORF-a
 - type: oci
   component: corge
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0003
   version: 9.2.0-4
   fixedBy: 9.2.0-5
   severity: high
   status: released
   url: https://blah.com/CORGE-a
"""

    def test_matches(self):
        """Test matches()"""
        a_data = {
            "component": "foo",
            "detectedIn": "Some Distro",
            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
            "version": "1.2.2",
            "fixedBy": "1.2.3",
            "severity": "medium",
            "status": "needed",
            "url": "https://blah.com/BAR-a",
        }
        a = cvelib.scan.ScanOCI(a_data)

        b_same = copy.deepcopy(a_data)
        b_diff = copy.deepcopy(a_data)
        b_diff["component"] = "other"
        b_imprecise = copy.deepcopy(a_data)
        b_imprecise["severity"] = "high"
        b_close = copy.deepcopy(a_data)
        b_close["status"] = "needs-triage"

        tsts = [
            # a, b, expectedFuzzy, expectedPrecise
            (a, cvelib.scan.ScanOCI(b_same), True, True),
            (a, cvelib.scan.ScanOCI(b_close), True, True),
            (
                a,
                cvelib.scan.ScanOCI(b_imprecise),
                True,
                False,
            ),
            (a, cvelib.scan.ScanOCI(b_diff), False, False),
        ]

        for a, b, expF, expP in tsts:
            f, p = a.matches(b)
            self.assertEqual(expF, f)
            self.assertEqual(expP, p)

    def test_diff(self):
        """Test diff()"""
        a_data = {
            "component": "foo",
            "detectedIn": "Some Distro",
            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
            "version": "1.2.2",
            "fixedBy": "1.2.3",
            "severity": "medium",
            "status": "needed",
            "url": "https://blah.com/BAR-a",
        }
        a = cvelib.scan.ScanOCI(a_data)

        b_same = copy.deepcopy(a_data)
        b_diff = copy.deepcopy(a_data)
        b_diff["fixedBy"] = "1.2.4"
        b_diff["severity"] = "low"
        b_diff["status"] = "needs-triage"

        tsts = [
            # a, b, precise, expected
            (
                a,
                cvelib.scan.ScanOCI(b_same),
                False,
                """ - type: oci
   component: foo
   detectedIn: Some Distro
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a""",
            ),
            (
                a,
                cvelib.scan.ScanOCI(b_diff),
                False,
                """ - type: oci
   component: foo
   detectedIn: Some Distro
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
-  fixedBy: 1.2.3
+  fixedBy: 1.2.4
-  severity: medium
+  severity: low
   status: needed
   url: https://blah.com/BAR-a""",
            ),
            (
                a,
                cvelib.scan.ScanOCI(b_diff),
                True,
                """ - type: oci
   component: foo
   detectedIn: Some Distro
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
-  fixedBy: 1.2.3
+  fixedBy: 1.2.4
-  severity: medium
+  severity: low
-  status: needed
+  status: needs-triage
   url: https://blah.com/BAR-a""",
            ),
        ]

        for a, b, precise, exp in tsts:
            res = a.diff(b, precise=precise)
            self.assertEqual(exp, res, msg=res)

    def test_parse(self):
        """Test parse()"""
        tsts = [
            # valid
            (self._getValidYaml(), None),
            ("", None),
            # invalid
            (None, "invalid yaml:\n'None'"),
            ("bad", "invalid Scan-Reports document: 'type' missing for item"),
            (
                """ - type: other
   foo: bar
   baz: norf""",
                "invalid Scan-Reports document: unknown type 'other'",
            ),
        ]

        for s, expErr in tsts:
            if expErr is None:
                res = cvelib.scan.parse(s)
                if s == "":
                    self.assertEqual(0, len(res))
                else:
                    self.assertEqual(3, len(res))
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.scan.parse(s)
                self.assertEqual(expErr, str(context.exception))

    def test_combineLikeOCIs(self):
        """Test combineLikeOCIs()"""
        a_data = {
            "component": "foo",
            "detectedIn": "Some Distro",
            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
            "version": "1.2.2",
            "fixedBy": "1.2.3",
            "severity": "medium",
            "status": "needed",
            "url": "https://blah.com/BAR-a",
        }
        b_data = {
            "component": "other",
            "detectedIn": "Some Distro",
            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0002",
            "version": "9.8.7",
            "fixedBy": "9.8.8",
            "severity": "medium",
            "status": "needed",
            "url": "https://blah.com/BAZ-a",
        }
        c_data = {
            "component": "libfoo",
            "detectedIn": "Some Distro",
            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
            "version": "1.2.2",
            "fixedBy": "1.2.3",
            "severity": "medium",
            "status": "needed",
            "url": "https://blah.com/BAR-a",
        }
        # ocis, expected number, component1, adv1, component1, adv2
        tsts = [
            (
                [cvelib.scan.ScanOCI(a_data)],
                1,
                "foo",
                "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                "",
                "",
            ),
            (
                [cvelib.scan.ScanOCI(a_data), cvelib.scan.ScanOCI(b_data)],
                2,
                "foo",
                "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                "other",
                "https://www.cve.org/CVERecord?id=CVE-2023-0002",
            ),
            (
                [
                    cvelib.scan.ScanOCI(a_data),
                    cvelib.scan.ScanOCI(b_data),
                    cvelib.scan.ScanOCI(c_data),
                ],
                2,
                "foo, libfoo",
                "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                "other",
                "https://www.cve.org/CVERecord?id=CVE-2023-0002",
            ),
        ]

        for ocis, expN, expComp1, expAdv1, expComp2, expAdv2 in tsts:
            res = cvelib.scan.combineLikeOCIs(ocis)
            self.assertEqual(expN, len(res))
            self.assertEqual(expAdv1, res[0].advisory)
            self.assertEqual(expComp1, res[0].component)
            if expAdv2 != "":
                self.assertEqual(expAdv2, res[1].advisory)
            if expComp2 != "":
                self.assertEqual(expComp2, res[1].component)

    def _getValidOCIs(self):
        """Returns valid list of ScanOCIs"""
        return [
            cvelib.scan.ScanOCI(
                {
                    "component": "foo",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                    "version": "1.2.2",
                    "fixedBy": "1.2.2",
                    "severity": "low",
                    "status": "released",
                    "url": "https://blah.com/BAR-a",
                }
            ),
            cvelib.scan.ScanOCI(
                {
                    "component": "foo",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0002",
                    "version": "1.2.2",
                    "fixedBy": "1.2.3",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://blah.com/BAR-a",
                }
            ),
            cvelib.scan.ScanOCI(
                {
                    "component": "baz",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0003",
                    "version": "2.3.4",
                    "fixedBy": "unavailable",
                    "severity": "high",
                    "status": "needs-triage",
                    "url": "https://blah.com/BAR-a",
                }
            ),
            cvelib.scan.ScanOCI(
                {
                    "component": "norf",
                    "detectedIn": "Distro 1.0",
                    "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0004",
                    "version": "2.3.4",
                    "fixedBy": "2.3.4",
                    "severity": "negligible",
                    "status": "released",
                    "url": "https://blah.com/BAR-a",
                }
            ),
        ]

    def test_getScanOCIsReportUnused(self):
        """Test getScanOCIsReportUnused()"""
        tsts = [
            ([], False, ""),
            ([], True, ""),
            (
                self._getValidOCIs(),
                False,
                "baz  2.3.4 n/a (high)\nfoo  1.2.2 needed (low,medium)\nnorf 2.3.4 released (negligible)",
            ),
            (self._getValidOCIs(), True, "foo  1.2.2 needed (low,medium)"),
        ]

        for ocis, fixable, exp in tsts:
            res = cvelib.scan.getScanOCIsReportUnused(ocis, fixable=fixable)
            self.assertEqual(exp, res)

    def test_formatWhereFromOCIType(self):
        """Test formatWhereFromFromOCIType()"""
        tsts = [
            # oci_type, namespace, where_override, exp
            ("", "", "", "unknown"),
            ("other", "", "", "unknown"),
            ("other", "", "ovr", "ovr"),
            ("other", "blah", "", "unknown"),
            ("other", "blah", "ovr", "ovr"),
            ("gar", "proj/us", "", "gar-us.proj"),
            ("gar", "proj/us-west1", "", "gar-us-west1.proj"),
            ("gar", "proj/us", "ovr", "gar-ovr"),
            ("quay", "org", "", "quay-org"),
            ("quay", "org", "ovr", "quay-ovr"),
            ("dso", "", "", "dockerhub"),
            ("dso", "", "ovr", "dockerhub-ovr"),
            ("other", "b@d", "", "unknown"),
            ("other", "", "b@d", "unknown"),
        ]

        for oci_type, ns, whr, exp in tsts:
            res = cvelib.scan.formatWhereFromOCIType(oci_type, ns, whr)
            self.assertEqual(exp, res)

    def test__parseScanURL(self):
        """Test _parseScanURL()"""
        tsts = [
            # url, where_override, expProduct, expWhere, expSoftware, expModifier
            ("", "", "", "", "", ""),
            ("https://other", "", "oci", "unknown", "TBD", ""),
            ("https://other", "some-override", "oci", "some-override", "TBD", ""),
            ("unavailable", "", "oci", "unknown", "TBD", ""),
            (
                "https://us-docker.pkg.dev/project/REPO/IMGNAME@sha256:deadbeef",
                "",
                "oci",
                "gar-us.project",
                "REPO",
                "IMGNAME",
            ),
            (
                "https://us-west1-docker.pkg.dev/project/REPO/IMGNAME@sha256:deadbeef",
                "",
                "oci",
                "gar-us-west1.project",
                "REPO",
                "IMGNAME",
            ),
            (
                "https://us-docker.pkg.dev/project/REPO/IMGNAME@sha256:deadbeef",
                "proj-override",
                "oci",
                "gar-proj-override",
                "REPO",
                "IMGNAME",
            ),
            (
                "https://quay.io/repository/org/IMGNAME/manifest/sha256:deadbeef",
                "",
                "oci",
                "quay-org",
                "IMGNAME",
                "",
            ),
            (
                "https://quay.io/repository/org/IMGNAME/manifest/sha256:deadbeef",
                "org-override",
                "oci",
                "quay-org-override",
                "IMGNAME",
                "",
            ),
            (
                "https://dso.docker.com/images/IMGNAME/digests/sha256:deadbeef",
                "",
                "oci",
                "dockerhub",
                "IMGNAME",
                "",
            ),
            (
                "https://dso.docker.com/images/IMGNAME/digests/sha256:deadbeef",
                "override",
                "oci",
                "dockerhub-override",
                "IMGNAME",
                "",
            ),
        ]

        for url, whr, expP, expW, expS, expM in tsts:
            (resP, resW, resS, resM) = cvelib.scan._parseScanURL(
                url, where_override=whr
            )
            self.assertEqual(expP, resP, msg="url=%s" % url)
            self.assertEqual(expW, resW, msg="url=%s" % url)
            self.assertEqual(expS, resS, msg="url=%s" % url)
            self.assertEqual(expM, resM, msg="url=%s" % url)

    def test_parseNsAndImageToPkg(self):
        """Test parseNsAndImageToPkg()"""
        tsts = [
            # oci_type, ns, img, where_override, expProduct, expWhere,
            # expSoftware, expModifier
            ("", "", "", "", "", "", "", ""),
            ("gar", "foo/loc", "bar/baz", "", "oci", "gar-loc.foo", "bar", "baz"),
            ("gar", "foo/loc", "bar/baz", "ovr", "oci", "gar-ovr", "bar", "baz"),
            ("quay", "foo", "bar", "", "oci", "quay-foo", "bar", ""),
            ("quay", "foo", "bar", "ovr", "oci", "quay-ovr", "bar", ""),
            ("dso", "", "bar", "", "oci", "dockerhub", "bar", ""),
            ("dso", "", "bar", "ovr", "oci", "dockerhub-ovr", "bar", ""),
        ]

        for oci_type, ns, img, whr, expP, expW, expS, expM in tsts:
            (resP, resW, resS, resM) = cvelib.scan.parseNsAndImageToPkg(
                oci_type, ns, img, where_override=whr
            )
            self.assertEqual(
                expP, resP, msg="oci_type=%s, ns=%s, img=%s" % (oci_type, ns, img)
            )
            self.assertEqual(
                expW, resW, msg="oci_type=%s, ns=%s, img=%s" % (oci_type, ns, img)
            )
            self.assertEqual(
                expS, resS, msg="oci_type=%s, ns=%s, img=%s" % (oci_type, ns, img)
            )
            self.assertEqual(
                expM, resM, msg="oci_type=%s, ns=%s, img=%s" % (oci_type, ns, img)
            )

    def test_parseNsAndImageToURLPattern(self):
        """Test parseNsAndImageToURLPattern()"""
        tsts = [
            # oci_type, ns, img, where_override, matchStr, matches
            (
                "gar",
                "foo/loc",
                "bar/baz",
                "",
                "https://loc-docker.pkg.dev/foo/bar/baz@sha256:deadbeef",
                True,
            ),
            (
                "gar",
                "foo/loc",
                "bar/baz",
                "",
                "https://other-loc-docker.pkg.dev/other-proj/bar/baz@sha256:deadbeef",
                False,
            ),
            (
                "gar",
                "foo/loc",
                "other-repo/baz",
                "",
                "https://loc-docker.pkg.dev/foo/bar/baz@sha256:deadbeef",
                False,
            ),
            (
                "gar",
                "foo/loc",
                "bar/other-mod",
                "",
                "https://loc-docker.pkg.dev/foo/bar/baz@sha256:deadbeef",
                False,
            ),
            (
                "gar",
                "foo/loc",
                "bar/baz",
                "ovr",
                "https://loc-docker.pkg.dev/foo/bar/baz@sha256:deadbeef",
                True,
            ),
            (
                "gar",
                "foo/loc",
                "bar/baz",
                "ovr",
                "https://other-loc-docker.pkg.dev/other-proj/bar/baz@sha256:deadbeef",
                True,
            ),
            (
                "quay",
                "foo",
                "bar",
                "",
                "https://quay.io/repository/foo/bar/manifest/sha256:deadbeef",
                True,
            ),
            (
                "quay",
                "foo",
                "bar",
                "",
                "https://quay.io/repository/other-org/bar/manifest/sha256:deadbeef",
                False,
            ),
            (
                "quay",
                "other",
                "bar",
                "",
                "https://quay.io/repository/foo/bar/manifest/sha256:deadbeef",
                False,
            ),
            (
                "quay",
                "foo",
                "other",
                "",
                "https://quay.io/repository/foo/bar/manifest/sha256:deadbeef",
                False,
            ),
            (
                "quay",
                "foo",
                "bar",
                "ovr",
                "https://quay.io/repository/foo/bar/manifest/sha256:deadbeef",
                True,
            ),
            (
                "quay",
                "foo",
                "bar",
                "ovr",
                "https://quay.io/repository/other-org/bar/manifest/sha256:deadbeef",
                True,
            ),
            (
                "dso",
                "ignored",
                "foo",
                "",
                "https://dso.docker.com/images/foo/digests/sha256:deadbeef",
                True,
            ),
            (
                "dso",
                "ignored",
                "other",
                "",
                "https://dso.docker.com/images/foo/digests/sha256:deadbeef",
                False,
            ),
            (
                "dso",
                "ignored",
                "foo",
                "ovr",
                "https://dso.docker.com/images/foo/digests/sha256:deadbeef",
                True,
            ),
            (
                "dso",
                "ignored",
                "other",
                "ovr",
                "https://dso.docker.com/images/foo/digests/sha256:deadbeef",
                False,
            ),
        ]

        for oci_type, ns, img, whr, m, exp in tsts:
            pat = cvelib.scan.parseNsAndImageToURLPattern(
                oci_type, ns, img, where_override=whr
            )
            assert pat is not None  # for pyright
            res = pat.search(m)
            if exp:
                self.assertTrue(
                    res is not None,
                    msg="oci_type=%s, ns=%s, img=%s, whr=%s" % (oci_type, ns, img, whr),
                )
            else:
                self.assertTrue(
                    res is None,
                    msg="oci_type=%s, ns=%s, img=%s, whr=%s" % (oci_type, ns, img, whr),
                )

        pat = cvelib.scan.parseNsAndImageToURLPattern("", "", "", where_override="")
        self.assertTrue(pat is None)

    def test_getScanOCIsReport(self):
        """Test getScanOCIsReport()"""
        now: datetime.datetime = datetime.datetime.now()
        self.maxDiff = 8196
        # oci_reports, scan_type, with_templates, template_urls, where_override, expected
        tsts = [
            (
                {
                    "some-repo": [
                        cvelib.scan.ScanOCI(
                            {
                                "component": "foo",
                                "detectedIn": "Distro 1.0",
                                "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                                "version": "1.2.2",
                                "fixedBy": "1.2.2",
                                "severity": "low",
                                "status": "released",
                                "url": "https://blah.com/BAR-a",
                            }
                        )
                    ]
                },
                "",
                False,
                [],
                "",
                """some-repo report: 1
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.2
   severity: low
   status: released
   url: https://blah.com/BAR-a""",
            ),
            (
                {
                    "some-repo": [
                        cvelib.scan.ScanOCI(
                            {
                                "component": "foo",
                                "detectedIn": "Distro 1.0",
                                "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0001",
                                "version": "1.2.2",
                                "fixedBy": "1.2.2",
                                "severity": "low",
                                "status": "released",
                                "url": "https://blah.com/BAR-a",
                            }
                        )
                    ]
                },
                "quay",
                True,
                [],
                "",
                """## some-repo quay.io template
Please address quay.io alert in some-repo:

The following alert was issued:
- [ ] [foo](https://www.cve.org/CVERecord?id=CVE-2023-0001) (low)

Since a 'low' severity issue is present, tentatively adding the 'security/low' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * https://blah.com/BAR-a

## end template

## some-repo CVE template
Candidate: CVE-%d-NNNN
OpenDate: %0.2d-%0.2d-%0.2d
CloseDate:
PublicDate:
CRD:
References:
 https://blah.com/BAR-a
 https://www.cve.org/CVERecord?id=CVE-2023-0001
Description:
 Please address alert in some-repo
 - [ ] foo (low)
Scan-Reports:
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.2
   severity: low
   status: released
   url: https://blah.com/BAR-a
Notes:
Mitigation:
Bugs:
Priority: low
Discovered-by: quay.io
Assigned-to:
CVSS:

Patches_TBD:
oci/unknown_TBD: needs-triage

## end CVE template

some-repo report: 1
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.2
   severity: low
   status: released
   url: https://blah.com/BAR-a"""
                % (now.year, now.year, now.month, now.day),
            ),
        ]

        for oci_reports, scan_type, with_templates, template_urls, whr, exp in tsts:
            res = cvelib.scan.getScanOCIsReport(
                oci_reports,
                scan_type,
                with_templates,
                template_urls=template_urls,
                oci_where_override=whr,
            )
            self.assertEqual(exp, res)

    def test_getScanOCIsReportTemplates(self):
        """Test test_getScanOCIsReportTemplates()"""
        now: datetime.datetime = datetime.datetime.now()
        self.maxDiff = 8196
        # alert_name, pkg_name, oci_reports, template_urls, where_override, expected
        tsts = [
            ("foo", "bar/baz", [], [], "", ""),
            (
                "foo",
                "bar/baz",
                self._getValidOCIs(),
                [],
                "",
                """## bar/baz foo template
Please address foo alerts in bar/baz:

The following alerts were issued:
- [ ] [baz](https://www.cve.org/CVERecord?id=CVE-2023-0003) (high)
- [ ] [foo](https://www.cve.org/CVERecord?id=CVE-2023-0001) (low)
- [ ] [foo](https://www.cve.org/CVERecord?id=CVE-2023-0002) (medium)
- [ ] [norf](https://www.cve.org/CVERecord?id=CVE-2023-0004) (negligible)

Since a 'high' severity issue is present, tentatively adding the 'security/high' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * https://blah.com/BAR-a

## end template

## bar/baz CVE template
Candidate: CVE-%d-NNNN
OpenDate: %0.2d-%0.2d-%0.2d
CloseDate:
PublicDate:
CRD:
References:
 https://blah.com/BAR-a
 https://www.cve.org/CVERecord?id=CVE-2023-0001
 https://www.cve.org/CVERecord?id=CVE-2023-0002
 https://www.cve.org/CVERecord?id=CVE-2023-0003
 https://www.cve.org/CVERecord?id=CVE-2023-0004
Description:
 Please address alerts in bar/baz
 - [ ] baz (high)
 - [ ] foo (low)
 - [ ] foo (medium)
 - [ ] norf (negligible)
Scan-Reports:
 - type: oci
   component: baz
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0003
   version: 2.3.4
   fixedBy: unavailable
   severity: high
   status: needs-triage
   url: https://blah.com/BAR-a
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.2
   severity: low
   status: released
   url: https://blah.com/BAR-a
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0002
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
 - type: oci
   component: norf
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0004
   version: 2.3.4
   fixedBy: 2.3.4
   severity: negligible
   status: released
   url: https://blah.com/BAR-a
Notes:
Mitigation:
Bugs:
Priority: high
Discovered-by: foo
Assigned-to:
CVSS:

Patches_TBD:
oci/unknown_TBD: needs-triage

## end CVE template"""
                % (now.year, now.year, now.month, now.day),
            ),
            (
                "foo",
                "bar/baz",
                [
                    cvelib.scan.ScanOCI(
                        {
                            "component": "foo",
                            "detectedIn": "Distro 1.0",
                            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0002",
                            "version": "1.2.2",
                            "fixedBy": "1.2.3",
                            "severity": "medium",
                            "status": "needed",
                            "url": "https://blah.com/BAR-a",
                        }
                    ),
                    cvelib.scan.ScanOCI(
                        {
                            "component": "foo",
                            "detectedIn": "Distro 1.0",
                            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0003",
                            "version": "1.2.2",
                            "fixedBy": "1.2.3",
                            "severity": "medium",
                            "status": "needed",
                            "url": "https://blah.com/BAR-a",
                        }
                    ),
                ],
                [],
                "",
                """## bar/baz foo template
Please address foo alerts in bar/baz:

The following alerts were issued:
- [ ] [foo](https://www.cve.org/CVERecord?id=CVE-2023-0002) (medium)
- [ ] [foo](https://www.cve.org/CVERecord?id=CVE-2023-0003) (medium)

Since a 'medium' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * https://blah.com/BAR-a

## end template

## bar/baz CVE template
Candidate: CVE-%d-NNNN
OpenDate: %0.2d-%0.2d-%0.2d
CloseDate:
PublicDate:
CRD:
References:
 https://blah.com/BAR-a
 https://www.cve.org/CVERecord?id=CVE-2023-0002
 https://www.cve.org/CVERecord?id=CVE-2023-0003
Description:
 Please address alerts in bar/baz
 - [ ] foo (2 medium)
Scan-Reports:
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0002
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0003
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
Notes:
Mitigation:
Bugs:
Priority: medium
Discovered-by: foo
Assigned-to:
CVSS:

Patches_TBD:
oci/unknown_TBD: needs-triage

## end CVE template"""
                % (now.year, now.year, now.month, now.day),
            ),
            (
                "gar",
                "bar/baz",
                [
                    cvelib.scan.ScanOCI(
                        {
                            "component": "foo",
                            "detectedIn": "Distro 1.0",
                            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0002",
                            "version": "1.2.2",
                            "fixedBy": "1.2.3",
                            "severity": "medium",
                            "status": "needed",
                            "url": "https://blah.com/BAR-a",
                        }
                    )
                ],
                ["https://some/url", "https://some/other/url"],
                "",
                """## bar/baz GAR template
Please address GAR alert in bar/baz:

The following alert was issued:
- [ ] [foo](https://www.cve.org/CVERecord?id=CVE-2023-0002) (medium)

Since a 'medium' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * https://some/url
 * https://some/other/url
 * https://blah.com/BAR-a

## end template

## bar/baz CVE template
Candidate: CVE-%d-NNNN
OpenDate: %0.2d-%0.2d-%0.2d
CloseDate:
PublicDate:
CRD:
References:
 https://blah.com/BAR-a
 https://www.cve.org/CVERecord?id=CVE-2023-0002
Description:
 Please address alert in bar/baz
 - [ ] foo (medium)
Scan-Reports:
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0002
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
Notes:
Mitigation:
Bugs:
Priority: medium
Discovered-by: gar
Assigned-to:
CVSS:

Patches_TBD:
oci/unknown_TBD: needs-triage

## end CVE template"""
                % (now.year, now.year, now.month, now.day),
            ),
            (
                "quay",
                "bar/baz",
                [
                    cvelib.scan.ScanOCI(
                        {
                            "component": "foo",
                            "detectedIn": "Distro 1.0",
                            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0002",
                            "version": "1.2.2",
                            "fixedBy": "1.2.3",
                            "severity": "medium",
                            "status": "needed",
                            "url": "https://blah.com/BAR-a",
                        }
                    )
                ],
                ["https://some/url", "https://some/other/url"],
                "",
                """## bar/baz quay.io template
Please address quay.io alert in bar/baz:

The following alert was issued:
- [ ] [foo](https://www.cve.org/CVERecord?id=CVE-2023-0002) (medium)

Since a 'medium' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * https://some/url
 * https://some/other/url
 * https://blah.com/BAR-a

## end template

## bar/baz CVE template
Candidate: CVE-%d-NNNN
OpenDate: %0.2d-%0.2d-%0.2d
CloseDate:
PublicDate:
CRD:
References:
 https://blah.com/BAR-a
 https://www.cve.org/CVERecord?id=CVE-2023-0002
Description:
 Please address alert in bar/baz
 - [ ] foo (medium)
Scan-Reports:
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0002
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
Notes:
Mitigation:
Bugs:
Priority: medium
Discovered-by: quay.io
Assigned-to:
CVSS:

Patches_TBD:
oci/unknown_TBD: needs-triage

## end CVE template"""
                % (now.year, now.year, now.month, now.day),
            ),
            (
                "foo",
                "bar/baz",
                [
                    cvelib.scan.ScanOCI(
                        {
                            "component": "foo",
                            "detectedIn": "Distro 1.0",
                            "advisory": "unavailable",
                            "version": "1.2.2",
                            "fixedBy": "1.2.3",
                            "severity": "medium",
                            "status": "needed",
                            "url": "https://blah.com/BAR-a",
                        }
                    )
                ],
                [],
                "",
                """## bar/baz foo template
Please address foo alert in bar/baz:

The following alert was issued:
- [ ] foo (medium)

Since a 'medium' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * https://blah.com/BAR-a

## end template

## bar/baz CVE template
Candidate: CVE-%d-NNNN
OpenDate: %0.2d-%0.2d-%0.2d
CloseDate:
PublicDate:
CRD:
References:
 https://blah.com/BAR-a
Description:
 Please address alert in bar/baz
 - [ ] foo (medium)
Scan-Reports:
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: unavailable
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
Notes:
Mitigation:
Bugs:
Priority: medium
Discovered-by: foo
Assigned-to:
CVSS:

Patches_TBD:
oci/unknown_TBD: needs-triage

## end CVE template"""
                % (now.year, now.year, now.month, now.day),
            ),
            (
                "foo",
                "bar/baz",
                [
                    cvelib.scan.ScanOCI(
                        {
                            "component": "foo",
                            "detectedIn": "Distro 1.0",
                            "advisory": "unavailable",
                            "version": "1.2.2",
                            "fixedBy": "1.2.3",
                            "severity": "unknown",
                            "status": "needed",
                            "url": "https://blah.com/BAR-a",
                        }
                    )
                ],
                [],
                "",
                """## bar/baz foo template
Please address foo alert in bar/baz:

The following alert was issued:
- [ ] foo (unknown)

Since a 'unknown' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * https://blah.com/BAR-a

## end template

## bar/baz CVE template
Candidate: CVE-%d-NNNN
OpenDate: %0.2d-%0.2d-%0.2d
CloseDate:
PublicDate:
CRD:
References:
 https://blah.com/BAR-a
Description:
 Please address alert in bar/baz
 - [ ] foo (unknown)
Scan-Reports:
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: unavailable
   version: 1.2.2
   fixedBy: 1.2.3
   severity: unknown
   status: needed
   url: https://blah.com/BAR-a
Notes:
Mitigation:
Bugs:
Priority: medium
Discovered-by: foo
Assigned-to:
CVSS:

Patches_TBD:
oci/unknown_TBD: needs-triage

## end CVE template"""
                % (now.year, now.year, now.month, now.day),
            ),
            (
                "foo",
                "bar/baz",
                [
                    cvelib.scan.ScanOCI(
                        {
                            "component": "foo",
                            "detectedIn": "Distro 1.0",
                            "advisory": "https://www.cve.org/CVERecord?id=CVE-2023-0002",
                            "version": "1.2.2",
                            "fixedBy": "1.2.3",
                            "severity": "medium",
                            "status": "needed",
                            "url": "https://blah.com/BAR-a",
                        }
                    )
                ],
                [],
                "some-override",
                """## bar/baz foo template
Please address foo alert in bar/baz:

The following alert was issued:
- [ ] [foo](https://www.cve.org/CVERecord?id=CVE-2023-0002) (medium)

Since a 'medium' severity issue is present, tentatively adding the 'security/medium' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated.

Thanks!

References:
 * https://blah.com/BAR-a

## end template

## bar/baz CVE template
Candidate: CVE-%d-NNNN
OpenDate: %0.2d-%0.2d-%0.2d
CloseDate:
PublicDate:
CRD:
References:
 https://blah.com/BAR-a
 https://www.cve.org/CVERecord?id=CVE-2023-0002
Description:
 Please address alert in bar/baz
 - [ ] foo (medium)
Scan-Reports:
 - type: oci
   component: foo
   detectedIn: Distro 1.0
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0002
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
Notes:
Mitigation:
Bugs:
Priority: medium
Discovered-by: foo
Assigned-to:
CVSS:

Patches_TBD:
oci/some-override_TBD: needs-triage

## end CVE template"""
                % (now.year, now.year, now.month, now.day),
            ),
        ]

        for alert_name, pkg_name, oci_reports, template_urls, whr, exp in tsts:
            res = cvelib.scan.getScanOCIsReportTemplates(
                alert_name, pkg_name, oci_reports, template_urls, oci_where_override=whr
            )
            self.assertEqual(exp, res)
