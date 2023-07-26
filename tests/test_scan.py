"""test_scan.py: tests for scan.py module"""
#
# SPDX-License-Identifier: MIT

import copy
import datetime
import os
from unittest import TestCase

import cvelib.common
import cvelib.github
import cvelib.scan


class TestScanOCI(TestCase):
    """Tests for the scan report OCI data and functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        os.environ["SEDG_EXPERIMENTAL"] = "1"

    def tearDown(self):
        """Teardown functions common for all tests"""
        if "SEDG_EXPERIMENTAL" in os.environ:
            del os.environ["SEDG_EXPERIMENTAL"]

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
            # valid
            ("foo"),
        ]

        for s in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            sm.setComponent(s)

    def test_setDetectedIn(self):
        """Test setDetectedIn()"""
        tsts = [
            # valid
            ("foo"),
        ]

        for s in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            sm.setDetectedIn(s)

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

    def test_setVersionFixed(self):
        """Test setVersionFixed()"""
        tsts = [
            # valid
            ("foo"),
        ]

        for s in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            sm.setVersionFixed(s)

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
            # valid
            ("https://foo", None),
            ("unavailable", None),
            # invalid
            ("foo", "invalid advisory url: foo"),
        ]

        for s, expErr in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            if expErr is None:
                sm.setAdvisory(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    sm.setAdvisory(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setUrl(self):
        """Test setUrl()"""
        tsts = [
            # valid
            ("https://foo", None),
            ("unavailable", None),
            # invalid
            ("foo", "invalid url: foo"),
        ]

        for s, expErr in tsts:
            sm = cvelib.scan.ScanOCI(self._getValid())
            if expErr is None:
                sm.setUrl(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    sm.setUrl(s)
                self.assertEqual(expErr, str(context.exception))


class TestScanCommon(TestCase):
    """Tests for the scan report common functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        os.environ["SEDG_EXPERIMENTAL"] = "1"

    def tearDown(self):
        """Teardown functions common for all tests"""
        if "SEDG_EXPERIMENTAL" in os.environ:
            del os.environ["SEDG_EXPERIMENTAL"]

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

        b_same = copy.deepcopy(a_data)
        b_diff = copy.deepcopy(a_data)
        b_diff["component"] = "other"
        b_imprecise = copy.deepcopy(a_data)
        b_imprecise["severity"] = "high"
        b_close = copy.deepcopy(a_data)
        b_close["status"] = "needs-triage"

        tsts = [
            # a, b, expectedFuzzy, expectedPrecise
            (cvelib.scan.ScanOCI(a_data), cvelib.scan.ScanOCI(b_same), True, True),
            (cvelib.scan.ScanOCI(a_data), cvelib.scan.ScanOCI(b_close), True, True),
            (
                cvelib.scan.ScanOCI(a_data),
                cvelib.scan.ScanOCI(b_imprecise),
                True,
                False,
            ),
            (cvelib.scan.ScanOCI(a_data), cvelib.scan.ScanOCI(b_diff), False, False),
        ]

        for a, b, expF, expP in tsts:
            f, p = cvelib.scan.matches(a, b)
            self.assertEqual(expF, f)
            self.assertEqual(expP, p)

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

    def test_formatWhereFromNamespace(self):
        """Test formatWhereFromNamespace()"""
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
            ("other", "b@d", "", "unknown"),
            ("other", "", "b@d", "unknown"),
        ]

        for oci_type, ns, whr, exp in tsts:
            res = cvelib.scan.formatWhereFromNamespace(oci_type, ns, whr)
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
        ]

        for url, whr, expP, expW, expS, expM in tsts:
            (resP, resW, resS, resM) = cvelib.scan._parseScanURL(
                url, where_override=whr
            )
            self.assertEqual(expP, resP, msg="url=%s" % url)
            self.assertEqual(expW, resW, msg="url=%s" % url)
            self.assertEqual(expS, resS, msg="url=%s" % url)
            self.assertEqual(expM, resM, msg="url=%s" % url)

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
                    )
                ],
                [],
                "",
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
                ["https://some/url", "https://some/other/url"],
                "",
                """## bar/baz foo template
Please address foo alert in bar/baz:

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
