"""test_scan.py: tests for scan.py module"""
#
# SPDX-License-Identifier: MIT

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
            "detectedIn": "myorg/myimg@sha256:deadbeef",
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
   detectedIn: myorg/myimg@sha256:deadbeef
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
   detectedIn: myorg/myimg@sha256:deadbeef
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "dtectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
                    "detectedIn": "myorg/myimg@sha256:deadbeef",
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
   detectedIn: myorg/myimg@sha256:deadbeef
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0001
   version: 1.2.2
   fixedBy: 1.2.3
   severity: medium
   status: needed
   url: https://blah.com/BAR-a
 - type: oci
   component: baz
   detectedIn: myorg/myimg2@sha256:deadbeef1
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0002
   version: 2.3.3
   fixedBy: 2.3.4
   severity: medium
   status: needed
   url: https://blah.com/NORF-a
 - type: oci
   component: corge
   detectedIn: myorg/myimg@sha256:deadbeef
   advisory: https://www.cve.org/CVERecord?id=CVE-2023-0003
   version: 9.2.0-4
   fixedBy: 9.2.0-5
   severity: high
   status: released
   url: https://blah.com/CORGE-a
"""

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
