"""test_cve.py: tests for cve.py module"""

from email.message import EmailMessage
from unittest import TestCase
from unittest.mock import MagicMock
import copy
import datetime

import cvelib.cve
import cvelib.common


class TestCve(TestCase):
    """Tests for the CVE data and functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        self.orig_readCveHeaders = None

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.orig_readCveHeaders is not None:
            cvelib.common.readCveHeaders = self.orig_readCveHeaders

    def _mockHeaders(self, header_dict):
        """Mock headers for use with"""
        # TODO: we want RFC6532
        m = EmailMessage()
        for k in header_dict:
            m.__setitem__(k, header_dict[k])

        return m

    def _mock_readCveHeaders(self, header_dict):
        """Mock readCveHeaders() and return the expected value"""
        expected = self._mockHeaders(header_dict)
        self.orig_readCveHeaders = cvelib.common.readCveHeaders
        cvelib.common.readCveHeaders = MagicMock(return_value=expected)

        return expected

    def _cve_template(self):
        """Generate a valid CVE"""
        return copy.deepcopy(
            {
                "Candidate": "CVE-2020-1234",
                "PublicDate": "2020-06-30",
                "CRD": "2020-06-30 01:02:03 -0700",
                "References": "http://example.com",
                "Description": "Some description",
                "Notes": "Some notes",
                "Mitigation": "Some mitigation",
                "Bugs": "http://example.com/bug",
                "Priority": "medium",
                "Discovered-by": "Jane Doe (jdoe)",
                "Assigned-to": "John Doe (johnny)",
                "CVSS": "...",
            }
        )

    def test___init__valid(self):
        """Test __init__()"""
        exp = self._mock_readCveHeaders(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        for key in exp:
            self.assertTrue(key in cve.headers)
            self.assertEqual(exp[key], cve.headers[key])

    def test___str__(self):
        """Test __str__()"""
        self._mock_readCveHeaders(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        self.assertTrue("Candidate=" in cve.__str__())

    def test___repr__(self):
        """Test __repr__()"""
        self._mock_readCveHeaders(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        self.assertTrue("Candidate=" in cve.__repr__())

    def test__isPresent(self):
        """Test _isPresent()"""
        # default cannot be empty
        hdrs = self._mockHeaders({"Foo": "blah"})
        cvelib.cve.CVE()._isPresent(hdrs, "Foo")

        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._isPresent(hdrs, "Bar")
        self.assertEqual("missing field 'Bar'", str(context.exception))

        hdrs = ["foo"]
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._isPresent(hdrs, "Foo")
        self.assertEqual("headers not of type 'EmailMessage'", str(context.exception))

    def test___init__bad(self):
        """Test __init__()"""
        self._mock_readCveHeaders(
            {
                "Candidate": "CVE-2020-1234",
            }
        )
        try:
            cvelib.cve.CVE(fn="fake")
        except cvelib.common.CveException:
            pass
        except Exception:  # pragma: nocover
            raise

    def test__setFromHeaders(self):
        """Test _setFromHeaders()"""
        # valid
        hdrs = self._mockHeaders(self._cve_template())
        cvelib.cve.CVE()._setFromHeaders(hdrs)

        # invalid
        hdrs = self._mockHeaders(self._cve_template())
        del hdrs["Candidate"]
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._setFromHeaders(hdrs)
        self.assertEqual("missing required field 'Candidate'", str(context.exception))

    def test__verifyCve(self):
        """Test _verifyCve()"""
        # valid
        hdrs = self._mockHeaders(self._cve_template())
        cvelib.cve.CVE()._verifyCve(hdrs)

        # optional
        hdrs = self._mockHeaders(self._cve_template())
        hdrs["Priority_foo"] = "medium"
        cvelib.cve.CVE()._verifyCve(hdrs)

        # missing optional is ok
        hdrs = self._mockHeaders(self._cve_template())
        del hdrs["CRD"]
        cvelib.cve.CVE()._verifyCve(hdrs)

        # invalid
        hdrs = self._mockHeaders(self._cve_template())
        del hdrs["Candidate"]
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._verifyCve(hdrs)
        self.assertEqual("missing required field 'Candidate'", str(context.exception))

    def test__verifyCandidate(self):
        """Test _verifyCandidate()"""
        tsts = [
            # valid
            ("CVE-2020-1234", True),
            ("CVE-2020-123456789012", True),
            ("CVE-2020-NNN1", True),
            ("CVE-2020-NNNN1", True),
            ("CVE-2020-NNNN1234", True),
            ("CVE-2020-NNNN12345678", True),
            ("CVE-2020-GH1234#foo", True),
            ("CVE-2020-GH1#a", True),
            ("CVE-2020-GH1234#abcdefg-1.2beta", True),
            ("CVE-2020-GH123456789012#a", True),
            ("CVE-2020-GH1#%s" % ("a" * 40), True),
            ("BAD", False),
            ("CVE-202O-1234", False),
            ("CV3-2020-1234", False),
            ("CV3-20200-1234", False),
            ("CVE-2020-1234567890123", False),
            ("aCVE-2020-1234", False),
            ("CVE-2020-1234b", False),
            ("CV3-2020-!234", False),
            ("CVE-2020-1", False),
            ("CVE-2020-12", False),
            ("CVE-2020-123", False),
            ("CVE-2020-NNN", False),
            ("CVE-2020-NNNN", False),
            ("CVE-2020-1234N", False),
            ("CVE-2020-1234BAD", False),
            ("CVE-2020-G1234", False),
            ("CVE-2020-GH1234", False),
            ("CVE-2020-GH1234#", False),
            ("CVE-2020-GH1234##foo", False),
            ("CVE-2020-GH1234#@", False),
            ("CVE-2020-GH!234#foo", False),
            ("CVE-2020-GH1234#f@o", False),
            ("CVE-2020-GH1#%s" % ("a" * 41), False),
        ]
        for (cand, valid) in tsts:
            if valid:
                cvelib.cve.CVE()._verifyCandidate("Candidate", cand)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifyCandidate("Candidate", cand)
                self.assertEqual(
                    "invalid Candidate: '%s'" % cand, str(context.exception)
                )

    def test__verifyDate(self):
        """Test _verifyDate()"""
        tsts = [
            # valid
            ("2020-01-01", True),
            ("2020-02-29", True),
            ("2020-12-31", True),
            ("2020-01-01 00:00:00", True),
            ("2020-12-31 23:59:59", True),
            ("2020-12-01 12:34:56 UTC", True),
            ("2020-12-01 12:34:56 -0500", True),
            # invalid
            ("bad", False),
            ("2020-bad", False),
            ("2020-12-bad", False),
            ("2020-12-14bad", False),
            ("2020-12-14 bad", False),
            ("2020-12-14 07:bad", False),
            ("2020-12-14 07:08:bad", False),
            ("2020-12-14 07:08:09bad", False),
            ("2020-12-14 07:08:09 bad", False),
            ("2020-12-14 07:08:09 +bad", False),
            ("2020-12-14 07:08:09 -bad", False),
            ("2020-12-14 07:08:09 -03bad", False),
            ("2020-12-14 07:08:09 -0999999", False),
            ("2020-12-14 07:08:09 BADTZ", False),
            ("2020-12-32", False),
            ("2021-02-29", False),
            ("2020-06-31", False),
            ("-2020-12-01", False),
            ("2020-12-01 30:01:02", False),
            ("2020-12-01 24:01:02", False),
            ("2020-12-01 07:60:02", False),
            ("2020-12-01 07:59:60", False),
        ]
        for (date, valid) in tsts:
            if valid:
                cvelib.cve.CVE()._verifyDate("PublicDate", date)
            else:
                suffix = "(use empty, YYYY-MM-DD [HH:MM:SS [TIMEZONE]]"
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifyDate("PublicDate", date)
                self.assertEqual(
                    "invalid PublicDate: '%s' %s" % (date, suffix),
                    str(context.exception),
                )

    def test__verifyPublicDate(self):
        """Test _verifyPublicDate()"""
        # valid
        cvelib.cve.CVE()._verifyPublicDate("PublicDate", "")
        cvelib.cve.CVE()._verifyPublicDate("PublicDate", "2021-01-25")
        # invalid
        suffix = "(use empty, YYYY-MM-DD [HH:MM:SS [TIMEZONE]]"
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._verifyPublicDate("PublicDate", "bad")
        self.assertEqual(
            "invalid PublicDate: 'bad' %s" % suffix, str(context.exception)
        )

    def test__verifyCRD(self):
        """Test _verifyCRD()"""
        # valid
        cvelib.cve.CVE()._verifyCRD("CRD", "")
        cvelib.cve.CVE()._verifyCRD("CRD", "2021-01-25")
        # invalid
        suffix = "(use empty, YYYY-MM-DD [HH:MM:SS [TIMEZONE]]"
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._verifyCRD("CRD", "bad")
        self.assertEqual("invalid CRD: 'bad' %s" % suffix, str(context.exception))

    def test__verifyPriority(self):
        """Test _verifyCRD()"""
        tsts = [
            # valid
            ("Priority", "negligible", True),
            ("Priority", "low", True),
            ("Priority", "medium", True),
            ("Priority", "high", True),
            ("Priority", "critical", True),
            ("Priority_foo", "negligible", True),
            ("Priority_foo", "low", True),
            ("Priority_foo", "medium", True),
            ("Priority_foo", "high", True),
            ("Priority_foo", "critical", True),
            # invalid
            ("Priority", "untriaged", False),
            ("Priority_foo", "untriaged", False),
        ]
        for (key, val, valid) in tsts:
            if valid:
                cvelib.cve.CVE()._verifyPriority(key, val)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifyPriority(key, val)
                self.assertEqual(
                    "invalid %s: '%s'" % (key, val), str(context.exception)
                )

    def test_cveFromUrl(self):
        """Test cveFromUrl()"""
        # If this runs before Jan 1 00:00:00 but the test runs after, it will
        # fail.
        year = datetime.datetime.now().year
        tsts = [
            # valid
            (
                "https://github.com/influxdata/idpe/issues/5519",
                "CVE-%s-GH5519#idpe" % year,
                None,
            ),
            ("https://github.com/foo/bar/issues/1", "CVE-%s-GH1#bar" % year, None),
            # invalid
            ("bad", None, "unsupported url: 'bad' (only support github)"),
            (
                "http://example.com",
                None,
                "unsupported url: 'http://example.com' (only support github)",
            ),
            (
                "https://launchpad.net/bugs/1234",
                None,
                "unsupported url: 'https://launchpad.net/bugs/1234' (only support github)",
            ),
            (
                "https://github.com/influxdata/idpe/pull/6238",
                None,
                "invalid url: 'https://github.com/influxdata/idpe/pull/6238' (only support github issues)",
            ),
        ]
        for (url, exp, exp_fail) in tsts:
            if exp is not None:
                res = cvelib.cve.CVE().cveFromUrl(url)
                self.assertEqual(res, exp)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE().cveFromUrl(url)
                self.assertEqual(
                    exp_fail,
                    str(context.exception),
                )
