"""test_cve.py: tests for cve.py module"""

from unittest import TestCase
from unittest.mock import MagicMock
import copy
import datetime
import os
import tempfile

import cvelib.cve
import cvelib.common
import cvelib.tests.util


class TestCve(TestCase):
    """Tests for the CVE data and functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        self.orig_readCve = None
        self.maxDiff = None
        self.tmpdir = None

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.orig_readCve is not None:
            cvelib.common.readCve = self.orig_readCve
            self.orig_readCve = None

        if self.tmpdir is not None:
            cvelib.common.recursive_rm(self.tmpdir)

    def _mockHeaders(self, header_dict):
        """Mock headers for use with"""
        # TODO: we want RFC6532
        m = {}
        for k in header_dict:
            m[k] = header_dict[k]

        return m

    def _mock_readCve(self, header_dict):
        """Mock readCve() and return the expected value"""
        expected = self._mockHeaders(header_dict)
        if self.orig_readCve is None:
            self.orig_readCve = cvelib.common.readCve
        cvelib.common.readCve = MagicMock(return_value=expected)

        return expected

    def _cve_template(self):
        """Generate a valid CVE to mimic what readCve() might see"""
        return copy.deepcopy(
            {
                "Candidate": "CVE-2020-1234",
                "PublicDate": "2020-06-30",
                "CRD": "2020-06-30 01:02:03 -0700",
                "References": "\n http://example.com",
                "Description": "\n Some description\n more desc",
                "Notes": "\n person> some notes\n  more notes\n person2> blah",
                "Mitigation": "Some mitigation",
                "Bugs": "\n http://example.com/bug",
                "Priority": "medium",
                "Discovered-by": "Jane Doe (jdoe)",
                "Assigned-to": "John Doe (johnny)",
                "CVSS": "...",
            }
        )

    def test___init__valid(self):
        """Test __init__()"""
        # just the required
        exp = self._mock_readCve(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        for key in exp:
            self.assertTrue(key in cve.data)

        # also with packages
        t = self._cve_template()
        t["Tags_foo"] = "pie"
        t["Patches_foo"] = ""
        t["snap/pub_foo/mod"] = "released (123-4)"
        exp = self._mock_readCve(t)
        cve = cvelib.cve.CVE(fn="fake")
        for key in exp:
            self.assertTrue(key in cve.data)

    def test___str__(self):
        """Test __str__()"""
        self._mock_readCve(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        self.assertTrue("Candidate=" in cve.__str__())

    def test___repr__(self):
        """Test __repr__()"""
        self._mock_readCve(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        self.assertTrue("Candidate=" in cve.__repr__())

    def test_onDiskFormat(self):
        """Test onDiskFormat()"""
        self.maxDiff = 1024
        self._mock_readCve(self._cve_template())
        exp = """Candidate: CVE-2020-1234
PublicDate: 2020-06-30
CRD: 2020-06-30 01:02:03 -0700
References:
 http://example.com
Description:
 Some description
 more desc
Notes:
 person> some notes
  more notes
 person2> blah
Mitigation: Some mitigation
Bugs:
 http://example.com/bug
Priority: medium
Discovered-by: Jane Doe (jdoe)
Assigned-to: John Doe (johnny)
CVSS: ...
"""
        cve = cvelib.cve.CVE(fn="fake")
        res = cve.onDiskFormat()
        self.assertEqual(exp, res)

        pkgs = []
        # no patches for pkg1
        pkgs.append(cvelib.pkg.CvePkg("git", "pkg1", "needed"))

        # (unsorted) patches for these
        pkg2a = cvelib.pkg.CvePkg("snap", "pkg2", "needed", "pub", "", "123-4")
        pkg2a.setPatches(["upstream: http://a", "other: http://b"])
        pkgs.append(pkg2a)

        pkg2b = cvelib.pkg.CvePkg("git", "pkg2", "released", "", "inky", "5678")
        pkgs.append(pkg2b)

        pkg3 = cvelib.pkg.CvePkg("snap", "pkg3", "needed")
        pkg3.setTags("pie")
        pkgs.append(pkg3)

        pkg4 = cvelib.pkg.CvePkg("git", "pkg3", "needed")
        pkg4.setTags("hardlink-restriction")
        pkgs.append(pkg4)

        cve.setPackages(pkgs)

        exp2 = (
            exp
            + """
Patches_pkg1:
git_pkg1: needed

Patches_pkg2:
 upstream: http://a
 other: http://b
git_pkg2/inky: released (5678)
snap/pub_pkg2: needed (123-4)

Patches_pkg3:
Tags_pkg3: hardlink-restriction pie
git_pkg3: needed
snap_pkg3: needed
"""
        )
        res = cve.onDiskFormat()
        self.assertEqual(exp2, res)

    def test_onDiskFormatSorted(self):
        """Test onDiskFormat() - sorted"""
        self.maxDiff = 1024
        self._mock_readCve(self._cve_template())
        exp = """Candidate: CVE-2020-1234
PublicDate: 2020-06-30
CRD: 2020-06-30 01:02:03 -0700
References:
 http://example.com
Description:
 Some description
 more desc
Notes:
 person> some notes
  more notes
 person2> blah
Mitigation: Some mitigation
Bugs:
 http://example.com/bug
Priority: medium
Discovered-by: Jane Doe (jdoe)
Assigned-to: John Doe (johnny)
CVSS: ...

Patches_bar:
debian/buster_bar: needed
debian/squeeze_bar: needed
git/github_bar: needs-triage
ubuntu/bionic_bar: needed
ubuntu/focal_bar: needed
upstream_bar: needed

Patches_baz:
git/github_baz: needs-triage

Patches_corge:
git/github_corge: needs-triage

Patches_foo:
upstream_foo: pending

Patches_norf:
git/github_norf: needs-triage
"""
        cve = cvelib.cve.CVE(fn="fake")

        # Put these in random order and verify what we expect
        pkgs = []
        tsts = [
            # product, software, status, where, modifier, when, compat
            ("upstream", "foo", "pending", "", "", "", False),
            ("git", "bar", "needs-triage", "github", "", "", False),
            ("ubuntu", "bar", "needed", "focal", "", "", False),
            ("ubuntu", "bar", "needed", "bionic", "", "", False),
            ("upstream", "foo", "pending", "", "", "", False),
            ("debian", "bar", "needed", "squeeze", "", "", False),
            ("debian", "bar", "needed", "buster", "", "", False),
            ("git", "baz", "needs-triage", "github", "", "", False),
            ("git", "norf", "needs-triage", "github", "", "", False),
            ("git", "corge", "needs-triage", "github", "", "", False),
            ("upstream", "bar", "needed", "", "", "", False),
        ]
        for product, software, status, where, modifier, when, compat in tsts:
            pkgs.append(
                cvelib.pkg.CvePkg(
                    product,
                    software,
                    status,
                    where=where,
                    modifier=modifier,
                    when=when,
                    compatUbuntu=compat,
                )
            )

        cve.setPackages(pkgs)
        with cvelib.tests.util.capturedOutput() as (output, error):
            res = cve.onDiskFormat()

        self.assertEqual(exp, res)
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

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
        self.assertEqual("data not of type dict", str(context.exception))

    def test__verifySingleline(self):
        """Test _isSingleline()"""
        cvelib.cve.CVE()._verifySingleline("Empty", "")
        cvelib.cve.CVE()._verifySingleline("Key", "value")
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._verifySingleline("Key", "foo\nbar")
        self.assertEqual(
            "invalid Key: 'foo\nbar' (expected single line)", str(context.exception)
        )

    def test__verifyMultiline(self):
        """Test _isMultiline()"""
        tsts = [
            ("Empty", "", 0, None),
            ("Key", "\n foo", 1, None),
            ("Key", "\n foo\n", 1, None),
            ("Key", "\n foo\n bar", 2, None),
            ("Key", "\n foo\n .\n bar", 3, None),
            # bad
            ("Key", "\n", None, "invalid Key (empty)"),
            ("Key", "single", None, "invalid Key: 'single' (missing leading newline)"),
            (
                "Key",
                "no\nleading\nnewline",
                None,
                "invalid Key: 'no\nleading\nnewline' (missing leading newline)",
            ),
            (
                "Key",
                "\nno\nleading\nspace",
                None,
                "invalid Key: '\nno\nleading\nspace' (missing leading space)",
            ),
            ("Key", "\n foo\n\n", None, "invalid Key: '\n foo\n\n' (empty line)"),
        ]
        for key, val, num, err in tsts:
            if num is not None:
                lines = cvelib.cve.CVE()._verifyMultiline(key, val)
                self.assertEqual(len(lines), num)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifyMultiline(key, val)
                self.assertEqual(err, str(context.exception))

    def test___init__bad(self):
        """Test __init__()"""
        self._mock_readCve(
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

    def test__setFromData(self):
        """Test _setFromData()"""
        # valid
        hdrs = self._mockHeaders(self._cve_template())
        cvelib.cve.CVE()._setFromData(hdrs)

        # optional missing is ok
        hdrs = self._mockHeaders(self._cve_template())
        del hdrs["CRD"]
        cvelib.cve.CVE()._setFromData(hdrs)

        # valid with packages
        t = self._cve_template()
        t["upstream_foo"] = "needed"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE()._setFromData(hdrs)

        # comment ignored
        t = self._cve_template()
        t["#blah_foo"] = "needed"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE()._setFromData(hdrs)

        # valide Patches_foo
        t = self._cve_template()
        t["Patches_foo"] = ""
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE()._setFromData(hdrs)

        # invalid
        hdrs = self._mockHeaders(self._cve_template())
        del hdrs["Candidate"]
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._setFromData(hdrs)
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
        """Test _verifyPriority()"""
        tsts = [
            # valid
            ("Priority", "negligible", False, True),
            ("Priority", "low", False, True),
            ("Priority", "medium", False, True),
            ("Priority", "high", False, True),
            ("Priority", "critical", False, True),
            ("Priority_foo", "negligible", False, True),
            ("Priority_foo", "low", False, True),
            ("Priority_foo", "medium", False, True),
            ("Priority_foo", "high", False, True),
            ("Priority_foo", "critical", False, True),
            ("Priority", "untriaged", True, True),
            ("Priority_foo", "untriaged", True, True),
            # invalid
            ("Priority", "untriaged", False, False),
            ("Priority_foo", "untriaged", False, False),
            ("Priority", "bad", True, False),
            ("Priority", "bad", False, False),
        ]
        for (key, val, untriagedOk, valid) in tsts:
            if valid:
                cvelib.cve.CVE()._verifyPriority(key, val, untriagedOk=untriagedOk)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifyPriority(key, val, untriagedOk=untriagedOk)
                self.assertEqual(
                    "invalid %s: '%s'" % (key, val), str(context.exception)
                )

    def test__verifyBugsAndReferences(self):
        """Test _verifyReferences() and _verifyBugs()"""
        tsts = [
            # valid
            ("\n cvs://1", None),
            ("\n ftp://1", None),
            ("\n git://1", None),
            ("\n http://1", None),
            ("\n https://1", None),
            ("\n sftp://1", None),
            ("\n shttp://1", None),
            ("\n svn://1", None),
            ("\n https://github.com/foo/bar/issues/1234", None),
            ("\n https://launchpad.net/bugs/1234", None),
            ("\n https://launchpad.net/ubuntu/+source/foo/+bug/1234", None),
            ("\n https://1\n http://2\n http://3", None),
            ("\n https://1 (comment 1)\n http://2 (comment 2)\n http://3 blah", None),
            # invalid
            ("\n", "invalid %(key)s (empty)"),
            ("\nhttp://1", "invalid %(key)s: '\nhttp://1' (missing leading space)"),
            ("\n\n http://1", "invalid %(key)s: '\n\n http://1' (empty line)"),
            ("\n https://", "invalid url in %(key)s: 'https://'"),
        ]
        for tstType in ["Bugs", "References"]:
            fn = None
            if tstType == "Bugs":
                fn = cvelib.cve.CVE()._verifyBugs
            elif tstType == "References":
                fn = cvelib.cve.CVE()._verifyReferences

            for val, err in tsts:
                if not err:
                    fn(tstType, val)
                else:
                    with self.assertRaises(cvelib.common.CveException) as context:
                        fn(tstType, val)
                    self.assertEqual(err % {"key": tstType}, str(context.exception))

    def test__verifyDescriptionAndNotes(self):
        """Test _verifyDescription() and _verifyNotes()"""
        tsts = [
            # valid
            ("\n foo", None),
            ("\n foo\n", None),
            ("\n foo\n bar", None),
            ("\n foo\n bar\n .\n baz", None),
            ("\n person> foo\n  bar\n  .\n  baz", None),
            # invalid
            ("\n", "invalid %(key)s (empty)"),
            ("\nfoo", "invalid %(key)s: '\nfoo' (missing leading space)"),
            ("\n\n foo", "invalid %(key)s: '\n\n foo' (empty line)"),
        ]
        for tstType in ["Description", "Notes"]:
            fn = None
            if tstType == "Description":
                fn = cvelib.cve.CVE()._verifyDescription
            elif tstType == "Notes":
                fn = cvelib.cve.CVE()._verifyNotes

            for val, err in tsts:
                if not err:
                    fn(tstType, val)
                else:
                    with self.assertRaises(cvelib.common.CveException) as context:
                        fn(tstType, val)
                    self.assertEqual(err % {"key": tstType}, str(context.exception))

    def test__verifyDiscoveredByAndAssignedTo(self):
        """Test _verifyDiscoveredBy() and _verifyAssignedTo"""
        tsts = [
            # valid
            ("nick", None),
            ("Madonna", None),
            ("Joe Schmoe", None),
            ("Joe Schmoe (jschmoe)", None),
            ("Joe Schmoe (@jschmoe)", None),
            ("Harry Potter Jr.", None),
            ("Alfred Foo-Bar", None),
            ("Angus O'Hare", None),
            # invalid
            ("Joe\nSchmoe", "invalid %(key)s: 'Joe\nSchmoe' (expected single line)"),
            ("Joe (", "invalid %(key)s: 'Joe ('"),
            ("Joe )", "invalid %(key)s: 'Joe )'"),
            ("Joe ()", "invalid %(key)s: 'Joe ()'"),
            ("Joe (@)", "invalid %(key)s: 'Joe (@)'"),
            ("Joe @joeschmoe", "invalid %(key)s: 'Joe @joeschmoe'"),
            ("Joe Bár", "invalid %(key)s: 'Joe Bár'"),  # utf-8 not supported
        ]
        for tstType in ["Discovered-by", "Assigned-to"]:
            fn = None
            if tstType == "Discovered-by":
                fn = cvelib.cve.CVE()._verifyDiscoveredBy
            elif tstType == "Assigned-to":
                fn = cvelib.cve.CVE()._verifyAssignedTo

            for val, err in tsts:
                if not err:
                    fn(tstType, val)
                else:
                    with self.assertRaises(cvelib.common.CveException) as context:
                        fn(tstType, val)
                    self.assertEqual(err % {"key": tstType}, str(context.exception))

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
                res = cvelib.cve.cveFromUrl(url)
                self.assertEqual(res, exp)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.cveFromUrl(url)
                self.assertEqual(
                    exp_fail,
                    str(context.exception),
                )

    def test_setPackages(self):
        """Test setPackages()"""
        self._mock_readCve(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        self.assertEqual(len(cve.pkgs), 0)

        pkgs = [
            cvelib.pkg.CvePkg("git", "pkg1", "needed"),
            cvelib.pkg.CvePkg("git", "pkg2", "needed"),
        ]
        patches = {
            "pkg1": " upstream: http://a\n other: http://b",
            "pkg2": " vendor: http://c\n debdiff: https://d",
        }
        tags = {
            "pkg1": "pie hardlink-restriction",
            "pkg2": "apparmor",
        }
        cve.setPackages(pkgs, patches=patches, tags=tags)
        self.assertEqual(len(cve.pkgs), 2)
        self.assertEqual(len(cve.pkgs[0].patches), 2)
        self.assertEqual(len(cve.pkgs[0].tags), 2)
        self.assertEqual(len(cve.pkgs[1].patches), 2)
        self.assertEqual(len(cve.pkgs[1].tags), 1)

        # invalid
        cve = cvelib.cve.CVE(fn="fake")
        self.assertEqual(len(cve.pkgs), 0)
        with self.assertRaises(cvelib.common.CveException) as context:
            cve.setPackages(False)
        self.assertEqual("pkgs is not a list", str(context.exception))

        cve = cvelib.cve.CVE(fn="fake")
        self.assertEqual(len(cve.pkgs), 0)
        with self.assertRaises(cvelib.common.CveException) as context:
            cve.setPackages([False])
        self.assertEqual(
            "package is not of type cvelib.pkg.CvePkg", str(context.exception)
        )

        # append
        self._mock_readCve(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        self.assertEqual(len(cve.pkgs), 0)

        # append one
        pkgs = [cvelib.pkg.CvePkg("git", "pkg1", "needed")]
        cve.setPackages(pkgs)
        self.assertEqual(len(cve.pkgs), 1)
        self.assertEqual(len(cve._pkgs_list), 1)
        self.assertTrue(pkgs[0].what() in cve._pkgs_list)

        # append another
        pkgs = [cvelib.pkg.CvePkg("git", "pkg2", "needed")]
        cve.setPackages(pkgs, append=True)
        self.assertEqual(len(cve.pkgs), 2)
        self.assertEqual(len(cve._pkgs_list), 2)
        self.assertTrue(pkgs[0].what() in cve._pkgs_list)

        # append with duplicates
        pkgs = [
            cvelib.pkg.CvePkg("git", "pkg1", "needed"),
            cvelib.pkg.CvePkg("git", "pkg2", "needed"),
            cvelib.pkg.CvePkg("git", "pkg3", "needed"),
        ]
        cve.setPackages(pkgs, append=True)
        self.assertEqual(len(cve.pkgs), 3)
        self.assertEqual(len(cve._pkgs_list), 3)
        for p in pkgs:
            self.assertTrue(p.what() in cve._pkgs_list)

    def test_checkSyntax(self):
        """Test checkSyntax"""
        self.tmpdir = tempfile.mkdtemp(prefix="influx-security-tools-")
        content = (
            """[Location]
cve-data = %s
"""
            % self.tmpdir
        )
        self.orig_xdg_config_home, self.tmpdir = cvelib.tests.util._newConfigFile(
            content, self.tmpdir
        )

        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        tsts = [
            # valid
            ("active/CVE-2021-9999", None),
            ("retired/CVE-2021-9999", None),
            ("ignored/CVE-2021-9999", None),
            # invalid
            ("retired/CVE-bad", "WARN: retired/CVE-bad: invalid Candidate: 'CVE-bad'"),
        ]

        for fn, expErr in tsts:
            tmpl = self._cve_template()
            dir, cand = fn.split("/")
            tmpl["Candidate"] = cand
            content = cvelib.tests.util.cveContentFromDict(tmpl)

            cve_fn = os.path.join(cveDirs[dir], cand)

            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

            with cvelib.tests.util.capturedOutput() as (output, error):
                cvelib.cve.checkSyntax(cveDirs, False)
            os.unlink(cve_fn)

            if expErr is None:
                self.assertEqual(output.getvalue().strip(), "")
                self.assertEqual(error.getvalue().strip(), "")
            else:
                self.assertEqual(output.getvalue().strip(), "")
                self.assertEqual(error.getvalue().strip(), expErr)

        # non-matching
        tmpl = self._cve_template()
        content = cvelib.tests.util.cveContentFromDict(tmpl)
        cve_fn = os.path.join(cveDirs["active"], "CVE-1234-5678")
        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.tests.util.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_fn)

        self.assertEqual(output.getvalue().strip(), "")
        self.assertEqual(
            error.getvalue().strip(),
            "WARN: active/CVE-1234-5678: non-matching candidate 'CVE-2020-1234'",
        )

        # multiple
        tmpl = self._cve_template()
        content = cvelib.tests.util.cveContentFromDict(tmpl)
        cve_active_fn = os.path.join(cveDirs["active"], tmpl["Candidate"])
        with open(cve_active_fn, "w") as fp:
            fp.write("%s" % content)
        cve_retired_fn = os.path.join(cveDirs["retired"], tmpl["Candidate"])
        with open(cve_retired_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.tests.util.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_active_fn)
        os.unlink(cve_retired_fn)

        self.assertEqual(output.getvalue().strip(), "")
        self.assertTrue(
            error.getvalue()
            .strip()
            .startswith("WARN: multiple entries for CVE-2020-1234: ")
        )

    def test_pkgFromCandidate(self):
        """Test pkgFromCandidate()"""
        tsts = [
            # valid package
            ("CVE-2021-GH1234#foo", "git/github_foo", None),
            ("CVE-2021-GH1234#bar", "git/github_bar", None),
            ("CVE-2020-GH9999#foobar", "git/github_foobar", None),
            # no package
            ("CVE-2021-1234", None, None),
            ("CVE-2021-LP1234", None, None),
            # invalid
            ("CVE-2021-GH1234", "", "invalid candidate: 'CVE-2021-GH1234'"),
            (
                "CVE-2021-GH1234#",
                "",
                "invalid candidate: 'CVE-2021-GH1234#' (empty package)",
            ),
        ]
        for (cand, exp, exp_fail) in tsts:
            if exp_fail is None:
                res = cvelib.cve.pkgFromCandidate(cand)
                self.assertEqual(res, exp)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    res = cvelib.cve.pkgFromCandidate(cand)
                self.assertEqual(
                    exp_fail,
                    str(context.exception),
                )

    def test___genReferencesAndBugs(self):
        """Test _genReferencesAndBugs()"""
        tsts = [
            (
                "CVE-2020-1234",
                ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1234"],
                [],
            ),
            (
                "https://github.com/foo/bar/issues/1234",
                ["https://github.com/foo/bar/issues/1234"],
                ["https://github.com/foo/bar/issues/1234"],
            ),
            (
                "https://launchpad.net/bugs/1234",
                ["https://launchpad.net/bugs/1234"],
                ["https://launchpad.net/bugs/1234"],
            ),
        ]

        for cve, expRefs, expBugs in tsts:
            refs, bugs = cvelib.cve._genReferencesAndBugs(cve)
            self.assertEqual(refs, expRefs)
            self.assertEqual(bugs, expBugs)

    def test__createCve(self):
        """Test _createCve()"""

        def createAndVerify(cveDirs, cve_fn, cve, pkgs):
            # add a new CVE
            cvelib.cve._createCve(cveDirs, cve_fn, cve, pkgs, False)

            # now read it off disk and verify it
            res = cvelib.common.readCve(cve_fn)

            fields = [
                "Candidate",
                "PublicDate",
                "CRD",
                "References",
                "Description",
                "Notes",
                "Mitigation",
                "Bugs",
                "Priority",
                "Discovered-by",
                "Assigned-to",
                "CVSS",
            ]
            for k in fields:
                self.assertTrue(k in res)

            for k in res:
                if "_" in k:  # checked elsewhere
                    continue
                elif k == "Candidate":
                    self.assertEqual(res[k], os.path.basename(cve_fn))
                elif k == "References":
                    self.assertEqual(
                        res[k],
                        "\n https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s"
                        % os.path.basename(cve_fn),
                    )
                elif k == "Priority":
                    self.assertEqual(res[k], "untriaged")
                else:
                    self.assertEqual(res[k], "")
            return res

        self.tmpdir = tempfile.mkdtemp(prefix="influx-security-tools-")
        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        cve_fn = os.path.join(cveDirs["active"], "CVE-2021-999999")
        boiler_fn = os.path.join(cveDirs["active"], "00boilerplate")

        # missing boiler
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve._createCve(
                cveDirs, cve_fn, os.path.basename(cve_fn), ["git/github_foo"], False
            )
        self.assertEqual(
            "could not find 'active/00boilerplate'",
            str(context.exception),
        )

        boiler_content = """Candidate:
PublicDate:
References:
Description:
Notes:
Mitigation:
Bugs:
Priority: untriaged
Discovered-by:
Assigned-to:
CVSS:

#Patches_PKG:
#upstream_PKG:
"""
        with open(boiler_fn, "w") as fp:
            fp.write("%s" % boiler_content)

        res = createAndVerify(
            cveDirs, cve_fn, os.path.basename(cve_fn), ["git/github_foo"]
        )
        self.assertTrue("Patches_foo" in res)
        self.assertTrue("git/github_foo" in res)
        self.assertEqual(res["git/github_foo"], "needs-triage")
        self.assertFalse("Patches_bar" in res)
        self.assertFalse("git/github_bar" in res)

        # add to existing
        res2 = createAndVerify(
            cveDirs, cve_fn, os.path.basename(cve_fn), ["git/github_bar"]
        )
        self.assertTrue("Patches_foo" in res2)
        self.assertTrue("git/github_foo" in res2)
        self.assertEqual(res2["git/github_foo"], "needs-triage")
        self.assertTrue("Patches_bar" in res2)
        self.assertTrue("git/github_bar" in res2)
        self.assertEqual(res2["git/github_bar"], "needs-triage")

    def test_addCve(self):
        """Test _createCve()"""
        self.tmpdir = tempfile.mkdtemp(prefix="influx-security-tools-")
        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        boiler_fn = os.path.join(cveDirs["active"], "00boilerplate")
        boiler_content = """Candidate:
PublicDate:
References:
Description:
Notes:
Mitigation:
Bugs:
Priority: untriaged
Discovered-by:
Assigned-to:
CVSS:

#Patches_PKG:
#upstream_PKG:
"""
        with open(boiler_fn, "w") as fp:
            fp.write("%s" % boiler_content)

        boiler_baz_fn = "%s.baz" % boiler_fn
        with open(boiler_baz_fn, "w") as fp:
            fp.write(
                "%s" % boiler_content
                + """
Patches_baz:
upstream_baz: needed
"""
            )

        boiler_ubuntu_fn = "%s.ubuntu" % boiler_fn
        with open(boiler_ubuntu_fn, "w") as fp:
            fp.write(
                "%s" % boiler_content
                + """
#precise/esm_PKG:
#trusty_PKG:
#trusty/esm_PKG:
#xenial_PKG:
#bionic_PKG:
#focal_PKG:
#groovy_PKG:
#devel_PKG:
"""
            )

        tsts = [
            # valid strict
            ("CVE-2021-999999", ["git/github_foo"], False, None),
            ("CVE-2021-999999", ["git/github_foo", "git/github_bar"], False, None),
            ("https://github.com/foo/bar/issues/1234", [], False, None),
            ("https://github.com/foo/bar/issues/1234", ["git/github_bar"], False, None),
            ("CVE-2021-999999", ["git/github_baz/mod"], False, None),
            ("CVE-2021-999999", ["ubuntu/focal_norf"], False, None),
            ("CVE-2021-999999", ["debian/buster_norf"], False, None),
            # valid compat
            ("CVE-2021-999999", ["focal_baz"], True, None),
            ("CVE-2021-999999", ["norf"], True, None),
            ("CVE-2021-999999", ["norf", "corge"], True, None),
            # invalid
            (
                "CVE-2021-bad",
                ["git/github_foo"],
                False,
                "invalid Candidate: 'CVE-2021-bad'",
            ),
            (
                "https://github.com/foo",
                [],
                False,
                "invalid url: 'https://github.com/foo' (only support github issues)",
            ),
            (
                "CVE-2021-999999",
                ["focal_baz"],
                False,
                "invalid package entry 'focal_baz: needs-triage'",
            ),
            (
                "CVE-2021-999999",
                [],
                False,
                "could not find usable packages for 'CVE-2021-999999'",
            ),
        ]

        for cve, pkgs, compat, expFail in tsts:

            if expFail is not None:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.addCve(cveDirs, compat, cve, pkgs)
                self.assertEqual(expFail, str(context.exception))
                continue

            cve_fn = os.path.join(cveDirs["active"], cve)
            if cve.startswith("http"):
                cve_fn = os.path.join(cveDirs["active"], cvelib.cve.cveFromUrl(cve))

            with cvelib.tests.util.capturedOutput() as (output, error):
                cvelib.cve.addCve(cveDirs, compat, cve, pkgs)
            self.assertTrue(os.path.exists(cve_fn))

            out = output.getvalue().strip()
            err = error.getvalue().strip()
            self.assertEqual("", out)
            self.assertEqual("", err)

            with cvelib.tests.util.capturedOutput() as (output, error):
                res = cvelib.common.readCve(cve_fn)
            os.unlink(cve_fn)
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual("", error.getvalue().strip())

            for p in pkgs:
                if "_" in p:
                    self.assertTrue(p in res)
                    self.assertEqual(res[p], "needs-triage")
                elif compat:
                    for i in [
                        "precise/esm",
                        "trusty",
                        "trusty/esm",
                        "xenial",
                        "bionic",
                        "focal",
                        "groovy",
                        "devel",
                    ]:
                        uPkg = "%s_%s" % (i, p)
                        self.assertTrue(uPkg in res)
                        self.assertFalse(p in res)
                        self.assertEqual(res[uPkg], "needs-triage")
