"""test_cve.py: tests for cve.py module"""

from unittest import TestCase
from unittest.mock import MagicMock
import copy
import datetime
import os
import tempfile

import cvelib.cve
import cvelib.common
from cvelib.pkg import CvePkg
import cvelib.testutil


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
                "OpenDate": "2020-06-29",
                "PublicDate": "2020-06-30",
                "CRD": "2020-06-30 01:02:03 -0700",
                "References": "\n http://example.com",
                "Description": "\n Some description\n more desc",
                "Notes": "\n person> some notes\n  more notes\n person2> blah",
                "Mitigation": "\n Some mitigation\n more",
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
        tmpl = self._cve_template()
        tmpl[
            "GitHub-Advanced-Security"
        ] = """ - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-xg2h-wx96-xgxr
   severity: moderate
   status: dismissed (inaccurate; who)
   url: https://github.com/bar/baz/security/dependabot/1
 - type: secret
   secret: Slack Incoming Webhook URL
   detectedIn: /path/to/file
   status: dismissed (revoked; who)
   url: https://github.com/bar/baz/security/secret-scanning/1
"""
        self._mock_readCve(tmpl)
        exp = """Candidate: CVE-2020-1234
OpenDate: 2020-06-29
PublicDate: 2020-06-30
CRD: 2020-06-30 01:02:03 -0700
References:
 http://example.com
Description:
 Some description
 more desc
GitHub-Advanced-Security:
 - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-xg2h-wx96-xgxr
   severity: moderate
   status: dismissed (inaccurate; who)
   url: https://github.com/bar/baz/security/dependabot/1
 - type: secret
   secret: Slack Incoming Webhook URL
   detectedIn: /path/to/file
   status: dismissed (revoked; who)
   url: https://github.com/bar/baz/security/secret-scanning/1
Notes:
 person> some notes
  more notes
 person2> blah
Mitigation:
 Some mitigation
 more
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
        pkgs.append(CvePkg("git", "pkg1", "needed"))

        # (unsorted) patches for these
        pkg2a = CvePkg("snap", "pkg2", "needed", "pub", "", "123-4")
        pkg2a.setPatches(["upstream: http://a", "other: http://b"], False)
        pkgs.append(pkg2a)

        pkg2b = CvePkg("git", "pkg2", "released", "", "inky", "5678")
        pkgs.append(pkg2b)

        pkg3 = CvePkg("snap", "pkg3", "needed")
        pkg3.setTags([("pkg3", "pie")])
        pkgs.append(pkg3)

        pkg3b = CvePkg("git", "pkg3", "needed")
        pkg3b.setTags([("pkg3", "hardlink-restriction")])
        pkg3b.setPriorities([("pkg3", "low")])
        pkgs.append(pkg3b)

        pkg4 = CvePkg("debian", "pkg4", "needed", where="buster")
        pkgs.append(pkg4)

        pkg4b = CvePkg("debian", "pkg4", "needed", where="squeeze")
        pkgs.append(pkg4b)

        pkg4c = CvePkg("debian", "pkg4", "needed", where="wheezy")
        pkgs.append(pkg4c)

        pkg4d = CvePkg("debian", "pkg4", "needed", where="sid")
        pkgs.append(pkg4d)

        pkg4.setPriorities(
            [("pkg4", "high"), ("pkg4/sid", "negligible"), ("pkg4/buster", "low")]
        )
        pkg4.setTags(
            [
                ("pkg4/sid", "pie apparmor"),
                ("pkg4/buster", "pie"),
                ("pkg4/wheezy", "fortify-source"),
            ]
        )

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
Priority_pkg3: low
git_pkg3: needed
snap_pkg3: needed

Patches_pkg4:
Tags_pkg4/buster: pie
Tags_pkg4/sid: apparmor pie
Tags_pkg4/wheezy: fortify-source
Priority_pkg4: high
Priority_pkg4/buster: low
Priority_pkg4/sid: negligible
debian/buster_pkg4: needed
debian/sid_pkg4: needed
debian/squeeze_pkg4: needed
debian/wheezy_pkg4: needed
"""
        )
        res = cve.onDiskFormat()
        self.assertEqual(exp2, res)

    def test_onDiskFormatSorted(self):
        """Test onDiskFormat() - sorted"""
        self.maxDiff = 1024
        self._mock_readCve(self._cve_template())
        exp = """Candidate: CVE-2020-1234
OpenDate: 2020-06-29
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
Mitigation:
 Some mitigation
 more
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
                CvePkg(
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
        with cvelib.testutil.capturedOutput() as (output, error):
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

    def test__verifySingleline(self):
        """Test _verifySingleline()"""
        tsts = [
            # valid
            ("Empty", "", False, None),
            ("Key", "value", False, None),
            ("Key", "foo\\tbar", False, None),
            # allow_utf8 true
            ("Empty", "", True, None),
            ("Key", "value", True, None),
            ("Key", "foo\\tbar", True, None),
            ("Key", "foo bár", True, None),  # printable utf-8 supported
            # invalid
            (
                "Key",
                "foo\nbar",
                False,
                "invalid Key: 'foo\nbar' (expected single line)",
            ),
            (
                "Key",
                "foo\x00bar",
                False,
                "invalid Key (contains unprintable characters)",
            ),
            ("Key", "foo\tbar", False, "invalid Key (contains unprintable characters)"),
            (
                "Key",
                "foo b\u00A0r",
                False,
                "invalid Key (contains unprintable characters)",
            ),
            (
                "Key",
                "foo bar 😀",
                False,
                "invalid Key: 'foo bar 😀' (contains non-ASCII characters)",
            ),
            # invalid allow_utf8 true
            ("Key", "foo\nbar", True, "invalid Key: 'foo\nbar' (expected single line)"),
            (
                "Key",
                "foo\x00bar",
                True,
                "invalid Key (contains unprintable characters)",
            ),
            ("Key", "foo\tbar", True, "invalid Key (contains unprintable characters)"),
            (
                "Key",
                "foo b\u00A0r",
                True,
                "invalid Key (contains unprintable characters)",
            ),
        ]

        for key, val, allow_utf8, expErr in tsts:
            if expErr is None:
                cvelib.cve.CVE()._verifySingleline(key, val, allow_utf8=allow_utf8)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifySingleline(key, val, allow_utf8=allow_utf8)
                self.assertEqual(expErr, str(context.exception))

    def test__verifyMultiline(self):
        """Test _isMultiline()"""
        tsts = [
            # valid
            ("Empty", "", False, 0, None),
            ("Key", "\n foo", False, 1, None),
            ("Key", "\n foo\n", False, 1, None),
            ("Key", "\n foo\n bar", False, 2, None),
            ("Key", "\n foo\n .\n bar", False, 3, None),
            # valid allow_utf8 true
            ("Empty", "", True, 0, None),
            ("Key", "\n foo", True, 1, None),
            ("Key", "\n foo\n", True, 1, None),
            ("Key", "\n foo\n bar", True, 2, None),
            ("Key", "\n foo\n .\n bar", True, 3, None),
            ("Key", "\n foo bar 😀", True, 1, None),
            ("Key", "\n foo bár", True, 1, None),
            # bad
            ("Key", "\n", False, None, "invalid Key (empty)"),
            (
                "Key",
                "single",
                False,
                None,
                "invalid Key: 'single' (missing leading newline)",
            ),
            (
                "Key",
                "no\nleading\nnewline",
                False,
                None,
                "invalid Key: 'no\nleading\nnewline' (missing leading newline)",
            ),
            (
                "Key",
                "\nno\nleading\nspace",
                False,
                None,
                "invalid Key: '\nno\nleading\nspace' (missing leading space)",
            ),
            (
                "Key",
                "\n foo\n\n",
                False,
                None,
                "invalid Key: '\n foo\n\n' (empty line)",
            ),
            (
                "Key",
                "\n foo\x00bar",
                False,
                None,
                "invalid Key (contains unprintable characters)",
            ),
            (
                "Key",
                "\n foo\tbar",
                False,
                None,
                "invalid Key (contains unprintable characters)",
            ),
            (
                "Key",
                "\n foo b\u00A0r",
                False,
                None,
                "invalid Key (contains unprintable characters)",
            ),
            (
                "Key",
                "\n foo bar 😀",
                False,
                None,
                "invalid Key: '\n foo bar 😀' (contains non-ASCII characters)",
            ),
            (
                "Key",
                "\n foo bár",
                False,
                None,
                "invalid Key: '\n foo bár' (contains non-ASCII characters)",
            ),
            # bad allow_utf8 true
            ("Key", "\n", True, None, "invalid Key (empty)"),
            (
                "Key",
                "single",
                True,
                None,
                "invalid Key: 'single' (missing leading newline)",
            ),
            (
                "Key",
                "no\nleading\nnewline",
                True,
                None,
                "invalid Key: 'no\nleading\nnewline' (missing leading newline)",
            ),
            (
                "Key",
                "\nno\nleading\nspace",
                True,
                None,
                "invalid Key: '\nno\nleading\nspace' (missing leading space)",
            ),
            ("Key", "\n foo\n\n", True, None, "invalid Key: '\n foo\n\n' (empty line)"),
            (
                "Key",
                "\n foo\x00bar",
                True,
                None,
                "invalid Key (contains unprintable characters)",
            ),
            (
                "Key",
                "\n foo\tbar",
                True,
                None,
                "invalid Key (contains unprintable characters)",
            ),
            (
                "Key",
                "\n foo b\u00A0r",
                True,
                None,
                "invalid Key (contains unprintable characters)",
            ),
        ]
        for key, val, allow_utf8, num, err in tsts:
            if num is not None:
                lines = cvelib.cve.CVE()._verifyMultiline(
                    key, val, allow_utf8=allow_utf8
                )
                self.assertEqual(num, len(lines))
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifyMultiline(key, val, allow_utf8=allow_utf8)
                self.assertEqual(err, str(context.exception))

    def test__verifyRequired(self):
        """Test _verifyRequired()"""
        t = self._cve_template()
        cvelib.cve.CVE()._verifyRequired(t)
        del t["Candidate"]
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._verifyRequired(t)
        self.assertEqual("missing required field 'Candidate'", str(context.exception))

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

    def test_setData(self):
        """Test setData()"""
        # valid
        hdrs = self._mockHeaders(self._cve_template())
        cvelib.cve.CVE().setData(hdrs)

        # optional missing is ok
        hdrs = self._mockHeaders(self._cve_template())
        del hdrs["CRD"]
        del hdrs["Mitigation"]
        cvelib.cve.CVE().setData(hdrs)

        # valid with packages
        t = self._cve_template()
        t["upstream_foo"] = "needed"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # comment ignored
        t = self._cve_template()
        t["#blah_foo"] = "needed"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Patches_foo
        t = self._cve_template()
        t["Patches_foo"] = ""
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Patches_aa (short)
        t = self._cve_template()
        t["Patches_aa"] = ""
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Tags_foo
        t = self._cve_template()
        t["Tags_foo"] = "apparmor"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Tags_aa (short)
        t = self._cve_template()
        t["Tags_aa"] = "apparmor"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Tags_foo/bar
        t = self._cve_template()
        t["Tags_foo/bar"] = "apparmor"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Tags_foo_bar ('_' in name)
        t = self._cve_template()
        t["Tags_foo_bar"] = "apparmor pie"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Tags_foo_bar/baz ('_' in name)
        t = self._cve_template()
        t["Tags_foo_bar/baz"] = "apparmor pie"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Priority_foo
        t = self._cve_template()
        t["Priority_foo"] = "medium"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Priority_aa (short)
        t = self._cve_template()
        t["Priority_aa"] = "medium"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Priority_foo/bar
        t = self._cve_template()
        t["Priority_foo/bar"] = "medium"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Priority_foo_bar ('_' in name)
        t = self._cve_template()
        t["Priority_foo_bar"] = "medium"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # valid Priority_foo_bar/baz ('_' in name)
        t = self._cve_template()
        t["Priority_foo_bar/baz"] = "medium"
        hdrs = self._mockHeaders(t)
        cvelib.cve.CVE().setData(hdrs)

        # invalid
        hdrs = self._mockHeaders(self._cve_template())
        del hdrs["Candidate"]
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE().setData(hdrs)
        self.assertEqual("missing required field 'Candidate'", str(context.exception))

    def test_setDataPatchesKeys(self):
        """Test setData() - Patches_"""
        tsts = [
            # valid
            ("Patches_foo", False, True),
            ("Patches_%s" % ("a" * 50), False, True),
            ("Patches_foo_bar", False, True),  # non-compat allows '_' in software
            ("Patches_FOO", False, True),  # non-compat allows 'A-Z' in software
            # invalid
            ("Patches_", False, False),
            ("Patches_b@d", False, False),
            ("Patches_%s" % ("a" * 51), False, False),
            ("Patches_foo_bar/baz", False, False),
            ("Patches_foo_", False, False),
            # valid compat
            ("Patches_foo", True, True),
            ("Patches_%s" % ("a" * 50), True, True),
            # invalid compat
            ("Patches_", True, False),
            ("Patches_b@d", True, False),
            ("Patches_%s" % ("a" * 51), True, False),
            ("Patches_foo_bar/baz", True, False),
            ("Patches_foo_bar", True, False),  # compat disallows '_' in software
            ("Patches_FOO", True, False),  # compat disallows 'A-Z' in software
        ]
        for key, compat, valid in tsts:
            cve = cvelib.cve.CVE(compatUbuntu=compat)
            hdrs = self._mockHeaders(self._cve_template())
            hdrs[key] = ""
            if valid:
                cve.setData(hdrs)
            else:
                cstr = ""
                if compat:
                    cstr = "compat "
                with self.assertRaises(cvelib.common.CveException) as context:
                    cve.setData(hdrs)
                self.assertEqual(
                    "invalid %sPatches_ key: '%s'" % (cstr, key), str(context.exception)
                )

    def test_setDataTagsKeys(self):
        """Test setData() - Tags_"""
        tsts = [
            # valid
            ("Tags_foo", False, True),
            ("Tags_%s" % ("a" * 50), False, True),
            ("Tags_foo_bar", False, True),  # non-compat allows '_' in software
            ("Tags_foo_bar/baz", False, True),
            ("Tags_%s/foo" % ("a" * 50), False, True),
            ("Tags_foo/%s" % ("a" * 50), False, True),
            ("Tags_FOO", False, True),
            # invalid
            ("Tags_", False, False),
            ("Tags_b@d", False, False),
            ("Tags_%s" % ("a" * 51), False, False),
            ("Tags_foo/", False, False),
            ("Tags_foo/b@d", False, False),
            ("Tags_foo/%s" % ("a" * 51), False, False),
            ("Tags_foo/bar/bad", False, False),
            # valid ubuntu
            ("Tags_foo", True, True),
            ("Tags_%s" % ("a" * 50), True, True),
            ("Tags_foo_%s" % ("a" * 50), True, True),
            ("Tags_foo_precise/esm", True, True),
            # invalid compat
            ("Tags_", True, False),
            ("Tags_b@d", True, False),
            ("Tags_%s" % ("a" * 51), True, False),
            ("Tags_foo_", True, False),
            ("Tags_foo_b@d", True, False),
            ("Tags_foo_%s" % ("a" * 51), True, False),
            ("Tags_foo/bar", True, False),
            ("Tags_foo_bar_baz", True, False),
            ("Tags_FOO", True, False),
        ]
        for key, compat, valid in tsts:
            cve = cvelib.cve.CVE(compatUbuntu=compat)
            hdrs = self._mockHeaders(self._cve_template())
            hdrs[key] = ""
            if valid:
                cve.setData(hdrs)
            else:
                cstr = ""
                if compat:
                    cstr = "compat "
                with self.assertRaises(cvelib.common.CveException) as context:
                    cve.setData(hdrs)
                self.assertEqual(
                    "invalid %sTags_ key: '%s'" % (cstr, key), str(context.exception)
                )

    def test_setDataPriorityKeys(self):
        """Test setData() - Priority_"""
        tsts = [
            # valid
            ("Priority_foo", False, True),
            ("Priority_%s" % ("a" * 50), False, True),
            ("Priority_foo_bar", False, True),  # non-compat allows '_' in software
            ("Priority_foo_bar/baz", False, True),
            ("Priority_%s/foo" % ("a" * 50), False, True),
            ("Priority_foo/%s" % ("a" * 50), False, True),
            ("Priority_FOO", False, True),
            # invalid
            ("Priority_", False, False),
            ("Priority_b@d", False, False),
            ("Priority_%s" % ("a" * 51), False, False),
            ("Priority_foo/", False, False),
            ("Priority_foo/b@d", False, False),
            ("Priority_foo/%s" % ("a" * 51), False, False),
            ("Priority_foo/bar/bad", False, False),
            # valid ubuntu
            ("Priority_foo", True, True),
            ("Priority_%s" % ("a" * 50), True, True),
            ("Priority_foo_%s" % ("a" * 50), True, True),
            ("Priority_foo_precise/esm", True, True),
            # invalid compat
            ("Priority_", True, False),
            ("Priority_b@d", True, False),
            ("Priority_%s" % ("a" * 51), True, False),
            ("Priority_foo_", True, False),
            ("Priority_foo_b@d", True, False),
            ("Priority_foo_%s" % ("a" * 51), True, False),
            ("Priority_foo/bar", True, False),
            ("Priority_foo_bar_baz", True, False),
            ("Priority_FOO", True, False),
        ]
        for key, compat, valid in tsts:
            cve = cvelib.cve.CVE(compatUbuntu=compat)
            hdrs = self._mockHeaders(self._cve_template())
            hdrs[key] = "medium"
            if valid:
                cve.setData(hdrs)
            else:
                cstr = ""
                if compat:
                    cstr = "compat "
                with self.assertRaises(cvelib.common.CveException) as context:
                    cve.setData(hdrs)
                self.assertEqual(
                    "invalid %sPriority_ key: '%s'" % (cstr, key),
                    str(context.exception),
                )

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
        del hdrs["Mitigation"]
        cvelib.cve.CVE()._verifyCve(hdrs)

        # invalid - missing required
        hdrs = self._mockHeaders(self._cve_template())
        del hdrs["Candidate"]
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._verifyCve(hdrs)
        self.assertEqual("missing required field 'Candidate'", str(context.exception))

        # invalid - wrong type
        hdrs = self._mockHeaders(self._cve_template())
        hdrs["Description"] = ["wrong type"]
        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.CVE()._verifyCve(hdrs)
        self.assertEqual("field 'Description' is not str", str(context.exception))

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
            ("CVE-2020-GH1#%s" % ("a" * 50), True),
            ("CVE-2020-GH123456789012#A", True),
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
            ("CVE-2020-GH1#%s" % ("a" * 51), False),
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
            ("2019-02-25 09:00:00 CEST", True),
            # https://bugs.python.org/issue22377
            ("2020-12-14 07:08:09 BADTZ", True),
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
                cvelib.cve.CVE()._verifyDate("TestKey", date)
            else:
                suffix = "(use empty or YYYY-MM-DD [HH:MM:SS [TIMEZONE]])"
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifyDate("TestKey", date)
                self.assertEqual(
                    "invalid TestKey: '%s' %s" % (date, suffix),
                    str(context.exception),
                )

    def test__verifyPublicDateAndCRD(self):
        """Test _verifyPublicDate() and _verifyCRD()"""
        tsts = [
            # valid
            ("", False, None),
            ("2021-01-25", False, None),
            ("2021-01-25 16:00:00", False, None),
            # valid Ubuntu
            ("", True, None),
            ("2021-01-25", True, None),
            ("2021-01-25 16:00:00", True, None),
            ("unknown", True, None),
            # invalid
            ("\n", False, "invalid %(key)s: '\n' (expected single line)"),
            (
                "bad",
                False,
                "invalid %(key)s: 'bad' (use empty or YYYY-MM-DD [HH:MM:SS [TIMEZONE]])",
            ),
            (
                "unknown",
                False,
                "invalid %(key)s: 'unknown' (use empty or YYYY-MM-DD [HH:MM:SS [TIMEZONE]])",
            ),
            # invalid compat
            ("\n", True, "invalid %(key)s: '\n' (expected single line)"),
            (
                "bad",
                True,
                "invalid %(key)s: 'bad' (use 'unknown' or YYYY-MM-DD [HH:MM:SS [TIMEZONE]])",
            ),
        ]
        for tstType in ["PublicDate", "CRD"]:
            for val, compat, err in tsts:
                fn = None
                cve = cvelib.cve.CVE(compatUbuntu=compat)
                if tstType == "PublicDate":
                    fn = cve._verifyPublicDate
                elif tstType == "CRD":
                    fn = cve._verifyCRD
                else:  # pragma: nocover
                    continue  # needed by pyright

                if not err:
                    fn(tstType, val)
                else:
                    with self.assertRaises(cvelib.common.CveException) as context:
                        fn(tstType, val)
                    self.assertEqual(err % {"key": tstType}, str(context.exception))

    def test__verifyOpenDate(self):
        """Test _verifyOpenDate()"""
        tsts = [
            # valid
            ("2021-01-25", False, None),
            ("2021-01-25 16:00:00", False, None),
            # valid Ubuntu
            ("2021-01-25", True, None),
            ("2021-01-25 16:00:00", True, None),
            ("unknown", True, None),
            # invalid
            ("", False, "invalid %(key)s: '' (use YYYY-MM-DD [HH:MM:SS [TIMEZONE]])"),
            ("\n", False, "invalid %(key)s: '\n' (expected single line)"),
            (
                "bad",
                False,
                "invalid %(key)s: 'bad' (use YYYY-MM-DD [HH:MM:SS [TIMEZONE]])",
            ),
            (
                "unknown",
                False,
                "invalid %(key)s: 'unknown' (use YYYY-MM-DD [HH:MM:SS [TIMEZONE]])",
            ),
            # invalid compat
            ("", True, "invalid %(key)s: '' (use YYYY-MM-DD [HH:MM:SS [TIMEZONE]])"),
            ("\n", True, "invalid %(key)s: '\n' (expected single line)"),
            (
                "bad",
                True,
                "invalid %(key)s: 'bad' (use YYYY-MM-DD [HH:MM:SS [TIMEZONE]])",
            ),
        ]
        for val, compat, err in tsts:
            cve = cvelib.cve.CVE(compatUbuntu=compat)
            fn = cve._verifyOpenDate

            if not err:
                fn("OpenDate", val)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    fn("OpenDate", val)
                self.assertEqual(err % {"key": "OpenDate"}, str(context.exception))

    def test__verifyUrl(self):
        """Test _verifyUrl()"""
        tsts = [
            # valid
            ("cvs://1", None),
            ("ftp://1", None),
            ("git://1", None),
            ("http://1", None),
            ("https://1", None),
            ("sftp://1", None),
            ("shttp://1", None),
            ("svn://1", None),
            ("https://github.com/foo/bar/issues/1234", None),
            ("https://launchpad.net/bugs/1234", None),
            ("https://launchpad.net/ubuntu/+source/foo/+bug/1234", None),
            # invalid
            ("\n", "invalid url in %(key)s: '\n'"),
            ("", "invalid url in %(key)s: ''"),
            ("foo://", "invalid url in %(key)s: 'foo://'"),
        ]
        for val, err in tsts:
            if not err:
                cvelib.cve.CVE()._verifyUrl("TestKey", val)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.CVE()._verifyUrl("TestKey", val)
                self.assertEqual(err % {"key": "TestKey"}, str(context.exception))

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
            ("Priority_foo_bar", "medium", False, True),
            ("Priority_foo_bar/baz", "medium", False, True),
            ("Priority_foo_bar/baz", "untriaged", True, True),
            # invalid
            ("Priority", "untriaged", False, False),
            ("Priority_foo", "untriaged", False, False),
            ("Priority_foo_bar", "untriaged", False, False),
            ("Priority_foo_bar/baz", "untriaged", False, False),
            ("Priority", "bad", True, False),
            ("Priority", "needed", False, False),
            ("Priority", "needs-triage", False, False),
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
            # valid (others are verified separately)
            ("\n git://1", None),
            ("\n http://1", None),
            ("\n https://1", None),
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
            else:  # pragma: nocover
                continue  # needed by pyright

            for val, err in tsts:
                if not err:
                    fn(tstType, val)
                else:
                    with self.assertRaises(cvelib.common.CveException) as context:
                        fn(tstType, val)
                    self.assertEqual(err % {"key": tstType}, str(context.exception))

    def test__verifyDescriptionAndNotesAndMitigation(self):
        """Test _verifyDescription(), _verifyNotes() and _verifyMitigation()"""
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
            ("single line", "invalid %(key)s: 'single line' (missing leading newline)"),
        ]
        for tstType in ["Description", "Notes", "Mitigation"]:
            fn = None
            if tstType == "Description":
                fn = cvelib.cve.CVE()._verifyDescription
            elif tstType == "Notes":
                fn = cvelib.cve.CVE()._verifyNotes
            elif tstType == "Mitigation":
                fn = cvelib.cve.CVE()._verifyMitigation
            else:  # pragma: nocover
                continue  # needed by pyright

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
            ("irc_nick", None),
            ("Madonna", None),
            ("Joe Schmoe", None),
            ("Joe Schmoe (jschmoe)", None),
            ("Joe Schmoe (@jschmoe)", None),
            ("Harry Potter Jr.", None),
            ("Alfred Foo-Bar", None),
            ("Angus O'Hare", None),
            ("Angus O'Hare, Alfred Foo-Bar", None),
            ("Joe Schmoe (jschmoe), Madonna", None),
            ("Madonna, Joe Schmoe (@jschmoe)", None),
            ("Madonna (madonna), Joe Schmoe (@jschmoe)", None),
            ("Madonna, Joe Schmoe and Alfred Foo-Bar", None),
            ('Madonna, Joe "Ralph" Schmoe and Alfred Foo-Bar', None),
            ("Joe Bár", None),  # printable utf-8 supported
            ("Joe Bár (joebar)", None),
            ("Joe Bár (@joebar)", None),
            ("Joe Bár (@joebar), Joe Schmoe (@jschmoe)", None),
            ("Madonna, Angus O'Hare, Joe Bár (@joebar)", None),
            # invalid
            ("Joe\nSchmoe", "invalid %(key)s: 'Joe\nSchmoe' (expected single line)"),
            ("Joe (", "invalid %(key)s: 'Joe ('"),
            ("Joe )", "invalid %(key)s: 'Joe )'"),
            ("Joe ()", "invalid %(key)s: 'Joe ()'"),
            ("Joe (@)", "invalid %(key)s: 'Joe (@)'"),
            ("Joe @joeschmoe", "invalid %(key)s: 'Joe @joeschmoe'"),
            ("Joe B\u00A0r", "invalid %(key)s (contains unprintable characters)"),
        ]
        for tstType in ["Discovered-by", "Assigned-to"]:
            fn = None
            if tstType == "Discovered-by":
                fn = cvelib.cve.CVE()._verifyDiscoveredBy
            elif tstType == "Assigned-to":
                fn = cvelib.cve.CVE()._verifyAssignedTo
            else:  # pragma: nocover
                continue  # needed by pyright

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
            (
                "https://github.com/foo/%s/issues/1" % ("a" * 50),
                "CVE-%s-GH1#%s" % (year, ("a" * 50)),
                None,
            ),
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
            (
                "https://github.com/foo/%s/issues/1" % ("a" * 51),
                None,
                "invalid url: 'https://github.com/foo/%s/issues/1' (only support github issues)"
                % ("a" * 51),
            ),
        ]
        for (url, exp, exp_fail) in tsts:
            if exp is not None:
                res = cvelib.cve.cveFromUrl(url)
                self.assertEqual(exp, res)
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
        self.assertEqual(0, len(cve.pkgs))

        pkgs = [
            CvePkg("git", "pkg1", "needed"),
            CvePkg("git", "pkg2", "needed"),
        ]
        patches = {
            "pkg1": " upstream: http://a\n other: http://b",
            "pkg2": " vendor: http://c\n distro: https://d",
        }
        tags = {
            "pkg1": "pie hardlink-restriction",
            "pkg2": "apparmor",
            "pkg2_a": "fortify-source heap-protector",
        }
        priorities = {
            "pkg1": "high",
            "pkg2": "medium",
            "pkg2_a": "low",
        }

        cve.setPackages(pkgs, patches=patches, tags=tags, priorities=priorities)
        self.assertEqual(2, len(cve.pkgs))

        self.assertEqual(2, len(cve.pkgs[0].patches))
        self.assertEqual(1, len(cve.pkgs[0].tags))
        self.assertEqual(2, len(cve.pkgs[0].tags["pkg1"]))
        self.assertEqual(1, len(cve.pkgs[0].priorities))
        self.assertEqual("high", cve.pkgs[0].priorities["pkg1"])

        self.assertEqual(2, len(cve.pkgs[1].patches))
        self.assertEqual(2, len(cve.pkgs[1].tags))
        self.assertEqual(1, len(cve.pkgs[1].tags["pkg2"]))
        self.assertEqual(2, len(cve.pkgs[1].tags["pkg2_a"]))
        self.assertEqual(2, len(cve.pkgs[1].priorities))
        self.assertEqual("medium", cve.pkgs[1].priorities["pkg2"])
        self.assertEqual("low", cve.pkgs[1].priorities["pkg2_a"])

        # append
        self._mock_readCve(self._cve_template())
        cve = cvelib.cve.CVE(fn="fake")
        self.assertEqual(0, len(cve.pkgs))

        # append one
        pkgs = [CvePkg("git", "pkg1", "needed")]
        cve.setPackages(pkgs)
        self.assertEqual(1, len(cve.pkgs))
        self.assertEqual(1, len(cve._pkgs_list))
        self.assertTrue(pkgs[0].what() in cve._pkgs_list)

        # append another
        pkgs = [CvePkg("git", "pkg2", "needed")]
        cve.setPackages(pkgs, append=True)
        self.assertEqual(2, len(cve.pkgs))
        self.assertEqual(2, len(cve._pkgs_list))
        self.assertTrue(pkgs[0].what() in cve._pkgs_list)

        # append with duplicates
        pkgs = [
            CvePkg("git", "pkg1", "needed"),
            CvePkg("git", "pkg2", "needed"),
            CvePkg("git", "pkg3", "needed"),
        ]
        cve.setPackages(pkgs, append=True)
        self.assertEqual(3, len(cve.pkgs))
        self.assertEqual(3, len(cve._pkgs_list))
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
        self.orig_xdg_config_home, self.tmpdir = cvelib.testutil._newConfigFile(
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
            if fn.startswith("retired"):
                tmpl["git/github_pkg1"] = "released"
            else:
                tmpl["git/github_pkg1"] = "needed"
            content = cvelib.testutil.cveContentFromDict(tmpl)

            cve_fn = os.path.join(cveDirs[dir], cand)

            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

            with cvelib.testutil.capturedOutput() as (output, error):
                cvelib.cve.checkSyntax(cveDirs, False)
            os.unlink(cve_fn)

            if expErr is None:
                self.assertEqual("", output.getvalue().strip())
                self.assertEqual("", error.getvalue().strip())
            else:
                self.assertEqual("", output.getvalue().strip())
                self.assertEqual(expErr, error.getvalue().strip())

        # non-matching
        tmpl = self._cve_template()
        tmpl["git/github_pkg1"] = "needed"
        content = cvelib.testutil.cveContentFromDict(tmpl)
        cve_fn = os.path.join(cveDirs["active"], "CVE-1234-5678")
        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_fn)

        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "WARN: active/CVE-1234-5678: non-matching candidate 'CVE-2020-1234'",
            error.getvalue().strip(),
        )

        # missing packages
        tmpl = self._cve_template()
        content = cvelib.testutil.cveContentFromDict(tmpl)
        cve_fn = os.path.join(cveDirs["active"], tmpl["Candidate"])
        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_fn)

        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "WARN: active/CVE-2020-1234: missing affected software",
            error.getvalue().strip(),
        )

        # missing references
        tmpl = self._cve_template()
        tmpl["References"] = ""
        tmpl["git/github_pkg1"] = "needed"
        content = cvelib.testutil.cveContentFromDict(tmpl)
        cve_fn = os.path.join(cveDirs["active"], tmpl["Candidate"])
        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_fn)

        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "WARN: active/CVE-2020-1234: missing references",
            error.getvalue().strip(),
        )

        # retired has needed
        tmpl = self._cve_template()
        tmpl["Candidate"] = "CVE-1234-5678"
        tmpl["git/github_pkg1"] = "needed"
        content = cvelib.testutil.cveContentFromDict(tmpl)
        cve_fn = os.path.join(cveDirs["retired"], "CVE-1234-5678")
        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_fn)

        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "WARN: retired/CVE-1234-5678: is retired but has open items",
            error.getvalue().strip(),
        )

        # active has closed
        tmpl = self._cve_template()
        tmpl["Candidate"] = "CVE-1234-5678"
        tmpl["git/github_pkg1"] = "released"
        content = cvelib.testutil.cveContentFromDict(tmpl)
        cve_fn = os.path.join(cveDirs["active"], "CVE-1234-5678")
        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_fn)

        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "WARN: active/CVE-1234-5678: is active but has only closed items",
            error.getvalue().strip(),
        )

        # multiple
        tmpl = self._cve_template()
        tmpl["git/github_pkg1"] = "needed"
        content = cvelib.testutil.cveContentFromDict(tmpl)
        cve_active_fn = os.path.join(cveDirs["active"], tmpl["Candidate"])
        with open(cve_active_fn, "w") as fp:
            fp.write("%s" % content)

        cve_retired_fn = os.path.join(cveDirs["retired"], tmpl["Candidate"])
        tmpl["git/github_pkg1"] = "released"
        content = cvelib.testutil.cveContentFromDict(tmpl)
        with open(cve_retired_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_active_fn)
        os.unlink(cve_retired_fn)

        self.assertEqual("", output.getvalue().strip())
        self.assertTrue(
            error.getvalue()
            .strip()
            .startswith("WARN: multiple entries for CVE-2020-1234: ")
        )

        # ghas
        ghasTsts = [
            # valid
            ("gh-dependabot, gh-secret", None),
            ("gh-secret, gh-dependabot", None),
            ("foo, gh-dependabot, gh-secret", None),
            ("gh-dependabot, foo, gh-secret", None),
            ("gh-dependabot, gh-secret, foo", None),
            # invalid
            (
                "g-dependabot, gh-secret",
                "WARN: active/CVE-2020-1234: 'gh-dependabot' missing from Discovered-by",
            ),
            (
                "gh-dependaboT, gh-secret",
                "WARN: active/CVE-2020-1234: 'gh-dependabot' missing from Discovered-by",
            ),
            (
                "gh-dependabotX, gh-secret",
                "WARN: active/CVE-2020-1234: 'gh-dependabot' missing from Discovered-by",
            ),
            (
                "gh-dependabot, secret",
                "WARN: active/CVE-2020-1234: 'gh-secret' missing from Discovered-by",
            ),
            (
                "gh-dependabot",
                "WARN: active/CVE-2020-1234: 'gh-secret' missing from Discovered-by",
            ),
            (
                "gh-secret",
                "WARN: active/CVE-2020-1234: 'gh-dependabot' missing from Discovered-by",
            ),
        ]

        for dsc, expErr in ghasTsts:
            tmpl = self._cve_template()
            tmpl["git/github_pkg1"] = "needed"
            tmpl[
                "GitHub-Advanced-Security"
            ] = """
 - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-xg2h-wx96-xgxr
   severity: moderate
   status: dismissed (inaccurate; who)
   url: https://github.com/bar/baz/security/dependabot/1
 - type: secret
   secret: Slack Incoming Webhook URL
   detectedIn: /path/to/file
   status: dismissed (revoked; who)
   url: https://github.com/bar/baz/security/secret-scanning/1
"""
            tmpl["Discovered-by"] = dsc
            content = cvelib.testutil.cveContentFromDict(tmpl)
            cve_fn = os.path.join(cveDirs["active"], tmpl["Candidate"])
            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

            with cvelib.testutil.capturedOutput() as (output, error):
                cvelib.cve.checkSyntax(cveDirs, False)
            os.unlink(cve_fn)

            if expErr is None:
                self.assertEqual("", output.getvalue().strip())
                self.assertEqual("", error.getvalue().strip())
            else:
                self.assertEqual("", output.getvalue().strip())
                self.assertEqual(expErr, error.getvalue().strip())

        # retired has open GHAS
        tmpl = self._cve_template()
        tmpl["Candidate"] = "CVE-1234-5678"
        tmpl["git/github_pkg1"] = "released"
        tmpl["Discovered-by"] = "gh-dependabot"
        tmpl[
            "GitHub-Advanced-Security"
        ] = """
 - type: dependabot
   dependency: foo
   detectedIn: yarn.lock
   advisory: https://github.com/advisories/GHSA-xg2h-wx96-xgxr
   severity: moderate
   status: needed
   url: https://github.com/influxdata/foo/security/dependabot/1
"""
        content = cvelib.testutil.cveContentFromDict(tmpl)
        cve_fn = os.path.join(cveDirs["retired"], "CVE-1234-5678")
        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.cve.checkSyntax(cveDirs, False)
        os.unlink(cve_fn)

        self.assertEqual("", output.getvalue().strip())
        self.assertEqual(
            "WARN: retired/CVE-1234-5678: is retired but has open GitHub Advanced Security items",
            error.getvalue().strip(),
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
                self.assertEqual(exp, res)
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
                ["https://www.cve.org/CVERecord?id=CVE-2020-1234"],
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
            self.assertEqual(expRefs, refs)
            self.assertEqual(expBugs, bugs)

    def test__createCve(self):
        """Test _createCve()"""

        def createAndVerify(cveDirs, cve_fn, cve, pkgs):
            # add a new CVE
            cvelib.cve._createCve(cveDirs, cve_fn, cve, pkgs, False)

            # now read it off disk and verify it
            res = cvelib.common.readCve(cve_fn)

            fields = [
                "Candidate",
                "OpenDate",
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
                    self.assertEqual(os.path.basename(cve_fn), res[k])
                elif k == "References":
                    self.assertEqual(
                        "\n https://www.cve.org/CVERecord?id=%s"
                        % os.path.basename(cve_fn),
                        res[k],
                    )
                elif k == "Priority":
                    self.assertEqual("untriaged", res[k])
                elif k == "OpenDate":
                    now = datetime.datetime.now()
                    t = "%d-%0.2d-%0.2d" % (now.year, now.month, now.day)
                    self.assertEqual(t, res[k])
                else:
                    self.assertEqual("", res[k])
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
        self.assertEqual("needs-triage", res["git/github_foo"])
        self.assertFalse("Patches_bar" in res)
        self.assertFalse("git/github_bar" in res)

        # add to existing
        res2 = createAndVerify(
            cveDirs, cve_fn, os.path.basename(cve_fn), ["git/github_bar"]
        )
        self.assertTrue("Patches_foo" in res2)
        self.assertTrue("git/github_foo" in res2)
        self.assertEqual("needs-triage", res2["git/github_foo"])
        self.assertTrue("Patches_bar" in res2)
        self.assertTrue("git/github_bar" in res2)
        self.assertEqual("needs-triage", res2["git/github_bar"])

        # discovered-by
        cvelib.cve._createCve(
            cveDirs,
            cve_fn,
            os.path.basename(cve_fn),
            ["git/github_foo"],
            False,
            discovered_by="foo",
        )
        res3 = cvelib.common.readCve(cve_fn)
        self.assertEqual("foo", res3["Discovered-by"])

        # assigned-to
        cvelib.cve._createCve(
            cveDirs,
            cve_fn,
            os.path.basename(cve_fn),
            ["git/github_foo"],
            False,
            assigned_to="foo",
        )
        res4 = cvelib.common.readCve(cve_fn)
        self.assertEqual("foo", res4["Discovered-by"])

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
            ("CVE-2021-999999", ["git/github_foo"], False, None, False, None),
            ("CVE-2021-999999", ["git/github_foo"], False, None, True, None),
            (
                "CVE-2021-999999",
                ["git/github_foo", "git/github_bar"],
                False,
                None,
                False,
                None,
            ),
            ("https://github.com/foo/bar/issues/1234", [], False, None, False, None),
            ("https://github.com/foo/bar/issues/1234", [], False, None, True, None),
            (
                "https://github.com/foo/bar/issues/1234",
                ["git/github_bar"],
                False,
                None,
                False,
                None,
            ),
            (
                "https://github.com/foo/bar/issues/1234",
                ["git/github_bar"],
                False,
                "baz",
                False,
                None,
            ),
            ("CVE-2021-999999", ["git/github_baz/mod"], False, None, False, None),
            ("CVE-2021-999999", ["ubuntu/focal_norf"], False, None, False, None),
            ("CVE-2021-999999", ["debian/buster_norf"], False, None, False, None),
            # valid compat
            ("CVE-2021-999999", ["focal_baz"], True, None, False, None),
            ("CVE-2021-999999", ["norf"], True, None, False, None),
            ("CVE-2021-999999", ["norf", "corge"], True, None, False, None),
            # invalid
            (
                "CVE-2021-bad",
                ["git/github_foo"],
                False,
                None,
                False,
                "invalid Candidate: 'CVE-2021-bad'",
            ),
            (
                "https://github.com/foo",
                [],
                False,
                None,
                False,
                "invalid url: 'https://github.com/foo' (only support github issues)",
            ),
            (
                "CVE-2021-999999",
                ["focal_baz"],
                False,
                None,
                False,
                "invalid package entry 'focal_baz: needs-triage'",
            ),
            (
                "CVE-2021-999999",
                [],
                False,
                None,
                False,
                "could not find usable packages for 'CVE-2021-999999'",
            ),
        ]

        for cve, pkgs, compat, boiler, retired, expFail in tsts:

            if expFail is not None:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.cve.addCve(
                        cveDirs, compat, cve, pkgs, boiler=boiler, retired=retired
                    )
                self.assertEqual(expFail, str(context.exception))
                continue

            dir = "active"
            if retired:
                dir = "retired"
            cve_fn = os.path.join(cveDirs[dir], cve)
            if cve.startswith("http"):
                cve_fn = os.path.join(cveDirs[dir], cvelib.cve.cveFromUrl(cve))

            with cvelib.testutil.capturedOutput() as (output, error):
                cvelib.cve.addCve(
                    cveDirs, compat, cve, pkgs, boiler=boiler, retired=retired
                )
            self.assertTrue(os.path.exists(cve_fn))

            out = output.getvalue().strip()
            err = error.getvalue().strip()
            self.assertEqual("", out)
            self.assertEqual("", err)

            with cvelib.testutil.capturedOutput() as (output, error):
                res = cvelib.common.readCve(cve_fn)
            os.unlink(cve_fn)
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual("", error.getvalue().strip())

            for p in pkgs:
                if "_" in p:
                    self.assertTrue(p in res)
                    self.assertEqual("needs-triage", res[p])
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
                        self.assertEqual("needs-triage", res[uPkg])

            if boiler is not None:
                self.assertTrue("upstream_baz" in res)
                self.assertEqual("needed", res["upstream_baz"])

    def test__getCVEPaths(self):
        """Test _getCVEPaths"""
        self.tmpdir = tempfile.mkdtemp(prefix="influx-security-tools-")
        content = (
            """[Location]
cve-data = %s
"""
            % self.tmpdir
        )
        self.orig_xdg_config_home, self.tmpdir = cvelib.testutil._newConfigFile(
            content, self.tmpdir
        )

        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        testData = [
            "active/CVE-2021-9997",
            "retired/CVE-2021-9998",
            "ignored/CVE-2021-9999",
        ]

        # create some files
        for fn in testData:
            tmpl = self._cve_template()
            dir, cand = fn.split("/")
            tmpl["Candidate"] = cand
            content = cvelib.testutil.cveContentFromDict(tmpl)

            cve_fn = os.path.join(cveDirs[dir], cand)

            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

        res = cvelib.cve._getCVEPaths(cveDirs)
        self.assertEqual(len(testData), len(res))
        testData.sort()
        for i in range(len(testData)):
            self.assertTrue(testData[i] in res[i])

    def test_collectCVEData(self):
        """Test collectCVEData()"""
        self.tmpdir = tempfile.mkdtemp(prefix="influx-security-tools-")
        content = (
            """[Location]
cve-data = %s
"""
            % self.tmpdir
        )
        self.orig_xdg_config_home, self.tmpdir = cvelib.testutil._newConfigFile(
            content, self.tmpdir
        )

        cveDirs = {}
        for d in cvelib.common.cve_reldirs:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.mkdir(cveDirs[d], 0o0700)

        data = [
            # valid
            "active/CVE-2021-9999",
            "retired/CVE-2021-9999",
            "ignored/CVE-2021-9999",
        ]

        for fn in data:
            tmpl = self._cve_template()
            dir, cand = fn.split("/")
            tmpl["Candidate"] = cand
            content = cvelib.testutil.cveContentFromDict(tmpl)

            cve_fn = os.path.join(cveDirs[dir], cand)

            with open(cve_fn, "w") as fp:
                fp.write("%s" % content)

        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.cve.collectCVEData(cveDirs, False)

        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

        # add a bad CVE
        tmpl = self._cve_template()
        dir = "active"
        cand = "CVE-bad"
        tmpl["Candidate"] = cand
        content = cvelib.testutil.cveContentFromDict(tmpl)
        cve_fn = os.path.join(cveDirs[dir], cand)

        with open(cve_fn, "w") as fp:
            fp.write("%s" % content)

        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.cve.collectCVEData(cveDirs, False)
        self.assertEqual("invalid Candidate: 'CVE-bad'", str(context.exception))
