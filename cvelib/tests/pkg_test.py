"""pkg_test.py: tests for pkg.py module"""

from unittest import TestCase

import cvelib.pkg
import cvelib.common


class TestPkg(TestCase):
    """Tests for the CVE data and functions"""

    def setUp(self):
        """Setup functions common for all tests"""

    def tearDown(self):
        """Teardown functions common for all tests"""

    def test___init__valid(self):
        """Test __init__()"""
        cvelib.pkg.CvePkg("git", "foo", "needed")

    def test___str__(self):
        """Test __str__()"""
        tsts = [
            # valid
            ("git", "foo", "needed", "", "", "", "git_foo: needed", None),
            ("git", "foo", "needed", "pub", "", "", "git/pub_foo: needed", None),
            ("git", "foo", "needed", "", "inky", "", "git_foo/inky: needed", None),
            ("git", "foo", "needed", "", "", "123-4", "git_foo: needed (123-4)", None),
            (
                "git",
                "foo",
                "needed",
                "pub",
                "",
                "123-4",
                "git/pub_foo: needed (123-4)",
                None,
            ),
            (
                "git",
                "foo",
                "needed",
                "",
                "inky",
                "123-4",
                "git_foo/inky: needed (123-4)",
                None,
            ),
            (
                "git",
                "foo",
                "needed",
                "pub",
                "inky",
                "123-4",
                "git/pub_foo/inky: needed (123-4)",
                None,
            ),
            # invalid
            ("", "foo", "needed", "", "", "", None, "invalid product ''"),
            ("git", "", "needed", "", "", "", None, "invalid software ''"),
            ("git", "foo", "", "", "", "", None, "invalid status ''"),
            ("", "foo", "needed", "pub", "", "", None, "invalid product ''"),
            ("git", "", "needed", "pub", "", "", None, "invalid software ''"),
            ("git", "foo", "", "", "pub", "", None, "invalid status ''"),
            ("", "foo", "needed", "", "inky", "", None, "invalid product ''"),
            ("git", "", "needed", "", "inky", "", None, "invalid software ''"),
            ("git", "foo", "", "", "", "inky", None, "invalid status ''"),
            ("", "foo", "needed", "", "", "123-4", None, "invalid product ''"),
            ("git", "", "needed", "", "", "123-4", None, "invalid software ''"),
            ("git", "foo", "", "", "", "123-4", None, "invalid status ''"),
            (
                "bad",
                "foo",
                "needed",
                "pub",
                "inky",
                "123-4",
                None,
                "invalid product 'bad'",
            ),
            (
                "git",
                "b@d",
                "needed",
                "pub",
                "inky",
                "123-4",
                None,
                "invalid software 'b@d'",
            ),
            ("git", "foo", "bad", "pub", "inky", "123-4", None, "invalid status 'bad'"),
            (
                "git",
                "foo",
                "needed",
                "p!b",
                "inky",
                "123-4",
                None,
                "invalid where 'p!b'",
            ),
            (
                "git",
                "foo",
                "needed",
                "pub",
                "!nky",
                "123-4",
                None,
                "invalid modifier '!nky'",
            ),
            ("git", "foo", "needed", "pub", "inky", "b@d", None, "invalid when 'b@d'"),
        ]
        for prod, sw, st, where, mod, when, exp, exp_fail in tsts:
            if exp is not None:
                pkg = cvelib.pkg.CvePkg(
                    prod, sw, st, where=where, modifier=mod, when=when
                )
                self.assertEqual(exp, pkg.__str__())
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.pkg.CvePkg(
                        prod, sw, st, where=where, modifier=mod, when=when
                    )
                self.assertEqual(exp_fail, str(context.exception))

    def test___repr__(self):
        """Test __repr__()"""
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        pkg.setSoftware("foo")
        pkg.setStatus("needed")
        self.assertEqual("git_foo: needed", pkg.__repr__())

    def test_setProduct(self):
        """Test setProduct()"""
        tsts = [
            # valid
            ("git", False, True),
            ("snap", False, True),
            ("oci", False, True),
            ("ubuntu", False, True),
            ("upstream", False, True),
            # valid compatUbuntu
            ("focal", True, True),
            # invalid
            ("focal", False, False),
            ("bad", False, False),
            (" git", False, False),
            ("git ", False, False),
            # invalid compatUbuntu
            ("foc@l", True, False),
        ]
        for s, compat, valid in tsts:
            pkg = cvelib.pkg.CvePkg("git", "foo", "needed", compatUbuntu=compat)
            if valid:
                pkg.setProduct(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setProduct(s)
                self.assertEqual("invalid product '%s'" % s, str(context.exception))

    def test_setWhere(self):
        """Test setWhere()"""
        tsts = [
            # valid
            ("foo", True),
            # invalid
            ("b@d", False),
            ("foo ", False),
            (" foo ", False),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for s, valid in tsts:
            if valid:
                pkg.setWhere(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setWhere(s)
                self.assertEqual("invalid where '%s'" % s, str(context.exception))

    def test_setSoftware(self):
        """Test setSoftware()"""
        tsts = [
            # valid
            ("foo", True),
            # invalid
            ("b@d", False),
            ("foo ", False),
            (" foo ", False),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for s, valid in tsts:
            if valid:
                pkg.setSoftware(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setSoftware(s)
                self.assertEqual("invalid software '%s'" % s, str(context.exception))

    def test_setModifier(self):
        """Test setModifier()"""
        tsts = [
            # valid
            ("foo", True),
            # invalid
            ("b@d", False),
            ("foo ", False),
            (" foo ", False),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for s, valid in tsts:
            if valid:
                pkg.setModifier(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setModifier(s)
                self.assertEqual("invalid modifier '%s'" % s, str(context.exception))

    def test_setStatus(self):
        """Test setStatus()"""
        tsts = [
            # valid
            ("needs-triage", True),
            ("needed", True),
            ("pending", True),
            ("released", True),
            ("deferred", True),
            ("ignored", True),
            ("DNE", True),
            ("not-affected", True),
            # invalid
            ("b@d", False),
            ("not-affected ", False),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for s, valid in tsts:
            if valid:
                pkg.setStatus(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setStatus(s)
                self.assertEqual("invalid status '%s'" % s, str(context.exception))

    def test_setWhen(self):
        """Test setWhen()"""
        tsts = [
            # valid
            ("foo", True),
            ("foo ", True),
            (" foo", True),
            # invalid
            ("b@d", False),
            ("foo @", False),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for s, valid in tsts:
            if valid:
                pkg.setWhen(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setWhen(s)
                self.assertEqual("invalid when '%s'" % s, str(context.exception))

    def test_setPatches(self):
        """Test setPatches()"""
        # one patch
        tsts = [
            # valid
            (["upstream: foo"], True),
            (["debdiff: foo"], True),
            (["vendor: foo"], True),
            (["other: foo"], True),
            # invalid
            (["bad: foo"], False),
            (["upstream foo"], False),
            (["upstream:foo"], False),
            (["upstream:"], False),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for t, valid in tsts:
            if valid:
                pkg.setPatches(t)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setPatches(t)
                self.assertEqual("invalid patch '%s'" % t[0], str(context.exception))

        # multiple
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        self.assertEqual(0, len(pkg.patches))
        pkg.setPatches(["upstream: foo", "debdiff: foo"])
        self.assertEqual(2, len(pkg.patches))

        # multiple with bad
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        self.assertEqual(0, len(pkg.patches))
        with self.assertRaises(cvelib.common.CveException) as context:
            pkg.setPatches(["upstream: foo", "blah: foo"])
        self.assertEqual("invalid patch 'blah: foo'", str(context.exception))

        # bad input
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        self.assertEqual(0, len(pkg.patches))
        with self.assertRaises(cvelib.common.CveException) as context:
            pkg.setPatches([False])
        self.assertEqual("invalid patch (not a string)", str(context.exception))

        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        self.assertEqual(0, len(pkg.patches))
        with self.assertRaises(cvelib.common.CveException) as context:
            pkg.setPatches(False)
        self.assertEqual("invalid patches (not a list)", str(context.exception))

    def test_setTags(self):
        """Test setTags()"""
        # one patch
        tsts = [
            # valid
            ("apparmor", None),
            ("stack-protector", None),
            ("fortify-source", None),
            ("symlink-restriction", None),
            ("hardlink-restriction", None),
            ("heap-protector", None),
            ("pie", None),
            ("apparmor pie", None),
            # invalid
            ("bad", "invalid tag 'bad'"),
            ("apparmor bad", "invalid tag 'bad'"),
            ("bad apparmor", "invalid tag 'bad'"),
            ([], "invalid tags (not a string)"),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for t, err in tsts:
            if not err:
                pkg.setTags(t)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setTags(t)
                self.assertEqual(err, str(context.exception))

    def test_parse(self):
        """Test parse()"""
        tsts = [
            # valid
            ("upstream_foo: needed", False, True),
            ("upstream_foo: needed (123-4)", False, True),
            ("debian/buster_foo: needed (123-4)", False, True),
            ("debian/buster_foo/bar: needed (123-4)", False, True),
            ("ubuntu/focal_foo: needed", False, True),
            # valid compatUbuntu
            ("focal_foo: needed", True, True),
            ("lucid_gcc-4.1: ignored (reached end-of-life)", True, True),
            ("precise/esm_gcc-4.4: DNE (precise was needs-triage)", True, True),
            # invalid
            ("b@d", False, False),
            ("foo @", False, False),
            ("ubuntu/foc@l_foo: needed", False, False),
            # invalid compatUbuntu
            ("foc@l_foo: needed", True, False),
        ]
        for s, compat, valid in tsts:
            if valid:
                cvelib.pkg.parse(s, compatUbuntu=compat)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.pkg.parse(s, compatUbuntu=compat)
                errS = "invalid package entry '%s'" % s
                if compat:
                    errS = "invalid package entry for Ubuntu '%s'" % s
                self.assertEqual(errS, str(context.exception))

        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.pkg.parse(False)
        self.assertEqual("invalid package entry (not a string)", str(context.exception))
