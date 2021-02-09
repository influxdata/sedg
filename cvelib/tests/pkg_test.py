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
                self.assertEqual(pkg.__str__(), exp)
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
            ("git", True),
            ("snap", True),
            ("oci", True),
            # invalid
            ("focal", False),
            ("bad", False),
            (" git", False),
            ("git ", False),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for s, valid in tsts:
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
