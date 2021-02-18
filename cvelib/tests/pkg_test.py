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
            (["break-fix: - c5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"], True),
            (["break-fix: b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a -"], True),
            (
                [
                    "break-fix: b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a c5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"
                ],
                True,
            ),
            (["break-fix: - -"], True),
            (["break-fix:  - -"], True),
            (["break-fix: -  -"], True),
            (
                [
                    "break-fix: - c0ca3d70e8d3cf81e2255a217f7ca402f5ed0862|local-2015-1328-fix"
                ],
                True,
            ),
            (
                [
                    "break-fix: - local-2015-1328-fix|c0ca3d70e8d3cf81e2255a217f7ca402f5ed0862"
                ],
                True,
            ),
            (["break-fix: - local-2015-1328-fix"], True),
            (["break-fix: - local-2015-1328"], True),
            (["break-fix: - local-2015-1328-f2"], True),
            (
                [
                    "break-fix: local-2018-6559-break local-2015-1328-fix|local-2018-6559-fix"
                ],
                True,
            ),
            (
                [
                    "break-fix: 581738a681b6faae5725c2555439189ca81c0f1f f2d67fec0b43edce8c416101cdc52e71145b5fef|local-2020-8835-fix"
                ],
                True,
            ),
            (
                [
                    "break-fix: - c06cfb08b88dfbe13be44a69ae2fdc3a7c902d81|c53ee259ad3da891e191dee7af119af340f9c01b"
                ],
                True,
            ),
            (
                [
                    "break-fix: c06cfb08b88dfbe13be44a69ae2fdc3a7c902d81|c53ee259ad3da891e191dee7af119af340f9c01b -"
                ],
                True,
            ),
            # invalid
            (["bad: foo"], False),
            (["upstream foo"], False),
            (["upstream:foo"], False),
            (["upstream:"], False),
            (["break-fix: -"], False),
            (["break-fix: b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"], False),
            (["break-fix: b@d c5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"], False),
            (["break-fix: c5a8ffcae4103a9d823ea3aa3a761f65779fbe2a b@d"], False),
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
            (
                "ubuntu/trusty_gcc-snapshot: DNE (trusty was not-affected 20140405-0ubuntu1)",
                False,
                True,
            ),
            (
                "ubuntu/trusty_gcc-snapshot: DNE (trusty was not-affected [20140405-0ubuntu1])",
                False,
                True,
            ),
            ("upstream_shadow: released (1:4.1.5-1)", False, True),
            ("upstream_yui: released (2.8.2r1~squeeze-1)", False, True),
            ("upstream_xinetd: released (2.3.15,1:2.3.14-7.1)", False, True),
            (
                "ubuntu/precise_linux: ignored (was needs-triage ESM criteria)",
                False,
                True,
            ),
            (
                "ubuntu/lucid_eglibc: not-affected (__libc_use_alloca() not present)",
                False,
                True,
            ),
            (
                "ubuntu/precise_python2.7: not-affected (doesn't implement ssl.match_hostname)",
                False,
                True,
            ),
            (
                "upstream_procmail: not-affected (REJECTED/not a security issue)",
                False,
                True,
            ),
            ("ubuntu/lucid_jetty: not-affected (< 9.x)", False, True),
            ("ubuntu/precise_lightdm: not-affected (1.14/1.16 only)", False, True),
            (
                "upstream_linux: not-affected (debian: Fixed before src:linux-2.6 -> src:linux rename)",
                False,
                True,
            ),
            (
                "upstream_ruby-rack: not-affected (debian: Only affects >= 2.0.4)",
                False,
                True,
            ),
            ("ubuntu/dapper_acroread: not-affected (Windows|MacOS X)", False, True),
            (
                "ubuntu/trusty_gst-libav1.0: not-affected (compiled with `--with-system-libav`)",
                False,
                True,
            ),
            # valid compatUbuntu
            ("focal_foo: needed", True, True),
            ("lucid_gcc-4.1: ignored (reached end-of-life)", True, True),
            ("precise/esm_gcc-4.4: DNE (precise was needs-triage)", True, True),
            (
                "trusty/esm_gcc-snapshot: DNE (trusty was not-affected 20140405-0ubuntu1)",
                True,
                True,
            ),
            (
                "trusty/esm_gcc-snapshot: DNE (trusty was not-affected [20140405-0ubuntu1])",
                True,
                True,
            ),
            ("upstream_shadow: released (1:4.1.5-1)", True, True),
            ("upstream_yui: released (2.8.2r1~squeeze-1)", True, True),
            ("upstream_xinetd: released (2.3.15,1:2.3.14-7.1)", True, True),
            ("precise/esm_linux: ignored (was needs-triage ESM criteria)", True, True),
            (
                "lucid_eglibc: not-affected (__libc_use_alloca() not present)",
                True,
                True,
            ),
            ("maverick_qt4-x11: not-affected (webkit isn't built)", True, True),
            (
                'maverick_linux-ec2: ignored (binary supplied by "linux" now)',
                True,
                True,
            ),
            ("devel_grub2-signed: released (1.157)", True, True),
            # invalid
            ("b@d", False, False),
            ("foo @", False, False),
            ("ubuntu/foc@l_foo: needed", False, False),
            ("ubuntu/devel_grub2-signed: released (1.157)\n ", False, False),
            # invalid compatUbuntu
            ("foc@l_foo: needed", True, False),
            ("devel_grub2-signed: released (1.157)\n ", True, False),
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
                if "\n" in s:
                    errS = "invalid package entry '%s' (expected single line)" % s
                self.assertEqual(errS, str(context.exception))

        with self.assertRaises(cvelib.common.CveException) as context:
            cvelib.pkg.parse(False)
        self.assertEqual("invalid package entry (not a string)", str(context.exception))
