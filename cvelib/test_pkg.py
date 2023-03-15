"""test_pkg.py: tests for pkg.py module"""

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
            ("oci", False, True),
            ("snap", False, True),
            ("alpine", False, True),
            ("centos", False, True),
            ("debian", False, True),
            ("opensuse", False, True),
            ("rhel", False, True),
            ("suse", False, True),
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
            ("bar", True, False),
            ("a" * 40, True, False),
            # valid compat
            ("bar", True, True),
            # invalid
            ("b@d", False, False),
            ("bar ", False, False),
            (" bar ", False, False),
            ("a" * 41, False, False),
            # invalid compat
            ("b@d", False, True),
            ("bar ", False, True),
            (" bar ", False, True),
            ("bar_bar", False, True),
            ("BAR", False, True),
        ]
        for s, valid, compat in tsts:
            pkg = cvelib.pkg.CvePkg("git", "foo", "needed", compatUbuntu=compat)
            if valid:
                pkg.setWhere(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setWhere(s)
                compatS = ""
                if compat:
                    compatS = "compat "
                self.assertEqual(
                    "invalid %swhere '%s'" % (compatS, s), str(context.exception)
                )

    def test_setSoftware(self):
        """Test setSoftware()"""
        tsts = [
            # valid
            ("foo", False, True),
            ("foo1", False, True),
            ("foo-bar", False, True),
            ("foo.bar", False, True),
            ("foo-bar-1.0", False, True),
            ("foo_bar", False, True),
            ("FOO", False, True),
            # invalid
            ("b@d", False, False),
            ("foo ", False, False),
            (" foo ", False, False),
            ("F@O", False, False),
            # valid Ubuntu
            ("foo", True, True),
            ("foo1", True, True),
            ("foo-bar", True, True),
            ("foo.bar", True, True),
            ("foo-bar-1.0", True, True),
            # invalid Ubuntu
            ("foo_bar", True, False),
            ("b@d", True, False),
            ("foo ", True, False),
            (" foo ", True, False),
            ("FOO", True, False),
        ]
        for s, compat, valid in tsts:
            pkg = cvelib.pkg.CvePkg("git", "foo", "needed", compatUbuntu=compat)
            if valid:
                pkg.setSoftware(s)
            else:
                ustr = ""
                if compat:
                    ustr = "compat "
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setSoftware(s)
                self.assertEqual(
                    "invalid %ssoftware '%s'" % (ustr, s), str(context.exception)
                )

    def test_setModifier(self):
        """Test setModifier()"""
        tsts = [
            # valid
            ("foo", True, False),
            ("foo_bar", True, False),
            ("a" * 40, True, False),
            # valid compat
            ("foo", True, True),
            ("a" * 40, True, True),
            # invalid
            ("b@d", False, False),
            ("foo ", False, False),
            (" foo ", False, False),
            ("a" * 41, False, False),
            # invalid compat
            ("b@d", False, True),
            ("foo ", False, True),
            (" foo ", False, True),
            ("foo_bar", False, True),
            ("FOO", False, True),
        ]
        for s, valid, compat in tsts:
            pkg = cvelib.pkg.CvePkg("git", "foo", "needed", compatUbuntu=compat)
            if valid:
                pkg.setModifier(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setModifier(s)
                compatS = ""
                if compat:
                    compatS = "compat "
                self.assertEqual(
                    "invalid %smodifier '%s'" % (compatS, s), str(context.exception)
                )

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

    def test_setPriorities(self):
        """Test setPriorities()"""
        tsts = [
            # valid
            ([("test-key", "negligible")], None),
            ([("test-key", "low")], None),
            ([("test-key", "medium")], None),
            ([("test-key", "high")], None),
            ([("test-key", "critical")], None),
            ([("test-key", "critical"), ("test_key2", "high")], None),
            ([("test-key", "critical"), ("test_key_3", "high")], None),
            # invalid
            ([("test-key", "b@d")], "invalid package priority 'b@d'"),
            ([("test-key", "foo ")], "invalid package priority 'foo '"),
            ([("test-key", " foo ")], "invalid package priority ' foo '"),
            ([("test-key", "needed")], "invalid package priority 'needed'"),
            ([("test-key", "needs-triage")], "invalid package priority 'needs-triage'"),
            (
                [("test-key", "untriaged")],
                "invalid package priority 'untriaged' (please remove or set)",
            ),
            (
                [("test-key", "critical"), ("test_key2", "untriaged")],
                "invalid package priority 'untriaged' (please remove or set)",
            ),
            (
                [("test-key", "critical"), ("test_key_3", "b@d")],
                "invalid package priority 'b@d'",
            ),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for t, err in tsts:
            if err is None:
                pkg.setPriorities(t)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setPriorities(t)
                self.assertEqual(err, str(context.exception))

    def test_setPatches(self):
        """Test setPatches()"""
        # one patch
        tsts = [
            # valid
            (["upstream: foo"], False, True),
            (["distro: foo"], False, True),
            (["vendor: foo"], False, True),
            (["other: foo"], False, True),
            (["break-fix: http://a -"], False, True),
            (["break-fix: - http://b"], False, True),
            (["break-fix: http://a http://b"], False, True),
            (["break-fix: - c5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"], False, True),
            (["break-fix: b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a -"], False, True),
            (
                [
                    "break-fix: b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a c5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"
                ],
                False,
                True,
            ),
            (["break-fix: - -"], False, True),
            (["break-fix:  - -"], False, True),
            (["break-fix: -  -"], False, True),
            (
                [
                    "break-fix: - c0ca3d70e8d3cf81e2255a217f7ca402f5ed0862|local-2015-1328-fix"
                ],
                False,
                True,
            ),
            (
                [
                    "break-fix: - local-2015-1328-fix|c0ca3d70e8d3cf81e2255a217f7ca402f5ed0862"
                ],
                False,
                True,
            ),
            (["break-fix: - local-2015-1328-fix"], False, True),
            (["break-fix: - local-2015-1328"], False, True),
            (["break-fix: - local-2015-1328-f2"], False, True),
            (
                [
                    "break-fix: local-2018-6559-break local-2015-1328-fix|local-2018-6559-fix"
                ],
                False,
                True,
            ),
            (
                [
                    "break-fix: 581738a681b6faae5725c2555439189ca81c0f1f f2d67fec0b43edce8c416101cdc52e71145b5fef|local-2020-8835-fix"
                ],
                False,
                True,
            ),
            (
                [
                    "break-fix: - c06cfb08b88dfbe13be44a69ae2fdc3a7c902d81|c53ee259ad3da891e191dee7af119af340f9c01b"
                ],
                False,
                True,
            ),
            (
                [
                    "break-fix: c06cfb08b88dfbe13be44a69ae2fdc3a7c902d81|c53ee259ad3da891e191dee7af119af340f9c01b -"
                ],
                False,
                True,
            ),
            (
                [
                    "break-fix: 96bb55d8ff4082dfead8bf9a8a85ef7a8e270981 I0f887bb8f1fa5a69a55e23dbb522b3bb694ad27f"
                ],
                False,
                True,
            ),
            (
                [
                    "break-fix: Ic0dedbad74b970d7bd1a6624a845b5b1b9847443 Ic0dedbad257bf0a448d0bf67a14a3932b7925bfc"
                ],
                False,
                True,
            ),
            (["upstream: I89089155d1083332d02ae9039898227cbab42d07"], False, True),
            # valid ubuntu
            (["upstream: foo"], True, True),
            (["distro: foo"], True, True),
            (["vendor: foo"], True, True),
            (["other: foo"], True, True),
            (["debdiff: foo"], True, True),
            (["diff: foo"], True, True),
            (["fork: foo"], True, True),
            (["merge: foo"], True, True),
            (["proposed: foo"], True, True),
            (["unknown: foo"], True, True),
            (["alpine: foo"], True, True),
            (["android: foo"], True, True),
            (["debian: foo"], True, True),
            (["fedora: foo"], True, True),
            (["redhat: foo"], True, True),
            (["opensuse: foo"], True, True),
            (["dapper: foo"], True, True),
            (["hardy: foo"], True, True),
            (["jaunty: foo"], True, True),
            (["karmic: foo"], True, True),
            (["lucid: foo"], True, True),
            (["maverick: foo"], True, True),
            (["break-fix: http://a -"], True, True),
            (["break-fix: - http://b"], True, True),
            (["break-fix: http://a http://b"], True, True),
            (
                [
                    "break-fix: 96bb55d8ff4082dfead8bf9a8a85ef7a8e270981 I0f887bb8f1fa5a69a55e23dbb522b3bb694ad27f"
                ],
                True,
                True,
            ),
            (
                [
                    "break-fix: Ic0dedbad74b970d7bd1a6624a845b5b1b9847443 Ic0dedbad257bf0a448d0bf67a14a3932b7925bfc"
                ],
                True,
                True,
            ),
            (["upstream: I89089155d1083332d02ae9039898227cbab42d07"], True, True),
            # invalid
            (["bad: foo"], False, False),
            (["debdiff: foo"], False, False),
            (["upstream foo"], False, False),
            (["upstream:foo"], False, False),
            (["upstream:"], False, False),
            (["dapper: foo"], False, False),
            (["break-fix: -"], False, False),
            (["break-fix: http:// -"], False, False),
            (["break-fix: - http://"], False, False),
            (["break-fix: http:// http://b"], False, False),
            (["break-fix: http://a http://"], False, False),
            (["break-fix: http:// http://"], False, False),
            (
                ["break-fix: http://a b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"],
                False,
                False,
            ),
            (
                ["break-fix: b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a http://b"],
                False,
                False,
            ),
            (["break-fix: b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"], False, False),
            (["break-fix: b@d c5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"], False, False),
            (["break-fix: c5a8ffcae4103a9d823ea3aa3a761f65779fbe2a b@d"], False, False),
            # invalid ubuntu
            (["bad: foo"], True, False),
            (["upstream foo"], True, False),
            (["upstream:foo"], True, False),
            (["upstream:"], True, False),
            (["break-fix: http:// -"], True, False),
            (["break-fix: - http://"], True, False),
            (["break-fix: http:// http://b"], True, False),
            (["break-fix: http://a http://"], True, False),
            (["break-fix: http:// http://"], False, False),
            (
                ["break-fix: http://a b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a"],
                True,
                False,
            ),
            (
                ["break-fix: b5a8ffcae4103a9d823ea3aa3a761f65779fbe2a http://b"],
                True,
                False,
            ),
        ]
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        for t, compat, valid in tsts:
            if valid:
                pkg.setPatches(t, compatUbuntu=compat)
            else:
                errS = "invalid patch '%s'" % t[0]
                if compat:
                    errS = "invalid patch for compat '%s'" % t[0]
                with self.assertRaises(cvelib.common.CveException) as context:
                    pkg.setPatches(t, compatUbuntu=compat)
                self.assertEqual(errS, str(context.exception))

        # multiple
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        self.assertEqual(0, len(pkg.patches))
        pkg.setPatches(["upstream: foo", "distro: foo"], False)
        self.assertEqual(2, len(pkg.patches))

        # multiple with bad
        pkg = cvelib.pkg.CvePkg("git", "foo", "needed")
        self.assertEqual(0, len(pkg.patches))
        with self.assertRaises(cvelib.common.CveException) as context:
            pkg.setPatches(["upstream: foo", "blah: foo"], False)
        self.assertEqual("invalid patch 'blah: foo'", str(context.exception))

    def test_setTags(self):
        """Test setTags()"""
        # one patch
        tsts = [
            # valid
            ([("test-key", "apparmor")], None),
            ([("test-key", "stack-protector")], None),
            ([("test-key", "fortify-source")], None),
            ([("test-key", "symlink-restriction")], None),
            ([("test-key", "hardlink-restriction")], None),
            ([("test-key", "heap-protector")], None),
            ([("test-key", "limit-report")], None),
            ([("test-key", "pie")], None),
            ([("test-key", "apparmor"), ("test-key2", "pie stack-protector")], None),
            ([("test-key", "apparmor"), ("test-key_3", "pie stack-protector")], None),
            # invalid
            ([("test-key", "bad")], "invalid tag 'bad'"),
            ([("test-key", "apparmor bad")], "invalid tag 'bad'"),
            ([("test-key", "bad apparmor")], "invalid tag 'bad'"),
            (
                [("test-key", "apparmor"), ("test-key2", "bad stack-protector")],
                "invalid tag 'bad'",
            ),
            (
                [("test-key", "apparmor"), ("test-key_3", "pie bad")],
                "invalid tag 'bad'",
            ),
            # ([("test-key", "")], "invalid tag 'bad'"),
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
            ("upstream_foo1: needed (123-4)", False, True),
            ("upstream_foo-bar: needed (123-4)", False, True),
            ("upstream_foo.bar: needed (123-4)", False, True),
            ("upstream_foo-bar-1.0: needed (123-4)", False, True),
            ("upstream_foo_bar: needed (123-4)", False, True),
            ("alpine/3.16_foo: needed (123-4)", False, True),
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
            ("upstream_%s: needed" % ("a" * 50), False, True),
            ("git/%s_foo: needed" % ("a" * 40), False, True),
            ("upstream_foo/%s: needed" % ("a" * 40), False, True),
            ("upstream_foo: needed (%s)" % ("a" * 100), False, True),
            ("upstream_FOO: needed", False, True),
            ("upstream_foo-BAR: needed", False, True),
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
            ("focal_%s: needed" % ("a" * 50), True, True),
            ("%s_foo: needed" % ("a" * 40), True, True),
            ("snap/%s_foo: needed" % ("a" * 40), True, True),
            ("focal_foo/%s: needed" % ("a" * 40), True, True),
            ("focal_foo: needed (%s)" % ("a" * 100), True, True),
            ("upstream_foo1: needed (123-4)", True, True),
            ("upstream_foo-bar: needed (123-4)", True, True),
            ("upstream_foo.bar: needed (123-4)", True, True),
            ("upstream_foo-bar-1.0: needed (123-4)", True, True),
            # invalid
            ("b@d", False, False),
            ("foo @", False, False),
            ("ubuntu/foc@l_foo: needed", False, False),
            ("ubuntu/devel_grub2-signed: released (1.157)\n ", False, False),
            ("upstream_%s: needed" % ("a" * 51), False, False),
            ("git/%s_foo: needed" % ("a" * 41), False, False),
            ("upstream_foo/%s: needed" % ("a" * 41), False, False),
            ("upstream_foo: needed (%s)" % ("a" * 101), False, False),
            ("upstream_F@O: needed", False, False),
            # invalid compatUbuntu
            ("foc@l_foo: needed", True, False),
            ("devel_grub2-signed: released (1.157)\n ", True, False),
            ("focal_%s: needed" % ("a" * 51), True, False),
            ("%s_foo: needed" % ("a" * 41), True, False),
            ("snap/%s_foo: needed" % ("a" * 41), True, False),
            ("focal_foo/%s: needed" % ("a" * 40), False, False),
            ("focal_foo: needed (%s)" % ("a" * 101), True, False),
            ("upstream_foo_bar: needed (123-4)", True, False),
            ("upstream_FOO: needed", True, False),
            ("upstream_foo-BAR: needed", True, False),
        ]
        for s, compat, valid in tsts:
            if valid:
                cvelib.pkg.parse(s, compatUbuntu=compat)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.pkg.parse(s, compatUbuntu=compat)
                errS = "invalid package entry '%s'" % s
                if compat:
                    errS = "invalid package entry for compat '%s'" % s
                if "\n" in s:
                    errS = "invalid package entry '%s' (expected single line)" % s
                self.assertEqual(errS, str(context.exception))
