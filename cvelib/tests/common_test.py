"""test_common.py: tests for common.py module"""

from email.message import EmailMessage
import os
from unittest import TestCase

import cvelib.common
import cvelib.tests.util


class TestCommon(TestCase):
    """Tests for common functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        self.orig_xdg_config_home = None
        self.tmpdir = None

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.orig_xdg_config_home is None:
            if "XDG_CONFIG_HOME" in os.environ:
                del os.environ["XDG_CONFIG_HOME"]
        else:
            os.environ["XDG_CONFIG_HOME"] = self.orig_xdg_config_home
            self.orig_xdg_config_home = None

        if self.tmpdir is not None:
            cvelib.common.recursive_rm(self.tmpdir)

        cvelib.common.configCache = None

    def test_msg(self):
        """Test msg()"""
        cvelib.common.msg("Test msg")

    def test_warn(self):
        """Test warn()"""
        cvelib.common.warn("Test warning")

    def test_error(self):
        """Test error()"""
        cvelib.common.error("Test error", do_exit=False)

    def test_setCveHeader(self):
        """Test setCveHeader()"""
        m = EmailMessage()
        self.assertEqual(len(m), 0)

        # add
        cvelib.common.setCveHeader(m, "foo", "bar")
        self.assertEqual(len(m), 1)
        self.assertTrue("foo" in m)
        self.assertEqual(m["foo"], "bar")

        # replace
        cvelib.common.setCveHeader(m, "foo", "baz")
        self.assertEqual(len(m), 1)
        self.assertTrue("foo" in m)
        self.assertEqual(m["foo"], "baz")

        # delete
        cvelib.common.setCveHeader(m, "foo", None)
        self.assertEqual(len(m), 0)

    def test_getConfigFilePath(self):
        """Test getConfigFilePath()"""
        if "XDG_CONFIG_HOME" in os.environ:
            self.orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

        os.environ["XDG_CONFIG_HOME"] = "/fake/.config"
        res = cvelib.common.getConfigFilePath()
        self.assertEqual(res, "/fake/.config/influx-security-tools.conf")

        del os.environ["XDG_CONFIG_HOME"]
        res = cvelib.common.getConfigFilePath()
        self.assertEqual(
            res, os.path.expandvars("$HOME/.config/influx-security-tools.conf")
        )

    def test_readConfig(self):
        """Test readConfig()"""
        self.tmpdir = cvelib.tests.util._createTmpDir()

        if "XDG_CONFIG_HOME" in os.environ:
            self.orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmpdir, ".config")
        fn = os.path.expandvars("$XDG_CONFIG_HOME/influx-security-tools.conf")

        # create
        (exp_conf, exp_fn) = cvelib.common.readConfig()
        self.assertEqual(fn, exp_fn)
        self.assertTrue("Locations" in exp_conf)

        # reuse
        (exp_conf2, exp_fn2) = cvelib.common.readConfig()
        self.assertEqual(exp_conf, exp_conf2)  # same object
        self.assertEqual(exp_fn, exp_fn2)
        self.assertTrue("Locations" in exp_conf2)
        self.assertEqual(exp_conf["Locations"], exp_conf2["Locations"])

    def test_getConfigCveDataPath(self):
        """Test getConfigCveDataPath()"""
        self.tmpdir = cvelib.tests.util._createTmpDir()

        if "XDG_CONFIG_HOME" in os.environ:
            self.orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmpdir, ".config")
        os.mkdir(os.environ["XDG_CONFIG_HOME"], 0o0700)

        dataDir = os.path.join(os.environ["XDG_CONFIG_HOME"], "dataDir")
        os.mkdir(dataDir, 0o0700)
        exp = {}
        for d in cvelib.common.cve_reldirs:
            exp[d] = os.path.join(dataDir, d)
            os.mkdir(exp[d], 0o0700)

        fn = os.path.expandvars("$XDG_CONFIG_HOME/influx-security-tools.conf")
        with open(fn, "w") as fp:
            fp.write(
                """[Locations]
cve-data = %s
"""
                % dataDir
            )

        res_dirs = cvelib.common.getConfigCveDataPaths()
        self.assertTrue(res_dirs == exp)

    def test_getConfigCompatUbuntu(self):
        """Test getConfigCompatUbuntu()"""
        tsts = [
            ("yes", True),
            ("Yes", True),
            ("YES", True),
            ("no", False),
            ("No", False),
            ("NO", False),
            ("bad", False),
        ]
        for val, exp in tsts:
            cvelib.common.configCache = None
            self.orig_xdg_config_home, self.tmpdir = cvelib.tests.util._newConfigFile(
                """[Behavior]
compat-ubuntu = %s
"""
                % val
            )
            res = cvelib.common.getConfigCompatUbuntu()
            self.assertEqual(res, exp)

    def test_readCVE(self):
        """Test readCve()"""
        self.tmpdir = cvelib.tests.util._createTmpDir()

        tsts = [
            # one stanza - single
            ("foo: bar\n", {"foo": "bar"}),
            ("foo: bar\nbaz: norf\n", {"foo": "bar", "baz": "norf"}),
            # one stanza - empty
            ("foo:\n", {"foo": ""}),
            # one stanza - multi
            ("foo:\n bar\n", {"foo": "\n bar"}),
            ("foo:\n bar\n baz\n", {"foo": "\n bar\n baz"}),
            # one stanza - mixed
            (
                "foo: bar\nbaz:\n norf\n corge\nqux: quux\n",
                {"foo": "bar", "baz": "\n norf\n corge", "qux": "quux"},
            ),
            # multiple stanzas
            ("foo: bar\n\nbaz: norf\n", {"foo": "bar", "baz": "norf"}),
            (
                "foo: bar\n\nbaz:\n norf\n corge\n\nqux: quux\n",
                {"foo": "bar", "baz": "\n norf\n corge", "qux": "quux"},
            ),
            (
                "foo: bar\n\n\nbaz:\n norf\n corge\n\n\n\nqux: quux\n\n\n",
                {"foo": "bar", "baz": "\n norf\n corge", "qux": "quux"},
            ),
            # duplicates
            (
                "dupe-test1: bar\nbaz: norf\ndupe-test1: bar\n",
                {"dupe-test1": "bar", "baz": "norf"},
            ),
            (
                "dupe-test2: bar\nbaz: norf\n\ndupe-test2: bar\n",
                {"dupe-test2": "bar", "baz": "norf"},
            ),
            # weird cases
            ("bad", {}),
            ("f\x00o: bar", {}),
            ("foo: b\xaar", {"foo": "b\\xc2\\xaar"}),
            ("😀: bar", {"\\xf0\\x9f\\x98\\x80": "bar"}),  # utf-8 F09F9880
            ("foo: 😀", {"foo": "\\xf0\\x9f\\x98\\x80"}),
        ]
        for inp, exp in tsts:
            fn = os.path.join(self.tmpdir, "testcve")
            with open(fn, "w") as f:
                f.write(inp)

            res = cvelib.common.readCve(fn)
            self.assertTrue(res == exp)
            os.unlink(fn)
