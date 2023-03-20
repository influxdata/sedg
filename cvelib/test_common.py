"""test_common.py: tests for common.py module"""

from email.message import EmailMessage
import os
from unittest import TestCase, mock, skipIf

import cvelib.common
import cvelib.testutil


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

        if "TEST_UPDATE_PROGRESS" in os.environ:
            del os.environ["TEST_UPDATE_PROGRESS"]

    def test_msg(self):
        """Test msg()"""
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.common.msg("Test msg")
        self.assertEqual("Test msg", output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

    def test_warn(self):
        """Test warn()"""
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.common.warn("Test warning")
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("WARN: Test warning", error.getvalue().strip())

    def test_error(self):
        """Test error()"""
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.common.error("Test error", do_exit=False)
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("ERROR: Test error", error.getvalue().strip())

    @skipIf("CI" in os.environ, "in CI environment")
    def test_updateProgress(self):
        """Test updateProgress()"""
        os.environ["TEST_UPDATE_PROGRESS"] = "1"
        tsts = [
            # (progress, barLength, prefix, expOut)
            (0, 10, "", "[----------] 0%"),
            (0.5, 10, "", "[#####-----] 50%"),
            (0.5, 10, "test prefix: ", "test prefix: [#####-----] 50%"),
            (0.0, 10, "", "[----------] 0%"),
            (-1, 10, "", "[----------] 0%"),
            (1, 0, "", "#] 100%"),
            (0.5, 0, "a" * 100000, "%s..." % ("a" * 67)),
        ]
        for pro, bar, pre, expOut in tsts:
            with cvelib.testutil.capturedOutput() as (output, error):
                cvelib.common.updateProgress(pro, barLength=bar, prefix=pre)
            if bar == 0:
                self.assertTrue(output.getvalue().strip().endswith(expOut))
            else:
                self.assertEqual(expOut, output.getvalue().strip())
            self.assertEqual("", error.getvalue().strip())

    def test_epochToISO8601(self):
        """Test epochToISO8601()"""
        tsts = [
            # valid
            (1, "1970-01-01T00:00:01Z", True),
            (1658491453, "2022-07-22T12:04:13Z", True),
            # invalid
            (-1, "", False),
            ("1", "", False),
        ]

        for input, exp, is_valid in tsts:
            if is_valid:
                res = cvelib.common.epochToISO8601(input)
                self.assertEqual(exp, res)
            else:
                with self.assertRaises(ValueError):
                    cvelib.common.epochToISO8601(input)

    def test_setCveHeader(self):
        """Test setCveHeader()"""
        m = EmailMessage()
        self.assertEqual(0, len(m))

        # add
        cvelib.common.setCveHeader(m, "foo", "bar")
        self.assertEqual(1, len(m))
        self.assertTrue("foo" in m)
        self.assertEqual("bar", m["foo"])

        # replace
        cvelib.common.setCveHeader(m, "foo", "baz")
        self.assertEqual(1, len(m))
        self.assertTrue("foo" in m)
        self.assertEqual("baz", m["foo"])

        # delete
        cvelib.common.setCveHeader(m, "foo", None)
        self.assertEqual(0, len(m))

    def test_getConfigFilePath(self):
        """Test getConfigFilePath()"""
        if "XDG_CONFIG_HOME" in os.environ:
            self.orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

        os.environ["XDG_CONFIG_HOME"] = "/fake/.config"
        res = cvelib.common.getConfigFilePath()
        self.assertEqual("/fake/.config/sedg/sedg.conf", res)

        del os.environ["XDG_CONFIG_HOME"]
        res = cvelib.common.getConfigFilePath()
        self.assertEqual(
            os.path.expandvars("$HOME/.config/sedg/sedg.conf"),
            res,
        )

    def test_readConfig(self):
        """Test readConfig()"""
        self.tmpdir = cvelib.testutil._createTmpDir()

        if "XDG_CONFIG_HOME" in os.environ:  # pragma: nocover
            self.orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmpdir, ".config")
        fn = os.path.expandvars("$XDG_CONFIG_HOME/sedg/sedg.conf")

        # create
        with cvelib.testutil.capturedOutput() as (output, error):
            (exp_conf, exp_fn) = cvelib.common.readConfig()
        self.assertEqual(exp_fn, fn)
        self.assertTrue("Locations" in exp_conf)

        self.assertTrue(
            output.getvalue().strip().startswith("Created default config in ")
        )
        self.assertEqual("", error.getvalue().strip())

        # reuse
        with cvelib.testutil.capturedOutput() as (output, error):
            (exp_conf2, exp_fn2) = cvelib.common.readConfig()
        self.assertEqual(exp_conf, exp_conf2)  # same object
        self.assertEqual(exp_fn, exp_fn2)
        self.assertTrue("Locations" in exp_conf2)
        self.assertEqual(exp_conf["Locations"], exp_conf2["Locations"])

        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

    def _setup_conf_and_data(self):
        self.tmpdir = cvelib.testutil._createTmpDir()

        if "XDG_CONFIG_HOME" in os.environ:
            self.orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmpdir, ".config")
        os.mkdir(os.environ["XDG_CONFIG_HOME"], 0o0700)
        os.mkdir(os.path.join(os.environ["XDG_CONFIG_HOME"], "sedg"), 0o0700)

        dataDir = os.path.join(os.environ["XDG_CONFIG_HOME"], "dataDir")
        os.mkdir(dataDir, 0o0700)
        for d in cvelib.common.cve_reldirs:
            os.mkdir(os.path.join(dataDir, d), 0o0700)

        fn = os.path.expandvars("$XDG_CONFIG_HOME/sedg/sedg.conf")
        with open(fn, "w") as fp:
            fp.write(
                """[Locations]
cve-data = %s
"""
                % dataDir
            )

        return fn, dataDir

    def test_getConfigCveDataPaths(self):
        """Test getConfigCveDataPaths()"""
        _, dataDir = self._setup_conf_and_data()
        exp = {}
        for d in cvelib.common.cve_reldirs:
            exp[d] = os.path.join(dataDir, d)

        res_dirs = cvelib.common.getConfigCveDataPaths()
        self.assertTrue(res_dirs == exp)

    def test_getConfigCveDataPathsNonexistentDataDir(self):
        """Test getConfigCveDataPaths() - nonexistent cve-data"""
        fn, dataDir = self._setup_conf_and_data()

        # now remove the dir, patching error() to not sys.exit()
        cvelib.common.recursive_rm(dataDir)
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with cvelib.testutil.capturedOutput() as (output, error):
                res = cvelib.common.getConfigCveDataPaths()
            self.assertEqual(0, len(res))
            self.assertEqual("", output.getvalue().strip())
            expErr = (
                "ERROR: Please configure %s to\nset 'cve-data' in '[Locations]' to a valid path"
                % fn
            )
            self.assertEqual(expErr, error.getvalue().strip())

    def test_getConfigCveDataPathsNonexistentSubdir(self):
        """Test getConfigCveDataPaths() - nonexistent cve-data/subdir"""
        _, dataDir = self._setup_conf_and_data()

        # now remove the ignored dir, patching error() to not sys.exit()
        cvelib.common.recursive_rm(os.path.join(dataDir, "ignored"))
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with cvelib.testutil.capturedOutput() as (output, error):
                res = cvelib.common.getConfigCveDataPaths()
            self.assertEqual(0, len(res))
            self.assertEqual("", output.getvalue().strip())
            expErr = "ERROR: Could not find 'ignored' in '%s'" % dataDir
            self.assertEqual(expErr, error.getvalue().strip())

    def test_getConfigCveDataPathsLocationsInConfig(self):
        """Test getConfigCveDataPaths() - missing Locations"""
        fn, _ = self._setup_conf_and_data()

        # now clear out the config file, patching error() to not sys.exit()
        with open(fn, "w") as fp:
            fp.write("")

        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with cvelib.testutil.capturedOutput() as (output, error):
                res = cvelib.common.getConfigCveDataPaths()
            self.assertEqual(0, len(res))
            self.assertEqual("", output.getvalue().strip())
            expErr = (
                "ERROR: Please configure %s to\nset 'cve-data' in '[Locations]'" % fn
            )
            self.assertEqual(expErr, error.getvalue().strip())

    def test_getConfigCompatUbuntu(self):
        """Test getConfigCompatUbuntu()"""
        tsts = [
            ("yes", True, "", ""),
            ("Yes", True, "", ""),
            ("YES", True, "", ""),
            ("no", False, "", ""),
            ("No", False, "", ""),
            ("NO", False, "", ""),
            (
                "bad",
                False,
                "",
                "WARN: 'compat-ubuntu' in '[Behavior]' should be 'yes' or 'no'",
            ),
        ]
        for val, exp, expOut, expErr in tsts:
            cvelib.common.configCache = None
            self.orig_xdg_config_home, self.tmpdir = cvelib.testutil._newConfigFile(
                """[Behavior]
compat-ubuntu = %s
"""
                % val
            )

            with cvelib.testutil.capturedOutput() as (output, error):
                res = cvelib.common.getConfigCompatUbuntu()
            self.assertEqual(exp, res)

            self.assertEqual(expOut, output.getvalue().strip())
            self.assertEqual(expErr, error.getvalue().strip())

    def test_readCVE(self):
        """Test readCve()"""
        self.tmpdir = cvelib.testutil._createTmpDir()

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
            ("foo: b\xaar", {"foo": "b\xaar"}),
            ("😀: bar", {}),  # utf-8 F09F9880
            ("foo: 😀", {"foo": "😀"}),
        ]
        for inp, exp in tsts:
            fn = os.path.join(self.tmpdir, "testcve")
            with open(fn, "w") as f:
                f.write(inp)

            with cvelib.testutil.capturedOutput() as (output, error):
                res = cvelib.common.readCve(fn)
            os.unlink(fn)
            self.assertTrue(res == exp)

            if inp.startswith("dupe"):
                self.assertEqual("", output.getvalue().strip())
                self.assertTrue(
                    error.getvalue().strip().startswith("WARN: duplicate key 'dupe")
                )
            else:
                self.assertEqual("", output.getvalue().strip())
                self.assertEqual("", error.getvalue().strip())

    def test_readFile(self):
        """Test readFile()"""
        self.tmpdir = cvelib.testutil._createTmpDir()

        fn = os.path.join(self.tmpdir, "test")
        with open(fn, "w") as f:
            f.write("data")

        with cvelib.testutil.capturedOutput() as (output, error):
            res = cvelib.common.readFile(fn)
        os.unlink(fn)
        self.assertTrue(res == {"data"})
        self.assertEqual("", output.getvalue().strip())
        self.assertEqual("", error.getvalue().strip())

        fn_non = os.path.join(self.tmpdir, "active", "test")
        with mock.patch.object(
            cvelib.common.error,
            "__defaults__",
            (
                1,
                False,
            ),
        ):
            with cvelib.testutil.capturedOutput() as (output, error):
                res = cvelib.common.readFile(fn_non)
            self.assertTrue(res is None)
            self.assertEqual("", output.getvalue().strip())
            self.assertTrue(
                "'active/test' is not a regular file" in error.getvalue().strip()
            )

    def test__verifyDate(self):
        """Test _verifyDate()"""
        tsts = [
            # valid
            ("2020-01-01", False, False, True),
            ("2020-02-29", False, False, True),
            ("2020-12-31", False, False, True),
            ("2020-01-01 00:00:00", False, False, True),
            ("2020-12-31 23:59:59", False, False, True),
            ("2020-12-01 12:34:56 UTC", False, False, True),
            ("2020-12-01 12:34:56 -0500", False, False, True),
            ("2019-02-25 09:00:00 CEST", False, False, True),
            ("2020-01-01", True, False, True),
            ("2020-01-01", False, True, True),
            ("2020-01-01", True, True, True),
            # https://bugs.python.org/issue22377
            ("2020-12-14 07:08:09 BADTZ", False, False, True),
            # invalid
            ("bad", False, False, False),
            ("2020-bad", False, False, False),
            ("2020-12-bad", False, False, False),
            ("2020-12-14bad", False, False, False),
            ("2020-12-14 bad", False, False, False),
            ("2020-12-14 07:bad", False, False, False),
            ("2020-12-14 07:08:bad", False, False, False),
            ("2020-12-14 07:08:09bad", False, False, False),
            ("2020-12-14 07:08:09 bad", False, False, False),
            ("2020-12-14 07:08:09 +bad", False, False, False),
            ("2020-12-14 07:08:09 -bad", False, False, False),
            ("2020-12-14 07:08:09 -03bad", False, False, False),
            ("2020-12-14 07:08:09 -0999999", False, False, False),
            ("2020-12-32", False, False, False),
            ("2021-02-29", False, False, False),
            ("2020-06-31", False, False, False),
            ("-2020-12-01", False, False, False),
            ("2020-12-01 30:01:02", False, False, False),
            ("2020-12-01 24:01:02", False, False, False),
            ("2020-12-01 07:60:02", False, False, False),
            ("2020-12-01 07:59:60", False, False, False),
            ("bad", True, False, False),
            ("bad", False, True, False),
            ("bad", True, True, False),
        ]
        for (date, req, compat, valid) in tsts:
            if valid:
                cvelib.common.verifyDate("TestKey", date, req, compatUbuntu=compat)
            else:
                suffix = "(use empty or YYYY-MM-DD [HH:MM:SS [TIMEZONE]])"
                if req:
                    suffix = "(use YYYY-MM-DD [HH:MM:SS [TIMEZONE]])"
                elif compat:
                    suffix = "(use 'unknown' or YYYY-MM-DD [HH:MM:SS [TIMEZONE]])"
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.common.verifyDate("TestKey", date, req, compatUbuntu=compat)
                self.assertEqual(
                    "invalid TestKey: '%s' %s" % (date, suffix),
                    str(context.exception),
                )
