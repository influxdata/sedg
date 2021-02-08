"""test_common.py: tests for common.py module"""

import os
from unittest import TestCase
import tempfile

import cvelib.common


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

    def _createTmpDir(self):
        """Create a temporary directory"""
        d = tempfile.mkdtemp(prefix="influx-security-tools-")
        return d

    def test_msg(self):
        """Test msg()"""
        cvelib.common.msg("Test msg")

    def test_warn(self):
        """Test warn()"""
        cvelib.common.warn("Test warning")

    def test_error(self):
        """Test error()"""
        cvelib.common.error("Test error", do_exit=False)

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
        self.tmpdir = self._createTmpDir()

        if "XDG_CONFIG_HOME" in os.environ:
            self.orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmpdir, ".config")
        fn = os.path.expandvars("$XDG_CONFIG_HOME/influx-security-tools.conf")

        (exp_conf, exp_fn) = cvelib.common.readConfig()
        self.assertEqual(fn, exp_fn)
        self.assertTrue("Locations" in exp_conf)

    def test_getConfigCveDataPath(self):
        """Test getConfigCveDataPath()"""
        self.tmpdir = self._createTmpDir()

        if "XDG_CONFIG_HOME" in os.environ:
            self.orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmpdir, ".config")
        os.mkdir(os.environ["XDG_CONFIG_HOME"], 0o0700)
        data = os.path.join(os.environ["XDG_CONFIG_HOME"], "data")
        os.mkdir(data, 0o0700)
        fn = os.path.expandvars("$XDG_CONFIG_HOME/influx-security-tools.conf")

        with open(fn, "w") as fp:
            fp.write(
                """[Locations]
cve-data = %s
"""
                % data
            )

        exp_fn = cvelib.common.getConfigCveDataPath()
        self.assertEqual(exp_fn, data)
