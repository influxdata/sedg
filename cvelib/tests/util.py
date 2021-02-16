"""util.py; utility functions for tests"""

import os
import tempfile


def _createTmpDir():
    """Create a temporary directory"""
    d = tempfile.mkdtemp(prefix="influx-security-tools-")
    return d


def _newConfigFile(content, tmpdir=None):
    """Create a new config file"""
    if tmpdir is None:
        tmpdir = _createTmpDir()

    orig_xdg_config_home = None
    if "XDG_CONFIG_HOME" in os.environ:
        orig_xdg_config_home = os.environ["XDG_CONFIG_HOME"]

    os.environ["XDG_CONFIG_HOME"] = os.path.join(tmpdir, ".config")
    os.mkdir(os.environ["XDG_CONFIG_HOME"], 0o0700)
    fn = os.path.expandvars("$XDG_CONFIG_HOME/influx-security-tools.conf")

    with open(fn, "w") as fp:
        fp.write("%s" % content)

    return orig_xdg_config_home, tmpdir
