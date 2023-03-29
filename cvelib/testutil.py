"""util.py; utility functions for tests"""
#
# Copyright (c) 2021-2023 InfluxData
#
# Permission is hereby granted, free of charge, to any
# person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the
# Software without restriction, including without
# limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice
# shall be included in all copies or substantial portions
# of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
# ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

from contextlib import contextmanager
import os
from io import StringIO
import sys
import tempfile


def _createTmpDir():
    """Create a temporary directory"""
    d = tempfile.mkdtemp(prefix="sedg-")
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
    os.mkdir(os.path.join(os.environ["XDG_CONFIG_HOME"], "sedg"), 0o0700)
    fn = os.path.expandvars("$XDG_CONFIG_HOME/sedg/sedg.conf")

    with open(fn, "w") as fp:
        fp.write("%s" % content)

    return orig_xdg_config_home, tmpdir


@contextmanager
def capturedOutput():
    """Capture stdout and stderr as StringIO()"""
    newOut, newErr = StringIO(), StringIO()
    oldOut, oldErr = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = newOut, newErr
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = oldOut, oldErr


def cveContentFromDict(d):
    """Return string suitable for writing out to dictionary"""
    s = ""
    for key in d:
        s += "%s:%s\n" % (key, " %s" % d[key] if d[key] else "")
    return s
