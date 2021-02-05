"""test_common.py: tests for common.py module"""

from unittest import TestCase
import cvelib.common


class TestCommon(TestCase):
    """Tests for common functions"""
    def test_msg(self):
        """Test msg()"""
        cvelib.common.msg("Test msg")

    def test_warn(self):
        """Test warn()"""
        cvelib.common.warn("Test warning")

    def test_error(self):
        """Test error()"""
        cvelib.common.error("Test error", do_exit=False)
