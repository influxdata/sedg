"""test_cache.py: tests for cache.py module"""

from unittest import TestCase

import cvelib.cache


class TestCache(TestCase):
    """Tests for common functions"""

    def setUp(self):
        """Setup functions common for all tests"""

    def tearDown(self):
        """Teardown functions common for all tests"""

    def test__version(self):
        """Test version"""
        # We want to fail if we rev the version as a reminder
        exp = 0
        self.assertEqual(exp, cvelib.cache.CveCache.cveCacheVersion)
