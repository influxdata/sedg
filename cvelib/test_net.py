"""test_net.py: tests for net.py module"""

from unittest import TestCase, mock
import os

import cvelib.net

debug: bool = True


class TestNet(TestCase):
    """Tests for the net functions"""

    def setUp(self):
        """Setup functions common for all tests"""
        self.orig_ghtoken = None

        if "GHTOKEN" in os.environ:
            self.orig_ghtoken = os.getenv("GHTOKEN")
        os.environ["GHTOKEN"] = "fake-test-token"

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.orig_ghtoken is not None:
            os.environ["GHTOKEN"] = self.orig_ghtoken
            self.orig_ghtoken = None

    def _mock_response(self, status=200, json_data=None):
        """Build a mocked requests response

        Example:

          @mock.patch('requests.get')
          def test_requestGetRaw(self, mock_get):
              // successful
              mr = self._mock_response(json_data={"foo": "bar"})
              mock_get.return_value = mr
              res = foo('good')
              self.assertEqual(res, "...")

              // error status
              mr = self._mock_response(status=401)
              mock_get.return_value = mr
              res = foo('bad')
              self.assertEqual(res.status_code, 401)
        """
        mr = mock.Mock()
        mr.status_code = status
        if json_data:
            mr.json = mock.Mock(return_value=json_data)
        return mr

    @mock.patch("requests.get")
    def test_requestGetRaw(self, mock_get):
        """Test requestGetRaw()"""
        mr = self._mock_response(json_data={"foo": "bar"})
        mock_get.return_value = mr

        url = "https://api.github.com/repos/valid-org/valid-repo/issues"
        params = {
            "accept": "application/vnd.github.v3+json",
            "per_page": 100,
        }
        r = cvelib.net.requestGetRaw(url, params=params)
        self.assertEqual(200, r.status_code)
        rjson = r.json()
        self.assertTrue("foo" in rjson)
        self.assertEqual("bar", rjson["foo"])

    @mock.patch("requests.get")
    def test_requestGet(self, mock_get):
        """Test requestGet()"""
        mr = self._mock_response(json_data={"foo": "bar"})
        mock_get.return_value = mr

        url = "https://api.github.com/repos/valid-org/valid-repo/issues"
        params = {
            "accept": "application/vnd.github.v3+json",
            "per_page": 100,
        }
        rjson = cvelib.net.requestGet(url, params=params)
        self.assertTrue("foo" in rjson)
        self.assertEqual("bar", rjson["foo"])

    @mock.patch("requests.post")
    def test_graphQL(self, mock_post):
        """Test requestGet()"""
        mr = self._mock_response(json_data={"foo": "bar"})
        mock_post.return_value = mr

        rjson = cvelib.net.queryGraphQL("foo", headers={})
        self.assertTrue("foo" in rjson)
        self.assertEqual("bar", rjson["foo"])
