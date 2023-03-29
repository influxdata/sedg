"""test_net.py: tests for net.py module"""
#
# Copyright (c) 2023 InfluxData
# Author: Jamie Strandboge <jamie@influxdata.com>
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
