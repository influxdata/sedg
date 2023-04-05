"""test_net.py: tests for net.py module"""
#
# SPDX-License-Identifier: MIT

from unittest import TestCase, mock
import os

import cvelib.net
import cvelib.testutil
import cvelib.common

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

    def _mock_response(self, status=200, json_data=None, resp_headers=None):
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

        mr.headers = {}
        if resp_headers:
            mr.headers = resp_headers

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

    @mock.patch("requests.get")
    def test_ghAPIGetList(self, mock_get):
        """Test ghAPIGetList()"""
        url = "https://api.github.com/orgs/valid-org/dependabot/alerts"
        link1 = '<%s?after=blah1>; rel="next", <%s>; rel="prev"' % (url, url)
        link2 = '<%s?after=blah2>; rel="prev", <%s>; rel="first"' % (url, url)

        # link with next
        resp_headers = {"Link": link1}
        mr = self._mock_response(json_data=[{"foo": "bar"}], resp_headers=resp_headers)
        mock_get.return_value = mr
        rc, rjson = cvelib.net.ghAPIGetList(url)
        self.assertEqual(0, rc)
        self.assertTrue("foo" in rjson[0])
        self.assertEqual("bar", rjson[0]["foo"])

        # link without next
        resp_headers = {"Link": link2}
        mr = self._mock_response(json_data=[{"foo": "bar"}], resp_headers=resp_headers)
        mock_get.return_value = mr
        rc, rjson = cvelib.net.ghAPIGetList(url)
        self.assertEqual(0, rc)
        self.assertTrue("foo" in rjson[0])
        self.assertEqual("bar", rjson[0]["foo"])

        # bad link
        with cvelib.testutil.capturedOutput() as (output, error):
            cvelib.net.ghAPIGetList("https://bad.link", do_exit=False)
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual(
                "ERROR: ghAPIGet() only supports https://api.github.com/ URLs",
                error.getvalue().strip(),
            )
