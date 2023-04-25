"""test_github.py: tests for github.py module"""
#
# SPDX-License-Identifier: MIT

from unittest import TestCase

import cvelib.common
import cvelib.github


class TestGitHubDependabot(TestCase):
    """Tests for the GitHub dependabot data and functions"""

    def setUp(self):
        """Setup functions common for all tests"""

    def tearDown(self):
        """Teardown functions common for all tests"""

    def _getValid(self):
        """Returns a valid data structure"""
        return {
            "dependency": "foo",
            "detectedIn": "go.sum",
            "advisory": "https://github.com/advisories/GHSA-a",
            "severity": "medium",
            "status": "needed",
            "url": "https://github.com/bar/baz/security/dependabot/1",
        }

    def test___init__valid(self):
        """Test __init__()"""
        data = self._getValid()
        cvelib.github.GHDependabot(data)

    def test___repr__(self):
        """Test __repr__()"""
        data = self._getValid()
        exp = """ - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-a
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/dependabot/1"""

        ghd = cvelib.github.GHDependabot(data)
        self.assertEqual(exp, ghd.__repr__())

    def test___str__(self):
        """Test __str__()"""
        data = self._getValid()
        exp = """ - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-a
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/dependabot/1"""

        ghd = cvelib.github.GHDependabot(data)
        self.assertEqual(exp, ghd.__str__())

        data["dependency"] = "@foo/bar"
        exp = """ - type: dependabot
   dependency: "@foo/bar"
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-a
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/dependabot/1"""

        ghd = cvelib.github.GHDependabot(data)
        self.assertEqual(exp, ghd.__str__())

    def test__verifyRequired(self):
        """Test _verifyRequired()"""
        tsts = [
            # valid
            (self._getValid(), None),
            # invalid
            (
                {
                    "dpendency": "foo",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/dependabot/1",
                },
                "missing required field 'dependency'",
            ),
            (
                {
                    "dependency": "",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/dependabot/1",
                },
                "empty required field 'dependency'",
            ),
            (
                {
                    "dependency": "foo\nbar",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/dependabot/1",
                },
                "field 'dependency' should be single line",
            ),
            (
                {
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/dependabot/1",
                },
                "missing required field 'dependency'",
            ),
            (
                {
                    "dependency": "foo",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/dependabot/1",
                },
                "missing required field 'detectedIn'",
            ),
            (
                {
                    "dependency": "foo",
                    "detectedIn": "go.sum",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/dependabot/1",
                },
                "missing required field 'advisory'",
            ),
            (
                {
                    "dependency": "foo",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/dependabot/1",
                },
                "missing required field 'severity'",
            ),
            (
                {
                    "dependency": "foo",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "medium",
                    "url": "https://github.com/bar/baz/security/dependabot/1",
                },
                "missing required field 'status'",
            ),
            (
                {
                    "dependency": "foo",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "medium",
                    "status": "needed",
                },
                "missing required field 'url'",
            ),
        ]

        for data, expErr in tsts:
            ghd = cvelib.github.GHDependabot(self._getValid())
            if expErr is None:
                ghd._verifyRequired(data)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd._verifyRequired(data)
                self.assertEqual(expErr, str(context.exception))

    def test_setDependency(self):
        """Test setDependency()"""
        tsts = [
            # valid
            ("foo", None),
            ("@foo/bar", None),
            # invalid
            ("foo bar", "invalid dependabot dependency: foo bar"),
            ("`foo", "invalid dependabot dependency: `foo ('`' is reserved)"),
        ]

        for s, expErr in tsts:
            ghd = cvelib.github.GHDependabot(self._getValid())
            if expErr is None:
                ghd.setDependency(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd.setDependency(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setDetectedIn(self):
        """Test setDetectedIn()"""
        tsts = [
            # valid
            ("foo", None),
            ("path/to/bar", None),
        ]

        for s, expErr in tsts:
            ghd = cvelib.github.GHDependabot(self._getValid())
            ghd.setDetectedIn(s)

    def test_setAdvisory(self):
        """Test setAdvisory()"""
        tsts = [
            # valid
            ("https://github.com/advisories/GHSA-a", None),
            ("unavailable", None),
            # invalid
            ("foo", "invalid dependabot advisory: foo"),
        ]

        for s, expErr in tsts:
            ghd = cvelib.github.GHDependabot(self._getValid())
            if expErr is None:
                ghd.setAdvisory(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd.setAdvisory(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setSeverity(self):
        """Test setSeverity()"""
        tsts = [
            # valid
            ("low", None),
            ("medium", None),
            ("high", None),
            ("critical", None),
            # invalid
            ("negligible", "invalid dependabot severity: negligible"),
            ("mdium", "invalid dependabot severity: mdium"),
            ("other", "invalid dependabot severity: other"),
        ]

        for s, expErr in tsts:
            ghd = cvelib.github.GHDependabot(self._getValid())
            if expErr is None:
                ghd.setSeverity(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd.setSeverity(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setStatus(self):
        """Test setStatus()"""
        tsts = [
            # valid
            ("needs-triage", None),
            ("needed", None),
            ("released", None),
            ("removed", None),
            ("dismissed (started; username)", None),
            ("dismissed (no-bandwidth; username)", None),
            ("dismissed (tolerable; username)", None),
            ("dismissed (inaccurate; username)", None),
            ("dismissed (code-not-used; username)", None),
            # invalid
            (
                "fixed",
                "invalid dependabot status: fixed. Use 'needs-triage|needed|released|removed|dismissed (...)'",
            ),
            (
                "dismissed",
                "invalid dependabot status: dismissed. Use 'dismissed (started|no-bandwidth|tolerable|inaccurate|code-not-used; <github username>)",
            ),
            (
                "dismissed (tolerable)",
                "invalid dependabot status: dismissed (tolerable). Use 'dismissed (started|no-bandwidth|tolerable|inaccurate|code-not-used; <github username>)",
            ),
            (
                "dismissed (tolerable; Jane Doe)",
                "invalid dependabot status: dismissed (tolerable; Jane Doe). Use 'dismissed (started|no-bandwidth|tolerable|inaccurate|code-not-used; <github username>)",
            ),
        ]

        for s, expErr in tsts:
            ghd = cvelib.github.GHDependabot(self._getValid())
            if expErr is None:
                ghd.setStatus(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd.setStatus(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setUrl(self):
        """Test setUrl()"""
        tsts = [
            # valid
            ("https://github.com/bar/baz/security/dependabot/1", None),
            ("unavailable", None),
            # invalid
            ("foo", "invalid dependabot alert url: foo"),
            (
                "https://github.com/bar/baz/security/secret-scanning/1",
                "invalid dependabot alert url: https://github.com/bar/baz/security/secret-scanning/1",
            ),
        ]

        for s, expErr in tsts:
            ghd = cvelib.github.GHDependabot(self._getValid())
            if expErr is None:
                ghd.setUrl(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd.setUrl(s)
                self.assertEqual(expErr, str(context.exception))


class TestGitHubSecret(TestCase):
    """Tests for the GitHub secret data and functions"""

    def setUp(self):
        """Setup functions common for all tests"""

    def tearDown(self):
        """Teardown functions common for all tests"""

    def _getValid(self):
        """Returns a valid data structure"""
        return {
            "secret": "foo",
            "detectedIn": "path/to/file",
            "severity": "medium",
            "status": "needed",
            "url": "https://github.com/bar/baz/security/secret-scanning/1",
        }

    def test___init__valid(self):
        """Test __init__()"""
        data = self._getValid()
        cvelib.github.GHSecret(data)

    def test___repr__(self):
        """Test __repr__()"""
        data = self._getValid()
        exp = """ - type: secret-scanning
   secret: foo
   detectedIn: path/to/file
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/secret-scanning/1"""

        ghs = cvelib.github.GHSecret(data)
        self.assertEqual(exp, ghs.__repr__())

    def test___str__(self):
        """Test __str__()"""
        data = self._getValid()
        exp = """ - type: secret-scanning
   secret: foo
   detectedIn: path/to/file
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/secret-scanning/1"""

        ghs = cvelib.github.GHSecret(data)
        self.assertEqual(exp, ghs.__str__())

    def test__verifyRequired(self):
        """Test _verifyRequired()"""
        tsts = [
            # valid
            (self._getValid(), None),
            # invalid
            (
                {
                    "scret": "foo",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/secret-scanning/1",
                },
                "missing required field 'secret'",
            ),
            (
                {
                    "secret": "",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/secret-scanning/1",
                },
                "empty required field 'secret'",
            ),
            (
                {
                    "secret": "foo\nbar",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/secret-scanning/1",
                },
                "field 'secret' should be single line",
            ),
            (
                {
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/secret-scanning/1",
                },
                "missing required field 'secret'",
            ),
            (
                {
                    "secret": "foo",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/secret-scanning/1",
                },
                "missing required field 'detectedIn'",
            ),
            (
                {
                    "secret": "foo",
                    "detectedIn": "/path/to/file",
                },
                "missing required field 'severity'",
            ),
            (
                {
                    "secret": "foo",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                },
                "missing required field 'status'",
            ),
            (
                {
                    "secret": "foo",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                },
                "missing required field 'url'",
            ),
        ]

        for data, expErr in tsts:
            ghs = cvelib.github.GHSecret(self._getValid())
            if expErr is None:
                ghs._verifyRequired(data)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghs._verifyRequired(data)
                self.assertEqual(expErr, str(context.exception))

    def test_setSecret(self):
        """Test setSecret()"""
        tsts = [
            # valid
            ("foo", None),
            ("foo bar", None),
        ]

        for s, expErr in tsts:
            ghs = cvelib.github.GHSecret(self._getValid())
            ghs.setSecret(s)

    def test_setDetectedIn(self):
        """Test setDetectedIn()"""
        tsts = [
            # valid
            ("foo", None),
            ("path/to/bar", None),
        ]

        for s, expErr in tsts:
            ghs = cvelib.github.GHSecret(self._getValid())
            ghs.setDetectedIn(s)

    def test_setSeverity(self):
        """Test setSeverity()"""
        tsts = [
            # valid
            ("low", None),
            ("medium", None),
            ("high", None),
            ("critical", None),
            # invalid
            ("negligible", "invalid secret severity: negligible"),
            ("mdium", "invalid secret severity: mdium"),
            ("other", "invalid secret severity: other"),
        ]

        for s, expErr in tsts:
            ghd = cvelib.github.GHSecret(self._getValid())
            if expErr is None:
                ghd.setSeverity(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd.setSeverity(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setStatus(self):
        """Test setStatus()"""
        tsts = [
            # valid
            ("needs-triage", None),
            ("needed", None),
            ("released", None),
            ("dismissed (revoked; username)", None),
            ("dismissed (false-positive; username)", None),
            ("dismissed (used-in-tests; username)", None),
            ("dismissed (wont-fix; username)", None),
            # invalid
            (
                "fixed",
                "invalid secret status: fixed. Use 'needs-triage|needed|released|dismissed (...)'",
            ),
            (
                "dismissed",
                "invalid secret status: dismissed. Use 'dismissed (revoked|false-positive|used-in-tests|wont-fix; <github username>)",
            ),
            (
                "dismissed (revoked)",
                "invalid secret status: dismissed (revoked). Use 'dismissed (revoked|false-positive|used-in-tests|wont-fix; <github username>)",
            ),
            (
                "dismissed (revoked; Jane Doe)",
                "invalid secret status: dismissed (revoked; Jane Doe). Use 'dismissed (revoked|false-positive|used-in-tests|wont-fix; <github username>)",
            ),
        ]

        for s, expErr in tsts:
            ghs = cvelib.github.GHSecret(self._getValid())
            if expErr is None:
                ghs.setStatus(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghs.setStatus(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setUrl(self):
        """Test setUrl()"""
        tsts = [
            # valid
            ("https://github.com/bar/baz/security/secret-scanning/1", None),
            ("unavailable", None),
            # invalid
            ("foo", "invalid secret alert url: foo"),
            (
                "https://github.com/bar/baz/security/dependabot/1",
                "invalid secret alert url: https://github.com/bar/baz/security/dependabot/1",
            ),
        ]

        for s, expErr in tsts:
            ghs = cvelib.github.GHSecret(self._getValid())
            if expErr is None:
                ghs.setUrl(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghs.setUrl(s)
                self.assertEqual(expErr, str(context.exception))


class TestGitHubCode(TestCase):
    """Tests for the GitHub code data and functions"""

    def setUp(self):
        """Setup functions common for all tests"""

    def tearDown(self):
        """Teardown functions common for all tests"""

    def _getValid(self):
        """Returns a valid data structure"""
        return {
            "description": "foo",
            "detectedIn": "path/to/file",
            "severity": "medium",
            "status": "needed",
            "url": "https://github.com/bar/baz/security/code-scanning/1",
        }

    def test___init__valid(self):
        """Test __init__()"""
        data = self._getValid()
        cvelib.github.GHCode(data)

    def test___repr__(self):
        """Test __repr__()"""
        data = self._getValid()
        exp = """ - type: code-scanning
   description: foo
   detectedIn: path/to/file
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/code-scanning/1"""

        ghs = cvelib.github.GHCode(data)
        self.assertEqual(exp, ghs.__repr__())

    def test___str__(self):
        """Test __str__()"""
        data = self._getValid()
        exp = """ - type: code-scanning
   description: foo
   detectedIn: path/to/file
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/code-scanning/1"""

        ghs = cvelib.github.GHCode(data)
        self.assertEqual(exp, ghs.__str__())

    def test__verifyRequired(self):
        """Test _verifyRequired()"""
        tsts = [
            # valid
            (self._getValid(), None),
            # invalid
            (
                {
                    "dscription": "foo",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/code-scanning/1",
                },
                "missing required field 'description'",
            ),
            (
                {
                    "description": "",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/code-scanning/1",
                },
                "empty required field 'description'",
            ),
            (
                {
                    "description": "foo\nbar",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/code-scanning/1",
                },
                "field 'description' should be single line",
            ),
            (
                {
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/code-scanning/1",
                },
                "missing required field 'description'",
            ),
            (
                {
                    "description": "foo",
                    "severity": "medium",
                    "status": "needed",
                    "url": "https://github.com/bar/baz/security/code-scanning/1",
                },
                "missing required field 'detectedIn'",
            ),
            (
                {
                    "description": "foo",
                    "detectedIn": "/path/to/file",
                },
                "missing required field 'severity'",
            ),
            (
                {
                    "description": "foo",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                },
                "missing required field 'status'",
            ),
            (
                {
                    "description": "foo",
                    "detectedIn": "/path/to/file",
                    "severity": "medium",
                    "status": "needed",
                },
                "missing required field 'url'",
            ),
        ]

        for data, expErr in tsts:
            ghs = cvelib.github.GHCode(self._getValid())
            if expErr is None:
                ghs._verifyRequired(data)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghs._verifyRequired(data)
                self.assertEqual(expErr, str(context.exception))

    def test_setCode(self):
        """Test setCode()"""
        tsts = [
            # valid
            ("foo", None),
            ("foo bar", None),
        ]

        for s, expErr in tsts:
            ghs = cvelib.github.GHCode(self._getValid())
            ghs.setDescription(s)

    def test_setDetectedIn(self):
        """Test setDetectedIn()"""
        tsts = [
            # valid
            ("foo", None),
            ("path/to/bar", None),
        ]

        for s, expErr in tsts:
            ghs = cvelib.github.GHCode(self._getValid())
            ghs.setDetectedIn(s)

    def test_setSeverity(self):
        """Test setSeverity()"""
        tsts = [
            # valid
            ("low", None),
            ("medium", None),
            ("high", None),
            ("critical", None),
            # invalid
            ("negligible", "invalid code severity: negligible"),
            ("mdium", "invalid code severity: mdium"),
            ("other", "invalid code severity: other"),
        ]

        for s, expErr in tsts:
            ghd = cvelib.github.GHCode(self._getValid())
            if expErr is None:
                ghd.setSeverity(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd.setSeverity(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setStatus(self):
        """Test setStatus()"""
        tsts = [
            # valid
            ("needs-triage", None),
            ("needed", None),
            ("released", None),
            ("dismissed (false-positive; username)", None),
            ("dismissed (used-in-tests; username)", None),
            ("dismissed (wont-fix; username)", None),
            # invalid
            (
                "fixed",
                "invalid code status: fixed. Use 'needs-triage|needed|released|dismissed (...)'",
            ),
            (
                "dismissed",
                "invalid code status: dismissed. Use 'dismissed (false-positive|used-in-tests|wont-fix; <github username>)",
            ),
            (
                "dismissed (false-positive)",
                "invalid code status: dismissed (false-positive). Use 'dismissed (false-positive|used-in-tests|wont-fix; <github username>)",
            ),
            (
                "dismissed (false-positive; Jane Doe)",
                "invalid code status: dismissed (false-positive; Jane Doe). Use 'dismissed (false-positive|used-in-tests|wont-fix; <github username>)",
            ),
            (
                "dismissed (revoked; ghuser1)",
                "invalid code status: dismissed (revoked; ghuser1). Use 'dismissed (false-positive|used-in-tests|wont-fix; <github username>)",
            ),
        ]

        for s, expErr in tsts:
            ghs = cvelib.github.GHCode(self._getValid())
            if expErr is None:
                ghs.setStatus(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghs.setStatus(s)
                self.assertEqual(expErr, str(context.exception))

    def test_setUrl(self):
        """Test setUrl()"""
        tsts = [
            # valid
            ("https://github.com/bar/baz/security/code-scanning/1", None),
            ("unavailable", None),
            # invalid
            ("foo", "invalid code alert url: foo"),
            (
                "https://github.com/bar/baz/security/dependabot/1",
                "invalid code alert url: https://github.com/bar/baz/security/dependabot/1",
            ),
        ]

        for s, expErr in tsts:
            ghs = cvelib.github.GHCode(self._getValid())
            if expErr is None:
                ghs.setUrl(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghs.setUrl(s)
                self.assertEqual(expErr, str(context.exception))


class TestGitHubCommon(TestCase):
    """Tests for the GitHub common functions"""

    def setUp(self):
        """Setup functions common for all tests"""

    def tearDown(self):
        """Teardown functions common for all tests"""

    def _getValidYaml(self):
        """Returns a valid yaml document"""
        return """ - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-a
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/dependabot/1
 - type: secret-scanning
   secret: bar
   detectedIn: path/to/files
   severity: high
   status: needed
   url: https://github.com/bar/baz/security/secret-scanning/1
 - type: code-scanning
   description: baz
   detectedIn: path/to/files
   severity: low
   status: needed
   url: https://github.com/bar/baz/security/code-scanning/1"""

    def test_parse(self):
        """Test parse()"""
        tsts = [
            # valid
            (self._getValidYaml(), None),
            ("", None),
            # invalid
            (None, "invalid yaml:\n'None'"),
            ("bad", "invalid GHAS document: 'type' missing for item"),
            (
                """ - type: other
   foo: bar
   baz: norf""",
                "invalid GHAS document: unknown GHAS type 'other'",
            ),
            (
                """ - type: dependabot
   dependency: @foo/bar
   detectedIn: path/to/thing
   advisory: https://github.com/advisories/GHSA-a
   severity: medium
   status: needed
   url: https://github.com/bar/baz/security/dependabot/1""",
                "invalid yaml: uses unquoted 'dependency: @...'",
            ),
        ]

        for s, expErr in tsts:
            if expErr is None:
                res = cvelib.github.parse(s)
                if s == "":
                    self.assertEqual(0, len(res))
                else:
                    self.assertEqual(3, len(res))
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    cvelib.github.parse(s)
                self.assertEqual(expErr, str(context.exception))