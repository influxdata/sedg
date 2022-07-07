"""test_github.py: tests for github.py module"""

from unittest import TestCase

import cvelib.common
import github


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
            "severity": "moderate",
            "status": "needed",
        }

    def test___init__valid(self):
        """Test __init__()"""
        data = self._getValid()
        github.GHDependabot(data)

    def test___repr__(self):
        """Test __repr__()"""
        data = self._getValid()
        exp = """ - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-a
   severity: moderate
   status: needed"""

        ghd = github.GHDependabot(data)
        self.assertEqual(exp, ghd.__repr__())

    def test___str__(self):
        """Test __str__()"""
        data = self._getValid()
        exp = """ - type: dependabot
   dependency: foo
   detectedIn: go.sum
   advisory: https://github.com/advisories/GHSA-a
   severity: moderate
   status: needed"""

        ghd = github.GHDependabot(data)
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
                    "severity": "moderate",
                    "status": "needed",
                },
                "missing required field 'dependency'",
            ),
            (
                {
                    "dependency": "",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "moderate",
                    "status": "needed",
                },
                "empty required field 'dependency'",
            ),
            (
                {
                    "dependency": "foo\nbar",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "moderate",
                    "status": "needed",
                },
                "field 'dependency' should be single line",
            ),
            (
                {
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "moderate",
                    "status": "needed",
                },
                "missing required field 'dependency'",
            ),
            (
                {
                    "dependency": "foo",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "moderate",
                    "status": "needed",
                },
                "missing required field 'detectedIn'",
            ),
            (
                {
                    "dependency": "foo",
                    "detectedIn": "go.sum",
                    "severity": "moderate",
                    "status": "needed",
                },
                "missing required field 'advisory'",
            ),
            (
                {
                    "dependency": "foo",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "status": "needed",
                },
                "missing required field 'severity'",
            ),
            (
                {
                    "dependency": "foo",
                    "detectedIn": "go.sum",
                    "advisory": "https://github.com/advisories/GHSA-a",
                    "severity": "moderate",
                },
                "missing required field 'status'",
            ),
        ]

        for data, expErr in tsts:
            ghd = github.GHDependabot(self._getValid())
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
            # invalid
            ("foo bar", "invalid dependabot dependency: foo bar"),
        ]

        for s, expErr in tsts:
            ghd = github.GHDependabot(self._getValid())
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
            ghd = github.GHDependabot(self._getValid())
            ghd.setDetectedIn(s)

    def test_setAdvisory(self):
        """Test setAdvisory()"""
        tsts = [
            # valid
            ("https://github.com/advisories/GHSA-a", None),
            # invalid
            ("foo", "invalid dependabot advisory: foo"),
        ]

        for s, expErr in tsts:
            ghd = github.GHDependabot(self._getValid())
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
            ("moderate", None),
            ("high", None),
            ("critical", None),
            # invalid
            ("negligible", "invalid dependabot severity: negligible"),
            ("medium", "invalid dependabot severity: medium"),
            ("other", "invalid dependabot severity: other"),
        ]

        for s, expErr in tsts:
            ghd = github.GHDependabot(self._getValid())
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
            ("dismissed (started; username)", None),
            ("dismissed (no-bandwidth; username)", None),
            ("dismissed (tolerable; username)", None),
            ("dismissed (inaccurate; username)", None),
            ("dismissed (code-not-used; username)", None),
            # invalid
            (
                "fixed",
                "invalid dependabot status: fixed. Use 'needs-triage|needed|released|dismissed (...)'",
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
            ghd = github.GHDependabot(self._getValid())
            if expErr is None:
                ghd.setStatus(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghd.setStatus(s)
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
            "status": "needed",
        }

    def test___init__valid(self):
        """Test __init__()"""
        data = self._getValid()
        github.GHSecret(data)

    def test___repr__(self):
        """Test __repr__()"""
        data = self._getValid()
        exp = """ - type: secret
   secret: foo
   detectedIn: path/to/file
   status: needed"""

        ghs = github.GHSecret(data)
        self.assertEqual(exp, ghs.__repr__())

    def test___str__(self):
        """Test __str__()"""
        data = self._getValid()
        exp = """ - type: secret
   secret: foo
   detectedIn: path/to/file
   status: needed"""

        ghs = github.GHSecret(data)
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
                    "status": "needed",
                },
                "missing required field 'secret'",
            ),
            (
                {
                    "secret": "",
                    "detectedIn": "/path/to/file",
                    "status": "needed",
                },
                "empty required field 'secret'",
            ),
            (
                {
                    "secret": "foo\nbar",
                    "detectedIn": "/path/to/file",
                    "status": "needed",
                },
                "field 'secret' should be single line",
            ),
            (
                {
                    "detectedIn": "/path/to/file",
                    "status": "needed",
                },
                "missing required field 'secret'",
            ),
            (
                {
                    "secret": "foo",
                    "status": "needed",
                },
                "missing required field 'detectedIn'",
            ),
            (
                {
                    "secret": "foo",
                    "detectedIn": "/path/to/file",
                },
                "missing required field 'status'",
            ),
        ]

        for data, expErr in tsts:
            ghs = github.GHSecret(self._getValid())
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
            ghs = github.GHSecret(self._getValid())
            ghs.setSecret(s)

    def test_setDetectedIn(self):
        """Test setDetectedIn()"""
        tsts = [
            # valid
            ("foo", None),
            ("path/to/bar", None),
        ]

        for s, expErr in tsts:
            ghs = github.GHSecret(self._getValid())
            ghs.setDetectedIn(s)

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
            ghs = github.GHSecret(self._getValid())
            if expErr is None:
                ghs.setStatus(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    ghs.setStatus(s)
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
   severity: moderate
   status: needed
 - type: secret
   secret: bar
   detectedIn: path/to/files
   status: needed"""

    def test_parse(self):
        """Test parse()"""
        tsts = [
            # valid
            (self._getValidYaml(), None),
            # invalid
            (None, "invalid yaml:\n'None'"),
            ("bad", "invalid GHAS document: 'type' missing for item"),
            (
                """ - type: other
   foo: bar
   baz: norf""",
                "invalid GHAS document: unknown GHAS type 'other'",
            ),
        ]

        for s, expErr in tsts:
            if expErr is None:
                github.parse(s)
            else:
                with self.assertRaises(cvelib.common.CveException) as context:
                    github.parse(s)
                self.assertEqual(expErr, str(context.exception))
