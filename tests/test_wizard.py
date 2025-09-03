"""test_wizard.py: tests for wizard.py module"""

#
# SPDX-License-Identifier: MIT

from unittest import TestCase, mock

# from unittest.mock import patch, mock_open
import builtins
import contextlib
import json
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

import cvelib.wizard
import cvelib.common
import tests.testutil


class TestWizard(TestCase):
    def setUp(self):
        """Setup functions common for all tests"""
        self.tmpdir = None
        self.orig_xdg_config_home = None

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.orig_xdg_config_home is None:
            if "XDG_CONFIG_HOME" in os.environ:
                del os.environ["XDG_CONFIG_HOME"]
        else:  # pragma: nocover
            os.environ["XDG_CONFIG_HOME"] = self.orig_xdg_config_home
            self.orig_xdg_config_home = None
        cvelib.common.configCache = None

        if self.tmpdir is not None:
            cvelib.common.recursive_rm(self.tmpdir)

    def _create_sample_alerts_json(self):
        """Create sample alerts JSON data"""
        return [
            {
                "repo": "granite",
                "org": "influxdata",
                "alerts": [
                    {
                        "display_name": "github.com/uptrace/bun",
                        "severity": "medium",
                        "type": "dependabot",
                        "url": "https://github.com/influxdata/granite/security/dependabot/86",
                        "created_at": "2025-01-01T00:00:00Z",
                        "manifest_path": "go.mod",
                        "advisory": "https://github.com/advisories/GHSA-h4h6-vccr-44h2",
                    },
                    {
                        "display_name": "github.com/uptrace/bun",
                        "severity": "low",
                        "type": "dependabot",
                        "url": "https://github.com/influxdata/granite/security/dependabot/87",
                        "created_at": "2025-01-01T00:00:00Z",
                        "manifest_path": "go.mod",
                        "advisory": "https://github.com/advisories/GHSA-h4h6-vccr-55i3",
                    },
                ],
                "highest_severity": "medium",
                "alert_types": ["dependabot"],
                "references": [
                    "https://github.com/influxdata/granite/security/dependabot",
                    "https://github.com/influxdata/granite/security/dependabot/86",
                    "https://github.com/influxdata/granite/security/dependabot/87",
                ],
                "template_urls": [],
            }
        ]

    def _create_test_alert(
        self,
        display_name: str = "test-package",
        severity: str = "medium",
        alert_type: str = "dependabot",
        url: str = "https://github.com/org/repo/security/dependabot/1",
        created_at: str = "2025-01-01T00:00:00Z",
        manifest_path: str = "package.json",
        advisory: str = "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
    ) -> Dict[str, Any]:
        """Create a test alert dictionary with sensible defaults"""
        return {
            "display_name": display_name,
            "severity": severity,
            "type": alert_type,
            "url": url,
            "created_at": created_at,
            "manifest_path": manifest_path,
            "advisory": advisory,
        }

    def _create_test_alert_data(
        self,
        repo: str = "test-repo",
        org: str = "test-org",
        alerts: Optional[List[Dict[str, Any]]] = None,
        highest_severity: Optional[str] = None,
        alert_types: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
        template_urls: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a test alert_data dictionary with sensible defaults"""
        if alerts is None:
            alerts = [self._create_test_alert()]

        if highest_severity is None:
            highest_severity = "medium"

        if alert_types is None:
            alert_types = list(set(a["type"] for a in alerts))

        if references is None:
            references = [f"https://github.com/{org}/{repo}/security/dependabot"]
            for alert in alerts:
                if alert["url"] not in references:
                    references.append(alert["url"])

        if template_urls is None:
            template_urls = []

        return {
            "repo": repo,
            "org": org,
            "alerts": alerts,
            "highest_severity": highest_severity,
            "alert_types": alert_types,
            "references": references,
            "template_urls": template_urls,
        }

    def _mock_editor_adds_closedate(self, content, suffix=".cve"):
        assert suffix  # for pyright
        # Add CloseDate to the CVE content
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("CloseDate:"):
                lines[i] = "CloseDate: 2025-06-24"
                break
        return "\n".join(lines)

    @contextlib.contextmanager
    def _mock_user_input_sequence(self, inputs: List[str]):
        """Context manager for mocking user input sequences.

        This replaces mocking of _promptWithOptions and _promptWithDefault
        by directly mocking builtins.input with a sequence of responses.
        """
        with mock.patch("builtins.input", side_effect=inputs) as mock_input:
            yield mock_input

    @contextlib.contextmanager
    def _mock_wizard_command(self, args: List[str], experimental: bool = True):
        """Context manager for mocking wizard command line arguments"""
        with mock.patch("sys.argv", ["cve-add-wizard"] + args):
            env_dict = {"SEDG_EXPERIMENTAL": "1"} if experimental else {}
            with mock.patch.dict("os.environ", env_dict, clear=not experimental):
                yield

    def _setup_temp_config_with_cve_dirs(self, use_cve_data_subdir=True):
        """Helper to set up temporary config with CVE data directories and required subdirs"""
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")

        if use_cve_data_subdir:
            cve_data_dir = os.path.join(self.tmpdir, "cve-data")
        else:
            # Use tmpdir directly as cve-data dir (for backward compatibility)
            cve_data_dir = self.tmpdir

        # Use testutil._newConfigFile to handle config setup
        content = f"[Locations]\ncve-data = {cve_data_dir}\n"
        self.orig_xdg_config_home, _ = tests.testutil._newConfigFile(
            content, self.tmpdir
        )

        # Create CVE data directory and required subdirectories
        os.makedirs(cve_data_dir, exist_ok=True)
        required_dirs = ["active", "retired", "ignored", "templates"]
        for subdir in required_dirs:
            os.makedirs(os.path.join(cve_data_dir, subdir), exist_ok=True)

        # Clear config cache to force re-reading of our temp config
        cvelib.common.configCache = None

        return cve_data_dir

    @mock.patch("subprocess.run")
    def test__closeGithubIssueWithGh_exception(self, mock_subprocess):
        """Test close_github_issue_with_gh when general exception occurs"""
        mock_subprocess.side_effect = RuntimeError("Unexpected error")

        success, error = cvelib.wizard._closeGithubIssueWithGh(
            "test-org", "test-repo", "123", "completed"
        )

        self.assertFalse(success)
        self.assertTrue(error.startswith("Error executing gh command:"))

    @mock.patch("subprocess.run")
    def test__closeGithubIssueWithGh_failure(self, mock_subprocess):
        """Test close_github_issue_with_gh when command fails"""
        mock_subprocess.return_value.returncode = 1
        mock_subprocess.return_value.stdout = ""
        mock_subprocess.return_value.stderr = "Issue not found"

        success, error = cvelib.wizard._closeGithubIssueWithGh(
            "test-org", "test-repo", "999", "completed"
        )

        self.assertFalse(success)
        self.assertEqual(error, "Issue not found")

    @mock.patch("subprocess.run")
    def test__closeGithubIssueWithGh_success(self, mock_subprocess):
        """Test close_github_issue_with_gh successful closure"""
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = ""
        mock_subprocess.return_value.stderr = ""

        success, error = cvelib.wizard._closeGithubIssueWithGh(
            "test-org", "test-repo", "123", "completed"
        )

        self.assertTrue(success)
        self.assertEqual(error, "")
        mock_subprocess.assert_called_once_with(
            [
                "gh",
                "issue",
                "close",
                "123",
                "--repo",
                "test-org/test-repo",
                "--reason",
                "completed",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

    @mock.patch("subprocess.run")
    def test__closeGithubIssueWithGh_timeout(self, mock_subprocess):
        """Test close_github_issue_with_gh when command times out"""
        mock_subprocess.side_effect = subprocess.TimeoutExpired("gh", 30)

        success, error = cvelib.wizard._closeGithubIssueWithGh(
            "test-org", "test-repo", "123", "completed"
        )

        self.assertFalse(success)
        self.assertEqual(error, "GitHub CLI command timed out")

    @mock.patch("subprocess.run")
    def test__createGithubIssueWithGh_failure(self, mock_subprocess):
        """Test create_github_issue_with_gh when command fails"""
        mock_subprocess.return_value.returncode = 1
        mock_subprocess.return_value.stdout = ""
        mock_subprocess.return_value.stderr = "Authentication required"

        success, url, error = cvelib.wizard._createGithubIssueWithGh(
            "org", "repo", "Test Issue", "Test body"
        )

        self.assertFalse(success)
        self.assertEqual(url, "")
        self.assertEqual(error, "Authentication required")

    @mock.patch("subprocess.run")
    def test__createGithubIssueWithGh_general_exception(self, mock_subprocess):
        """Test create_github_issue_with_gh when general exception occurs"""
        mock_subprocess.side_effect = RuntimeError("Unexpected error")

        success, url, error = cvelib.wizard._createGithubIssueWithGh(
            "org", "repo", "Test Issue", "Test body"
        )

        self.assertFalse(success)
        self.assertEqual(url, "")
        self.assertEqual(error, "Error executing gh command: Unexpected error")

    @mock.patch("subprocess.run")
    def test__createGithubIssueWithGh_no_labels(self, mock_subprocess):
        """Test create_github_issue_with_gh without labels"""
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "https://github.com/org/repo/issues/124"
        mock_subprocess.return_value.stderr = ""

        success, url, error = cvelib.wizard._createGithubIssueWithGh(
            "org", "repo", "Test Issue", "Test body"
        )

        self.assertTrue(success)
        self.assertEqual(url, "https://github.com/org/repo/issues/124")
        self.assertEqual(error, "")

        expected_cmd = [
            "gh",
            "issue",
            "create",
            "--repo",
            "org/repo",
            "--title",
            "Test Issue",
            "--body",
            "Test body",
        ]
        mock_subprocess.assert_called_once_with(
            expected_cmd, capture_output=True, text=True, timeout=30
        )

    @mock.patch("subprocess.run")
    def test__createGithubIssueWithGh_success(self, mock_subprocess):
        """Test create_github_issue_with_gh successful creation"""
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "https://github.com/org/repo/issues/123"
        mock_subprocess.return_value.stderr = ""

        success, url, error = cvelib.wizard._createGithubIssueWithGh(
            "org", "repo", "Test Issue", "Test body", "bug,priority/high"
        )

        self.assertTrue(success)
        self.assertEqual(url, "https://github.com/org/repo/issues/123")
        self.assertEqual(error, "")

        expected_cmd = [
            "gh",
            "issue",
            "create",
            "--repo",
            "org/repo",
            "--title",
            "Test Issue",
            "--body",
            "Test body",
            "--label",
            "bug,priority/high",
        ]
        mock_subprocess.assert_called_once_with(
            expected_cmd, capture_output=True, text=True, timeout=30
        )

    @mock.patch("subprocess.run")
    def test__createGithubIssueWithGh_timeout(self, mock_subprocess):
        """Test create_github_issue_with_gh when command times out"""
        mock_subprocess.side_effect = subprocess.TimeoutExpired("gh", 30)

        success, url, error = cvelib.wizard._createGithubIssueWithGh(
            "org", "repo", "Test Issue", "Test body"
        )

        self.assertFalse(success)
        self.assertEqual(url, "")
        self.assertEqual(error, "GitHub CLI command timed out")

    def test__extractDescriptionChanges(self):
        """Test extract_description_changes function"""
        original = """The following alert was issued:
- [ ] [github.com/uptrace/bun](https://example.com) (medium)

Since a medium severity issue is present, tentatively adding the 'security/medium' label.

References:
 * https://docs.example.com"""

        modified = """The following alert was issued:
- [ ] [github.com/uptrace/bun](https://example.com) (medium)

Adding the 'critical' label due to FILL ME IN

References:
 * https://docs.example.com"""

        changes = cvelib.wizard._extractDescriptionChanges(modified, original)
        self.assertEqual(changes, "Adding the 'critical' label due to FILL ME IN")

        # Test with no changes
        no_changes = cvelib.wizard._extractDescriptionChanges(original, original)
        self.assertEqual(no_changes, "")

        # Test with multiline changes
        multiline_modified = """The following alert was issued:
- [ ] [github.com/uptrace/bun](https://example.com) (medium)

Adding the 'critical' label due to FILL ME IN.
This requires immediate attention.
Security team has been notified.

References:
 * https://docs.example.com"""

        multiline_changes = cvelib.wizard._extractDescriptionChanges(
            multiline_modified, original
        )
        expected_multiline = "Adding the 'critical' label due to FILL ME IN.\nThis requires immediate attention.\nSecurity team has been notified."
        self.assertEqual(multiline_changes, expected_multiline)

    def test__extractIssueNumberFromUrl(self):
        """Test extract_issue_number_from_url function"""
        # Test valid URLs
        self.assertEqual(
            cvelib.wizard._extractIssueNumberFromUrl(
                "https://github.com/org/repo/issues/123"
            ),
            "123",
        )
        self.assertEqual(
            cvelib.wizard._extractIssueNumberFromUrl(
                "https://github.com/org/repo/issues/456/"
            ),
            "456",
        )

        # Test invalid URLs
        self.assertEqual(
            cvelib.wizard._extractIssueNumberFromUrl("https://github.com/"), ""
        )
        self.assertEqual(
            cvelib.wizard._extractIssueNumberFromUrl(
                "https://github.com/org/repo/issues/abc"
            ),
            "",
        )
        self.assertEqual(
            cvelib.wizard._extractIssueNumberFromUrl(
                "https://github.com/org/repo/issues/-123"
            ),
            "",
        )
        self.assertEqual(
            cvelib.wizard._extractIssueNumberFromUrl("https://github.com/org/repo"),
            "",
        )
        self.assertEqual(
            cvelib.wizard._extractIssueNumberFromUrl(
                "https://github.com/org/repo/pull/123"
            ),
            "",
        )
        self.assertEqual(cvelib.wizard._extractIssueNumberFromUrl("not-a-url"), "")
        self.assertEqual(
            cvelib.wizard._extractIssueNumberFromUrl(
                "https://example.com/no-issues-here"
            ),
            "",
        )
        self.assertEqual(cvelib.wizard._extractIssueNumberFromUrl(""), "")
        self.assertEqual(cvelib.wizard._extractIssueNumberFromUrl("/"), "")

    def test__formatAsNoteText(self):
        """Test format_note_text function for proper line wrapping"""
        # Test short text
        short_text = "This is a short note"
        formatted = cvelib.wizard._formatAsNoteText(short_text)
        self.assertEqual(formatted, " PERSON> This is a short note")

        # Test long text that needs wrapping
        long_text = "This is a very long note that should be wrapped at 80 characters to ensure proper formatting in the CVE file and maintain readability while following the standard format"
        formatted = cvelib.wizard._formatAsNoteText(long_text)
        lines = formatted.split("\n")

        # First line should start with attribution
        self.assertTrue(lines[0].startswith(" PERSON> "))

        # All lines should be 80 characters or less
        for line in lines:
            self.assertLessEqual(len(line), 80)

        # Continuation lines should start with two spaces
        for line in lines[1:]:
            self.assertTrue(line.startswith("  "))

    def test__formatAsNoteText_custom_author(self):
        """Test format_note_text function with custom author"""
        # Test with custom author without @
        text = "Test note with custom author"
        formatted = cvelib.wizard._formatAsNoteText(text, "jsmith")
        self.assertEqual(formatted, " jsmith> Test note with custom author")

        # Test with custom author with @
        formatted_with_at = cvelib.wizard._formatAsNoteText(text, "@jsmith")
        self.assertEqual(formatted_with_at, " @jsmith> Test note with custom author")

        # Test with text that has paragraphs that become empty after cleaning
        result = cvelib.wizard._formatAsNoteText("Valid text\n\n   \n\n")
        self.assertIn("PERSON> Valid text", result)
        self.assertNotIn("   ", result)

    def test__formatAsNoteText_various_empty(self):
        """Test _formatAsNoteText when all paragraphs are empty after processing"""
        # Test text that results in empty paragraphs after stripping
        text = "\n\n   \n   \n\n"
        result = cvelib.wizard._formatAsNoteText(text)
        self.assertEqual(result, "")

        result = cvelib.wizard._formatAsNoteText("   \n\n   ")
        self.assertEqual(result, "")

        # Test with only whitespace and newlines
        result = cvelib.wizard._formatAsNoteText("   \n\n  \t  \n   ")
        self.assertEqual(result, "")

        # Test with multiple empty paragraphs
        result = cvelib.wizard._formatAsNoteText("\n\n\n\n")
        self.assertEqual(result, "")

        # Text with paragraphs that are only whitespace/special chars
        text = "\t\t\t\n\n    \n\n\r\r\n\n   \u00A0\u00A0  \n\n"
        result = cvelib.wizard._formatAsNoteText(text)
        self.assertEqual(result, "")

        # Test with only whitespace and newlines, with author
        text = "\n\n\n\n\n\n   \n   \n   \n\n\n"
        result = cvelib.wizard._formatAsNoteText(text, "author")
        self.assertEqual(result, "")

    def test__formatAsNoteText_empty_wrap(self):
        """Test _formatAsNoteText when textwrap returns empty list"""
        # Create a string that would cause textwrap to return empty list
        # This happens with certain edge cases in text wrapping
        with mock.patch("textwrap.wrap") as mock_wrap:
            # Return empty list for any call
            mock_wrap.return_value = []
            # Use a very long word that can't be wrapped
            result = cvelib.wizard._formatAsNoteText("x" * 100)
            # Should return empty string when no lines can be wrapped
            self.assertEqual(result, "")

    def test__formatAsNoteText_multiline(self):
        """Test format_note_text function with multiline input"""
        # Test with single newlines - should be converted to spaces
        single_newline_text = "First line\nSecond line\nThird line"
        formatted = cvelib.wizard._formatAsNoteText(single_newline_text)
        self.assertEqual(formatted, " PERSON> First line Second line Third line")

        # Test with double newlines - should create separate paragraphs
        double_newline_text = "First paragraph of the note.\n\nSecond paragraph with more details.\n\nThird paragraph conclusion."
        formatted = cvelib.wizard._formatAsNoteText(double_newline_text)
        lines = formatted.split("\n")

        # Should have attribution line, first paragraph, separator, second paragraph, separator, third paragraph
        self.assertTrue(lines[0].startswith(" PERSON> First paragraph"))

        # Find paragraph separators
        separator_indices = [i for i, line in enumerate(lines) if line.strip() == "."]
        self.assertEqual(
            len(separator_indices), 2
        )  # Two separators between three paragraphs

        # Check that separators have correct indentation
        for idx in separator_indices:
            self.assertEqual(lines[idx], "  .")

        # Verify content exists between separators
        self.assertIn("Second paragraph", formatted)
        self.assertIn("Third paragraph", formatted)

        # Test with multiple newlines (more than 2) - should be treated as paragraph break
        multi_newline_text = "First paragraph.\n\n\n\nSecond paragraph."
        formatted = cvelib.wizard._formatAsNoteText(multi_newline_text)
        lines = formatted.split("\n")
        # Should have first paragraph, separator, second paragraph
        self.assertTrue(lines[0].startswith(" PERSON> First paragraph."))
        self.assertEqual(lines[1], "  .")
        self.assertEqual(lines[2], "  Second paragraph.")

        # Test mixed case - single newlines within paragraphs, double between
        mixed_text = "First paragraph with\na line break inside.\n\nSecond paragraph also with\nanother line break."
        formatted = cvelib.wizard._formatAsNoteText(mixed_text)
        lines = formatted.split("\n")
        # First paragraph should have single newline converted to space
        self.assertTrue(
            lines[0].startswith(" PERSON> First paragraph with a line break inside.")
        )
        self.assertEqual(lines[1], "  .")
        self.assertEqual(lines[2], "  Second paragraph also with another line break.")

    def test__formatAsNoteText_hyphenated_words(self):
        """Test that hyphenated words are not split across lines"""
        # Test long text with hyphenated word at the end
        text_with_hyphen = "This is a very long line with lots of text and it ends with a long-hyphenated-word."
        formatted = cvelib.wizard._formatAsNoteText(text_with_hyphen)
        lines = formatted.split("\n")

        # Verify hyphenated word is not split
        all_text = " ".join(line.strip() for line in lines)
        self.assertIn("long-hyphenated-word", all_text)

        # Check that hyphenated word is not split across lines
        for line in lines:
            # If the line contains part of the hyphenated word, it should contain the whole word
            if "hyphenated" in line:
                self.assertIn("long-hyphenated-word", line)

        # Test with multiple hyphenated words in a long paragraph
        long_text = (
            "This is a document with multiple long-hyphenated-words and another-compound-term "
            "that should not be split across lines when text wrapping occurs during formatting."
        )
        formatted = cvelib.wizard._formatAsNoteText(long_text)
        lines = formatted.split("\n")

        # Verify each hyphenated word remains intact
        for hyphenated_word in ["long-hyphenated-words", "another-compound-term"]:
            found = False
            for line in lines:
                if hyphenated_word in line:
                    found = True
                    break
            self.assertTrue(
                found, f"'{hyphenated_word}' should appear intact in the formatted text"
            )

    def test__generateCveContent(self):
        """Test generate_cve_content function"""
        alerts = self._create_sample_alerts_json()[0]["alerts"]
        tracking_url = "https://github.com/influxdata/granite/issues/123"

        cve_content = cvelib.wizard._generateCveContent(
            alerts, "influxdata", "granite", tracking_url
        )

        # Check key components
        self.assertIn("Candidate: CVE-", cve_content)
        self.assertIn("OpenDate:", cve_content)
        self.assertIn(tracking_url, cve_content)
        self.assertIn("GitHub-Advanced-Security:", cve_content)
        self.assertIn("- type: dependabot", cve_content)
        self.assertIn("dependency: github.com/uptrace/bun", cve_content)
        self.assertIn("Priority: medium", cve_content)
        self.assertIn("Discovered-by: gh-dependabot", cve_content)
        self.assertIn("Patches_granite:", cve_content)
        self.assertIn("git/influxdata_granite: needs-triage", cve_content)

    def test__generateCveContent_at_symbol_display_name(self):
        """Test _generateCveContent with display_name starting with @"""
        alerts = [
            self._create_test_alert(
                display_name="@scoped/package", alert_type="dependabot"
            )
        ]
        tracking_url = "https://github.com/test-org/test-repo/issues/123"

        result = cvelib.wizard._generateCveContent(
            alerts, "test-org", "test-repo", tracking_url
        )
        # Should quote the dependency name
        self.assertIn('dependency: "@scoped/package"', result)

    def test__generateCveContent_code_scanning_alerts(self):
        """Test _generateCveContent with code-scanning alerts"""
        alerts = [
            self._create_test_alert(
                display_name="SQL injection vulnerability",
                alert_type="code-scanning",
                severity="high",
            )
        ]
        tracking_url = "https://github.com/test-org/test-repo/issues/123"

        result = cvelib.wizard._generateCveContent(
            alerts, "test-org", "test-repo", tracking_url
        )

        # Check for code-scanning specific fields
        self.assertIn("- type: code-scanning", result)
        self.assertIn("description: SQL injection vulnerability", result)
        self.assertIn("Discovered-by: gh-code", result)

    @mock.patch("cvelib.wizard.cveFromUrl")
    def test__generateCveContent_cveFromUrl_exception(self, mock_cve_from_url):
        """Test _generateCveContent when cveFromUrl raises exception"""
        # Make cveFromUrl raise an exception
        mock_cve_from_url.side_effect = Exception("URL parsing failed")

        alerts = [self._create_test_alert()]
        tracking_url = "https://github.com/test-org/test-repo/issues/123"

        result = cvelib.wizard._generateCveContent(
            alerts, "test-org", "test-repo", tracking_url
        )

        # Should fall back to default CVE format
        self.assertIn("Candidate: CVE-", result)
        self.assertIn("-NNNN", result)

    def test__generateCveContent_multiple_alerts(self):
        """Test _generateCveContent with multiple alerts"""
        alerts = [
            self._create_test_alert(
                display_name="package-1", url="https://example.com/1"
            ),
            self._create_test_alert(
                display_name="package-1", url="https://example.com/2"
            ),
            self._create_test_alert(
                display_name="package-1", url="https://example.com/3"
            ),
        ]
        tracking_url = "https://github.com/test-org/test-repo/issues/123"

        result = cvelib.wizard._generateCveContent(
            alerts, "test-org", "test-repo", tracking_url
        )
        # Should show count in checklist - it appears as "package-1 (3 medium)"
        self.assertIn("package-1 (3 medium)", result)

    def test__generateCveContent_secret_scanning_alerts(self):
        """Test _generateCveContent with secret-scanning alerts"""
        alerts = [
            self._create_test_alert(
                display_name="AWS Access Key",
                alert_type="secret-scanning",
                severity="critical",
            )
        ]
        tracking_url = "https://github.com/test-org/test-repo/issues/123"

        result = cvelib.wizard._generateCveContent(
            alerts, "test-org", "test-repo", tracking_url
        )

        # Check for secret-scanning specific fields
        self.assertIn("- type: secret-scanning", result)
        self.assertIn("secret: AWS Access Key", result)
        self.assertIn("detectedIn: tbd", result)
        self.assertIn("Discovered-by: gh-secret", result)

    def test__generateCveContent_with_custom_priority(self):
        """Test generate_cve_content function with custom priority override"""
        alerts = self._create_sample_alerts_json()[0]["alerts"]
        tracking_url = "https://github.com/influxdata/granite/issues/123"

        # Test with custom priority different from calculated priority
        cve_content = cvelib.wizard._generateCveContent(
            alerts, "influxdata", "granite", tracking_url, "critical"
        )

        # Check that both global priority and per-package override are present
        self.assertIn("Priority: medium", cve_content)  # Calculated priority
        self.assertIn("Priority_granite: critical", cve_content)  # Override

        # Verify priority override comes before Patches section
        priority_idx = cve_content.find("Priority_granite: critical")
        patches_idx = cve_content.find("Patches_granite:")
        self.assertGreater(
            patches_idx, priority_idx
        )  # Patches should come after priority override

        # Test with custom priority same as calculated priority (no override)
        cve_content_same = cvelib.wizard._generateCveContent(
            alerts, "influxdata", "granite", tracking_url, "medium"
        )

        self.assertIn("Priority: medium", cve_content_same)
        self.assertNotIn("Priority_granite:", cve_content_same)  # No override

    def test__generateCveContent_with_description_changes(self):
        """Test generate_cve_content function with description changes"""
        alerts = self._create_sample_alerts_json()[0]["alerts"]
        tracking_url = "https://github.com/influxdata/granite/issues/123"
        description_changes = "Adding the 'critical' label due to FILL ME IN"

        cve_content = cvelib.wizard._generateCveContent(
            alerts, "influxdata", "granite", tracking_url, "", description_changes
        )

        # Check that Notes section contains the description changes
        self.assertIn("Notes:", cve_content)
        self.assertIn(
            "PERSON> Adding the 'critical' label due to FILL ME IN", cve_content
        )

        # Test with no description changes
        cve_content_no_changes = cvelib.wizard._generateCveContent(
            alerts, "influxdata", "granite", tracking_url, "", ""
        )

        # Notes section should be empty
        notes_start = cve_content_no_changes.find("Notes:")
        mitigation_start = cve_content_no_changes.find("Mitigation:")
        notes_content = cve_content_no_changes[
            notes_start + 6 : mitigation_start
        ].strip()
        self.assertEqual(notes_content, "")

    def test__generateIssueDescription(self):
        """Test generate_issue_description function"""
        alerts = self._create_sample_alerts_json()[0]["alerts"]
        description = cvelib.wizard._generateIssueDescription(
            alerts, "influxdata", "granite"
        )

        # Check key components
        self.assertIn("The following alerts were issued:", description)
        self.assertIn("- [ ] [github.com/uptrace/bun]", description)
        self.assertIn("(medium)", description)
        self.assertIn("(low)", description)
        self.assertIn("security/medium", description)
        self.assertIn(
            "https://github.com/influxdata/granite/security/dependabot", description
        )

    def test__generateIssueDescription_code_scanning(self):
        """Test _generateIssueDescription with code-scanning alerts"""
        alerts = [
            self._create_test_alert(
                alert_type="code-scanning",
                display_name="SQL Injection",
                severity="high",
            )
        ]
        description = cvelib.wizard._generateIssueDescription(
            alerts, "test-org", "test-repo"
        )
        # Should include code-scanning URL
        self.assertIn(
            "https://github.com/test-org/test-repo/security/code-scanning", description
        )

    def test__generateIssueDescription_comprehensive(self):
        """Test generate_issue_description with comprehensive coverage"""
        alerts = [
            {
                "display_name": "test-package",
                "severity": "critical",
                "type": "dependabot",
                "url": "https://example.com/alert1",
            },
            {
                "display_name": "another-package",
                "severity": "low",
                "type": "secret-scanning",
                "url": "https://example.com/alert2",
            },
        ]

        description = cvelib.wizard._generateIssueDescription(
            alerts, "test-org", "test-repo"
        )

        # Check key components
        self.assertIn("The following alerts were issued:", description)
        self.assertIn("- [ ] [test-package]", description)
        self.assertIn("- [ ] [another-package]", description)
        self.assertIn("(critical)", description)
        self.assertIn("(low)", description)
        self.assertIn("security/critical", description)

    def test__generateIssueDescription_sorting(self):
        """Test that checklist items are sorted by display name then URL"""
        # Create alerts with various display names and URLs to test sorting
        alerts = [
            {
                "display_name": "zlib",
                "severity": "high",
                "type": "dependabot",
                "url": "https://github.com/org/repo/security/dependabot/3",
            },
            {
                "display_name": "axios",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://github.com/org/repo/security/dependabot/1",
            },
            {
                "display_name": "axios",  # Same display name, different URL
                "severity": "low",
                "type": "dependabot",
                "url": "https://github.com/org/repo/security/dependabot/2",
            },
            {
                "display_name": "lodash",
                "severity": "critical",
                "type": "dependabot",
                "url": "https://github.com/org/repo/security/dependabot/4",
            },
            {
                "display_name": "axios",  # Same display name, yet another URL
                "severity": "high",
                "type": "dependabot",
                "url": "https://github.com/org/repo/security/dependabot/10",
            },
        ]

        description = cvelib.wizard._generateIssueDescription(
            alerts, "test-org", "test-repo"
        )

        # Extract checklist lines for verification
        lines = description.split("\n")
        checklist_lines = [line for line in lines if line.startswith("- [ ]")]

        # Verify we have the right number of items
        self.assertEqual(len(checklist_lines), 5)

        # Verify the sort order:
        # 1. All axios entries should come first (alphabetically before lodash and zlib)
        # 2. Within axios entries, they should be sorted by URL
        # 3. Then lodash
        # 4. Then zlib
        expected_order = [
            "- [ ] [axios](https://github.com/org/repo/security/dependabot/1) (medium)",
            "- [ ] [axios](https://github.com/org/repo/security/dependabot/10) (high)",
            "- [ ] [axios](https://github.com/org/repo/security/dependabot/2) (low)",
            "- [ ] [lodash](https://github.com/org/repo/security/dependabot/4) (critical)",
            "- [ ] [zlib](https://github.com/org/repo/security/dependabot/3) (high)",
        ]

        self.assertEqual(checklist_lines, expected_order)

    def test__generateIssueSummary(self):
        """Test generate_issue_summary function"""
        # Test with duplicate alert types
        alerts = [
            self._create_test_alert(alert_type="dependabot"),
            self._create_test_alert(alert_type="dependabot"),
        ]
        summary = cvelib.wizard._generateIssueSummary(alerts, "granite")
        self.assertEqual(summary, "Please address alerts (dependabot) in granite")

        # Test with single alert
        alerts = [self._create_test_alert(alert_type="secret-scanning")]
        summary = cvelib.wizard._generateIssueSummary(alerts, "foo")
        self.assertEqual(summary, "Please address alert (secret-scanning) in foo")

        # Test with multiple alert types
        alerts = [
            self._create_test_alert(alert_type="dependabot"),
            self._create_test_alert(alert_type="secret-scanning"),
        ]
        summary = cvelib.wizard._generateIssueSummary(alerts, "bar")
        self.assertEqual(
            summary, "Please address alerts (dependabot, secret-scanning) in bar"
        )

    def test__generateIssueSummary_edge_cases(self):
        """Test generate_issue_summary with edge cases"""
        # Test with single alert
        alerts = [self._create_test_alert(alert_type="dependabot")]
        summary = cvelib.wizard._generateIssueSummary(alerts, "test-repo")
        self.assertEqual(summary, "Please address alert (dependabot) in test-repo")

        # Test with multiple different alert types
        alerts = [
            self._create_test_alert(alert_type="dependabot"),
            self._create_test_alert(alert_type="secret-scanning"),
            self._create_test_alert(alert_type="code-scanning"),
        ]
        summary = cvelib.wizard._generateIssueSummary(alerts, "test-repo")
        self.assertEqual(
            summary,
            "Please address alerts (code-scanning, dependabot, secret-scanning) in test-repo",
        )

    def test__generatePriorityErrorMessage(self):
        """Test _generatePriorityErrorMessage function"""
        result = cvelib.wizard._generatePriorityErrorMessage()
        self.assertIn("ERROR: Priority must be a single letter", result)
        self.assertIn("c/h/m/l/n", result)

    def test__generatePriorityPromptText(self):
        """Test _generatePriorityPromptText function"""
        result = cvelib.wizard._generatePriorityPromptText()
        # Should generate text like "Priority (c/critical for h/high for m/medium for l/low for n/negligible)"
        self.assertIn("Priority", result)
        self.assertIn("c/critical", result)
        self.assertIn("h/high", result)
        self.assertIn("m/medium", result)
        self.assertIn("l/low", result)
        self.assertIn("n/negligible", result)

    def test__getHighestSeverity(self):
        """Test get_highest_severity function"""
        # Test with multiple severities
        alerts = [
            self._create_test_alert(severity="low"),
            self._create_test_alert(severity="medium"),
            self._create_test_alert(severity="high"),
        ]
        self.assertEqual(cvelib.wizard._getHighestSeverity(alerts), "high")

        # Test with single severity
        alerts = [self._create_test_alert(severity="low")]
        self.assertEqual(cvelib.wizard._getHighestSeverity(alerts), "low")

        # Test with unknown severity
        alerts = [self._create_test_alert(severity="unknown")]
        self.assertEqual(cvelib.wizard._getHighestSeverity(alerts), "medium")

        # Test with empty list
        alerts = []
        self.assertEqual(cvelib.wizard._getHighestSeverity(alerts), "medium")

        # Test with empty alert list
        self.assertEqual(cvelib.wizard._getHighestSeverity([]), "medium")

        # Test with unknown severity
        alerts = [{"severity": "unknown"}]
        self.assertEqual(cvelib.wizard._getHighestSeverity(alerts), "medium")

    def test__getHighestSeverity_invalid_severity(self):
        """Test _getHighestSeverity with invalid severity value"""
        # Test with severity not in gh_severities list
        alerts = [
            self._create_test_alert(severity="invalid-severity"),
            self._create_test_alert(severity="low"),
        ]
        # Should handle invalid severity and return "low"
        result = cvelib.wizard._getHighestSeverity(alerts)
        self.assertEqual(result, "low")

        # Test with all invalid severities
        alerts = [
            self._create_test_alert(severity="invalid1"),
            self._create_test_alert(severity="invalid2"),
        ]
        # Should return default "medium"
        result = cvelib.wizard._getHighestSeverity(alerts)
        self.assertEqual(result, "medium")

    def test__groupAlertsByRepo(self):
        """Test group_alerts_by_repo function"""
        alerts_data = self._create_sample_alerts_json()

        # Add another repo using helper
        secret_alert = self._create_test_alert(
            display_name="secret-key",
            severity="high",
            alert_type="secret-scanning",
            url="https://github.com/influxdata/foo/security/secret-scanning/1",
        )
        alerts_data.append(
            self._create_test_alert_data(
                repo="foo",
                org="influxdata",
                alerts=[secret_alert],
                highest_severity="high",
                alert_types=["secret-scanning"],
                references=[
                    "https://github.com/influxdata/foo/security/secret-scanning"
                ],
            )
        )

        grouped = cvelib.wizard._groupAlertsByRepo(alerts_data)

        self.assertEqual(len(grouped), 2)
        self.assertIn("influxdata/granite", grouped)
        self.assertIn("influxdata/foo", grouped)
        self.assertEqual(len(grouped["influxdata/granite"]["alerts"]), 2)
        self.assertEqual(len(grouped["influxdata/foo"]["alerts"]), 1)

    def test__groupAlertsByRepo_multiple_repos(self):
        """Test _groupAlertsByRepo with multiple entries for same repo"""
        # Create multiple alert_data entries for the same org/repo
        alerts_data = [
            self._create_test_alert_data(
                repo="test-repo",
                org="test-org",
                alerts=[self._create_test_alert(severity="low")],
                highest_severity="low",
                alert_types=["dependabot"],
                references=["https://ref1"],
            ),
            self._create_test_alert_data(
                repo="test-repo",
                org="test-org",
                alerts=[
                    self._create_test_alert(
                        severity="high", alert_type="secret-scanning"
                    )
                ],
                highest_severity="high",
                alert_types=["secret-scanning"],
                references=["https://ref2", "https://ref3"],
            ),
        ]

        grouped = cvelib.wizard._groupAlertsByRepo(alerts_data)

        # Should have only one entry for test-org/test-repo
        self.assertEqual(len(grouped), 1)
        self.assertIn("test-org/test-repo", grouped)

        # Should have merged alerts
        self.assertEqual(len(grouped["test-org/test-repo"]["alerts"]), 2)

        # Should have highest severity from all alerts
        self.assertEqual(grouped["test-org/test-repo"]["highest_severity"], "high")

        # Should have merged alert types
        self.assertIn("dependabot", grouped["test-org/test-repo"]["alert_types"])
        self.assertIn("secret-scanning", grouped["test-org/test-repo"]["alert_types"])

        # Should have merged references
        self.assertIn("https://ref1", grouped["test-org/test-repo"]["references"])
        self.assertIn("https://ref2", grouped["test-org/test-repo"]["references"])
        self.assertIn("https://ref3", grouped["test-org/test-repo"]["references"])

    def test__groupAlertsByRepo_edge_cases(self):
        """Test group_alerts_by_repo with edge cases"""
        # Test with empty list
        result = cvelib.wizard._groupAlertsByRepo([])
        self.assertEqual(result, {})

        # Test with single repo
        alerts_data = [
            {
                "repo": "single-repo",
                "org": "test-org",
                "alerts": [{"severity": "medium"}],
                "highest_severity": "medium",
            }
        ]

        result = cvelib.wizard._groupAlertsByRepo(alerts_data)
        self.assertEqual(len(result), 1)
        self.assertIn("test-org/single-repo", result)

    @mock.patch("subprocess.run")
    def test__isGhCliAvailable_failure(self, mock_subprocess):
        """Test is_gh_cli_available when gh command fails"""
        mock_subprocess.return_value.returncode = 1
        self.assertFalse(cvelib.wizard._isGhCliAvailable())

    @mock.patch("subprocess.run")
    def test__isGhCliAvailable_not_found(self, mock_subprocess):
        """Test is_gh_cli_available when gh is not found"""
        mock_subprocess.side_effect = FileNotFoundError()
        self.assertFalse(cvelib.wizard._isGhCliAvailable())

    @mock.patch("subprocess.run")
    def test__isGhCliAvailable_subprocess_error(self, mock_subprocess):
        """Test is_gh_cli_available when subprocess error occurs"""
        mock_subprocess.side_effect = subprocess.SubprocessError("Process error")
        self.assertFalse(cvelib.wizard._isGhCliAvailable())

    @mock.patch("subprocess.run")
    def test__isGhCliAvailable_success(self, mock_subprocess):
        """Test is_gh_cli_available when gh is available"""
        mock_subprocess.return_value.returncode = 0
        self.assertTrue(cvelib.wizard._isGhCliAvailable())
        mock_subprocess.assert_called_once_with(
            ["gh", "--version"], capture_output=True, text=True, timeout=3
        )

    @mock.patch("subprocess.run")
    def test__isGhCliAvailable_timeout(self, mock_subprocess):
        """Test is_gh_cli_available when command times out"""
        mock_subprocess.side_effect = subprocess.TimeoutExpired("gh", 10)
        self.assertFalse(cvelib.wizard._isGhCliAvailable())

    def test__isMarkdownCheckboxLine_edge_cases(self):
        """Test is_markdown_checkbox_line with various edge cases"""
        # Test uppercase X
        self.assertTrue(
            cvelib.wizard._isMarkdownCheckboxLine("- [X] Task with uppercase X")
        )

        # Test with extra whitespace
        self.assertTrue(
            cvelib.wizard._isMarkdownCheckboxLine("   - [ ] Indented task   ")
        )

        # Test false cases
        self.assertFalse(
            cvelib.wizard._isMarkdownCheckboxLine("- Task without checkbox")
        )
        self.assertFalse(cvelib.wizard._isMarkdownCheckboxLine("[] Not a checkbox"))
        self.assertFalse(cvelib.wizard._isMarkdownCheckboxLine(""))

    @mock.patch("cvelib.wizard._openEditor")
    def test__openEditor(self, mock_subprocess):
        """Test open_editor function"""
        # Mock the editor to return modified content
        mock_subprocess.return_value = "edited content"

        result = cvelib.wizard._openEditor("original content")
        self.assertEqual(result, "edited content")

    @mock.patch("shutil.which")
    @mock.patch("os.environ.get")
    def test__openEditor_env_editor_not_available(self, mock_env_get, mock_which):
        """Test openEditor when environment editor is not available"""
        # Mock environment variable set but editor not available
        mock_env_get.side_effect = lambda var: (
            "nonexistent-editor" if var == "SEDG_EDITOR" else None
        )
        mock_which.return_value = None

        with self.assertRaises(RuntimeError) as cm:
            cvelib.wizard._openEditor("test content")

        self.assertIn("No suitable editor found", str(cm.exception))

    @mock.patch("shutil.which")
    @mock.patch("os.environ.get")
    def test__openEditor_no_editor_found(self, mock_env_get, mock_which):
        """Test openEditor when no editor is found"""
        # Mock no environment variables set
        mock_env_get.return_value = None
        # Mock no editors available
        mock_which.return_value = None

        with self.assertRaises(RuntimeError) as cm:
            cvelib.wizard._openEditor("test content")

        self.assertIn("No suitable editor found", str(cm.exception))

    @mock.patch("shutil.which")
    @mock.patch("subprocess.call")
    @mock.patch(
        "builtins.open", new_callable=mock.mock_open, read_data="edited content"
    )
    @mock.patch("os.unlink")
    @mock.patch("tempfile.NamedTemporaryFile")
    def test__openEditor_success(
        self, mock_tempfile, mock_unlink, _, mock_subprocess, mock_which
    ):
        """Test openEditor success case"""
        # Setup mocks
        mock_which.return_value = "/usr/bin/nano"
        mock_tempfile.return_value.__enter__.return_value.name = "/tmp/test.md"
        mock_subprocess.return_value = 0

        result = cvelib.wizard._openEditor("initial content", suffix=".md")
        self.assertEqual(result, "edited content")
        mock_subprocess.assert_called_once()
        mock_unlink.assert_called_once()

    @mock.patch("shutil.which")
    def test__openEditor_invalid_editor_characters(self, mock_which):
        """Test openEditor with various invalid editor names"""
        # Test various invalid characters that don't match ^[a-zA-Z0-9_]+$
        invalid_editors = [
            ("editor-with-dash", "-"),
            ("editor.with.dot", "."),
            ("editor with space", " "),
            ("editor@with@at", "@"),
            ("editor!with!bang", "!"),
            ("editor$with$dollar", "$"),
        ]

        for editor_name, _ in invalid_editors:
            with self.subTest(editor=editor_name):
                with mock.patch.dict(
                    os.environ, {"SEDG_EDITOR": editor_name}, clear=True
                ):
                    # Mock which to return a path (simulating editor exists)
                    mock_which.return_value = f"/usr/bin/{editor_name}"

                    # Should raise RuntimeError due to invalid character
                    with self.assertRaises(RuntimeError) as cm:
                        cvelib.wizard._openEditor("test content")
                    self.assertIn("No suitable editor found", str(cm.exception))

    @mock.patch("subprocess.call")
    @mock.patch(
        "builtins.open", new_callable=mock.mock_open, read_data="edited content"
    )
    @mock.patch("os.unlink")
    @mock.patch("tempfile.NamedTemporaryFile")
    @mock.patch("shutil.which")
    def test__openEditor_valid_editor_names(
        self, mock_which, mock_tempfile, mock_unlink, mock_open_file, mock_subprocess
    ):
        """Test openEditor with valid editor names matching ^[a-zA-Z0-9_]+$"""
        assert mock_unlink  # for pyright
        assert mock_open_file  # for pyright
        # Test various valid editor names
        valid_editors = [
            "vim",
            "EMACS",
            "code",
            "nano123",
            "my_editor",
            "EDITOR_2023",
            "Vi_M",
        ]

        for editor_name in valid_editors:
            with self.subTest(editor=editor_name):
                with mock.patch.dict(
                    os.environ, {"SEDG_EDITOR": editor_name}, clear=True
                ):
                    # Mock which to return a path (simulating editor exists)
                    mock_which.return_value = f"/usr/bin/{editor_name}"
                    mock_tempfile.return_value.__enter__.return_value.name = (
                        "/tmp/test.txt"
                    )
                    mock_subprocess.return_value = 0

                    # Should work without raising an exception
                    result = cvelib.wizard._openEditor("test content")
                    self.assertEqual(result, "edited content")

    def test__parsePriorityInput(self):
        """Test parse_priority_input function with single-letter shortcuts only"""
        # Test cases for valid single letter shortcuts
        test_cases = [
            # (input, expected_output)
            ("c", "critical"),
            ("h", "high"),
            ("m", "medium"),
            ("l", "low"),
            ("n", "negligible"),
            ("C", "critical"),
            ("H", "high"),
            ("M", "medium"),
            ("L", "low"),
            ("N", "negligible"),
        ]

        for input_val, expected in test_cases:
            with self.subTest(input=input_val):
                self.assertEqual(cvelib.wizard._parsePriorityInput(input_val), expected)

        # Test full priority names (should return empty string now)
        self.assertEqual(cvelib.wizard._parsePriorityInput("critical"), "")
        self.assertEqual(cvelib.wizard._parsePriorityInput("high"), "")
        self.assertEqual(cvelib.wizard._parsePriorityInput("medium"), "")
        self.assertEqual(cvelib.wizard._parsePriorityInput("low"), "")
        self.assertEqual(cvelib.wizard._parsePriorityInput("negligible"), "")

        # Test full priority names (uppercase/mixed case - should return empty string)
        self.assertEqual(cvelib.wizard._parsePriorityInput("CRITICAL"), "")
        self.assertEqual(cvelib.wizard._parsePriorityInput("High"), "")
        self.assertEqual(cvelib.wizard._parsePriorityInput("MEDIUM"), "")

        # Test invalid input (should return empty string)
        self.assertEqual(cvelib.wizard._parsePriorityInput("invalid"), "")
        self.assertEqual(cvelib.wizard._parsePriorityInput("x"), "")
        self.assertEqual(cvelib.wizard._parsePriorityInput(""), "")

        # Test with whitespace (should still work for valid single letters)
        self.assertEqual(cvelib.wizard._parsePriorityInput(" c "), "critical")
        self.assertEqual(cvelib.wizard._parsePriorityInput(" m "), "medium")

        # Test with whitespace for invalid input (should return empty string)
        self.assertEqual(cvelib.wizard._parsePriorityInput(" medium "), "")

        # Test invalid input returns empty string
        result = cvelib.wizard._parsePriorityInput("invalid")
        self.assertEqual(result, "")

        # Test empty input returns empty string
        result = cvelib.wizard._parsePriorityInput("")
        self.assertEqual(result, "")

    def test__processRepoAlerts_abort(self):
        """Test process_repo_alerts when user chooses to abort"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Simulate user inputs: org/repo, summary, then abort
        with self._mock_user_input_sequence(
            [
                "test-org/test-repo",  # org/repo prompt
                "test-repo",  # summary prompt
                "a",  # abort choice
            ]
        ):
            alerts_data = {
                "alerts": [
                    {
                        "display_name": "test-package",
                        "severity": "low",
                        "type": "dependabot",
                        "url": "https://example.com/alert",
                    }
                ]
            }

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoAlerts(
                    "test-org",
                    "test-repo",
                    alerts_data,
                    "",
                    "",
                    "",
                    False,
                    None,
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertFalse(result)

            # Verify no stderr in positive test (user abort is not an error)
            self.assertEqual("", error.getvalue().strip())

    def test__processRepoAlerts_abort_at_start(self):
        """Test process_repo_alerts when user chooses to abort at the initial prompt"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Mock the user typing 'a' at the initial org/repo prompt
        with self._mock_user_input_sequence(["a"]):  # abort at first prompt
            alerts_data = {
                "alerts": [
                    {
                        "display_name": "test-package",
                        "severity": "high",
                        "type": "dependabot",
                        "url": "https://example.com/alert",
                    }
                ]
            }

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoAlerts(
                    "test-org",
                    "test-repo",
                    alerts_data,
                    "",
                    "",
                    "",
                    False,
                    None,
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertFalse(result)

            # Verify no stderr
            self.assertEqual("", error.getvalue().strip())

    @mock.patch("cvelib.wizard._processRepoGHIssue")
    def test__processRepoAlerts_abort_from_issue(self, mock_process_issue):
        """Test _processRepoAlerts when user aborts from issue creation"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Make _processRepoGHIssue return False (abort)
        mock_process_issue.return_value = (False, None)

        alert_data = self._create_test_alert_data()

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoAlerts(
                "test-org",
                "test-repo",
                alert_data,
                "",
                "",
                "testuser",
                False,
                None,
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertFalse(result)

        # Verify no stderr in positive test (user abort is not an error)
        self.assertEqual("", error.getvalue().strip())

    @mock.patch("cvelib.wizard._processRepoCVE")
    @mock.patch("cvelib.wizard._processRepoGHIssue")
    def test__processRepoAlerts_abort_on_cve_failure(
        self, mock_process_issue, mock_process_cve
    ):
        """Test _processRepoAlerts returns False when _processRepoCVE returns False"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Setup mocks
        mock_process_issue.return_value = (True, {"tracking_url": "https://test.com"})
        mock_process_cve.return_value = False  # Simulate CVE processing failure

        alerts = [self._create_test_alert()]
        alert_data = {"alerts": alerts}

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoAlerts(
                "test-org",
                "test-repo",
                alert_data,
                "",
                "",
                "",
                False,
                None,
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertFalse(result)  # Should return False when CVE processing fails

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())

    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoAlerts_abort_with_a(self, mock_prompt_default):
        """Test process_repo_alerts when user chooses to abort with 'a' at the initial prompt"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Mock the user typing 'a' at the initial org/repo prompt
        mock_prompt_default.return_value = "a"

        alerts_data = {
            "alerts": [
                {
                    "display_name": "test-package",
                    "severity": "medium",
                    "type": "dependabot",
                    "url": "https://example.com/alert",
                }
            ]
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoAlerts(
                "test-org",
                "test-repo",
                alerts_data,
                "",
                "",
                "",
                False,
                None,
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertFalse(result)

        # Verify no stderr in positive test (user abort is not an error)
        self.assertEqual("", error.getvalue().strip())
        # Should only have called prompt_with_default once for the org/repo prompt
        mock_prompt_default.assert_called_once()

    @mock.patch("cvelib.wizard._closeGithubIssueWithGh")
    @mock.patch("cvelib.wizard._extractIssueNumberFromUrl")
    @mock.patch("cvelib.wizard._isGhCliAvailable")
    @mock.patch("cvelib.wizard._createGithubIssueWithGh")
    def test__processRepoAlerts_auto_close_issue_with_closedate(
        self,
        mock_gh_create,
        mock_gh_available,
        mock_extract_issue,
        mock_close_gh,
    ):
        """Test process_repo_alerts auto-closes GitHub issue when CVE has CloseDate"""
        # Setup mocks for GitHub CLI
        mock_gh_available.return_value = True
        mock_gh_create.return_value = (
            True,
            "https://github.com/test-org/test-repo/issues/123",
            "",
        )
        mock_extract_issue.return_value = "123"
        mock_close_gh.return_value = (True, "")

        # Setup temporary config with proper directory structure
        self._setup_temp_config_with_cve_dirs(use_cve_data_subdir=False)
        assert self.tmpdir is not None  # for pyright

        # Simulate user inputs in sequence
        with self._mock_user_input_sequence(
            [
                "test-org/test-repo",  # org/repo prompt
                "test-repo",  # summary prompt
                "c",  # create - First action: create GitHub issue
                "e",  # edit - CVE action: edit to add CloseDate
                "c",  # create - CVE action: create after editing
            ]
        ):
            # Don't mock builtins.open as we need real config file reading
            with mock.patch(
                "cvelib.wizard._openEditor",
                side_effect=self._mock_editor_adds_closedate,
            ):
                alerts_data = {
                    "alerts": [
                        {
                            "display_name": "test-package",
                            "severity": "high",
                            "type": "dependabot",
                            "url": "https://example.com/alert",
                        }
                    ]
                }

                with tests.testutil.capturedOutput() as (_, error):
                    result = cvelib.wizard._processRepoAlerts(
                        "test-org",
                        "test-repo",
                        alerts_data,
                        "",
                        "",
                        "",
                        False,
                        None,
                        cvelib.common.getConfigCveDataPaths(),
                    )
                    self.assertTrue(result)

                # Verify no stderr in positive test
                self.assertEqual("", error.getvalue().strip())
                # Verify GitHub issue was created
                mock_gh_create.assert_called_once()
                # Verify GitHub issue was closed due to CloseDate
                mock_close_gh.assert_called_once_with(
                    "test-org", "test-repo", "123", "completed"
                )

    @mock.patch("cvelib.wizard._isGhCliAvailable")
    def test__processRepoAlerts_create_manual_fallback(
        self,
        mock_gh_available,
    ):
        """Test process_repo_alerts when gh CLI fails and falls back to manual"""
        # Setup mocks
        mock_gh_available.return_value = False  # gh CLI not available

        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        # Simulate user inputs for manual fallback
        with self._mock_user_input_sequence(
            [
                "test-org/test-repo",  # org/repo prompt
                "test-repo",  # summary prompt
                "c",  # create choice
                "123",  # Issue number (manual input)
                "c",  # CVE action: create
                "n",  # Don't overwrite CVE file (n for no)
            ]
        ):
            # Don't mock builtins.open as we need real config file reading
            with mock.patch("os.path.exists", return_value=True), mock.patch(
                "os.path.join", side_effect=lambda *args: "/".join(args)
            ):

                alerts_data = {
                    "alerts": [
                        {
                            "display_name": "test-package",
                            "severity": "medium",
                            "type": "dependabot",
                            "url": "https://example.com/alert1",
                        }
                    ]
                }

                with tests.testutil.capturedOutput() as (_, error):
                    result = cvelib.wizard._processRepoAlerts(
                        "test-org",
                        "test-repo",
                        alerts_data,
                        "label1,label2",
                        "security/",
                        "testuser",
                        False,
                        None,
                        cvelib.common.getConfigCveDataPaths(),
                    )
                    self.assertTrue(result)

                # Verify no stderr in positive test
                self.assertEqual("", error.getvalue().strip())

    @mock.patch("cvelib.wizard._isGhCliAvailable")
    @mock.patch("cvelib.wizard._createGithubIssueWithGh")
    def test__processRepoAlerts_create_with_gh_success(
        self,
        mock_gh_create,
        mock_gh_available,
    ):
        """Test process_repo_alerts when user chooses create and gh CLI succeeds"""
        # Setup mocks for GitHub CLI
        mock_gh_available.return_value = True
        mock_gh_create.return_value = (
            True,
            "https://github.com/test-org/test-repo/issues/123",
            "",
        )

        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        # Simulate user inputs
        with self._mock_user_input_sequence(
            [
                "test-org/test-repo",  # org/repo prompt
                "test-repo",  # summary prompt
                "c",  # create choice
                "c",  # CVE action: create
                "n",  # Don't overwrite existing CVE file (n for no)
            ]
        ):
            # Don't mock builtins.open as we need real config file reading
            with mock.patch("os.path.exists", return_value=True), mock.patch(
                "os.path.join", side_effect=lambda *args: "/".join(args)
            ):

                alerts_data = {
                    "alerts": [
                        {
                            "display_name": "test-package",
                            "severity": "high",
                            "type": "dependabot",
                            "url": "https://example.com/alert1",
                        }
                    ]
                }

                with tests.testutil.capturedOutput() as (_, error):
                    result = cvelib.wizard._processRepoAlerts(
                        "test-org",
                        "test-repo",
                        alerts_data,
                        "label1,label2",
                        "security/",
                        "testuser",
                        False,
                        None,
                        cvelib.common.getConfigCveDataPaths(),
                    )
                    self.assertTrue(result)

                # Verify no stderr in positive test
                self.assertEqual("", error.getvalue().strip())
                mock_gh_create.assert_called_once()

    @mock.patch("cvelib.wizard._openEditor")
    def test__processRepoAlerts_edit_fields(self, mock_editor):
        """Test process_repo_alerts with editing different fields"""
        # Mock editor for description editing
        mock_editor.return_value = "Edited description content"

        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        # Simulate user inputs for editing multiple fields
        with self._mock_user_input_sequence(
            [
                "e",  # edit - First action: edit
                "u",  # url - Edit field: url
                "new-org/new-repo",  # Edit URL
                "e",  # edit - Second action: edit
                "t",  # title - Edit field: title
                "Custom Issue Title",  # Edit title
                "e",  # edit - Third action: edit
                "d",  # description - Edit field: description
                "c",  # create - Final action: create
                "456",  # Issue number
                "c",  # CVE action: create
                "n",  # Don't overwrite CVE file (n for no)
            ]
        ):
            with mock.patch(
                "cvelib.wizard._isGhCliAvailable", return_value=False
            ), mock.patch("os.path.exists", return_value=True), mock.patch(
                "os.path.join", side_effect=lambda *args: "/".join(args)
            ):

                alerts_data = {
                    "alerts": [
                        {
                            "display_name": "test-package",
                            "severity": "high",
                            "type": "dependabot",
                            "url": "https://example.com/alert",
                        }
                    ]
                }

                with tests.testutil.capturedOutput() as (_, error):
                    result = cvelib.wizard._processRepoAlerts(
                        "test-org",
                        "test-repo",
                        alerts_data,
                        "",
                        "",
                        "",
                        False,
                        None,
                        cvelib.common.getConfigCveDataPaths(),
                    )
                    self.assertTrue(result)

                # Verify no stderr in positive test
                self.assertEqual("", error.getvalue().strip())

    def test__processRepoAlerts_edit_validation_errors(self):
        """Test process_repo_alerts with validation errors in edit mode"""
        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        # Simulate user inputs including invalid inputs that need validation
        with self._mock_user_input_sequence(
            [
                "",  # org/repo (use default)
                "e",  # edit - First action: edit
                "u",  # url - Edit field: url
                "/invalid/input/",  # Invalid input with leading/trailing slashes
                "//invalid//",  # Invalid input with double slashes
                "valid-org/valid-repo",  # Valid input
                "c",  # create - Final action: create
                "123",  # Issue number
                "c",  # CVE action: create
                "n",  # Don't overwrite CVE file (n for no)
            ]
        ):
            with mock.patch(
                "cvelib.wizard._isGhCliAvailable", return_value=False
            ), mock.patch("os.path.exists", return_value=True), mock.patch(
                "os.path.join", side_effect=lambda *args: "/".join(args)
            ):

                alerts_data = {
                    "alerts": [
                        {
                            "display_name": "test-package",
                            "severity": "low",
                            "type": "dependabot",
                            "url": "https://example.com/alert",
                        }
                    ]
                }

                with tests.testutil.capturedOutput() as (_, error):
                    result = cvelib.wizard._processRepoAlerts(
                        "test-org",
                        "test-repo",
                        alerts_data,
                        "",
                        "",
                        "",
                        False,
                        None,
                        cvelib.common.getConfigCveDataPaths(),
                    )
                    self.assertTrue(result)

                # Verify no stderr in positive test
                self.assertEqual("", error.getvalue().strip())

    @mock.patch("cvelib.wizard._closeGithubIssueWithGh")
    @mock.patch("cvelib.wizard._extractIssueNumberFromUrl")
    def test__processRepoAlerts_github_close_failure(self, mock_extract, mock_close):
        """Test processRepoAlerts when GitHub issue closing fails"""
        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        # Mock issue number extraction and failed close
        mock_extract.return_value = "123"
        mock_close.return_value = (False, "Connection failed")

        with mock.patch("os.path.exists", return_value=True), mock.patch(
            "os.path.join", side_effect=lambda *args: "/".join(args)
        ), mock.patch("builtins.input", return_value="123"), mock.patch(
            "cvelib.wizard._promptWithOptions",
            side_effect=[
                "create",
                "edit",
                "create",
                "yes",
            ],  # action, CVE edit, CVE create, overwrite
        ), mock.patch(
            "cvelib.wizard._promptWithDefault",
            side_effect=["test-org/test-repo", "test-repo"],
        ), mock.patch(
            "cvelib.wizard._isGhCliAvailable", return_value=True
        ), mock.patch(
            "cvelib.wizard._createGithubIssueWithGh",
            return_value=(True, "https://github.com/test-org/test-repo/issues/123", ""),
        ), mock.patch(
            "cvelib.wizard._openEditor", side_effect=self._mock_editor_adds_closedate
        ):

            alerts_data = {
                "alerts": [
                    {
                        "display_name": "test-package",
                        "severity": "high",
                        "type": "dependabot",
                        "url": "https://example.com/alert",
                    }
                ]
            }

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoAlerts(
                    "test-org",
                    "test-repo",
                    alerts_data,
                    "label1,label2",
                    "security/",
                    "testuser",
                    False,
                    None,
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
            mock_close.assert_called_once()

    @mock.patch("cvelib.wizard._closeGithubIssueWithGh")
    @mock.patch("cvelib.wizard._extractIssueNumberFromUrl")
    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    @mock.patch("builtins.input")
    def test__processRepoAlerts_no_auto_close_manual_issue(
        self,
        mock_input,
        mock_prompt_default,
        mock_prompt_options,
        mock_extract_issue,
        mock_close_gh,
    ):
        """Test process_repo_alerts does NOT auto-close manually created issues"""
        # Setup mocks
        assert mock_extract_issue  # for pyright
        mock_prompt_default.side_effect = [
            "test-org/test-repo",
            "test-repo",
        ]  # org/repo, summary
        mock_prompt_options.side_effect = [
            "create",  # First action: create GitHub issue
            "edit",  # CVE action: edit to add CloseDate
            "create",  # CVE action: create after editing
        ]

        # Mock manual issue creation (no gh CLI available)
        mock_input.side_effect = ["456"]  # Manual issue number

        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        # Don't mock builtins.open as we need real config file reading
        with mock.patch(
            "cvelib.wizard._isGhCliAvailable", return_value=False
        ), mock.patch(
            "cvelib.wizard._openEditor", side_effect=self._mock_editor_adds_closedate
        ):

            alerts_data = {
                "alerts": [
                    {
                        "display_name": "test-package",
                        "severity": "high",
                        "type": "dependabot",
                        "url": "https://example.com/alert",
                    }
                ]
            }

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoAlerts(
                    "test-org",
                    "test-repo",
                    alerts_data,
                    "",
                    "",
                    "",
                    False,
                    None,
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
            # Verify GitHub issue was NOT closed (manual creation, not via gh CLI)
            mock_close_gh.assert_not_called()

    @mock.patch("cvelib.wizard._closeGithubIssueWithGh")
    @mock.patch("cvelib.wizard._extractIssueNumberFromUrl")
    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    @mock.patch("cvelib.wizard._isGhCliAvailable")
    @mock.patch("cvelib.wizard._createGithubIssueWithGh")
    @mock.patch("builtins.input")
    def test__processRepoAlerts_no_auto_close_without_closedate(
        self,
        mock_input,
        mock_gh_create,
        mock_gh_available,
        mock_prompt_default,
        mock_prompt_options,
        mock_extract_issue,
        mock_close_gh,
    ):
        """Test process_repo_alerts does NOT auto-close when CVE has no CloseDate"""
        # Setup mocks
        assert mock_input  # for pyright
        assert mock_extract_issue  # for pyright
        mock_prompt_default.side_effect = [
            "test-org/test-repo",
            "test-repo",
        ]  # org/repo, summary
        mock_prompt_options.side_effect = [
            "create",  # First action: create GitHub issue
            "create",  # CVE action: create (no CloseDate)
        ]

        # Mock GitHub CLI
        mock_gh_available.return_value = True
        mock_gh_create.return_value = (
            True,
            "https://github.com/test-org/test-repo/issues/123",
            "",
        )

        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        # Don't mock builtins.open as we need real config file reading
        # Only patch the specific file operations we don't want to actually perform

        alerts_data = {
            "alerts": [
                {
                    "display_name": "test-package",
                    "severity": "medium",
                    "type": "dependabot",
                    "url": "https://example.com/alert",
                }
            ]
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoAlerts(
                "test-org",
                "test-repo",
                alerts_data,
                "",
                "",
                "",
                False,
                None,
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Verify GitHub issue was created
        mock_gh_create.assert_called_once()
        # Verify GitHub issue was NOT closed (no CloseDate)
        mock_close_gh.assert_not_called()

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoAlerts_skip(self, mock_prompt_default, mock_prompt_options):
        """Test process_repo_alerts when user chooses to skip"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Mock initial prompts before the skip choice
        mock_prompt_default.side_effect = [
            "test-org/test-repo",
            "test-repo",
        ]  # org/repo, summary
        mock_prompt_options.return_value = "skip"

        alerts_data = {
            "alerts": [
                {
                    "display_name": "test-package",
                    "severity": "low",
                    "type": "dependabot",
                    "url": "https://example.com/alert",
                }
            ]
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoAlerts(
                "test-org",
                "test-repo",
                alerts_data,
                "",
                "",
                "",
                False,
                None,
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())

    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoAlerts_skip_at_start(self, mock_prompt_default):
        """Test process_repo_alerts when user chooses to skip at the initial prompt"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Mock the user typing 's' at the initial org/repo prompt
        mock_prompt_default.return_value = "s"

        alerts_data = {
            "alerts": [
                {
                    "display_name": "test-package",
                    "severity": "low",
                    "type": "dependabot",
                    "url": "https://example.com/alert",
                }
            ]
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoAlerts(
                "test-org",
                "test-repo",
                alerts_data,
                "",
                "",
                "",
                False,
                None,
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Should only have called prompt_with_default once for the org/repo prompt
        mock_prompt_default.assert_called_once()

    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoAlerts_skip_with_s(self, mock_prompt_default):
        """Test process_repo_alerts when user chooses to skip with 's' at the initial prompt"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Mock the user typing 's' at the initial org/repo prompt
        mock_prompt_default.return_value = "s"

        alerts_data = {
            "alerts": [
                {
                    "display_name": "test-package",
                    "severity": "medium",
                    "type": "dependabot",
                    "url": "https://example.com/alert",
                }
            ]
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoAlerts(
                "test-org",
                "test-repo",
                alerts_data,
                "",
                "",
                "",
                False,
                None,
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Should only have called prompt_with_default once for the org/repo prompt
        mock_prompt_default.assert_called_once()

    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoAlerts_existing_ghas_urls_all_filtered(
        self, mock_prompt_default
    ):
        """Test process_repo_alerts when all alerts are already in CVE data"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Create test data with alerts
        alerts_data = {
            "alerts": [
                {
                    "display_name": "test-package-1",
                    "severity": "high",
                    "type": "dependabot",
                    "url": "https://github.com/org/repo/security/dependabot/1",
                },
                {
                    "display_name": "test-package-2",
                    "severity": "medium",
                    "type": "dependabot",
                    "url": "https://github.com/org/repo/security/dependabot/2",
                },
            ]
        }

        # Create existing GHAS URLs dict
        existing_ghas_urls = {
            "https://github.com/org/repo/security/dependabot/1": "/path/to/CVE-2024-0001",
            "https://github.com/org/repo/security/dependabot/2": "/path/to/CVE-2024-0002",
        }

        # Capture printed output
        with tests.testutil.capturedOutput() as (output, error):
            result = cvelib.wizard._processRepoAlerts(
                "org",
                "repo",
                alerts_data,
                "",
                "",
                "",
                False,
                existing_ghas_urls,
                cvelib.common.getConfigCveDataPaths(),
            )

            # Should return True (continue to next repository)
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())

        # Verify warnings were printed to stdout
        output_str = output.getvalue()
        self.assertIn("WARNING: Found 2 alert(s) already in CVE data", output_str)
        self.assertIn("WARNING: No new alerts to process", output_str)

        # Should not have prompted for anything
        mock_prompt_default.assert_not_called()

    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoAlerts_existing_ghas_urls_some_filtered(
        self, mock_prompt_default
    ):
        """Test process_repo_alerts when some alerts are already in CVE data"""
        # Set up temporary config with CVE directories
        self._setup_temp_config_with_cve_dirs()

        # Mock user skipping the repository
        mock_prompt_default.return_value = "s"

        # Create test data with mixed alerts
        alerts_data = {
            "alerts": [
                {
                    "display_name": "existing-package",
                    "severity": "high",
                    "type": "dependabot",
                    "url": "https://github.com/org/repo/security/dependabot/1",
                },
                {
                    "display_name": "new-package",
                    "severity": "medium",
                    "type": "dependabot",
                    "url": "https://github.com/org/repo/security/dependabot/2",
                },
                {
                    "display_name": "another-existing",
                    "severity": "low",
                    "type": "secret-scanning",
                    "url": "https://github.com/org/repo/security/secret-scanning/1",
                },
            ]
        }

        # Create existing GHAS URLs dict
        existing_ghas_urls = {
            "https://github.com/org/repo/security/dependabot/1": "/cve-data/active/CVE-2024-0001",
            "https://github.com/org/repo/security/secret-scanning/1": "/cve-data/active/CVE-2024-0002",
        }

        # Capture printed output
        with tests.testutil.capturedOutput() as (output, error):
            result = cvelib.wizard._processRepoAlerts(
                "org",
                "repo",
                alerts_data,
                "",
                "",
                "",
                False,
                existing_ghas_urls,
                cvelib.common.getConfigCveDataPaths(),
            )

            # Should return True (user skipped)
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())

        # Verify warnings were printed to stdout
        output_str = output.getvalue()

        # Check for existing alerts warning
        self.assertIn("WARNING: Found 2 alert(s) already in CVE data", output_str)

        # Check that specific alerts were mentioned
        self.assertIn("existing-package", output_str)
        self.assertIn("another-existing", output_str)

        # Check for processing new alerts message
        self.assertIn("Processing 1 new alert(s)", output_str)

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_abort(self, mock_prompt_options):
        """Test _processRepoCVE when user chooses to abort"""
        mock_prompt_options.return_value = "abort"

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoCVE(
                "test-org",
                "test-repo",
                alerts,
                issue_data,
                "testuser",
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertFalse(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_create_no_auto_close_manual_issue(
        self, mock_prompt_options
    ):
        """Test _processRepoCVE creates CVE with CloseDate but no auto-close for manual issue"""
        mock_prompt_options.return_value = "create"

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,  # Issue was created manually
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        # Mock _generateCveContent to return content with CloseDate
        with mock.patch(
            "cvelib.wizard._generateCveContent"
        ) as mock_generate, mock.patch(
            "cvelib.wizard._closeGithubIssueWithGh"
        ) as mock_close:
            mock_generate.return_value = (
                "Candidate: CVE-2025-TEST\nCloseDate: 2025-06-24\nDescription: test\n"
            )

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoCVE(
                    "test-org",
                    "test-repo",
                    alerts,
                    issue_data,
                    "testuser",
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
        # Should not attempt to close issue since it was created manually
        mock_close.assert_not_called()

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._closeGithubIssueWithGh")
    @mock.patch("cvelib.wizard._extractIssueNumberFromUrl")
    def test__processRepoCVE_create_with_closedate_and_auto_close(
        self, mock_extract, mock_close, mock_prompt_options
    ):
        """Test _processRepoCVE creates CVE with CloseDate and auto-closes GitHub issue"""
        mock_prompt_options.return_value = "create"
        mock_extract.return_value = "123"
        mock_close.return_value = (True, "")

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": True,  # Issue was created via gh CLI
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        # Mock _generateCveContent to return content with CloseDate
        with mock.patch("cvelib.wizard._generateCveContent") as mock_generate:
            mock_generate.return_value = (
                "Candidate: CVE-2025-TEST\nCloseDate: 2025-06-24\nDescription: test\n"
            )

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoCVE(
                    "test-org",
                    "test-repo",
                    alerts,
                    issue_data,
                    "testuser",
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
        mock_close.assert_called_once_with("test-org", "test-repo", "123", "completed")

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._openEditor")
    @mock.patch("cvelib.wizard._runGitCommand")
    @mock.patch("cvelib.wizard._generateCveContent")
    def test__processRepoCVE_empty_commit_message(
        self, mock_generate, mock_git_cmd, mock_editor, mock_prompt_options
    ):
        """Test _processRepoCVE with empty commit message"""
        mock_prompt_options.side_effect = [
            "create",
            "edit",
        ]  # Create CVE, then edit commit
        mock_generate.return_value = "Candidate: CVE-2025-TEST\nDescription: test\n"
        mock_git_cmd.return_value = (True, "", "")  # Git repo check succeeds
        mock_editor.return_value = ""  # Empty commit message from editor

        self._setup_temp_config_with_cve_dirs()

        alerts = [self._create_test_alert()]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
            "cve_repo_name": "test-repo",
        }

        with tests.testutil.capturedOutput() as (output, error):
            result = cvelib.wizard._processRepoCVE(
                "test-org",
                "test-repo",
                alerts,
                issue_data,
                "testuser",
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        self.assertIn("Empty commit message. Skipping git commit.", output.getvalue())

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._runGitCommand")
    @mock.patch("cvelib.wizard._generateCveContent")
    def test__processRepoCVE_git_add_failure(
        self, mock_generate, mock_git_cmd, mock_prompt_options
    ):
        """Test _processRepoCVE when git add fails"""
        mock_prompt_options.side_effect = ["create", "yes"]  # Create CVE, then commit
        mock_generate.return_value = "Candidate: CVE-2025-TEST\nDescription: test\n"

        # Git is a repo, but add fails
        mock_git_cmd.side_effect = [
            (True, "", ""),  # First call: check if git repo
            (False, "", "Failed to add file"),  # Second call: git add fails
        ]

        self._setup_temp_config_with_cve_dirs()

        alerts = [self._create_test_alert()]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
            "cve_repo_name": "test-repo",
        }

        with tests.testutil.capturedOutput() as (output, error):
            result = cvelib.wizard._processRepoCVE(
                "test-org",
                "test-repo",
                alerts,
                issue_data,
                "testuser",
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Should print error message about git add failure
        output_text = output.getvalue()
        self.assertIn("- Failed to add CVE file to git:", output_text)
        self.assertIn("Error: Failed to add file", output_text)

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._openEditor")
    def test__processRepoCVE_git_commit_edit(self, mock_editor, mock_prompt_options):
        """Test _processRepoCVE allows editing commit message"""
        mock_prompt_options.side_effect = [
            "create",
            "edit",
        ]  # Create CVE, edit commit message
        mock_editor.return_value = "chore: custom commit message"

        # Setup temp directory and config
        cve_data_dir = self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "low",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        with mock.patch(
            "cvelib.wizard._generateCveContent"
        ) as mock_generate, mock.patch("cvelib.wizard._runGitCommand") as mock_git_cmd:
            mock_generate.return_value = (
                "Candidate: CVE-2025-TEST\nCloseDate: 2025-06-24\nDescription: test\n"
            )
            mock_git_cmd.return_value = (True, "", "")

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoCVE(
                    "test-org",
                    "test-repo",
                    alerts,
                    issue_data,
                    "testuser",
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
        # Should have opened editor with default message
        mock_editor.assert_called_once_with(
            "chore: add/retire CVE-2025-TEST", suffix=".gitc"
        )

        # Should have called: git rev-parse, git add -N, and git commit
        self.assertEqual(mock_git_cmd.call_count, 3)

        # First call: git rev-parse
        first_call = mock_git_cmd.call_args_list[0]
        self.assertEqual(
            first_call[0][0],
            ["git", "rev-parse", "--git-dir"],
        )
        self.assertEqual(first_call[0][1], cve_data_dir)

        # Second call: git add -N
        second_call = mock_git_cmd.call_args_list[1]
        self.assertEqual(
            second_call[0][0],
            ["git", "add", "-N", "retired/CVE-2025-TEST"],
        )
        self.assertEqual(second_call[0][1], cve_data_dir)

        # Third call: git commit with custom message
        third_call = mock_git_cmd.call_args_list[2]
        self.assertEqual(
            third_call[0][0],
            ["git", "commit", "retired/CVE-2025-TEST", "-F", "-"],
        )
        self.assertEqual(third_call[0][1], cve_data_dir)
        self.assertEqual(third_call[1]["input_text"], "chore: custom commit message")

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._runGitCommand")
    @mock.patch("cvelib.wizard._generateCveContent")
    def test__processRepoCVE_git_commit_failure(
        self, mock_generate, mock_git_cmd, mock_prompt_options
    ):
        """Test _processRepoCVE when git commit fails"""
        mock_prompt_options.side_effect = ["create", "yes"]  # Create CVE, then commit
        mock_generate.return_value = "Candidate: CVE-2025-TEST\nDescription: test\n"

        # Git is a repo, add succeeds, but commit fails
        mock_git_cmd.side_effect = [
            (True, "", ""),  # First call: check if git repo
            (True, "", ""),  # Second call: git add succeeds
            (False, "", "Failed to commit"),  # Third call: git commit fails
        ]

        self._setup_temp_config_with_cve_dirs()

        alerts = [self._create_test_alert()]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
            "cve_repo_name": "test-repo",
        }

        with tests.testutil.capturedOutput() as (output, error):
            result = cvelib.wizard._processRepoCVE(
                "test-org",
                "test-repo",
                alerts,
                issue_data,
                "testuser",
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Should print error message about commit failure
        output_text = output.getvalue()
        self.assertIn("- Failed to commit CVE file:", output_text)
        self.assertIn("Error: Failed to commit", output_text)

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._openEditor")
    def test__processRepoCVE_git_commit_multiline(
        self, mock_editor, mock_prompt_options
    ):
        """Test _processRepoCVE properly handles multiline commit messages"""
        mock_prompt_options.side_effect = [
            "create",
            "edit",
        ]  # Create CVE, edit commit message
        # Return multiline commit message
        mock_editor.return_value = "chore: add/retire CVE-2025-TEST\n\nThis is a multiline commit message.\nIt has multiple lines.\n\nAnd paragraphs."

        # Setup temp directory and config
        cve_data_dir = self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        with mock.patch(
            "cvelib.wizard._generateCveContent"
        ) as mock_generate, mock.patch("cvelib.wizard._runGitCommand") as mock_git_cmd:
            mock_generate.return_value = (
                "Candidate: CVE-2025-TEST\nCloseDate: 2025-06-24\nDescription: test\n"
            )
            mock_git_cmd.return_value = (True, "", "")

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoCVE(
                    "test-org",
                    "test-repo",
                    alerts,
                    issue_data,
                    "testuser",
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
        # Should have opened editor with default message
        mock_editor.assert_called_once_with(
            "chore: add/retire CVE-2025-TEST", suffix=".gitc"
        )

        # Should have called git commands: rev-parse, add, commit
        self.assertEqual(mock_git_cmd.call_count, 3)

        # Third call should be git commit with multiline message
        third_call = mock_git_cmd.call_args_list[2]
        self.assertEqual(
            third_call[0][0],
            ["git", "commit", "retired/CVE-2025-TEST", "-F", "-"],
        )
        self.assertEqual(third_call[0][1], cve_data_dir)
        # Verify the full multiline message is passed
        self.assertEqual(
            third_call[1]["input_text"],
            "chore: add/retire CVE-2025-TEST\n\nThis is a multiline commit message.\nIt has multiple lines.\n\nAnd paragraphs.",
        )

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_git_commit_no(self, mock_prompt_options):
        """Test _processRepoCVE does not commit when user chooses no"""
        mock_prompt_options.side_effect = ["create", "no"]  # Create CVE, don't commit

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        with mock.patch(
            "cvelib.wizard._generateCveContent"
        ) as mock_generate, mock.patch("cvelib.wizard._runGitCommand") as mock_git:
            mock_generate.return_value = "Candidate: CVE-2025-TEST\nDescription: test\n"
            # Git check returns True, but user will choose "no" for commit
            mock_git.return_value = (True, "", "")

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoCVE(
                    "test-org",
                    "test-repo",
                    alerts,
                    issue_data,
                    "testuser",
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
        # Should only call git rev-parse to check if it's a git repo
        self.assertEqual(mock_git.call_count, 1)
        # Verify it was the git repo check
        mock_git.assert_called_once_with(["git", "rev-parse", "--git-dir"], mock.ANY)

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_git_commit_yes(self, mock_prompt_options):
        """Test _processRepoCVE commits to git when user chooses yes"""
        mock_prompt_options.side_effect = ["create", "yes"]  # Create CVE, then commit

        # Setup temp directory and config
        cve_data_dir = self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        # Mock git commands to succeed
        with mock.patch(
            "cvelib.wizard._generateCveContent"
        ) as mock_generate, mock.patch("cvelib.wizard._runGitCommand") as mock_git_cmd:
            mock_generate.return_value = "Candidate: CVE-2025-TEST\nDescription: test\n"
            mock_git_cmd.return_value = (True, "", "")

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoCVE(
                    "test-org",
                    "test-repo",
                    alerts,
                    issue_data,
                    "testuser",
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
        # Should have called: git rev-parse, git add -N, and git commit
        self.assertEqual(mock_git_cmd.call_count, 3)

        # First call: git rev-parse to check if it's a git repo
        first_call = mock_git_cmd.call_args_list[0]
        self.assertEqual(
            first_call[0][0],
            ["git", "rev-parse", "--git-dir"],
        )
        self.assertEqual(first_call[0][1], cve_data_dir)

        # Second call: git add -N
        second_call = mock_git_cmd.call_args_list[1]
        self.assertEqual(
            second_call[0][0],
            ["git", "add", "-N", "active/CVE-2025-TEST"],
        )
        self.assertEqual(second_call[0][1], cve_data_dir)

        # Third call: git commit with stdin
        third_call = mock_git_cmd.call_args_list[2]
        self.assertEqual(
            third_call[0][0],
            ["git", "commit", "active/CVE-2025-TEST", "-F", "-"],
        )
        self.assertEqual(third_call[0][1], cve_data_dir)
        self.assertEqual(third_call[1]["input_text"], "chore: add CVE-2025-TEST")

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_issue_number_extraction_warning(self, mock_prompt_options):
        """Test _processRepoCVE warning when issue number can't be extracted"""
        mock_prompt_options.return_value = "create"

        self._setup_temp_config_with_cve_dirs()

        alerts = [self._create_test_alert(severity="high")]
        issue_data = {
            "tracking_url": "https://invalid-url-format",  # Invalid URL
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": True,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
            "cve_repo_name": "test-repo",
        }

        with mock.patch("cvelib.wizard._generateCveContent") as mock_generate:
            mock_generate.return_value = (
                "Candidate: CVE-2025-TEST\nCloseDate: 2025-06-24\nDescription: test\n"
            )

            with tests.testutil.capturedOutput() as (output, error):
                result = cvelib.wizard._processRepoCVE(
                    "test-org",
                    "test-repo",
                    alerts,
                    issue_data,
                    "testuser",
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Should print warning about issue number extraction
        output_text = output.getvalue()
        self.assertIn(
            "Warning: Could not extract issue number from https://invalid-url-format to close issue",
            output_text,
        )

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_no_git_repository(self, mock_prompt_options):
        """Test _processRepoCVE does not prompt for git when not a git repository"""
        mock_prompt_options.return_value = "create"

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        with mock.patch(
            "cvelib.wizard._generateCveContent"
        ) as mock_generate, mock.patch("cvelib.wizard._runGitCommand") as mock_git:
            mock_generate.return_value = "Candidate: CVE-2025-TEST\nDescription: test\n"
            # Git check returns False (not a git repository)
            mock_git.return_value = (False, "", "")

            with tests.testutil.capturedOutput() as (_, error):
                result = cvelib.wizard._processRepoCVE(
                    "test-org",
                    "test-repo",
                    alerts,
                    issue_data,
                    "testuser",
                    cvelib.common.getConfigCveDataPaths(),
                )
                self.assertTrue(result)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
        # Should only have been called once for CVE creation, not for git commit prompt
        mock_prompt_options.assert_called_once_with(
            "\nWhat would you like to do?", ["create", "edit", "skip", "abort"]
        )
        # Git command should only be called once to check if it's a repo
        mock_git.assert_called_once_with(["git", "rev-parse", "--git-dir"], mock.ANY)

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_repo_with_modifier(self, mock_prompt_options):
        """Test _processRepoCVE handles repo with modifier correctly in CVE content"""
        mock_prompt_options.return_value = "create"

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
                "manifest_path": "go.mod",
                "advisory": "https://github.com/advisories/GHSA-test",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
            "cve_repo_name": "foo/1.2",  # Repo name with modifier
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoCVE(
                "original-org",
                "original-repo",
                alerts,
                issue_data,
                "testuser",
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        assert self.tmpdir  # for pyright

        # Read the created CVE file to verify content
        cve_files = os.listdir(os.path.join(self.tmpdir, "cve-data", "active"))
        self.assertEqual(len(cve_files), 1)

        cve_file_path = os.path.join(self.tmpdir, "cve-data", "active", cve_files[0])
        with open(cve_file_path, "r") as f:
            cve_content = f.read()

        # Verify the description contains the full repo name with modifier
        self.assertIn("Please address alert in foo/1.2", cve_content)

        # Verify Patches_ uses base repo name (without modifier)
        self.assertIn("Patches_foo:", cve_content)

        # Verify git line uses full repo name with modifier
        self.assertIn("git/original-org_foo/1.2: needs-triage", cve_content)

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_repo_with_modifier_and_custom_priority(
        self, mock_prompt_options
    ):
        """Test _processRepoCVE handles repo with modifier and custom priority correctly"""
        mock_prompt_options.return_value = "create"

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
                "manifest_path": "go.mod",
                "advisory": "https://github.com/advisories/GHSA-test",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "high",  # Custom priority different from severity
            "default_description": "default",
            "issue_description": "description",
            "cve_repo_name": "foo/1.2",  # Repo name with modifier
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoCVE(
                "original-org",
                "original-repo",
                alerts,
                issue_data,
                "testuser",
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        assert self.tmpdir  # for pyright

        # Read the created CVE file to verify content
        cve_files = os.listdir(os.path.join(self.tmpdir, "cve-data", "active"))
        self.assertEqual(len(cve_files), 1)

        cve_file_path = os.path.join(self.tmpdir, "cve-data", "active", cve_files[0])
        with open(cve_file_path, "r") as f:
            cve_content = f.read()

        # Verify the description contains the full repo name with modifier
        self.assertIn("Please address alert in foo/1.2", cve_content)

        # Verify Priority_ uses base repo name (without modifier) with custom priority
        self.assertIn("Priority_foo: high", cve_content)

        # Verify Patches_ uses base repo name (without modifier)
        self.assertIn("Patches_foo:", cve_content)

        # Verify git line uses full repo name with modifier
        self.assertIn("git/original-org_foo/1.2: needs-triage", cve_content)

    @mock.patch("cvelib.wizard._promptWithOptions")
    def test__processRepoCVE_skip(self, mock_prompt_options):
        """Test _processRepoCVE when user chooses to skip"""
        mock_prompt_options.return_value = "skip"

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoCVE(
                "test-org",
                "test-repo",
                alerts,
                issue_data,
                "testuser",
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        mock_prompt_options.assert_called_once_with(
            "\nWhat would you like to do?", ["create", "edit", "skip", "abort"]
        )

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._generateCveContent")
    def test__processRepoCVE_uses_custom_repo_name(
        self, mock_generate_cve, mock_prompt_options
    ):
        """Test _processRepoCVE uses custom repo name from issue_data"""
        mock_prompt_options.return_value = "create"
        mock_generate_cve.return_value = "Candidate: CVE-2025-TEST\nDescription: test\n"

        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
            "cve_repo_name": "custom-repo-name",  # Custom repo name
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoCVE(
                "original-org",
                "original-repo",
                alerts,
                issue_data,
                "testuser",
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())

        # Verify _generateCveContent was called with the custom repo name
        mock_generate_cve.assert_called_once()
        call_args = mock_generate_cve.call_args[0]
        self.assertEqual(call_args[0], alerts)  # alerts
        self.assertEqual(call_args[1], "original-org")  # org
        self.assertEqual(call_args[2], "custom-repo-name")  # repo (should be custom)

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._generateCveContent")
    def test__processRepoCVE_write_failure(self, mock_generate, mock_prompt_options):
        """Test _processRepoCVE when file write fails"""
        mock_prompt_options.return_value = "create"
        mock_generate.return_value = "CVE content"

        # Use the existing helper to set up config and directories
        self._setup_temp_config_with_cve_dirs()

        alerts = [self._create_test_alert()]
        issue_data = {
            "tracking_url": "https://github.com/test-org/test-repo/issues/123",
            "issue_org": "test-org",
            "issue_repo": "test-repo",
            "issue_created_via_gh": False,
            "custom_priority": "",
            "default_description": "default",
            "issue_description": "description",
            "cve_repo_name": "test-repo",
        }

        # Monkey patch open to fail only for CVE file writes
        original_open = builtins.open

        def mock_open_wrapper(filename, *args, **kwargs):
            # Only fail when writing CVE files
            if "CVE-" in str(filename) and len(args) > 0 and "w" in str(args[0]):
                raise Exception("Permission denied")
            return original_open(filename, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=mock_open_wrapper):
            with tests.testutil.capturedOutput() as (_, error):
                with self.assertRaises(SystemExit):
                    cvelib.wizard._processRepoCVE(
                        "test-org",
                        "test-repo",
                        alerts,
                        issue_data,
                        "testuser",
                        cvelib.common.getConfigCveDataPaths(),
                    )
                self.assertNotEqual("", error.getvalue().strip())

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoGHIssue_abort_with_a(
        self, mock_prompt_default, mock_prompt_options
    ):
        """Test _processRepoGHIssue when user chooses to abort with 'a'"""
        assert mock_prompt_options  # for pyright
        mock_prompt_default.return_value = "a"

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]

        with tests.testutil.capturedOutput() as (_, error):
            continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                "test-org", "test-repo", alerts, "labels", "security/", False
            )
            self.assertFalse(continue_processing)

        # Verify no stderr in positive test (user abort is not an error)
        self.assertEqual("", error.getvalue().strip())
        self.assertIsNone(issue_data)

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoGHIssue_custom_repo_name(
        self, mock_prompt_default, mock_prompt_options
    ):
        """Test _processRepoGHIssue stores custom repo name for CVE generation"""
        # Set up prompt responses
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # GitHub org/repo
            "custom-repo-name",  # Repository name for issue summary
        ]
        mock_prompt_options.return_value = "create"

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]

        with mock.patch("cvelib.wizard._isGhCliAvailable") as mock_gh_cli, mock.patch(
            "cvelib.wizard._createGithubIssueWithGh"
        ) as mock_create_issue:
            mock_gh_cli.return_value = True
            mock_create_issue.return_value = (
                True,
                "https://github.com/test-org/test-repo/issues/789",
                "",
            )

            with tests.testutil.capturedOutput() as (_, error):
                continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                    "original-org",
                    "original-repo",
                    alerts,
                    "labels",
                    "security/",
                    False,
                )
                self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        self.assertIsNotNone(issue_data)
        assert issue_data  # for pyright

        # Verify the custom repo name is stored
        self.assertEqual(issue_data["cve_repo_name"], "custom-repo-name")

        # Also verify it's different from the original repo
        self.assertNotEqual(issue_data["cve_repo_name"], "original-repo")

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoGHIssue_custom_repo_name_with_modifier(
        self, mock_prompt_default, mock_prompt_options
    ):
        """Test _processRepoGHIssue extracts repo name from org/repo format"""
        # Set up prompt responses
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # GitHub org/repo
            "custom-repo-name/modifier",  # Repository name with modifier
        ]
        mock_prompt_options.return_value = "create"

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]

        with mock.patch("cvelib.wizard._isGhCliAvailable") as mock_gh_cli, mock.patch(
            "cvelib.wizard._createGithubIssueWithGh"
        ) as mock_create_issue, tests.testutil.capturedOutput() as (_, error):
            mock_gh_cli.return_value = True
            mock_create_issue.return_value = (
                True,
                "https://github.com/test-org/test-repo/issues/999",
                "",
            )

            continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                "original-org", "original-repo", alerts, "labels", "security/", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        self.assertIsNotNone(issue_data)
        assert issue_data  # for pyright

        # Verify both the repo name and its modifier is stored
        self.assertEqual(issue_data["cve_repo_name"], "custom-repo-name/modifier")

    @mock.patch("builtins.input", return_value="123")
    @mock.patch("cvelib.wizard._promptWithDefault")
    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._openEditor")
    @mock.patch("cvelib.wizard._isGhCliAvailable")
    def test__processRepoGHIssue_edit_back(
        self,
        mock_gh_cli,
        mock_editor,
        mock_prompt_options,
        mock_prompt_default,
        mock_input,
    ):
        """Test _processRepoGHIssue with 'back' option"""
        assert mock_editor  # for pyright
        assert mock_input  # for pyright
        mock_gh_cli.return_value = False

        # Track calls to prevent infinite loops
        prompt_options_calls = []

        def safe_prompt_options(prompt, options):
            prompt_options_calls.append((prompt, options))
            if len(prompt_options_calls) > 10:  # pragma: nocover
                raise Exception(
                    f"Infinite loop detected! Calls: {prompt_options_calls}"
                )

            # Return values based on call number
            responses = [
                "edit",  # Call 1: Main action prompt -> choose edit
                "back",  # Call 2: Edit field prompt -> choose back
                "create",  # Call 3: Main action prompt again -> choose create
            ]

            if len(prompt_options_calls) <= len(responses):
                return responses[len(prompt_options_calls) - 1]
            else:  # pragma: nocover
                # If we somehow get more calls, abort to prevent infinite loop
                return "abort"

        mock_prompt_options.side_effect = safe_prompt_options
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # Initial org/repo
            "test-repo",  # Initial summary
        ]

        alerts = [self._create_test_alert()]

        with tests.testutil.capturedOutput() as (_, error):
            continue_processing, _ = cvelib.wizard._processRepoGHIssue(
                "original-org", "original-repo", alerts, "", "", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Verify we got exactly 3 calls to prompt options
        self.assertEqual(len(prompt_options_calls), 3)

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoGHIssue_edit_flow_consistency(
        self, mock_prompt_default, mock_prompt_options
    ):
        """Test _processRepoGHIssue edit flow uses same logic as initial prompting"""
        # Set up prompt responses - initial prompt then edit
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # Initial GitHub org/repo
            "initial-repo",  # Initial repository name for issue summary
            "different-org/different-repo",  # Edit: new org/repo
            "edited-repo/2.0",  # Edit: new repository name with modifier
        ]
        mock_prompt_options.side_effect = [
            "edit",  # Choose to edit
            "url",  # Edit URL first
            "edit",  # Choose to edit again
            "title",  # Edit title
            "create",  # Finally create
        ]

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]

        with mock.patch("cvelib.wizard._isGhCliAvailable") as mock_gh_cli, mock.patch(
            "cvelib.wizard._createGithubIssueWithGh"
        ) as mock_create_issue, tests.testutil.capturedOutput() as (_, error):
            mock_gh_cli.return_value = True
            mock_create_issue.return_value = (
                True,
                "https://github.com/different-org/different-repo/issues/456",
                "",
            )

            continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                "original-org", "original-repo", alerts, "labels", "security/", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        self.assertIsNotNone(issue_data)
        assert issue_data  # for pyright

        # Verify the edited values are stored correctly
        self.assertEqual(issue_data["issue_org"], "different-org")
        self.assertEqual(issue_data["issue_repo"], "different-repo")
        self.assertEqual(issue_data["cve_repo_name"], "edited-repo/2.0")

        # Verify the issue was created with the edited values
        mock_create_issue.assert_called_once()
        call_args = mock_create_issue.call_args
        self.assertEqual(call_args[0][0], "different-org")  # org
        self.assertEqual(call_args[0][1], "different-repo")  # repo
        self.assertEqual(
            call_args[0][2], "Please address alert (dependabot) in edited-repo/2.0"
        )  # title

    @mock.patch("builtins.input", return_value="123")
    @mock.patch("cvelib.wizard._promptWithDefault")
    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._isGhCliAvailable")
    def test__processRepoGHIssue_edit_labels(
        self, mock_gh_cli, mock_prompt_options, mock_prompt_default, _
    ):
        """Test _processRepoGHIssue editing labels"""
        mock_gh_cli.return_value = False

        # Track calls to prevent infinite loops
        prompt_options_calls = []

        def safe_prompt_options(prompt, options):
            prompt_options_calls.append((prompt, options))
            if len(prompt_options_calls) > 10:  # pragma: nocover
                raise Exception(
                    f"Infinite loop detected! Calls: {prompt_options_calls}"
                )

            # Return values based on call number
            responses = [
                "edit",  # Call 1: Main action prompt -> choose edit
                "labels",  # Call 2: Edit field prompt -> choose labels
                "create",  # Call 3: Main action prompt again -> choose create
            ]

            if len(prompt_options_calls) <= len(responses):
                return responses[len(prompt_options_calls) - 1]
            else:  # pragma: nocover
                # If we somehow get more calls, abort to prevent infinite loop
                return "abort"

        mock_prompt_options.side_effect = safe_prompt_options
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # Initial org/repo
            "test-repo",  # Initial summary
            "new-labels,updated",  # New labels when editing
        ]

        alerts = [self._create_test_alert()]

        with tests.testutil.capturedOutput() as (_, error):
            continue_processing, _ = cvelib.wizard._processRepoGHIssue(
                "original-org", "original-repo", alerts, "old-labels", "", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Verify we got exactly 3 calls to prompt options
        self.assertEqual(len(prompt_options_calls), 3)

    @mock.patch("cvelib.wizard._generatePriorityErrorMessage")
    @mock.patch("cvelib.wizard._updateDescriptionForCustomPriority")
    @mock.patch("cvelib.wizard._generatePriorityPromptText")
    @mock.patch("cvelib.wizard._parsePriorityInput")
    @mock.patch("cvelib.wizard._promptWithDefault")
    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._isGhCliAvailable")
    @mock.patch("cvelib.wizard._createGithubIssueWithGh")
    def test__processRepoGHIssue_edit_priority_workflow(
        self,
        mock_create_issue,
        mock_gh_cli,
        mock_prompt_options,
        mock_prompt_default,
        mock_parse_priority,
        mock_priority_prompt_text,
        mock_update_desc_priority,
        mock_priority_error,
    ):
        """Test _processRepoGHIssue priority editing workflow"""
        # Initial setup prompts
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # Initial org/repo
            "test-repo",  # Initial summary
            "h",  # First priority input (invalid)
            "h",  # Second priority input (valid)
        ]

        mock_prompt_options.side_effect = [
            "edit",  # Choose to edit
            "priority",  # Edit priority
            "create",  # Finally create
        ]

        # Mock priority parsing
        mock_parse_priority.side_effect = [
            "",  # First call returns empty (invalid)
            "high",  # Second call returns valid priority
        ]

        # Mock priority prompt text
        mock_priority_prompt_text.return_value = (
            "Priority (c/critical for h/high for m/medium for l/low for n/negligible)"
        )

        # Mock priority error message
        mock_priority_error.return_value = (
            "Invalid priority. Please enter a single letter: c, h, m, l, or n"
        )

        # Mock description update
        mock_update_desc_priority.return_value = (
            "Updated description with custom priority"
        )

        # Mock GitHub CLI
        mock_gh_cli.return_value = True
        mock_create_issue.return_value = (
            True,
            "https://github.com/test-org/test-repo/issues/123",
            "",
        )

        alerts = [self._create_test_alert(severity="medium")]

        with tests.testutil.capturedOutput() as (output, error):
            continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                "original-org", "original-repo", alerts, "", "security/", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        self.assertIsNotNone(issue_data)
        assert issue_data is not None  # for pyright

        # Verify priority was updated
        self.assertEqual(issue_data["custom_priority"], "high")

        # Verify print statements
        output_text = output.getvalue()
        self.assertIn("Current priority: medium", output_text)
        self.assertIn("Calculated highest severity: medium", output_text)
        self.assertIn("- Updated priority: high", output_text)
        self.assertIn("- Updated labels: security/high", output_text)
        self.assertIn(
            "Invalid priority. Please enter a single letter: c, h, m, l, or n",
            output_text,
        )

        # Verify description was updated
        mock_update_desc_priority.assert_called_once()

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._isGhCliAvailable")
    @mock.patch("cvelib.wizard._createGithubIssueWithGh")
    @mock.patch("cvelib.wizard._promptWithDefault")
    @mock.patch("builtins.input")
    def test__processRepoGHIssue_gh_cli_failure_fallback(
        self,
        mock_input,
        mock_prompt_default,
        mock_gh_create,
        mock_gh_available,
        mock_prompt_options,
    ):
        """Test _processRepoGHIssue when gh CLI fails and falls back to manual"""
        mock_prompt_default.side_effect = ["test-org/test-repo", "test-repo"]
        mock_prompt_options.return_value = "create"
        mock_gh_available.return_value = True
        mock_gh_create.return_value = (False, "", "gh CLI error")
        mock_input.return_value = "456"

        alerts = [
            {
                "display_name": "test-package",
                "severity": "medium",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]

        with tests.testutil.capturedOutput() as (_, error):
            continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                "test-org", "test-repo", alerts, "labels", "security/", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        self.assertIsNotNone(issue_data)
        if issue_data is not None:
            self.assertEqual(
                issue_data["tracking_url"],
                "https://github.com/test-org/test-repo/issues/456",
            )
            self.assertFalse(issue_data["issue_created_via_gh"])

    @mock.patch("cvelib.wizard._processOrgRepoInput")
    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoGHIssue_invalid_org_repo_format(
        self, mock_prompt_default, mock_prompt_options, mock_process_org_repo
    ):
        """Test _processRepoGHIssue with invalid org/repo format"""
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # Initial org/repo
            "test-repo",  # Initial summary
            "invalid//format",  # Invalid format that will trigger ValueError
            "valid-org/valid-repo",  # Valid retry input after error
        ]
        mock_prompt_options.side_effect = [
            "edit",  # Choose to edit
            "url",  # Edit URL
            "create",  # Finally create
        ]

        # Make _processOrgRepoInput raise ValueError for invalid format
        mock_process_org_repo.side_effect = [
            (
                "test-org",
                "test-repo",
                "https://github.com/test-org/test-repo/issues/new",
            ),  # First call succeeds
            ValueError(
                "Invalid format. No leading, trailing, or multiple forward slashes allowed."
            ),  # Second call fails
            (
                "valid-org",
                "valid-repo",
                "https://github.com/valid-org/valid-repo/issues/new",
            ),  # Third call succeeds
        ]

        alerts = [self._create_test_alert()]

        with mock.patch("cvelib.wizard._isGhCliAvailable") as mock_gh_cli, mock.patch(
            "cvelib.wizard._createGithubIssueWithGh"
        ) as mock_create_issue, tests.testutil.capturedOutput() as (output, error):
            mock_gh_cli.return_value = True
            mock_create_issue.return_value = (
                True,
                "https://github.com/valid-org/valid-repo/issues/123",
                "",
            )

            continue_processing, _ = cvelib.wizard._processRepoGHIssue(
                "original-org", "original-repo", alerts, "", "", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Should print error message
        self.assertIn(
            "ERROR: Invalid format. No leading, trailing, or multiple forward slashes allowed.",
            output.getvalue(),
        )

    @mock.patch("builtins.input")
    @mock.patch("cvelib.wizard._promptWithDefault")
    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._isGhCliAvailable")
    def test__processRepoGHIssue_manual_issue_number(
        self, mock_gh_cli, mock_prompt_options, mock_prompt_default, mock_input
    ):
        """Test _processRepoGHIssue with manual issue number input"""
        mock_gh_cli.return_value = False

        # Track calls to prevent infinite loops
        input_calls = []

        def safe_input(prompt=""):
            input_calls.append(prompt)
            if len(input_calls) > 10:  # pragma: nocover
                raise Exception(
                    f"Infinite loop detected in input! Calls: {input_calls}"
                )

            # First input is invalid, second is valid
            responses = ["invalid", "123"]
            if len(input_calls) <= len(responses):
                return responses[len(input_calls) - 1]
            else:  # pragma: nocover
                # Emergency exit
                return "1"

        mock_input.side_effect = safe_input
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # org/repo
            "test-repo",  # summary
        ]
        mock_prompt_options.return_value = "create"

        alerts = [self._create_test_alert()]

        with tests.testutil.capturedOutput() as (output, error):
            continue_processing, _ = cvelib.wizard._processRepoGHIssue(
                "original-org", "original-repo", alerts, "", "", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Should print error for invalid input
        self.assertIn("ERROR: Please enter a non-negative integer.", output.getvalue())
        # Verify we tried input twice
        self.assertEqual(len(input_calls), 2)

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoGHIssue_repo_with_modifier(
        self, mock_prompt_default, mock_prompt_options
    ):
        """Test _processRepoGHIssue handles repo name with modifier (e.g., foo/1.2) in issue summary"""
        # Set up prompt responses
        mock_prompt_default.side_effect = [
            "test-org/test-repo",  # GitHub org/repo
            "foo/1.2",  # Repository name with modifier for issue summary
        ]
        mock_prompt_options.return_value = "create"

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]

        with mock.patch("cvelib.wizard._isGhCliAvailable") as mock_gh_cli, mock.patch(
            "cvelib.wizard._createGithubIssueWithGh"
        ) as mock_create_issue, tests.testutil.capturedOutput() as (_, error):
            mock_gh_cli.return_value = True
            mock_create_issue.return_value = (
                True,
                "https://github.com/test-org/test-repo/issues/123",
                "",
            )

            continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                "original-org", "original-repo", alerts, "labels", "security/", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        self.assertIsNotNone(issue_data)
        assert issue_data  # for pyright

        # Verify the full repo name with modifier is stored
        self.assertEqual(issue_data["cve_repo_name"], "foo/1.2")

        # Verify the issue was created with the correct summary containing the modifier
        mock_create_issue.assert_called_once()
        call_args = mock_create_issue.call_args
        self.assertEqual(call_args[0][0], "test-org")  # org
        self.assertEqual(call_args[0][1], "test-repo")  # repo
        self.assertEqual(
            call_args[0][2], "Please address alert (dependabot) in foo/1.2"
        )  # title with modifier

    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    def test__processRepoGHIssue_skip_with_s(
        self, mock_prompt_default, mock_prompt_options
    ):
        """Test _processRepoGHIssue when user chooses to skip with 's'"""
        assert mock_prompt_options  # for pyright
        mock_prompt_default.return_value = "s"

        alerts = [
            {
                "display_name": "test-package",
                "severity": "high",
                "type": "dependabot",
                "url": "https://example.com/alert",
            }
        ]

        with tests.testutil.capturedOutput() as (_, error):
            continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                "test-org", "test-repo", alerts, "labels", "security/", False
            )
            self.assertTrue(continue_processing)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        self.assertIsNone(issue_data)
        mock_prompt_default.assert_called_once_with(
            "GitHub org/repo for filing issues (or [s]kip/[a]bort)",
            "test-org/test-repo",
        )

    @mock.patch("builtins.input")
    def test__promptWithDefault(self, mock_input):
        """Test prompt_with_default function"""
        # Test with default accepted
        mock_input.return_value = ""
        result = cvelib.wizard._promptWithDefault("Enter value", "default")
        self.assertEqual(result, "default")

        # Test with custom value
        mock_input.return_value = "custom"
        result = cvelib.wizard._promptWithDefault("Enter value", "default")
        self.assertEqual(result, "custom")

    def test__promptWithDefault_no_default(self):
        """Test _promptWithDefault when default is empty string"""
        with mock.patch("builtins.input") as mock_input:
            mock_input.return_value = "user input"
            result = cvelib.wizard._promptWithDefault("Enter value", "")
            self.assertEqual(result, "user input")
            mock_input.assert_called_once_with("Enter value: ")

    @mock.patch("builtins.input")
    def test__promptWithOptions(self, mock_input):
        """Test prompt_with_options function"""
        # Test valid option
        mock_input.return_value = "c"
        result = cvelib.wizard._promptWithOptions("Choose", ["create", "edit", "skip"])
        self.assertEqual(result, "create")

        # Test full option name
        mock_input.return_value = "e"
        result = cvelib.wizard._promptWithOptions("Choose", ["create", "edit", "skip"])
        self.assertEqual(result, "edit")

    def test__promptWithOptions_invalid_option(self):
        """Test _promptWithOptions with invalid option selection"""
        with mock.patch("builtins.input") as mock_input, mock.patch(
            "builtins.print"
        ) as mock_print:
            # First input is invalid, second is valid
            mock_input.side_effect = ["invalid", "c"]
            result = cvelib.wizard._promptWithOptions(
                "Choose", ["create", "skip", "abort"]
            )
            self.assertEqual(result, "create")
            mock_print.assert_any_call(
                "Invalid option. Please choose from: [c]reate/[s]kip/[a]bort"
            )

    @mock.patch("subprocess.run")
    def test__runGitCommand_timeout(self, mock_run):
        """Test _runGitCommand with timeout"""
        mock_run.side_effect = subprocess.TimeoutExpired(["git", "status"], 5)
        success, _, stderr = cvelib.wizard._runGitCommand(["git", "status"], ".")
        self.assertFalse(success)
        self.assertEqual(stderr, "Git command timed out")

    @mock.patch("cvelib.wizard._processRepoAlerts")
    def test__runWizard(self, mock_process):
        """Test run_wizard function"""
        # Setup temp directory and config with CVE data directory
        self._setup_temp_config_with_cve_dirs()

        # Setup alerts data
        alerts_data = self._create_sample_alerts_json()

        # Write alerts data to a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(alerts_data, f)
            alerts_file = f.name

        try:
            mock_process.return_value = True  # Continue processing

            # Run wizard with captured output
            with tests.testutil.capturedOutput() as (_, error):
                cvelib.wizard._runWizard(alerts_file, "", "", "")

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())

            # Verify
            mock_process.assert_called_once()

            # Check the call arguments
            call_args = mock_process.call_args[0]
            self.assertEqual(call_args[0], "influxdata")
            self.assertEqual(call_args[1], "granite")
        finally:
            # Clean up the temp file
            os.unlink(alerts_file)

    @mock.patch("cvelib.wizard._processRepoAlerts")
    def test__runWizard_abort_in_loop(self, mock_process_alerts):
        """Test _runWizard when user aborts in main loop"""
        # Make _processRepoAlerts return False (abort)
        mock_process_alerts.return_value = False

        alerts_data = [self._create_test_alert_data()]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(alerts_data, f)
            f.flush()
            temp_file = f.name

        self._setup_temp_config_with_cve_dirs()

        try:
            with tests.testutil.capturedOutput() as (_, error):
                cvelib.wizard._runWizard(temp_file, "", "", "", False)
            # Should complete without error
            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())
        finally:
            os.unlink(temp_file)

    @mock.patch("cvelib.wizard._processRepoAlerts")
    def test__runWizard_comprehensive(self, mock_process):
        """Test run_wizard with comprehensive coverage"""
        # Setup config with CVE data directories
        self._setup_temp_config_with_cve_dirs()

        # Setup mock data
        alerts_data = [
            {
                "repo": "test-repo",
                "org": "test-org",
                "alerts": [{"severity": "high"}],
                "highest_severity": "high",
                "alert_types": ["dependabot"],
                "references": ["https://example.com"],
                "template_urls": [],
            }
        ]

        # Create a temporary JSON file with alerts data
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(alerts_data, f)
            alerts_file = f.name

        try:
            # Test continuing to next repo
            mock_process.return_value = True

            with tests.testutil.capturedOutput() as (_, error):
                cvelib.wizard._runWizard(
                    alerts_file, "default-labels", "priority/", "author"
                )

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())

            mock_process.assert_called_once()
            call_args = mock_process.call_args[0]
            self.assertEqual(call_args[0], "test-org")
            self.assertEqual(call_args[1], "test-repo")
        finally:
            # Clean up the temp file
            os.unlink(alerts_file)

    def test__runWizard_empty_alerts(self):
        """Test _runWizard with empty alerts array"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("[]")
            f.flush()
            temp_file = f.name

        try:
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.wizard._runWizard(temp_file, "", "", "", False)

            # Verify no stderr
            self.assertEqual("", error.getvalue().strip())
            # Verify expected output
            self.assertIn("No alerts found in the JSON file.", output.getvalue())
        finally:
            os.unlink(temp_file)

    def test__runWizard_generic_file_exception(self):
        """Test _runWizard with generic file read exception"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_file = f.name

        # Remove the file to cause read error
        os.unlink(temp_file)

        with tests.testutil.capturedOutput() as (_, error):
            with self.assertRaises(SystemExit):
                cvelib.wizard._runWizard(temp_file, "", "", "", False)

        # For negative test with file error, we expect error output
        self.assertNotEqual("", error.getvalue().strip())

    def test__runWizard_invalid_json(self):
        """Test run_wizard with invalid JSON"""
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="sedg-", suffix=".json", delete=False
        ) as f:
            f.write("invalid json")
            f.flush()
            temp_file = f.name

        try:
            with tests.testutil.capturedOutput() as (_, error):
                with self.assertRaises(SystemExit):
                    cvelib.wizard._runWizard(temp_file, "", "", "")

            # For negative test with invalid JSON, we expect error output
            self.assertNotEqual("", error.getvalue().strip())
        finally:
            os.unlink(temp_file)

    def test__runWizard_missing_config_directory(self):
        """Test _runWizard with missing CVE data directory configuration"""
        # Setup config but don't create CVE data directory structure
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")

        # Create config pointing to non-existent directory
        content = "[Locations]\ncve-data = /nonexistent/path\n"
        self.orig_xdg_config_home, _ = tests.testutil._newConfigFile(
            content, self.tmpdir
        )

        # Clear config cache to force re-reading of our temp config
        cvelib.common.configCache = None

        # Create a temporary JSON file with alerts data
        alerts_data = [
            {
                "org": "test-org",
                "repo": "test-repo",
                "alerts": [
                    {
                        "display_name": "test-package",
                        "severity": "medium",
                        "type": "dependabot",
                        "url": "https://example.com/alert",
                    }
                ],
                "highest_severity": "medium",
                "alert_types": ["dependabot"],
                "references": ["https://example.com/alert"],
            }
        ]

        # Write alerts data to a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(alerts_data, f)
            alerts_file = f.name

        try:
            # Config validation happens early and calls error() which does sys.exit(1)
            with tests.testutil.capturedOutput() as (_, error):
                with self.assertRaises(SystemExit):
                    cvelib.wizard._runWizard(
                        alerts_file,
                        "label1,label2",
                        "security/",
                        "testuser",
                        False,
                    )

            # For negative test with config error, we expect error output
            self.assertNotEqual("", error.getvalue().strip())
        finally:
            # Clean up the temporary file
            os.unlink(alerts_file)

    def test__runWizard_non_dict_in_json(self):
        """Test _runWizard with non-dict objects in JSON array"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            # Write array with non-dict element
            f.write('[{"valid": "dict"}, "not a dict", 123]')
            f.flush()
            temp_file = f.name

        try:
            with tests.testutil.capturedOutput() as (_, error):
                with self.assertRaises(SystemExit):
                    cvelib.wizard._runWizard(temp_file, "", "", "", False)

            # For negative test with invalid data, we expect error output
            self.assertNotEqual("", error.getvalue().strip())
        finally:
            os.unlink(temp_file)

    def test__runWizard_not_array(self):
        """Test run_wizard with non-array JSON"""
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="sedg-", suffix=".json", delete=False
        ) as f:
            f.write('{"not": "an array"}')
            f.flush()
            temp_file = f.name

        try:
            with tests.testutil.capturedOutput() as (_, error):
                with self.assertRaises(SystemExit):
                    cvelib.wizard._runWizard(temp_file, "", "", "")

            # For negative test with wrong JSON structure, we expect error output
            self.assertNotEqual("", error.getvalue().strip())
        finally:
            os.unlink(temp_file)

    @mock.patch("cvelib.wizard.collectCVEData")
    @mock.patch("cvelib.wizard.getConfigCveDataPaths")
    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test__runWizard_collects_existing_ghas_urls(
        self, mock_open_file, mock_get_paths, mock_collect_cve
    ):
        """Test that _runWizard properly collects existing GHAS URLs"""

        # Mock CVE data paths (getConfigCveDataPaths returns a dict)
        mock_get_paths.return_value = {
            "active": "/path/to/cve-data/active",
            "retired": "/path/to/cve-data/retired",
            "ignored": "/path/to/cve-data/ignored",
            "templates": "/path/to/cve-data/templates",
        }

        # Create mock CVE objects with GHAS entries
        mock_cve1 = mock.Mock()
        mock_cve1.fn = "/path/to/CVE-2024-0001"
        mock_ghas1 = mock.Mock()
        mock_ghas1.url = "https://github.com/org/repo/security/dependabot/1"
        mock_cve1.ghas = [mock_ghas1]

        mock_cve2 = mock.Mock()
        mock_cve2.fn = "/path/to/CVE-2024-0002"
        mock_ghas2 = mock.Mock()
        mock_ghas2.url = "https://github.com/org/repo/security/secret-scanning/1"
        mock_cve2.ghas = [mock_ghas2]

        # CVE without GHAS
        mock_cve3 = mock.Mock()
        mock_cve3.fn = "/path/to/CVE-2024-0003"
        mock_cve3.ghas = []

        mock_collect_cve.return_value = [mock_cve1, mock_cve2, mock_cve3]

        # Mock JSON file content
        alerts_json = json.dumps(
            [
                {
                    "org": "test-org",
                    "repo": "test-repo",
                    "alerts": [
                        {
                            "display_name": "test-package",
                            "severity": "high",
                            "type": "dependabot",
                            "url": "https://github.com/test-org/test-repo/security/dependabot/99",
                        }
                    ],
                }
            ]
        )
        mock_open_file.return_value.read.return_value = alerts_json

        # Mock os.path.isdir to return True
        with mock.patch("os.path.isdir", return_value=True), mock.patch(
            "cvelib.wizard._groupAlertsByRepo"
        ) as mock_group, mock.patch("cvelib.wizard._processRepoAlerts") as mock_process:

            # Mock grouping function
            mock_group.return_value = {
                "test-org/test-repo": {
                    "org": "test-org",
                    "repo": "test-repo",
                    "alerts": [],
                }
            }

            # Mock process function to return True
            mock_process.return_value = True

            # Run the wizard with captured output
            with tests.testutil.capturedOutput() as (_, error):
                cvelib.wizard._runWizard("test.json", "", "", "", False)

            # Verify no stderr in positive test
            self.assertEqual("", error.getvalue().strip())

            # Verify collectCVEData was called with correct parameters
            mock_collect_cve.assert_called_once_with(
                {
                    "active": "/path/to/cve-data/active",
                    "retired": "/path/to/cve-data/retired",
                    "ignored": "/path/to/cve-data/ignored",
                    "templates": "/path/to/cve-data/templates",
                },
                compatUbuntu=False,
                untriagedOk=True,
            )

            # Verify _processRepoAlerts was called with existing_ghas_urls
            mock_process.assert_called_once()
            call_args = mock_process.call_args[0]
            existing_urls = call_args[7]  # 8th argument (0-indexed)

            # Verify the existing URLs were collected correctly
            self.assertEqual(len(existing_urls), 2)
            self.assertIn(
                "https://github.com/org/repo/security/dependabot/1", existing_urls
            )
            self.assertIn(
                "https://github.com/org/repo/security/secret-scanning/1", existing_urls
            )
            self.assertEqual(
                existing_urls["https://github.com/org/repo/security/dependabot/1"],
                "/path/to/CVE-2024-0001",
            )
            self.assertEqual(
                existing_urls["https://github.com/org/repo/security/secret-scanning/1"],
                "/path/to/CVE-2024-0002",
            )

    def test__runWizard_collectCVEData_exception(self):
        """Test _runWizard when collectCVEData raises exception"""
        # Setup temp directory and config
        self._setup_temp_config_with_cve_dirs()

        # Create test alerts data
        alerts_data = [self._create_test_alert_data()]

        # Write alerts data to a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(alerts_data, f)
            alerts_file = f.name

        try:
            with mock.patch("cvelib.wizard.collectCVEData") as mock_collect:
                # Make collectCVEData raise an exception
                mock_collect.side_effect = Exception("Failed to read CVE data")

                with mock.patch("cvelib.wizard._processRepoAlerts") as mock_process:
                    mock_process.return_value = True

                    # Mock warn to verify it's called with the right message
                    with mock.patch("cvelib.wizard.warn") as mock_warn:
                        # Run wizard - should continue despite exception
                        with tests.testutil.capturedOutput() as (_, error):
                            cvelib.wizard._runWizard(alerts_file, "", "", "")

                        self.assertEqual("", error.getvalue().strip())

                        # Verify no stdout output in this test
                        # The warning is handled by the mocked warn function

                        # Check that warn was called
                        mock_warn.assert_called_once()
                        warning_msg = mock_warn.call_args[0][0]
                        self.assertIn(
                            "Failed to collect existing GHAS URLs", warning_msg
                        )
                        self.assertIn("Failed to read CVE data", warning_msg)

                    # Should have called _processRepoAlerts with empty existing_ghas_urls
                    mock_process.assert_called_once()
                    call_args = mock_process.call_args[0]
                    existing_urls = call_args[7]  # 8th argument (0-indexed)
                    self.assertEqual(existing_urls, {})
        finally:
            os.unlink(alerts_file)

    def test__parseOrgRepoInput_invalid_format(self):
        """Test _parseOrgRepoInput with invalid formats"""
        # Test with leading slash
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("/invalid/format", "default-org")
        self.assertIn(
            "No leading, trailing, or multiple forward slashes", str(cm.exception)
        )

        # Test with trailing slash
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("invalid/format/", "default-org")
        self.assertIn(
            "No leading, trailing, or multiple forward slashes", str(cm.exception)
        )

        # Test with double slash
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("invalid//format", "default-org")
        self.assertIn(
            "No leading, trailing, or multiple forward slashes", str(cm.exception)
        )

        # Test with multiple slashes (more than 2 parts)
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("org/repo/extra", "default-org")
        self.assertIn(
            "Invalid format. Use 'org/repo' or just 'repo'", str(cm.exception)
        )

        # Test with too short response
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("e", "default-org")
        self.assertIn(
            "when specified, must be longer than 1 character", str(cm.exception)
        )

    def test__parseOrgRepoInput_invalid_org_validation(self):
        """Test _parseOrgRepoInput with invalid org (pkg-where pattern)"""
        # Test org with uppercase letters (not allowed in pkg-where)
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("INVALID-ORG/repo", "default-org")
        self.assertIn("org must match format:", str(cm.exception))
        # Test org with underscore (not allowed in pkg-where)
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("invalid_org/repo", "default-org")
        self.assertIn("org must match format:", str(cm.exception))
        # Test org with special characters
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("org@name/repo", "default-org")
        self.assertIn("org must match format:", str(cm.exception))
        # Test org that's too long (>40 chars for pkg-where)
        long_org = "a" * 41  # 41 chars, exceeds pkg-where limit
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput(f"{long_org}/repo", "default-org")
        self.assertIn("org must match format:", str(cm.exception))

    def test__parseOrgRepoInput_invalid_repo_validation(self):
        """Test _parseOrgRepoInput with invalid repo (pkg-software pattern)"""
        # Test repo with special characters not allowed in pkg-software
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("org/repo@name", "default-org")
        self.assertIn("repo must match format:", str(cm.exception))
        # Test repo with spaces
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput("org/repo name", "default-org")
        self.assertIn("repo must match format:", str(cm.exception))
        # Test with a repo name that's too long (>50 chars for pkg-software)
        long_repo = "a" * 51  # 51 chars, exceeds pkg-software limit
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._parseOrgRepoInput(f"org/{long_repo}", "default-org")
        self.assertIn("repo must match format:", str(cm.exception))

    def test__processOrgRepoInput_value_error_propagation(self):
        """Test _processOrgRepoInput propagates ValueError from _parseOrgRepoInput"""
        # Test that ValueError from _parseOrgRepoInput is propagated
        with self.assertRaises(ValueError) as cm:
            cvelib.wizard._processOrgRepoInput(
                "//invalid//", "test-org", "issue-org", "issue-repo"
            )
        self.assertIn(
            "No leading, trailing, or multiple forward slashes", str(cm.exception)
        )

    def test__processRepoGHIssue_invalid_org_repo_input(self):
        """Test _processRepoGHIssue with invalid org/repo input"""
        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        alerts = [self._create_test_alert()]

        # Simulate user inputs with invalid org/repo format, then valid
        with self._mock_user_input_sequence(
            [
                "//invalid//",  # Invalid org/repo format
                "test-org/test-repo",  # Valid org/repo
                "test-repo",  # Summary
                "s",  # Skip
            ]
        ):
            with tests.testutil.capturedOutput() as (output, error):
                continue_processing, issue_data = cvelib.wizard._processRepoGHIssue(
                    "test-org", "test-repo", alerts, "", "", False
                )

                # Verify no stderr in positive test
                self.assertEqual("", error.getvalue().strip())
                self.assertTrue(continue_processing)
                self.assertIsNone(issue_data)
                # Check that error was printed
                self.assertIn(
                    "ERROR: Invalid format. No leading, trailing, or multiple forward slashes allowed.",
                    output.getvalue(),
                )

    def test__updateDescriptionForCustomPriority_different_priority(self):
        """Test updateDescriptionForCustomPriority when custom priority differs"""
        issue_description = """The following alert was issued:
- [ ] [test-package](url) (medium)

References:
 * link1
 * link2"""

        result = cvelib.wizard._updateDescriptionForCustomPriority(
            issue_description,
            "high",  # custom_priority
            "medium",  # highest_severity
            "security/",  # gh_priority_prefix
            False,  # description_manually_edited
            "default_desc",  # default_description
        )

        self.assertIn("Adding the 'security/high' label due to FILL ME IN", result)
        self.assertIn("References:", result)

    def test__updateDescriptionForCustomPriority_manually_edited(self):
        """Test updateDescriptionForCustomPriority when description was manually edited"""
        issue_description = "manually edited description"

        result = cvelib.wizard._updateDescriptionForCustomPriority(
            issue_description,
            "high",  # custom_priority
            "medium",  # highest_severity (different)
            "security/",  # gh_priority_prefix
            True,  # description_manually_edited (should preserve)
            "default_desc",  # default_description
        )

        # Should preserve manually edited description unchanged
        self.assertEqual(result, "manually edited description")

    def test__updateDescriptionForCustomPriority_same_priority(self):
        """Test updateDescriptionForCustomPriority when custom priority matches calculated"""
        issue_description = "modified description"

        result = cvelib.wizard._updateDescriptionForCustomPriority(
            issue_description,
            "medium",  # custom_priority
            "medium",  # highest_severity (same)
            "security/",  # gh_priority_prefix
            False,  # description_manually_edited
            "default_desc",  # default_description
        )

        # Should restore default description when priority matches and not manually edited
        self.assertEqual(result, "default_desc")

    @mock.patch("cvelib.wizard._isGhCliAvailable")
    @mock.patch("cvelib.wizard._promptWithOptions")
    @mock.patch("cvelib.wizard._promptWithDefault")
    @mock.patch("builtins.input")
    def test_gh_disable_cli_forces_manual_creation(
        self, mock_input, mock_prompt_default, mock_prompt_options, mock_gh_available
    ):
        """Test that --gh-disable-cli forces manual creation even when gh CLI is available"""
        # Setup mocks
        mock_prompt_default.side_effect = [
            "test-org/test-repo",
            "test-repo",
        ]  # org/repo, summary
        mock_prompt_options.side_effect = [
            "create",  # First action: create GitHub issue
            "create",  # CVE action: create
        ]

        # Mock manual issue number input
        mock_input.side_effect = ["123"]  # Manual issue number

        # Mock that gh CLI is available but disabled
        mock_gh_available.return_value = True

        # Setup temporary directory and config with CVE dirs
        self._setup_temp_config_with_cve_dirs()

        # Don't mock builtins.open as we need real config file reading
        # Only patch the specific file operations we don't want to actually perform

        alerts_data = {
            "alerts": [
                {
                    "display_name": "test-package",
                    "severity": "medium",
                    "type": "dependabot",
                    "url": "https://example.com/alert",
                }
            ]
        }

        with tests.testutil.capturedOutput() as (_, error):
            result = cvelib.wizard._processRepoAlerts(
                "test-org",
                "test-repo",
                alerts_data,
                "",
                "",
                "",
                True,
                None,
                cvelib.common.getConfigCveDataPaths(),
            )
            self.assertTrue(result)

        # Verify no stderr in positive test
        self.assertEqual("", error.getvalue().strip())
        # Verify gh CLI was not used (manual creation was forced)
        mock_input.assert_called_once()  # Manual issue number was prompted

    @mock.patch("cvelib.wizard._runWizard")
    def test_main_cve_add_wizard(self, mock_run_wizard):
        """Test main_cve_add_wizard function"""
        # Create a temp file
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="sedg-", suffix=".json", delete=False
        ) as f:
            f.write("[]")
            f.flush()
            temp_file = f.name

        try:
            # Mock sys.argv and set experimental environment variable
            with mock.patch("sys.argv", ["cve-add-wizard", "gh", temp_file]):
                with mock.patch.dict("os.environ", {"SEDG_EXPERIMENTAL": "1"}):
                    cvelib.wizard.main_cve_add_wizard()

            mock_run_wizard.assert_called_once_with(temp_file, "", "", "", False)
        finally:
            os.unlink(temp_file)

    def test_main_cve_add_wizard_as_main(self):
        """Test main_cve_add_wizard when run as __main__"""
        with self._mock_wizard_command(["gh", "--help"]):
            with mock.patch("cvelib.wizard.__name__", "__main__"):
                with tests.testutil.capturedOutput() as (_, error):
                    with self.assertRaises(SystemExit) as cm:
                        cvelib.wizard.main_cve_add_wizard()
                    # Should exit with 0 for help
                    self.assertEqual(cm.exception.code, 0)
                # Help output should go to stdout, not stderr
                self.assertEqual("", error.getvalue().strip())

    def test_main_cve_add_wizard_experimental_check(self):
        """Test main_cve_add_wizard requires SEDG_EXPERIMENTAL=1"""
        # Test without SEDG_EXPERIMENTAL environment variable
        with mock.patch("sys.argv", ["cve-add-wizard", "sample.json"]):
            with mock.patch.dict("os.environ", {}, clear=True):
                with tests.testutil.capturedOutput() as (_, error):
                    with self.assertRaises(SystemExit):
                        cvelib.wizard.main_cve_add_wizard()
                    # Should have error message about experimental functionality
                    self.assertIn(
                        "ERROR: This functionality is experimental", error.getvalue()
                    )

        # Test with SEDG_EXPERIMENTAL=1 (should proceed past experimental check)
        with mock.patch("sys.argv", ["cve-add-wizard", "gh", "/nonexistent/file.json"]):
            with mock.patch.dict("os.environ", {"SEDG_EXPERIMENTAL": "1"}):
                with tests.testutil.capturedOutput() as (_, error):
                    with self.assertRaises(
                        SystemExit
                    ):  # Should fail on file not found, not experimental check
                        cvelib.wizard.main_cve_add_wizard()
                    # Should NOT have experimental error (we're ignoring file not found error)
                    self.assertNotIn(
                        "ERROR: This functionality is experimental", error.getvalue()
                    )

    def test_main_cve_add_wizard_file_not_found(self):
        """Test main_cve_add_wizard with non-existent file"""
        with self._mock_wizard_command(["gh", "/nonexistent/file.json"]):
            with tests.testutil.capturedOutput() as (_, error):
                with self.assertRaises(SystemExit):
                    cvelib.wizard.main_cve_add_wizard()
                # Should have error message about file not found
                self.assertIn(
                    "ERROR: File not found: /nonexistent/file.json", error.getvalue()
                )

    def test_main_cve_add_wizard_invalid_author(self):
        """Test main_cve_add_wizard with invalid author format"""
        with self._mock_wizard_command(
            ["gh", "--author", "invalid@author", "file.json"]
        ):
            with tests.testutil.capturedOutput() as (_, error):
                with self.assertRaises(SystemExit):
                    cvelib.wizard.main_cve_add_wizard()
                # Should have error message about invalid author format
                self.assertIn("ERROR: --author must match format", error.getvalue())

    def test_main_cve_add_wizard_invalid_priority_prefix(self):
        """Test main_cve_add_wizard with comma in priority prefix"""
        with self._mock_wizard_command(
            ["gh", "--priority-prefix", "security,label", "file.json"]
        ):
            with tests.testutil.capturedOutput() as (_, error):
                with self.assertRaises(SystemExit):
                    cvelib.wizard.main_cve_add_wizard()
                # Should have error message about comma in priority prefix
                self.assertIn(
                    "ERROR: --priority-prefix cannot contain commas", error.getvalue()
                )

    def test_main_cve_add_wizard_no_subcommand(self):
        """Test main_cve_add_wizard prints help when no subcommand"""
        with mock.patch("sys.argv", ["cve-add-wizard"]), mock.patch.dict(
            "os.environ", {"SEDG_EXPERIMENTAL": "1"}
        ):
            with mock.patch("argparse.ArgumentParser.print_help") as mock_help:
                cvelib.wizard.main_cve_add_wizard()
                mock_help.assert_called_once()

    def test_main_entry_point(self):
        """Test the main entry point when called as script"""
        # Test that the main block exists and calls the right function
        # We can't easily test the actual execution, but we can test the module structure
        self.assertTrue(hasattr(cvelib.wizard, "main_cve_add_wizard"))
