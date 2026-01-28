#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

"""Tests for cvelib/rfc5322.py"""

import unittest
import cvelib.rfc5322


class TestRfc5322(unittest.TestCase):
    """Tests for RFC5322 parser"""

    #
    # Basic parsing tests
    #
    def test_parseHeaders_empty(self):
        """Test parseHeaders() with empty input"""
        self.assertEqual({}, cvelib.rfc5322.parseHeaders(""))

    def test_parseHeaders_single_header(self):
        """Test parseHeaders() with single header"""
        self.assertEqual(
            {"Key": "value"},
            cvelib.rfc5322.parseHeaders("Key: value\n"),
        )

    def test_parseHeaders_single_header_no_trailing_newline(self):
        """Test parseHeaders() with single header without trailing newline"""
        self.assertEqual(
            {"Key": "value"},
            cvelib.rfc5322.parseHeaders("Key: value"),
        )

    def test_parseHeaders_multiple_headers(self):
        """Test parseHeaders() with multiple headers"""
        self.assertEqual(
            {"Key1": "value1", "Key2": "value2"},
            cvelib.rfc5322.parseHeaders("Key1: value1\nKey2: value2\n"),
        )

    def test_parseHeaders_empty_value(self):
        """Test parseHeaders() with empty value"""
        self.assertEqual(
            {"Key": ""},
            cvelib.rfc5322.parseHeaders("Key:\n"),
        )

    #
    # Multiline value tests
    #
    def test_parseHeaders_multiline_single_continuation(self):
        """Test parseHeaders() with single continuation line"""
        self.assertEqual(
            {"Key": "\n value"},
            cvelib.rfc5322.parseHeaders("Key:\n value\n"),
        )

    def test_parseHeaders_multiline_multiple_continuations(self):
        """Test parseHeaders() with multiple continuation lines"""
        self.assertEqual(
            {"Key": "\n value1\n value2"},
            cvelib.rfc5322.parseHeaders("Key:\n value1\n value2\n"),
        )

    def test_parseHeaders_multiline_tab_continuation(self):
        """Test parseHeaders() with tab continuation"""
        self.assertEqual(
            {"Key": "\n\tvalue"},
            cvelib.rfc5322.parseHeaders("Key:\n\tvalue\n"),
        )

    def test_parseHeaders_multiline_mixed_continuation(self):
        """Test parseHeaders() with mixed space and tab continuation"""
        self.assertEqual(
            {"Key": "\n value1\n\tvalue2"},
            cvelib.rfc5322.parseHeaders("Key:\n value1\n\tvalue2\n"),
        )

    def test_parseHeaders_mixed_single_and_multiline(self):
        """Test parseHeaders() with mixed single and multiline headers"""
        self.assertEqual(
            {"Key1": "value1", "Key2": "\n line1\n line2", "Key3": "value3"},
            cvelib.rfc5322.parseHeaders(
                "Key1: value1\nKey2:\n line1\n line2\nKey3: value3\n"
            ),
        )

    #
    # Stanza tests
    #
    def test_parseHeaders_multiple_stanzas(self):
        """Test parseHeaders() with multiple stanzas (separated by blank lines)"""
        self.assertEqual(
            {"Key1": "value1", "Key2": "value2"},
            cvelib.rfc5322.parseHeaders("Key1: value1\n\nKey2: value2\n"),
        )

    def test_parseHeaders_multiple_blank_lines(self):
        """Test parseHeaders() with multiple consecutive blank lines"""
        self.assertEqual(
            {"Key1": "value1", "Key2": "value2"},
            cvelib.rfc5322.parseHeaders("Key1: value1\n\n\n\nKey2: value2\n"),
        )

    def test_parseHeaders_stanza_with_multiline(self):
        """Test parseHeaders() with stanzas containing multiline values"""
        self.assertEqual(
            {"Key1": "value1", "Key2": "\n line1\n line2", "Key3": "value3"},
            cvelib.rfc5322.parseHeaders(
                "Key1: value1\n\nKey2:\n line1\n line2\n\nKey3: value3\n"
            ),
        )

    #
    # Colon handling tests
    #
    def test_parseHeaders_colon_in_value(self):
        """Test parseHeaders() with colon in value"""
        self.assertEqual(
            {"URL": "https://example.com/path"},
            cvelib.rfc5322.parseHeaders("URL: https://example.com/path\n"),
        )

    def test_parseHeaders_multiple_colons_in_value(self):
        """Test parseHeaders() with multiple colons in value"""
        self.assertEqual(
            {"Time": "12:30:45"},
            cvelib.rfc5322.parseHeaders("Time: 12:30:45\n"),
        )

    def test_parseHeaders_colon_in_continuation(self):
        """Test parseHeaders() with colon in continuation line"""
        self.assertEqual(
            {"URLs": "\n https://example.com:8080\n https://other.com:443"},
            cvelib.rfc5322.parseHeaders(
                "URLs:\n https://example.com:8080\n https://other.com:443\n"
            ),
        )

    #
    # Line ending tests
    #
    def test_parseHeaders_crlf(self):
        """Test parseHeaders() with Windows line endings (CRLF)"""
        self.assertEqual(
            {"Key1": "value1", "Key2": "value2"},
            cvelib.rfc5322.parseHeaders("Key1: value1\r\nKey2: value2\r\n"),
        )

    def test_parseHeaders_cr_only(self):
        """Test parseHeaders() with old Mac line endings (CR only)"""
        self.assertEqual(
            {"Key1": "value1", "Key2": "value2"},
            cvelib.rfc5322.parseHeaders("Key1: value1\rKey2: value2\r"),
        )

    def test_parseHeaders_mixed_line_endings(self):
        """Test parseHeaders() with mixed line endings"""
        self.assertEqual(
            {"Key1": "value1", "Key2": "value2", "Key3": "value3"},
            cvelib.rfc5322.parseHeaders("Key1: value1\nKey2: value2\r\nKey3: value3\r"),
        )

    #
    # Invalid key tests
    #
    def test_parseHeaders_key_with_space(self):
        """Test parseHeaders() raises on keys containing spaces"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("Key With Space: value\n")
        self.assertEqual("invalid key: 'Key With Space'", ctx.exception.value)

    def test_parseHeaders_key_with_tab(self):
        """Test parseHeaders() raises on keys containing tabs"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("Key\tTab: value\n")
        self.assertEqual("invalid key: 'Key\tTab'", ctx.exception.value)

    def test_parseHeaders_key_starting_with_number(self):
        """Test parseHeaders() raises on keys starting with number"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("1Key: value\n")
        self.assertEqual("invalid key: '1Key'", ctx.exception.value)

    def test_parseHeaders_key_with_special_chars(self):
        """Test parseHeaders() raises on keys with special characters"""
        # Note: # is allowed at start of key for commented-out headers (e.g., #Patches_PKG)
        for char in ["!", "@", "$", "%", "^", "&", "*", "(", ")", "=", "+"]:
            with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
                cvelib.rfc5322.parseHeaders("Key%s: value\n" % char)
            self.assertEqual(
                "invalid key: 'Key%s'" % char,
                ctx.exception.value,
                "Key with '%s' should raise" % char,
            )

    def test_parseHeaders_key_with_hash_prefix(self):
        """Test parseHeaders() accepts keys with # prefix (commented-out headers)"""
        # CVE format uses #Key: for commented headers, email.parser accepts these
        self.assertEqual(
            {"#Patches_PKG": "", "#upstream_PKG": ""},
            cvelib.rfc5322.parseHeaders("#Patches_PKG:\n#upstream_PKG:\n"),
        )

    def test_parseHeaders_empty_key(self):
        """Test parseHeaders() raises on lines starting with colon (empty key)"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders(": value\n")
        self.assertEqual("empty key (line starts with ':')", ctx.exception.value)

    def test_parseHeaders_key_with_null_byte(self):
        """Test parseHeaders() raises on keys containing null bytes"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("Key\x00Name: value\n")
        self.assertEqual("invalid key: 'Key\x00Name'", ctx.exception.value)

    def test_parseHeaders_key_with_unicode(self):
        """Test parseHeaders() raises on keys containing non-ASCII characters"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("Clave\u00f1o: value\n")
        self.assertEqual("invalid key: 'Clave\u00f1o'", ctx.exception.value)

    def test_parseHeaders_key_with_emoji(self):
        """Test parseHeaders() raises on keys containing emoji"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("\U0001f600: value\n")
        self.assertEqual("invalid key: '\U0001f600'", ctx.exception.value)

    def test_parseHeaders_valid_keys_with_hyphen_underscore(self):
        """Test parseHeaders() accepts keys with hyphens and underscores"""
        self.assertEqual(
            {"Key-Name": "value1", "Key_Name": "value2"},
            cvelib.rfc5322.parseHeaders("Key-Name: value1\nKey_Name: value2\n"),
        )

    def test_parseHeaders_valid_key_with_numbers(self):
        """Test parseHeaders() accepts keys with numbers (not at start)"""
        self.assertEqual(
            {"Key123": "value", "Key1-Name2": "value2"},
            cvelib.rfc5322.parseHeaders("Key123: value\nKey1-Name2: value2\n"),
        )

    def test_parseHeaders_valid_key_with_slash(self):
        """Test parseHeaders() accepts keys with forward slashes"""
        self.assertEqual(
            {"git/org_foo": "pending", "snap/pub_pkg": "needed"},
            cvelib.rfc5322.parseHeaders("git/org_foo: pending\nsnap/pub_pkg: needed\n"),
        )

    #
    # Invalid line tests
    #
    def test_parseHeaders_line_without_colon_raises(self):
        """Test parseHeaders() - line without colon raises exception"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("Key1: value1\nrandom text\nKey2: value2\n")
        self.assertEqual("line without colon: 'random text'", ctx.exception.value)

    def test_parseHeaders_orphan_continuation_raises(self):
        """Test parseHeaders() raises on continuation lines before any header"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders(" orphan line\nKey: value\n")
        self.assertEqual(
            "continuation line without preceding header: ' orphan line'",
            ctx.exception.value,
        )

    def test_parseHeaders_only_continuation_lines(self):
        """Test parseHeaders() raises with only continuation lines"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders(" line1\n line2\n")
        self.assertEqual(
            "continuation line without preceding header: ' line1'",
            ctx.exception.value,
        )

    #
    # Duplicate key tests
    #
    def test_parseHeaders_duplicate_keys_last_wins(self):
        """Test parseHeaders() with duplicate keys - last value wins"""
        self.assertEqual(
            {"Key": "second"},
            cvelib.rfc5322.parseHeaders("Key: first\nKey: second\n"),
        )

    def test_parseHeaders_duplicate_keys_warns(self):
        """Test parseHeaders() warns on duplicate keys"""
        warnings = []
        cvelib.rfc5322.parseHeaders(
            "Key: first\nKey: second\n",
            warnFn=lambda msg: warnings.append(msg),
        )
        self.assertEqual(1, len(warnings))
        self.assertIn("duplicate key 'Key'", warnings[0])

    def test_parseHeaders_duplicate_keys_across_stanzas(self):
        """Test parseHeaders() detects duplicates across stanzas"""
        warnings = []
        result = cvelib.rfc5322.parseHeaders(
            "Key: first\n\nKey: second\n",
            warnFn=lambda msg: warnings.append(msg),
        )
        self.assertEqual({"Key": "second"}, result)
        self.assertEqual(1, len(warnings))

    def test_parseHeaders_missing_space_after_colon_warns(self):
        """Test parseHeaders() warns when no space after colon"""
        warnings = []
        result = cvelib.rfc5322.parseHeaders(
            "Key:value\n",
            warnFn=lambda msg: warnings.append(msg),
        )
        self.assertEqual({"Key": "value"}, result)
        self.assertEqual(1, len(warnings))
        self.assertIn("missing space after colon for key 'Key'", warnings[0])

    def test_parseHeaders_missing_space_after_colon_no_warn_for_empty(self):
        """Test parseHeaders() does not warn for empty values"""
        warnings = []
        result = cvelib.rfc5322.parseHeaders(
            "Key:\n",
            warnFn=lambda msg: warnings.append(msg),
        )
        self.assertEqual({"Key": ""}, result)
        self.assertEqual(0, len(warnings))

    #
    # Value content tests
    #
    def test_parseHeaders_value_with_unicode(self):
        """Test parseHeaders() preserves unicode in values"""
        self.assertEqual(
            {"Key": "hello \u4e16\u754c \U0001f389"},
            cvelib.rfc5322.parseHeaders("Key: hello \u4e16\u754c \U0001f389\n"),
        )

    def test_parseHeaders_value_with_special_chars(self):
        """Test parseHeaders() preserves special characters in values"""
        self.assertEqual(
            {"Key": "!@#$%^&*()=+[]{}|;',.<>?"},
            cvelib.rfc5322.parseHeaders("Key: !@#$%^&*()=+[]{}|;',.<>?\n"),
        )

    def test_parseHeaders_value_with_quotes(self):
        """Test parseHeaders() preserves quotes in values"""
        self.assertEqual(
            {"Key": "single ' and double \""},
            cvelib.rfc5322.parseHeaders("Key: single ' and double \"\n"),
        )

    def test_parseHeaders_value_with_backslash(self):
        """Test parseHeaders() preserves backslashes in values"""
        self.assertEqual(
            {"Key": "path\\to\\file"},
            cvelib.rfc5322.parseHeaders("Key: path\\to\\file\n"),
        )

    def test_parseHeaders_value_leading_whitespace_stripped(self):
        """Test parseHeaders() strips leading whitespace from value after colon"""
        self.assertEqual(
            {"Key": "value"},
            cvelib.rfc5322.parseHeaders("Key:   value\n"),
        )

    def test_parseHeaders_value_trailing_whitespace_preserved(self):
        """Test parseHeaders() preserves trailing whitespace in value"""
        self.assertEqual(
            {"Key": "value   "},
            cvelib.rfc5322.parseHeaders("Key: value   \n"),
        )

    #
    # Security/DoS prevention tests
    #
    def test_parseHeaders_very_long_line(self):
        """Test parseHeaders() rejects lines exceeding maximum length"""
        long_value = "x" * (cvelib.rfc5322.MAX_LINE_LENGTH + 1)
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("Key: %s\n" % long_value)
        self.assertIn("exceeds maximum length", str(ctx.exception))

    def test_parseHeaders_very_long_key(self):
        """Test parseHeaders() raises on keys exceeding maximum length"""
        long_key = "K" + "e" * cvelib.rfc5322.MAX_KEY_LENGTH
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("%s: value\n" % long_key)
        self.assertTrue(ctx.exception.value.startswith("key exceeds maximum length:"))

    def test_parseHeaders_very_long_value_across_continuations(self):
        """Test parseHeaders() rejects values exceeding maximum length"""
        # Create a value that exceeds limit across multiple continuation lines
        line = " " + "x" * 1000 + "\n"
        lines_needed = (cvelib.rfc5322.MAX_VALUE_LENGTH // 1000) + 10
        content = "Key:\n" + line * lines_needed
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders(content)
        self.assertIn("exceeds maximum length", str(ctx.exception))

    def test_parseHeaders_too_many_lines(self):
        """Test parseHeaders() rejects content with too many lines"""
        content = "Key: value\n" * (cvelib.rfc5322.MAX_LINES + 1)
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders(content)
        self.assertIn("exceeds maximum line count", str(ctx.exception))

    def test_parseHeaders_null_bytes_in_value(self):
        """Test parseHeaders() handles null bytes in values"""
        # Null bytes in values should be preserved (caller can validate)
        result = cvelib.rfc5322.parseHeaders("Key: val\x00ue\n")
        self.assertEqual({"Key": "val\x00ue"}, result)

    def test_parseHeaders_control_chars_in_value(self):
        """Test parseHeaders() handles control characters in values"""
        # Control chars in values should be preserved (caller can validate)
        result = cvelib.rfc5322.parseHeaders("Key: val\x01\x02\x03ue\n")
        self.assertEqual({"Key": "val\x01\x02\x03ue"}, result)

    #
    # Whitespace handling tests
    #
    def test_parseHeaders_only_whitespace_content(self):
        """Test parseHeaders() raises with content that is only whitespace"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("   \n\t\n  \n")
        self.assertEqual(
            "continuation line without preceding header: '   '",
            ctx.exception.value,
        )

    def test_parseHeaders_only_newlines(self):
        """Test parseHeaders() raises with content that is only newlines"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("\n\n\n")
        self.assertEqual("leading blank line", ctx.exception.value)

    def test_parseHeaders_leading_blank_lines(self):
        """Test parseHeaders() raises on leading blank lines"""
        with self.assertRaises(cvelib.rfc5322.Rfc5322Exception) as ctx:
            cvelib.rfc5322.parseHeaders("\n\n\nKey: value\n")
        self.assertEqual("leading blank line", ctx.exception.value)

    def test_parseHeaders_trailing_blank_lines(self):
        """Test parseHeaders() with trailing blank lines"""
        self.assertEqual(
            {"Key": "value"},
            cvelib.rfc5322.parseHeaders("Key: value\n\n\n"),
        )

    #
    # Real-world CVE format tests
    #
    def test_parseHeaders_cve_format(self):
        """Test parseHeaders() with realistic CVE file format"""
        content = """Candidate: CVE-2024-0001
OpenDate: 2024-01-01
CloseDate:
PublicDate: 2024-01-15
References:
 https://www.cve.org/CVERecord?id=CVE-2024-0001
 https://example.com/advisory
Description:
 A vulnerability was found in Example Software.
 This allows remote attackers to cause a denial of service.
Notes:
 jdoe> Affects versions 1.0 through 2.5
 jdoe> Fixed in version 2.6
Priority: high
"""
        result = cvelib.rfc5322.parseHeaders(content)
        self.assertEqual("CVE-2024-0001", result["Candidate"])
        self.assertEqual("2024-01-01", result["OpenDate"])
        self.assertEqual("", result["CloseDate"])
        self.assertEqual("2024-01-15", result["PublicDate"])
        self.assertTrue(result["References"].startswith("\n"))
        self.assertIn(
            "https://www.cve.org/CVERecord?id=CVE-2024-0001", result["References"]
        )
        self.assertTrue(result["Description"].startswith("\n"))
        self.assertIn("denial of service", result["Description"])
        self.assertTrue(result["Notes"].startswith("\n"))
        self.assertEqual("high", result["Priority"])


if __name__ == "__main__":
    unittest.main()
