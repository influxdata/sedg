#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

"""RFC5322-style header parser.

This module provides a simple parser for RFC5322-style headers (the format
used in email headers). Historically, sedg used the email.parser module but
to avoid Python version-specific behavior changes in how multiline header
values are parsed, we now implement our own parser.
"""

import re
from typing import Callable, Dict, List, Optional

# RFC5322 field name: printable ASCII except colon and space
# We extend this to allow characters commonly used in this codebase:
# - hyphens (e.g., "Discovered-by")
# - underscores (e.g., "git_pkg1")
# - forward slashes (e.g., "git/org_foo", "snap/pub_pkg2")
# - dots (e.g., "oci/gar-us.proj_pkg1")
# - hash/pound at start (e.g., "#Patches_PKG:" for commented-out headers)
#
# Notes:
# - email.parser accepts these, downstream validation rejects invalid keys
# - RFC5322 has a concept of an email body, but the Cve format only uses
#   headers, so anything that looks like a body will raise an error.
_VALID_KEY_PATTERN = re.compile(r"^#?[A-Za-z][A-Za-z0-9_./-]*$")

# Maximum limits to prevent DoS
MAX_LINE_LENGTH = 65536
MAX_LINES = 100000
MAX_KEY_LENGTH = 256
MAX_VALUE_LENGTH = 1048576  # 1MB


class Rfc5322Exception(Exception):
    """This class represents RFC5322 parsing exceptions"""

    def __init__(self, value: str) -> None:
        self.value = value


def parseHeaders(
    content: str,
    warnFn: Optional[Callable[[str], None]] = None,
) -> Dict[str, str]:
    """Parse RFC5322-style headers.

    Args:
        content: The content to parse
        warnFn: Optional callback for warnings (e.g., duplicate keys)

    Returns:
        Dictionary mapping header names to values. For multiline values
        (continuation lines starting with space/tab), the value is prefixed
        with a newline character.

    Raises:
        Rfc5322Exception: If content exceeds safety limits or contains
            malformed lines (lines without colons that aren't continuations)
    """
    result: Dict[str, str] = {}
    current_key: Optional[str] = None
    current_lines: List[str] = []
    is_multiline: bool = False

    def save_current() -> None:
        nonlocal current_key, current_lines, is_multiline
        if current_key:
            if is_multiline:
                val = "\n" + "\n".join(current_lines)
            else:
                val = current_lines[0] if current_lines else ""
            # Check value length limit
            if len(val) > MAX_VALUE_LENGTH:
                raise Rfc5322Exception(
                    "value for '%s' exceeds maximum length" % current_key
                )
            if current_key in result:
                if warnFn:
                    warnFn("duplicate key '%s'" % current_key)
            result[current_key] = val
        current_key = None
        current_lines = []
        is_multiline = False

    # Normalize line endings (CRLF -> LF)
    content = content.replace("\r\n", "\n").replace("\r", "\n")

    # Handle empty content
    if not content:
        return result

    lines = content.split("\n")

    # Check line count limit
    if len(lines) > MAX_LINES:
        raise Rfc5322Exception("content exceeds maximum line count")

    # Parse the content looking for key and single line or multiline values.
    # When a key is found, record it as current_key and its value is appended
    # to current_lines (for single of multi lines). On empty line or finished
    # processing multiline, save the current_key and its value (current_lines)
    # in results.
    for line in lines:
        # Check line length limit
        if len(line) > MAX_LINE_LENGTH:
            raise Rfc5322Exception("line exceeds maximum length")

        if not line:
            # Empty line - stanza separator (but not allowed before first header)
            if not current_key and not result:
                raise Rfc5322Exception("leading blank line")
            save_current()
            continue

        if line[0] in [" ", "\t"]:
            # Continuation line - must have a current key
            if not current_key:
                raise Rfc5322Exception(
                    "continuation line without preceding header: '%s'" % line[:50]
                )
            current_lines.append(line)
            is_multiline = True
            continue

        if ":" not in line:
            raise Rfc5322Exception("line without colon: '%s'" % line[:50])

        # New header - save previous first
        save_current()

        key, _, value = line.partition(":")

        # Validate key
        if not key:
            raise Rfc5322Exception("empty key (line starts with ':')")

        if len(key) > MAX_KEY_LENGTH:
            raise Rfc5322Exception("key exceeds maximum length: '%s'" % key[:50])

        if not _VALID_KEY_PATTERN.match(key):
            raise Rfc5322Exception("invalid key: '%s'" % key[:50])

        current_key = key

        # Warn if no space after colon for non-empty single-line values
        if value and not value[0].isspace():
            if warnFn:
                warnFn("missing space after colon for key '%s'" % key)

        value = value.lstrip()
        current_lines = [value] if value else []

    # Handle last header
    save_current()

    return result
