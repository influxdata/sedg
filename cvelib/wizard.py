#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from cvelib.common import (
    _experimental,
    cve_file_line_width,
    cve_priorities,
    gh_severities,
    gh_template_clause_text,
    error,
    getConfigCveDataPaths,
    rePatterns,
    warn,
)
from cvelib.cve import collectCVEData, cveFromUrl


def _naturalSortKey(url: str) -> Tuple[str, int]:
    """Generate a natural sort key for URLs with numeric suffixes.

    For URLs ending in /number, extract the numeric part for proper sorting.
    For example:
    - https://github.com/org/repo/security/dependabot/9 -> (..., 9)
    - https://github.com/org/repo/security/dependabot/10 -> (..., 10)

    This ensures that /9 sorts before /10.
    """
    # Split URL by '/' and check if last part is a number
    parts: List[str] = url.rstrip("/").split("/")
    if parts and parts[-1].isdigit():
        # Return base URL and numeric value for proper sorting
        base_url: str = "/".join(parts[:-1])
        return (base_url, int(parts[-1]))
    # For non-numeric endings, use sys.maxsize to sort them after numeric ones
    return (url, sys.maxsize)


def _extractUrlFromChecklistItem(item: str) -> str:
    """Extract URL from a markdown checklist item.

    Example input: '- [ ] [name](https://github.com/org/repo/security/dependabot/10) (low)'
    Returns: 'https://github.com/org/repo/security/dependabot/10'
    """
    # Extract URL from markdown link format [text](url)
    import re

    match = re.search(r"\]\(([^)]+)\)", item)
    if match:
        return match.group(1)
    return item  # Return original if no URL found


def _checklistItemSortKey(item: str) -> Tuple[str, Tuple[str, int]]:
    """Generate a sort key for markdown checklist items.

    Sorts first by display name, then by URL with numeric suffix handling.

    Example: '- [ ] [axios](https://github.com/.../10) (low)'
    Returns: ('axios', ('https://github.com/...', 10))
    """
    import re

    # Extract display name from [name](...) pattern
    # Look for pattern after the checkbox: ] [name](
    name_match = re.search(r"\] \[([^\]]+)\]", item)
    display_name = name_match.group(1) if name_match else ""

    # Extract and sort URL
    url = _extractUrlFromChecklistItem(item)
    url_key = _naturalSortKey(url)

    return (display_name, url_key)


def _isMarkdownCheckboxLine(line: str) -> bool:
    """Check if a line is a markdown checkbox (checked or unchecked)"""
    stripped: str = line.strip()
    return stripped.startswith("- [ ]") or stripped.lower().startswith("- [x]")


def _parsePriorityInput(input_str: str) -> str:
    """Parse priority input, only accepting single-letter shortcuts"""
    input_lower: str = input_str.lower().strip()

    # Map single letters to full priority names, calculated from cve_priorities
    priority_shortcuts: Dict[str, str] = {}
    for priority in cve_priorities:
        shortcut: str = priority[0].lower()  # First letter
        priority_shortcuts[shortcut] = priority

    # Only accept single letter shortcuts
    if input_lower in priority_shortcuts:
        return priority_shortcuts[input_lower]

    # Return empty string for invalid input (not a recognized single letter)
    return ""


def _formatAsNoteText(text: str, attribution: str = "PERSON") -> str:
    """Format CVE Notes text with proper line wrapping and attribution.

    Since the user's text editor may or may not automatically line-wrap with
    newlines but web browser textarea issue comment editors in bug trackers
    typically use two or more newlines to show a paragraph, this function
    considers '\n\n' to be the paragraph delimiter (with more newlines
    trimmed). A single '\n' within a line is converted to a single space.
    Eg, '1st\nparagraph\n\n2nd paragraph\n\n\n3rd paragraph' will be
    formatted as a CVE note like so:

    Notes:
     PERSON> 1st paragraph
      .
      2nd paragraph
      .
      3rd paragraph
    """
    if not text.strip():
        return ""

    # Split text into paragraphs on two or more newlines
    # First, normalize multiple newlines to exactly two newlines
    normalized_text: str = re.sub(r"\n{2,}", "\n\n", text.strip())

    # Split on double newlines to get paragraphs
    raw_paragraphs: List[str] = normalized_text.split("\n\n")

    paragraph: str
    paragraphs: List[str] = []
    for paragraph in raw_paragraphs:
        # Replace single newlines with spaces within each paragraph
        cleaned_para: str = paragraph.replace("\n", " ")
        # Normalize whitespace
        cleaned_para = " ".join(cleaned_para.split())
        if cleaned_para:  # Skip empty paragraphs
            paragraphs.append(cleaned_para)

    # Wrap the text to 'cve_file_line_width' characters, accounting for
    # attribution prefix
    # First line: " attribution> " (len = 1 + len(attribution) + 2)
    # Continuation lines: "  " (2 spaces)
    first_line_prefix: str = f" {attribution}> "
    continuation_prefix: str = "  "
    paragraph_separator: str = "  ."

    # Calculate available width for first line and continuation lines
    first_line_width: int = cve_file_line_width - len(first_line_prefix)
    continuation_width: int = cve_file_line_width - len(continuation_prefix)

    result_lines: List[str] = []

    para_idx: int
    for para_idx, paragraph in enumerate(paragraphs):
        # Wrap the current paragraph
        wrapped_lines: List[str] = textwrap.wrap(
            paragraph,
            width=first_line_width if para_idx == 0 else continuation_width,
            break_on_hyphens=False,
        )

        if not wrapped_lines:
            continue

        if para_idx == 0:
            # First paragraph: start with attribution
            result_lines.append(f"{first_line_prefix}{wrapped_lines[0]}")
            # Continuation lines for first paragraph
            for line in wrapped_lines[1:]:
                continuation_wrapped = textwrap.wrap(
                    line, width=continuation_width, break_on_hyphens=False
                )
                for cont_line in continuation_wrapped:
                    result_lines.append(f"{continuation_prefix}{cont_line}")
        else:
            # Add paragraph separator before subsequent paragraphs
            result_lines.append(paragraph_separator)
            # Add all lines of the paragraph with continuation prefix
            for line in wrapped_lines:
                continuation_wrapped = textwrap.wrap(
                    line, width=continuation_width, break_on_hyphens=False
                )
                for cont_line in continuation_wrapped:
                    result_lines.append(f"{continuation_prefix}{cont_line}")

    return "\n".join(result_lines)


def _extractDescriptionChanges(current_desc: str, original_desc: str) -> str:
    """Extract text between markdown checklist and References from modified description

    Issue descriptions have the form:

    The following alerts were issued:
    - [ ] [bar](https:...) (low)
    - [x] [foo](https:...) (high)

    FREE FORM TEXT

    References:
     * ...

    This function extracts the 'FREE FORM TEXT' section.
    """
    if current_desc == original_desc:
        return ""

    # Find the section between last checklist item and References in current description
    desc_lines: List[str] = current_desc.split("\n")

    checklist_end_idx: int
    references_idx: int
    checklist_end_idx, references_idx = _findDescriptionSectionIndices(desc_lines)

    if checklist_end_idx >= 0 and references_idx > checklist_end_idx:
        # Extract lines between checklist and References
        extracted_lines: List[str] = []
        for i in range(checklist_end_idx + 1, references_idx):
            line: str = desc_lines[
                i
            ].rstrip()  # Remove trailing whitespace but keep the line
            extracted_lines.append(line)

        # Join the lines and strip leading/trailing whitespace from the entire result
        return "\n".join(extracted_lines).strip()

    return ""


def _openEditor(content: str, suffix: str = ".txt") -> str:
    """Open the system editor with the given content and return the edited result"""
    # Check environment variables first
    editor: Optional[str] = (
        os.environ.get("SEDG_EDITOR")
        or os.environ.get("VISUAL")
        or os.environ.get("EDITOR")
    )

    # If no environment variable is set, check for available editors in order
    if not editor:
        for candidate in ["editor", "nano", "vi"]:
            if shutil.which(candidate):
                editor = candidate
                break

    # Verify that the selected editor is available
    ed_pat = re.compile(r"^[a-zA-Z0-9_]+$")
    if not editor or not shutil.which(editor) or (editor and not ed_pat.match(editor)):
        raise RuntimeError(
            "No suitable editor found. Please set SEDG_EDITOR, VISUAL, or EDITOR environment variable, or install one of: nano, vi"
        )

    with tempfile.NamedTemporaryFile(
        mode="w+", prefix="sedg-", suffix=suffix, delete=False
    ) as f:
        f.write(content)
        f.flush()
        temp_path: str = f.name

    try:
        subprocess.call([editor, temp_path])
        with open(temp_path, "r") as f:
            result: str = f.read()
    finally:
        os.unlink(temp_path)

    return result


def _getHighestSeverity(alerts: List[Dict[str, Any]]) -> str:
    """Get the highest severity from a list of alerts"""
    highest: int = 0

    for alert in alerts:
        try:
            cur: int = gh_severities.index(alert.get("severity", "unknown"))
        except ValueError:
            cur = 0

        if cur > highest:
            highest = cur

    priority: str = gh_severities[highest]
    if priority == "unknown":
        priority = "medium"

    return priority


def _groupAlertsByRepo(alerts_data: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Group alerts by repository"""
    grouped: Dict[str, Dict[str, Any]] = {}
    for data in alerts_data:
        key: str = f"{data['org']}/{data['repo']}"
        if key not in grouped:
            grouped[key] = data
        else:
            # Merge alerts if multiple entries for same repo
            grouped[key]["alerts"].extend(data["alerts"])
            # Update highest severity
            all_alerts: List[Any] = grouped[key]["alerts"]
            grouped[key]["highest_severity"] = _getHighestSeverity(all_alerts)
            # Merge alert types
            for alert_type in data["alert_types"]:
                if alert_type not in grouped[key]["alert_types"]:
                    grouped[key]["alert_types"].append(alert_type)
            # Merge references
            for ref in data["references"]:
                if ref not in grouped[key]["references"]:
                    grouped[key]["references"].append(ref)

    return grouped


def _promptWithDefault(prompt: str, default: str = "") -> str:
    """Prompt user with a default value"""
    if default:
        user_input: str = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ").strip()


def _promptWithOptions(message: str, options: List[str]) -> str:
    """Prompt user with specific options"""
    options_str: str = "/".join(f"[{opt[0]}]{opt[1:]}" for opt in options)
    while True:
        response: str = input(f"{message} ({options_str}): ").strip()
        if response and len(response) == 1:
            # Only accept single letter inputs
            for opt in options:
                if opt[0].lower() == response.lower():
                    return opt
        print(f"Invalid option. Please choose from: {options_str}")


def _generateIssueSummary(alerts: List[Dict[str, Any]], repo: str) -> str:
    """Generate GitHub issue summary"""
    alert_types: Set[str] = set()
    for alert in alerts:
        alert_types.add(alert["type"])

    plural: str = "s" if len(alerts) > 1 else ""
    alert_types_str: str = ", ".join(sorted(alert_types))
    return f"Please address alert{plural} ({alert_types_str}) in {repo}"


def _generateIssueDescription(alerts: List[Dict[str, Any]], org: str, repo: str) -> str:
    """Generate GitHub issue description with markdown checklist"""
    # Build checklist
    checklist_items: List[str] = []
    alert_types: Set[str] = set()
    clauses: List[str] = []

    for alert in alerts:
        alert_types.add(alert["type"])

        # Add clause if not already added
        if (
            alert["type"] in gh_template_clause_text
            and gh_template_clause_text[alert["type"]] not in clauses
        ):
            clauses.append(gh_template_clause_text[alert["type"]])

        # Create checklist item
        item: str = (
            f"- [ ] [{alert['display_name']}]({alert['url']}) ({alert['severity']})"
        )
        if item not in checklist_items:
            checklist_items.append(item)

    # Sort the checklist items by display name first, then by URL with numeric sorting
    checklist: str = "\n".join(sorted(checklist_items, key=_checklistItemSortKey))
    highest_severity: str = _getHighestSeverity(alerts)
    plural: str = "s were" if len(alerts) > 1 else " was"

    # Build references section
    urls: Set[str] = set()
    for alert in alerts:
        if alert["type"] == "code-scanning":
            urls.add(f"https://github.com/{org}/{repo}/security/code-scanning")
        elif alert["type"] == "dependabot":
            urls.add(f"https://github.com/{org}/{repo}/security/dependabot")
        elif alert["type"] == "secret-scanning":
            urls.add(f"https://github.com/{org}/{repo}/security/secret-scanning")

    references: str = "\n * ".join(sorted(urls, key=_naturalSortKey))

    return f"""The following alert{plural} issued:
{checklist}

Since a{' ' if highest_severity[0] not in 'aeiou' else 'n '}{highest_severity} severity issue is present, tentatively adding the 'security/{highest_severity}' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. {' '.join(sorted(clauses))}

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
 * {references}"""


# XXX: consider refactoring this so that it can be reused in report.py (but
# maybe we'll remove --with-templates...)
def _generateCveContent(
    alerts: List[Dict[str, Any]],
    org: str,
    repo: str,
    tracking_url: str,
    custom_priority: str = "",
    description_changes: str = "",
    gh_author: str = "",
) -> str:
    """Generate CVE file content"""
    now: datetime.datetime = datetime.datetime.now()
    highest_severity: str = _getHighestSeverity(alerts)

    # Calculate CVE candidate from tracking URL
    candidate: str
    try:
        candidate, _ = cveFromUrl(tracking_url)
    except Exception:
        # Fallback to default format if URL parsing fails
        candidate = f"CVE-{now.year}-NNNN"

    # Build references
    references: List[str] = [tracking_url]
    advisories: List[str] = []

    for alert in sorted(alerts, key=lambda x: _naturalSortKey(x.get("url", ""))):
        alert_url: str = alert.get("url", "")
        if alert_url and alert_url not in references:
            references.append(alert_url)
        if alert["type"] == "dependabot" and "advisory" in alert and alert["advisory"]:
            adv: str = f"{alert['advisory']} ({alert['display_name']})"
            if adv not in advisories:
                advisories.append(adv)

    references.extend(sorted(advisories))
    references_str: str = "\n ".join(references)

    # Build description checklist
    checklist_items: Dict[str, int] = {}
    for alert in alerts:
        key: str = f"- [ ] {alert['display_name']} ({alert['severity']})"
        if key not in checklist_items:
            checklist_items[key] = 1
        else:
            checklist_items[key] += 1

    checklist: List[str] = []
    for item, count in sorted(checklist_items.items()):
        if count > 1:
            # Add count to the item
            item: str = item.replace("(", f"({count} ", 1)
        checklist.append(f" {item}")
    checklist_str: str = "\n".join(checklist)

    # Build GitHub-Advanced-Security section
    ghas_items: List[str] = []
    discovered_by: Set[str] = set()
    seen_urls: Set[str] = set()

    for alert in sorted(alerts, key=lambda x: _naturalSortKey(x.get("url", ""))):
        # Skip duplicate alerts (same URL)
        alert_url: str = alert.get("url", "")
        if alert_url in seen_urls:
            continue
        seen_urls.add(alert_url)

        ghas_item: str = f" - type: {alert['type']}\n"

        if alert["type"] == "dependabot":
            if alert["display_name"].startswith("@"):
                ghas_item += f'   dependency: "{alert["display_name"]}"\n'
            else:
                ghas_item += f"   dependency: {alert['display_name']}\n"
            ghas_item += f"   detectedIn: {alert.get('manifest_path', 'unknown')}\n"
            discovered_by.add("gh-dependabot")
        elif alert["type"] == "code-scanning":
            ghas_item += f"   description: {alert['display_name']}\n"
            discovered_by.add("gh-code")
        elif alert["type"] == "secret-scanning":
            ghas_item += f"   secret: {alert['display_name']}\n"
            ghas_item += "   detectedIn: tbd\n"
            discovered_by.add("gh-secret")

        ghas_item += f"   severity: {alert['severity']}\n"
        if alert["type"] == "dependabot" and "advisory" in alert and alert["advisory"]:
            ghas_item += f"   advisory: {alert['advisory']}\n"
        ghas_item += "   status: needs-triage\n"
        ghas_item += f"   url: {alert['url']}"

        ghas_items.append(ghas_item)

    ghas_str: str = "\n".join(ghas_items)
    discovered_by_str: str = ", ".join(sorted(discovered_by))

    plural: str = "s" if len(alerts) > 1 else ""

    # some fields require the repo without any modifiers
    base_repo: str = repo.split("/")[0]

    # Build per-package priority override if custom priority differs from calculated
    priority_override_section: str = ""
    if custom_priority and custom_priority != highest_severity:
        priority_override_section = f"Priority_{base_repo}: {custom_priority}\n"

    # Build notes section if there are description changes
    notes_section: str = ""
    if description_changes and description_changes.strip():
        # Use provided author or default to 'PERSON'
        author: str = gh_author if gh_author else "PERSON"
        formatted_note: str = _formatAsNoteText(description_changes, author)
        if formatted_note:
            notes_section = f"\n{formatted_note}"

    return f"""Candidate: {candidate}
OpenDate: {now.year}-{now.month:02d}-{now.day:02d}
CloseDate:
PublicDate:
CRD:
References:
 {references_str}
Description:
 Please address alert{plural} in {repo}
{checklist_str}
GitHub-Advanced-Security:
{ghas_str}
Notes:{notes_section}
Mitigation:
Bugs:
 {tracking_url}
Priority: {highest_severity}
Discovered-by: {discovered_by_str}
Assigned-to:
CVSS:

{priority_override_section}Patches_{base_repo}:
git/{org}_{repo}: needs-triage"""


def _findDescriptionSectionIndices(desc_lines: Sequence[str]) -> Tuple[int, int]:
    """
    Find the indices of checklist end and References section in description lines.

    Returns:
        (checklist_end_idx: int, references_idx: int)
        Returns (-1, -1) if not found.
    """
    # Find the end of the markdown checklist
    checklist_end_idx: int = -1
    for i, line in enumerate(desc_lines):
        if _isMarkdownCheckboxLine(line):
            checklist_end_idx = i

    # Find the References section
    references_idx: int = -1
    for i, line in enumerate(desc_lines):
        if line.strip() == "References:":
            references_idx = i
            break

    return checklist_end_idx, references_idx


def _updateDescriptionForCustomPriority(
    issue_description: str,
    custom_priority: str,
    highest_severity: str,
    gh_priority_prefix: str,
    description_manually_edited: bool,
    default_description: str,
) -> str:
    """Update issue description based on custom priority selection.

    This function handles the business logic for updating the issue description
    when a user sets a custom priority that differs from the calculated severity.
    """
    if custom_priority != highest_severity and not description_manually_edited:
        # Replace all text between markdown checklist and References
        desc_lines: Sequence[str] = issue_description.split("\n")

        checklist_end_idx: int
        references_idx: int
        checklist_end_idx, references_idx = _findDescriptionSectionIndices(desc_lines)

        if checklist_end_idx >= 0 and references_idx > checklist_end_idx:
            # Build new description with replacement text
            new_desc_lines: List[str] = []

            # Keep everything up to and including the last checklist item
            for i in range(checklist_end_idx + 1):
                new_desc_lines.append(desc_lines[i])

            # Add the custom priority note
            priority_label: str = f"{gh_priority_prefix}{custom_priority}"
            new_desc_lines.append("")
            new_desc_lines.append(
                f"Adding the '{priority_label}' label due to FILL ME IN"
            )
            new_desc_lines.append("")

            # Add References section and everything after
            for i in range(references_idx, len(desc_lines)):
                new_desc_lines.append(desc_lines[i])

            return "\n".join(new_desc_lines)
    elif custom_priority == highest_severity and not description_manually_edited:
        # Priority matches calculated, restore original description only if not manually edited
        return default_description

    return issue_description


def _generatePriorityPromptText() -> str:
    """Generate priority prompt text from common.py:cve_priorities"""
    # Build shortcut/full name pairs from cve_priorities
    shortcuts: List[str] = []
    for priority in cve_priorities:
        shortcut: str = priority[0].lower()  # First letter
        shortcuts.append(f"{shortcut}/{priority}")

    return f"Priority ({' for '.join(shortcuts)})"


def _generatePriorityErrorMessage() -> str:
    """Generate priority error message from common.py:cve_priorities"""
    shortcuts: List[str] = [priority[0].lower() for priority in cve_priorities]
    return f"ERROR: Priority must be a single letter: {'/'.join(shortcuts)}"


def _parseOrgRepoInput(orig: str, default_org: str) -> Tuple[str, str]:
    """
    Parse org/repo input and return (org, repo) tuple.

    Handles cases:
    - "org/repo" -> returns ("org", "repo")
    - "repo" -> returns (default_org, "repo")

    Raises ValueError for invalid formats.
    """
    input_str: str = orig.strip()

    # Validate input - no leading, trailing, or multiple slashes
    if input_str.startswith("/") or input_str.endswith("/") or "//" in input_str:
        raise ValueError(
            "Invalid format. No leading, trailing, or multiple forward slashes allowed."
        )

    # Validate input - must be longer than a single character
    if len(input_str) == 1:
        raise ValueError(
            "Invalid format (when specified, must be longer than 1 character)"
        )

    # Parse org/repo and return tuple
    org: str = default_org
    repo: str
    if "/" in input_str:
        # User provided org/repo format
        parts: List[str] = input_str.split("/")
        if len(parts) != 2:
            raise ValueError("Invalid format. Use 'org/repo' or just 'repo'.")
        org = parts[0]
        repo = parts[1]
    else:
        # User provided only repo name, use default org
        repo = input_str

    if not rePatterns["pkg-where"].match(org):
        raise ValueError("org must match format: %s" % rePatterns["pkg-where"].pattern)

    if not rePatterns["pkg-software"].match(repo):
        raise ValueError(
            "repo must match format: %s" % rePatterns["pkg-software"].pattern
        )

    return org, repo


def _extractIssueNumberFromUrl(issue_url: str) -> str:
    """Extract issue number from GitHub issue URL"""
    try:
        # GitHub issue URLs have format: https://github.com/org/repo/issues/123
        parts: List[str] = issue_url.rstrip("/").split("/")
        if len(parts) >= 2 and parts[-2] == "issues":
            if int(parts[-1]) < 0:
                raise ValueError
            return parts[-1]
    except (IndexError, ValueError):
        pass
    return ""


def _isGhCliAvailable() -> bool:
    """Check if the 'gh' CLI tool is available in PATH"""
    try:
        result: subprocess.CompletedProcess = subprocess.run(
            ["gh", "--version"], capture_output=True, text=True, timeout=3
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        return False


def _runGhCommand(cmd: List[str]) -> Tuple[bool, str, str]:
    """
    Run a gh CLI command and return standardized results.

    Returns:
        (success: bool, stdout_content: str, error_message: str)
    """
    try:
        result: subprocess.CompletedProcess = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0:
            return True, result.stdout.strip(), ""
        else:
            error_msg: str = (
                result.stderr.strip() or result.stdout.strip() or "Unknown error"
            )
            return False, "", error_msg

    except subprocess.TimeoutExpired:
        return False, "", "GitHub CLI command timed out"
    except Exception as e:
        return False, "", f"Error executing gh command: {str(e)}"


def _createGithubIssueWithGh(
    org: str, repo: str, title: str, body: str, labels: str = ""
) -> Tuple[bool, str, str]:
    """
    Create a GitHub issue using the 'gh' CLI tool.

    Returns:
        (success: bool, issue_url: str, error_message: str)
    """
    # Build the gh command
    cmd: List[str] = [
        "gh",
        "issue",
        "create",
        "--repo",
        f"{org}/{repo}",
        "--title",
        title,
        "--body",
        body,
    ]

    # Add labels if provided
    if labels.strip():
        # Split labels by comma and clean them up
        label_list: List[str] = [
            label.strip() for label in labels.split(",") if label.strip()
        ]
        if label_list:
            cmd.extend(["--label", ",".join(label_list)])

    # Execute the command using the common helper
    success, stdout_content, error_msg = _runGhCommand(cmd)

    if success:
        # gh returns the issue URL on success
        return True, stdout_content, ""
    else:
        return False, "", error_msg


def _closeGithubIssueWithGh(
    org: str, repo: str, issue_number: str, reason: str = "completed"
) -> Tuple[bool, str]:
    """
    Close a GitHub issue using the 'gh' CLI tool.

    Returns:
        (success: bool, error_message: str)
    """
    # Build the gh command to close the issue
    cmd: List[str] = [
        "gh",
        "issue",
        "close",
        issue_number,
        "--repo",
        f"{org}/{repo}",
        "--reason",
        reason,
    ]

    # Execute the command using the common helper
    success, _, error_msg = _runGhCommand(cmd)

    if success:
        return True, ""
    else:
        return False, error_msg


def _runGitCommand(
    cmd: List[str], cwd: str, input_text: Optional[str] = None
) -> Tuple[bool, str, str]:
    """Run a git command and return success status, stdout, and stderr.

    Args:
        cmd: Git command to run
        cwd: Working directory for the command
        input_text: Optional text to send to stdin

    Returns:
        (success: bool, stdout: str, stderr: str)
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
            input=input_text,
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Git command timed out"
    except Exception as e:
        return False, "", str(e)


def _processSummaryInput(
    summary_input: str,
    repo: str,
    alerts: List[Dict[str, Any]],
    current_summary: str,
    current_repo_name: str,
) -> Tuple[str, str]:
    """
    Process user's summary input and determine if it's a repo name or custom summary.

    Returns:
        (issue_summary, cve_repo_name)
    """
    # If input looks like a simple repo name (no spaces, standard repo characters
    # or a /), generate a new summary. Otherwise, use it as the full summary.
    if " " not in summary_input and all(
        c.isalnum() or c in ".-_/" for c in summary_input
    ):
        # Looks like a repo name, generate new summary
        if summary_input != repo:
            issue_summary: str = _generateIssueSummary(alerts, summary_input)
            print(f"- Updated issue summary: {issue_summary}")
            return issue_summary, summary_input
        else:
            return current_summary, current_repo_name
    else:
        # Use as custom summary
        if summary_input != current_summary:
            print(f"Using custom summary: {summary_input}")
        return summary_input, current_repo_name


def _processOrgRepoInput(
    org_repo: str, default_org: str, current_org: str, current_repo: str
) -> Tuple[str, str, str]:
    """
    Process org/repo input and return (org, repo, url).

    Returns:
        (issue_org, issue_repo, issue_url)
    """
    try:
        issue_org: str
        issue_repo: str
        issue_url: str
        issue_org, issue_repo = _parseOrgRepoInput(org_repo, default_org)
        issue_url = f"https://github.com/{issue_org}/{issue_repo}/issues/new"
        if issue_org != current_org or issue_repo != current_repo:
            print(f"- Updated GitHub issue URL: {issue_url}")
        return issue_org, issue_repo, issue_url
    except ValueError as e:
        raise ValueError(str(e))


def _processRepoGHIssue(
    org: str,
    repo: str,
    alerts: List[Dict[str, Any]],
    gh_default_labels: str,
    gh_priority_prefix: str,
    gh_disable_cli: bool = False,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Process GitHub issue creation for alerts.

    Returns:
        (continue_processing: bool, issue_data: Optional[Dict[str, Any]])
        - continue_processing: True to continue, False to abort wizard
        - issue_data: Dict with issue details if created, None if skipped
    """
    # Step 1: GitHub org and repo
    default_org_repo: str = f"{org}/{repo}"
    default_url: str = f"https://github.com/{org}/{repo}/issues/new"
    print(f"Default GitHub issue URL: {default_url}")

    org_repo: str
    issue_org: str = org
    issue_repo: str = repo
    issue_url: str = default_url

    while True:
        org_repo = _promptWithDefault(
            "GitHub org/repo for filing issues (or [s]kip/[a]bort)",
            default_org_repo,
        )

        # Check if user wants to skip this repository
        if org_repo.lower() == "s":
            print(f"Skipping repository {org}/{repo}.")
            return True, None

        # Check if user wants to abort the wizard
        if org_repo.lower() == "a":
            print("Aborting wizard.")
            return False, None

        try:
            issue_org, issue_repo, issue_url = _processOrgRepoInput(
                org_repo, org, issue_org, issue_repo
            )
            break
        except ValueError as e:
            print(f"\nERROR: {e}")
            continue

    # Step 2: Issue summary
    default_summary: str = _generateIssueSummary(alerts, repo)
    print(f"\nDefault issue summary: {default_summary}")
    summary_input: str = _promptWithDefault("Repository name for issue summary", repo)

    # Track the repo name to use for CVE generation
    cve_repo_name: str = repo  # Default to original repo

    # Process the summary input
    issue_summary, cve_repo_name = _processSummaryInput(
        summary_input, repo, alerts, default_summary, cve_repo_name
    )

    # Step 3: Set default labels (no prompt)
    highest_severity: str = _getHighestSeverity(alerts)
    custom_priority: str = ""  # Track user-specified priority override

    def build_labels(priority_to_use: str) -> str:
        """Build labels list based on command line arguments and priority"""
        label_parts: List[str] = []

        # Add default labels if provided
        if gh_default_labels:
            label_parts.extend(
                [
                    label.strip()
                    for label in gh_default_labels.split(",")
                    if label.strip()
                ]
            )

        # Add priority label with optional prefix
        label_parts.append(f"{gh_priority_prefix}{priority_to_use}")

        return ",".join(label_parts)

    labels: str = build_labels(highest_severity)

    # Step 4: Generate default description
    default_description: str = _generateIssueDescription(alerts, org, repo)
    issue_description: str = default_description
    description_manually_edited: bool = (
        False  # Track if user manually edited description
    )

    # Step 5: Display and confirm
    while True:
        print("\n" + "=" * 60)
        print("GITHUB ISSUE PREVIEW")
        print("=" * 60)
        print(f"URL: {issue_url}")
        print(f"Title: {issue_summary}")
        print(f"Labels: {labels}")
        print("\nDescription:")
        print("-" * 40)
        print(issue_description)
        print("-" * 40)

        action: str = _promptWithOptions(
            "\nWhat would you like to do?", ["create", "edit", "skip", "abort"]
        )

        if action == "abort":
            print("Aborting wizard.")
            return False, None
        elif action == "skip":
            print(f"Skipping alerts for {repo}.")
            return True, None
        elif action == "edit":
            # Allow editing any field
            edit_field: str = _promptWithOptions(
                "\nWhat would you like to edit?",
                ["url", "title", "labels", "priority", "description", "back"],
            )

            if edit_field == "url":
                current_org_repo: str = f"{issue_org}/{issue_repo}"

                while True:
                    edited_org_repo: str = _promptWithDefault(
                        "\nGitHub issue org/repo", current_org_repo
                    )

                    try:
                        issue_org, issue_repo, issue_url = _processOrgRepoInput(
                            edited_org_repo, issue_org, issue_org, issue_repo
                        )
                        break
                    except ValueError as e:
                        print(f"\nERROR: {e}")
                        continue
            elif edit_field == "title":
                # Show current summary
                print(f"Current issue summary: {issue_summary}")
                summary_input = _promptWithDefault(
                    "\nRepository name or custom summary", issue_summary
                )

                # Process the summary input
                issue_summary, cve_repo_name = _processSummaryInput(
                    summary_input, repo, alerts, issue_summary, cve_repo_name
                )
            elif edit_field == "labels":
                labels = _promptWithDefault("\nGitHub labels (comma-separated)", labels)
            elif edit_field == "priority":
                current_priority: str = (
                    custom_priority if custom_priority else highest_severity
                )
                print(f"\nCurrent priority: {current_priority}")
                print(f"Calculated highest severity: {highest_severity}")

                # Prompt for new priority with validation
                while True:
                    prompt_text: str = f"\n{_generatePriorityPromptText()}"

                    user_input: str = _promptWithDefault(
                        prompt_text,
                        current_priority[0] if current_priority else "",
                    )

                    new_priority: str = _parsePriorityInput(user_input)

                    if new_priority and new_priority in cve_priorities:
                        custom_priority = new_priority
                        # Rebuild labels with new priority
                        labels = build_labels(custom_priority)

                        # Update description based on custom priority
                        issue_description = _updateDescriptionForCustomPriority(
                            issue_description,
                            custom_priority,
                            highest_severity,
                            gh_priority_prefix,
                            description_manually_edited,
                            default_description,
                        )

                        print(f"- Updated priority: {custom_priority}")
                        print(f"- Updated labels: {labels}")
                        break
                    else:
                        print(_generatePriorityErrorMessage())
            elif edit_field == "description":
                issue_description = _openEditor(issue_description, suffix=".md")
                description_manually_edited = True
            elif edit_field == "back":
                continue
        else:
            # action == "create"
            break

    # Step 6: Create GitHub issue and get tracking URL
    tracking_url: str = ""
    issue_created_via_gh: bool = False  # Track if issue was created via gh CLI

    # Check if gh CLI is available and not disabled
    if not gh_disable_cli and _isGhCliAvailable():
        print("\nFound 'gh' CLI tool. Creating GitHub issue automatically...")
        success, created_issue_url, error_msg = _createGithubIssueWithGh(
            issue_org, issue_repo, issue_summary, issue_description, labels
        )

        if success:
            print(f"+ Successfully created: {created_issue_url}")
            tracking_url = created_issue_url
            issue_created_via_gh = True
        else:
            print("- Failed to create GitHub issue with 'gh' CLI:")
            print(f"  Error: {error_msg}")
            print("  Falling back to manual creation...")
    else:
        if gh_disable_cli:
            print("\n'gh' CLI tool disabled via --gh-disable-cli. Create manually...")
        else:
            print("\n'gh' CLI tool not found in PATH. Create manually...")

    # Fall back to manual creation if gh CLI failed or is not available
    if not tracking_url:
        print(f"\nPlease create a new GitHub issue at {issue_url}")
        while True:
            issue_number: str = input("and provide the issue number: ").strip()

            if issue_number.isdigit() and int(issue_number) >= 0:
                break
            else:
                print("ERROR: Please enter a non-negative integer.")

        tracking_url = (
            f"https://github.com/{issue_org}/{issue_repo}/issues/{issue_number}"
        )

    # Return issue data for CVE creation
    issue_data = {
        "tracking_url": tracking_url,
        "issue_org": issue_org,
        "issue_repo": issue_repo,
        "issue_created_via_gh": issue_created_via_gh,
        "custom_priority": custom_priority,
        "default_description": default_description,
        "issue_description": issue_description,
        "cve_repo_name": cve_repo_name,  # Repository name to use in CVE
    }

    return True, issue_data


def _processRepoCVE(
    org: str,
    repo: str,
    alerts: List[Dict[str, Any]],
    issue_data: Dict[str, Any],
    gh_author: str,
    cve_dirs: Dict[str, str],
) -> bool:
    """
    Process CVE file creation for alerts.

    Args:
        org: Original organization name
        repo: Repository name
        alerts: List of alert data
        issue_data: GitHub issue data from _processRepoGHIssue
        gh_author: Author name for CVE
        cve_dirs: Dictionary of CVE directories from getConfigCveDataPaths

    Returns:
        bool: True to continue, False to abort wizard
    """
    tracking_url = issue_data["tracking_url"]
    custom_priority = issue_data["custom_priority"]
    default_description = issue_data["default_description"]
    issue_description = issue_data["issue_description"]
    issue_org = issue_data["issue_org"]
    issue_repo = issue_data["issue_repo"]
    issue_created_via_gh = issue_data["issue_created_via_gh"]
    cve_repo_name = issue_data.get(
        "cve_repo_name", repo
    )  # Use provided repo name or default

    # Extract description changes if the issue description was modified
    description_changes: str = _extractDescriptionChanges(
        issue_description.strip(), default_description.strip()
    )
    # Use cve_repo_name instead of repo for CVE content generation
    cve_content: str = _generateCveContent(
        alerts,
        org,
        cve_repo_name,
        tracking_url,
        custom_priority,
        description_changes,
        gh_author,
    )

    # CVE file creation
    while True:
        print("\n" + "=" * 60)
        print("CVE FILE PREVIEW")
        print("=" * 60)
        print(cve_content)
        print("-" * 40)

        cve_action = _promptWithOptions(
            "\nWhat would you like to do?", ["create", "edit", "skip", "abort"]
        )

        if cve_action == "abort":
            print("Aborting wizard.")
            return False
        elif cve_action == "skip":
            print(f"Skipping CVE creation for {repo}.")
            return True
        elif cve_action == "edit":
            cve_content = _openEditor(cve_content, suffix=".cve")
            # Loop back to show updated content and prompt again
            continue
        else:
            # cve_action == "create"
            break

    # Extract candidate from CVE content
    candidate_line: str = cve_content.split("\n")[0]
    if ": " in candidate_line:
        candidate = candidate_line.split(": ", 1)[1].strip()
    else:
        candidate = "CVE-UNKNOWN"

    # Determine directory (active or retired based on CloseDate)
    close_date_line: Optional[str] = next(
        (line for line in cve_content.split("\n") if line.startswith("CloseDate:")),
        None,
    )
    close_date: str = ""
    if close_date_line and ": " in close_date_line:
        close_date = close_date_line.split(": ", 1)[1].strip()

    cve_dir: str = "retired" if close_date else "active"

    # Use CVE data paths passed from _runWizard
    cve_path: str = cve_dirs[cve_dir]

    # Derive the base CVE data directory from the paths we have
    # All paths in cve_dirs are like /path/to/cve-data/[active|retired|ignored|templates]
    # So we can get the parent directory of any of them
    cve_data_dir: str = os.path.dirname(cve_path)

    cve_file: str = os.path.join(cve_path, candidate)
    cve_file_rel: str = os.path.relpath(cve_file, cve_data_dir)

    # Check if file exists
    if os.path.exists(cve_file):
        overwrite: str = _promptWithOptions(
            f"\nCVE file {cve_file_rel} already exists. Overwrite?", ["yes", "no"]
        )
        if overwrite != "yes":
            print("Skipping CVE creation.")
            return True

    # Write CVE file
    try:
        with open(cve_file, "w") as f:
            f.write(cve_content)
            if not cve_content.endswith("\n"):
                f.write("\n")
        print(f"\nCVE file created: {cve_file_rel}")

        # Check if cve_data_dir is a git repository and prompt for commit
        success, _, _ = _runGitCommand(["git", "rev-parse", "--git-dir"], cve_data_dir)
        if success:
            # Generate commit message
            if cve_dir == "retired":
                default_commit_msg: str = f"chore: add/retire {candidate}"
            else:
                default_commit_msg: str = f"chore: add {candidate}"

            # Show preview and prompt user
            print("\nDetected git repository. Commit message preview:")
            print(f"  {default_commit_msg}")

            commit_action: str = _promptWithOptions(
                "\nCommit CVE file to git?", ["yes", "edit", "no"]
            )

            commit_msg: str = default_commit_msg
            if commit_action == "edit":
                commit_msg = _openEditor(default_commit_msg, suffix=".gitc")
                commit_msg = commit_msg.strip()
                if not commit_msg:
                    print("Empty commit message. Skipping git commit.")
                    commit_action = "no"

            if commit_action in ["yes", "edit"] and commit_msg:
                print(f"\nCommit message:\n{commit_msg}")
                print("\nCommitting CVE file to git...")

                # Add file to git index
                success, _, error_msg = _runGitCommand(
                    ["git", "add", "-N", cve_file_rel], cve_data_dir
                )

                if success:
                    # Commit the file - use stdin for multiline commit messages
                    cmd: List[str] = ["git", "commit", cve_file_rel, "-F", "-"]
                    success, _, error_msg = _runGitCommand(
                        cmd, cve_data_dir, input_text=commit_msg
                    )

                    if success:
                        # Show only first line of commit message for success
                        first_line: str = commit_msg.split("\n")[0]
                        print(f"+ Successfully committed: {first_line}")
                    else:
                        print("- Failed to commit CVE file:")
                        print(f"  Error: {error_msg}")
                else:
                    print("- Failed to add CVE file to git:")
                    print(f"  Error: {error_msg}")

        # If issue was created via gh CLI and CVE has CloseDate, close the GitHub issue
        if issue_created_via_gh and close_date:
            extracted_issue_number: str = _extractIssueNumberFromUrl(tracking_url)
            if extracted_issue_number:
                print(
                    f"\nCVE has CloseDate set ({close_date}). Closing GitHub issue #{extracted_issue_number}..."
                )
                success, error_msg = _closeGithubIssueWithGh(
                    issue_org, issue_repo, extracted_issue_number, "completed"
                )

                if success:
                    print(f"+ Successfully closed GitHub issue {tracking_url}")
                else:
                    print(f"- Failed to close GitHub issue #{extracted_issue_number}:")
                    print(f"  Error: {error_msg}")
                    print(f"  You may need to close it manually at {tracking_url}")
            else:
                print(
                    f"\nWarning: Could not extract issue number from {tracking_url} to close issue"
                )

    except Exception as e:
        error(f"Failed to write CVE file: {e}")

    return True


def _processRepoAlerts(
    org: str,
    repo: str,
    alert_data: Dict[str, Any],
    gh_default_labels: str,
    gh_priority_prefix: str,
    gh_author: str,
    gh_disable_cli: bool,
    existing_ghas_urls: Optional[Dict[str, str]],
    cve_dirs: Dict[str, str],
) -> bool:
    """Process alerts for a single repository. Returns True to continue, False to abort."""
    alerts: List = alert_data["alerts"]

    if existing_ghas_urls is None:
        existing_ghas_urls = {}

    print(f"\n{'=' * 60}")
    print(f"Processing alerts for {org}/{repo}")
    print(f"Found {len(alerts)} alert(s)")

    # Filter out alerts that already exist in CVE data
    new_alerts = []
    existing_alerts = []

    for alert in alerts:
        if alert.get("url") in existing_ghas_urls:
            existing_alerts.append((alert, existing_ghas_urls[alert["url"]]))
        else:
            new_alerts.append(alert)

    # Warn about existing alerts
    if existing_alerts:
        print(f"\nWARNING: Found {len(existing_alerts)} alert(s) already in CVE data:")
        for alert, cve_file in existing_alerts:
            print(f"  - {alert['display_name']} ({alert['severity']})")
            print(f"    URL: {alert['url']}")
            print(f"    CVE file: {cve_file}")

    # Check if there are any new alerts to process
    if not new_alerts:
        print(f"\nWARNING: No new alerts to process for {org}/{repo}")
        print("All alerts are already tracked in existing CVE files.")
        return True  # Continue to next repository

    print(f"\nProcessing {len(new_alerts)} new alert(s)")
    print(f"{'=' * 60}\n")

    # Update alerts to only process new ones
    alerts = new_alerts

    # Main processing loop
    while True:
        # Process GitHub issue creation
        continue_processing, issue_data = _processRepoGHIssue(
            org, repo, alerts, gh_default_labels, gh_priority_prefix, gh_disable_cli
        )

        if not continue_processing:
            return False  # Abort wizard

        if issue_data is None:
            return True  # Skip this repository

        # Process CVE file creation
        continue_processing = _processRepoCVE(
            org, repo, alerts, issue_data, gh_author, cve_dirs
        )

        if not continue_processing:
            return False  # Abort wizard
        else:
            return True  # Successfully completed processing


def _runWizard(
    alerts_file: str,
    gh_default_labels: str,
    gh_priority_prefix: str,
    gh_author: str,
    gh_disable_cli: bool = False,
) -> None:
    """Main wizard orchestration"""
    # Read and parse JSON file
    raw_data = []
    try:
        with open(alerts_file, "r", encoding="utf-8") as f:
            content = f.read()
        raw_data = json.loads(content)
    except json.JSONDecodeError as e:
        error(f"Invalid JSON in file {alerts_file}: {e}")
    except Exception as e:
        error(f"Error reading file {alerts_file}: {e}")

    # Validate structure in the most simple way
    if not isinstance(raw_data, list):
        error("JSON file must contain an array of alert objects")
    for obj in raw_data:
        if not isinstance(obj, dict):
            error("JSON file must contain an array of alert objects")

    # Now that it is simply verified, proceed
    alerts_data: List[Dict[str, Any]] = raw_data
    if not alerts_data:
        print("No alerts found in the JSON file.")
        return

    # Get CVE directories using getConfigCveDataPaths()
    # This will validate the configuration and error out if not properly configured
    cve_dirs = getConfigCveDataPaths()

    # Collect existing GHAS URLs from CVE data
    print("Collecting existing GHAS URLs from CVE data...")
    existing_ghas_urls: Dict[str, str] = {}  # Map URL to CVE filename

    # Collect all CVEs
    try:
        cves = collectCVEData(cve_dirs, compatUbuntu=False, untriagedOk=True)

        # Extract GHAS URLs from each CVE
        for cve in cves:
            if hasattr(cve, "ghas") and cve.ghas:
                for ghas_entry in cve.ghas:
                    if hasattr(ghas_entry, "url") and ghas_entry.url:
                        existing_ghas_urls[ghas_entry.url] = cve.fn
    except Exception as e:
        warn(f"Failed to collect existing GHAS URLs: {e}")
        existing_ghas_urls = {}

    print(f"Found {len(existing_ghas_urls)} existing GHAS URLs in CVE data")

    # Group alerts by repo
    grouped: Dict[str, Dict[str, Any]] = _groupAlertsByRepo(alerts_data)

    print(f"Found alerts for {len(grouped)} repository(ies)")

    # Process each repo
    for i, (repo_key, repo_data) in enumerate(sorted(grouped.items()), 1):
        org: str = repo_data["org"]
        repo: str = repo_data["repo"]

        print(f"\n# Processing repository {i} of {len(grouped)}: {repo_key}")

        if not _processRepoAlerts(
            org,
            repo,
            repo_data,
            gh_default_labels,
            gh_priority_prefix,
            gh_author,
            gh_disable_cli,
            existing_ghas_urls,
            cve_dirs,
        ):
            # User chose to abort
            break

    print("\nDone.")


def _mainCveAddWizardGh(
    alerts_file: str,
    default_labels: str,
    priority_prefix: str,
    author: str,
    disable_cli: bool,
) -> None:
    """Handle the 'gh' subcommand for cve-add-wizard"""
    # Validate input parameters
    if "," in priority_prefix:
        error("--priority-prefix cannot contain commas")

    if author != "" and not rePatterns["notes-author"].match(author):
        error("--author must match format: %s" % rePatterns["notes-author"].pattern)

    if not os.path.exists(alerts_file):
        error(f"File not found: {alerts_file}")

    _runWizard(
        alerts_file,
        default_labels,
        priority_prefix,
        author,
        disable_cli,
    )


def main_cve_add_wizard() -> None:
    """Entry point for cve-add-wizard command"""
    _experimental()

    # for better 'input()' line handling
    import readline

    _ = readline  # for pyright

    parser = argparse.ArgumentParser(
        prog="cve-add-wizard",
        description="Interactive wizard to create issues and CVE files from alerts",
    )

    # Add subcommands
    sub = parser.add_subparsers(dest="cmd", help="Available commands")

    # gh subcommand
    parser_gh = sub.add_parser(
        "gh",
        help="Process alerts for and with GitHub",
    )
    parser_gh.add_argument(
        "alerts_file",
        help="JSON file containing alerts from 'cve-report --alerts --with-templates-json'",
    )
    parser_gh.add_argument(
        "--default-labels",
        type=str,
        default="",
        help="Comma-separated list of default labels for GitHub issues (may be empty)",
    )
    parser_gh.add_argument(
        "--priority-prefix",
        type=str,
        default="",
        help="Prefix for priority labels (e.g., 'security/'; may be empty)",
    )
    parser_gh.add_argument(
        "--author",
        type=str,
        default="",
        help="Author attribution (GitHub username) for CVE notes",
    )
    parser_gh.add_argument(
        "--disable-cli",
        action="store_true",
        help="Disable the use of 'gh' CLI tool for handling GitHub issues",
    )

    args: argparse.Namespace = parser.parse_args()

    # Check if a subcommand was provided
    if not hasattr(args, "cmd") or args.cmd is None:
        parser.print_help()
        return

    # Route to appropriate handler
    if args.cmd == "gh":
        _mainCveAddWizardGh(
            args.alerts_file,
            args.default_labels,
            args.priority_prefix,
            args.author,
            args.disable_cli,
        )
