#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import copy
import datetime
from enum import Enum
import os
import pathlib
import requests
import sys
import textwrap
import time
from typing import (
    Any,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypedDict,
    Union,
)

from cvelib.cve import (
    CVE,
    checkSyntax,
    collectCVEData,
    collectGHAlertUrls,
    _parseFilterPriorities,
)
from cvelib.common import (
    cve_priorities,
    error,
    epochToISO8601,
    getConfigCveDataPaths,
    getConfigCompatUbuntu,
    getConfigTemplateURLs,
    readFile,
    rePatterns,
    updateProgress,
    warn,
    _experimental,
)
import cvelib.gar
from cvelib.github import GHDependabot, GHSecret, GHCode
from cvelib.net import requestGetRaw, ghAPIGetList
import cvelib.quay


#
# cve-report-updated-bugs
#

# TODO: pass these around
repos_all: Dict[str, Dict[str, Union[str, bool]]] = {}  # keys is list of repos
issues_ind: Dict[
    str, Mapping[str, Any]
] = {}  # keys are 'repo/num', values are arbitrary json docs from GitHub


class ReportOutput(Enum):
    OPEN = 1
    CLOSED = 2
    BOTH = 3


def _repoArchived(repo: Dict[str, Union[bool, str]]) -> bool:
    if "archived" in repo:
        return bool(repo["archived"])
    return False


def _repoSecretsScanning(repo: Dict[str, Union[bool, str]]) -> bool:
    if "secret_scanning" in repo and repo["secret_scanning"]:
        return True
    return False


# https://docs.github.com/en/rest/orgs?apiVersion=2022-11-28
def _getGHReposAll(org: str) -> Dict[str, Dict[str, Union[bool, str]]]:
    """Obtain the list of GitHub repos for the specified org"""
    global repos_all
    if len(repos_all) > 0:
        if sys.stdout.isatty():
            print("Using previously fetched list of repos")
        return copy.deepcopy(repos_all)

    # jsons is a single list of res.json()s that are alerts for these URLs
    jsons: List[Dict[str, Any]] = []
    _, jsons = ghAPIGetList("https://api.github.com/orgs/%s/repos" % org)

    for repo in jsons:
        if "name" not in repo:
            error(
                "could not find name in response json: '%s'" % repo
            )  # pragma: nocover
        name: str = repo["name"]

        # Collect interesting info for later use
        repos_all[name] = {}
        if "archived" in repo:
            repos_all[name]["archived"] = repo["archived"]

        if "private" in repo:
            repos_all[name]["private"] = repo["private"]

        if "security_and_analysis" not in repo:
            error(
                "could not find 'security_and_analysis' for '%s'. Do you have the right permissions?"
                % (name)
            )  # pragma: nocover
        if (
            "secret_scanning" in repo["security_and_analysis"]
            and "status" in repo["security_and_analysis"]["secret_scanning"]
            and repo["security_and_analysis"]["secret_scanning"]["status"] == "enabled"
        ):
            repos_all[name]["secret_scanning"] = True
        else:
            repos_all[name]["secret_scanning"] = False

    return copy.deepcopy(repos_all)


# https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28
def _getGHIssuesForRepo(
    repo: str,
    org: str,
    labels: List[str] = [],
    skip_labels: List[str] = [],
    since: int = 0,
) -> List[str]:
    """Obtain the list of GitHub issues for the specified repo and org"""
    url: str = "https://api.github.com/repos/%s/%s/issues" % (org, repo)
    params: Dict[str, Union[str, int]] = {
        "per_page": 100,
        "state": "all",
    }

    if since > 0:
        params["since"] = epochToISO8601(since)

    # Unfortunately, we have to do a separate query per label because sending
    # params["labels"] = ",".join(labels) doesn't work (the labels are ANDed).
    query_labels: List[str] = [""]
    if len(labels) > 0:
        query_labels = labels

    issues: Dict[str, List[str]] = {}  # keys are repos, values are lists of issue urls
    query_label: str
    for query_label in query_labels:
        # get a list of issues for each label
        if query_label != "":
            params["labels"] = query_label

        rc: int = 0
        jsons: List[Any] = []
        rc, jsons = ghAPIGetList(url, params=params, progress=False, do_exit=False)

        if rc == 404:
            warn("Skipping %s (%d)" % (url, rc))
            return []
        elif rc == 1 or rc == 410 or rc >= 400:
            return []

        issue: Dict[str, Any]
        for issue in jsons:
            # check if issue has any of the labels that we designated if
            # present, we should skip
            if len(skip_labels) > 0 and "labels" in issue:
                found: bool = False
                i: Dict[str, Any]
                for i in issue["labels"]:
                    if "name" in i and i["name"] in skip_labels:
                        found = True
                if found:
                    continue

            if "pull_request" in issue and len(issue["pull_request"]) > 0:
                continue  # skip pull requests

            if "html_url" in issue:
                if repo not in issues:
                    issues[repo] = []
                if issue["html_url"] not in issues[repo]:
                    issues[repo].append(issue["html_url"])

    if repo in issues:
        return sorted(copy.deepcopy(issues[repo]))
    return []  # repo with turned off issues


def _getKnownIssues(
    cves: List[CVE], filter_url: Optional[str] = None
) -> Dict[str, List[str]]:
    """Obtain the list of URLs in our CVE info"""

    def _collectable(url: str, filter: Optional[str]) -> bool:
        if rePatterns["github-issue"].match(url):
            if filter is None or "/%s/" % filter in url:
                return True
        return False

    urls: Dict[str, List[str]] = {}
    for cve in cves:
        for u in cve.references + cve.bugs:
            url: str = u.split()[0]
            if _collectable(url, filter_url):
                # strip off GH comments
                if url.startswith("https://github.com/") and "#" in url:
                    url = url.split("#")[0]
                if url not in urls:
                    urls[url] = []
                if cve.candidate not in urls[url]:
                    urls[url].append(cve.candidate)

    return urls


def getMissingReport(
    cves: List[CVE],
    org: str,
    repos: List[str] = [],
    excluded_repos: List[str] = [],
    labels: List[str] = [],
    skip_labels: List[str] = [],
    since: int = 0,
) -> None:
    """Compare list of issues in issue trackers against our CVE data"""
    known_urls: Dict[str, List[str]] = _getKnownIssues(cves, filter_url=org)

    repo_info: Dict[str, Dict[str, Union[bool, str]]] = {}
    fetch_repos: List[str] = repos

    if len(fetch_repos) == 0:
        repo_info = _getGHReposAll(org)
        fetch_repos = list(repo_info.keys())
    total: int = 1
    if len(fetch_repos) > 0:
        total = len(fetch_repos)

    name: str = ""
    gh_urls: List[str] = []

    count: int = 1
    for name in sorted(fetch_repos):
        if name in excluded_repos:
            continue
        if name in repo_info and _repoArchived(repo_info[name]):
            continue
        updateProgress(count / total, prefix="Collecting issues: ")
        count += 1

        url: str
        for url in _getGHIssuesForRepo(
            name,
            org,
            labels=labels,
            skip_labels=skip_labels,
            since=since,
        ):
            if url not in known_urls and url not in gh_urls:
                gh_urls.append(url)

    if len(gh_urls) == 0:
        print("No missing issues.")
    else:
        print("Issues missing from CVE data:")
        for url in gh_urls:
            print(" %s" % url)


# https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28
def _getGHAlertsEnabled(
    org: str, alert_type: str, repos: List[str] = [], excluded_repos: List[str] = []
) -> Tuple[List[str], List[str]]:
    """Obtain list of GitHub repositories with alerts enabled"""
    repo_info: Dict[str, Dict[str, Union[bool, str]]] = {}
    fetch_repos: List[str] = repos

    if len(fetch_repos) == 0:
        repo_info = _getGHReposAll(org)
        fetch_repos = list(repo_info.keys())

    enabled: List[str] = []
    disabled: List[str] = []

    # Unfortunately there isn't an API to tell us all the repos with dependabot
    # or code-scanning alerts, so get a list of URLs and then see if enabled or
    # not
    suffix: str = "vulnerability-alerts"
    if alert_type == "code-scanning":
        suffix = "code-scanning/alerts"

    count: int = 0
    for name in sorted(fetch_repos):
        if name in excluded_repos:
            continue
        if name in repo_info and _repoArchived(repo_info[name]):
            continue

        count += 1
        updateProgress(count / len(fetch_repos), prefix="Collecting repo status: ")

        url: str = "https://api.github.com/repos/%s/%s/%s" % (
            org,
            name,
            suffix,
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params: Dict[str, Union[str, int]] = {}

        res: requests.Response = requestGetRaw(url, headers=headers, params=params)
        if res.status_code == 204 or res.status_code == 200:
            # enabled
            enabled.append(name)
        elif res.status_code == 404 or (
            res.status_code == 403 and alert_type == "code-scanning"
        ):
            # 404 is disabled and 403 is disabled due to GitHub Advanced
            # Security not enabled
            disabled.append(name)
        else:  # pragma: nocover
            error("Problem fetching %s:\n%d - %s" % (url, res.status_code, res))

    return enabled, disabled


# https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28
def _getGHSecretsScanningEnabled(
    org: str, repos: List[str] = [], excluded_repos: List[str] = []
) -> Tuple[List[str], List[str]]:
    """Obtain list of GitHub repositories with secret scanning enabled"""
    enabled: List[str] = []
    disabled: List[str] = []

    # secret_scanning is under security_and_analysis in
    # https://api.github.com/orgs/ORG/repos, which _getGHReposAll() fetches so
    # just need to look through repo_info
    repo_info: Dict[str, Dict[str, Union[bool, str]]] = _getGHReposAll(org)
    for name in sorted(repo_info.keys()):
        if name in excluded_repos:
            continue
        elif len(repos) != 0 and name not in repos:
            continue
        elif len(repos) == 0 and _repoArchived(repo_info[name]):
            continue

        if _repoSecretsScanning(repo_info[name]):
            enabled.append(name)
        else:
            disabled.append(name)

    return enabled, disabled


def getGHAlertsStatusReport(
    org: str, repos: List[str] = [], excluded_repos: List[str] = []
) -> None:
    """Obtain list of repos that have vulnerability alerts enabled/disabled"""
    alert_type: str = ""
    for alert_type in ["code-scanning", "dependabot", "secret-scanning"]:
        enabled: List[str] = []
        disabled: List[str] = []
        if alert_type == "secret-scanning":
            enabled, disabled = _getGHSecretsScanningEnabled(
                org, repos, excluded_repos=excluded_repos
            )
        else:
            enabled, disabled = _getGHAlertsEnabled(
                org, alert_type, repos, excluded_repos=excluded_repos
            )
        for repo in sorted(enabled + disabled):
            print(
                "%s,%s,%s,https://github.com/%s/%s/settings/security_analysis"
                % (
                    alert_type,
                    "enabled" if repo in enabled else "disabled",
                    repo,
                    org,
                    repo,
                )
            )


def getUpdatedReport(
    cves: List[CVE], org: str, excluded_repos: List[str] = [], since: int = 0
) -> None:
    """Obtain list of URLs that have received an update since last run"""
    cachedGetGHIssuesForRepo: Dict[str, List[str]] = {}
    urls: Dict[str, List[str]] = _getKnownIssues(cves, filter_url=org)

    # find updates
    updated_urls: List[str] = []
    print("Collecting known issues:")
    for url in sorted(urls.keys()):
        # ['https:', '', 'github.com', '<org>', '<repo>', 'issues', '<num>']
        tmp: List[str] = url.split("/")

        repo: str = tmp[4]
        if repo in excluded_repos:
            continue

        if repo not in cachedGetGHIssuesForRepo:
            cachedGetGHIssuesForRepo[repo] = _getGHIssuesForRepo(
                repo,
                org,
                since=since,
            )

        if url in cachedGetGHIssuesForRepo[repo]:
            updated_urls.append(url)

    if len(updated_urls) == 0:
        print("No updated issues.")
    else:
        print("Updated issues:")
        for url in updated_urls:
            print(" %s (%s)" % (url, ", ".join(urls[url])))


#
# gh --alerts
#
def _printGHAlertsSummary(
    org: str, repo: str, alerts: List[Dict[str, str]], status: str
) -> None:
    """Print out the alert summary"""
    if status not in ["resolved", "updated"]:
        error("Unsupported alert status: %s" % status)
        return

    urls: List[str] = []
    print("%s %s alerts: %d" % (repo, status, len(alerts)))

    # for n in alert:
    for n in sorted(alerts, key=lambda i: (i["html_url"], i["created_at"])):
        url: str = "https://github.com/%s/%s/security/%s" % (org, repo, n["alert_type"])
        if url not in urls:
            urls.append(url)

        if n["alert_type"] == "dependabot":
            print("  %s" % n["dependabot_package_name"])
        elif n["alert_type"] == "code-scanning":
            print("  %s" % n["code_description"])
        elif n["alert_type"] == "secret-scanning":
            print("  %s" % n["secret_type_display_name"])

        print("    - severity: %s" % n["severity"])
        print("    - created: %s" % n["created_at"])

        if status == "resolved":
            if n["alert_type"] == "secret-scanning":
                print("    - resolved: %s" % n["resolved_at"])
                print("    - reason: %s" % n["resolution"])
                print("    - comment: %s" % n["resolution_comment"])
                if "resolved_by" in n and n["resolved_by"] is not None:
                    print("    - by: %s" % n["resolved_by"])
            else:
                print("    - dismissed: %s" % n["dismissed_at"])
                print("    - reason: %s" % n["dismissed_reason"])
                print("    - comment: %s" % n["dismissed_comment"])
                if "dismissed_by" in n and n["dismissed_by"] is not None:
                    print("    - by: %s" % n["dismissed_by"])

        if n["alert_type"] == "dependabot":
            print("    - %s" % n["dependabot_manifest_path"])
            print("    - advisory: %s" % n["security_advisory_ghsa_url"])

        print("    - url: %s" % (n["html_url"]))
        print("")

    if len(urls) > 0:
        print("  References:\n  - %s" % "\n  - ".join(sorted(urls)))
        print("")


def _printGHAlertsTemplates(
    org: str, repo: str, alert: List[Dict[str, str]], template_urls: List[str] = []
) -> None:
    """Print out the alerts issue templates"""
    sev: List[str] = ["unknown", "low", "medium", "high", "critical"]
    clause_txt: Dict[str, str] = {
        "dependabot": "Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.",
        "secret-scanning": "While any secrets should be removed from the repo, they will live forever in git history so please remember to rotate the secret too.",
        "code-scanning": "Code scanning only reported against the default branch so please be sure to check any other supported branches when researching/fixing.",
    }
    urls: List[str] = []
    highest: int = 0

    alert_types: List[str] = []
    references: List[str] = []
    advisories: List[str] = []
    html_items: List[str] = []
    txt_items: Dict[str, int] = {}
    clauses: List[str] = []
    for n in sorted(alert, key=lambda i: i["html_url"]):
        url: str = "https://github.com/%s/%s/security/%s" % (org, repo, n["alert_type"])
        if url not in urls:
            urls.append(url)

        ref = "%s" % (n["html_url"])
        if ref not in references:
            references.append(ref)
        if n["alert_type"] == "dependabot":
            adv: str = "%s (%s)" % (
                n["security_advisory_ghsa_url"],
                n["dependabot_package_name"],
            )
            if adv not in advisories:
                advisories.append(adv)

        if n["alert_type"] not in alert_types:
            alert_types.append(n["alert_type"])

        if clause_txt[n["alert_type"]] not in clauses:
            clauses.append(clause_txt[n["alert_type"]])

        display_name: str = ""
        if n["alert_type"] == "dependabot":
            display_name = n["dependabot_package_name"]
        elif n["alert_type"] == "code-scanning":
            display_name = n["code_description"]
        elif n["alert_type"] == "secret-scanning":
            display_name = n["secret_type_display_name"]

        s: str = "- [ ] [%s](%s) (%s)" % (display_name, ref, n["severity"])
        if s not in html_items:
            html_items.append(s)

        t: str = "- [ ] %s (%s)" % (display_name, n["severity"])
        if t not in txt_items:
            txt_items[t] = 1
        else:
            txt_items[t] += 1

        cur: int
        try:
            cur = sev.index(n["severity"])
        except ValueError:
            cur = sev.index("unknown")

        if cur > highest:
            highest = cur

    checklist: str = ""
    i: str
    for i in sorted(html_items):
        checklist += "%s\n" % i

    priority: str = sev[highest]
    if priority == "unknown":
        priority = "medium"

    plural: bool = len(alert) > 1

    print("## %s template" % repo)
    template: str = """Please address alert%s (%s) in %s

The following alert%s issued:
%s
Since a%s '%s' severity issue is present, tentatively adding the 'security/%s' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. %s

Thanks!

References:
 * %s%s
""" % (
        "s" if plural else "",
        ", ".join(sorted(alert_types)),
        repo,
        "s were" if plural else " was",
        checklist,
        "n" if sev.index("unknown") == highest else "",
        sev[highest],
        priority,
        " ".join(sorted(clauses)),
        "" if len(template_urls) == 0 else "%s\n * " % "\n * ".join(template_urls),
        "\n * ".join(sorted(urls)),
    )

    print(template)
    print("## end template")

    checklist: str = ""
    i: str
    for i in sorted(txt_items.keys()):
        if txt_items[i] > 1:
            checklist += " %s\n" % (i.replace("(", "(%d " % (txt_items[i])))
        else:
            checklist += " %s\n" % i
    now: datetime.datetime = datetime.datetime.now()
    print("\n## %s CVE template" % repo)
    print(
        """Candidate: %s
OpenDate: %s
CloseDate:
PublicDate:
CRD:
References:
 %s
Description:
 Please address alert%s in %s
%sGitHub-Advanced-Security:"""
        % (
            "CVE-%d-NNNN" % now.year,
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "\n ".join(references + sorted(advisories)),
            "s" if plural else "",
            repo,
            checklist,
        )
    )

    discovered_by: List[str] = []
    for n in sorted(alert, key=lambda i: i["html_url"]):
        s: str = " - type: %s\n" % n["alert_type"]

        if n["alert_type"] == "dependabot":
            if n["dependabot_package_name"].startswith("@"):
                s += '   dependency: "%s"\n' % n["dependabot_package_name"]
            else:
                s += "   dependency: %s\n" % n["dependabot_package_name"]
            s += "   detectedIn: %s\n" % n["dependabot_manifest_path"]
            if "gh-dependabot" not in discovered_by:
                discovered_by.append("gh-dependabot")
        elif n["alert_type"] == "code-scanning":
            s += "   description: %s\n" % n["code_description"]
            if "gh-code" not in discovered_by:
                discovered_by.append("gh-code")
        elif n["alert_type"] == "secret-scanning":
            s += "   secret: %s\n" % n["secret_type_display_name"]
            s += "   detectedIn: tbd\n"
            if "gh-secret" not in discovered_by:
                discovered_by.append("gh-secret")

        s += "   severity: %s\n" % n["severity"]
        if n["alert_type"] == "dependabot":
            s += "   advisory: %s\n" % n["security_advisory_ghsa_url"]
        s += "   status: needs-triage\n"
        s += "   url: %s" % n["html_url"]
        print(s)
    print(
        """Notes:
Mitigation:
Bugs:
Priority: %s
Discovered-by: %s
Assigned-to:
CVSS:

Patches_%s:
git/%s_%s: needs-triage"""
        % (
            priority,
            ", ".join(sorted(discovered_by)),
            repo,
            org,
            repo,
        )
    )
    print("## end CVE template")


def _parseAlert(alert: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    """Parse alert json into common format"""
    a: Dict[str, str] = {}

    # common dicts
    repo: str = alert["repository"]["name"]

    for k in ["dismissed_by", "resolved_by"]:
        if k in alert and alert[k] is not None:
            a[k] = alert[k]["login"]

    a["private"] = str(alert["repository"]["private"])

    # simple key/value
    for k in [
        "created_at",
        "dismissed_at",
        "dismissed_comment",
        "dismissed_reason",
        "fixed_at",
        "html_url",
        "published_at",
        "resolution",
        "resolved_at",
        "resolution_comment",
        "state",
        "updated_at",
        "withdrawn_at",
    ]:
        if k in alert:
            a[k] = alert[k]

    # codeql specific
    if "rule" in alert:
        a["alert_type"] = "code-scanning"
        a["severity"] = alert["rule"]["security_severity_level"]
        a["code_description"] = alert["rule"]["description"]

    # dependabot specific
    if "dependency" in alert:
        a["alert_type"] = "dependabot"
        a["dependabot_package_name"] = alert["dependency"]["package"]["name"]
        a["dependabot_manifest_path"] = alert["dependency"]["manifest_path"]
    if "security_advisory" in alert and alert["security_advisory"] is not None:
        # alert["security_advisory"] = None indicates a withdrawn alert
        a["severity"] = alert["security_advisory"]["severity"]
        a["security_advisory_ghsa_url"] = (
            "https://github.com/advisories/%s" % alert["security_advisory"]["ghsa_id"]
        )

    # secret scanning specific
    # NOTE: the location of the secret needs another API call. For now, skip
    if "secret_type_display_name" in alert:
        # if repo is public, suggest high priority, otherwise medium
        a["severity"] = "high"
        if a["private"].lower() == "true":
            a["severity"] = "medium"

        a["alert_type"] = "secret-scanning"
        a["secret_type_display_name"] = alert["secret_type_display_name"]

    # codeql allows 'null'
    if a["severity"] is None:
        a["severity"] = "unknown"

    return repo, copy.deepcopy(a)


# As of the 2022-11-28 API, alerts have a predictable json format so we can
# largely share alert fetching code
# https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28
# https://docs.github.com/en/rest/secret-scanning?apiVersion=2022-11-28
# https://docs.github.com/en/rest/code-scanning?apiVersion=2022-11-28
#
# dependabot
# [
#   {
#     "number": 20,
#     "state": "open",
#     "dependency": {
#       "package": {
#         "ecosystem": "...",
#         "name": "some-name"
#       },
#       "manifest_path": "/path/to/file",
#       "scope": "runtime"
#     },
#     "security_advisory": {
#       "ghsa_id": "GHSA-...",
#       "cve_id": "CVE-...",
#       "summary": "some summary",
#       "description": "some desc",
#       "severity": "high",
#       "identifiers": [
#         {
#           "value": "GHSA-...",
#           "type": "GHSA"
#         },
#         {
#           "value": "CVE-...",
#           "type": "CVE"
#         }
#       ],
#     "references": [
#       {
#         "url": "https://github.com/.../GHSA-..."
#       },
#       {
#         "url": "https://nvd.nist.gov/vuln/detail/CVE-..."
#       }
#       "published_at": "2022-02-16T22:36:21Z",
#       "updated_at": "2023-01-30T05:02:57Z",
#       "withdrawn_at": null,
#       "vulnerabilities": [
#         {
#           "package": {
#             "ecosystem": "...",
#             "name": "some-name"
#           },
#           "severity": "high",
#           "vulnerable_version_range": "< 1.2.3",
#           "first_patched_version": {
#             "identifier": "1.2.3"
#           }
#         }
#       ],
#       "cvss": {
#         ...
#       },
#       "cwes": [
#         ...
#       ]
#     },
#     "security_vulnerability": {
#       "package": {
#         "ecosystem": "...",
#         "name": "some-name"
#       },
#       "severity": "high",
#       "vulnerable_version_range": "< 1.2.3",
#       "first_patched_version": {
#         "identifier": "1.2.3"
#       }
#     },
#     "url": "https://api.github.com/repos/valid-org/valid-repo/dependabot/alerts/20",
#     "html_url": "https://github.com/valid-org/valid-repo/security/dependabot/20",
#     "created_at": "2023-05-23T12:17:56Z",
#     "updated_at": "2023-05-23T12:17:56Z",
#     "dismissed_at": null,
#     "dismissed_by": null,
#     "dismissed_reason": null,
#     "dismissed_comment": null,
#     "fixed_at": null,
#     "auto_dismissed_at": null,
#     "repository": {
#       ...
#       "name": "valid-repo",
#       "full_name": "valid-org/valid-repo",
#       "private": false,
#       "owner": {
#         ...
#       },
#       "html_url": "https://github.com/valid-org/valid-repo",
#       "url": "https://api.github.com/repos/valid-org/valid-repo",
#       ...
#     }
#   },
#   ...
#
# secret-scanning
# [
#   {
#     "number": 2,
#     "created_at": "2023-04-20T20:34:12Z",
#     "updated_at": "2023-04-21T17:01:49Z",
#     "url": "https://api.github.com/repos/valid-org/enterprise/secret-scanning/alerts/2",
#     "html_url": "https://github.com/valid-org/enterprise/security/secret-scanning/2",
#     "locations_url": "https://api.github.com/repos/valid-org/enterprise/secret-scanning/alerts/2/locations",
#     "state": "resolved",
#     "secret_type": "some-type",
#     "secret_type_display_name": "some display",
#     "secret": "...",
#     "resolution": "revoked",
#     "resolved_by": {
#       "login": "user",
#       ...
#     },
#     "resolved_at": "2023-04-21T17:01:49Z",
#     "resolution_comment": "https://github.com/valid-org/valid-repo/issues/447",
#     "push_protection_bypassed": false,
#     "push_protection_bypassed_by": null,
#     "push_protection_bypassed_at": null,
#     "repository": {
#       ...
#       "name": "valid-repo",
#       "full_name": "valid-org/valid-repo",
#       "private": false,
#       "owner": {
#         ...
#       },
#       "html_url": "https://github.com/valid-org/valid-repo",
#       "url": "https://api.github.com/repos/valid-org/valid-repo",
#       ...
#     }
#   },
#   ...
#
# code-scanning
# [
#   {
#     "number": 13,
#     "created_at": "2023-04-24T22:20:52Z",
#     "updated_at": "2023-05-25T16:27:42Z",
#     "url": "https://api.github.com/repos/valid-org/valid-repo/code-scanning/alerts/13",
#     "html_url": "https://github.com/valid-org/valid-repo/security/code-scanning/13",
#     "state": "dismissed",
#     "fixed_at": null,
#     "dismissed_by": {
#       "login": "user",
#       ...
#     },
#     "dismissed_at": "2023-04-25T15:50:37Z",
#     "dismissed_reason": "won't fix",
#     "dismissed_comment": "This doesn't contain sensitive info.",
#     "rule": {
#       "id": "some-id",
#       "severity": "error",
#       "description": "some desc",
#       "name": "some-name",
#       "tags": [...],
#       "security_severity_level": "high"
#     },
#     "tool": {
#        ...
#     },
#     "most_recent_instance": {
#        ...
#     },
#     ...
#     "repository": {
#       ...
#       "name": "valid-repo",
#       "full_name": "valid-org/valid-repo",
#       "private": false,
#       "owner": {
#         ...
#       },
#       "html_url": "https://github.com/valid-org/valid-repo",
#       "url": "https://api.github.com/repos/valid-org/valid-repo",
#       ...
#     }
#   },
#   ...
#
def _getGHAlertsAll(
    org: str, alert_types=["code-scanning", "dependabot", "secret-scanning"]
) -> Dict[str, List[Dict[str, str]]]:
    """Obtain the list of GitHub alerts for the specified org"""

    for a in alert_types:
        if a not in ["code-scanning", "dependabot", "secret-scanning"]:
            error("Unsupported alert type: %s" % a, do_exit=False)
            return {}

    # { "repo": [{ <alert1> }, { <alert2> }] }
    alerts: Dict[str, List[Dict[str, str]]] = {}

    # jsons is a single list of res.json()s that are alerts for these URLs
    jsons: List[Dict[str, str]] = []
    for alert_type in alert_types:
        _, tmp = ghAPIGetList(
            "https://api.github.com/orgs/%s/%s/alerts" % (org, alert_type)
        )
        jsons += copy.deepcopy(tmp)

    alert: Dict[str, Any] = {}
    for alert in jsons:
        repo: str = ""
        a: Dict[str, str] = {}
        repo, a = _parseAlert(alert)

        if repo not in alerts:
            alerts[repo] = []
        alerts[repo].append(a)

    return copy.deepcopy(alerts)


def getGHAlertsReport(
    cves: List[CVE],
    org: str,
    since: int = 0,
    repos: List[str] = [],
    excluded_repos: List[str] = [],
    with_templates: bool = False,
    alert_types: List[str] = [],
    template_urls: List[str] = [],
) -> None:
    """Show GitHub alerts"""
    since_str: str = epochToISO8601(since)

    # find updates
    updated: Dict[str, List[Dict[str, str]]] = {}
    resolved: Dict[str, List[Dict[str, str]]] = {}

    # collect the alerts we know about
    knownAlerts: Set[str]
    knownAlerts, _ = collectGHAlertUrls(cves)

    alerts: Dict[str, List[Dict[str, str]]] = {}
    if len(alert_types) > 0:
        alerts = _getGHAlertsAll(org, alert_types=alert_types)
    else:
        alerts = _getGHAlertsAll(org)

    repo: str
    for repo in alerts:
        if len(repos) > 0 and repo not in repos:
            continue
        if len(excluded_repos) > 0 and repo in excluded_repos:
            continue

        for alert in alerts[repo]:
            if (
                "dismissed_at" in alert
                and alert["dismissed_at"] is not None
                and alert["dismissed_at"] > since_str
            ):
                if repo not in resolved:
                    resolved[repo] = []
                resolved[repo].append(alert)
            elif (
                "resolved_at" in alert
                and alert["resolved_at"] is not None
                and alert["resolved_at"] > since_str
            ):
                if repo not in resolved:
                    resolved[repo] = []
                resolved[repo].append(alert)
            elif "created_at" in alert and alert["created_at"] > since_str:
                if alert["html_url"] in knownAlerts:
                    warn(
                        "found previously known url with newer createdAt: %s (skipping)"
                        % alert["html_url"]
                    )
                    continue

                if repo not in updated:
                    updated[repo] = []

                updated[repo].append(alert)

    if len(updated) == 0:
        print("No alerts for the specified repos.")
    else:
        print("Alerts:")
        for repo in sorted(updated.keys()):
            if with_templates:
                _printGHAlertsTemplates(org, repo, updated[repo], template_urls)
                print("")
            _printGHAlertsSummary(org, repo, updated[repo], "updated")

    if len(resolved) > 0:
        print("Resolved alerts:")
        for repo in sorted(resolved.keys()):
            print("")
            if with_templates:
                _printGHAlertsTemplates(org, repo, resolved[repo], template_urls)
                print("")
            _printGHAlertsSummary(org, repo, resolved[repo], "resolved")


def getOCIReports(
    cves: List[CVE],
    registry: str,
    namespace: str,
    images: List[str] = [],
    excluded_images: List[str] = [],
    with_templates: bool = False,
    template_urls: List[str] = [],
    raw: bool = False,
    fixable: bool = True,
    filter_priority: Optional[str] = None,
) -> None:
    """Show OCI reports"""

    # if no priority filter, default to all priorities
    priorities: List[str] = cve_priorities
    if filter_priority is not None:
        priorities = _parseFilterPriorities(filter_priority)

    reports: Dict[str, str] = {}
    for img in images:
        # XXX: implement as interfaces
        if registry == "quay":
            reports[img] = cvelib.quay.getQuaySecurityReport(
                "%s/%s" % (namespace, img),
                raw=raw,
                fixable=fixable,
                with_templates=with_templates,
                template_urls=template_urls,
                priorities=priorities,
            )
        elif registry == "gar":
            reports[img] = cvelib.gar.getGARSecurityReport(
                "%s/%s" % (namespace, img),
                raw=raw,
                fixable=fixable,
                with_templates=with_templates,
                template_urls=template_urls,
                priorities=priorities,
            )

    s: str = ""
    # output a list of jsons
    if raw:
        jsons: List[str] = []
        for r in sorted(reports):
            if reports[r] != "":
                jsons.append(reports[r])
        s = "[%s]" % ",".join(jsons)
    else:
        first: bool = True
        for r in sorted(reports):
            if not first:
                s += "\n\n"
            else:
                first = False
            s += "# %s\n%s" % (r, reports[r])
    print(s)


#
# cve-report
#
class _statsUniqueCVEsPriorityCounts(TypedDict):
    """Type hinting for priorities in _statsUniqueCVEsPkgSoftware"""

    num: int
    cves: List[str]


class _statsUniqueCVEsPkgSoftware(TypedDict):
    """Type hinting for _readStatsUniqueCVEs()"""

    deps: List[str]
    secrets: List[str]
    negligible: _statsUniqueCVEsPriorityCounts
    low: _statsUniqueCVEsPriorityCounts
    medium: _statsUniqueCVEsPriorityCounts
    high: _statsUniqueCVEsPriorityCounts
    critical: _statsUniqueCVEsPriorityCounts
    tags: Dict[str, List[str]]


# _readStatsUniqueCVEs() takes the list of provided CVEs and generates a stats
# dict:
#   stats = {
#     pkg.software: {          // _statsUniqueCVEsPkgSoftware
#       "deps": [<candidate>]
#       "secrets": [<candidate>]
#       "<priority>": {        // _statsUniqueCVEsPriorityCounts
#         "num": int,
#         "cves": [<candidate>]
#       },
#       "tags": {
#         "<tag>": [<candidate>]
#       },
#     }
# While the results of collectCVEData() is typically what is passed into 'cves'
# and those CVEs may already be filtered, allow filtering by status even more
# to allow not having to call collectCVEData() twice.
def _readStatsUniqueCVEs(
    cves: List[CVE],
    filter_status: Optional[List[str]] = None,
) -> Dict[str, _statsUniqueCVEsPkgSoftware]:
    """Read in stats by unique CVE and discovered-by dependabot and secrets"""
    stats: Dict[str, _statsUniqueCVEsPkgSoftware] = {}
    for cve in cves:
        last_software: str = ""
        for pkg in cve.pkgs:
            if filter_status is not None and pkg.status not in filter_status:
                continue

            priority: str = cve.priority
            if pkg.software in pkg.priorities:
                priority = pkg.priorities[pkg.software]

            # only count an open CVE once per software/priority
            if last_software == pkg.software:
                continue
            last_software = pkg.software

            if pkg.software not in stats:
                stats[pkg.software] = _statsUniqueCVEsPkgSoftware(
                    deps=[],
                    secrets=[],
                    negligible=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    low=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    medium=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    high=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    critical=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    tags={},
                )

            if pkg.software in pkg.tags:
                for tag in pkg.tags[pkg.software]:
                    if tag not in stats[pkg.software]["tags"]:
                        stats[pkg.software]["tags"][tag] = []
                    stats[pkg.software]["tags"][tag].append(cve.candidate)

            stats[pkg.software][priority]["num"] += 1
            stats[pkg.software][priority]["cves"].append(cve.candidate)

            if (
                "gh-dependabot" in cve.discoveredBy.lower()
                and cve.candidate not in stats[pkg.software]["deps"]
            ):
                stats[pkg.software]["deps"].append(cve.candidate)

            if (
                "gh-secret" in cve.discoveredBy.lower()
                and cve.candidate not in stats[pkg.software]["secrets"]
            ):
                stats[pkg.software]["secrets"].append(cve.candidate)

    return stats


def getHumanReportOpenByPkgPriority(
    stats: Dict[str, _statsUniqueCVEsPkgSoftware]
) -> None:
    """Show report of open issues by package priority"""
    maxlen: int = 30
    headerStr: str = (
        "{pkg:%d} {critical:>10s} {high:>10s} {medium:>10s} {low:>10s} {negligible:>10s}"
        % maxlen
    )
    print(
        headerStr.format(
            pkg="Package",
            critical="Critical",
            high="High",
            medium="Medium",
            low="Low",
            negligible="Negligible",
        )
    )

    tableStr: str = (
        "{pkg:%ds} {critical:>10d} {high:>10d} {medium:>10d} {low:>10d} {negligible:>10d}"
        % maxlen
    )
    table_f: object = tableStr.format
    totals: Dict[str, int] = {}
    for pri in cve_priorities:
        totals[pri] = 0

    for p in sorted(stats):
        print(
            table_f(
                pkg=(p[: maxlen - 3] + "...") if len(p) > maxlen else p,
                critical=stats[p]["critical"]["num"],
                high=stats[p]["high"]["num"],
                medium=stats[p]["medium"]["num"],
                low=stats[p]["low"]["num"],
                negligible=stats[p]["negligible"]["num"],
            )
        )
        for pri in cve_priorities:
            totals[pri] += stats[p][pri]["num"]

    print(
        table_f(
            pkg="Total:",
            critical=totals["critical"],
            high=totals["high"],
            medium=totals["medium"],
            low=totals["low"],
            negligible=totals["negligible"],
        )
    )


def getHumanReport(
    cves: List[CVE],
) -> None:
    """Show report of open and closed issues"""
    stats_open: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves,
    )
    print("# Unique open issues by software")
    getHumanReportOpenByPkgPriority(stats_open)

    print("\n# Unique closed issues by software")
    stats_closed: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves,
        filter_status=["released"],
    )
    getHumanReportOpenByPkgPriority(stats_closed)


class _humanTodoScores(TypedDict):
    """Type hinting for getHumanTodo()"""

    score: int
    msg: str


def getHumanTodo(
    cves: List[CVE],
) -> None:
    """Show report of open items in todo list format"""
    stats_open: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves,
    )
    points: Dict[str, int] = {
        "critical": 200,
        "high": 100,
        "medium": 50,
        "low": 10,
        "negligible": 0,
    }

    scores: Dict[str, _humanTodoScores] = {}
    sw: str
    for sw in stats_open.keys():
        score: int = 0

        s: str = ""
        p: str
        for p in cve_priorities:
            score += stats_open[sw][p]["num"] * points[p]
            if stats_open[sw][p]["num"] > 0:
                s += "%d %s, " % (stats_open[sw][p]["num"], p)
        scores[sw] = _humanTodoScores(score=score, msg="%s: %s" % (sw, s[:-2]))

    # descending sorted by score then ascending by key ('sw')
    v: _humanTodoScores
    for (_, v) in sorted(scores.items(), key=lambda k: (-k[1]["score"], k)):
        print("%-8d %s" % (v["score"], v["msg"]))


def getHumanSoftwareInfo(
    cves: List[CVE],
    packages: str = "",
) -> None:
    """Show report of open items by software and priority"""
    pkgs: Optional[Set[str]] = _parseSoftwareArg(packages)
    stats_open: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves,
    )

    sw: str
    for sw in sorted(stats_open.keys()):
        if pkgs is not None and sw not in pkgs:
            continue
        print("%s:" % sw)
        p: str
        for p in cve_priorities:
            if stats_open[sw][p]["num"] > 0:
                print("  %s:" % p)
                for cve in sorted(stats_open[sw][p]["cves"]):
                    print("    %s" % cve)


def _parseSoftwareArg(p: str) -> Optional[Set[str]]:
    """Read the 'packages file' (a list of packages, one per line)"""
    pkgs: Optional[Set[str]] = None
    if p:
        if os.path.exists(p):
            pkgs = readFile(p)
        else:  # try to parse comma-separated list
            pkgs = set(p.split(","))

    return pkgs


def getHumanSummary(
    cves: List[CVE],
    packages: str = "",
    report_output: ReportOutput = ReportOutput.OPEN,
) -> None:
    """Show report in summary format"""

    def _output(
        stats: Dict[str, _statsUniqueCVEsPkgSoftware],
        state: str,
        pkgs: Optional[Set[str]] = None,
    ):
        maxlen: int = 30
        tableStr: str = "{pri:10s} {repo:%ds} {cve:25s} {extra:s}" % maxlen
        table_f: object = tableStr.format

        lines_open: Dict[str, Dict[str, List[str]]] = {}
        totals: Dict[str, Dict[str, int]] = {
            "critical": {"num": 0, "num_repos": 0},
            "high": {"num": 0, "num_repos": 0},
            "medium": {"num": 0, "num_repos": 0},
            "low": {"num": 0, "num_repos": 0},
            "negligible": {"num": 0, "num_repos": 0},
        }
        repo: str
        for repo in sorted(stats):
            # skip repos not in the list we want to report on
            if pkgs is not None and repo not in pkgs:
                continue

            priority: str
            for priority in stats[repo]:
                if priority in ["deps", "secrets", "tags"]:
                    continue

                if stats[repo][priority]["num"] > 0:
                    if priority not in lines_open:
                        lines_open[priority] = {}
                    lines_open[priority][repo] = stats[repo][priority]["cves"]

                    totals[priority]["num"] += len(stats[repo][priority]["cves"])
                    totals[priority]["num_repos"] += 1

        print("# %s\n" % state.capitalize())
        print(
            table_f(pri="Priority", repo="Repository", cve="Issue", extra="").rstrip()
        )
        print(
            table_f(pri="--------", repo="----------", cve="-----", extra="").rstrip()
        )
        for priority in cve_priorities:
            if priority not in lines_open:
                continue
            for repo in sorted(lines_open[priority]):
                for cve in sorted(lines_open[priority][repo]):
                    # print("%s\t%s\t%s" % (priority, repo, cve))
                    extras: List[str] = []

                    if cve in stats[repo]["deps"]:
                        extras.append("dependabot")
                    if cve in stats[repo]["secrets"]:
                        extras.append("secret-scanning")
                    for tag in stats[repo]["tags"]:
                        if cve in stats[repo]["tags"][tag]:
                            extras.append(tag)

                    extra: str = ""
                    if len(extras) > 0:
                        extra = "(%s)" % ", ".join(extras)

                    print(
                        table_f(
                            pri=priority,
                            repo=(repo[: maxlen - 3] + "...")
                            if len(repo) > maxlen
                            else repo,
                            cve=cve,
                            extra=extra,
                        ).rstrip()
                    )

        print("\nTotals:")
        for priority in cve_priorities:
            print(
                "- %s: %d in %d repos"
                % (priority, totals[priority]["num"], totals[priority]["num_repos"])
            )

    pkgs: Optional[Set[str]] = _parseSoftwareArg(packages)

    if report_output == ReportOutput.OPEN or report_output == ReportOutput.BOTH:
        stats_open: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
            cves,
            filter_status=["needs-triage", "needed", "pending"],
        )
        _output(stats_open, "open", pkgs)

    if report_output == ReportOutput.CLOSED or report_output == ReportOutput.BOTH:
        if report_output == ReportOutput.BOTH:
            print("\n")
        stats_closed: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
            cves,
            filter_status=["released"],
        )
        _output(stats_closed, "closed", pkgs)


# line protocol
# We plan to query on priority, status, product and where so put them as tags
#
#   <measurement>,priority=X,status=X,product=X,where=X id=X software=X modifier=X
#
# Note: the concept of 'team' will be handled within the flux
def _readStatsLineProtocol(
    cves: List[CVE],
    measurement="cveLog",
    base_timestamp: Optional[int] = None,
    pkgs: Optional[Set[str]] = None,
) -> List[str]:
    """Obtain InfluxDB line protocol from stats"""
    stats: List[str] = []
    lp_f: object = '{measurement},priority={priority},status={status},product={product},where={where} id="{id}",software="{software}",modifier="{modifier}" {timestamp}'.format

    base_tm: Optional[int] = None
    if base_timestamp is not None:
        if not isinstance(base_timestamp, int) or base_timestamp < 0:
            raise ValueError
        base_tm = int(time.mktime(time.gmtime(base_timestamp))) * 1000 * 1000 * 1000

    # XXX: perhaps use a timestamp relative to the mtime of the file or git
    # commit (that would rotate out though with retention policy)
    for cve in cves:
        for pkg in cve.pkgs:
            if pkgs is not None and pkg.software not in pkgs:
                continue

            priority: str = cve.priority
            if pkg.software in pkg.priorities:
                priority = pkg.priorities[pkg.software]

            timestamp: int
            if base_tm is None:
                timestamp = int(time.time_ns())
            else:
                timestamp = base_tm
                base_tm += 1

            where: str = pkg.where
            if where == "":
                where = "unspecified"

            stats.append(
                lp_f(
                    measurement=measurement,
                    priority=priority,
                    status=pkg.status,
                    product=pkg.product,
                    where=where,
                    id=cve.candidate,
                    software=pkg.software,
                    modifier=pkg.modifier,
                    timestamp=timestamp,
                )
            )

    return stats


def getInfluxDBLineProtocol(
    cves: List[CVE],
    packages: str = "",
    base_timestamp: Optional[int] = None,
) -> None:
    """Show report of open items in InfluxDB line protocol format"""
    pkgs: Optional[Set[str]] = _parseSoftwareArg(packages)
    stats_open: List[str] = _readStatsLineProtocol(
        cves,
        base_timestamp=base_timestamp,
        pkgs=pkgs,
    )
    for s in stats_open:
        print(s)


# _readStatsGHAS() takes the list of provided CVEs and generates a stats
# dict:
#   stats = {
#     pkg.software: {
#       "<dependabot|secret>": {
#         "<dependency or secret name>": {
#           "<status>": {
#             "<priority>": {
#               "num": <num>,
#               "cves": [<candidate>]
#           }
#         }
#       }
#     }
#   }
def _readStatsGHAS(
    cves: List[CVE],
    pkg_filter_status: Optional[List[str]] = None,
    ghas_filter_status: Optional[List[str]] = None,
) -> Dict[str, _statsUniqueCVEsPkgSoftware]:
    """Read in stats by GHAS"""

    def _find_adjusted_priority(priority: str, sev: str) -> str:
        if cve_priorities.index(sev) > cve_priorities.index(priority):
            return sev
        return priority

    # TODO: type hint
    stats = {}
    for cve in cves:
        alert: Union[GHDependabot, GHSecret, GHCode]
        for alert in cve.ghas:
            for pkg in cve.pkgs:
                if (
                    pkg_filter_status is not None
                    and pkg.status not in pkg_filter_status
                ):
                    continue

                ghas_status: str = alert.status.split()[0]
                if (
                    ghas_filter_status is not None
                    and ghas_status not in ghas_filter_status
                ):
                    continue

                priority: str = cve.priority
                if pkg.software in pkg.priorities:
                    priority = pkg.priorities[pkg.software]
                if isinstance(alert, GHDependabot):
                    priority = _find_adjusted_priority(priority, alert.severity)

                sw = (
                    "%s/%s" % (pkg.software, pkg.modifier)
                    if pkg.modifier != ""
                    else pkg.software
                )
                if sw not in stats:
                    stats[sw] = {}

                alert_type = "dependabot"
                if isinstance(alert, GHSecret):
                    alert_type = "secret-scanning"
                elif isinstance(alert, GHCode):
                    alert_type = "code-scanning"

                if alert_type not in stats[sw]:
                    stats[sw][alert_type] = {}

                what: str
                if isinstance(alert, GHSecret):
                    what = alert.secret
                elif isinstance(alert, GHCode):
                    what = alert.description
                else:
                    what = alert.dependency
                if what not in stats[sw][alert_type]:
                    stats[sw][alert_type][what] = {}

                if priority not in stats[sw][alert_type][what]:
                    stats[sw][alert_type][what][priority] = {"num": 0, "cves": []}

                stats[sw][alert_type][what][priority]["num"] += 1
                if cve.candidate not in stats[sw][alert_type][what][priority]["cves"]:
                    stats[sw][alert_type][what][priority]["cves"].append(cve.candidate)

    return stats


def getHumanSummaryGHAS(
    cves: List[CVE],
    packages: str = "",
    report_output: ReportOutput = ReportOutput.OPEN,
) -> None:
    """Show GitHub Advanced Security report in summary format"""

    def _output(stats, state: str, pkgs: Optional[Set[str]] = None):
        maxlen: int = 20
        maxlen_aff: int = 35
        tableStr: str = "{pri:10s} {repo:%ds} {aff:%ds} {cve:25s} {extra:s}" % (
            maxlen,
            maxlen_aff,
        )
        table_f: object = tableStr.format

        # TODO: cleanup Any
        lines: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}
        totals: Dict[str, Dict[str, int]] = {
            "critical": {"num": 0, "num_repos": 0},
            "high": {"num": 0, "num_repos": 0},
            "medium": {"num": 0, "num_repos": 0},
            "low": {"num": 0, "num_repos": 0},
            "negligible": {"num": 0, "num_repos": 0},
        }

        last: str = ""
        for priority in cve_priorities:
            for repo in sorted(stats):
                # skip repos not in the list we want to report on
                if pkgs is not None and repo not in pkgs:
                    continue

                typ: str
                for typ in stats[repo]:
                    affected: str
                    for affected in stats[repo][typ]:
                        if (
                            priority not in stats[repo][typ][affected]
                            or stats[repo][typ][affected][priority]["num"] < 1
                        ):
                            continue

                        if priority not in lines:
                            lines[priority] = {}
                        if repo not in lines[priority]:
                            lines[priority][repo] = {}
                        if affected not in lines[priority][repo]:
                            lines[priority][repo][affected] = {
                                "typ": typ,
                                "cves": [],
                                "num_affected": 0,
                            }
                        cves: List[str] = stats[repo][typ][affected][priority]["cves"]
                        lines[priority][repo][affected]["cves"] = cves

                        num: int = stats[repo][typ][affected][priority]["num"]
                        totals[priority]["num"] += num

                        lines[priority][repo][affected]["num_affected"] += num
                        if repo != last:
                            totals[priority]["num_repos"] += 1
                            last = repo

        print("# %s\n" % state.capitalize())
        print(
            table_f(
                pri="Priority", repo="Repository", aff="Affected", cve="CVEs", extra=""
            ).rstrip()
        )
        print(
            table_f(
                pri="--------", repo="----------", aff="--------", cve="----", extra=""
            ).rstrip()
        )
        for priority in cve_priorities:
            if priority not in lines:
                continue
            repo: str
            for repo in sorted(lines[priority]):
                affected: str
                for affected in sorted(lines[priority][repo]):
                    num_aff: str = ""
                    if lines[priority][repo][affected]["num_affected"] > 1:
                        num_aff = (
                            " (%d)" % lines[priority][repo][affected]["num_affected"]
                        )

                    aff = (
                        (affected[: maxlen_aff - (3 + len(num_aff))] + "...")
                        if len(affected) > (maxlen_aff - len(num_aff))
                        else affected
                    )
                    aff += num_aff
                    print(
                        table_f(
                            pri=priority,
                            repo=(repo[: maxlen - 3] + "...")
                            if len(repo) > maxlen
                            else repo,
                            aff=aff,
                            cve=", ".join(lines[priority][repo][affected]["cves"]),
                            extra="(%s)" % lines[priority][repo][affected]["typ"],
                        ).rstrip()
                    )

        print("\nTotals:")
        for priority in cve_priorities:
            print(
                "- %s: %d in %d repos"
                % (priority, totals[priority]["num"], totals[priority]["num_repos"])
            )

    pkgs: Optional[Set[str]] = _parseSoftwareArg(packages)

    if report_output == ReportOutput.OPEN or report_output == ReportOutput.BOTH:
        # report on a) packages that are open and b) alerts that are needed
        stats_open = _readStatsGHAS(
            cves,
            pkg_filter_status=["needed", "needs-triage", "pending"],
            ghas_filter_status=["needed", "needs-triage"],
        )
        _output(stats_open, "open", pkgs)

    if report_output == ReportOutput.CLOSED or report_output == ReportOutput.BOTH:
        if report_output == ReportOutput.BOTH:
            print("\n")
        # report on a) packages that are closed (but not deferred) and b)
        # alerts that are released/dismissed. We report on ignored issues since
        # we'll sometimes use 'ignored' for CVE status with 'dismissed' as GHAS
        # status.
        stats_closed = _readStatsGHAS(
            cves,
            pkg_filter_status=["released", "not-affected", "ignored"],
            ghas_filter_status=["released", "dismissed"],
        )
        _output(stats_closed, "closed", pkgs)


#
# cve-report gh --active|--archived
#
def getReposReport(org: str, archived: Optional[bool] = False) -> None:
    """Show list of active and archived repos"""
    repos: Dict[str, Dict[str, Union[bool, str]]] = _getGHReposAll(org)
    for name in sorted(repos.keys()):
        if archived and _repoArchived(repos[name]):
            print(name)
        elif not archived and not _repoArchived(repos[name]):
            print(name)


def _main_report_parse_args(sysargs: Sequence[str]) -> argparse.Namespace:
    """Parse args for main_report()"""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="cve-report",
        description="Generate reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
Use -h or --help for additional options for report commands (positional
arguments). Eg:

  $ cve-report summary -h


Example usage:

# Summary reports

  # open issues
  $ cve-report summary

  # open issues filtered by product git/org and oci/dockerhub
  $ cve-report summary --filter-product=git/myorg,oci/dockerhub

  # closed issues
  $ cve-report summary --closed

  # open issues for just 'foo' and 'bar' software (repos)
  $ cve-report summary --software=foo,bar

  # similary, but with software (repo) list from a file
  $ cve-report summary --software=/path/to/software/list

  # open GitHub Advanced Security (GHAS) issues
  $ cve-report summary --ghas

  # counts of unique issues by priority for each software
  $ cve-report summary --unique


# Software report

  # open issues by software and priority
  $ cve-report sw

  # similarly, but for just 'foo' and 'bar' software (repos)
  $ cve-report sw --software=foo,bar

  # similarly, but with software (repo) list from a file
  $ cve-report sw --software=/path/to/software/list

# Todo list with heuristic scoring

  $ cve-report todo


# InfluxDB line protocol

  $ cve-report influxdb
  $ cve-report influxdb --starttime=$(date --date "8 days ago" "+%s")


# GitHub-specific reports

  # show active repos for org
  $ cve-report gh --org <org> --status=active

  # show archived repos for org
  $ cve-report gh --org <org> --status=archived

  # show GHAS alerts for org
  $ cve-report gh --org <org> --alerts --since YYYY-MM-DD

  # show GitHub dependabot alerts for org with template text
  $ cve-report gh --org <org> --alerts=dependabot --with-templates --since YYYY-MM-DD

  # show GHAS alerts for foo and bar repos in org
  $ cve-report gh --org <org> --alerts --software=foo,bar --since YYYY-MM-DD

  # show GitHub issue URLs with label 'security' that aremissing from CVE data
  $ cve-report gh --org <org> --missing --labels=security --since YYYY-MM-DD

  # show GitHub issue URLs from the foo and bar repos with label 'security'
  # that are missing from CVE data
  $ cve-report gh --org <org> --missing --labels=security --software=foo,bar --since YYYY-MM-DD

  # show GitHub issue URLs with label 'security' updated since YYYY-MM-DD
  $ cve-report gh --org <org> --updated --labels=security --since YYYY-MM-DD

  # show GitHub issue URLs with label 'security' updated since YYYY-MM-DD that
  # aren't for the baz and norf repos.
  $ cve-report gh --org <org> --updated --labels=security --excluded-repos=baz,norf --since YYYY-MM-DD

  # Show a combined report (alerts, updated and missing)
  $ cve-report gh --org <org> --alerts --updated --missing --labels=security --since YYYY-MM-DD

# OCI reports

  # Show list of OCI image names
  $ cve-report gar --namespace <project>/<location> --list  # eg, foo/us
  $ cve-report quay --namespace <org> --list

  # Show list of GAR repositories
  $ cve-report gar --namespace <project/location> --list-repos

  # Show latest SHA256 digest with a scan result for image name
  $ cve-report gar --namespace <project>/<location> --list-digest <repo>/<name>
  $ cve-report quay --namespace <org> --list-digest <name>

  # Show SHA256 digest for image name with tag
  $ cve-report gar --namespace <project>/<location> --list-digest <repo>/<name>:<tag>
  $ cve-report quay --namespace <org> --list-digest <name>:<tag>

  # Show security report for image name with digest
  $ cve-report gar --alerts --namespace <project>/<location> --image-names <repo>/<name>@<digest>
  $ cve-report quay --alerts --namespace <org> --image-names <name>@<digest>

  # Eg, to research the 'foo' project with location 'us' in GAR:
  # - find all the container images
  $ cve-report gar --namespace foo/us --list
  ...
  foo/us/bar/bar
  foo/us/bar/baz
  # - find a digest for an image
  $ cve-report gar --namespace foo/us --list-digest bar/baz
  sha256:791be3...
  # - pull the report for the image with a particular digest
  $ cve-report gar --alerts --namespace foo/us --image-names bar/baz@sha256:791be3...
  qux   1.2.3-1        needed (low,medium)
  norf  2.3.4+deb11u1  needed (low,medium)
        """
        ),
    )

    def _add_common_filter(p):
        p.add_argument(
            "--filter-product",
            dest="filter_product",
            help="comma-separated list of PRODUCTs to limit by (eg 'git/org')",
            metavar="PRODUCT",
            type=str,
            default=None,
        )
        p.add_argument(
            "--filter-priority",
            dest="filter_priority",
            help="comma-separated list of PRIORITYs to limit by (eg 'critical,high' or '-negligible')",
            metavar="PRIORITY",
            type=str,
            default=None,
        )
        p.add_argument(
            "--filter-tag",
            dest="filter_tag",
            help="comma-separated list of TAGs to limit by (eg 'apparmor,pie' or '-limit-report')",
            metavar="TAG",
            type=str,
            default=None,
        )
        p.add_argument(
            "-s",
            "--software",
            dest="software",
            help="comma-separated list of software (repos) or PATH to file with software list (newline separated) to limit by (eg, 'foo,bar')",
            type=str,
            default=None,
        )

    def _add_issues_filter(p):
        p.add_argument(
            "--open",
            dest="open",
            help="show open issues",
            action="store_true",
        )
        p.add_argument(
            "--closed",
            dest="closed",
            help="show closed issues",
            action="store_true",
        )
        p.add_argument(
            "--all",
            dest="all",
            help="show all issues",
            action="store_true",
        )

    def _add_common_oci(p, what: str, where: str, imgname: str):
        p.add_argument(
            "--list",
            dest="list",
            help="list %s OCI image names" % what,
            action="store_true",
        )
        bare_imgname: str = imgname.split("@")[0]
        p.add_argument(
            "--list-digest",
            dest="list_digest",
            help="list %s OCI image digest (eg, SHA256) for NAME (eg %s)"
            % (what, "%s" % bare_imgname),
            metavar="NAME",
            type=str,
        )
        p.add_argument(
            "--alerts",
            dest="alerts",
            help="show %s security reports" % what,
            action="store_true",
        )
        p.add_argument(
            "--filter-priority",
            dest="filter_priority",
            help="comma-separated list of PRIORITYs to limit by (eg 'critical,high' or '-negligible')",
            metavar="PRIORITY",
            type=str,
            default=None,
        )
        p.add_argument(
            "--with-templates",
            dest="with_templates",
            help="show issue templates with %s security reports" % what,
            action="store_true",
        )
        p.add_argument(
            "--raw",
            dest="raw",
            help="display raw JSON for %s security reports" % what,
            action="store_true",
        )
        p.add_argument(
            "--all",
            dest="all",
            help="also show unfixable items in %s security reports" % what,
            action="store_true",
        )
        p.add_argument(
            "--namespace",
            dest="namespace",
            help="%s namespace (eg %s)" % (what, where),
            metavar=where,
            type=str,
            default=None,
        )
        p.add_argument(
            "--images",
            dest="images",
            help="comma-separated list of %s image names or PATH to file with %s image name list (newline separated) to limit by (eg, '%s,%s:tag,%s')"
            % (what, what, bare_imgname, bare_imgname, imgname),
            type=str,
            metavar="NAMES",
            default=None,
        )
        p.add_argument(
            "--excluded-images",
            dest="excluded_images",
            help="comma-separated list of %s image names to exclude (eg, '%s,%s1')"
            % (what, bare_imgname, bare_imgname),
            type=str,
            metavar="NAMES",
            default=None,
        )

    sub = parser.add_subparsers(dest="cmd")

    # summary
    parser_summary = sub.add_parser("summary")
    _add_common_filter(parser_summary)
    _add_issues_filter(parser_summary)
    parser_summary.add_argument(
        "--ghas",
        dest="ghas",
        help="show GitHub Advanced Security issues",
        action="store_true",
    )
    parser_summary.add_argument(
        "--unique",
        dest="unique",
        help="show unique issues by software (repos)",
        action="store_true",
    )

    # influxdb
    parser_influxdb = sub.add_parser("influxdb")
    _add_common_filter(parser_influxdb)
    parser_influxdb.add_argument(
        "--starttime",
        dest="starttime",
        type=int,
        help="use TIME as base start time for InfluxDB line protocol",
        metavar="TIME",
        default=None,
    )

    # sw
    parser_sw = sub.add_parser("sw")
    _add_common_filter(parser_sw)

    # todo
    parser_todo = sub.add_parser("todo")
    _add_common_filter(parser_todo)

    # gh
    parser_gh = sub.add_parser("gh")
    parser_gh.add_argument(
        "--alerts",
        nargs="?",
        default=None,
        const="unspecified",
        dest="alerts",
        help="show GHAS alerts. Optionally add comma-separated list of alert types (code-scanning, dependabot, secret-scanning)",
        metavar="TYPE",
        type=str,
    )
    parser_gh.add_argument(
        "--missing",
        dest="missing",
        help="show URLs missing from CVE info since '--since TIME'",
        action="store_true",
    )
    parser_gh.add_argument(
        "--updated",
        dest="updated",
        help="show URLs that have been updated since '--since TIME'",
        action="store_true",
    )
    parser_gh.add_argument(
        "--status",
        dest="status",
        help="show GHAS enabled/disabled status for repos (--status=alerts) or show active/archived status for repos (--status=active|archived)",
        type=str,
    )
    parser_gh.add_argument(
        "--org",
        dest="org",
        type=str,
        help="GitHub ORG",
        default=None,
    )
    parser_gh.add_argument(
        "-s",
        "--software",
        dest="software",
        help="comma-separated list of GitHub repos or PATH to file with GitHub repo list (newline separated) to limit by (eg, 'foo,bar')",
        type=str,
        default=None,
    )
    parser_gh.add_argument(
        "--excluded-software",
        dest="excluded_software",
        type=str,
        help="comma-separated list of GitHub repos to exclude",
        default=None,
    )
    # The GitHub API uses:
    #   &labels=foo     - issue has 'foo' label
    #   &labels=bar,baz - issue has 'bar' and 'baz' labels
    #
    # --labels uses ',' for AND and ':' for OR such that
    #   foo             - show issues with 'foo' label
    #   foo:bar         - show issues with 'foo' or 'bar' label
    #   foo:bar,baz     - show issues with 'foo' label or 'bar' and 'baz labels
    parser_gh.add_argument(
        "--labels",
        dest="labels",
        type=str,
        help="colon-separated list of GitHub labels (use commas for ANDed labels)",
        default=None,
    )
    # Consider that --labels=foo returns all issues with the label 'foo'.
    # Sometimes it is useful to list all issues with the label foo but without
    # label 'bar'. Use --labels=foo --exclude-labels=bar
    parser_gh.add_argument(
        "--excluded-labels",
        dest="excluded_labels",
        type=str,
        help="colon-separated list of GitHub labels to exclude issues when present",
        default=None,
    )
    parser_gh.add_argument(
        "--since",
        dest="since",
        type=str,
        help="limit report to issues since TIME (in epoch seconds)",
        metavar="TIME",
        default="0",
    )
    parser_gh.add_argument(
        "--since-stamp",
        dest="since_stamp",
        type=str,
        help="limit report to issues since mtime of FILE",
        metavar="FILE",
        default=None,
    )
    parser_gh.add_argument(
        "--with-templates",
        dest="with_templates",
        help="show issue templates with GHAS alerts",
        action="store_true",
    )

    # quay
    parser_quay = sub.add_parser("quay")
    _add_common_oci(parser_quay, "quay.io", "ORG", "NAME@sha256:SHA256")

    # gar
    parser_gar = sub.add_parser("gar")
    _add_common_oci(
        parser_gar,
        "GAR",
        "PROJECT/LOCATION",
        "REPO/NAME@sha256:SHA256",
    )
    parser_gar.add_argument(
        "--list-repos",
        dest="list_repos",
        help="list GAR repository names",
        action="store_true",
    )

    args: argparse.Namespace = parser.parse_args(sysargs)

    if args.cmd is None:
        parser.print_help(sys.stderr)
        error("Please specify a report command")

    # check for unreasonable combinations
    if args.cmd == "summary":
        if args.all | args.closed | args.open:
            if args.unique:
                error(
                    "--open, --closed and --all not supported with 'summary --unique'"
                )
            elif not args.all ^ args.closed ^ args.open:
                # if any are specified, only one can be
                error("Please use only one of --all, --closed or --open with 'summary'")
        if args.software:
            if args.ghas:
                error("--software is not supported with 'summary --ghas'")
            elif args.unique:
                error("--software is not supported with 'summary --unique'")
    elif args.cmd == "todo" and args.software:
        error("--software is not supported with 'todo'")
    elif args.cmd == "gh":
        if (
            not args.missing
            and not args.updated
            and not args.alerts
            and not args.status
        ):
            error(
                "Please specify one of --alerts, --missing, --updates or --status with 'gh'"
            )
        elif (args.updated or args.missing or args.alerts) and (
            args.since == "0" and args.since_stamp is None
        ):
            error(
                "Please specify --since and/or --since-stamp with --missing/--updated/--alerts"
            )
        elif args.with_templates and not args.alerts:
            error("Please specify --alerts with --with-templates")
        elif (
            args.updated
            and args.software is not None
            and args.alerts is None
            and not args.missing
        ):
            error("Unsupported option --software with --updated")
        elif args.org is None:
            error("Please specify --org")
        elif "GHTOKEN" not in os.environ:
            error("Please export GitHub personal access token as GHTOKEN")

        if args.since != "0":
            try:
                int(args.since)
            except ValueError:
                if not rePatterns["date-only"].search(args.since):
                    error(
                        "Please specify seconds since epoch or YYYY-MM-DD with --since"
                    )
    elif args.cmd == "gar" or args.cmd == "quay":
        if (
            args.cmd == "gar"
            and not args.alerts
            and not args.list
            and not args.list_repos
            and not args.list_digest
        ):
            error(
                "Please specify one of --alerts, --list, --list-repos or --list-digest with 'gar'"
            )
        elif (
            args.cmd == "quay"
            and not args.alerts
            and not args.list
            and not args.list_digest
        ):
            error("Please specify one of --alerts, --list or --list-digest with 'quay'")
        elif not args.namespace:
            error("Please specify --namespace with '%s'" % args.cmd)
        elif args.cmd == "quay" and args.namespace.count("/") > 0:
            error("--namespace '%s' should not contain '/'" % args.namespace)
        elif args.cmd == "gar" and args.namespace.count("/") != 1:
            error("--namespace '%s' should contain one '/'" % args.namespace)
        elif not args.alerts:
            if args.with_templates:
                error("Please specify --alerts with --with-templates")
            if args.all:
                error("Please specify --alerts with --all")
            if args.raw:
                error("Please specify --alerts with --raw")
            if args.filter_priority:
                error("Please specify --alerts with --filter-priority")
        # below here are --alerts specific
        elif args.raw and (args.with_templates or args.all):
            error("--raw not supported with --all or --with-templates")
        elif args.list:
            error("Unsupported option --list with --alerts")
        elif args.list_digest:
            error("Unsupported option --list-digest with --alerts")
        elif args.cmd == "gar" and args.list_repos:
            error("Unsupported option --list-repos with --alerts")
        elif not args.images and not args.excluded_images:
            error("Please specify --images or --excluded-images with --alerts")

    return args


#
# CLI mains
#
def main_report(sysargs: Optional[Sequence[str]] = None):
    """Main function for cve-report command"""
    if sysargs is None:
        sysargs = sys.argv[1:]
    args: argparse.Namespace = _main_report_parse_args(sysargs)

    cveDirs: Dict[str, str] = getConfigCveDataPaths()
    compat: bool = getConfigCompatUbuntu()
    template_urls: List[str] = getConfigTemplateURLs()

    # XXX: skipping this makes things faster, but it is nice to have. For now
    # only with 'gh' since it is already slow
    # First, check the syntax of our CVEs
    if args.cmd == "gh":
        checkSyntax(cveDirs, compat, untriagedOk=True)

    # Gather the CVEs
    cves: List[CVE] = []
    if args.cmd in ["summary", "influxdb", "sw", "todo"]:
        # default (--open) has open statuses (but not 'deferred')
        filter_status = "needs-triage,needed,pending"
        if args.cmd == "summary":
            if args.all:
                # --all has all statuses
                filter_status = None
            elif args.closed:
                # --closed is all the non-active statuses
                filter_status = "DNE,ignored,not-affected,released"
            elif args.ghas:
                # getHumanSummaryGHAS() filters down internally so send all to
                # collectCVEData
                filter_status = None
            elif args.unique:
                filter_status = "needs-triage,needed,pending,released"

        cves = collectCVEData(
            cveDirs,
            compat,
            untriagedOk=True,
            filter_status=filter_status,
            filter_product=args.filter_product,
            filter_priority=args.filter_priority,
            filter_tag=args.filter_tag,
        )

        # send to a report
        if args.cmd == "influxdb":
            getInfluxDBLineProtocol(cves, args.software, args.starttime)
        elif args.cmd == "sw":
            getHumanSoftwareInfo(cves, args.software)
        elif args.cmd == "todo":
            getHumanTodo(cves)
        elif args.cmd == "summary":
            # default to open
            report_output: ReportOutput = ReportOutput.OPEN
            if args.closed:
                report_output = ReportOutput.CLOSED
            elif args.all:
                report_output = ReportOutput.BOTH

            if args.ghas:
                getHumanSummaryGHAS(cves, args.software, report_output=report_output)
            elif args.unique:
                getHumanReport(cves)
            else:
                getHumanSummary(cves, args.software, report_output=report_output)
    elif args.cmd == "gh":
        repos: List[str] = []
        if args.software is not None:
            tmp: Optional[Set[str]] = _parseSoftwareArg(args.software)
            if tmp is not None:
                repos = list(tmp)

        excluded_repos: List[str] = []
        if args.excluded_software is not None:
            tmp: Optional[Set[str]] = _parseSoftwareArg(args.excluded_software)
            if tmp is not None:
                excluded_repos = list(tmp)

        if args.status in ["active", "archived"]:
            getReposReport(args.org, archived=(args.status == "archived"))
            return
        elif args.status == "alerts":
            getGHAlertsStatusReport(
                args.org, repos=repos, excluded_repos=excluded_repos
            )
            return

        # at this point, we should be any of args.missing, args.updates or
        # args.alerts
        cves: List[CVE] = collectCVEData(cveDirs, compat, untriagedOk=True)

        # Allow for specifying --since and --since-stamp together. Eg:
        #   --since alone just sets 'since' with no stamp file
        #   --since-stamp alone where stamp file doesn't exists defaults to '0'
        #     then creates the stamp file
        #   --since-stamp alone where stamp file exists uses mtime of stamp
        #     file then updates the stamp file
        #   --since with --since-stamp sets 'since' to --since and then updates
        #     stamp file
        since: int = 0
        try:
            since = int(args.since)
        except ValueError:  # input validation happened in _main_report_parse_args()
            year, mon, day = args.since.split("-")
            since = int(
                datetime.datetime(int(year), int(mon), int(day), 0, 0, 0).strftime("%s")
            )

        if (
            since == 0
            and args.since_stamp is not None
            and os.path.exists(args.since_stamp)
        ):
            since = int(os.path.getmtime(args.since_stamp))

        if args.alerts:
            if args.missing or args.updated:
                print("\n# Alerts")

            if args.alerts == "unspecified":
                alert_types = ["code-scanning", "dependabot", "secret-scanning"]
            else:
                alert_types = args.alerts.split(",")

            getGHAlertsReport(
                cves,
                args.org,
                since=since,
                repos=repos,
                excluded_repos=excluded_repos,
                with_templates=args.with_templates,
                alert_types=alert_types,
                template_urls=template_urls,
            )

        if args.updated:
            if args.alerts is not None or args.missing:
                print("\n# Updates")

            getUpdatedReport(cves, args.org, excluded_repos=excluded_repos, since=since)

        if args.missing:
            if args.alerts is not None or args.updated:
                print("\n# Missing")

            labels: List[str] = []
            if args.labels is not None:
                labels = args.labels.split(":")
            excluded_labels: List[str] = []
            if args.excluded_labels is not None:
                excluded_labels = args.excluded_labels.split(":")
            getMissingReport(
                cves,
                args.org,
                repos=repos,
                excluded_repos=excluded_repos,
                labels=labels,
                skip_labels=excluded_labels,
                since=since,
            )

        if args.since_stamp is not None:
            pathlib.Path(args.since_stamp).touch()
    elif args.cmd in ["quay", "gar"]:
        # EXPERIMENTAL: this script and APIs subject to change
        _experimental()
        if args.list:
            ocis: List[str] = []
            if args.cmd == "quay":
                ocis: List[str] = cvelib.quay.getQuayOCIsForOrg(args.namespace)
                for r in sorted(ocis):
                    # ORG/NAME
                    print("%s/%s" % (args.namespace, r))
            elif args.cmd == "gar":
                ocis: List[str] = cvelib.gar.getGAROCIsForProjectLoc(args.namespace)
                for r in sorted(ocis):
                    # PROJECT/LOCATION/REPO/NAME
                    print("%s/%s" % (args.namespace, r.split("/", maxsplit=5)[-1]))
        elif args.cmd == "gar" and args.list_repos:
            repos: List[str] = cvelib.gar.getGARReposForProjectLoc(args.namespace)
            for r in sorted(repos):
                # PROJECT/LOCATION/REPO
                print("%s/%s" % (args.namespace, r.split("/")[-1]))
        elif args.list_digest:
            digest: str = ""
            if args.cmd == "quay":
                digest = cvelib.quay.getQuayDigestForImage(
                    "%s/%s" % (args.namespace, args.list_digest)
                )
            elif args.cmd == "gar":
                digest = cvelib.gar.getGARDigestForImage(
                    "%s/%s" % (args.namespace, args.list_digest)
                )

            if digest == "":  # pragma: nocover
                sys.exit(1)

            print(digest.split("@")[1])
        elif args.alerts:
            images: List[str] = []
            if args.images is not None:
                tmp: Optional[Set[str]] = _parseSoftwareArg(args.images)
                if tmp is not None:
                    images = list(tmp)

            excluded_images: List[str] = []
            if args.excluded_images is not None:
                warn("TODO: implement --excluded-images")
                tmp: Optional[Set[str]] = _parseSoftwareArg(args.excluded_images)
                if tmp is not None:
                    excluded_images = list(tmp)

            # verify images
            for img in images + excluded_images:
                c: int = img.count("/")
                if args.cmd == "gar" and c != 1:
                    error("image name '%s' should contain one '/'" % img)
                    return  # for tests
                elif args.cmd == "quay" and c > 0:
                    error("image name '%s' should not contain '/'" % img)
                    return  # for tests

            getOCIReports(
                cves,
                registry=args.cmd,
                namespace=args.namespace,
                images=images,
                excluded_images=excluded_images,
                with_templates=args.with_templates,
                template_urls=template_urls,
                raw=args.raw,
                fixable=(not args.all),
                filter_priority=args.filter_priority,
            )
