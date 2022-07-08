#!/usr/bin/env python3

import copy
import requests
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

from cvelib.cve import CVE
from cvelib.common import (
    error,
    rePatterns,
    updateProgress,
    warn,
)
from cvelib.net import requestGetRaw, requestGet, queryGraphQL

# TODO: pass these around
repos_all: List[str] = []  # list of repos
issues_all: Dict[str, List[str]] = {}  # keys are repos, values are lists of issue urls
issues_ind: Dict[
    str, Mapping[str, Any]
] = {}  # keys are 'repo/num', values are arbitrary json docs from GitHub


def _getGHReposAll(org: str) -> List[str]:
    """Obtain the list of GitHub repos for the specified org"""
    global repos_all
    if len(repos_all) > 0:
        print("Using previously fetched list of repos")
        return copy.deepcopy(repos_all)

    url: str = "https://api.github.com/orgs/%s/repos" % org
    params: Dict[str, Union[str, int]] = {
        "accept": "application/vnd.github.v3+json",
        "per_page": 100,
    }

    print("Fetching list of repos: ", end="", flush=True)
    count: int = 0
    while True:
        count += 1
        print(".", end="", flush=True)
        params["page"] = count

        resj = requestGet(url, params=params)
        if len(resj) == 0:
            print(" done!")
            break

        for repo in resj:
            if "name" in repo:
                repos_all.append(repo["name"])

    return copy.deepcopy(repos_all)


def _getGHIssuesForRepo(
    repo: str, org: str, labels: List[str] = [], skip_labels: List[str] = []
) -> List[str]:
    """Obtain the list of GitHub issues for the specified repo and org"""
    global issues_all
    if repo in issues_all:
        print("Using previously fetched list of issues for %s" % repo)
        return sorted(copy.deepcopy(issues_all[repo]))

    url: str = "https://api.github.com/repos/%s/%s/issues" % (org, repo)
    params: Dict[str, Union[str, int]] = {
        "accept": "application/vnd.github.v3+json",
        "per_page": 100,
    }
    query_labels: List[str] = [""]
    if len(labels) > 0:
        query_labels = labels

    print(" %s/%s: " % (org, repo), end="", flush=True)
    query_label: str
    for query_label in query_labels:
        count: int = 0
        while True:
            count += 1
            print(".", end="", flush=True)
            params["page"] = count

            if query_label != "":
                params["labels"] = query_label

            r: requests.Response = requestGetRaw(url, params=params)
            if r.status_code == 410:  # repo turned off issues
                # warn("Skipping %s (%d) - issues turned off" % (url, r.status_code))
                return []
            elif r.status_code == 404:
                warn("Skipping %s (%d)" % (url, r.status_code))
                return []
            elif r.status_code >= 400:
                error(
                    "Problem fetching %s:\n%d - %s" % (url, r.status_code, r.json()),
                    do_exit=False,
                )
                return []

            resj = r.json()
            if len(resj) == 0:
                break

            issue: Dict[str, Any]
            for issue in resj:
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
                    if repo not in issues_all:
                        issues_all[repo] = []
                    if issue["html_url"] not in issues_all[repo]:
                        issues_all[repo].append(issue["html_url"])
    print(" done!")

    if repo in issues_all:
        return sorted(copy.deepcopy(issues_all[repo]))
    return []  # repo with turned off issues


def _getGHIssue(repo: str, org: str, number: int) -> Mapping[str, Any]:
    """Obtain the GitHub issue for the specified repo, org and issue number"""
    global issues_ind
    k: str = "%s/%d" % (repo, number)
    if k in issues_ind:
        print("Using previously fetched issue for %s" % k)
        return issues_ind[k]

    url: str = "https://api.github.com/repos/%s/%s/issues/%d" % (org, repo, number)
    params: Dict[str, Union[str, int]] = {"accept": "application/vnd.github.v3+json"}

    r: requests.Response = requestGetRaw(url, params=params)
    if r.status_code == 410:  # repo turned off issues
        # warn("Skipping %s (%d) - issues turned off" % (url, r.status_code))
        return {}
    elif r.status_code == 404:
        warn("Skipping %s (%d)" % (url, r.status_code))
        return {}
    elif r.status_code >= 400:
        error(
            "Problem fetching %s:\n%d - %s" % (url, r.status_code, r.json()),
            do_exit=False,
        )
        return {}

    issues_ind[k] = r.json()
    return issues_ind[k]


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
                if url.startswith("https://github.com") and "#" in url:
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
) -> None:
    """Compare list of issues in issue trackers against our CVE data"""
    known_urls: Dict[str, List[str]] = _getKnownIssues(cves, filter_url=org)

    fetch_repos: List[str] = repos
    if len(fetch_repos) == 0:
        fetch_repos = _getGHReposAll(org)

    gh_urls: List[str] = []
    print("Fetching list of issues for:")
    for repo in sorted(fetch_repos):
        if repo in excluded_repos:
            continue

        url: str
        for url in _getGHIssuesForRepo(
            repo, org, labels=labels, skip_labels=skip_labels
        ):
            if url not in known_urls and url not in gh_urls:
                gh_urls.append(url)

    if len(gh_urls) == 0:
        print("No missing issues for the specified repos.")
    else:
        print("Issues missing from CVE data:")
        for url in gh_urls:
            print(" %s" % url)


def _getGHAlertsEnabled(
    org: str, repos: List[str] = [], excluded_repos: List[str] = []
) -> Tuple[List[str], List[str]]:
    fetch_repos: List[str] = repos
    if len(fetch_repos) == 0:
        fetch_repos = _getGHReposAll(org)

    enabled: List[str] = []
    disabled: List[str] = []

    # Unfortunately there doesn't seem to be an API to tell us all the repos
    # with dependabot alerts, so get a list of URLs and then see if enabled or
    # not
    count: int = 0
    for repo in sorted(fetch_repos):
        if repo in excluded_repos:
            continue

        count += 1
        updateProgress(count / len(fetch_repos), prefix="Collecting repo status: ")

        url: str = "https://api.github.com/repos/%s/%s/vulnerability-alerts" % (
            org,
            repo,
        )
        params: Dict[str, Union[str, int]] = {
            "accept": "application/vnd.github.v3+json"
        }

        res: requests.Response = requestGetRaw(url, params=params)
        if res.status_code == 204:
            # enabled
            enabled.append(repo)
        elif res.status_code == 404:
            # disabled
            disabled.append(repo)
        else:  # pragma: nocover
            error("Problem fetching %s:\n%d - %s" % (url, res.status_code, res))

    return enabled, disabled


def getGHAlertsStatusReport(
    org: str, repos: List[str] = [], excluded_repos: List[str] = []
) -> None:
    """Obtain list of repos that have vulnerability alerts enabled/disabled"""
    enabled: List[str]
    disabled: List[str]
    enabled, disabled = _getGHAlertsEnabled(org, repos, excluded_repos=excluded_repos)
    print("Enabled:\n%s" % "\n".join(" %s" % r for r in enabled))
    print("Disabled:\n%s" % "\n".join(" %s" % r for r in disabled))


def getUpdatedReport(cves: List[CVE], org: str, since: int = 0) -> None:
    """Obtain list of URLs that have received an update since last run"""
    urls: Dict[str, List[str]] = _getKnownIssues(cves, filter_url=org)

    # convert since to a date string that we can lexigraphically compare to the
    # github string
    if not isinstance(since, int) or since < 0:
        raise ValueError
    since_str: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since))

    # find updates
    updated_urls: List[str] = []
    count: int = 0
    for url in sorted(urls.keys()):
        count += 1
        updateProgress(count / len(urls), prefix="Collecting known issues: ")

        # TODO: break this out
        if not rePatterns["github-issue"].match(url):
            continue  # only support github issues at this time
        tmp: List[str] = url.split("/")

        # compare the issue's updated_at with our since time
        issue: Mapping[str, Any] = _getGHIssue(tmp[4], tmp[3], int(tmp[6]))
        if "updated_at" in issue and issue["updated_at"] > since_str:
            updated_urls.append(url)

    if len(updated_urls) == 0:
        print("No updated issues for the specified repos.")
    else:
        print("Updated issues:")
        for url in updated_urls:
            print(" %s (%s)" % (url, ", ".join(urls[url])))


def _printGHAlertsUpdatedSummary(
    org: str, repo: str, alert: List[Dict[str, str]]
) -> None:
    """Print out the alert summary"""
    url: str = "https://github.com/%s/%s/security/dependabot" % (org, repo)
    print("%s alerts: %d (%s)" % (repo, len(alert), url))

    # for n in alert:
    for n in sorted(alert, key=lambda i: (i["pkg"], i["created"])):
        print("  %s" % n["pkg"])
        print("    - severity: %s" % n["severity"])
        print("    - created: %s" % n["created"])
        print("    - %s" % n["path"])
        print("    - %s" % n["ghsa"])
        print("")


def _printGHAlertsDismissedSummary(
    org: str, repo: str, alert: List[Dict[str, str]]
) -> None:
    """Print out the alert summary"""
    url: str = "https://github.com/%s/%s/security/dependabot" % (org, repo)
    print("%s dismissed alerts: %d (%s)" % (repo, len(alert), url))

    # for n in alert:
    for n in sorted(alert, key=lambda i: (i["pkg"], i["dismissed"])):
        print("  %s" % n["pkg"])
        print("    - severity: %s" % n["severity"])
        print("    - dismissed: %s" % n["dismissed"])
        print("    - reason: %s" % n["reason"])
        if n["name"] is not None:
            print("    - by: %s" % n["name"])
        print("    - %s" % n["path"])
        print("    - %s" % n["ghsa"])
        print("")


def _printGHAlertsUpdatedTemplates(
    org: str, repo: str, alert: List[Dict[str, str]]
) -> None:
    """Print out the updated alerts issue templates"""
    sev: List[str] = ["unknown", "low", "moderate", "high", "critical"]
    highest: int = 0

    items: Dict[str, int] = {}
    for n in alert:
        s: str = "- [ ] %s (%s)" % (n["pkg"], n["severity"])
        if s not in items:
            items[s] = 1
        else:
            items[s] += 1

        cur: int
        try:
            cur = sev.index(n["severity"])
        except ValueError:
            cur = sev.index("unknown")

        if cur > highest:
            highest = cur

    checklist: str = ""
    i: str
    for i in sorted(items.keys()):
        if items[i] > 1:
            checklist += "%s\n" % (i.replace("(", "(%d " % (items[i])))
        else:
            checklist += "%s\n" % i

    priority: str = sev[highest]
    if priority == "moderate" or priority == "unknown":
        priority = "medium"

    print("## %s template" % repo)
    url: str = "https://github.com/%s/%s/security/dependabot" % (org, repo)
    template: str = """Please update dependabot flagged dependencies in %s

%s lists the following updates:
%s
Since a '%s' severity issue is present, tentatively adding the 'security/%s' label. At the time of filing, the above is untriaged. When updating the above checklist, please add supporting github comments as triaged, not affected or remediated. Dependabot only reported against the default branch so please be sure to check any other supported branches when researching/fixing.

Thanks!

References:
 * https://docs.influxdata.io/development/security/issue_handling/
 * https://docs.influxdata.io/development/security/issue_response/#developers
""" % (
        repo,
        url,
        checklist,
        sev[highest],
        priority,
    )

    print(template)
    print("## end template")


def getGHAlertsUpdatedReport(
    org: str,
    since: int = 0,
    repos: List[str] = [],
    excluded_repos: List[str] = [],
    with_templates: bool = False,
) -> None:
    """Obtain list of URLs that have received a vulnerability update since last run"""
    enabled: List[str]
    enabled, _ = _getGHAlertsEnabled(org, repos, excluded_repos)

    # convert since to a date string that we can lexigraphically compare to the
    # github string
    if not isinstance(since, int) or since < 0:
        raise ValueError
    since_str: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since))

    # find updates
    updated: Dict[str, List[Dict[str, str]]] = {}
    dismissed: Dict[str, List[Dict[str, str]]] = {}
    count: int = 0

    # for large numbers of 'enabled', we might get rate limited:
    # https://docs.github.com/en/graphql/overview/resource-limitations
    repo: str
    for repo in sorted(enabled):
        count += 1
        updateProgress(count / len(enabled), prefix="Collecting alerts: ")

        cursorAfter: str = ""
        while True:
            query: str = """
    {
      repository(name: "%s", owner: "%s") {
        vulnerabilityAlerts(first: 100%s) {
          nodes {
            createdAt
            dismissedAt
            dismissReason
            dismisser {
              name
            }
            securityVulnerability {
              package {
                name
              }
              severity
            }
            vulnerableManifestPath
            securityAdvisory {
              permalink
            }
          }
          pageInfo {
            startCursor
            endCursor
            hasNextPage
          }
        }
      }
    }
    """ % (
                repo,
                org,
                cursorAfter,
            )
            res: Dict[str, Any] = queryGraphQL(query)
            # import json
            # print(json.dumps(res, indent=2))
            n: Dict[str, Any]
            for n in res["data"]["repository"]["vulnerabilityAlerts"]["nodes"]:
                # skip any that are dismissed
                if n["dismissedAt"] is not None and n["dismissedAt"] > since_str:
                    if repo not in dismissed:
                        dismissed[repo] = []

                    dismissed[repo].append(
                        {
                            "pkg": n["securityVulnerability"]["package"]["name"],
                            "severity": n["securityVulnerability"]["severity"].lower(),
                            "path": n["vulnerableManifestPath"],
                            "ghsa": n["securityAdvisory"]["permalink"],
                            "dismissed": n["dismissedAt"],
                            "name": n["dismisser"]["name"],
                            "reason": n["dismissReason"],
                        }
                    )
                elif n["createdAt"] > since_str:
                    if repo not in updated:
                        updated[repo] = []

                    updated[repo].append(
                        {
                            "pkg": n["securityVulnerability"]["package"]["name"],
                            "severity": n["securityVulnerability"]["severity"].lower(),
                            "path": n["vulnerableManifestPath"],
                            "ghsa": n["securityAdvisory"]["permalink"],
                            "created": n["createdAt"],
                        }
                    )

            # deal with pagination
            if not res["data"]["repository"]["vulnerabilityAlerts"]["pageInfo"][
                "hasNextPage"
            ]:
                break
            cursorAfter: str = (
                ', after: "%s"'
                % res["data"]["repository"]["vulnerabilityAlerts"]["pageInfo"][
                    "endCursor"
                ]
            )

    if len(updated) == 0:
        print("No vulnerability alerts for the specified repos.")
    else:
        print("Vulnerability alerts:")
        for repo in sorted(updated.keys()):
            if with_templates:
                _printGHAlertsUpdatedTemplates(org, repo, updated[repo])
                print("")
            _printGHAlertsUpdatedSummary(org, repo, updated[repo])

    if len(dismissed) > 0:
        print("Dismissed vulnerability alerts:")
        for repo in sorted(dismissed.keys()):
            print("")
            _printGHAlertsDismissedSummary(org, repo, dismissed[repo])
