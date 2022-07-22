#!/usr/bin/env python3

import copy
import datetime
import os
import requests
import time
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, TypedDict, Union

from cvelib.cve import CVE, collectGHAlertUrls
from cvelib.common import (
    cve_priorities,
    error,
    rePatterns,
    updateProgress,
    warn,
)
from cvelib.net import requestGetRaw, requestGet, queryGraphQL


#
# cve-report-updated-bugs
#

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
        print("    - advisory: %s" % n["ghsa"])
        print("    - url: %s/%d" % (url, n["number"]))
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
        print("    - created: %s" % n["created"])
        print("    - dismissed: %s" % n["dismissed"])
        print("    - reason: %s" % n["reason"])
        if n["name"] is not None:
            print("    - by: %s" % n["name"])
        print("    - %s" % n["path"])
        print("    - advisory: %s" % n["ghsa"])
        print("    - url: %s/%d" % (url, n["number"]))
        print("")


def _printGHAlertsUpdatedTemplates(
    org: str, repo: str, alert: List[Dict[str, str]]
) -> None:
    """Print out the updated alerts issue templates"""
    sev: List[str] = ["unknown", "low", "moderate", "high", "critical"]
    url: str = "https://github.com/%s/%s/security/dependabot" % (org, repo)
    highest: int = 0

    references: List[str] = []
    advisories: List[str] = []
    html_items: List[str] = []
    txt_items: Dict[str, int] = {}
    for n in alert:
        ref = "%s/%d" % (url, n["number"])
        references.append(ref)
        advisories.append("%s (%s)" % (n["ghsa"], n["pkg"]))
        s: str = "- [ ] [%s](%s) (%s)" % (n["pkg"], ref, n["severity"])

        if s not in html_items:
            html_items.append(s)

        t: str = "- [ ] %s (%s)" % (n["pkg"], n["severity"])
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
    if priority == "moderate" or priority == "unknown":
        priority = "medium"

    print("## %s template" % repo)
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
PublicDate: %s
CRD:
References:
 %s
 %s
Description:
 Please update dependabot flagged dependencies in %s
%sGitHub-Advanced-Security:"""
        % (
            "CVE-%d-NNNN" % now.year,
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "%d-%0.2d-%0.2d" % (now.year, now.month, now.day),
            "\n ".join(references),
            "\n ".join(advisories),
            repo,
            checklist,
        )
    )
    for n in alert:
        s: str = """ - type: dependabot
   dependency: %s
   detectedIn: %s
   severity: %s
   advisory: %s
   status: needs-triage
   url: %s/%d""" % (
            n["pkg"],
            n["path"],
            n["severity"],
            n["ghsa"],
            url,
            n["number"],
        )
        print(s)
    print(
        """Notes:
Mitigation:
Bugs:
Priority: %s
Discovered-by: gh-dependabot
Assigned-to:
CVSS:

Patches_%s:
git/%s_%s: needs-triage"""
        % (
            priority,
            repo,
            org,
            repo,
        )
    )
    print("## end CVE template")


# https://docs.github.com/en/graphql/reference/objects#repositoryvulnerabilityalert
#
# GraphQL can be used on repos that have dependabot enabled. Oddly, there
# doesn't seem to be a way to see 'active' alerts. It seems that one would
# have to pull down the dependency graph (DependencyGraphDependency?) then
# see if anything in the RepositoryVulnerabilityAlerts are affected by looking
# at the versions....
#
# Eg:
# query = '''
# {
#   repository(name: "%s", owner: "%s") {
#     vulnerabilityAlerts(first: 100) {
#       nodes {
#         createdAt
#         dismissedAt
#         dismissReason
#         dismisser {
#           name
#         }
#         number
#         securityVulnerability {
#           package {
#             name
#           }
#           severity
#           advisory {
#             description
#           }
#         }
#         vulnerableManifestPath
#         securityAdvisory {
#           permalink
#         }
#       }
#     }
#   }
# }
# ''' % (repo, org)
def getGHAlertsUpdatedReport(
    cves: List[CVE],
    org: str,
    since: int = 0,
    repos: List[str] = [],
    excluded_repos: List[str] = [],
    with_templates: bool = False,
) -> None:
    """Show GitHub alerts alerts"""
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

    # collect the alerts we know about
    knownAlerts: Set[str]
    knownAlerts, _ = collectGHAlertUrls(cves)

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
            number
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
                url: str = "https://github.com/%s/%s/security/dependabot/%d" % (
                    org,
                    repo,
                    n["number"],
                )
                if n["dismissedAt"] is not None and n["dismissedAt"] > since_str:
                    if repo not in dismissed:
                        dismissed[repo] = []

                    dismissed[repo].append(
                        {
                            "pkg": n["securityVulnerability"]["package"]["name"],
                            "severity": n["securityVulnerability"]["severity"].lower(),
                            "path": n["vulnerableManifestPath"],
                            "ghsa": n["securityAdvisory"]["permalink"],
                            "created": n["createdAt"],
                            "dismissed": n["dismissedAt"],
                            "name": n["dismisser"]["name"],
                            "reason": n["dismissReason"],
                            "number": n["number"],
                        }
                    )
                elif n["createdAt"] > since_str:
                    if url in knownAlerts:
                        warn(
                            "found previously known url with newer createdAt: %s (skipping)"
                            % url
                        )
                        continue

                    if repo not in updated:
                        updated[repo] = []

                    updated[repo].append(
                        {
                            "pkg": n["securityVulnerability"]["package"]["name"],
                            "severity": n["securityVulnerability"]["severity"].lower(),
                            "path": n["vulnerableManifestPath"],
                            "ghsa": n["securityAdvisory"]["permalink"],
                            "created": n["createdAt"],
                            "number": n["number"],
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
            if with_templates:
                _printGHAlertsUpdatedTemplates(org, repo, dismissed[repo])
                print("")
            _printGHAlertsDismissedSummary(org, repo, dismissed[repo])


#
# cve-report
#
class _statsUniqueCVEsPriorityCounts(TypedDict):
    """Type hinting for _readStatsUniqueCVEs()"""

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


def _readStatsUniqueCVEs(
    cves: List[CVE],
    filter_status: List[str] = ["needs-triage", "needed", "pending"],
    filter_product: Optional[str] = None,
) -> Dict[str, _statsUniqueCVEsPkgSoftware]:
    """Read in stats by unique CVE, discovering dependabot and secrets"""
    # stats = {
    #   pkg.software: {          // _statsUniqueCVEsPkgSoftware
    #     "deps": [<candidate>]
    #     "<priority>": {        // _statsUniqueCVEsPriorityCounts
    #       "num": int,
    #       "cves": [<candidate>]
    #     },
    #   }
    stats: Dict[str, _statsUniqueCVEsPkgSoftware] = {}
    for cve in cves:
        last_software: str = ""
        for pkg in cve.pkgs:
            if pkg.status not in filter_status:
                continue

            if filter_product is not None:
                found = False
                for filter in filter_product.split(","):
                    tmp = filter.split("/", maxsplit=1)
                    if tmp[0] != pkg.product:
                        continue
                    elif len(tmp) == 2 and tmp[1] != pkg.where:
                        continue
                    found = True
                    break
                if not found:
                    continue

            # only count an open CVE once per software/priority
            if last_software == pkg.software:
                continue
            last_software = pkg.software

            priority: str = cve.priority
            if pkg.software in pkg.priorities:
                priority = pkg.priorities[pkg.software]

            if pkg.software not in stats:
                stats[pkg.software] = _statsUniqueCVEsPkgSoftware(
                    deps=[],
                    secrets=[],
                    negligible=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    low=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    medium=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    high=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                    critical=_statsUniqueCVEsPriorityCounts(num=0, cves=[]),
                )

            stats[pkg.software][priority]["num"] += 1
            if "cves" not in stats[pkg.software][priority]:
                stats[pkg.software][priority]["cves"] = []
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


def getHumanReport(cves: List[CVE], filter_product: Optional[str] = None) -> None:
    stats_open: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves, filter_product=filter_product
    )
    print("# Unique open issues by software")
    getHumanReportOpenByPkgPriority(stats_open)

    print("\n# Unique closed issues by software")
    stats_closed: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves, filter_status=["released"], filter_product=filter_product
    )
    getHumanReportOpenByPkgPriority(stats_closed)


class _humanTodoScores(TypedDict):
    """Type hinting for getHumanTodo()"""

    score: int
    msg: str


def getHumanTodo(cves: List[CVE], filter_product: Optional[str] = None) -> None:
    stats_open: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves, filter_product=filter_product
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
    cves: List[CVE], pkg: str = "", filter_product: Optional[str] = None
) -> None:
    stats_open: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves, filter_product=filter_product
    )

    sw: str
    for sw in sorted(stats_open.keys()):
        if pkg != "" and sw != pkg:
            continue
        print("%s:" % sw)
        p: str
        for p in cve_priorities:
            if stats_open[sw][p]["num"] > 0:
                print("  %s:" % p)
                for cve in sorted(stats_open[sw][p]["cves"]):
                    print("    %s" % cve)


def _readPackagesFile(pkg_fn: str) -> Optional[Set[str]]:
    pkgs = None
    if pkg_fn:
        if not os.path.isfile(pkg_fn):
            error("'%s' is not a regular file" % pkg_fn)
        with open(pkg_fn, "r") as fh:
            pkgs = set(fh.read().splitlines())

    return pkgs


def getHumanSummary(
    cves: List[CVE],
    pkg_fn: str = "",
    closed: bool = False,
    filter_product: Optional[str] = None,
) -> None:
    def _output(
        stats: Dict[str, _statsUniqueCVEsPkgSoftware],
        state: str,
        pkgs: Optional[Set[str]],
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
                if priority == "deps" or priority == "secrets":
                    continue

                if stats[repo][priority]["num"] > 0:
                    if priority not in lines_open:
                        lines_open[priority] = {}
                    lines_open[priority][repo] = stats[repo][priority]["cves"]

                    if priority not in totals:
                        totals[priority] = {"num": 0, "num_repos": 0}
                    totals[priority]["num"] += len(stats[repo][priority]["cves"])
                    totals[priority]["num_repos"] += 1

        print("# %s\n" % state.capitalize())
        print(table_f(pri="Priority", repo="Repository", cve="Issue", extra=""))
        print(table_f(pri="--------", repo="----------", cve="-----", extra=""))
        for priority in ["critical", "high", "medium", "low", "negligible"]:
            if priority not in lines_open:
                continue
            for repo in sorted(lines_open[priority]):
                for cve in sorted(lines_open[priority][repo]):
                    # print("%s\t%s\t%s" % (priority, repo, cve))
                    extra: str = ""
                    if cve in stats[repo]["deps"] and cve in stats[repo]["secrets"]:
                        extra = "(dependabot, secret)"
                    elif cve in stats[repo]["deps"]:
                        extra = "(dependabot)"
                    elif cve in stats[repo]["secrets"]:
                        extra = "(secrets)"

                    # TODO: add 'limit-report' to extra if specified

                    print(
                        table_f(
                            pri=priority,
                            repo=(repo[: maxlen - 3] + "...")
                            if len(repo) > maxlen
                            else repo,
                            cve=cve,
                            extra=extra,
                        )
                    )

        print("\nTotals:")
        for priority in ["critical", "high", "medium", "low", "negligible"]:
            print(
                "- %s: %d in %d repos"
                % (priority, totals[priority]["num"], totals[priority]["num_repos"])
            )

    pkgs: Optional[Set[str]] = _readPackagesFile(pkg_fn)

    stats_open: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
        cves, filter_product=filter_product
    )
    _output(stats_open, "open", pkgs)

    if closed:
        print("\n")
        stats_closed: Dict[str, _statsUniqueCVEsPkgSoftware] = _readStatsUniqueCVEs(
            cves, filter_status=["released"], filter_product=filter_product
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
    filter_status: List[str] = ["needs-triage", "needed", "pending"],
    filter_product: Optional[str] = None,
    base_timestamp: Optional[int] = None,
    pkgs: Optional[Set[str]] = None,
) -> List[str]:
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

            if pkg.status not in filter_status:
                continue

            if filter_product is not None:
                found = False
                for filter in filter_product.split(","):
                    tmp = filter.split("/", maxsplit=1)
                    if tmp[0] != pkg.product:
                        continue
                    elif len(tmp) == 2 and tmp[1] != pkg.where:
                        continue
                    found = True
                    break
                if not found:
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
    pkg_fn: str = "",
    base_timestamp: Optional[int] = None,
    filter_product: Optional[str] = None,
) -> None:
    pkgs: Optional[Set[str]] = _readPackagesFile(pkg_fn)
    stats_open: List[str] = _readStatsLineProtocol(
        cves, base_timestamp=base_timestamp, pkgs=pkgs, filter_product=filter_product
    )
    for s in stats_open:
        print(s)
