#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import csv
import datetime
import json
import os
import sqlite3
import sys
import textwrap
from typing import Dict, List, Tuple

from cvelib.common import (
    _experimental,
    CveException,
    error,
    warn,
    verifyDate,
)
import cvelib.cve
import cvelib.github
import cvelib.pkg
import cvelib.scan


class CVEdb(object):
    def __init__(self, dbname):
        _experimental()
        self.conn: sqlite3.Connection = sqlite3.connect(dbname)

    def __del__(self):
        if hasattr(self, "conn"):
            self.conn.close()

    def create_tables(self):
        """Create all the tables"""
        cursor = self.conn.cursor()

        cursor.execute("""
CREATE TABLE 'cves' (
    'candidate' TEXT PRIMARY KEY NOT NULL,
    'openDate' DATE,
    'closeDate' DATE,
    'publicDate' DATE,
    'crd' DATE,
    'description' TEXT,
    'notes' TEXT,
    'mitigation' TEXT,
    'priority' TEXT,
    'assignedTo' TEXT,
    'cvss' TEXT
)
""")

        cursor.execute("""
CREATE TABLE 'pkgs' (
    'product' TEXT,
    'where' TEXT,
    'software' TEXT NOT NULL,
    'modifier' TEXT,
    'candidate' TEXT NOT NULL,
    'status' TEXT NOT NULL,
    'when' TEXT,
    PRIMARY KEY ('product', 'where', 'software', 'modifier', 'candidate')
)
""")

        cursor.execute("""
CREATE TABLE 'cve_references' (
    'candidate' TEXT NOT NULL,
    'reference' TEXT NOT NULL,
    PRIMARY KEY ('candidate', 'reference')
)
""")

        cursor.execute("""
CREATE TABLE 'cve_bugs' (
    'candidate' TEXT NOT NULL,
    'bug' TEXT NOT NULL,
    PRIMARY KEY ('candidate', 'bug')
)
""")

        cursor.execute("""
CREATE TABLE 'cve_discovered_by' (
    'candidate' TEXT NOT NULL,
    'discoverer' TEXT NOT NULL,
    PRIMARY KEY ('candidate', 'discoverer')
)
""")

        cursor.execute("""
CREATE TABLE 'ghas_dependabot' (
    'candidate' TEXT NOT NULL,
    'dependency' TEXT NOT NULL,
    'detectedIn' TEXT NOT NULL,
    'advisory' TEXT NOT NULL,
    'severity' TEXT NOT NULL,
    'status' TEXT NOT NULL,
    'url' TEXT NOT NULL,
    PRIMARY KEY ('candidate', 'dependency', 'detectedIn', 'advisory', 'url')
)
""")

        cursor.execute("""
CREATE TABLE 'ghas_secret' (
    'candidate' TEXT NOT NULL,
    'secret' TEXT NOT NULL,
    'detectedIn' TEXT NOT NULL,
    'severity' TEXT NOT NULL,
    'status' TEXT NOT NULL,
    'url' TEXT NOT NULL,
    PRIMARY KEY ('candidate', 'secret', 'detectedIn', 'url')
)
""")

        cursor.execute("""
CREATE TABLE 'ghas_code' (
    'candidate' TEXT NOT NULL,
    'description' TEXT NOT NULL,
    'detectedIn' TEXT NOT NULL,
    'severity' TEXT NOT NULL,
    'status' TEXT NOT NULL,
    'url' TEXT NOT NULL,
    PRIMARY KEY ('candidate', 'description', 'detectedIn', 'url')
)
""")

        cursor.execute("""
CREATE TABLE 'scan_oci' (
    'candidate' TEXT NOT NULL,
    'component' TEXT NOT NULL,
    'detectedIn' TEXT NOT NULL,
    'advisory' TEXT NOT NULL,
    'versionAffected' TEXT NOT NULL,
    'versionFixed' TEXT NOT NULL,
    'severity' TEXT NOT NULL,
    'status' TEXT NOT NULL,
    'url' TEXT NOT NULL,
    PRIMARY KEY ('candidate', 'component', 'detectedIn', 'advisory', 'url')
)
""")

        cursor.execute("""
CREATE TABLE 'pkg_patches' (
    'product' TEXT,
    'where' TEXT,
    'software' TEXT NOT NULL,
    'modifier' TEXT,
    'candidate' TEXT NOT NULL,
    'patch' TEXT NOT NULL,
    PRIMARY KEY ('product', 'where', 'software', 'modifier', 'candidate', 'patch')
)
""")

        cursor.execute("""
CREATE TABLE 'pkg_tags' (
    'product' TEXT,
    'where' TEXT,
    'software' TEXT NOT NULL,
    'modifier' TEXT,
    'candidate' TEXT NOT NULL,
    'tagKey' TEXT NOT NULL,
    'tag' TEXT NOT NULL,
    PRIMARY KEY ('product', 'where', 'software', 'modifier', 'candidate', 'tagKey', 'tag')
)
""")

        cursor.execute("""
CREATE TABLE 'pkg_priorities' (
    'product' TEXT,
    'where' TEXT,
    'software' TEXT NOT NULL,
    'modifier' TEXT,
    'candidate' TEXT NOT NULL,
    'priorityKey' TEXT NOT NULL,
    'priority' TEXT NOT NULL,
    PRIMARY KEY ('product', 'where', 'software', 'modifier', 'candidate', 'priorityKey')
)
""")

        cursor.execute("""
CREATE TABLE 'pkg_close_dates' (
    'product' TEXT,
    'where' TEXT,
    'software' TEXT NOT NULL,
    'modifier' TEXT,
    'candidate' TEXT NOT NULL,
    'closeDateKey' TEXT NOT NULL,
    'closeDate' DATE NOT NULL,
    PRIMARY KEY ('product', 'where', 'software', 'modifier', 'candidate', 'closeDateKey')
)
""")

    def insert_into_cves(self, cve: cvelib.cve.CVE, commit: bool = True):
        """Insert a CVE into the database"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO 'cves' (
                'candidate',
                'openDate',
                'closeDate',
                'publicDate',
                'crd',
                'description',
                'notes',
                'mitigation',
                'priority',
                'assignedTo',
                'cvss'
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                cve.candidate,
                convertCveDateToISO8601(cve.openDate, cve.candidate),
                convertCveDateToISO8601(cve.closeDate, cve.candidate),
                convertCveDateToISO8601(cve.publicDate, cve.candidate),
                convertCveDateToISO8601(cve.crd, cve.candidate),
                " \n".join(cve.description),
                " \n".join(cve.notes),
                " \n".join(cve.mitigation),
                cve.priority,
                cve.assignedTo,
                cve.cvss,
            ),
        )
        if commit:
            self.conn.commit()

    def insert_into_pkgs(
        self, candidate: str, pkg: cvelib.pkg.CvePkg, commit: bool = True
    ):
        """Insert a pkg into the database"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO 'pkgs' (
                'product',
                'where',
                'software',
                'modifier',
                'candidate',
                'status',
                'when'
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                pkg.product,
                pkg.where,
                pkg.software,
                pkg.modifier,
                candidate,
                pkg.status,
                pkg.when,
            ),
        )
        if commit:
            self.conn.commit()

    def insert_into_cve_references(
        self, candidate: str, references: List[str], commit: bool = True
    ):
        """Insert CVE references into the database"""
        cursor = self.conn.cursor()
        for ref in references:
            ref = ref.strip()
            if ref:
                cursor.execute(
                    """
                    INSERT INTO 'cve_references' (
                        'candidate', 'reference'
                    ) VALUES (?, ?)
                """,
                    (candidate, ref),
                )
        if commit:
            self.conn.commit()

    def insert_into_cve_bugs(
        self, candidate: str, bugs: List[str], commit: bool = True
    ):
        """Insert CVE bugs into the database"""
        cursor = self.conn.cursor()
        for bug in bugs:
            bug = bug.strip()
            if bug:
                cursor.execute(
                    """
                    INSERT INTO 'cve_bugs' (
                        'candidate', 'bug'
                    ) VALUES (?, ?)
                """,
                    (candidate, bug),
                )
        if commit:
            self.conn.commit()

    def insert_into_cve_discovered_by(
        self, candidate: str, discoveredBy: str, commit: bool = True
    ):
        """Insert CVE discoveredBy into the database"""
        cursor = self.conn.cursor()
        for discoverer in discoveredBy.split(","):
            discoverer = discoverer.strip()
            if discoverer:
                cursor.execute(
                    """
                    INSERT INTO 'cve_discovered_by' (
                        'candidate', 'discoverer'
                    ) VALUES (?, ?)
                """,
                    (candidate, discoverer),
                )
        if commit:
            self.conn.commit()

    def insert_into_ghas_dependabot(
        self,
        candidate: str,
        dep: cvelib.github.GHDependabot,
        commit: bool = True,
    ):
        """Insert a GHAS dependabot alert into the database"""
        # OR IGNORE: some retired CVEs have truly identical entries (all
        # fields match including url=unavailable). Parse-time checks catch
        # meaningful duplicates; this silently drops identical rows.
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO 'ghas_dependabot' (
                'candidate',
                'dependency',
                'detectedIn',
                'advisory',
                'severity',
                'status',
                'url'
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                candidate,
                dep.dependency,
                dep.detectedIn,
                dep.advisory,
                dep.severity,
                dep.status,
                dep.url,
            ),
        )
        if commit:
            self.conn.commit()

    def insert_into_ghas_secret(
        self,
        candidate: str,
        sec: cvelib.github.GHSecret,
        commit: bool = True,
    ):
        """Insert a GHAS secret alert into the database"""
        # OR IGNORE: see insert_into_ghas_dependabot comment
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO 'ghas_secret' (
                'candidate',
                'secret',
                'detectedIn',
                'severity',
                'status',
                'url'
            ) VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                candidate,
                sec.secret,
                sec.detectedIn,
                sec.severity,
                sec.status,
                sec.url,
            ),
        )
        if commit:
            self.conn.commit()

    def insert_into_ghas_code(
        self,
        candidate: str,
        code: cvelib.github.GHCode,
        commit: bool = True,
    ):
        """Insert a GHAS code scanning alert into the database"""
        # OR IGNORE: see insert_into_ghas_dependabot comment
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO 'ghas_code' (
                'candidate',
                'description',
                'detectedIn',
                'severity',
                'status',
                'url'
            ) VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                candidate,
                code.description,
                code.detectedIn,
                code.severity,
                code.status,
                code.url,
            ),
        )
        if commit:
            self.conn.commit()

    def insert_into_ghas(
        self,
        candidate: str,
        ghas_item: object,
        commit: bool = True,
    ):
        """Insert a GHAS alert into the appropriate table"""
        if isinstance(ghas_item, cvelib.github.GHDependabot):
            self.insert_into_ghas_dependabot(candidate, ghas_item, commit=commit)
        elif isinstance(ghas_item, cvelib.github.GHSecret):
            self.insert_into_ghas_secret(candidate, ghas_item, commit=commit)
        elif isinstance(ghas_item, cvelib.github.GHCode):
            self.insert_into_ghas_code(candidate, ghas_item, commit=commit)
        else:
            warn("unsupported GHAS type: %s" % type(ghas_item).__name__)

    def insert_into_scan_oci(
        self, candidate: str, oci: cvelib.scan.ScanOCI, commit: bool = True
    ):
        """Insert a scan OCI report into the database"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO 'scan_oci' (
                'candidate',
                'component',
                'detectedIn',
                'advisory',
                'versionAffected',
                'versionFixed',
                'severity',
                'status',
                'url'
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                candidate,
                oci.component,
                oci.detectedIn,
                oci.advisory,
                oci.versionAffected,
                oci.versionFixed,
                oci.severity,
                oci.status,
                oci.url,
            ),
        )
        if commit:
            self.conn.commit()

    def insert_into_pkg_patches(
        self, candidate: str, pkg: cvelib.pkg.CvePkg, commit: bool = True
    ):
        """Insert package patches into the database"""
        cursor = self.conn.cursor()
        for patch in pkg.patches:
            cursor.execute(
                """
                INSERT INTO 'pkg_patches' (
                    'product', 'where', 'software', 'modifier',
                    'candidate', 'patch'
                ) VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    pkg.product,
                    pkg.where,
                    pkg.software,
                    pkg.modifier,
                    candidate,
                    patch,
                ),
            )
        if commit:
            self.conn.commit()

    def insert_into_pkg_tags(
        self, candidate: str, pkg: cvelib.pkg.CvePkg, commit: bool = True
    ):
        """Insert package tags into the database"""
        cursor = self.conn.cursor()
        for tagKey, tagVals in pkg.tags.items():
            for tag in tagVals:
                cursor.execute(
                    """
                    INSERT INTO 'pkg_tags' (
                        'product', 'where', 'software', 'modifier',
                        'candidate', 'tagKey', 'tag'
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        pkg.product,
                        pkg.where,
                        pkg.software,
                        pkg.modifier,
                        candidate,
                        tagKey,
                        tag,
                    ),
                )
        if commit:
            self.conn.commit()

    def insert_into_pkg_priorities(
        self, candidate: str, pkg: cvelib.pkg.CvePkg, commit: bool = True
    ):
        """Insert package priorities into the database"""
        cursor = self.conn.cursor()
        for priKey, priVal in pkg.priorities.items():
            cursor.execute(
                """
                INSERT INTO 'pkg_priorities' (
                    'product', 'where', 'software', 'modifier',
                    'candidate', 'priorityKey', 'priority'
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    pkg.product,
                    pkg.where,
                    pkg.software,
                    pkg.modifier,
                    candidate,
                    priKey,
                    priVal,
                ),
            )
        if commit:
            self.conn.commit()

    def insert_into_pkg_close_dates(
        self, candidate: str, pkg: cvelib.pkg.CvePkg, commit: bool = True
    ):
        """Insert package close dates into the database"""
        cursor = self.conn.cursor()
        for cdKey, cdVal in pkg.closeDates.items():
            cursor.execute(
                """
                INSERT INTO 'pkg_close_dates' (
                    'product', 'where', 'software', 'modifier',
                    'candidate', 'closeDateKey', 'closeDate'
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    pkg.product,
                    pkg.where,
                    pkg.software,
                    pkg.modifier,
                    candidate,
                    cdKey,
                    cdVal,
                ),
            )
        if commit:
            self.conn.commit()

    def get_schema(self) -> List:
        """Get database schema"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT sql FROM sqlite_master WHERE type="table" ORDER BY name')
        result = cursor.fetchall()
        return result

    def commit(self):
        """Commit the current transaction"""
        self.conn.commit()

    def execute_query(self, q: str) -> Tuple[List[str], List]:
        """Execute a read-only query using set_authorizer()"""

        def _readOnlyAuthorizer(action, arg1, arg2, dbname, trigger):
            """Only allow read operations"""
            _ = arg1  # for pyright
            _ = arg2  # for pyright
            _ = dbname  # for pyright
            _ = trigger  # for pyright

            # SQLITE_SELECT: allows the SELECT statement itself
            # SQLITE_READ: allows reading individual columns (fired per column)
            # SQLITE_FUNCTION: allows SQL functions (COUNT, COALESCE, etc)
            allowed = {
                sqlite3.SQLITE_SELECT,
                sqlite3.SQLITE_READ,
                sqlite3.SQLITE_FUNCTION,
            }
            if action in allowed:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        self.conn.set_authorizer(_readOnlyAuthorizer)
        try:
            cursor = self.conn.cursor()
            cursor.execute(q)
            results = cursor.fetchall()
            columns = (
                [desc[0] for desc in cursor.description] if cursor.description else []
            )
        except sqlite3.DatabaseError as e:
            print("Query error: %s" % e)
            return [], []
        finally:
            self.conn.set_authorizer(None)
        return columns, results


def parse_dsn(dsn: str) -> Tuple:
    """Parse DSN"""
    driver: str = ""
    location: str = ""
    username: str = ""
    password: str = ""
    db: str = ""  # if add other drivers, support parameters

    tmp_dsn = dsn.split("/", maxsplit=3)

    driver = tmp_dsn[0].split(":")[0]

    if "@" in tmp_dsn[2]:
        # handle '@' in password
        tmp_upl = tmp_dsn[2].rsplit("@", maxsplit=1)
        if ":" in tmp_upl[0]:
            # handle ':' in password
            username, password = tmp_upl[0].split(":", maxsplit=1)
        location = tmp_upl[1]
    else:
        location = tmp_dsn[2]

    db = tmp_dsn[3]

    return driver, location, username, password, db


def convertCveDateToISO8601(cve_date: str, candidate: str) -> str:
    """Convert CVE date to ISO8601

    CVE date may be:
    * YYYY-MM-DD
    * YYYY-MM-DD HH:MM:SS
    * YYYY-MM-DD HH:MM:SS TIMEZONE

    ISO8601 date may be:
    * YYYY-MM-DD
    * YYYY-MM-DDThh:mm:ss
    * YYYY-MM-DDThh:mm:ssZ
    * YYYY-MM-DDThh:mm:ss[+-]HHMM

    ISO8601 also supports these, but the CVE format does not:
    * YYYY-MM-DDThh:mm:ss[+-]HH:MM
    * YYYY-MM-DDThh:mm:ss[+-]HH
    """
    if cve_date == "":
        return cve_date

    try:
        verifyDate("", cve_date)
    except CveException:
        warn("ignoring CVE date in %s: %s" % (candidate, cve_date))
        return ""

    iso_date: str = ""

    tmp: List[str] = cve_date.split(" ")
    if len(tmp) == 1:  # just date
        iso_date = cve_date
    elif len(tmp) == 2:  # just date and time
        iso_date = "%sT%s" % (tmp[0], tmp[1])
    elif len(tmp) == 3:  # date, time and timezone
        if tmp[2].startswith("+") or tmp[2].startswith("-"):
            # convert CVE date [+-]HHMM to fromisoformat() compatible [+-]HH:MM
            iso_date = "%sT%s%s:%s" % (tmp[0], tmp[1], tmp[2][:3], tmp[2][3:])
        else:
            if tmp[2] != "UTC":
                warn(
                    "non-ISO8601 compatible timezone specified in %s: %s. Using UTC"
                    % (candidate, cve_date)
                )
            # fromisoformat() doesn't support 'Z' so just use "-00:00"
            iso_date = "%sT%s+00:00" % (tmp[0], tmp[1])

    try:
        datetime.datetime.fromisoformat(iso_date)
    except Exception:  # pragma: nocover
        # this should be unreachable due to verifyDate(), above
        warn(
            "non-conformant ISO8601 date in %s: %s -> %s"
            % (candidate, cve_date, iso_date)
        )
        return ""

    # Valid ISO8601 according to standard. Note: datetime.fromisoformat() is
    # available but it doesn't handle ':' in the offset (eg, '+00:00'), but
    # SQL will.
    return iso_date


def print_results(res: List[Tuple], format: str, columns: List[str]) -> None:
    if format == "json":
        print(json.dumps([dict(zip(columns, row)) for row in res]))
    elif format == "raw":
        for r in res:
            print(r)
    else:  # default to csv
        try:
            if columns:
                # use \r\n to match csv.writer line endings
                sys.stdout.write("#%s\r\n" % ",".join(columns))
            csv.writer(sys.stdout).writerows(res)
        except BrokenPipeError:  # pragma: nocover
            pass


#
# CLI mains
#
def main_cve_query():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="cve-query",
        description="Query cve database with SQL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
Example queries:
  # Packages affected by a CVE
  cve-query -q "SELECT * FROM pkgs WHERE candidate = 'CVE-2023-1234'"

  # Dismissed dependabot alerts for the 'lodash' dependency
  cve-query -q "SELECT candidate, status FROM ghas_dependabot
    WHERE dependency = 'lodash' AND status LIKE 'dismissed%%'"

  # CVEs for 'go' opened between dates with priority >= medium
  cve-query -q "SELECT DISTINCT c.candidate, COALESCE(pp.priority, c.priority) as priority
    FROM pkgs p
    JOIN cves c ON p.candidate = c.candidate
    LEFT JOIN pkg_priorities pp ON pp.candidate = p.candidate
      AND pp.product = p.product AND pp.'where' = p.'where'
      AND pp.software = p.software AND pp.modifier = p.modifier
      AND pp.priorityKey = p.software
    WHERE p.software = 'go' AND c.openDate BETWEEN '2025-01-01' AND '2025-12-31'
      AND COALESCE(pp.priority, c.priority) IN ('medium', 'high', 'critical')"

  # Software affected by a particular GHSA
  cve-query -q "SELECT DISTINCT p.software FROM ghas_dependabot g
    JOIN pkgs p ON g.candidate = p.candidate
    WHERE g.advisory = 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm'"

  # Count open CVEs by priority
  cve-query -q "SELECT c.priority, COUNT(DISTINCT c.candidate) as count
    FROM cves c JOIN pkgs p ON c.candidate = p.candidate
    WHERE p.status IN ('needs-triage', 'needed', 'pending')
    GROUP BY c.priority ORDER BY count DESC"

  # Open scan_oci vulnerabilities by severity
  cve-query -q "SELECT s.severity, COUNT(*) as count FROM scan_oci s
    WHERE s.status IN ('needs-triage', 'needed')
    GROUP BY s.severity ORDER BY count DESC"

  # CVEs open longer than 90 days
  cve-query -q "SELECT c.candidate, c.openDate, c.priority FROM cves c
    JOIN pkgs p ON c.candidate = p.candidate
    WHERE p.status IN ('needs-triage', 'needed', 'pending')
      AND c.openDate < DATE('now', '-90 days')
    GROUP BY c.candidate ORDER BY c.openDate"

  # Top discoverers by CVE count
  cve-query -q "SELECT d.discoverer, COUNT(DISTINCT d.candidate) as count
    FROM cve_discovered_by d GROUP BY d.discoverer
    ORDER BY count DESC LIMIT 10"

  # Find CVEs referencing a specific bug
  cve-query -q "SELECT c.candidate, c.priority, c.openDate FROM cves c
    JOIN cve_bugs b ON c.candidate = b.candidate
    WHERE b.bug = 'https://github.com/org/repo/issues/NNN'"

  # Show database schema
  cve-query --show-schema
            """),
    )

    parser.add_argument(
        "--dsn",
        dest="dsn",
        help="Database source name. Defaults to 'sqlite:///:memory:'",
        metavar="DSN",
        default="sqlite:///:memory:",
    )

    parser.add_argument(
        "--db-overwrite",
        dest="db_overwrite",
        help="Overwrite DBNAME",
        action="store_true",
    )

    parser.add_argument(
        "--show-schema",
        dest="show_schema",
        help="Show database schema",
        action="store_true",
    )

    parser.add_argument(
        "-q",
        "--query",
        dest="query",
        help="SQL to execute",
        metavar="SQL",
    )

    parser.add_argument(
        "-f",
        "--query-file",
        dest="query_file",
        help="SQL to execute from file",
        metavar="FILENAME",
    )

    parser.add_argument(
        "--output-format",
        dest="output_format",
        help="Output format (available: csv, raw; default csv)",
        metavar="FORMAT",
        default="csv",
    )

    args: argparse.Namespace = parser.parse_args()

    dsn: str = args.dsn
    if "SEDG_CVE_QUERY_DSN" in os.environ:
        dsn = os.environ["SEDG_CVE_QUERY_DSN"]
    driver, _, _, _, dbname = parse_dsn(dsn)
    if driver != "sqlite":
        error("only 'sqlite' supported")

    cveDirs: Dict[str, str] = cvelib.cve.getConfigCveDataPaths()
    compat: bool = cvelib.cve.getConfigCompatUbuntu()

    db: CVEdb
    if dbname != ":memory:" and os.path.exists(dbname) and not args.db_overwrite:
        db = CVEdb(dbname)
    else:
        if dbname != ":memory:" and args.db_overwrite:
            os.unlink(dbname)

        db = CVEdb(dbname)
        db.create_tables()

        for cve in cvelib.cve.collectCVEData(
            cveDirs,
            compat,
            untriagedOk=True,
            filter_tag="-limit-report",  # XXX: don't hardcode this
        ):
            # For performance, commit=False and commit everything at the end
            db.insert_into_cves(cve, commit=False)
            db.insert_into_cve_references(cve.candidate, cve.references, commit=False)
            db.insert_into_cve_bugs(cve.candidate, cve.bugs, commit=False)
            db.insert_into_cve_discovered_by(
                cve.candidate, cve.discoveredBy, commit=False
            )
            for ghas_item in cve.ghas:
                db.insert_into_ghas(cve.candidate, ghas_item, commit=False)
            for scan in cve.scan_reports:
                db.insert_into_scan_oci(cve.candidate, scan, commit=False)
            for pkg in cve.pkgs:
                db.insert_into_pkgs(cve.candidate, pkg, commit=False)
                db.insert_into_pkg_patches(cve.candidate, pkg, commit=False)
                db.insert_into_pkg_tags(cve.candidate, pkg, commit=False)
                db.insert_into_pkg_priorities(cve.candidate, pkg, commit=False)
                db.insert_into_pkg_close_dates(cve.candidate, pkg, commit=False)

        db.commit()

        # an indicator to show that this is intended only for queries
        if dbname != ":memory:":
            os.chmod(dbname, 0o0444)

    if args.show_schema:
        res = db.get_schema()
        for r in res:
            print(r[0])
        print(
            "\n-- Relationships:\n"
            "--\n"
            "-- cve_references, cve_bugs, cve_discovered_by: join to cves on\n"
            "--   candidate\n"
            "--\n"
            "-- ghas_dependabot, ghas_secret, ghas_code: join to cves on\n"
            "--   candidate\n"
            "--\n"
            "-- scan_oci: join to cves on candidate\n"
            "--\n"
            "-- pkgs: join to cves on candidate\n"
            "--\n"
            "-- pkg_patches, pkg_tags, pkg_priorities, pkg_close_dates: join to\n"
            "--   pkgs on (product, where, software, modifier, candidate)\n"
            "--\n"
            "-- Note: pkg_priorities.priorityKey typically matches pkgs.software.\n"
            "--   When joining to get effective priority, use:\n"
            "--     LEFT JOIN pkg_priorities pp ON pp.candidate = p.candidate\n"
            "--       AND pp.product = p.product AND pp.'where' = p.'where'\n"
            "--       AND pp.software = p.software AND pp.modifier = p.modifier\n"
            "--       AND pp.priorityKey = p.software\n"
            "--   Then: COALESCE(pp.priority, cves.priority) as priority"
        )
    elif args.query or args.query_file:
        sql: str
        if args.query_file:
            if not os.path.isfile(args.query_file):
                error("'%s' is not a regular file" % args.query_file)
            with open(args.query_file, "r", encoding="utf-8") as fp:
                sql = fp.read()
        else:
            sql = args.query
        columns, res = db.execute_query(sql)
        supported_formats: List[str] = ["csv", "json", "raw"]
        if args.output_format not in supported_formats:
            error(
                "Unsupported output format '%s'. Please use: %s"
                % (args.output_format, ", ".join(supported_formats))
            )
        print_results(res, format=args.output_format, columns=columns)
