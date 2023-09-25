#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import os
import sqlite3
import textwrap
from typing import Dict, List, Tuple

from cvelib.common import error, warn, _experimental
import cvelib.cve
import cvelib.pkg


class CVEdb(object):
    def __init__(self, dbname):
        _experimental()
        self.conn: sqlite3.Connection = sqlite3.connect(dbname)

    def __del__(self):
        if hasattr(self, "conn"):
            self.conn.close()

    # TODO cves:
    # - add/break out scans
    # Later cves:
    # - break out references
    # - break out mitigation
    # - break out bugs
    # - break out discoveredBy
    # - break out assignedTo
    # Later pkgs
    # - add/break out tags
    # - add/break out patches
    def create_tables(self):
        """Create all the tables"""
        cursor = self.conn.cursor()

        cursor.execute(
            """
CREATE TABLE 'cves' (
    'candidate' TEXT PRIMARY KEY NOT NULL,
    'openDate' DATE,
    'closeDate' DATE,
    'publicDate' DATE,
    'crd' DATE,
    'references' TEXT,
    'description' TEXT,
    'notes' TEXT,
    'mitigation' TEXT,
    'bugs' TEXT,
    'priority' TEXT,
    'discoveredBy' TEXT,
    'assignedTo' TEXT,
    'cvss' TEXT
)
"""
        )

        cursor.execute(
            """
CREATE TABLE 'pkgs' (
    'product' TEXT,
    'where' TEXT,
    'software' TEXT NOT NULL,
    'modifier' TEXT,
    'candidate' TEXT NOT NULL,
    'status' TEXT NOT NULL,
    'when' TEXT,
    'priority' TEXT,
    PRIMARY KEY ('product', 'where', 'software', 'modifier', 'candidate')
)
"""
        )

    def insert_into_cves(self, cve: cvelib.cve.CVE):
        """Insert a CVE into the database"""
        cursor = self.conn.cursor()
        # Insert using parameterized queries
        cursor.execute(
            """
            INSERT INTO 'cves' (
                'candidate',
                'openDate',
                'closeDate',
                'publicDate',
                'crd',
                'references',
                'description',
                'notes',
                'mitigation',
                'bugs',
                'priority',
                'discoveredBy',
                'assignedTo',
                'cvss'
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                cve.candidate,
                convertDateISO8601(cve.openDate, cve.candidate),
                convertDateISO8601(cve.closeDate, cve.candidate),
                convertDateISO8601(cve.publicDate, cve.candidate),
                convertDateISO8601(cve.crd, cve.candidate),
                " \n".join(cve.references),
                " \n".join(cve.description),
                " \n".join(cve.notes),
                " \n".join(cve.mitigation),
                " \n".join(cve.bugs),
                cve.priority,
                cve.discoveredBy,
                cve.assignedTo,
                cve.cvss,
            ),
        )

        self.conn.commit()

    def insert_into_pkgs(self, candidate: str, pkg: cvelib.pkg.CvePkg):
        """Insert a pkg into the database"""
        cursor = self.conn.cursor()
        # Insert using parameterized queries
        cursor.execute(
            """
            INSERT INTO 'pkgs' (
                'product',
                'where',
                'software',
                'modifier',
                'candidate',
                'status',
                'when',
                'priority'
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                pkg.product,
                pkg.where,
                pkg.software,
                pkg.modifier,
                candidate,
                pkg.status,
                pkg.when,
                ""
                if pkg.software not in pkg.priorities
                else pkg.priorities[pkg.software],
            ),
        )

        self.conn.commit()

    def get_schema(self) -> List:
        """Get database schema"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT sql FROM sqlite_master WHERE type="table"')
        result = cursor.fetchall()
        return result

    def execute_query(self, q: str) -> List:
        """Execute query"""
        # XXX: make this robust
        if not q.startswith("SELECT "):
            print("Only support SELECT")
            return []
        cursor = self.conn.cursor()
        # XXX: this is trusting
        cursor.execute(q)
        results = cursor.fetchall()
        return results


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


def convertDateISO8601(d: str, candidate: str) -> str:
    """Convert CVE date to ISO8601"""
    if d == "":
        return d

    tmp = d.split(" ")
    if len(tmp) == 1:  # just date
        return d
    elif len(tmp) == 2:  # just date and time
        return "%sT%s" % (tmp[0], tmp[1])
    elif len(tmp) == 3:  # date, time and timezone
        if tmp[2].startswith("+") or tmp[2].startswith("-"):
            return "%sT%s%s" % (tmp[0], tmp[1], tmp[2])
        if tmp[2] != "UTC":
            warn(
                "non-ISO8601 compatible timezone specified in %s: %s. Using UTC"
                % (candidate, d)
            )
        return "%sT%sZ" % (tmp[0], tmp[1])
    warn("ignoring non-ISO8601 date in %s: %s" % (candidate, d))
    return ""


#
# CLI mains
#
def main_cve_query():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="cve-query",
        description="Query cve database with SQL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
cve-query ...
            """
        ),
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
        dest="query",
        help="SQL to execute",
        metavar="SQL",
    )

    args: argparse.Namespace = parser.parse_args()

    driver, _, _, _, dbname = parse_dsn(args.dsn)
    if driver != "sqlite":
        error("only 'sqlite' supported")

    cveDirs: Dict[str, str] = cvelib.cve.getConfigCveDataPaths()
    compat: bool = cvelib.cve.getConfigCompatUbuntu()

    db: CVEdb
    if dbname != ":memory:" and os.path.exists(dbname) and not args.db_overwrite:
        db = CVEdb(dbname)
    else:
        if args.db_overwrite:
            os.unlink(dbname)

        db = CVEdb(dbname)
        db.create_tables()

        for cve in cvelib.cve.collectCVEData(cveDirs, compat, untriagedOk=True):
            db.insert_into_cves(cve)
            for pkg in cve.pkgs:
                db.insert_into_pkgs(cve.candidate, pkg)

        # an indicator to show that this is intended only for queries
        if dbname != ":memory:":
            os.chmod(dbname, 0o0444)

    if args.show_schema:
        res = db.get_schema()
        for r in res:
            print(r[0])
    elif args.query:
        res = db.execute_query(args.query)
        for r in res:
            print(r)
