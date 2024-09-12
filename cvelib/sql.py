#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

import argparse
import csv
import datetime
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
                convertCveDateToISO8601(cve.openDate, cve.candidate),
                convertCveDateToISO8601(cve.closeDate, cve.candidate),
                convertCveDateToISO8601(cve.publicDate, cve.candidate),
                convertCveDateToISO8601(cve.crd, cve.candidate),
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
                (
                    ""
                    if pkg.software not in pkg.priorities
                    else pkg.priorities[pkg.software]
                ),
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


def print_results(res: List[Tuple], format: str) -> None:
    if format == "raw":
        for r in res:
            print(r)
    else:  # default to csv
        try:
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
    elif args.query or args.query_file:
        sql: str
        if args.query_file:
            if not os.path.isfile(args.query_file):
                error("'%s' is not a regular file" % args.query_file)
            with open(args.query_file, "r", encoding="utf-8") as fp:
                sql = fp.read()
        else:
            sql = args.query
        res = db.execute_query(sql)
        supported_formats: List[str] = ["csv", "raw"]
        if args.output_format not in supported_formats:
            error(
                "Unsupported output format '%s'. Please use: %s"
                % (args.output_format, ", ".join(supported_formats))
            )
        print_results(res, format=args.output_format)
