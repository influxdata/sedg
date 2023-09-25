"""test_common.py: tests for common.py module"""
#
# SPDX-License-Identifier: MIT

import unittest
import os

import cvelib.cve
import cvelib.sql


class TestCVEdb(unittest.TestCase):
    def setUp(self):
        """Setup functions common for all tests"""
        os.environ["SEDG_EXPERIMENTAL"] = "1"

    def tearDown(self):
        """Teardown functions common for all tests"""
        if "SEDG_EXPERIMENTAL" in os.environ:  # pragma: nocover
            del os.environ["SEDG_EXPERIMENTAL"]

        if hasattr(self, "conn"):
            self.conn.close()

    def _mock_cve(self):
        """Mock CVE object with sample data"""
        cve = cvelib.cve.CVE()
        cve.candidate = "CVE-2023-1234"
        cve.openDate = "2023-01-01"
        cve.closeDate = "2023-01-02"
        cve.publicDate = "2023-01-04"
        cve.crd = "2023-01-03"
        cve.references = ["https://ref1", "https://ref2"]
        cve.description = ["desc line1", "desc line2"]
        cve.notes = ["note line1", "note line2"]
        cve.mitigation = ["mitigation line1", "mitigation line2"]
        cve.bugs = ["https://bug1", "https://bug2"]
        cve.priority = "high"
        cve.discoveredBy = "John Doe"
        cve.assignedTo = "Jane Smith"
        cve.cvss = "9.8"

        return cve

    def test_parse_dsn(self):
        """Test parse_dsn()"""
        tsts = [
            # dsn, exp_drv, exp_loc, exp_user, exp_pw, exp_db
            ("sqlite:///:memory:", "sqlite", "", "", "", ":memory:"),
            ("sqlite:///db.sqlite", "sqlite", "", "", "", "db.sqlite"),
            ("sqlite:///./db.sqlite", "sqlite", "", "", "", "./db.sqlite"),
            (
                "sqlite:////path/to/db.sqlite",
                "sqlite",
                "",
                "",
                "",
                "/path/to/db.sqlite",
            ),
            (
                "postgresql://localhost/dbname",
                "postgresql",
                "localhost",
                "",
                "",
                "dbname",
            ),
            (
                "postgresql://localhost:5432/dbname",
                "postgresql",
                "localhost:5432",
                "",
                "",
                "dbname",
            ),
            (
                "postgresql://usr:pw@localhost:5432/dbname",
                "postgresql",
                "localhost:5432",
                "usr",
                "pw",
                "dbname",
            ),
            (
                "postgresql://foo.bar:5432/dbname",
                "postgresql",
                "foo.bar:5432",
                "",
                "",
                "dbname",
            ),
            (
                "postgresql://usr:pw@foo.bar:5432/dbname",
                "postgresql",
                "foo.bar:5432",
                "usr",
                "pw",
                "dbname",
            ),
            (
                "postgresql://u@sr:p@w@foo.bar:5432/dbname",
                "postgresql",
                "foo.bar:5432",
                "u@sr",
                "p@w",
                "dbname",
            ),
            (
                "postgresql://usr:p:w@foo.bar:5432/dbname",
                "postgresql",
                "foo.bar:5432",
                "usr",
                "p:w",
                "dbname",
            ),
            # don't support user with ':' at this time
            (
                "postgresql://u:sr:pw@foo.bar:5432/dbname",
                "postgresql",
                "foo.bar:5432",
                "u",
                "sr:pw",
                "dbname",
            ),
            # don't support user without password at this time
            (
                "postgresql://usr@foo.bar:5432/dbname",
                "postgresql",
                "foo.bar:5432",
                "",
                "",
                "dbname",
            ),
        ]

        for dsn, exp_drv, exp_loc, exp_user, exp_pw, exp_db in tsts:
            (drv, loc, user, pw, db) = cvelib.sql.parse_dsn(dsn)
            self.assertEqual(exp_drv, drv)
            self.assertEqual(exp_loc, loc)
            self.assertEqual(exp_user, user)
            self.assertEqual(exp_pw, pw)
            self.assertEqual(exp_db, db)

    def test_insert_into_cves(self):
        """Test insert_into_cves()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cve = self._mock_cve()
        db.insert_into_cves(cve)

        self.cursor.execute("SELECT * FROM cves WHERE candidate=?", (cve.candidate,))
        res = self.cursor.fetchone()
        self.assertEqual(14, len(res))
        self.assertEqual(cve.candidate, res[0])
        self.assertEqual(cve.openDate, res[1])
        self.assertEqual(cve.closeDate, res[2])
        self.assertEqual(cve.publicDate, res[3])
        self.assertEqual(cve.crd, res[4])
        self.assertEqual(" \n".join(cve.references), res[5])
        self.assertEqual(" \n".join(cve.description), res[6])
        self.assertEqual(" \n".join(cve.notes), res[7])
        self.assertEqual(" \n".join(cve.mitigation), res[8])
        self.assertEqual(" \n".join(cve.bugs), res[9])
        self.assertEqual(cve.priority, res[10])
        self.assertEqual(cve.discoveredBy, res[11])
        self.assertEqual(cve.assignedTo, res[12])
        self.assertEqual(cve.cvss, res[13])

    def test_get_schema(self):
        """Test get_schema()"""
        self.maxDiff = 16384
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        res = db.get_schema()
        self.assertEqual(2, len(res))

        # XXX: brittle
        exp0 = """CREATE TABLE 'cves' (
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
)"""
        self.assertEqual(exp0, res[0][0])

        exp1 = """CREATE TABLE 'pkgs' (
    'product' TEXT,
    'where' TEXT,
    'software' TEXT NOT NULL,
    'modifier' TEXT,
    'candidate' TEXT NOT NULL,
    'status' TEXT NOT NULL,
    'when' TEXT,
    'priority' TEXT,
    PRIMARY KEY ('product', 'where', 'software', 'modifier', 'candidate')
)"""
        self.assertEqual(exp1, res[1][0])

    def test_execute_query(self):
        """Test execute_query()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cve = self._mock_cve()
        db.insert_into_cves(cve)

        query = "SELECT * FROM 'cves'"
        res = db.execute_query(query)
        exp = (
            cve.candidate,
            cve.openDate,
            cve.closeDate,
            cve.publicDate,
            cve.crd,
            " \n".join(cve.references),
            " \n".join(cve.description),
            " \n".join(cve.notes),
            " \n".join(cve.mitigation),
            " \n".join(cve.bugs),
            cve.priority,
            cve.discoveredBy,
            cve.assignedTo,
            cve.cvss,
        )
        self.assertEqual(1, len(res))
        self.assertEqual(exp, res[0])

        # invalid
        res = db.execute_query("UPDATE...")
        self.assertEqual(0, len(res))
