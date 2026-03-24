"""test_sql.py: tests for sql.py module"""

#
# SPDX-License-Identifier: MIT

from unittest import TestCase, mock
import os
import tempfile

import cvelib.common
import cvelib.cve
import cvelib.github
import cvelib.pkg
import cvelib.scan
import cvelib.sql
import tests.testutil


class TestCVEdb(TestCase):
    def setUp(self):
        """Setup functions common for all tests"""
        os.environ["SEDG_EXPERIMENTAL"] = "1"
        self.tmpdir = None
        self.orig_xdg_config_home = None

    def tearDown(self):
        """Teardown functions common for all tests"""
        if self.orig_xdg_config_home is None:
            if "XDG_CONFIG_HOME" in os.environ:
                del os.environ["XDG_CONFIG_HOME"]
        else:  # pragma: nocover
            os.environ["XDG_CONFIG_HOME"] = self.orig_xdg_config_home
            self.orig_xdg_config_home = None
        cvelib.common.configCache = None

        if "SEDG_EXPERIMENTAL" in os.environ:  # pragma: nocover
            del os.environ["SEDG_EXPERIMENTAL"]

        if hasattr(self, "conn"):
            self.conn.close()

        if self.tmpdir is not None:
            cvelib.common.recursive_rm(self.tmpdir)

    def _setup_temp_config(self):
        """Helper to set up temporary config with CVE data directories"""
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-")
        content = f"[Locations]\ncve-data = {self.tmpdir}\n"
        self.orig_xdg_config_home, tmpdir = tests.testutil._newConfigFile(
            content, self.tmpdir
        )

        # Create required directories
        cveDirs = {}
        for d in ["active", "retired", "ignored", "templates"]:
            cveDirs[d] = os.path.join(self.tmpdir, d)
            os.makedirs(cveDirs[d], 0o0700)

        return tmpdir, cveDirs

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

    def _mock_cve_file(self, cand="CVE-2023-1234"):
        """Generate a valid CVE template"""
        return {
            "Candidate": cand,
            "OpenDate": "2023-01-01",
            "CloseDate": "",
            "PublicDate": "2023-01-02",
            "CRD": "2023-01-03",
            "References": "\n https://example.com/cve-ref",
            "Description": "\n Test CVE description",
            "Notes": "\n test> some notes",
            "Mitigation": "\n Test mitigation",
            "Bugs": "\n https://example.com/bug",
            "Priority": "medium",
            "Discovered-by": "Test User",
            "Assigned-to": "Test Assignee",
            "CVSS": "",
            "upstream_testpkg": "needs-triage",
        }

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
            drv, loc, user, pw, db = cvelib.sql.parse_dsn(dsn)
            self.assertEqual(exp_drv, drv)
            self.assertEqual(exp_loc, loc)
            self.assertEqual(exp_user, user)
            self.assertEqual(exp_pw, pw)
            self.assertEqual(exp_db, db)

    def test_convertCveDateToISO8601(self):
        """Test convertCveDateToISO8601()"""
        tsts = [
            # date_str, candidate, exp, exp_err
            ("", "CVE-2023-NNN1", "", ""),
            ("2023-05-20", "CVE-2023-NNN1", "2023-05-20", ""),
            ("2023-05-20 12:00:00", "CVE-2023-NNN1", "2023-05-20T12:00:00", ""),
            (
                "2023-05-20 12:00:00 UTC",
                "CVE-2023-NNN1",
                "2023-05-20T12:00:00+00:00",
                "",
            ),
            (
                "2023-05-20 12:00:00 +0000",
                "CVE-2023-NNN1",
                "2023-05-20T12:00:00+00:00",
                "",
            ),
            (
                "2023-05-20 12:00:00 +0100",
                "CVE-2023-NNN1",
                "2023-05-20T12:00:00+01:00",
                "",
            ),
            (
                "2023-05-20 12:00:00 +1530",
                "CVE-2023-NNN1",
                "2023-05-20T12:00:00+15:30",
                "",
            ),
            (
                "2023-05-20 12:00:00 -0000",
                "CVE-2023-NNN1",
                "2023-05-20T12:00:00-00:00",
                "",
            ),
            # errors
            (
                "2023-05-20 12:00:00 CDT",
                "CVE-2023-NNN1",
                "2023-05-20T12:00:00+00:00",
                "WARN: non-ISO8601 compatible timezone specified in CVE-2023-NNN1: 2023-05-20 12:00:00 CDT. Using UTC",
            ),
            (
                "bad",
                "CVE-2023-NNN1",
                "",
                "WARN: ignoring CVE date in CVE-2023-NNN1: bad",
            ),
        ]
        for date_str, cand, exp, exp_err in tsts:
            with tests.testutil.capturedOutput() as (output, error):
                res = cvelib.sql.convertCveDateToISO8601(date_str, cand)
            self.assertEqual("", output.getvalue().strip())
            self.assertEqual(exp_err, error.getvalue().strip())
            self.assertEqual(exp, res)

    def test_print_results(self):
        """Test print_results"""
        tsts = [
            # list, format, exp
            ([], "csv", ""),
            ([("foo", "bar")], "csv", "foo,bar"),
            ([("foo", "bar"), ("baz", "quz")], "csv", "foo,bar\r\nbaz,quz"),
            ([], "raw", ""),
            ([("foo", "bar")], "raw", "('foo', 'bar')"),
            ([("foo", "bar"), ("baz", "quz")], "raw", "('foo', 'bar')\n('baz', 'quz')"),
        ]
        for lst, fmt, exp in tsts:
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.sql.print_results(lst, fmt)
            self.assertEqual("", error.getvalue().strip())
            self.assertEqual(exp, output.getvalue().strip())

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
        self.assertEqual(11, len(res))
        self.assertEqual(cve.candidate, res[0])
        self.assertEqual(cve.openDate, res[1])
        self.assertEqual(cve.closeDate, res[2])
        self.assertEqual(cve.publicDate, res[3])
        self.assertEqual(cve.crd, res[4])
        self.assertEqual(" \n".join(cve.description), res[5])
        self.assertEqual(" \n".join(cve.notes), res[6])
        self.assertEqual(" \n".join(cve.mitigation), res[7])
        self.assertEqual(cve.priority, res[8])
        self.assertEqual(cve.assignedTo, res[9])
        self.assertEqual(cve.cvss, res[10])

    def test_insert_into_pkgs(self):
        """Test insert_into_pkgs()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cve_cand1 = "CVE-2023-NNN1"
        pkg = cvelib.pkg.parse("git/repo_foo/bar: released (1.0)")
        db.insert_into_pkgs(cve_cand1, pkg)

        self.cursor.execute("SELECT * FROM pkgs WHERE candidate=?", (cve_cand1,))
        res = self.cursor.fetchone()
        self.assertEqual(7, len(res))
        self.assertEqual(pkg.product, res[0])
        self.assertEqual(pkg.where, res[1])
        self.assertEqual(pkg.software, res[2])
        self.assertEqual(pkg.modifier, res[3])
        self.assertEqual(cve_cand1, res[4])
        self.assertEqual(pkg.status, res[5])
        self.assertEqual(pkg.when, res[6])

        cve_cand2 = "CVE-2023-NNN2"
        pkg = cvelib.pkg.parse("upstream_baz: needed")
        db.insert_into_pkgs(cve_cand2, pkg)

        self.cursor.execute("SELECT * FROM pkgs WHERE candidate=?", (cve_cand2,))
        res = self.cursor.fetchone()
        self.assertEqual(7, len(res))
        self.assertEqual(pkg.software, res[2])
        self.assertEqual(cve_cand2, res[4])

    def test_get_schema(self):
        """Test get_schema()"""
        self.maxDiff = 16384
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        res = db.get_schema()
        self.assertEqual(13, len(res))

        exp_cves = """CREATE TABLE 'cves' (
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
)"""
        self.assertEqual(exp_cves, res[3][0])

        exp_pkgs = """CREATE TABLE 'pkgs' (
    'product' TEXT,
    'where' TEXT,
    'software' TEXT NOT NULL,
    'modifier' TEXT,
    'candidate' TEXT NOT NULL,
    'status' TEXT NOT NULL,
    'when' TEXT,
    PRIMARY KEY ('product', 'where', 'software', 'modifier', 'candidate')
)"""
        self.assertEqual(exp_pkgs, res[11][0])

        # Verify all table names are present
        table_names = [r[0].split("'")[1] for r in res]
        for exp_table in [
            "cves",
            "pkgs",
            "cve_references",
            "cve_bugs",
            "cve_discovered_by",
            "ghas_dependabot",
            "ghas_secret",
            "ghas_code",
            "scan_oci",
            "pkg_patches",
            "pkg_tags",
            "pkg_priorities",
            "pkg_close_dates",
        ]:
            self.assertIn(exp_table, table_names)

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
            " \n".join(cve.description),
            " \n".join(cve.notes),
            " \n".join(cve.mitigation),
            cve.priority,
            cve.assignedTo,
            cve.cvss,
        )
        self.assertEqual(1, len(res))
        self.assertEqual(exp, res[0])

        # invalid - write operations are denied by authorizer
        with tests.testutil.capturedOutput() as (output, error):
            res = db.execute_query("DELETE FROM cves")
        self.assertEqual(0, len(res))
        self.assertIn("Query error:", output.getvalue())

        # malformed SQL
        with tests.testutil.capturedOutput() as (output, error):
            res = db.execute_query("UPDATE...")
        self.assertEqual(0, len(res))
        self.assertIn("Query error:", output.getvalue())

        # case-insensitive select works
        res = db.execute_query("select * from 'cves'")
        self.assertEqual(1, len(res))
        self.assertEqual(exp, res[0])

        # INSERT denied
        with tests.testutil.capturedOutput() as (output, error):
            res = db.execute_query(
                "INSERT INTO cves (candidate) VALUES ('CVE-2023-HACK')"
            )
        self.assertEqual(0, len(res))
        self.assertIn("Query error:", output.getvalue())

        # DROP denied
        with tests.testutil.capturedOutput() as (output, error):
            res = db.execute_query("DROP TABLE cves")
        self.assertEqual(0, len(res))
        self.assertIn("Query error:", output.getvalue())

        # verify data is unchanged after denied operations
        res = db.execute_query("SELECT COUNT(*) FROM cves")
        self.assertEqual(1, res[0][0])

    def test_insert_into_cve_references(self):
        """Test insert_into_cve_references()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        refs = ["https://ref1", "https://ref2"]
        db.insert_into_cve_references(cand, refs)

        self.cursor.execute("SELECT * FROM cve_references WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(2, len(res))
        self.assertEqual((cand, "https://ref1"), res[0])
        self.assertEqual((cand, "https://ref2"), res[1])

        # empty list
        db.insert_into_cve_references("CVE-2023-0002", [])
        self.cursor.execute(
            "SELECT * FROM cve_references WHERE candidate=?", ("CVE-2023-0002",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(0, len(res))

        # whitespace-only entries are skipped
        db.insert_into_cve_references("CVE-2023-0003", [" ", "https://ref3"])
        self.cursor.execute(
            "SELECT * FROM cve_references WHERE candidate=?", ("CVE-2023-0003",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(1, len(res))
        self.assertEqual("https://ref3", res[0][1])

    def test_insert_into_cve_bugs(self):
        """Test insert_into_cve_bugs()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        bugs = ["https://bug1", "https://bug2"]
        db.insert_into_cve_bugs(cand, bugs)

        self.cursor.execute("SELECT * FROM cve_bugs WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(2, len(res))
        self.assertEqual((cand, "https://bug1"), res[0])
        self.assertEqual((cand, "https://bug2"), res[1])

        # empty list
        db.insert_into_cve_bugs("CVE-2023-0002", [])
        self.cursor.execute(
            "SELECT * FROM cve_bugs WHERE candidate=?", ("CVE-2023-0002",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(0, len(res))

    def test_insert_into_cve_discovered_by(self):
        """Test insert_into_cve_discovered_by()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        db.insert_into_cve_discovered_by(cand, "Alice, Bob")

        self.cursor.execute(
            "SELECT * FROM cve_discovered_by WHERE candidate=?", (cand,)
        )
        res = self.cursor.fetchall()
        self.assertEqual(2, len(res))
        self.assertEqual((cand, "Alice"), res[0])
        self.assertEqual((cand, "Bob"), res[1])

        # single discoverer
        db.insert_into_cve_discovered_by("CVE-2023-0002", "Charlie")
        self.cursor.execute(
            "SELECT * FROM cve_discovered_by WHERE candidate=?", ("CVE-2023-0002",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(1, len(res))
        self.assertEqual(("CVE-2023-0002", "Charlie"), res[0])

        # empty string
        db.insert_into_cve_discovered_by("CVE-2023-0003", "")
        self.cursor.execute(
            "SELECT * FROM cve_discovered_by WHERE candidate=?", ("CVE-2023-0003",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(0, len(res))

    def test_insert_into_ghas_dependabot(self):
        """Test insert_into_ghas_dependabot()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        dep = cvelib.github.GHDependabot(
            {
                "dependency": "lodash",
                "detectedIn": "package-lock.json",
                "advisory": "https://github.com/advisories/GHSA-test-1234-5678",
                "severity": "high",
                "status": "needs-triage",
                "url": "https://github.com/org/repo/security/dependabot/1",
            }
        )
        db.insert_into_ghas_dependabot(cand, dep)

        self.cursor.execute("SELECT * FROM ghas_dependabot WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(1, len(res))
        self.assertEqual(cand, res[0][0])
        self.assertEqual("lodash", res[0][1])
        self.assertEqual("package-lock.json", res[0][2])
        self.assertEqual("https://github.com/advisories/GHSA-test-1234-5678", res[0][3])
        self.assertEqual("high", res[0][4])
        self.assertEqual("needs-triage", res[0][5])
        self.assertEqual("https://github.com/org/repo/security/dependabot/1", res[0][6])

    def test_insert_into_ghas_secret(self):
        """Test insert_into_ghas_secret()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        sec = cvelib.github.GHSecret(
            {
                "secret": "github_personal_access_token",
                "detectedIn": "config.yml",
                "severity": "critical",
                "status": "needs-triage",
                "url": "https://github.com/org/repo/security/secret-scanning/1",
            }
        )
        db.insert_into_ghas_secret(cand, sec)

        self.cursor.execute("SELECT * FROM ghas_secret WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(1, len(res))
        self.assertEqual(cand, res[0][0])
        self.assertEqual("github_personal_access_token", res[0][1])
        self.assertEqual("config.yml", res[0][2])
        self.assertEqual("critical", res[0][3])
        self.assertEqual("needs-triage", res[0][4])
        self.assertEqual(
            "https://github.com/org/repo/security/secret-scanning/1", res[0][5]
        )

    def test_insert_into_ghas_code(self):
        """Test insert_into_ghas_code()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        code = cvelib.github.GHCode(
            {
                "description": "SQL injection vulnerability",
                "detectedIn": "src/app.py",
                "severity": "high",
                "status": "needs-triage",
                "url": "https://github.com/org/repo/security/code-scanning/1",
            }
        )
        db.insert_into_ghas_code(cand, code)

        self.cursor.execute("SELECT * FROM ghas_code WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(1, len(res))
        self.assertEqual(cand, res[0][0])
        self.assertEqual("SQL injection vulnerability", res[0][1])
        self.assertEqual("src/app.py", res[0][2])
        self.assertEqual("high", res[0][3])
        self.assertEqual("needs-triage", res[0][4])
        self.assertEqual(
            "https://github.com/org/repo/security/code-scanning/1", res[0][5]
        )

    def test_insert_into_ghas(self):
        """Test insert_into_ghas()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"

        dep = cvelib.github.GHDependabot(
            {
                "dependency": "lodash",
                "detectedIn": "package-lock.json",
                "advisory": "https://github.com/advisories/GHSA-test-1234-5678",
                "severity": "high",
                "status": "needs-triage",
                "url": "https://github.com/org/repo/security/dependabot/1",
            }
        )
        db.insert_into_ghas(cand, dep)
        self.cursor.execute("SELECT COUNT(*) FROM ghas_dependabot")
        self.assertEqual(1, self.cursor.fetchone()[0])

        sec = cvelib.github.GHSecret(
            {
                "secret": "github_personal_access_token",
                "detectedIn": "config.yml",
                "severity": "critical",
                "status": "needs-triage",
                "url": "https://github.com/org/repo/security/secret-scanning/1",
            }
        )
        db.insert_into_ghas(cand, sec)
        self.cursor.execute("SELECT COUNT(*) FROM ghas_secret")
        self.assertEqual(1, self.cursor.fetchone()[0])

        code = cvelib.github.GHCode(
            {
                "description": "SQL injection vulnerability",
                "detectedIn": "src/app.py",
                "severity": "high",
                "status": "needs-triage",
                "url": "https://github.com/org/repo/security/code-scanning/1",
            }
        )
        db.insert_into_ghas(cand, code)
        self.cursor.execute("SELECT COUNT(*) FROM ghas_code")
        self.assertEqual(1, self.cursor.fetchone()[0])

    def test_insert_into_ghas_unsupported_type(self):
        """Test insert_into_ghas() with unsupported type"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()

        cand = "CVE-2023-0001"
        with mock.patch("cvelib.sql.warn") as mock_warn:
            db.insert_into_ghas(cand, "not a ghas object")  # type: ignore[arg-type]
            mock_warn.assert_called_once_with("unsupported GHAS type: str")

    def test_insert_into_scan_oci(self):
        """Test insert_into_scan_oci()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        oci = cvelib.scan.ScanOCI(
            {
                "component": "libssl3",
                "detectedIn": "myimage@sha256:abc123",
                "advisory": "https://security.example.com/CVE-2023-0001",
                "version": "3.0.2-0ubuntu1.6",
                "fixedBy": "3.0.2-0ubuntu1.7",
                "severity": "high",
                "status": "needs-triage",
                "url": "https://quay.io/repository/org/myimage/manifest/sha256:abc123",
            }
        )
        db.insert_into_scan_oci(cand, oci)

        self.cursor.execute("SELECT * FROM scan_oci WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(1, len(res))
        self.assertEqual(cand, res[0][0])
        self.assertEqual("libssl3", res[0][1])
        self.assertEqual("myimage@sha256:abc123", res[0][2])
        self.assertEqual("https://security.example.com/CVE-2023-0001", res[0][3])
        self.assertEqual("3.0.2-0ubuntu1.6", res[0][4])
        self.assertEqual("3.0.2-0ubuntu1.7", res[0][5])
        self.assertEqual("high", res[0][6])
        self.assertEqual("needs-triage", res[0][7])
        self.assertEqual(
            "https://quay.io/repository/org/myimage/manifest/sha256:abc123",
            res[0][8],
        )

    def test_insert_into_pkg_patches(self):
        """Test insert_into_pkg_patches()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        pkg = cvelib.pkg.parse("upstream_foo: needed")
        pkg.setPatches(
            [
                "upstream: https://example.com/patch1",
                "vendor: https://example.com/patch2",
            ],
            False,
        )
        db.insert_into_pkg_patches(cand, pkg)

        self.cursor.execute("SELECT * FROM pkg_patches WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(2, len(res))
        self.assertEqual("upstream: https://example.com/patch1", res[0][5])
        self.assertEqual("vendor: https://example.com/patch2", res[1][5])

        # empty patches
        pkg2 = cvelib.pkg.parse("upstream_bar: needed")
        db.insert_into_pkg_patches("CVE-2023-0002", pkg2)
        self.cursor.execute(
            "SELECT * FROM pkg_patches WHERE candidate=?", ("CVE-2023-0002",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(0, len(res))

    def test_insert_into_pkg_tags(self):
        """Test insert_into_pkg_tags()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        pkg = cvelib.pkg.parse("upstream_foo: needed")
        pkg.setTags([("foo", "apparmor hardlink-restriction")])
        db.insert_into_pkg_tags(cand, pkg)

        self.cursor.execute("SELECT * FROM pkg_tags WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(2, len(res))
        self.assertEqual("foo", res[0][5])
        self.assertEqual("apparmor", res[0][6])
        self.assertEqual("foo", res[1][5])
        self.assertEqual("hardlink-restriction", res[1][6])

        # empty tags
        pkg2 = cvelib.pkg.parse("upstream_bar: needed")
        db.insert_into_pkg_tags("CVE-2023-0002", pkg2)
        self.cursor.execute(
            "SELECT * FROM pkg_tags WHERE candidate=?", ("CVE-2023-0002",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(0, len(res))

    def test_insert_into_pkg_priorities(self):
        """Test insert_into_pkg_priorities()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        pkg = cvelib.pkg.parse("upstream_foo: needed")
        pkg.setPriorities([("foo", "high"), ("other", "low")])
        db.insert_into_pkg_priorities(cand, pkg)

        self.cursor.execute("SELECT * FROM pkg_priorities WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(2, len(res))
        # Check both rows exist (order may vary by dict iteration)
        priorities = {r[5]: r[6] for r in res}
        self.assertEqual("high", priorities["foo"])
        self.assertEqual("low", priorities["other"])

        # empty priorities
        pkg2 = cvelib.pkg.parse("upstream_bar: needed")
        db.insert_into_pkg_priorities("CVE-2023-0002", pkg2)
        self.cursor.execute(
            "SELECT * FROM pkg_priorities WHERE candidate=?", ("CVE-2023-0002",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(0, len(res))

    def test_insert_into_pkg_close_dates(self):
        """Test insert_into_pkg_close_dates()"""
        db = cvelib.sql.CVEdb(":memory:")
        db.create_tables()
        self.conn = db.conn
        self.cursor = self.conn.cursor()

        cand = "CVE-2023-0001"
        pkg = cvelib.pkg.parse("upstream_foo: needed")
        pkg.setCloseDates([("foo", "2023-06-01")])
        db.insert_into_pkg_close_dates(cand, pkg)

        self.cursor.execute("SELECT * FROM pkg_close_dates WHERE candidate=?", (cand,))
        res = self.cursor.fetchall()
        self.assertEqual(1, len(res))
        self.assertEqual("foo", res[0][5])
        self.assertEqual("2023-06-01", res[0][6])

        # empty closeDates
        pkg2 = cvelib.pkg.parse("upstream_bar: needed")
        db.insert_into_pkg_close_dates("CVE-2023-0002", pkg2)
        self.cursor.execute(
            "SELECT * FROM pkg_close_dates WHERE candidate=?", ("CVE-2023-0002",)
        )
        res = self.cursor.fetchall()
        self.assertEqual(0, len(res))

    @mock.patch(
        "sys.argv",
        [
            "cve-query",
            "--show-schema",
        ],
    )
    def test_main_cve_query_show_schema(self):
        """Test main_cve_query() - show schema"""
        self._setup_temp_config()

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.sql.main_cve_query()

        self.assertEqual("", error.getvalue().strip())
        out = output.getvalue()
        for table in [
            "cves",
            "pkgs",
            "cve_references",
            "cve_bugs",
            "cve_discovered_by",
            "ghas_dependabot",
            "ghas_secret",
            "ghas_code",
            "scan_oci",
            "pkg_patches",
            "pkg_tags",
            "pkg_priorities",
            "pkg_close_dates",
        ]:
            self.assertIn("CREATE TABLE '%s'" % table, out)

    @mock.patch(
        "sys.argv",
        [
            "cve-query",
            "--query",
            "SELECT COUNT(*) FROM cves",
        ],
    )
    def test_main_cve_query_from_arg(self):
        """Test main_cve_query() - query as arg with CVE data"""
        _, cveDirs = self._setup_temp_config()

        # Create a test CVE file using _cve_template()
        cve_data = self._mock_cve_file("CVE-2023-5555")
        cve_content = tests.testutil.cveContentFromDict(cve_data)
        cve_fn = os.path.join(cveDirs["active"], "CVE-2023-5555")
        with open(cve_fn, "w") as fp:
            fp.write(cve_content)

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.sql.main_cve_query()

        self.assertEqual("", error.getvalue().strip())
        self.assertIn("1", output.getvalue())  # One CVE in database

    def test_main_cve_query_from_file(self):
        """Test main_cve_query() - query from file with CVE data"""
        tmpdir, cveDirs = self._setup_temp_config()

        # Create a test CVE file using _cve_template()
        cve_data = self._mock_cve_file("CVE-2023-6666")
        cve_content = tests.testutil.cveContentFromDict(cve_data)
        cve_fn = os.path.join(cveDirs["active"], "CVE-2023-6666")
        with open(cve_fn, "w") as fp:
            fp.write(cve_content)

        query_fn = os.path.join(tmpdir, "test.sql")
        content = "SELECT COUNT(*) FROM cves"
        with open(query_fn, "w") as fp:
            fp.write("%s" % content)

        with mock.patch(
            "sys.argv",
            [
                "cve-query",
                "--query-file",
                query_fn,
            ],
        ):

            with tests.testutil.capturedOutput() as (output, error):
                cvelib.sql.main_cve_query()

            self.assertEqual("", error.getvalue().strip())
            self.assertIn("1", output.getvalue())  # One CVE in database

    @mock.patch(
        "sys.argv",
        [
            "cve-query",
            "--query",
            "SELECT COUNT(*) FROM cves",
            "--output-format",
            "raw",
        ],
    )
    def test_main_cve_query_raw_output(self):
        """Test main_cve_query() - raw output format"""
        self._setup_temp_config()

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.sql.main_cve_query()

        self.assertEqual("", error.getvalue().strip())
        self.assertIn("(0,)", output.getvalue())

    @mock.patch(
        "sys.argv",
        [
            "cve-query",
            "--show-schema",
        ],
    )
    @mock.patch.dict(os.environ, {"SEDG_CVE_QUERY_DSN": "sqlite:///test.db"})
    def test_main_cve_query_env_dsn(self):
        """Test main_cve_query() - DSN from environment"""
        tmpdir, _ = self._setup_temp_config()

        # Change to tmpdir to ensure test.db is created there
        orig_cwd = os.getcwd()
        os.chdir(tmpdir)

        try:
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.sql.main_cve_query()

            self.assertEqual("", error.getvalue().strip())
            self.assertIn("CREATE TABLE 'cves'", output.getvalue())
            # Check that database file was created
            self.assertTrue(os.path.exists("test.db"))
        finally:
            os.chdir(orig_cwd)

    def test_main_cve_query_db_overwrite(self):
        """Test main_cve_query() - database overwrite"""
        tmpdir, _ = self._setup_temp_config()
        db_path = os.path.join(tmpdir, "test.db")
        # Write some content to the file
        with open(db_path, "wb") as db_file:
            db_file.write(b"existing content")

        with mock.patch(
            "sys.argv",
            [
                "cve-query",
                "--dsn",
                f"sqlite:///{db_path}",
                "--db-overwrite",
                "--show-schema",
            ],
        ):

            with tests.testutil.capturedOutput() as (output, error):
                cvelib.sql.main_cve_query()

            self.assertEqual("", error.getvalue().strip())
            self.assertIn("CREATE TABLE 'cves'", output.getvalue())

    def test_main_cve_query_existing_db(self):
        """Test main_cve_query() - use existing database"""
        tmpdir, _ = self._setup_temp_config()
        db_path = os.path.join(tmpdir, "test.db")

        # Pre-create database with schema
        db = cvelib.sql.CVEdb(db_path)
        db.create_tables()
        db.conn.close()

        with mock.patch(
            "sys.argv",
            [
                "cve-query",
                "--dsn",
                f"sqlite:///{db_path}",
                "--show-schema",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.sql.main_cve_query()

            self.assertEqual("", error.getvalue().strip())
            self.assertIn("CREATE TABLE 'cves'", output.getvalue())

    @mock.patch(
        "sys.argv",
        [
            "cve-query",
            "--query",
            "SELECT COUNT(*) FROM cves",
            "--output-format",
            "invalid",
        ],
    )
    def test_main_cve_query_invalid_format(self):
        """Test main_cve_query() - invalid output format"""
        self._setup_temp_config()

        with tests.testutil.capturedOutput() as (output, error):
            with self.assertRaises(SystemExit):
                cvelib.sql.main_cve_query()

        self.assertEqual("", output.getvalue().strip())
        self.assertIn("Unsupported output format 'invalid'", error.getvalue())

    @mock.patch(
        "sys.argv",
        [
            "cve-query",
            "--query-file",
            "/nonexistent/file.sql",
        ],
    )
    def test_main_cve_query_nonexistent_file(self):
        """Test main_cve_query() - nonexistent query file"""
        self._setup_temp_config()

        with tests.testutil.capturedOutput() as (output, error):
            with self.assertRaises(SystemExit):
                cvelib.sql.main_cve_query()

        self.assertEqual("", output.getvalue().strip())
        self.assertIn("'/nonexistent/file.sql' is not a regular file", error.getvalue())

    @mock.patch(
        "sys.argv",
        [
            "cve-query",
            "--dsn",
            "postgresql://localhost/testdb",
            "--show-schema",
        ],
    )
    def test_main_cve_query_unsupported_driver(self):
        """Test main_cve_query() - unsupported database driver"""

        with tests.testutil.capturedOutput() as (output, error):
            with self.assertRaises(SystemExit):
                cvelib.sql.main_cve_query()

        self.assertEqual("", output.getvalue().strip())
        self.assertIn("only 'sqlite' supported", error.getvalue())

    @mock.patch(
        "sys.argv",
        [
            "cve-query",
            "--show-schema",
        ],
    )
    def test_main_cve_query_with_cve_data(self):
        """Test main_cve_query() - with actual CVE data to populate database"""
        _, cveDirs = self._setup_temp_config()

        # Create a test CVE file
        cve_data = self._mock_cve_file("CVE-2023-9999")
        cve_content = tests.testutil.cveContentFromDict(cve_data)
        cve_fn = os.path.join(cveDirs["active"], "CVE-2023-9999")
        with open(cve_fn, "w") as fp:
            fp.write(cve_content)

        with tests.testutil.capturedOutput() as (output, error):
            cvelib.sql.main_cve_query()

        self.assertEqual("", error.getvalue().strip())
        out = output.getvalue()
        self.assertIn("CREATE TABLE 'cves'", out)
        self.assertIn("CREATE TABLE 'pkgs'", out)

    def test_main_cve_query_with_ghas_data(self):
        """Test main_cve_query() - with GHAS data"""
        _, cveDirs = self._setup_temp_config()

        cve_data = self._mock_cve_file("CVE-2023-8888")
        cve_data["GitHub-Advanced-Security"] = (
            "\n"
            " - type: dependabot\n"
            "   dependency: lodash\n"
            "   detectedIn: package-lock.json\n"
            "   advisory: https://github.com/advisories/GHSA-test-1234-5678\n"
            "   severity: high\n"
            "   status: needs-triage\n"
            "   url: https://github.com/org/repo/security/dependabot/1\n"
            " - type: secret-scanning\n"
            "   secret: github_personal_access_token\n"
            "   detectedIn: config.yml\n"
            "   severity: critical\n"
            "   status: needs-triage\n"
            "   url: https://github.com/org/repo/security/secret-scanning/1\n"
            " - type: code-scanning\n"
            "   description: SQL injection\n"
            "   detectedIn: src/app.py\n"
            "   severity: high\n"
            "   status: needs-triage\n"
            "   url: https://github.com/org/repo/security/code-scanning/1"
        )
        cve_content = tests.testutil.cveContentFromDict(cve_data)
        cve_fn = os.path.join(cveDirs["active"], "CVE-2023-8888")
        with open(cve_fn, "w") as fp:
            fp.write(cve_content)

        with mock.patch(
            "sys.argv",
            [
                "cve-query",
                "--query",
                "SELECT COUNT(*) FROM ghas_dependabot",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.sql.main_cve_query()

            self.assertEqual("", error.getvalue().strip())
            self.assertIn("1", output.getvalue())

    def test_main_cve_query_with_ghas_data_unavailable(self):
        """Test main_cve_query() - with GHAS data using unavailable URLs"""
        _, cveDirs = self._setup_temp_config()

        cve_data = self._mock_cve_file("CVE-2023-8889")
        cve_data["GitHub-Advanced-Security"] = (
            "\n"
            " - type: dependabot\n"
            "   dependency: foo\n"
            "   detectedIn: go.sum\n"
            "   advisory: https://github.com/advisories/GHSA-a\n"
            "   severity: high\n"
            "   status: needed\n"
            "   url: unavailable\n"
            " - type: dependabot\n"
            "   dependency: bar\n"
            "   detectedIn: go.sum\n"
            "   advisory: https://github.com/advisories/GHSA-b\n"
            "   severity: medium\n"
            "   status: needed\n"
            "   url: unavailable"
        )
        cve_content = tests.testutil.cveContentFromDict(cve_data)
        cve_fn = os.path.join(cveDirs["active"], "CVE-2023-8889")
        with open(cve_fn, "w") as fp:
            fp.write(cve_content)

        with mock.patch(
            "sys.argv",
            [
                "cve-query",
                "--query",
                "SELECT COUNT(*) FROM ghas_dependabot",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.sql.main_cve_query()

            self.assertEqual("", error.getvalue().strip())
            self.assertIn("2", output.getvalue())

    def test_main_cve_query_with_scan_data(self):
        """Test main_cve_query() - with scan report data"""
        _, cveDirs = self._setup_temp_config()

        cve_data = self._mock_cve_file("CVE-2023-7777")
        cve_data["Scan-Reports"] = (
            "\n"
            " - type: oci\n"
            "   component: libssl3\n"
            "   detectedIn: Distro 1.0\n"
            "   advisory: https://www.cve.org/CVERecord?id=CVE-2023-7777\n"
            "   version: 3.0.2\n"
            "   fixedBy: 3.0.3\n"
            "   severity: high\n"
            "   status: needs-triage\n"
            "   url: https://quay.io/repository/org/myimage/manifest/sha256:abc123"
        )
        cve_content = tests.testutil.cveContentFromDict(cve_data)
        cve_fn = os.path.join(cveDirs["active"], "CVE-2023-7777")
        with open(cve_fn, "w") as fp:
            fp.write(cve_content)

        with mock.patch(
            "sys.argv",
            [
                "cve-query",
                "--query",
                "SELECT COUNT(*) FROM scan_oci",
            ],
        ):
            with tests.testutil.capturedOutput() as (output, error):
                cvelib.sql.main_cve_query()

            self.assertEqual("", error.getvalue().strip())
            self.assertIn("1", output.getvalue())
