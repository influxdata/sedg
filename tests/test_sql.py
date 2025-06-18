"""test_common.py: tests for common.py module"""

#
# SPDX-License-Identifier: MIT

from unittest import TestCase, mock
import os
import tempfile

import cvelib.common
import cvelib.cve
import cvelib.pkg
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
            (drv, loc, user, pw, db) = cvelib.sql.parse_dsn(dsn)
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
        self.assertEqual(8, len(res))
        self.assertEqual(pkg.product, res[0])
        self.assertEqual(pkg.where, res[1])
        self.assertEqual(pkg.software, res[2])
        self.assertEqual(pkg.modifier, res[3])
        self.assertEqual(cve_cand1, res[4])
        self.assertEqual(pkg.status, res[5])
        self.assertEqual(pkg.when, res[6])
        self.assertEqual("", res[7])

        cve_cand2 = "CVE-2023-NNN2"
        pkg = cvelib.pkg.parse("upstream_baz: needed")
        pkg_pri_override = "low"
        pkg.setPriorities([("baz", pkg_pri_override), ("other", "critical")])
        db.insert_into_pkgs(cve_cand2, pkg)

        self.cursor.execute("SELECT * FROM pkgs WHERE candidate=?", (cve_cand2,))
        res = self.cursor.fetchone()
        self.assertEqual(8, len(res))
        self.assertEqual(pkg.software, res[2])
        self.assertEqual(cve_cand2, res[4])
        self.assertEqual(pkg_pri_override, res[7])

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
        self.assertIn("CREATE TABLE 'cves'", output.getvalue())
        self.assertIn("CREATE TABLE 'pkgs'", output.getvalue())

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
        self.assertIn("CREATE TABLE 'cves'", output.getvalue())
        self.assertIn("CREATE TABLE 'pkgs'", output.getvalue())
