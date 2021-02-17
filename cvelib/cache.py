#!/usr/bin/env python3

import copy
import glob
import os

import cvelib.common
import cvelib.cve


try:
    import sqlite3
except Exception:
    raise cvelib.common.CveException("Could not find sqlite3 package. Is it installed?")


class CveCache(object):
    # changing this causes a db rebuild on the next run
    cveCacheVersion = 0

    def __init__(self, fn):
        # Database specific attributes
        self._conn = None

        # Cache attributes
        self.cacheFile = fn
        self.cache = None

        if not os.path.exists(fn):
            self._dbInit()
        self._dbRebuildIfNeeded()

    #
    # DB helpers
    #
    def _dbConnect(self):
        """Connect to the database and return a cursor"""
        if self._conn is None:
            self._conn = sqlite3.connect(self.cacheFile)
            self._conn.row_factory = sqlite3.Row

        return self._conn.cursor()

    def _dbDisconnect(self):
        """Connect to the database and return a cursor"""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # XXX: this will likely need to be reassessed. For now:
    # - meta table - info about this db, eg, the version
    # - cves table
    #   - contains everything
    def _dbGetTables(self):
        """Return the tables for init"""
        tables = {
            "meta": """
CREATE TABLE meta (
    'version' int NOT NULL
)
"""
        }

        cvesTable = """
CREATE TABLE cves (
    Candidate text NOT NULL,
    mtime text NOT NULL,"""

        columns = sorted(cvelib.cve.CVE.cve_required + cvelib.cve.CVE.cve_optional)
        for k in columns:
            if k == "Candidate":
                continue
            cvesTable += "\n    '%s' text," % k
        cvesTable = cvesTable.rstrip(",")
        cvesTable += "\n)\n"

        tables["cves"] = cvesTable
        return tables

    def _dbInit(self):
        """Initialize the database"""
        cur = self._dbConnect()
        tables = self._dbGetTables()
        for t in tables:
            cur.execute(tables[t])

        cur.execute("INSERT INTO meta VALUES (?)", [(CveCache.cveCacheVersion)])
        self._conn.commit()

        # was it added?
        self._dbQuery(cur, "SELECT name FROM sqlite_master WHERE type='table'")
        res = cur.fetchall()
        if len(res) != len(tables):
            raise cvelib.common.CveException("database not initialized")

        cur.close()

    def _dbRebuildIfNeeded(self):
        """Rebuild the database if older"""
        cur = self._dbConnect()
        self._dbQuery(cur, "SELECT version FROM meta")
        res = cur.fetchall()
        if len(res) != 1:
            raise cvelib.common.CveException("db corrupted (wrong number of versions)")

        version = res[0][0]
        if version != CveCache.cveCacheVersion:
            cvelib.common.warn("Rebuilding due to different version")
            cur.close()
            self._dbDisconnect()
            os.unlink(self.cacheFile)
            self._dbInit()

    def _dbQuery(self, cursor, query):
        """Perform an SQL query (assumes validated input)"""
        cursor.execute(query)

    def _dbDump(self):
        """Dump database as SQL"""
        self._dbConnect()
        for line in self._conn.iterdump():
            print(line)

    def _insertTupleFromRead(self, fn, mtime, compatUbuntu):
        """Read the CVE and return a tuple"""
        try:
            cve = cvelib.cve.CVE(fn=fn, untriagedOk=True, compatUbuntu=compatUbuntu)
        except Exception as e:
            cvelib.common.warn("could not read '%s': %s" % (fn, e))
            return None

        # Candidate and mtime are the first two, then sorted
        # Refactor onDiskFormat()
        return (
            cve.candidate,
            str(mtime),
            cve.assignedTo,
            "\n %s" % "\n ".join(cve.bugs) if cve.bugs else "",
            " %s" % cve.cvss if cve.cvss else "",
            cve.crd,
            "\n %s" % "\n ".join(cve.description) if cve.description else "",
            cve.discoveredBy,
            cve.mitigation,
            "\n %s" % "\n ".join(cve.notes) if cve.notes else "",
            cve.priority,
            cve.publicDate,
            "\n %s" % "\n ".join(cve.references) if cve.references else "",
        )

    def update(self, cveDirs, compatUbuntu):
        """Update the cache's CVE data"""
        # pull in the cache data
        cur = self._dbConnect()
        self._dbQuery(cur, "SELECT * FROM cves")
        cache = {}
        for r in cur.fetchall():
            cve = r["candidate"]
            if cve in cache:
                # should not happen
                cvelib.common.warn("skipping duplicate entry for '%s'" % cve)
                continue
            cache[cve] = int(r["mtime"])

        # gather the on disk data
        cve_files = (
            glob.glob(cveDirs["active"] + "/CVE*")
            + glob.glob(cveDirs["retired"] + "/CVE-*")
            + glob.glob(cveDirs["ignored"] + "/CVE-*")
        )

        # iterate through on disk data, updating the db
        self._dbQuery(cur, "BEGIN TRANSACTION")
        addItems = []
        delItems = []
        seen = {}
        for cve_fn in cve_files:
            cve = os.path.basename(cve_fn)
            seen[cve] = True
            mtime = int(os.path.getmtime(cve_fn))
            if cve not in cache:
                tupl = self._insertTupleFromRead(cve_fn, mtime, compatUbuntu)
                if tupl is None:
                    continue
                addItems.append(tupl)
            elif cache[cve] < mtime:
                delItems.append((cve,))
                tupl = self._insertTupleFromRead(cve_fn, mtime, compatUbuntu)
                if tupl is None:
                    continue
                addItems.append(tupl)

        if delItems:
            cur.executemany("DELETE FROM cves WHERE candidate=?", delItems)
        if addItems:
            cur.executemany(
                "INSERT INTO cves VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", addItems
            )

        self._dbQuery(cur, "END TRANSACTION")
        self._conn.commit()

        # remove CVEs no longer on disk
        self._dbQuery(cur, "BEGIN TRANSACTION")
        delItems = []
        for cve in cache:
            if cve not in seen:
                delItems.append((cve,))
        if delItems:
            cur.executemany("DELETE FROM cves WHERE candidate=?", delItems)

        self._dbQuery(cur, "END TRANSACTION")
        self._conn.commit()

    def read(self, compatUbuntu):
        """Read cache into memory"""
        if self.cache is not None:
            return self.cache

        cache = {}
        cur = self._dbConnect()
        self._dbQuery(cur, "SELECT * FROM cves")

        for r in cur.fetchall():
            data = {}
            for key in r.keys():
                if key == "mtime":
                    continue
                data[key] = r[key]

            cve = None
            cve = cvelib.cve.CVE(untriagedOk=True, compatUbuntu=compatUbuntu)
            cve.setData(copy.deepcopy(data))
            cache[data["Candidate"]] = cve

        self.cache = cache
        return self.cache

    def dump(self, compatUbuntu):
        """Dump cache"""
        cache = self.read(compatUbuntu)
        for cve in sorted(cache.keys()):
            print("# %s" % cve)
            print(cache[cve].onDiskFormat())
