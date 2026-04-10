"""
Creates step1b_nvd_cache.db for session SBOM-20260409-sb01.
Seeded with 8 CVE records matching the VulnerabilityRecord mock entities.
Run: python create_nvd_cache_db.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "step1b_nvd_cache.db")


def create_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Table: vulnerabilities
    cur.execute("""
        CREATE TABLE vulnerabilities (
            cve_id                 TEXT PRIMARY KEY NOT NULL,
            purl                   TEXT,
            cpe                    TEXT,
            cvss_score             REAL NOT NULL,
            severity               TEXT NOT NULL CHECK(severity IN ('High','Medium','Low')),
            affected_version_range TEXT NOT NULL,
            fixed_version          TEXT,
            advisory_url           TEXT,
            last_synced            TEXT NOT NULL
        )
    """)

    # Table: sync_log
    cur.execute("""
        CREATE TABLE sync_log (
            sync_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            synced_at       TEXT NOT NULL,
            records_added   INTEGER DEFAULT 0,
            records_updated INTEGER DEFAULT 0,
            source          TEXT NOT NULL CHECK(source IN ('daily_cron','on_demand'))
        )
    """)

    # Seed vulnerability records — one row per CVE in VulnerabilityRecord mock entities
    seed_vulns = [
        (
            "CVE-2023-34540",
            "pkg:pypi/langchain@0.0.101",
            "cpe:2.3:a:langchain:langchain:0.0.101:*:*:*:*:python:*:*",
            9.8,
            "High",
            ">=0.0.1,<0.0.247",
            "0.0.247",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-34540",
            "2026-04-09T06:00:00Z",
        ),
        (
            "CVE-2022-21797",
            "pkg:pypi/joblib@0.14.1",
            "cpe:2.3:a:joblib:joblib:0.14.1:*:*:*:*:python:*:*",
            9.8,
            "High",
            "<1.2.0",
            "1.2.0",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-21797",
            "2026-04-09T06:00:00Z",
        ),
        (
            "CVE-2021-33430",
            "pkg:pypi/numpy@1.22.0",
            "cpe:2.3:a:numpy:numpy:1.22.0:*:*:*:*:python:*:*",
            5.5,
            "Medium",
            ">=1.9.0,<1.22.2",
            "1.22.2",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-33430",
            "2026-04-09T06:00:00Z",
        ),
        (
            "CVE-2023-25399",
            "pkg:pypi/scipy@1.6.0",
            "cpe:2.3:a:scipy:scipy:1.6.0:*:*:*:*:python:*:*",
            5.5,
            "Medium",
            "<1.11.0",
            "1.11.0",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-25399",
            "2026-04-09T06:00:00Z",
        ),
        (
            "CVE-2023-32681",
            "pkg:pypi/requests@2.27.1",
            "cpe:2.3:a:python-requests:requests:2.27.1:*:*:*:*:python:*:*",
            6.1,
            "Medium",
            ">=2.3.0,<2.31.0",
            "2.31.0",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
            "2026-04-09T06:00:00Z",
        ),
        (
            "CVE-2018-19787",
            "pkg:pypi/lxml@4.6.3",
            "cpe:2.3:a:lxml:lxml:4.6.3:*:*:*:*:python:*:*",
            6.1,
            "Medium",
            "<4.7.1",
            "4.7.1",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-19787",
            "2026-04-09T06:00:00Z",
        ),
        (
            "CVE-2023-44271",
            "pkg:pypi/Pillow@9.0.1",
            "cpe:2.3:a:python:pillow:9.0.1:*:*:*:*:python:*:*",
            7.5,
            "High",
            "<10.0.0",
            "10.0.0",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-44271",
            "2026-04-09T06:00:00Z",
        ),
        (
            "CVE-2022-29216",
            "pkg:pypi/tensorflow@1.15.5",
            "cpe:2.3:a:google:tensorflow:1.15.5:*:*:*:*:python:*:*",
            8.8,
            "High",
            "<2.9.0",
            "2.9.0",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-29216",
            "2026-04-09T06:00:00Z",
        ),
    ]

    cur.executemany(
        """INSERT INTO vulnerabilities
           (cve_id, purl, cpe, cvss_score, severity,
            affected_version_range, fixed_version, advisory_url, last_synced)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        seed_vulns,
    )

    # Seed sync_log — 2 historical syncs
    seed_sync = [
        ("2026-04-08T06:00:00Z", 8, 0, "daily_cron"),
        ("2026-04-09T06:00:00Z", 0, 1, "daily_cron"),
    ]
    cur.executemany(
        """INSERT INTO sync_log (synced_at, records_added, records_updated, source)
           VALUES (?,?,?,?)""",
        seed_sync,
    )

    conn.commit()
    conn.close()

    print(f"Created: {DB_PATH}")
    print(f"  vulnerabilities: {len(seed_vulns)} rows")
    print(f"  sync_log:        {len(seed_sync)} rows")

    # Verify
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT cve_id, severity, cvss_score FROM vulnerabilities ORDER BY cvss_score DESC")
    rows = cur.fetchall()
    print("\nSeeded CVEs:")
    for row in rows:
        print(f"  {row[0]:20s}  {row[1]:7s}  CVSS {row[2]}")
    conn.close()


if __name__ == "__main__":
    create_db()
