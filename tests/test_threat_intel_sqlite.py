#!/usr/bin/env python3
"""
Comprehensive Offline Test Suite for RAQIB SQLite Threat Intelligence Subsystem
Tests all requirements:
1. Schema & WAL Mode
2. Feodo Ingestion & 30-day TTL & ipaddress validation
3. MITRE ATT&CK Ingestion & Revoked/Deprecated filtering
4. Rule 4: Merge rule preserving verified=1 records
5. Rule 5: Pre-flight checks (HTTPS only, size limit, timeout, format, atomic rollback)
6. Rule 6: Concurrency lock file & skip if fresh
7. Rule 7: Matcher integration (known behavior vs unknown behavior, non-definitive verdict)
8. Bad cases: invalid IP, oversized payload, broken JSON, lock contention
"""

import datetime
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INTEL_SCRIPT_PATH = ROOT / "tools" / "malware" / "10_raqib_intelligence.py"
FIXTURES_DIR = ROOT / "tests" / "fixtures"

# Load the intelligence engine dynamically
spec = importlib.util.spec_from_file_location("raqib_intel", str(INTEL_SCRIPT_PATH))
intel = importlib.util.module_from_spec(spec)
sys.modules["raqib_intel"] = intel
spec.loader.exec_module(intel)


class TestRaqibThreatIntel(unittest.TestCase):

    def setUp(self):
        # Create a unique temporary directory for each test run to isolate SQLite DB and lock file
        self.test_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.test_dir.name) / "test_raqib.db"
        self.lock_path = Path(self.test_dir.name) / "test_raqib.lock"

        # Override env vars
        os.environ["RAQIB_THREAT_INTEL_DB"] = str(self.db_path)
        os.environ["RAQIB_UPDATE_LOCK"] = str(self.lock_path)

        self.conn = intel.get_db(self.db_path)

    def tearDown(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.test_dir.cleanup()
        os.environ.pop("RAQIB_THREAT_INTEL_DB", None)
        os.environ.pop("RAQIB_UPDATE_LOCK", None)

    # -------------------------------------------------------------------------
    # 1. Database & Schema Initialization (WAL Mode)
    # -------------------------------------------------------------------------
    def test_01_schema_and_wal(self):
        """Verify that SQLite database operates in WAL mode and all required tables exist."""
        wal_row = self.conn.execute("PRAGMA journal_mode;").fetchone()
        self.assertEqual(wal_row[0].lower(), "wal", "Database should be in WAL mode")

        tables = [
            "ioc_ips", "update_log", "staging_ioc_ips",
            "malware_families", "malware_behaviors",
            "staging_malware_families", "staging_malware_behaviors"
        ]
        rows = self.conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        existing_tables = {r["name"] for r in rows}
        for tbl in tables:
            self.assertIn(tbl, existing_tables, f"Table {tbl} must exist in database")

    # -------------------------------------------------------------------------
    # 2. Feodo Tracker Ingestion & Validation
    # -------------------------------------------------------------------------
    def test_02_feodo_ingestion_and_ttl(self):
        """Test Feodo ingestion, ipaddress validation, and 30-day TTL."""
        feodo_fixture = FIXTURES_DIR / "sample_feodo.json"
        res = intel.ingest_feodo(self.conn, feed_url_or_path=str(feodo_fixture), allow_offline=True, force=True)

        self.assertEqual(res["status"], "SUCCESS")
        # In sample_feodo: 3 valid IPs, 1 invalid IP ('999.888.777.666'), 1 loopback ('127.0.0.1')
        self.assertEqual(res["count"], 3, "Only the 3 valid non-loopback public IPs should be ingested")

        # Verify ioc_ips records
        rows = self.conn.execute("SELECT ip, malware_family, source, expires_at FROM ioc_ips ORDER BY ip").fetchall()
        self.assertEqual(len(rows), 3)
        ips = {r["ip"] for r in rows}
        self.assertIn("198.51.100.14", ips)
        self.assertIn("203.0.113.88", ips)
        self.assertIn("192.0.2.77", ips)
        self.assertNotIn("999.888.777.666", ips)
        self.assertNotIn("127.0.0.1", ips)

        # Check TTL is approximately 30 days
        exp_dt = datetime.fromisoformat(rows[0]["expires_at"].replace("Z", "+00:00"))
        now_dt = datetime.now(timezone.utc)
        diff_days = (exp_dt - now_dt).days
        self.assertIn(diff_days, (29, 30), f"Expires_at should be ~30 days in future, got {diff_days}")

        # Check update_log
        log_row = self.conn.execute("SELECT source, status, row_count FROM update_log WHERE source='feodo'").fetchone()
        self.assertIsNotNone(log_row)
        self.assertEqual(log_row["status"], "SUCCESS")
        self.assertEqual(log_row["row_count"], 3)

    # -------------------------------------------------------------------------
    # 3. MITRE ATT&CK Ingestion & Filtering (Revoked/Deprecated)
    # -------------------------------------------------------------------------
    def test_03_attack_ingestion_and_filtering(self):
        """Test ATT&CK ingestion filters out revoked/deprecated objects."""
        attack_fixture = FIXTURES_DIR / "sample_attack.json"
        res = intel.ingest_attack(self.conn, feed_url_or_path=str(attack_fixture), allow_offline=True, force=True)

        self.assertEqual(res["status"], "SUCCESS")

        # Active families: QakBot, Pikabot. Revoked: DeadMalware (must be absent!)
        fam_rows = self.conn.execute("SELECT name FROM malware_families").fetchall()
        fam_names = {r["name"] for r in fam_rows}
        self.assertIn("QakBot", fam_names)
        self.assertIn("Pikabot", fam_names)
        self.assertNotIn("DeadMalware", fam_names, "Revoked malware must NOT be imported")

        # Active techniques: T1059.001, T1071.001. Deprecated: T9999 (must be absent!)
        beh_rows = self.conn.execute("SELECT technique_id FROM malware_behaviors").fetchall()
        tech_ids = {r["technique_id"] for r in beh_rows}
        self.assertIn("T1059.001", tech_ids)
        self.assertIn("T1071.001", tech_ids)
        self.assertNotIn("T9999", tech_ids, "Deprecated technique must NOT be imported")

    # -------------------------------------------------------------------------
    # 4. Rule 4: Merge Rule Preserving verified=1 Rows
    # -------------------------------------------------------------------------
    def test_04_merge_rule_verified_immutability(self):
        """Test that records marked verified=1 are NEVER overwritten by synchronization."""
        # Pre-seed verified=1 family
        now_ts = intel.now_utc_iso()
        with self.conn:
            self.conn.execute("""
                INSERT INTO malware_families (id, name, aliases, description, verified, created_at, updated_at)
                VALUES ('CUSTOM-001', 'QakBot', '["CustomAlias"]', 'Analyst locked description', 1, ?, ?);
            """, (now_ts, now_ts))

            self.conn.execute("""
                INSERT INTO malware_behaviors (family_name, technique_id, technique_name, tactic, verified, created_at, updated_at)
                VALUES ('QakBot', 'T1059.001', 'Analyst Custom PowerShell Title', 'Execution', 1, ?, ?);
            """, (now_ts, now_ts))

        # Run ATT&CK sync (which has different description for QakBot and standard technique name)
        attack_fixture = FIXTURES_DIR / "sample_attack.json"
        res = intel.ingest_attack(self.conn, feed_url_or_path=str(attack_fixture), allow_offline=True, force=True)
        self.assertEqual(res["status"], "SUCCESS")

        # Verify QakBot was NOT overwritten!
        qak_row = self.conn.execute("SELECT id, description, verified FROM malware_families WHERE name='QakBot'").fetchone()
        self.assertEqual(qak_row["verified"], 1)
        self.assertEqual(qak_row["description"], "Analyst locked description", "verified=1 description must NOT be overwritten")
        self.assertEqual(qak_row["id"], "CUSTOM-001", "verified=1 ID must NOT be overwritten")

        # Verify behavior technique was NOT overwritten!
        beh_row = self.conn.execute("SELECT technique_name, verified FROM malware_behaviors WHERE family_name='QakBot' AND technique_id='T1059.001'").fetchone()
        self.assertEqual(beh_row["verified"], 1)
        self.assertEqual(beh_row["technique_name"], "Analyst Custom PowerShell Title")

        # But Pikabot (which had verified=0) WAS imported cleanly
        pika_row = self.conn.execute("SELECT verified FROM malware_families WHERE name='Pikabot'").fetchone()
        self.assertIsNotNone(pika_row)
        self.assertEqual(pika_row["verified"], 0)

    # -------------------------------------------------------------------------
    # 5. Rule 5: Pre-Flight Inspection & Bad Cases
    # -------------------------------------------------------------------------
    def test_05_preflight_checks(self):
        """Test strict preflight checks: HTTPS enforcement, size limits, and format errors."""
        # Insecure HTTP URL rejection
        with self.assertRaises(ValueError) as ctx:
            intel.preflight_fetch("http://feodotracker.abuse.ch/downloads/ipblocklist.json", max_bytes=1000)
        self.assertIn("only HTTPS feeds are permitted", str(ctx.exception))

        # Size limit exceeded rejection
        feodo_fixture = FIXTURES_DIR / "sample_feodo.json"
        with self.assertRaises(ValueError) as ctx:
            # Set tiny max limit of 10 bytes
            intel.preflight_fetch(str(feodo_fixture), max_bytes=10, allow_offline=True)
        self.assertIn("exceeds maximum limit", str(ctx.exception))

        # Malformed JSON handling: staging should rollback and failure logged
        bad_json_path = Path(self.test_dir.name) / "bad_feed.json"
        bad_json_path.write_text("{ this is completely broken json ...", encoding="utf-8")
        res = intel.ingest_feodo(self.conn, feed_url_or_path=str(bad_json_path), allow_offline=True, force=True)
        self.assertEqual(res["status"], "FAILURE")
        self.assertIn("failed to parse valid JSON", res["message"])

        # Ensure staging table remains empty after failure
        stg_count = self.conn.execute("SELECT COUNT(*) AS c FROM staging_ioc_ips").fetchone()["c"]
        self.assertEqual(stg_count, 0)

        # Ensure failure is logged in update_log
        log_row = self.conn.execute("SELECT status FROM update_log WHERE source='feodo' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(log_row["status"], "FAILURE")

    # -------------------------------------------------------------------------
    # 6. Rule 6: Concurrency Lock & Freshness Skip
    # -------------------------------------------------------------------------
    def test_06_concurrency_lock_and_freshness(self):
        """Test inter-process locking and skip-if-fresh threshold."""
        # Concurrency Lock Test
        with intel.UpdateLock(self.lock_path):
            # Attempt to acquire lock again should raise UpdateLockError
            second_lock = intel.UpdateLock(self.lock_path)
            with self.assertRaises(intel.UpdateLockError):
                second_lock.acquire()

        # Lock is released after exiting block: should succeed now
        with intel.UpdateLock(self.lock_path):
            pass

        # Freshness Skip Test
        feodo_fixture = FIXTURES_DIR / "sample_feodo.json"
        # First sync
        res1 = intel.ingest_feodo(self.conn, feed_url_or_path=str(feodo_fixture), allow_offline=True, force=True)
        self.assertEqual(res1["status"], "SUCCESS")

        # Second sync without force -> Should SKIP
        res2 = intel.ingest_feodo(self.conn, feed_url_or_path=str(feodo_fixture), allow_offline=True, force=False)
        self.assertEqual(res2["status"], "SKIPPED")
        self.assertIn("Last success was", res2["message"])

        # Second sync WITH force -> Should SUCCEED
        res3 = intel.ingest_feodo(self.conn, feed_url_or_path=str(feodo_fixture), allow_offline=True, force=True)
        self.assertEqual(res3["status"], "SUCCESS")

    # -------------------------------------------------------------------------
    # 7. Rule 7: Matcher Integration & Behavioral Profiler
    # -------------------------------------------------------------------------
    def test_07_matcher_lookup_and_unknown_behavior(self):
        """Test IP lookup: returns family, source, age, behaviors, and unknown behavior fallback without final verdict."""
        # Populate DB with both feeds
        intel.ingest_feodo(self.conn, feed_url_or_path=str(FIXTURES_DIR / "sample_feodo.json"), allow_offline=True, force=True)
        intel.ingest_attack(self.conn, feed_url_or_path=str(FIXTURES_DIR / "sample_attack.json"), allow_offline=True, force=True)

        # 1. Match with known ATT&CK behavior profile (QakBot -> 198.51.100.14)
        qak_res = intel.lookup_ip("198.51.100.14", conn=self.conn)
        self.assertTrue(qak_res["match"])
        self.assertEqual(qak_res["malware_family"], "QakBot")
        self.assertEqual(qak_res["source"], "Feodo Tracker")
        self.assertIn("ago", qak_res["age"].lower())
        self.assertIsInstance(qak_res["behavior"], list)
        tech_ids = {b["technique_id"] for b in qak_res["behavior"]}
        self.assertIn("T1059.001", tech_ids)
        self.assertIn("T1071.001", tech_ids)
        # Verify verdict is non-definitive
        self.assertIn("Non-definitive", qak_res["final_verdict"])
        self.assertIn("disclaimer", qak_res)

        # 2. Match where malware family has NO behavior profile (UnknownFamilyXYZ -> 192.0.2.77)
        unk_res = intel.lookup_ip("192.0.2.77", conn=self.conn)
        self.assertTrue(unk_res["match"])
        self.assertEqual(unk_res["malware_family"], "UnknownFamilyXYZ")
        # Rule 7 requirement: والعائلة اللي بدون ملف سلوك ترجّع "unknown"
        self.assertEqual(unk_res["behavior"], "unknown", "Family without behavior profile must return 'unknown'")
        self.assertIn("Non-definitive", unk_res["final_verdict"])

        # 3. Bad IP syntax lookup
        bad_ip_res = intel.lookup_ip("999.999.999.999", conn=self.conn)
        self.assertFalse(bad_ip_res["match"])
        self.assertEqual(bad_ip_res["error"], "Invalid IP address syntax")
        self.assertEqual(bad_ip_res["final_verdict"], "None")

        # 4. Clean/Unknown IP lookup
        clean_res = intel.lookup_ip("8.8.8.8", conn=self.conn)
        self.assertFalse(clean_res["match"])
        self.assertEqual(clean_res["status"], "NOT_FOUND")
        self.assertIn("Non-definitive", clean_res["final_verdict"])


if __name__ == "__main__":
    unittest.main()
