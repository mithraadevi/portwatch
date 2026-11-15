import glob
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import storage

# The database layout of the first release of storage (before the authorization
# columns existed). Written out here on purpose, so these tests do not depend on
# the current code to build an "old" database.
LEGACY_SCHEMA = """
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, resolved_ip TEXT NOT NULL,
    started_at TEXT NOT NULL, finished_at TEXT NOT NULL, config_json TEXT NOT NULL);
CREATE TABLE port_results (
    scan_id INTEGER NOT NULL REFERENCES scans(id), port INTEGER NOT NULL, state TEXT NOT NULL,
    detail TEXT, banner TEXT, service TEXT, product TEXT, confidence TEXT, evidence TEXT,
    unexpected INTEGER, PRIMARY KEY (scan_id, port));
"""


def make_legacy_db(path):
    """Create an old-style database holding one scan with two ports."""
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SCHEMA)
    conn.execute("INSERT INTO scans (target, resolved_ip, started_at, finished_at, config_json) "
                 "VALUES (?,?,?,?,?)",
                 ("localhost", "127.0.0.1", "2026-11-03T10:00:00+00:00",
                  "2026-11-03T10:00:03+00:00",
                  json.dumps({"start_port": 444, "end_port": 445, "timeout": 6.0})))
    conn.execute("INSERT INTO port_results (scan_id, port, state, detail) VALUES (1, 444, 'CLOSED', '')")
    conn.execute("INSERT INTO port_results (scan_id, port, state, detail, banner, service, product, "
                 "confidence, evidence, unexpected) VALUES (1, 445, 'OPEN', '', '', 'unknown', '', "
                 "'unknown', 'no banner, no port guess', 0)")
    conn.commit()
    conn.close()


def sample_scan(ack=None):
    scan = {
        "target": "localhost", "resolved_ip": "127.0.0.1",
        "started_at": "2026-11-09T10:00:00+00:00", "finished_at": "2026-11-09T10:00:01+00:00",
        "config": {"start_port": 1, "end_port": 1, "timeout": 3.0},
        "results": [{"port": 1, "state": "CLOSED", "detail": ""}],
    }
    if ack:
        scan["acknowledgment"] = ack
    return scan


class TestFreshDatabase(unittest.TestCase):
    def test_new_database_is_at_the_current_version_with_audit_columns(self):
        db = storage.connect(":memory:")
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], storage.SCHEMA_VERSION)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(scans)")}
        self.assertTrue({"operator", "ack_at", "ack_version"} <= columns)
        db.close()


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = os.path.join(self.tmp.name, "portwatch.db")
        make_legacy_db(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_old_database_is_upgraded_and_keeps_its_scans(self):
        db = storage.connect(self.path)
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
        scan = storage.load_scan(db, 1)
        self.assertEqual(scan["target"], "localhost")
        self.assertEqual(len(scan["results"]), 2)
        self.assertEqual(scan["results"][1]["service_info"]["service"], "unknown")
        db.close()

    def test_old_scans_are_marked_pre_audit_and_nothing_is_invented(self):
        db = storage.connect(self.path)
        self.assertIsNone(storage.load_scan(db, 1)["acknowledgment"])
        self.assertFalse(storage.list_scans(db)[0]["audited"])
        db.close()

    def test_a_backup_with_the_original_data_is_made_before_upgrading(self):
        messages = []
        storage.connect(self.path, on_migrate=messages.append).close()
        backups = glob.glob(os.path.join(self.tmp.name, "portwatch.pre-migration-*.db"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(messages and "backup" in messages[0].lower())
        old = sqlite3.connect(backups[0])
        self.assertEqual(old.execute("PRAGMA user_version").fetchone()[0], 0)  # still the old layout
        self.assertEqual(old.execute("SELECT COUNT(*) FROM port_results").fetchone()[0], 2)
        old.close()

    def test_connecting_again_does_nothing_more(self):
        storage.connect(self.path).close()
        storage.connect(self.path).close()
        backups = glob.glob(os.path.join(self.tmp.name, "portwatch.pre-migration-*.db"))
        self.assertEqual(len(backups), 1)  # no second backup, no error

    def test_an_interrupted_upgrade_can_be_finished(self):
        # Simulate a crash after one column was added but before the version was set.
        conn = sqlite3.connect(self.path)
        conn.execute("ALTER TABLE scans ADD COLUMN operator TEXT")
        conn.commit()
        conn.close()
        db = storage.connect(self.path)
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(scans)")}
        self.assertTrue({"operator", "ack_at", "ack_version"} <= columns)
        db.close()

    def test_a_database_from_a_newer_version_is_refused(self):
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA user_version = 99")
        conn.commit()
        conn.close()
        with self.assertRaises(ValueError):
            storage.connect(self.path)


class TestStoredAcknowledgment(unittest.TestCase):
    def test_acknowledgment_round_trip(self):
        ack = {"operator": "ADMIN", "acknowledged_at": "2026-11-09T10:00:00+00:00", "text_version": "1"}
        db = storage.connect(":memory:")
        scan_id = storage.save_scan(db, sample_scan(ack))
        self.assertEqual(storage.load_scan(db, scan_id)["acknowledgment"], ack)
        self.assertTrue(storage.list_scans(db)[0]["audited"])
        db.close()

    def test_scan_without_acknowledgment_is_stored_as_pre_audit(self):
        db = storage.connect(":memory:")
        scan_id = storage.save_scan(db, sample_scan())
        self.assertIsNone(storage.load_scan(db, scan_id)["acknowledgment"])
        db.close()

    def test_hostile_operator_name_is_stored_as_plain_text(self):
        evil = "x'); DROP TABLE scans; --"
        ack = {"operator": evil, "acknowledged_at": "2026-11-09T10:00:00+00:00", "text_version": "1"}
        db = storage.connect(":memory:")
        scan_id = storage.save_scan(db, sample_scan(ack))
        self.assertEqual(storage.load_scan(db, scan_id)["acknowledgment"]["operator"], evil)
        self.assertEqual(len(storage.list_scans(db)), 1)
        db.close()


if __name__ == "__main__":
    unittest.main()
