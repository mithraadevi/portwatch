import os
import re
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # lets this file import its sibling test helpers

import chain
import drift
import storage
from test_migration import make_v2_db


def scan(target="localhost", ip="127.0.0.1", open_port=8000, started="2026-11-09T10:00:00+00:00"):
    results = [{"port": p, "state": "CLOSED", "detail": ""} for p in (7999, 8001) if p != open_port]
    results.append({"port": open_port, "state": "OPEN", "detail": "", "banner": "HTTP/1.0 200 OK",
                    "service_info": {"service": "http", "product": "SimpleHTTP/0.6",
                                     "confidence": "high", "evidence": "banner",
                                     "unexpected_for_port": False}})
    return {
        "target": target, "resolved_ip": ip, "started_at": started, "finished_at": started,
        "config": {"start_port": 7999, "end_port": 8001, "timeout": 3.0, "workers": 50,
                   "scanner_version": "1.1", "banner_grabbing": True, "rules_version": "2"},
        "acknowledgment": {"operator": "ADMIN", "acknowledged_at": started, "text_version": "1"},
        "results": sorted(results, key=lambda r: r["port"]),
    }


def filled_db(count=3):
    db = storage.connect(":memory:")
    ids = [storage.save_scan(db, scan(started=f"2026-11-0{i + 1}T10:00:00+00:00")) for i in range(count)]
    return db, ids


def recompute(db, scan_id):
    """What an attacker with full access would do: rewrite a scan's fingerprint to match its new data."""
    row = db.execute("SELECT prev_hash FROM scans WHERE id = ?", (scan_id,)).fetchone()
    new_hash = chain.fingerprint(row["prev_hash"], chain.canonical_record(db, scan_id))
    db.execute("UPDATE scans SET record_hash = ? WHERE id = ?", (new_hash, scan_id))
    db.commit()


class TestFingerprints(unittest.TestCase):
    def test_scans_are_chained_one_to_the_next(self):
        db, ids = filled_db(3)
        hashes = [db.execute("SELECT prev_hash, record_hash FROM scans WHERE id=?", (i,)).fetchone()
                  for i in ids]
        self.assertEqual(hashes[0]["prev_hash"], chain.GENESIS)
        self.assertEqual(hashes[1]["prev_hash"], hashes[0]["record_hash"])
        self.assertEqual(hashes[2]["prev_hash"], hashes[1]["record_hash"])
        for h in hashes:
            self.assertRegex(h["record_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(len({h["record_hash"] for h in hashes}), 3)

    def test_same_data_always_gives_the_same_fingerprint(self):
        first, second = storage.connect(":memory:"), storage.connect(":memory:")
        a = storage.save_scan(first, scan())
        b = storage.save_scan(second, scan())
        self.assertEqual(first.execute("SELECT record_hash FROM scans WHERE id=?", (a,)).fetchone()[0],
                         second.execute("SELECT record_hash FROM scans WHERE id=?", (b,)).fetchone()[0])

    def test_an_untouched_history_verifies(self):
        db, _ = filled_db(4)
        result = chain.verify(db)
        self.assertTrue(result["ok"])
        self.assertEqual((result["verified"], result["pre_chain"], result["broken"]), (4, 0, 0))
        self.assertIsNone(result["first_break"])

    def test_empty_database_verifies(self):
        result = chain.verify(storage.connect(":memory:"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["total"], 0)

    def test_loaded_scan_exposes_its_fingerprint(self):
        db, ids = filled_db(1)
        self.assertRegex(storage.load_scan(db, ids[0])["fingerprint"], r"^[0-9a-f]{64}$")
        self.assertTrue(storage.list_scans(db)[0]["chained"])


class TestTamperDetection(unittest.TestCase):
    def test_changed_port_result_is_detected_at_that_scan(self):
        db, ids = filled_db(3)
        db.execute("UPDATE port_results SET state='CLOSED' WHERE scan_id=? AND state='OPEN'", (ids[1],))
        db.commit()
        result = chain.verify(db)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["scan_id"], ids[1])
        self.assertIn("changed", result["first_break"]["problems"][0])
        self.assertEqual(result["scans"][ids[0]]["status"], "verified")
        self.assertEqual(result["scans"][ids[2]]["status"], "verified")  # later scans are judged fairly

    def test_each_kind_of_edit_is_noticed(self):
        edits = [
            "UPDATE scans SET target='elsewhere' WHERE id=1",
            "UPDATE scans SET resolved_ip='10.9.9.9' WHERE id=1",
            "UPDATE scans SET started_at='2020-01-01T00:00:00+00:00' WHERE id=1",
            "UPDATE scans SET config_json='{}' WHERE id=1",
            "UPDATE scans SET operator='someone-else' WHERE id=1",
            "UPDATE scans SET ack_at='2020-01-01T00:00:00+00:00' WHERE id=1",
            "UPDATE port_results SET banner='forged' WHERE scan_id=1 AND state='OPEN'",
            "UPDATE port_results SET service='ssh' WHERE scan_id=1 AND state='OPEN'",
            "DELETE FROM port_results WHERE scan_id=1 AND port=7999",
        ]
        for sql in edits:
            db, _ = filled_db(2)
            db.execute(sql)
            db.commit()
            result = chain.verify(db)
            self.assertFalse(result["ok"], sql)
            self.assertEqual(result["first_break"]["scan_id"], 1, sql)

    def test_rewriting_a_fingerprint_breaks_the_next_link(self):
        db, ids = filled_db(3)
        db.execute("UPDATE port_results SET state='CLOSED' WHERE scan_id=? AND state='OPEN'", (ids[1],))
        recompute(db, ids[1])  # the attacker also fixes scan 2's own fingerprint
        result = chain.verify(db)
        self.assertEqual(result["scans"][ids[1]]["status"], "verified")  # looks fine by itself
        self.assertEqual(result["first_break"]["scan_id"], ids[2])        # but scan 3 no longer links
        self.assertIn("does not link", result["first_break"]["problems"][0])

    def test_removing_a_scan_from_the_middle_is_detected(self):
        db, ids = filled_db(3)
        db.execute("DELETE FROM port_results WHERE scan_id=?", (ids[1],))
        db.execute("DELETE FROM scans WHERE id=?", (ids[1],))
        db.commit()
        result = chain.verify(db)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["scan_id"], ids[2])

    def test_stripping_a_fingerprint_is_detected(self):
        db, ids = filled_db(3)
        db.execute("UPDATE scans SET prev_hash=NULL, record_hash=NULL WHERE id=?", (ids[1],))
        db.commit()
        result = chain.verify(db)
        self.assertEqual(result["first_break"]["scan_id"], ids[1])
        self.assertIn("no fingerprint", result["first_break"]["problems"][0])


class TestKnownLimits(unittest.TestCase):
    """What the chain alone cannot catch. These tests document the limits honestly."""

    def test_rewriting_the_newest_scan_is_not_caught_by_the_chain_but_by_an_anchor(self):
        db, ids = filled_db(3)
        kept = db.execute("SELECT record_hash FROM scans WHERE id=?", (ids[2],)).fetchone()[0]
        db.execute("UPDATE port_results SET state='CLOSED' WHERE scan_id=? AND state='OPEN'", (ids[2],))
        recompute(db, ids[2])
        self.assertTrue(chain.verify(db)["ok"])                # the chain cannot tell
        self.assertIsNone(chain.find_anchor(db, kept))         # the kept fingerprint can

    def test_removing_the_newest_scan_is_not_caught_by_the_chain_but_by_an_anchor(self):
        db, ids = filled_db(3)
        kept = db.execute("SELECT record_hash FROM scans WHERE id=?", (ids[2],)).fetchone()[0]
        db.execute("DELETE FROM port_results WHERE scan_id=?", (ids[2],))
        db.execute("DELETE FROM scans WHERE id=?", (ids[2],))
        db.commit()
        self.assertTrue(chain.verify(db)["ok"])
        self.assertIsNone(chain.find_anchor(db, kept))

    def test_a_kept_fingerprint_is_found_while_history_is_intact(self):
        db, ids = filled_db(3)
        kept = db.execute("SELECT record_hash FROM scans WHERE id=?", (ids[1],)).fetchone()[0]
        self.assertEqual(chain.find_anchor(db, kept), ids[1])
        self.assertEqual(chain.find_anchor(db, "  " + kept.upper() + "\n"), ids[1])  # copy/paste noise
        self.assertIsNone(chain.find_anchor(db, "0" * 64))
        self.assertIsNone(chain.find_anchor(db, ""))
        self.assertIsNone(chain.find_anchor(db, None))


class TestExistingDatabases(unittest.TestCase):
    def test_old_scans_are_pre_chain_and_the_chain_starts_with_the_next_scan(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, "portwatch.db")
            make_v2_db(path)
            db = storage.connect(path)
            self.assertEqual(chain.verify(db)["pre_chain"], 1)
            new_id = storage.save_scan(db, scan())
            row = db.execute("SELECT prev_hash FROM scans WHERE id=?", (new_id,)).fetchone()
            self.assertEqual(row["prev_hash"], chain.GENESIS)  # not tied to the unverifiable scan
            result = chain.verify(db)
            self.assertTrue(result["ok"])
            self.assertEqual((result["pre_chain"], result["verified"]), (1, 1))
            db.close()

    def test_a_pre_chain_scan_appearing_after_chained_ones_is_flagged(self):
        db, ids = filled_db(2)
        db.execute("INSERT INTO scans (target, resolved_ip, started_at, finished_at, config_json) "
                   "VALUES ('x','127.0.0.1','t','t','{}')")
        db.commit()
        result = chain.verify(db)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"]["scan_id"], 3)


class TestConcurrentSaves(unittest.TestCase):
    def test_saves_from_two_connections_at_once_still_form_one_valid_chain(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, "portwatch.db")
            storage.connect(path).close()  # create the tables once, before the threads start
            errors = []

            def worker(label):
                try:
                    db = storage.connect(path)
                    for i in range(15):
                        storage.save_scan(db, scan(target=f"{label}-{i}"))
                    db.close()
                except Exception as exc:  # collect, so the test can report it
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(name,)) for name in ("a", "b", "c", "d")]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errors, [])
            db = storage.connect(path)
            result = chain.verify(db)
            self.assertEqual(result["total"], 60)
            self.assertTrue(result["ok"], result["first_break"])
            db.close()


class TestReportAndDriftIntegration(unittest.TestCase):
    def test_report_text(self):
        db, ids = filled_db(2)
        text = chain.render(chain.verify(db))
        self.assertIn("no changes detected", text)
        self.assertIn("Keep it somewhere outside", text)
        self.assertRegex(text, r"Latest fingerprint: [0-9a-f]{64}")
        self.assertIn("not tamper-proof", text)

        db.execute("UPDATE scans SET target='x' WHERE id=2")
        db.commit()
        broken = chain.render(chain.verify(db))
        self.assertIn("HISTORY BROKEN", broken)
        self.assertIn("scan #2", broken)

    def test_pre_chain_scans_are_explained_in_the_report(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, "portwatch.db")
            make_v2_db(path)
            db = storage.connect(path)
            text = chain.render(chain.verify(db))
            self.assertIn("pre-chain", text)
            self.assertIn("nothing to verify yet", text)  # must not claim "no changes detected"
            self.assertNotIn("no changes detected", text)
            self.assertNotIn("Latest fingerprint", text)  # nothing chained yet
            db.close()

    def test_drift_reports_verification_status_of_both_scans(self):
        db, ids = filled_db(2)
        db.execute("UPDATE scans SET target='x' WHERE id=?", (ids[0],))
        db.commit()
        old, new = storage.load_scan(db, ids[0]), storage.load_scan(db, ids[1])
        result = drift.compare_scans(old, new, verification=chain.verify(db)["scans"])
        self.assertTrue(any("FAILED history verification" in w and f"#{ids[0]}" in w
                            for w in result["warnings"]))
        self.assertTrue(any(f"Scan #{ids[1]}" in n and "passed history verification" in n
                            for n in result["notes"]))

    def test_drift_works_without_verification_information(self):
        db, ids = filled_db(2)
        result = drift.compare_scans(storage.load_scan(db, ids[0]), storage.load_scan(db, ids[1]))
        self.assertFalse(any("verification" in text for text in result["warnings"] + result["notes"]))


if __name__ == "__main__":
    unittest.main()
