import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chain
import storage
import ui_data
from test_chain import scan as chained_scan
from test_migration import make_legacy_db, make_v2_db


def make_db(path, scans=2):
    db = storage.connect(path)
    for i in range(scans):
        storage.save_scan(db, chained_scan(started=f"2026-11-0{i + 1}T10:00:00+00:00"))
    db.close()


class TestOpenReadonly(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = os.path.join(self.tmp.name, "portwatch.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_good_database_opens_and_cannot_be_written(self):
        make_db(self.path)
        conn, problem = ui_data.open_readonly(self.path)
        self.assertIsNone(problem)
        self.assertEqual(len(storage.list_scans(conn)), 2)
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("UPDATE scans SET target = 'changed'")
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("DELETE FROM port_results")
        conn.close()

    def test_a_missing_database_is_reported_and_not_created(self):
        conn, problem = ui_data.open_readonly(self.path)
        self.assertIsNone(conn)
        self.assertIn("No database found", problem)
        self.assertFalse(os.path.exists(self.path))  # a read-only view must not create files

    def test_an_old_database_is_not_upgraded_by_looking_at_it(self):
        make_v2_db(self.path)
        before = Path(self.path).read_bytes()
        conn, problem = ui_data.open_readonly(self.path)
        self.assertIsNone(conn)
        self.assertIn("python storage.py", problem)
        self.assertEqual(Path(self.path).read_bytes(), before)       # file untouched
        self.assertEqual(os.listdir(self.tmp.name), ["portwatch.db"])  # and no backup was made

    def test_a_very_old_database_is_also_left_alone(self):
        make_legacy_db(self.path)
        conn, problem = ui_data.open_readonly(self.path)
        self.assertIsNone(conn)
        self.assertIn("older layout", problem)

    def test_a_database_from_a_newer_version_is_refused(self):
        make_db(self.path, scans=1)
        raw = sqlite3.connect(self.path)
        raw.execute("PRAGMA user_version = 99")
        raw.commit()
        raw.close()
        conn, problem = ui_data.open_readonly(self.path)
        self.assertIsNone(conn)
        self.assertIn("newer version", problem)

    def test_something_that_is_not_a_portwatch_database(self):
        raw = sqlite3.connect(self.path)
        raw.execute("CREATE TABLE other (x)")
        raw.commit()
        raw.close()
        conn, problem = ui_data.open_readonly(self.path)
        self.assertIsNone(conn)
        self.assertIn("not a PortWatch database", problem)

    def test_a_file_that_is_not_a_database_at_all(self):
        with open(self.path, "w") as f:
            f.write("this is just text, not a database " * 50)
        conn, problem = ui_data.open_readonly(self.path)
        self.assertIsNone(conn)
        self.assertTrue(problem)

    def test_a_path_with_spaces_and_odd_characters(self):
        odd = os.path.join(self.tmp.name, "my scans #1 (copy)")
        os.makedirs(odd)
        path = os.path.join(odd, "portwatch.db")
        make_db(path, scans=1)
        conn, problem = ui_data.open_readonly(path)
        self.assertIsNone(problem)
        conn.close()

    def test_the_database_path_can_be_overridden(self):
        old = os.environ.get(ui_data.ENV_DB)
        try:
            os.environ[ui_data.ENV_DB] = "/somewhere/else.db"
            self.assertEqual(ui_data.db_path(), "/somewhere/else.db")
            del os.environ[ui_data.ENV_DB]
            self.assertEqual(ui_data.db_path(), storage.DEFAULT_DB)
        finally:
            if old is not None:
                os.environ[ui_data.ENV_DB] = old


class TestNetworkExposure(unittest.TestCase):
    def test_only_loopback_addresses_count_as_private(self):
        for private in ("localhost", "127.0.0.1", "::1"):
            self.assertFalse(ui_data.is_network_exposed(private), private)

    def test_unset_or_open_addresses_count_as_exposed(self):
        for exposed in (None, "", "0.0.0.0", "::", "192.168.1.20"):
            self.assertTrue(ui_data.is_network_exposed(exposed), exposed)


class TestTablesAndLabels(unittest.TestCase):
    def setUp(self):
        self.db = storage.connect(":memory:")
        self.ids = [storage.save_scan(self.db, chained_scan(started=f"2026-11-0{i + 1}T10:00:00+00:00"))
                    for i in range(3)]

    def tearDown(self):
        self.db.close()

    def test_history_rows_are_newest_first_with_labels(self):
        rows = ui_data.scan_rows(self.db)
        self.assertEqual([r["ID"] for r in rows], [3, 2, 1])
        self.assertEqual(rows[0]["History"], "verified")
        self.assertEqual(rows[0]["Authorization"], "recorded")
        self.assertEqual(rows[0]["Started"], "2026-11-03 10:00 UTC")
        self.assertEqual(rows[0]["Ports"], "7999-8001")

    def test_a_broken_scan_is_labelled_loudly(self):
        self.db.execute("UPDATE scans SET target='x' WHERE id=2")
        self.db.commit()
        history = {r["ID"]: r["History"] for r in ui_data.scan_rows(self.db)}
        self.assertEqual(history[2], "BROKEN")
        self.assertEqual(history[1], "verified")

    def test_a_scan_without_a_fingerprint_after_chained_ones_is_flagged(self):
        self.db.execute("INSERT INTO scans (target, resolved_ip, started_at, finished_at, config_json) "
                        "VALUES ('old','127.0.0.1','2026-10-01T10:00:00+00:00','t','{\"start_port\":1,\"end_port\":2}')")
        self.db.commit()
        row = ui_data.scan_rows(self.db, chain.verify(self.db)["scans"])[0]
        self.assertEqual(row["Authorization"], "pre-audit")
        # A scan with no fingerprint that appears AFTER chained scans is a red flag: either
        # a fingerprint was stripped or a scan was slipped in outside PortWatch.
        self.assertEqual(row["History"], "BROKEN")

    def test_scan_label_is_one_readable_line(self):
        label = ui_data.scan_label(storage.list_scans(self.db)[0])
        self.assertIn("#3", label)
        self.assertIn("localhost", label)
        self.assertIn("2026-11-03 10:00 UTC", label)

    def test_format_time_copes_with_bad_input(self):
        self.assertEqual(ui_data.format_time("2026-11-22T06:44:21.720409+00:00"), "2026-11-22 06:44 UTC")
        self.assertEqual(ui_data.format_time("garbage"), "garbage")
        self.assertEqual(ui_data.format_time(None), "None")

    def test_verification_messages(self):
        level, text = ui_data.verification_message(chain.verify(self.db))
        self.assertEqual(level, "success")
        self.assertIn("3 scan(s) verified", text)

        self.db.execute("UPDATE scans SET target='x' WHERE id=2")
        self.db.commit()
        level, text = ui_data.verification_message(chain.verify(self.db))
        self.assertEqual(level, "error")
        self.assertIn("scan #2", text)

        level, text = ui_data.verification_message(chain.verify(storage.connect(":memory:")))
        self.assertEqual(level, "info")

    def test_only_pre_chain_scans_means_nothing_to_verify(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, "portwatch.db")
            make_v2_db(path)
            db = storage.connect(path)
            level, text = ui_data.verification_message(chain.verify(db))
            self.assertEqual(level, "info")
            self.assertIn("none can be verified", text)
            db.close()


class TestScanView(unittest.TestCase):
    def setUp(self):
        self.db = storage.connect(":memory:")
        scan = chained_scan()
        scan["results"][1]["banner"] = "<script>alert(1)</script> ![x](http://evil.example/x.png)"
        scan["config"]["ip_version"] = 4
        scan["config"]["resolved_addresses"] = ["127.0.0.1", "::1"]
        scan["results"].append({"port": 9000, "state": "NO_RESPONSE", "detail": "no reply within 3.0s"})
        scan["config"]["end_port"] = 9000
        self.sid = storage.save_scan(self.db, scan)
        self.scan = storage.load_scan(self.db, self.sid)

    def tearDown(self):
        self.db.close()

    def test_everything_the_page_needs_is_in_the_view(self):
        view = ui_data.scan_view(self.scan)
        self.assertEqual(view["counts"]["OPEN"], 1)
        self.assertEqual(view["counts"]["NO_RESPONSE"], 1)
        self.assertEqual(view["findings"][0]["Port"], 8000)
        self.assertEqual(view["findings"][0]["Severity"], "Medium")
        self.assertEqual(view["assessment"]["verdict"], "LOW EXPOSURE")
        self.assertEqual(view["unchecked"], [{"Port": 9000, "State": "NO_RESPONSE", "Detail": "no reply within 3.0s"}])

    def test_facts_show_the_address_family_other_addresses_and_authorization(self):
        facts = dict(ui_data.describe_scan(self.scan))
        self.assertEqual(facts["Address scanned"], "127.0.0.1 (IPv4)")
        self.assertEqual(facts["Also resolves to (not scanned)"], "::1")
        self.assertIn("confirmed by ADMIN", facts["Authorization"])
        self.assertEqual(facts["Identification rules"], "2")

    def test_a_pre_audit_scan_says_so(self):
        scan = dict(self.scan, acknowledgment=None)
        facts = dict(ui_data.describe_scan(scan))
        self.assertIn("pre-audit", facts["Authorization"])

    def test_banner_text_is_returned_unchanged_for_safe_display(self):
        # The data layer must not "fix" or interpret untrusted text; the page shows it in st.code.
        self.assertEqual(ui_data.banner_rows(self.scan),
                         [(8000, "<script>alert(1)</script> ![x](http://evil.example/x.png)")])

    def test_a_scan_with_no_open_ports_has_an_empty_findings_table(self):
        empty = chained_scan()
        empty["results"] = [{"port": p, "state": "CLOSED", "detail": ""} for p in (7999, 8000, 8001)]
        sid = storage.save_scan(self.db, empty)
        view = ui_data.scan_view(storage.load_scan(self.db, sid))
        self.assertEqual(view["findings"], [])
        self.assertEqual(view["banners"], [])
        self.assertEqual(view["assessment"]["verdict"], "NO EXPOSURE FOUND")


if __name__ == "__main__":
    unittest.main()
