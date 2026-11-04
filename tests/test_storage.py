import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import risk
import storage


def sample_scan(target="localhost", ports=(8000,), start=7990, end=8010):
    results = []
    for p in range(start, end + 1):
        if p in ports:
            results.append({
                "port": p, "state": "OPEN", "detail": "",
                "banner": "HTTP/1.0 200 OK | Server: SimpleHTTP/0.6",
                "service_info": {"service": "http", "product": "SimpleHTTP/0.6",
                                 "confidence": "high", "evidence": "banner",
                                 "unexpected_for_port": False},
            })
        else:
            results.append({"port": p, "state": "CLOSED", "detail": ""})
    return {
        "target": target, "resolved_ip": "127.0.0.1",
        "started_at": "2026-10-10T05:00:00+00:00",
        "finished_at": "2026-10-10T05:00:03+00:00",
        "config": {"start_port": start, "end_port": end, "timeout": 3.0,
                   "workers": 50, "scanner_version": "1.0", "banner_grabbing": True},
        "results": results,
    }


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.db = storage.connect(":memory:")

    def tearDown(self):
        self.db.close()

    def test_round_trip_keeps_everything(self):
        original = sample_scan()
        scan_id = storage.save_scan(self.db, original)
        loaded = storage.load_scan(self.db, scan_id)

        self.assertEqual(loaded["target"], original["target"])
        self.assertEqual(loaded["config"], original["config"])
        self.assertEqual(len(loaded["results"]), len(original["results"]))
        open_port = [r for r in loaded["results"] if r["state"] == "OPEN"][0]
        self.assertEqual(open_port["port"], 8000)
        self.assertEqual(open_port["service_info"]["service"], "http")
        self.assertIs(open_port["service_info"]["unexpected_for_port"], False)

    def test_loaded_scan_works_with_risk_module(self):
        scan_id = storage.save_scan(self.db, sample_scan())
        out = risk.assess(storage.load_scan(self.db, scan_id))
        self.assertEqual(out["exposure_score"], 1.0)

    def test_unenriched_scan_can_be_saved(self):
        scan = sample_scan()
        for r in scan["results"]:
            r.pop("service_info", None)
            r.pop("banner", None)
        scan_id = storage.save_scan(self.db, scan)
        loaded = storage.load_scan(self.db, scan_id)
        self.assertNotIn("service_info", loaded["results"][0])

    def test_list_scans_newest_first_and_filter(self):
        a = storage.save_scan(self.db, sample_scan("alpha"))
        b = storage.save_scan(self.db, sample_scan("beta"))
        c = storage.save_scan(self.db, sample_scan("alpha"))
        self.assertEqual([s["id"] for s in storage.list_scans(self.db)], [c, b, a])
        self.assertEqual([s["id"] for s in storage.list_scans(self.db, "alpha")], [c, a])
        self.assertEqual(storage.list_scans(self.db)[0]["ports"], "7990-8010")

    def test_load_missing_scan_raises(self):
        with self.assertRaises(ValueError):
            storage.load_scan(self.db, 999)

    def test_hostile_target_name_is_stored_as_plain_text(self):
        evil = "x'); DROP TABLE scans; --"
        scan_id = storage.save_scan(self.db, sample_scan(evil))
        self.assertEqual(storage.load_scan(self.db, scan_id)["target"], evil)
        self.assertEqual(len(storage.list_scans(self.db)), 1)  # table still exists

    def test_failed_save_leaves_nothing_behind(self):
        bad = sample_scan()
        del bad["results"][0]["port"]  # makes the port rows fail halfway
        with self.assertRaises(KeyError):
            storage.save_scan(self.db, bad)
        self.assertEqual(storage.list_scans(self.db), [])  # the scan row was rolled back


if __name__ == "__main__":
    unittest.main()
