import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import drift
import storage

OPEN_INFO = {"unexpected_for_port": False, "evidence": "banner"}


def make_scan(scan_id=1, ip="127.0.0.1", start=400, end=410, open_ports=None, states=None,
              started="2026-11-08T10:00:00+00:00", target="localhost", **config):
    """Build a scan dictionary.

    open_ports: {port: (service, product, confidence)}
    states:     {port: "NO_RESPONSE" / "ERROR" / ...} overriding the default CLOSED
    config:     overrides for the stored settings (rules_version=None removes it, etc.)
    """
    open_ports = open_ports or {}
    states = states or {}
    results = []
    for p in range(start, end + 1):
        if p in open_ports:
            service, product, confidence = open_ports[p]
            results.append({"port": p, "state": "OPEN", "detail": "", "banner": "",
                            "service_info": {"service": service, "product": product,
                                             "confidence": confidence, **OPEN_INFO}})
        else:
            results.append({"port": p, "state": states.get(p, "CLOSED"), "detail": ""})
    cfg = {"start_port": start, "end_port": end, "timeout": 3.0, "workers": 50,
           "scanner_version": "1.1", "banner_grabbing": True, "rules_version": "2",
           "ip_version": 6 if ":" in ip else 4}
    for key, value in config.items():
        if value is None:
            cfg.pop(key, None)
        else:
            cfg[key] = value
    return {"id": scan_id, "target": target, "resolved_ip": ip, "started_at": started,
            "finished_at": started, "config": cfg, "results": results}


HTTP = ("http", "SimpleHTTP/0.6", "high")


class TestBasicComparison(unittest.TestCase):
    def test_identical_scans_show_no_drift(self):
        a = make_scan(1, open_ports={405: HTTP})
        b = make_scan(2, open_ports={405: HTTP}, started="2026-11-09T10:00:00+00:00")
        r = drift.compare_scans(a, b)
        self.assertTrue(r["comparable"])
        self.assertFalse(r["has_drift"])
        self.assertEqual(r["compared_ports"], 11)
        self.assertEqual((r["newly_opened"], r["newly_closed"], r["service_changed"]), ([], [], []))

    def test_newly_opened_and_newly_closed(self):
        a = make_scan(1, open_ports={402: HTTP})
        b = make_scan(2, open_ports={407: ("ssh", "OpenSSH_9.6", "high")},
                      started="2026-11-09T10:00:00+00:00")
        r = drift.compare_scans(a, b)
        self.assertEqual([p["port"] for p in r["newly_opened"]], [407])
        self.assertEqual(r["newly_opened"][0]["service"], "ssh")
        self.assertEqual([p["port"] for p in r["newly_closed"]], [402])
        self.assertTrue(r["has_drift"])


class TestIdentity(unittest.TestCase):
    def test_different_addresses_are_not_compared(self):
        r = drift.compare_scans(make_scan(1, ip="10.0.0.1"), make_scan(2, ip="10.0.0.2"))
        self.assertFalse(r["comparable"])
        self.assertEqual(r["blocked_kind"], "address")
        self.assertIn("10.0.0.1", r["blocked_reason"])
        self.assertIn("10.0.0.2", r["blocked_reason"])

    def test_override_compares_with_a_warning(self):
        r = drift.compare_scans(make_scan(1, ip="10.0.0.1"), make_scan(2, ip="10.0.0.2"),
                                allow_different_address=True)
        self.assertTrue(r["comparable"])
        self.assertTrue(any("different addresses" in w.lower() for w in r["warnings"]))

    def test_same_name_resolving_elsewhere_is_called_out(self):
        r = drift.compare_scans(make_scan(1, ip="10.0.0.1", target="example.test"),
                                make_scan(2, ip="10.0.0.2", target="example.test"))
        self.assertIn("resolved to different addresses", r["blocked_reason"])

    def test_ipv4_against_ipv6_is_not_compared(self):
        r = drift.compare_scans(make_scan(1, ip="127.0.0.1"), make_scan(2, ip="::1"))
        self.assertFalse(r["comparable"])
        self.assertIn("IPv4", r["blocked_reason"])
        self.assertIn("IPv6", r["blocked_reason"])

    def test_different_spellings_of_one_address_are_the_same_target(self):
        r = drift.compare_scans(make_scan(1, ip="::1"), make_scan(2, ip="0:0:0:0:0:0:0:1"))
        self.assertTrue(r["comparable"])

    def test_different_names_same_address_only_adds_a_note(self):
        r = drift.compare_scans(make_scan(1, target="localhost"), make_scan(2, target="127.0.0.1"))
        self.assertTrue(r["comparable"])
        self.assertTrue(any("different names" in n for n in r["notes"]))


class TestPortRangesAndStates(unittest.TestCase):
    def test_only_the_overlap_is_compared(self):
        a = make_scan(1, start=400, end=420, open_ports={402: HTTP})   # outside the overlap
        b = make_scan(2, start=410, end=430, open_ports={425: HTTP})   # outside the overlap
        r = drift.compare_scans(a, b)
        self.assertEqual(r["overlap"], (410, 420))
        self.assertEqual(r["compared_ports"], 11)
        self.assertEqual((r["newly_opened"], r["newly_closed"]), ([], []))
        self.assertTrue(any("Only ports 410-420" in n for n in r["notes"]))

    def test_ranges_that_do_not_overlap_cannot_be_compared(self):
        r = drift.compare_scans(make_scan(1, start=400, end=410), make_scan(2, start=500, end=510))
        self.assertFalse(r["comparable"])
        self.assertEqual(r["blocked_kind"], "ports")

    def test_ports_without_a_definite_answer_are_unknown_not_changed(self):
        a = make_scan(1, states={405: "NO_RESPONSE", 406: "ERROR"})
        b = make_scan(2, open_ports={405: HTTP, 406: HTTP})  # now OPEN, but before was unknown
        r = drift.compare_scans(a, b)
        self.assertEqual([u["port"] for u in r["unknown_ports"]], [405, 406])
        self.assertEqual(r["newly_opened"], [])
        self.assertEqual(r["compared_ports"], 9)
        self.assertFalse(r["has_drift"])


class TestLabelsAndRules(unittest.TestCase):
    def test_label_change_with_same_rules_is_a_change_on_the_target(self):
        a = make_scan(1, open_ports={405: ("http", "SimpleHTTP/0.6", "high")})
        b = make_scan(2, open_ports={405: ("http", "nginx/1.25", "high")})
        r = drift.compare_scans(a, b)
        self.assertEqual(len(r["service_changed"]), 1)
        self.assertEqual(r["service_changed"][0]["reason"], "target_changed")
        self.assertEqual(r["service_changed"][0]["new_product"], "nginx/1.25")
        self.assertTrue(r["has_drift"])

    def test_unknown_to_smb_with_different_rules_is_not_target_drift(self):
        # The real case from the project: port 445 was 'unknown' before SMB rules existed.
        # SSH stands in here so the test does not depend on a rating you may edit.
        a = make_scan(1, open_ports={405: ("unknown", "", "unknown")}, rules_version=None)
        b = make_scan(2, open_ports={405: ("ssh", "", "low")}, rules_version="2")
        r = drift.compare_scans(a, b)
        self.assertEqual(r["service_changed"][0]["reason"], "rules_differ")
        self.assertEqual(r["severity_changed"][0]["old"], "Needs review")
        self.assertEqual(r["severity_changed"][0]["new"], "Medium")
        self.assertEqual(r["severity_changed"][0]["reason"], "rules_differ")
        self.assertFalse(r["has_drift"])
        self.assertTrue(any("rules differ" in w.lower() for w in r["warnings"]))

    def test_severity_change_from_a_real_service_change(self):
        a = make_scan(1, open_ports={405: ("ssh", "OpenSSH_9.6", "high")})
        b = make_scan(2, open_ports={405: ("telnet", "", "high")})
        r = drift.compare_scans(a, b)
        self.assertEqual((r["severity_changed"][0]["old"], r["severity_changed"][0]["new"]),
                         ("Medium", "Critical"))
        self.assertEqual(r["severity_changed"][0]["reason"], "target_changed")
        self.assertTrue(r["has_drift"])

    def test_labels_are_not_compared_when_banner_grabbing_differs(self):
        a = make_scan(1, open_ports={405: HTTP, 406: HTTP}, banner_grabbing=False)
        b = make_scan(2, open_ports={405: ("ssh", "", "high"), 407: HTTP})
        r = drift.compare_scans(a, b)
        self.assertEqual(r["service_changed"], [])
        self.assertTrue(any("not compared" in n.lower() for n in r["notes"]))
        self.assertEqual([p["port"] for p in r["newly_opened"]], [407])  # states still compared
        self.assertEqual([p["port"] for p in r["newly_closed"]], [406])


class TestSettingsAndOrder(unittest.TestCase):
    def test_differing_settings_are_reported(self):
        a = make_scan(1, scanner_version="1.0", timeout=6.0, workers=10)
        b = make_scan(2, scanner_version="1.1", timeout=3.0, workers=50)
        r = drift.compare_scans(a, b)
        self.assertTrue(any("Scanner versions differ" in w for w in r["warnings"]))
        self.assertTrue(any("timeouts differ" in n for n in r["notes"]))
        self.assertTrue(any("Worker counts differ" in n for n in r["notes"]))

    def test_scans_given_in_reverse_time_order_get_a_warning(self):
        old = make_scan(1, started="2026-11-09T10:00:00+00:00")
        new = make_scan(2, started="2026-11-08T10:00:00+00:00")
        r = drift.compare_scans(old, new)
        self.assertTrue(any("newer than the second" in w for w in r["warnings"]))


class TestWithStoredScansAndReport(unittest.TestCase):
    def test_saved_scans_can_be_loaded_and_compared(self):
        db = storage.connect(":memory:")
        first = storage.save_scan(db, make_scan(None, open_ports={405: HTTP}))
        second = storage.save_scan(db, make_scan(None, open_ports={405: HTTP, 408: ("ssh", "x", "high")},
                                                started="2026-11-09T10:00:00+00:00"))
        r = drift.compare_scans(storage.load_scan(db, first), storage.load_scan(db, second))
        self.assertEqual([p["port"] for p in r["newly_opened"]], [408])
        self.assertTrue(any("pre-audit" in n for n in r["notes"]))
        db.close()

    def test_report_text_covers_the_main_outcomes(self):
        a = make_scan(1, open_ports={402: HTTP})
        b = make_scan(2, open_ports={407: ("ssh", "OpenSSH_9.6", "high")})
        text = drift.render(drift.compare_scans(a, b))
        self.assertIn("DRIFT DETECTED", text)
        self.assertIn("Newly opened ports", text)
        self.assertIn("Port 407 ssh", text)
        self.assertIn("Newly closed ports", text)
        self.assertIn("evidence of change, not proof", text)

        blocked = drift.render(drift.compare_scans(make_scan(1, ip="10.0.0.1"), make_scan(2, ip="10.0.0.2")))
        self.assertIn("NOT COMPARED", blocked)

        clean = drift.render(drift.compare_scans(make_scan(1), make_scan(2)))
        self.assertIn("no drift in the compared ports", clean)


if __name__ == "__main__":
    unittest.main()
