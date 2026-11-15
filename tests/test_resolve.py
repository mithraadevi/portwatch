import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import banner
import scanner
import storage


def fake_dns(*addresses):
    """Build what socket.getaddrinfo returns for the given addresses."""
    infos = []
    for a in addresses:
        if ":" in a:
            infos.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (a, 0, 0, 0)))
        else:
            infos.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)))
    return infos


def ipv6_loopback_available():
    """True if this machine can listen on ::1 (some machines have IPv6 switched off)."""
    if not socket.has_ipv6:
        return False
    try:
        s = socket.socket(socket.AF_INET6)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


class TestNormalize(unittest.TestCase):
    def test_different_spellings_become_one_form(self):
        self.assertEqual(scanner.normalize_address("0:0:0:0:0:0:0:1"), "::1")
        self.assertEqual(scanner.normalize_address("::1"), "::1")
        self.assertEqual(scanner.normalize_address("2001:0DB8:0:0:0:0:0:2"), "2001:db8::2")
        self.assertEqual(scanner.normalize_address("127.0.0.1"), "127.0.0.1")

    def test_non_address_is_returned_unchanged(self):
        self.assertEqual(scanner.normalize_address("not-an-ip"), "not-an-ip")


class TestResolveTarget(unittest.TestCase):
    def test_ipv4_literal(self):
        r = scanner.resolve_target("127.0.0.1")
        self.assertEqual((r["address"], r["version"]), ("127.0.0.1", 4))

    @unittest.skipUnless(socket.has_ipv6, "IPv6 not available here")
    def test_ipv6_literal_in_long_form_is_normalized(self):
        r = scanner.resolve_target("0:0:0:0:0:0:0:1", "6")
        self.assertEqual((r["address"], r["version"]), ("::1", 6))

    def test_choice_is_repeatable_whatever_order_dns_answers_in(self):
        addrs = ["2001:db8::2", "10.0.0.9", "10.0.0.2", "2001:db8::1"]
        expected_all = ["10.0.0.2", "10.0.0.9", "2001:db8::1", "2001:db8::2"]
        for order in (addrs, list(reversed(addrs))):
            with mock.patch("socket.getaddrinfo", return_value=fake_dns(*order)):
                r = scanner.resolve_target("example.test")
            self.assertEqual(r["address"], "10.0.0.2")  # lowest IPv4 wins under auto
            self.assertEqual(r["all"], expected_all)

    def test_duplicate_answers_are_collapsed(self):
        with mock.patch("socket.getaddrinfo", return_value=fake_dns("10.0.0.2", "10.0.0.2", "10.0.0.2")):
            r = scanner.resolve_target("example.test")
        self.assertEqual(r["all"], ["10.0.0.2"])

    def test_explicit_ipv6_choice(self):
        with mock.patch("socket.getaddrinfo", return_value=fake_dns("10.0.0.2", "2001:db8::2", "2001:db8::1")):
            r = scanner.resolve_target("example.test", "6")
        self.assertEqual((r["address"], r["version"]), ("2001:db8::1", 6))

    def test_auto_falls_back_to_ipv6_only_when_no_ipv4_exists(self):
        with mock.patch("socket.getaddrinfo", return_value=fake_dns("2001:db8::1")):
            r = scanner.resolve_target("example.test", "auto")
            self.assertEqual(r["version"], 6)
            with self.assertRaises(ValueError):
                scanner.resolve_target("example.test", "4")

    def test_requesting_ipv6_for_an_ipv4_only_name_fails_clearly(self):
        with mock.patch("socket.getaddrinfo", return_value=fake_dns("10.0.0.2")):
            with self.assertRaises(ValueError):
                scanner.resolve_target("example.test", "6")

    def test_invalid_version_choice(self):
        with self.assertRaises(ValueError):
            scanner.resolve_target("127.0.0.1", "5")

    def test_unresolvable_name(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror):
            with self.assertRaises(ValueError):
                scanner.resolve_target("nothing.invalid")


class TestScanRecordsResolution(unittest.TestCase):
    def test_scan_stores_resolution_details(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        try:
            data = scanner.scan("127.0.0.1", port, port, timeout=2.0, workers=1)
        finally:
            server.close()
        cfg = data["config"]
        self.assertEqual(data["resolved_ip"], "127.0.0.1")
        self.assertEqual(cfg["ip_version_requested"], "auto")
        self.assertEqual(cfg["ip_version"], 4)
        self.assertEqual(cfg["resolved_addresses"], ["127.0.0.1"])
        self.assertEqual(cfg["scanner_version"], "1.1")

    @unittest.skipUnless(ipv6_loopback_available(), "no IPv6 loopback on this machine")
    def test_ipv6_scan_end_to_end(self):
        server = socket.socket(socket.AF_INET6)
        server.bind(("::1", 0))
        server.listen()
        port = server.getsockname()[1]
        try:
            data = scanner.scan("::1", port, port, timeout=3.0, workers=1, ip_version="6")
        finally:
            server.close()
        self.assertEqual(data["results"][0]["state"], scanner.OPEN)
        self.assertEqual(data["config"]["ip_version"], 6)
        self.assertEqual(data["resolved_ip"], "::1")

    def test_new_settings_survive_saving_and_loading(self):
        db = storage.connect(":memory:")
        data = {
            "target": "example.test", "resolved_ip": "10.0.0.2",
            "started_at": "2026-11-09T10:00:00+00:00", "finished_at": "2026-11-09T10:00:01+00:00",
            "config": {"start_port": 1, "end_port": 2, "timeout": 3.0, "workers": 5,
                       "ip_version_requested": "auto", "ip_version": 4,
                       "resolved_addresses": ["10.0.0.2", "10.0.0.9"],
                       "scanner_version": "1.1", "banner_grabbing": True,
                       "banner_timeout": 2.0, "rules_version": "2"},
            "results": [{"port": 1, "state": "CLOSED", "detail": ""},
                        {"port": 2, "state": "CLOSED", "detail": ""}],
        }
        loaded = storage.load_scan(db, storage.save_scan(db, data))
        self.assertEqual(loaded["config"], data["config"])
        db.close()


class TestRulesAndBannerSettings(unittest.TestCase):
    def test_enrich_records_rules_version_and_banner_timeout(self):
        data = {"resolved_ip": "127.0.0.1", "config": {}, "results": [{"port": 5, "state": "CLOSED"}]}
        banner.enrich(data, timeout=2.5)
        self.assertEqual(data["config"]["banner_timeout"], 2.5)
        self.assertEqual(data["config"]["rules_version"], banner.RULES_VERSION)
        self.assertTrue(data["config"]["banner_grabbing"])

    def test_smb_is_guessed_from_port_445_with_low_confidence(self):
        info = banner.identify_service(445, "")
        self.assertEqual(info["service"], "smb")
        self.assertEqual(info["confidence"], "low")


if __name__ == "__main__":
    unittest.main()
