import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner


def free_port():
    """Ask the OS for an unused port, then release it (so it is CLOSED)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestCheckPort(unittest.TestCase):
    def test_open_port_detected(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        try:
            result = scanner.check_port("127.0.0.1", port, 1.0)
            self.assertEqual(result.state, scanner.OPEN)
        finally:
            server.close()

    def test_closed_port_detected(self):
        result = scanner.check_port("127.0.0.1", free_port(), 1.0)
        self.assertEqual(result.state, scanner.CLOSED)


class TestValidation(unittest.TestCase):
    def test_bad_port_values(self):
        for start, end in [(0, 10), (1, 70000), (-5, 10)]:
            with self.assertRaises(ValueError):
                scanner.validate_scan_request(start, end, 1.0, 10)

    def test_end_before_start(self):
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(100, 50, 1.0, 10)

    def test_scan_too_large(self):
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(1, scanner.MAX_PORTS + 1, 1.0, 10)

    def test_bad_timeout_and_workers(self):
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(1, 10, 0, 10)
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(1, 10, 99, 10)
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(1, 10, 1.0, scanner.MAX_WORKERS + 1)

    def test_empty_and_unresolvable_target(self):
        with self.assertRaises(ValueError):
            scanner.scan("   ", 1, 10)
        with self.assertRaises(ValueError):
            scanner.scan("this-host-does-not-exist.invalid", 1, 10)


class TestScan(unittest.TestCase):
    def test_full_scan_finds_open_port_and_stores_config(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        try:
            data = scanner.scan("127.0.0.1", port - 2, port + 2, timeout=1.0, workers=5)
        finally:
            server.close()

        states = {r["port"]: r["state"] for r in data["results"]}
        self.assertEqual(states[port], scanner.OPEN)
        self.assertEqual(len(data["results"]), 5)
        self.assertEqual(data["config"]["timeout"], 1.0)
        self.assertEqual(data["resolved_ip"], "127.0.0.1")
        self.assertIn("scanner_version", data["config"])

    def test_summarize_counts(self):
        fake = {"results": [
            {"port": 1, "state": scanner.OPEN},
            {"port": 2, "state": scanner.CLOSED},
            {"port": 3, "state": scanner.CLOSED},
            {"port": 4, "state": scanner.NO_RESPONSE},
        ]}
        counts = scanner.summarize(fake)
        self.assertEqual(counts[scanner.OPEN], 1)
        self.assertEqual(counts[scanner.CLOSED], 2)
        self.assertEqual(counts[scanner.NO_RESPONSE], 1)
        self.assertEqual(counts[scanner.ERROR], 0)


if __name__ == "__main__":
    unittest.main()
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner


def free_port():
    """Ask the OS for an unused port, then release it (so it is CLOSED)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestCheckPort(unittest.TestCase):
    def test_open_port_detected(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        try:
            result = scanner.check_port("127.0.0.1", port, 1.0)
            self.assertEqual(result.state, scanner.OPEN)
        finally:
            server.close()

    def test_closed_port_detected(self):
        # Windows retries refused connections, so a refusal can take ~2s. Use a longer timeout.
        result = scanner.check_port("127.0.0.1", free_port(), 5.0)
        self.assertEqual(result.state, scanner.CLOSED)


class TestValidation(unittest.TestCase):
    def test_bad_port_values(self):
        for start, end in [(0, 10), (1, 70000), (-5, 10)]:
            with self.assertRaises(ValueError):
                scanner.validate_scan_request(start, end, 1.0, 10)

    def test_end_before_start(self):
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(100, 50, 1.0, 10)

    def test_scan_too_large(self):
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(1, scanner.MAX_PORTS + 1, 1.0, 10)

    def test_bad_timeout_and_workers(self):
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(1, 10, 0, 10)
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(1, 10, 99, 10)
        with self.assertRaises(ValueError):
            scanner.validate_scan_request(1, 10, 1.0, scanner.MAX_WORKERS + 1)

    def test_empty_and_unresolvable_target(self):
        with self.assertRaises(ValueError):
            scanner.scan("   ", 1, 10)
        with self.assertRaises(ValueError):
            scanner.scan("this-host-does-not-exist.invalid", 1, 10)


class TestScan(unittest.TestCase):
    def test_full_scan_finds_open_port_and_stores_config(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        try:
            data = scanner.scan("127.0.0.1", port - 2, port + 2, timeout=1.0, workers=5)
        finally:
            server.close()

        states = {r["port"]: r["state"] for r in data["results"]}
        self.assertEqual(states[port], scanner.OPEN)
        self.assertEqual(len(data["results"]), 5)
        self.assertEqual(data["config"]["timeout"], 1.0)
        self.assertEqual(data["resolved_ip"], "127.0.0.1")
        self.assertIn("scanner_version", data["config"])

    def test_summarize_counts(self):
        fake = {"results": [
            {"port": 1, "state": scanner.OPEN},
            {"port": 2, "state": scanner.CLOSED},
            {"port": 3, "state": scanner.CLOSED},
            {"port": 4, "state": scanner.NO_RESPONSE},
        ]}
        counts = scanner.summarize(fake)
        self.assertEqual(counts[scanner.OPEN], 1)
        self.assertEqual(counts[scanner.CLOSED], 2)
        self.assertEqual(counts[scanner.NO_RESPONSE], 1)
        self.assertEqual(counts[scanner.ERROR], 0)


if __name__ == "__main__":
    unittest.main()