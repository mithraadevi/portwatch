import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import banner
import scanner


class FakeServer:
    """Tiny local server: sends `greeting` on connect (or waits for a request)."""

    def __init__(self, greeting=b"", reply_to_request=b""):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.greeting = greeting
        self.reply = reply_to_request
        self.running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                if self.greeting:
                    conn.sendall(self.greeting)
                elif self.reply:
                    conn.settimeout(2)
                    conn.recv(1024)
                    conn.sendall(self.reply)
                else:
                    threading.Event().wait(0.5)  # silent service
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self):
        self.running = False
        self.sock.close()


class TestSanitize(unittest.TestCase):
    def test_strips_control_characters_and_limits_length(self):
        dirty = b"\x1b[31mHELLO\x00\x07 world\r\n" + b"A" * 500
        clean = banner.sanitize(dirty)
        self.assertNotIn("\x1b", clean)
        self.assertNotIn("\x00", clean)
        self.assertLessEqual(len(clean), banner.MAX_BANNER_LEN)
        self.assertIn("HELLO", clean)


class TestIdentify(unittest.TestCase):
    def test_ssh_banner(self):
        info = banner.identify_service(22, "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(info["service"], "ssh")
        self.assertEqual(info["product"], "OpenSSH_9.6")
        self.assertEqual(info["confidence"], "high")
        self.assertFalse(info["unexpected_for_port"])

    def test_http_banner_with_server_header(self):
        info = banner.identify_service(8000, "HTTP/1.0 200 OK | Server: SimpleHTTP/0.6 Python/3.12")
        self.assertEqual(info["service"], "http")
        self.assertIn("SimpleHTTP", info["product"])

    def test_banner_contradicts_port_number(self):
        info = banner.identify_service(2222, "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(info["service"], "ssh")
        info22 = banner.identify_service(80, "SSH-2.0-OpenSSH_9.6")
        self.assertTrue(info22["unexpected_for_port"])  # SSH on the HTTP port

    def test_port_guess_only_is_low_confidence(self):
        info = banner.identify_service(3306, "")
        self.assertEqual(info["service"], "mysql")
        self.assertEqual(info["confidence"], "low")

    def test_unknown_port_no_banner(self):
        info = banner.identify_service(54321, "")
        self.assertEqual(info["service"], "unknown")
        self.assertEqual(info["confidence"], "unknown")


class TestGrab(unittest.TestCase):
    def test_grabs_ssh_banner_from_live_socket(self):
        srv = FakeServer(greeting=b"SSH-2.0-OpenSSH_9.6\r\n")
        try:
            text = banner.grab_banner("127.0.0.1", srv.port, timeout=2.0)
        finally:
            srv.stop()
        self.assertTrue(text.startswith("SSH-2.0-OpenSSH_9.6"))

    def test_silent_service_returns_empty_banner(self):
        srv = FakeServer()
        try:
            text = banner.grab_banner("127.0.0.1", srv.port, timeout=0.3)
        finally:
            srv.stop()
        self.assertEqual(text, "")

    def test_enrich_adds_service_info_to_open_ports(self):
        srv = FakeServer(greeting=b"SSH-2.0-OpenSSH_9.6\r\n")
        try:
            data = scanner.scan("127.0.0.1", srv.port, srv.port, timeout=3.0, workers=1)
            banner.enrich(data, timeout=2.0)
        finally:
            srv.stop()
        entry = data["results"][0]
        self.assertEqual(entry["state"], "OPEN")
        self.assertEqual(entry["service_info"]["service"], "ssh")
        self.assertTrue(data["config"]["banner_grabbing"])


if __name__ == "__main__":
    unittest.main()
