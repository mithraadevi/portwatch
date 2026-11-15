import os
import socket
import sys
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit
import scanner


class TestAcknowledgment(unittest.TestCase):
    def test_yes_answers_create_a_record(self):
        for answer in ("y", "Y", "yes", "  YES  "):
            ack = audit.require_acknowledgment("127.0.0.1", input_fn=lambda prompt, a=answer: a)
            self.assertIsNotNone(ack, answer)
            self.assertEqual(ack["text_version"], audit.ACK_VERSION)
            self.assertTrue(ack["operator"])

    def test_anything_else_is_a_refusal(self):
        for answer in ("n", "", "no", "maybe", "yep", "ok"):
            ack = audit.require_acknowledgment("127.0.0.1", input_fn=lambda prompt, a=answer: a)
            self.assertIsNone(ack, answer)

    def test_the_prompt_names_the_exact_address(self):
        seen = []
        audit.require_acknowledgment("203.0.113.7", input_fn=lambda prompt: seen.append(prompt) or "n")
        self.assertIn("203.0.113.7", seen[0])

    def test_timestamp_is_utc_and_readable(self):
        ack = audit.require_acknowledgment("127.0.0.1", input_fn=lambda prompt: "y")
        when = datetime.fromisoformat(ack["acknowledged_at"])
        self.assertIsNotNone(when.tzinfo)
        self.assertEqual(when.utcoffset().total_seconds(), 0)

    def test_operator_falls_back_when_username_unavailable(self):
        with mock.patch("getpass.getuser", side_effect=OSError):
            self.assertEqual(audit.current_operator(), "unknown")
        with mock.patch("getpass.getuser", return_value=""):
            self.assertEqual(audit.current_operator(), "unknown")


class TestScanUsesTheAcknowledgedAddress(unittest.TestCase):
    def test_pre_resolved_address_is_not_looked_up_again(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        resolved = {"address": "127.0.0.1", "version": 4, "all": ["127.0.0.1"]}
        try:
            # If scan() tried to resolve the name again, this would raise.
            with mock.patch("scanner.resolve_target", side_effect=AssertionError("looked up again")):
                data = scanner.scan("some-name.test", port, port, timeout=2.0, workers=1,
                                    resolved=resolved)
        finally:
            server.close()
        self.assertEqual(data["resolved_ip"], "127.0.0.1")
        self.assertEqual(data["target"], "some-name.test")
        self.assertEqual(data["results"][0]["state"], scanner.OPEN)

    def test_empty_target_is_rejected_by_resolve(self):
        for bad in ("", "   ", None):
            with self.assertRaises(ValueError):
                scanner.resolve_target(bad)


if __name__ == "__main__":
    unittest.main()
