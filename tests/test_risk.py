import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import risk


def entry(port, service, confidence="high", evidence="banner", unexpected=False):
    return {
        "port": port, "state": "OPEN", "banner": "",
        "service_info": {"service": service, "product": "", "confidence": confidence,
                         "evidence": evidence, "unexpected_for_port": unexpected},
    }


def scan_with(*entries, extra=()):
    return {"results": list(entries) + list(extra)}


class TestAssessPort(unittest.TestCase):
    def test_critical_service_high_confidence_full_points(self):
        r = risk.assess_port(entry(23, "telnet"))
        self.assertEqual(r["severity"], "Critical")
        self.assertEqual(r["points"], 5)

    def test_low_confidence_counts_half(self):
        r = risk.assess_port(entry(3306, "mysql", confidence="low", evidence="port number only"))
        self.assertEqual(r["points"], 2.5)
        self.assertTrue(r["notes"])

    def test_unknown_service_is_needs_review_not_dangerous(self):
        r = risk.assess_port(entry(54321, "unknown", confidence="unknown", evidence="none"))
        self.assertEqual(r["points"], 0)
        self.assertTrue(r["needs_review"])
        self.assertEqual(r["severity"], "Needs review")

    def test_mismatch_adds_bonus_and_note(self):
        r = risk.assess_port(entry(80, "ssh", unexpected=True))
        self.assertEqual(r["points"], 1 + risk.MISMATCH_BONUS)
        self.assertTrue(any("usual use" in n for n in r["notes"]))

    def test_entry_without_service_info_does_not_crash(self):
        r = risk.assess_port({"port": 9, "state": "OPEN"})
        self.assertTrue(r["needs_review"])


class TestAssess(unittest.TestCase):
    def test_many_unknown_ports_no_longer_inflate_score(self):
        # The old simulator: 13 unknown ports -> "HIGH RISK". Now they score 0.
        data = scan_with(*[entry(p, "unknown", "unknown", "none") for p in range(20, 33)])
        out = risk.assess(data)
        self.assertEqual(out["exposure_score"], 0)
        self.assertEqual(len(out["needs_review"]), 13)
        # ...but a score of 0 must not claim "no exposure" while 13 open ports are unscored.
        self.assertEqual(out["verdict"], "NOT SCORED: 13 OPEN PORT(S) NEED REVIEW")
        self.assertNotIn("NO EXPOSURE", out["verdict"])

    def test_headline_when_nothing_is_open(self):
        out = risk.assess(scan_with())
        self.assertEqual(out["verdict"], "NO EXPOSURE FOUND")

    def test_headline_flags_unscored_ports_next_to_a_real_score(self):
        data = scan_with(entry(23, "telnet"), entry(54321, "unknown", "unknown", "none"),
                         entry(54322, "unknown", "unknown", "none"))
        out = risk.assess(data)
        self.assertEqual(out["exposure_score"], 5)
        self.assertEqual(out["verdict"], "MEDIUM EXPOSURE (2 OPEN PORT(S) NOT SCORED)")

    def test_verdict_for_keeps_working_with_just_a_score(self):
        self.assertEqual(risk.verdict_for(0), "NO EXPOSURE FOUND")
        self.assertEqual(risk.verdict_for(3), "LOW EXPOSURE")
        self.assertEqual(risk.verdict_for(9), "MEDIUM EXPOSURE")
        self.assertEqual(risk.verdict_for(15), "HIGH EXPOSURE")
        self.assertEqual(risk.verdict_for(16), "VERY HIGH EXPOSURE")

    def test_score_adds_up_and_verdict(self):
        data = scan_with(entry(23, "telnet"), entry(21, "ftp"), entry(22, "ssh"))
        out = risk.assess(data)
        self.assertEqual(out["exposure_score"], 9)  # 5 + 3 + 1
        self.assertEqual(out["verdict"], "MEDIUM EXPOSURE")

    def test_no_response_reported_as_unknown_coverage(self):
        data = scan_with(entry(22, "ssh"),
                         extra=[{"port": 5, "state": "NO_RESPONSE"},
                                {"port": 6, "state": "NO_RESPONSE"}])
        out = risk.assess(data)
        self.assertTrue(any("2 port(s) gave no response" in n for n in out["coverage_notes"]))

    def test_disclaimer_present(self):
        out = risk.assess(scan_with())
        self.assertIn("not confirmed vulnerabilities", out["disclaimer"])

    def test_every_rated_service_has_valid_severity(self):
        for name, (sev, why, fix) in risk.SERVICE_RISK.items():
            self.assertIn(sev, risk.SEVERITY_POINTS, name)
            self.assertTrue(why and fix, name)


if __name__ == "__main__":
    unittest.main()
