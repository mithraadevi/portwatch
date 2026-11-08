"""PortWatch V1.2 - evidence-based exposure scoring.

Key ideas (fixing the simulator's problems):
  * An open port is EXPOSURE, not a proven vulnerability, so we call the number an
    "exposure score" and never claim a service is actually vulnerable.
  * Severity (how bad if this service is exposed) is kept separate from
    confidence (how sure we are what the service is).
  * Low-confidence guesses count for less. Unknown services are NOT scored as
    dangerous - they are flagged "needs review" instead.
  * Ports that gave no response are reported as unknown coverage, not as safe.
"""

# service -> (severity, why it matters, what to do)
# These ratings are a starting point; edit them to match your own judgement.
SERVICE_RISK = {
    "telnet": ("Critical", "Unencrypted remote login; credentials travel in plaintext.",
               "Disable Telnet and use SSH instead."),
    "rdp": ("Critical", "Remote desktop exposed to the network is a common brute-force target.",
            "Disable if unused. Otherwise put it behind a VPN and restrict source IPs."),
    "mysql": ("Critical", "Database reachable from the network.",
              "Bind to localhost or a private network; never expose databases to the internet."),
    "postgresql": ("Critical", "Database reachable from the network.",
                   "Bind to localhost and restrict access in pg_hba.conf."),
    "ftp": ("High", "FTP sends credentials and data unencrypted.",
            "Replace with SFTP or SCP."),
    "pop3": ("High", "POP3 sends mail credentials unencrypted.",
             "Use POP3S or IMAPS."),
    "smb": ("High", "File sharing exposed to the network has a long history of attacks.",
            "Block it at the firewall unless needed, keep systems patched, and disable SMBv1."),
    "ssh": ("Medium", "Encrypted, but exposed logins can be brute-forced.",
            "Use key-based login and restrict allowed IPs."),
    "smtp": ("Medium", "Mail servers can be abused for spam or open relay.",
             "Require authentication, disable open relay, use TLS."),
    "imap": ("Medium", "Mail access exposed; check it requires TLS.",
             "Use IMAPS and strong authentication."),
    "dns": ("Medium", "DNS servers can be abused for amplification attacks.",
            "Restrict zone transfers and rate-limit responses."),
    "http": ("Medium", "Unencrypted web traffic can be read or altered in transit.",
             "Redirect to HTTPS. Check what the site serves."),
    "https": ("Low", "Encrypted web service; risk depends on the application and TLS settings.",
              "Keep certificates and TLS versions up to date."),
}

SEVERITY_POINTS = {"Critical": 5, "High": 3, "Medium": 1, "Low": 0}
CONFIDENCE_WEIGHT = {"high": 1.0, "low": 0.5, "unknown": 0.0}
MISMATCH_BONUS = 1.0  # a service on an unexpected port deserves a closer look


def verdict_for(score):
    if score == 0:
        return "NO EXPOSURE FOUND"
    if score <= 3:
        return "LOW EXPOSURE"
    if score <= 9:
        return "MEDIUM EXPOSURE"
    if score <= 15:
        return "HIGH EXPOSURE"
    return "VERY HIGH EXPOSURE"


def assess_port(entry):
    """Build the risk record for one OPEN port entry (needs 'service_info')."""
    info = entry.get("service_info") or {"service": "unknown", "confidence": "unknown",
                                          "evidence": "not identified",
                                          "unexpected_for_port": False}
    service = info["service"]
    confidence = info["confidence"]
    notes = []

    if service in SERVICE_RISK:
        severity, why, fix = SERVICE_RISK[service]
    else:
        severity, why, fix = (None, "Service could not be identified.",
                              "Find out what is listening here. If it is not needed, stop it.")

    needs_review = severity is None
    points = 0.0
    if severity is not None:
        points = SEVERITY_POINTS[severity] * CONFIDENCE_WEIGHT[confidence]
        if confidence == "low":
            notes.append("Identified from the port number only; confirm what is really running.")
    if info.get("unexpected_for_port"):
        points += MISMATCH_BONUS
        notes.append("Service does not match the usual use of this port.")

    return {
        "port": entry["port"],
        "service": service,
        "severity": severity or "Needs review",
        "confidence": confidence,
        "evidence": info["evidence"],
        "points": points,
        "why": why,
        "recommendation": fix,
        "needs_review": needs_review,
        "notes": notes,
    }


def assess(scan_result):
    """Score a scan that has been through banner.enrich(). Returns a summary dict."""
    findings = [assess_port(r) for r in scan_result["results"] if r["state"] == "OPEN"]
    score = round(sum(f["points"] for f in findings), 1)

    no_response = sum(1 for r in scan_result["results"] if r["state"] == "NO_RESPONSE")
    errors = sum(1 for r in scan_result["results"] if r["state"] == "ERROR")
    coverage_notes = []
    if no_response:
        coverage_notes.append(
            f"{no_response} port(s) gave no response (firewall, packet loss or slow host); "
            "their state is unknown, not safe.")
    if errors:
        coverage_notes.append(f"{errors} port(s) hit errors and were not checked.")

    return {
        "exposure_score": score,
        "verdict": verdict_for(score),
        "findings": findings,
        "needs_review": [f["port"] for f in findings if f["needs_review"]],
        "coverage_notes": coverage_notes,
        "disclaimer": "Exposure score reflects open services, not confirmed vulnerabilities.",
    }
