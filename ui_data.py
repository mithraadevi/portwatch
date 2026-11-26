"""PortWatch web interface: the data layer.

Everything the interface needs to know is worked out here, in plain Python with no
Streamlit import, so it can be tested like the rest of PortWatch. app.py only
displays what these functions return.

The interface is READ-ONLY for now. open_readonly() opens the database in SQLite's
read-only mode, so no page can change a scan, add one, or upgrade the database by
accident. (Upgrading is done once by running `python storage.py`.)

Scan data comes from other machines (banners) and from the user (target names), so
it is UNTRUSTED text. The functions here return it unchanged and the interface shows
it only through widgets that never interpret it (tables, st.text, st.code, st.json),
never through Markdown or HTML.
"""

import os
import sqlite3
from datetime import datetime
from pathlib import Path

import chain
import risk
import scanner
import storage

ENV_DB = "PORTWATCH_DB"  # lets you point the interface at another database file


LOCAL_ADDRESSES = ("localhost", "127.0.0.1", "::1")


def is_network_exposed(server_address):
    """True if Streamlit is not restricted to this computer.

    An unset address (None) means Streamlit's default, which listens on every network
    interface, so anyone who can reach the machine could read the scan history.
    """
    return server_address not in LOCAL_ADDRESSES


def db_path():
    """The database the interface reads: $PORTWATCH_DB, or portwatch.db in the current folder."""
    return os.environ.get(ENV_DB) or storage.DEFAULT_DB


def open_readonly(path):
    """Open the database read-only. Returns (connection, None) or (None, message).

    Never creates a file (a missing database is reported, not created) and never
    upgrades an old database (it asks you to run storage.py instead).
    """
    p = Path(path)
    if not p.is_file():
        return None, (f"No database found at {p.resolve()}. Run `python run_scan.py` and save a "
                      "scan first, or start the interface from the PortWatch folder.")
    try:
        conn = sqlite3.connect(p.resolve().as_uri() + "?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        has_scans = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'"
                                 ).fetchone() is not None
    except sqlite3.DatabaseError as err:
        return None, f"{p.name} could not be read as a PortWatch database ({err})."

    if not has_scans:
        conn.close()
        return None, f"{p.name} is not a PortWatch database (it has no scans table)."
    if version > storage.SCHEMA_VERSION:
        conn.close()
        return None, (f"{p.name} was made by a newer version of PortWatch (schema {version}). "
                      "Update PortWatch.")
    if version < storage.SCHEMA_VERSION:
        conn.close()
        return None, (f"{p.name} uses an older layout (schema {version}) and needs a one-time "
                      "upgrade. Run `python storage.py` once (it makes a backup first), then "
                      "reload this page.")
    return conn, None


def format_time(iso_text):
    """'2026-11-22T06:44:21.7+00:00' -> '2026-11-22 06:44 UTC'. Unreadable text is returned as is."""
    try:
        when = datetime.fromisoformat(iso_text)
    except (TypeError, ValueError):
        return str(iso_text)
    return when.strftime("%Y-%m-%d %H:%M UTC")


def history_status(verification, scan_id):
    """'verified', 'pre-chain' or 'broken' for one scan."""
    return verification.get(scan_id, {"status": "pre-chain"})["status"]


def scan_rows(db, verification=None):
    """Rows for the History table, newest first."""
    verification = verification if verification is not None else chain.verify(db)["scans"]
    labels = {"verified": "verified", "pre-chain": "pre-chain", "broken": "BROKEN"}
    rows = []
    for s in storage.list_scans(db):
        rows.append({
            "ID": s["id"],
            "Target": s["target"],
            "Address": s["resolved_ip"],
            "Ports": s["ports"],
            "Started": format_time(s["started_at"]),
            "Authorization": "recorded" if s["audited"] else "pre-audit",
            "History": labels[history_status(verification, s["id"])],
        })
    return rows


def scan_label(s):
    """One-line description of a scan (an item of storage.list_scans) for a drop-down."""
    return (f"#{s['id']}  {s['target']}  {s['resolved_ip']}  ports {s['ports']}  "
            f"{format_time(s['started_at'])}")


def verification_message(result):
    """(level, text) for the banner above the History table. level: success / info / error."""
    if result["total"] == 0:
        return "info", "No saved scans yet."
    if not result["ok"]:
        first = result["first_break"]["scan_id"]
        return "error", (f"History verification FAILED: the first problem is at scan #{first}. "
                         "Scans may have been altered or removed. Run `python run_verify.py` for "
                         "details.")
    if result["verified"] == 0:
        return "info", (f"{result['pre_chain']} scan(s), all saved before fingerprints existed, so "
                        "none can be verified. The chain starts with the next scan you save.")
    text = f"History verification passed: {result['verified']} scan(s) verified, no changes detected."
    if result["pre_chain"]:
        text += f" {result['pre_chain']} older scan(s) are pre-chain and cannot be verified."
    return "success", text


def describe_scan(scan):
    """Header facts about one scan, as (label, value) pairs ready to display as text."""
    cfg = scan["config"]
    family = f"IPv{cfg['ip_version']}" if "ip_version" in cfg else "IPv4"
    ack = scan.get("acknowledgment")
    if ack:
        authorization = f"confirmed by {ack['operator']} at {format_time(ack['acknowledged_at'])}"
    else:
        authorization = "no record (pre-audit scan)"
    others = [a for a in cfg.get("resolved_addresses", []) if a != scan["resolved_ip"]]
    pairs = [
        ("Target", scan["target"]),
        ("Address scanned", f"{scan['resolved_ip']} ({family})"),
    ]
    if others:
        pairs.append(("Also resolves to (not scanned)", ", ".join(others)))
    pairs += [
        ("Ports", f"{cfg['start_port']}-{cfg['end_port']}"),
        ("Started", format_time(scan["started_at"])),
        ("Timeout", f"{cfg['timeout']} s"),
        ("Authorization", authorization),
        ("Scanner version", str(cfg.get("scanner_version", "unknown"))),
        ("Identification rules", str(cfg.get("rules_version", "unknown"))),
    ]
    return pairs


def state_counts(scan):
    return scanner.summarize(scan)


def finding_rows(assessment):
    """Rows for the findings table (one per open port)."""
    return [{
        "Port": f["port"],
        "Service": f["service"],
        "Severity": f["severity"],
        "Confidence": f["confidence"],
        "Evidence": f["evidence"],
        "Points": f["points"],
        "Why it matters": f["why"],
        "What to do": f["recommendation"],
        "Notes": " ".join(f["notes"]),
    } for f in assessment["findings"]]


def banner_rows(scan):
    """(port, banner text) for open ports that sent a banner. The text is untrusted."""
    return [(r["port"], r["banner"]) for r in scan["results"]
            if r["state"] == "OPEN" and r.get("banner")]


def unchecked_rows(scan):
    """Ports without a definite answer (NO_RESPONSE or ERROR), as table rows."""
    return [{"Port": r["port"], "State": r["state"], "Detail": r.get("detail", "")}
            for r in scan["results"] if r["state"] in ("NO_RESPONSE", "ERROR")]


def scan_view(scan):
    """Everything the Results page shows for one loaded scan."""
    assessment = risk.assess(scan)
    return {
        "facts": describe_scan(scan),
        "counts": state_counts(scan),
        "assessment": assessment,
        "findings": finding_rows(assessment),
        "banners": banner_rows(scan),
        "unchecked": unchecked_rows(scan),
    }
