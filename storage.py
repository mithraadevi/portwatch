"""PortWatch V2 (piece 1) - save scans to SQLite and load them back.

SQLite ships with Python, so there is nothing to install.

Two tables:
  scans         one row per scan (target, times, settings)
  port_results  one row per port checked in that scan

load_scan() returns the SAME dictionary shape that scanner.scan() produced, so
banner.py and risk.py work on saved scans exactly as they do on fresh ones.
"""

import json
import sqlite3

DEFAULT_DB = "portwatch.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    resolved_ip TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    config_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS port_results (
    scan_id    INTEGER NOT NULL REFERENCES scans(id),
    port       INTEGER NOT NULL,
    state      TEXT NOT NULL,
    detail     TEXT,
    banner     TEXT,
    service    TEXT,
    product    TEXT,
    confidence TEXT,
    evidence   TEXT,
    unexpected INTEGER,
    PRIMARY KEY (scan_id, port)
);
"""


def connect(path=DEFAULT_DB):
    """Open the database (creating it if needed) and make sure the tables exist."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def save_scan(conn, scan_result):
    """Store one scan and all its port results. Returns the new scan id."""
    # '?' placeholders (not string formatting) keep user-supplied text from being
    # run as SQL. The target name comes from the user, so this matters.
    with conn:  # one transaction: either everything is saved, or nothing is
        cur = conn.execute(
            "INSERT INTO scans (target, resolved_ip, started_at, finished_at, config_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_result["target"], scan_result["resolved_ip"],
             scan_result["started_at"], scan_result["finished_at"],
             json.dumps(scan_result["config"])),
        )
        scan_id = cur.lastrowid

        rows = []
        for r in scan_result["results"]:
            info = r.get("service_info")  # only present on OPEN ports that were enriched
            rows.append((
                scan_id, r["port"], r["state"], r.get("detail", ""), r.get("banner"),
                info["service"] if info else None,
                info["product"] if info else None,
                info["confidence"] if info else None,
                info["evidence"] if info else None,
                int(info["unexpected_for_port"]) if info else None,
            ))
        conn.executemany(
            "INSERT INTO port_results (scan_id, port, state, detail, banner, service, "
            "product, confidence, evidence, unexpected) VALUES (?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return scan_id


def list_scans(conn, target=None):
    """Return saved scans, newest first. Optionally only one target."""
    if target:
        cur = conn.execute(
            "SELECT id, target, resolved_ip, started_at, config_json FROM scans "
            "WHERE target = ? ORDER BY id DESC", (target,))
    else:
        cur = conn.execute(
            "SELECT id, target, resolved_ip, started_at, config_json FROM scans "
            "ORDER BY id DESC")
    scans = []
    for row in cur.fetchall():
        config = json.loads(row["config_json"])
        scans.append({
            "id": row["id"], "target": row["target"], "resolved_ip": row["resolved_ip"],
            "started_at": row["started_at"],
            "ports": f"{config['start_port']}-{config['end_port']}",
        })
    return scans


def load_scan(conn, scan_id):
    """Rebuild a scan dictionary (same shape as scanner.scan) from the database."""
    head = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if head is None:
        raise ValueError(f"No saved scan with id {scan_id}.")

    results = []
    for row in conn.execute(
            "SELECT * FROM port_results WHERE scan_id = ? ORDER BY port", (scan_id,)):
        entry = {"port": row["port"], "state": row["state"], "detail": row["detail"] or ""}
        if row["banner"] is not None:
            entry["banner"] = row["banner"]
        if row["service"] is not None:
            entry["service_info"] = {
                "service": row["service"], "product": row["product"],
                "confidence": row["confidence"], "evidence": row["evidence"],
                "unexpected_for_port": bool(row["unexpected"]),
            }
        results.append(entry)

    return {
        "id": head["id"],
        "target": head["target"],
        "resolved_ip": head["resolved_ip"],
        "started_at": head["started_at"],
        "finished_at": head["finished_at"],
        "config": json.loads(head["config_json"]),
        "results": results,
    }


if __name__ == "__main__":
    # Show what is saved: python storage.py
    db = connect()
    scans = list_scans(db)
    if not scans:
        print("No saved scans yet.")
    for s in scans:
        print(f"#{s['id']:<4} {s['target']:<22} ports {s['ports']:<12} {s['started_at']}")
