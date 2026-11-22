"""PortWatch storage - save scans to SQLite and load them back.

SQLite ships with Python, so there is nothing to install.

Two tables:
  scans         one row per scan (target, times, settings, authorization record,
                and the fingerprints that chain the history together)
  port_results  one row per port checked in that scan

load_scan() returns the SAME dictionary shape that scanner.scan() produced, so
banner.py and risk.py work on saved scans exactly as they do on fresh ones.

Schema versions (stored with SQLite's 'user_version' setting):
  1  scans and port_results (the first release of storage)
  2  adds the authorization record to scans: operator, ack_at, ack_version
  3  adds the hash chain to scans: prev_hash, record_hash (see chain.py)
connect() upgrades older databases automatically and keeps their data. Before
upgrading a database that already holds scans it makes a backup copy next to it.
"""

import json
import os
import sqlite3
from datetime import datetime

import chain

DEFAULT_DB = "portwatch.db"
SCHEMA_VERSION = 3

SCHEMA_V1 = """
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

# Columns added by each schema step (name, type).
# Version 2: scans saved before it have NULL here, meaning "pre-audit": no
#            authorization was recorded, and none is invented.
# Version 3: scans saved before it have NULL here, meaning "pre-chain": they
#            cannot be verified, and no fingerprint is invented for them.
NEW_COLUMNS_V2 = [("operator", "TEXT"), ("ack_at", "TEXT"), ("ack_version", "TEXT")]
NEW_COLUMNS_V3 = [("prev_hash", "TEXT"), ("record_hash", "TEXT")]
MIGRATION_STEPS = [(2, NEW_COLUMNS_V2), (3, NEW_COLUMNS_V3)]


def _table_exists(conn, name):
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def _columns(conn, table):
    # 'table' is always one of our own constant names, never user input.
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _backup(conn, path):
    """Copy a database file to a time-stamped backup next to it. Returns the new path."""
    root, ext = os.path.splitext(path)
    dest = f"{root}.pre-migration-{datetime.now().strftime('%Y%m%dT%H%M%S')}{ext}"
    copy = sqlite3.connect(dest)
    try:
        conn.backup(copy)
    finally:
        copy.close()
    return dest


def _upgrade(conn, path, on_migrate=None):
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        conn.close()
        raise ValueError(
            f"{path} was made by a newer version of PortWatch (schema {version}). "
            "Update PortWatch instead of opening it with this version.")

    # A database that already has scans but is older than the current schema is
    # protected with a backup before anything is changed.
    has_data = _table_exists(conn, "scans") and version < SCHEMA_VERSION
    if has_data and path != ":memory:":
        dest = _backup(conn, path)
        if on_migrate:
            on_migrate(f"Upgrading the scan database. A backup was saved as {dest}")

    conn.executescript(SCHEMA_V1)  # creates missing tables; leaves existing ones alone

    if version < SCHEMA_VERSION:
        existing = _columns(conn, "scans")
        for step_version, columns in MIGRATION_STEPS:
            if version < step_version:
                for name, coltype in columns:
                    if name not in existing:  # safe to run again after an interrupted upgrade
                        conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {coltype}")
                        existing.add(name)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()


def connect(path=DEFAULT_DB, on_migrate=None):
    """Open the database (creating or upgrading it if needed)."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    _upgrade(conn, path, on_migrate)
    return conn


def save_scan(conn, scan_result):
    """Store one scan and all its port results. Returns the new scan id.

    If the scan carries an 'acknowledgment' (see audit.py) it is stored with it.
    The scan is then sealed into the fingerprint chain (see chain.py).
    """
    ack = scan_result.get("acknowledgment") or {}
    # Concurrent saves cannot fork the chain, because of the ORDER of things below:
    # the first INSERT takes SQLite's write lock, and only then is the previous
    # fingerprint read and the new one written, all in this one transaction.
    # Do not move the sealing into a separate transaction.
    # '?' placeholders (not string formatting) keep user-supplied text from being
    # run as SQL. The target name comes from the user, so this matters.
    with conn:  # one transaction: either everything is saved, or nothing is
        cur = conn.execute(
            "INSERT INTO scans (target, resolved_ip, started_at, finished_at, config_json, "
            "operator, ack_at, ack_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_result["target"], scan_result["resolved_ip"],
             scan_result["started_at"], scan_result["finished_at"],
             json.dumps(scan_result["config"]),
             ack.get("operator"), ack.get("acknowledged_at"), ack.get("text_version")),
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
        chain.seal(conn, scan_id)
    return scan_id


def list_scans(conn, target=None):
    """Return saved scans, newest first. Optionally only one target."""
    sql = ("SELECT id, target, resolved_ip, started_at, config_json, ack_at, record_hash "
           "FROM scans " + ("WHERE target = ? " if target else "") + "ORDER BY id DESC")
    cur = conn.execute(sql, (target,) if target else ())
    scans = []
    for row in cur.fetchall():
        config = json.loads(row["config_json"])
        scans.append({
            "id": row["id"], "target": row["target"], "resolved_ip": row["resolved_ip"],
            "started_at": row["started_at"],
            "ports": f"{config['start_port']}-{config['end_port']}",
            "audited": row["ack_at"] is not None,
            "chained": row["record_hash"] is not None,
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

    acknowledgment = None
    if head["ack_at"] is not None:
        acknowledgment = {"operator": head["operator"], "acknowledged_at": head["ack_at"],
                          "text_version": head["ack_version"]}

    return {
        "id": head["id"],
        "target": head["target"],
        "resolved_ip": head["resolved_ip"],
        "started_at": head["started_at"],
        "finished_at": head["finished_at"],
        "config": json.loads(head["config_json"]),
        "acknowledgment": acknowledgment,  # None means a pre-audit scan
        "fingerprint": head["record_hash"],  # None means a pre-chain scan
        "results": results,
    }


if __name__ == "__main__":
    # Show what is saved: python storage.py
    db = connect(on_migrate=print)
    scans = list_scans(db)
    if not scans:
        print("No saved scans yet.")
    for s in scans:
        notes = []
        if not s["audited"]:
            notes.append("pre-audit: no authorization record")
        if not s["chained"]:
            notes.append("pre-chain: not verifiable")
        note = f"  ({'; '.join(notes)})" if notes else ""
        print(f"#{s['id']:<4} {s['target']:<22} ports {s['ports']:<12} {s['started_at']}{note}")
