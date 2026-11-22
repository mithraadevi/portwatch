"""PortWatch V2e - a tamper-evident scan history.

Every saved scan gets a fingerprint (SHA-256) computed from:
  * the scan's stored data (target, address, times, settings, authorization
    record and every port result), and
  * the fingerprint of the scan saved before it.

Editing an old scan changes its fingerprint. Rewriting that fingerprint too
breaks the link in the next scan. Removing a scan from the middle breaks the
next link as well. verify() walks the history and reports where it breaks.

Honest limits - this is tamper-EVIDENT, not tamper-PROOF:
  * Someone with full write access could change a scan and recompute every
    later fingerprint, and the chain would look valid.
  * Removing the newest scan(s) leaves a chain that still verifies.
  Both are caught only if you keep a fingerprint somewhere OUTSIDE the database
  (a note, an e-mail, a Git commit message) and check it with find_anchor().

Scans saved before this feature existed have no fingerprint. They are 'pre-chain':
nothing can be said about whether they were altered. The chain starts with the
first scan saved after the feature was added.
"""

import hashlib
import json

GENESIS = "0" * 64  # the 'previous fingerprint' of the very first chained scan

_SCAN_COLUMNS = ("id, target, resolved_ip, started_at, finished_at, config_json, "
                 "operator, ack_at, ack_version")
_PORT_COLUMNS = "port, state, detail, banner, service, product, confidence, evidence, unexpected"


def canonical_record(conn, scan_id):
    """One fixed, repeatable text form of a scan, built from the data AS STORED.

    Reading the rows back from the database (instead of using the dictionary that
    was passed in) means '' versus NULL or 1 versus True can never make an
    untouched scan look altered.
    """
    scan = conn.execute(f"SELECT {_SCAN_COLUMNS} FROM scans WHERE id = ?", (scan_id,)).fetchone()
    ports = conn.execute(
        f"SELECT {_PORT_COLUMNS} FROM port_results WHERE scan_id = ? ORDER BY port",
        (scan_id,)).fetchall()
    record = {"scan": list(tuple(scan)), "ports": [list(tuple(p)) for p in ports]}
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(previous_hash, canonical):
    """SHA-256 over the previous fingerprint plus this scan's canonical text."""
    return hashlib.sha256((previous_hash + "\n" + canonical).encode("utf-8")).hexdigest()


def latest_hash(conn):
    """Fingerprint of the newest chained scan, or GENESIS if none exists yet."""
    row = conn.execute("SELECT record_hash FROM scans WHERE record_hash IS NOT NULL "
                       "ORDER BY id DESC LIMIT 1").fetchone()
    return row["record_hash"] if row else GENESIS


def seal(conn, scan_id):
    """Compute and store the fingerprint of a just-saved scan.

    Must run inside the same transaction that saved the scan.
    """
    previous = latest_hash(conn)
    record = fingerprint(previous, canonical_record(conn, scan_id))
    conn.execute("UPDATE scans SET prev_hash = ?, record_hash = ? WHERE id = ?",
                 (previous, record, scan_id))
    return record


def verify(conn):
    """Check the whole history. Returns a dictionary describing the result.

    Each scan ends up as 'verified', 'pre-chain' or 'broken'. A scan is broken if
    its own data no longer matches its fingerprint ('data') or if it does not
    link to the fingerprint of the scan before it ('link').
    """
    rows = conn.execute("SELECT id, prev_hash, record_hash FROM scans ORDER BY id").fetchall()
    scans = {}
    expected_previous = GENESIS
    seen_chained = False
    latest = None

    for row in rows:
        sid = row["id"]
        if row["record_hash"] is None:
            if seen_chained:
                scans[sid] = {"status": "broken", "problems": [
                    "has no fingerprint although earlier scans do (the fingerprint was removed)"]}
            else:
                scans[sid] = {"status": "pre-chain", "problems": []}
            continue

        seen_chained = True
        problems = []
        if row["prev_hash"] != expected_previous:
            problems.append("does not link to the previous scan's fingerprint (an earlier scan "
                            "was changed, replaced or removed)")
        recomputed = fingerprint(row["prev_hash"] or "", canonical_record(conn, sid))
        if recomputed != row["record_hash"]:
            problems.append("its stored data no longer matches its fingerprint "
                            "(this scan was changed)")
        scans[sid] = {"status": "broken" if problems else "verified", "problems": problems}
        expected_previous = row["record_hash"]  # follow what is STORED, so later scans are judged fairly
        latest = row["record_hash"]

    broken = [sid for sid, info in scans.items() if info["status"] == "broken"]
    return {
        "ok": not broken,
        "total": len(scans),
        "verified": sum(1 for i in scans.values() if i["status"] == "verified"),
        "pre_chain": sum(1 for i in scans.values() if i["status"] == "pre-chain"),
        "broken": len(broken),
        "first_break": ({"scan_id": broken[0], "problems": scans[broken[0]]["problems"]}
                        if broken else None),
        "scans": scans,
        "latest_hash": latest,
    }


def find_anchor(conn, kept_hash):
    """Which scan has this fingerprint? Returns the scan id, or None.

    Use it with a fingerprint you kept outside the database: if the scan that
    produced it is gone or was altered, it will not be found.
    """
    row = conn.execute("SELECT id FROM scans WHERE record_hash = ?",
                       ((kept_hash or "").strip().lower(),)).fetchone()
    return row["id"] if row else None


def render(result):
    """Readable text for a verify() result."""
    line = "=" * 60
    out = [line, " PortWatch history verification", line,
           f" Scans: {result['total']}   verified: {result['verified']}   "
           f"pre-chain: {result['pre_chain']}   broken: {result['broken']}"]
    if result["total"] == 0:
        out.append(" No saved scans yet.")
    elif result["ok"] and result["verified"] == 0:
        out.append(" RESULT: nothing to verify yet. No scan has a fingerprint; the chain")
        out.append(" starts with the next scan you save.")
    elif result["ok"]:
        out.append(" RESULT: no changes detected in the chained scans.")
    else:
        first = result["first_break"]
        out.append(f" RESULT: HISTORY BROKEN, first problem at scan #{first['scan_id']}.")
        for sid, info in result["scans"].items():
            if info["status"] == "broken":
                for p in info["problems"]:
                    out.append(f"   Scan #{sid}: {p}")
    if result["pre_chain"]:
        out.append(f" {result['pre_chain']} scan(s) are pre-chain: saved before fingerprints "
                   "existed, so they cannot be verified.")
    if result["latest_hash"]:
        out.append(f" Latest fingerprint: {result['latest_hash']}")
        out.append(" Keep it somewhere outside this database. It is the only way to notice if the")
        out.append(" newest scans are removed. Check it later with: python run_verify.py <fingerprint>")
    out.append(" Tamper-evident, not tamper-proof: full write access can rewrite every fingerprint.")
    out.append(line)
    return "\n".join(out)
