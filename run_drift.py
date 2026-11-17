"""PortWatch drift report: compare two saved scans.

Usage:
    python run_drift.py            (shows your saved scans, then asks which two)
    python run_drift.py 1 6        (compare scan #1, the older, with scan #6, the newer)

This only READS the database. It never scans anything and never changes data.
"""

import sys

import drift
import storage


def show_scans(db):
    scans = storage.list_scans(db)
    if not scans:
        print("No saved scans yet. Run run_scan.py and answer y when asked to save.")
        return False
    for s in scans:
        note = "" if s["audited"] else "  (pre-audit)"
        print(f"#{s['id']:<4} {s['target']:<20} {s['resolved_ip']:<16} ports {s['ports']:<11} "
              f"{s['started_at'][:19]}{note}")
    return True


def ask_id(prompt):
    raw = input(prompt).strip().lstrip("#")
    if not raw.isdigit():
        raise SystemExit("Please enter a scan number, for example 3.")
    return int(raw)


if __name__ == "__main__":
    db = storage.connect(on_migrate=print)
    if not show_scans(db):
        raise SystemExit(0)

    if len(sys.argv) == 3 and all(a.lstrip("#").isdigit() for a in sys.argv[1:]):
        old_id, new_id = (int(a.lstrip("#")) for a in sys.argv[1:])
    else:
        print()
        old_id = ask_id("Older scan number: ")
        new_id = ask_id("Newer scan number: ")

    try:
        old, new = storage.load_scan(db, old_id), storage.load_scan(db, new_id)
    except ValueError as err:
        raise SystemExit(f"Error: {err}")

    result = drift.compare_scans(old, new)
    if result["blocked_kind"] == "address":
        print("\n" + drift.render(result))
        if input("\nCompare anyway? Results may not describe the same system. (y/n): "
                 ).strip().lower() == "y":
            result = drift.compare_scans(old, new, allow_different_address=True)
        else:
            raise SystemExit(0)
    print("\n" + drift.render(result))
