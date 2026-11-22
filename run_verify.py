"""PortWatch history check: has the saved scan history been altered?

Usage:
    python run_verify.py                  (check the whole history)
    python run_verify.py <fingerprint>    (also check a fingerprint you kept earlier)

This only READS the database. It never scans anything and never changes data.

The second form is how you notice that the NEWEST scans were removed, which the
chain alone cannot show: if the scan that produced your kept fingerprint is no
longer in the database, it will not be found.
"""

import sys

import chain
import storage

if __name__ == "__main__":
    db = storage.connect(on_migrate=print)
    result = chain.verify(db)
    print(chain.render(result))

    if len(sys.argv) > 1:
        kept = sys.argv[1].strip()
        found = chain.find_anchor(db, kept)
        print()
        if found is None:
            print(f"The fingerprint you kept ({kept[:16]}...) was NOT found in this database.")
            print("The scan that produced it was removed or altered, or the fingerprint was")
            print("copied incorrectly. Check the copy first.")
        else:
            print(f"The fingerprint you kept belongs to scan #{found}, and it is still there.")
            if not result["ok"]:
                print("But the history is broken (see above), so check which scans were affected.")
    raise SystemExit(0 if result["ok"] else 1)
