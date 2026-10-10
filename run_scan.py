"""PortWatch command-line runner: scan -> identify services -> score -> report.

Only scan systems you own or have explicit permission to test
(localhost, your own devices, or scanme.nmap.org).
"""

import banner
import risk
import scanner


def print_report(data, assessment):
    counts = scanner.summarize(data)
    print()
    print("=" * 60)
    print(f" PortWatch report: {data['target']} ({data['resolved_ip']})")
    cfg = data["config"]
    print(f" Ports {cfg['start_port']}-{cfg['end_port']}  |  timeout {cfg['timeout']}s")
    print("=" * 60)
    print(f" Open: {counts['OPEN']}   Closed: {counts['CLOSED']}   "
          f"No response: {counts['NO_RESPONSE']}   Errors: {counts['ERROR']}")
    print(f" Exposure score: {assessment['exposure_score']}  ->  {assessment['verdict']}")
    print("-" * 60)

    if not assessment["findings"]:
        print(" No open ports found in this range.")
    for f in assessment["findings"]:
        print(f" Port {f['port']:<6} {f['service']:<10} severity: {f['severity']:<13} "
              f"confidence: {f['confidence']} ({f['evidence']})")
        print(f"   Why: {f['why']}")
        print(f"   Fix: {f['recommendation']}")
        for note in f["notes"]:
            print(f"   Note: {note}")
        print()

    if assessment["needs_review"]:
        print(f" Needs review (could not identify): ports {assessment['needs_review']}")
    for note in assessment["coverage_notes"]:
        print(f" Coverage: {note}")
    print(f" {assessment['disclaimer']}")
    print("=" * 60)


def ask_int(prompt, default=None):
    raw = input(prompt).strip()
    if not raw and default is not None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit("Please enter a whole number.")


if __name__ == "__main__":
    host = input("Target (localhost or scanme.nmap.org): ").strip()
    start = ask_int("Start port: ")
    end = ask_int("End port: ")
    timeout = float(input("Timeout seconds (use 3+ for localhost on Windows) [1]: ") or 1)
    try:
        result = scanner.scan(host, start, end, timeout=timeout)
    except ValueError as err:
        raise SystemExit(f"Error: {err}")
    banner.enrich(result, timeout=max(timeout, 2.0))
    print_report(result, risk.assess(result))
