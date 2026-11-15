"""PortWatch command-line runner: scan -> identify services -> score -> report.

Only scan systems you own or have explicit permission to test
(localhost, your own devices, or scanme.nmap.org).
"""

import audit
import banner
import risk
import scanner
import storage


def print_report(data, assessment):
    counts = scanner.summarize(data)
    print()
    print("=" * 60)
    cfg = data["config"]
    family = f"IPv{cfg['ip_version']}" if "ip_version" in cfg else "IPv4"
    print(f" PortWatch report: {data['target']} ({data['resolved_ip']}, {family})")
    others = [a for a in cfg.get("resolved_addresses", []) if a != data["resolved_ip"]]
    if others:
        print(f" This name also resolves to: {', '.join(others)} (not scanned)")
    print(f" Ports {cfg['start_port']}-{cfg['end_port']}  |  timeout {cfg['timeout']}s")
    ack = data.get("acknowledgment")
    if ack:
        print(f" Authorization confirmed by {ack['operator']} at {ack['acknowledged_at']}")
    else:
        print(" No authorization record (pre-audit scan)")
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


def ask_ip_version():
    while True:
        choice = input("IP version: auto, 4 or 6 [auto]: ").strip().lower() or "auto"
        if choice in ("auto", "4", "6"):
            return choice
        print("Please type auto, 4 or 6.")


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
    ip_version = ask_ip_version()

    try:
        scanner.validate_scan_request(start, end, timeout, scanner.DEFAULT_WORKERS)
        resolved = scanner.resolve_target(host, ip_version)
    except ValueError as err:
        raise SystemExit(f"Error: {err}")

    print(f"\n{host} resolves to {resolved['address']} (IPv{resolved['version']}).")
    ack = audit.require_acknowledgment(resolved["address"])
    if ack is None:
        raise SystemExit("Scan cancelled: authorization was not confirmed.")

    try:
        # Scan exactly the address that was acknowledged.
        result = scanner.scan(host, start, end, timeout=timeout,
                              ip_version=ip_version, resolved=resolved)
    except ValueError as err:
        raise SystemExit(f"Error: {err}")
    result["acknowledgment"] = ack
    banner.enrich(result, timeout=max(timeout, 2.0))
    print_report(result, risk.assess(result))

    if input("Save this scan to history? (y/n): ").strip().lower() == "y":
        db = storage.connect(on_migrate=print)
        scan_id = storage.save_scan(db, result)
        print(f"Saved as scan #{scan_id} in {storage.DEFAULT_DB}")
