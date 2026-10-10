"""PortWatch V1 - real TCP connect scanner.

Replaces the random simulation with actual connection attempts.
Returns structured data (not printed text) so a UI, tests, or storage
can all use the same results.
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

SCANNER_VERSION = "1.0"

# Safety limits so nobody (including you, by accident) scans too much.
MAX_PORTS = 10000
MAX_WORKERS = 200
MAX_TIMEOUT = 10.0

# The four states a port can be in.
OPEN = "OPEN"                  # connection succeeded
CLOSED = "CLOSED"              # host actively refused the connection
NO_RESPONSE = "NO_RESPONSE"    # timed out: could be a firewall, packet loss, slow host...
ERROR = "ERROR"                # something else went wrong (see 'detail')


@dataclass
class PortResult:
    port: int
    state: str
    detail: str = ""


def check_port(ip, port, timeout):
    """Try one TCP connection and classify the outcome."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return PortResult(port, OPEN)
    except ConnectionRefusedError:
        return PortResult(port, CLOSED)
    except (TimeoutError, socket.timeout):
        # A timeout does NOT prove "filtered". We only know nobody answered in time.
        return PortResult(port, NO_RESPONSE, f"no reply within {timeout}s")
    except OSError as e:
        return PortResult(port, ERROR, str(e))


def validate_scan_request(start_port, end_port, timeout, workers):
    """Raise ValueError if the request is invalid or too large."""
    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        raise ValueError("Ports must be between 1 and 65535.")
    if end_port < start_port:
        raise ValueError("End port must be >= start port.")
    if end_port - start_port + 1 > MAX_PORTS:
        raise ValueError(f"Scan too large: maximum {MAX_PORTS} ports per scan.")
    if not (0 < timeout <= MAX_TIMEOUT):
        raise ValueError(f"Timeout must be between 0 and {MAX_TIMEOUT} seconds.")
    if not (1 <= workers <= MAX_WORKERS):
        raise ValueError(f"Workers must be between 1 and {MAX_WORKERS}.")


def scan(target, start_port, end_port, timeout=1.0, workers=50):
    """Scan a port range on one target and return a structured result (dict).

    The scan configuration is stored with the results, so later (V2) we can
    check that two scans are actually comparable.
    """
    validate_scan_request(start_port, end_port, timeout, workers)

    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    try:
        ip = socket.gethostbyname(target)  # IPv4 only for now
    except socket.gaierror:
        raise ValueError(f"Could not resolve target: {target}")

    started = datetime.now(timezone.utc)
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: check_port(ip, p, timeout), ports))

    finished = datetime.now(timezone.utc)
    return {
        "target": target,
        "resolved_ip": ip,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "config": {
            "start_port": start_port,
            "end_port": end_port,
            "timeout": timeout,
            "workers": workers,
            "scanner_version": SCANNER_VERSION,
        },
        "results": [asdict(r) for r in results],
    }


def summarize(scan_result):
    """Count how many ports are in each state."""
    counts = {OPEN: 0, CLOSED: 0, NO_RESPONSE: 0, ERROR: 0}
    for r in scan_result["results"]:
        counts[r["state"]] += 1
    return counts


if __name__ == "__main__":
    # Quick manual test: python scanner.py
    host = input("Target (use localhost or scanme.nmap.org): ").strip()
    start = int(input("Start port: "))
    end = int(input("End port: "))
    data = scan(host, start, end)
    print(f"\nScanned {data['target']} ({data['resolved_ip']})")
    for r in data["results"]:
        if r["state"] == OPEN:
            print(f"  {r['port']:<6} OPEN")
    print("\nSummary:", summarize(data))
