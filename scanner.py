"""PortWatch V1 - real TCP connect scanner.

Replaces the random simulation with actual connection attempts.
Returns structured data (not printed text) so a UI, tests, or storage
can all use the same results.
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

SCANNER_VERSION = "1.1"

# Safety limits so nobody (including you, by accident) scans too much.
MAX_PORTS = 10000
MAX_WORKERS = 200
DEFAULT_WORKERS = 50
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


def normalize_address(addr):
    """Write an IP address in one standard form ('0:0:0:0:0:0:0:1' becomes '::1')."""
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return addr


def resolve_target(target, ip_version="auto"):
    """Resolve a hostname or IP literal and choose ONE address to scan.

    Returns {"address": chosen, "version": 4 or 6, "all": every address found}.
    The list is de-duplicated and sorted (IPv4 first), and the choice follows
    fixed rules, so the same name always gives the same choice:
      "auto" -> the lowest IPv4 address, or IPv6 only if the name has no IPv4
      "4"    -> the lowest IPv4 address (error if none)
      "6"    -> the lowest IPv6 address (error if none)
    """
    if ip_version not in ("auto", "4", "6"):
        raise ValueError('IP version must be "auto", "4" or "6".')
    target = (target or "").strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    try:
        infos = socket.getaddrinfo(target, None, family=socket.AF_UNSPEC,
                                   type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target: {target}")

    found = set()
    for info in infos:
        try:
            found.add(ipaddress.ip_address(normalize_address(info[4][0])))
        except ValueError:
            continue  # ignore anything that is not a plain IP address
    v4 = sorted(a for a in found if a.version == 4)
    v6 = sorted(a for a in found if a.version == 6)
    if not v4 and not v6:
        raise ValueError(f"Could not resolve target: {target}")

    if ip_version == "4":
        if not v4:
            raise ValueError(f"No IPv4 address found for {target}.")
        chosen = v4[0]
    elif ip_version == "6":
        if not v6:
            raise ValueError(f"No IPv6 address found for {target}.")
        chosen = v6[0]
    else:
        chosen = v4[0] if v4 else v6[0]

    return {"address": str(chosen), "version": chosen.version,
            "all": [str(a) for a in v4 + v6]}


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


def scan(target, start_port, end_port, timeout=1.0, workers=DEFAULT_WORKERS,
         ip_version="auto", resolved=None):
    """Scan a port range on one target and return a structured result (dict).

    The scan configuration is stored with the results, so later (V2) we can
    check that two scans are actually comparable.
    """
    validate_scan_request(start_port, end_port, timeout, workers)

    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    # 'resolved' can be passed in when the caller already resolved the name (for
    # example to ask permission for that exact address), so it is not looked up twice.
    resolved = resolved or resolve_target(target, ip_version)
    ip = resolved["address"]

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
            "ip_version_requested": ip_version,
            "ip_version": resolved["version"],
            "resolved_addresses": resolved["all"],
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
    print("Run run_scan.py instead: it asks for authorization before scanning.")
