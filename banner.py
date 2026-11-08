"""PortWatch V1.1 - banner grabbing and service identification.

For every OPEN port we try to learn what is really running there, and we record
HOW we know (evidence) and how sure we are (confidence):

  high    - the service itself told us (its banner matched a known pattern)
  low     - we only guessed from the port number (e.g. 22 -> ssh)
  unknown - no banner and no guess

Banners come from the remote machine, so they are UNTRUSTED input. We cut them
to a safe length and strip control characters before storing or showing them.
"""

import re
import socket
from concurrent.futures import ThreadPoolExecutor

MAX_BANNER_LEN = 200

# Weak guesses based only on the port number (confidence: low).
PORT_GUESSES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 8000: "http", 8080: "http",
}

# Ports where a plain-text probe would be pointless (the service expects TLS).
TLS_PORTS = {443, 465, 993, 995, 8443}

# Ports where servers wait for US to speak first, so we send a harmless HEAD request.
HTTP_PORTS = {80, 8000, 8080, 8008, 8888}

HTTP_PROBE = b"HEAD / HTTP/1.0\r\nUser-Agent: PortWatch\r\n\r\n"


def sanitize(raw_bytes):
    """Turn untrusted bytes into a short, printable string."""
    text = raw_bytes.decode("utf-8", errors="replace")
    text = re.sub(r"[^\x20-\x7e\n]", "", text)  # keep printable ASCII + newline only
    text = " | ".join(line.strip() for line in text.splitlines() if line.strip())
    return text[:MAX_BANNER_LEN]


def grab_banner(ip, port, timeout=2.0):
    """Connect to an open port and return the sanitized banner ('' if none)."""
    if port in TLS_PORTS:
        return ""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = b""
            try:
                data = s.recv(1024)  # many services (SSH, FTP, SMTP) speak first
            except (TimeoutError, socket.timeout):
                pass
            if not data and port in HTTP_PORTS:
                try:
                    s.sendall(HTTP_PROBE)
                    data = s.recv(2048)
                except (TimeoutError, socket.timeout, OSError):
                    pass
            return sanitize(data)
    except OSError:
        return ""


def identify_service(port, banner):
    """Decide what service this is. Returns a dict with evidence and confidence."""
    guess = PORT_GUESSES.get(port)
    found = None  # (service, product)

    ssh = re.match(r"SSH-\d\.\d+-(\S+)", banner)
    http = re.match(r"HTTP/\d\.\d+\s+\d{3}", banner)
    if ssh:
        found = ("ssh", ssh.group(1))
    elif http:
        server = re.search(r"Server:\s*([^|]+)", banner, re.IGNORECASE)
        found = ("http", server.group(1).strip() if server else "")
    elif re.match(r"220[ -].*\b(ESMTP|SMTP)\b", banner, re.IGNORECASE):
        found = ("smtp", banner[4:80])
    elif re.match(r"220[ -]", banner) and re.search(r"ftp", banner, re.IGNORECASE):
        found = ("ftp", banner[4:80])
    elif banner.startswith("+OK"):
        found = ("pop3", banner[4:80])
    elif banner.startswith("* OK"):
        found = ("imap", banner[5:80])

    if found:
        service, product = found
        return {
            "service": service,
            "product": product,
            "confidence": "high",
            "evidence": "banner",
            "unexpected_for_port": bool(guess and guess != service and guess != "https"),
        }
    if guess:
        return {"service": guess, "product": "", "confidence": "low",
                "evidence": "port number only", "unexpected_for_port": False}
    return {"service": "unknown", "product": "", "confidence": "unknown",
            "evidence": "no banner, no port guess", "unexpected_for_port": False}


def enrich(scan_result, timeout=2.0, workers=20):
    """Add banner + service info to every OPEN port in a scan result (in place)."""
    ip = scan_result["resolved_ip"]
    open_entries = [r for r in scan_result["results"] if r["state"] == "OPEN"]

    def work(entry):
        banner = grab_banner(ip, entry["port"], timeout)
        entry["banner"] = banner
        entry["service_info"] = identify_service(entry["port"], banner)

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(open_entries) or 1))) as pool:
        list(pool.map(work, open_entries))

    scan_result["config"]["banner_grabbing"] = True
    return scan_result


if __name__ == "__main__":
    import scanner

    host = input("Target (localhost or scanme.nmap.org): ").strip()
    start = int(input("Start port: "))
    end = int(input("End port: "))
    t = float(input("Timeout seconds (use 3+ for localhost on Windows) [1]: ") or 1)
    data = enrich(scanner.scan(host, start, end, timeout=t), timeout=max(t, 2.0))
    for r in data["results"]:
        if r["state"] == "OPEN":
            info = r["service_info"]
            flag = "  <-- UNEXPECTED for this port" if info["unexpected_for_port"] else ""
            print(f"{r['port']:<6} {info['service']:<10} {info['product']:<30} "
                  f"[{info['confidence']}, {info['evidence']}]{flag}")
            if r["banner"]:
                print(f"       banner: {r['banner']}")
    print("\nSummary:", scanner.summarize(data))
