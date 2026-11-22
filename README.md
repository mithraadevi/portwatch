# PortWatch

PortWatch is a small network service assessment tool written in Python. It scans a target you are allowed to scan, works out what is running on the open ports, scores the exposure, keeps a history of every scan, and tells you **what changed** between two scans.

It started as a Colab notebook that *simulated* a port scan with random numbers. PortWatch replaces the simulation with real TCP connections and real evidence, and adds the parts a one-off scanner lacks: stored history, drift detection and a tamper-evident log.

> **Use it only on systems you own or have explicit permission to test** (your own computer, your own devices, or a host that is provided for testing). The tool asks for confirmation before every scan and records it. That prompt is an audit trail, not a legal protection.

## What it does

- **Real TCP scanning.** Connects to each port with bounded threads and input limits. Every port ends up as `OPEN`, `CLOSED`, `NO_RESPONSE` or `ERROR`. A timeout is reported as *no response*, never as "filtered", because it can also mean packet loss or a slow host.
- **Service identification with evidence.** Reads the greeting of each open service (SSH, HTTP and others) and records how it knows (`banner` or `port number only`) and how sure it is (`high`, `low`, `unknown`). Banner text comes from the remote machine, so it is shortened and cleaned before it is stored.
- **Exposure scoring.** Severity (how bad if this service is exposed) is kept separate from confidence (how sure we are what it is). Unknown services are marked "needs review" and are not scored as dangerous. The score measures open services, **not confirmed vulnerabilities**.
- **Scan history.** Saves scans, with the settings used, in a local SQLite database.
- **Drift detection.** Compares two saved scans and reports newly opened ports, newly closed ports, service changes and severity changes, but only after checking that the comparison is fair (see below).
- **Tamper-evident history.** Each saved scan is fingerprinted together with the one before it, so edits to old scans can be detected.
- **IPv4 first, IPv6 on request**, with every resolved address recorded.

## Requirements

- Python 3.10 or newer (developed on Python 3.14 on Windows).
- No third-party packages. Everything uses the Python standard library.

## Quick start

Download or clone this repository, open a terminal in its folder, and run:

```
python run_scan.py
```

To try it safely on your own machine, start a local web server in one terminal:

```
python -m http.server 8000
```

then scan it from another terminal with `python run_scan.py`, using target `localhost`, ports `7990` to `8010`, and a timeout of `3`. Port 8000 should show up as an HTTP service.

> **Windows note:** Windows is slow to refuse connections to closed *local* ports (about 2 seconds). With a timeout below 3 seconds those ports can show as `NO_RESPONSE` instead of `CLOSED`.

### Example output

```
============================================================
 PortWatch report: localhost (127.0.0.1, IPv4)
 Ports 7990-8010  |  timeout 3.0s
 Authorization confirmed by ADMIN at 2026-11-22T06:44:21+00:00
============================================================
 Open: 1   Closed: 20   No response: 0   Errors: 0
 Exposure score: 1.0  ->  LOW EXPOSURE
------------------------------------------------------------
 Port 8000   http       severity: Medium        confidence: high (banner)
   Why: Unencrypted web traffic can be read or altered in transit.
   Fix: Redirect to HTTPS. Check what the site serves.

 Exposure score reflects open services, not confirmed vulnerabilities.
============================================================
```

## Commands

| Command | What it does |
|---|---|
| `python run_scan.py` | Scan a target, print the report, optionally save it. Asks for authorization first. |
| `python storage.py` | List saved scans. |
| `python run_drift.py` | Compare two saved scans (asks which). Or `python run_drift.py 3 5` to compare scan 3 with scan 5. |
| `python run_verify.py` | Check that the saved history has not been altered. Add a fingerprint you kept to check it too: `python run_verify.py YOUR_FINGERPRINT`. |

`run_drift.py` and `run_verify.py` only read the database.

## How drift detection stays honest

A difference between two scans is *evidence* of change, not proof. Before comparing, PortWatch checks that:

1. **Both scans are of the same address.** Different addresses (including IPv4 against IPv6) get an identity warning and are not compared unless you override it.
2. **Only ports scanned by both are compared.**
3. **Only definite answers count.** A port that was `NO_RESPONSE` or `ERROR` in either scan is reported as "not compared", never as changed.
4. **Service labels are compared only when banner grabbing was on in both scans.** If the identification rules differ between the scans, a label change is reported as *"label changed, rules differ"* and does not count as a change on the target.
5. **Severity is recalculated from the current rules** for both scans, so editing a rating cannot create false drift.

## How the history stays tamper-evident

Every saved scan gets a SHA-256 fingerprint of its stored data plus the previous scan's fingerprint. Changing an old scan breaks its own fingerprint, rewriting that fingerprint breaks the next link, and removing a scan from the middle breaks the next link too. `run_verify.py` reports the first scan where the chain breaks.

This is tamper-**evident**, not tamper-**proof**:

- Someone with full write access to the database could change a scan and recompute every later fingerprint.
- Removing the *newest* scans leaves a chain that still verifies. To catch that, keep the latest fingerprint somewhere outside the database (a note, an e-mail, a commit message) and check it later with `python run_verify.py YOUR_FINGERPRINT`.
- Scans saved before the feature existed are marked **pre-chain** and cannot be verified.

## Project layout

| File | Responsibility |
|---|---|
| `scanner.py` | TCP connect scan, address resolution, input limits |
| `banner.py` | Banner reading and service identification (with confidence) |
| `risk.py` | Severity ratings, fix advice and the exposure score (ratings are editable in `SERVICE_RISK`) |
| `storage.py` | SQLite storage, schema upgrades with automatic backup |
| `audit.py` | The authorization prompt and its record |
| `drift.py` | Comparison of two scans |
| `chain.py` | Fingerprints and history verification |
| `run_scan.py`, `run_drift.py`, `run_verify.py` | Command-line entry points |
| `tests/` | Automated tests |
| `legacy/` | The original simulator notebook (see below) |
| `docs/` | Project roadmap |

All modules share one scan dictionary format, so a scan loaded from the database can be passed to anything that accepts a fresh scan.

## Tests

```
python -m unittest discover -s tests -v
```

The tests scan only your own machine, using local sockets and mocked name lookups, so they never scan anything else. (One test tries to resolve a hostname that cannot exist.) Tests that need an IPv6 loopback skip themselves on machines without one.

## Limitations

- **TCP connect scans only.** No UDP, no SYN scanning, no operating-system fingerprinting.
- **One address per run.** If a name resolves to several addresses, the others are recorded but not scanned. IPv4 is preferred; ask for IPv6 explicitly.
- **An open port is not a vulnerability.** The exposure score reflects open services. There is no vulnerability database and no version-aware warnings yet.
- **Service identification is only as good as the banner.** Encrypted ports (such as 443) are not probed, and services that send no greeting are identified by port number only, at low confidence.
- **An address is not an identity.** Reports say "same address", never "same machine". Load-balanced names, changing addresses and `127.0.0.1` on different computers can all look identical.
- **The authorization prompt is self-reported.** The operator is the operating-system username. It is enforced by the command-line tools, not by `scanner.scan()` itself.
- **The database is not encrypted.** Scan results and banners are stored in plain form in `portwatch.db`, which is kept out of Git by `.gitignore`.

## The original notebook

The first version was a Colab notebook that simulated scan results randomly. It is kept in `legacy/` for the history of the project. Its results were not real, so please do not use it for anything.

## Roadmap

The design decisions, what changed from the original plan, and what is planned next are in `docs/PortWatch_Roadmap_Revision_2.docx`. Next up is a Streamlit interface (New Scan, Results, History, Drift).

## License

See `LICENSE`.
