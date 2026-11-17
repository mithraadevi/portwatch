"""PortWatch V2d - drift detection: what changed between two scans?

Works on scan dictionaries (fresh ones from scanner.scan(), or saved ones from
storage.load_scan()), because they all have the same shape.

Before comparing anything it applies the rules from the roadmap (section 7.3):

  * Same address?   Different resolved addresses (including IPv4 against IPv6)
                    are probably different systems: no comparison, unless the
                    caller explicitly allows it.
  * Overlapping ports?   Only ports scanned by BOTH are compared.
  * Definite answers only?   A port counts only if both scans saw it OPEN or
                    CLOSED. NO_RESPONSE / ERROR on either side means "unknown",
                    never "changed".
  * Service labels?   Compared only if banner grabbing was on in both scans.
                    If the identification rules differ (or are unknown) a label
                    change is reported as coming from the rules, not the target.
  * Severity is recalculated from the CURRENT rules for both scans, so a changed
    rating can never create false drift.

An open port that is not different is not drift, and a difference between two
scans is evidence, not proof, that the target changed.
"""

from datetime import datetime

import risk
import scanner

DEFINITE = ("OPEN", "CLOSED")


# ---------- small helpers ----------

def _family(scan):
    version = scan["config"].get("ip_version")
    if version in (4, 6):
        return version
    return 6 if ":" in scan["resolved_ip"] else 4


def _by_port(scan):
    return {r["port"]: r for r in scan["results"]}


def _label(entry):
    """(service, product) of an open port, or None if it was not identified."""
    info = entry.get("service_info")
    if not info:
        return None
    return (info["service"], info.get("product") or "")


def _summary(entry):
    label = _label(entry)
    return {"port": entry["port"],
            "service": label[0] if label else None,
            "product": label[1] if label else None}


def _show(value):
    return "unknown" if value is None else str(value)


def _when(text):
    try:
        return datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None


def _blocked(result, reason, kind):
    """kind is 'address' (a different system) or 'ports' (nothing to compare)."""
    result["comparable"] = False
    result["blocked_reason"] = reason
    result["blocked_kind"] = kind
    return result


# ---------- the comparison ----------

def compare_scans(old, new, allow_different_address=False):
    """Compare two scans of the same target. 'old' should be the earlier one."""
    result = {
        "comparable": True, "blocked_reason": None, "blocked_kind": None,
        "old_id": old.get("id"), "new_id": new.get("id"),
        "target": new.get("target"), "address": new.get("resolved_ip"),
        "old_started": old.get("started_at"), "new_started": new.get("started_at"),
        "overlap": None, "compared_ports": 0,
        "warnings": [], "notes": [],
        "newly_opened": [], "newly_closed": [],
        "service_changed": [], "severity_changed": [],
        "unknown_ports": [], "has_drift": False,
    }
    warnings, notes = result["warnings"], result["notes"]
    old_cfg, new_cfg = old["config"], new["config"]

    # 1. Order of the scans.
    t_old, t_new = _when(old.get("started_at")), _when(new.get("started_at"))
    if t_old and t_new and t_old > t_new:
        warnings.append("The first scan is newer than the second, so 'opened' and 'closed' "
                        "are relative to the order you gave.")

    # 2. Identity: same address?
    a_old = scanner.normalize_address(old["resolved_ip"])
    a_new = scanner.normalize_address(new["resolved_ip"])
    result["address"] = a_new
    if a_old != a_new:
        f_old, f_new = _family(old), _family(new)
        if f_old != f_new:
            why = (f"The scans used different IP families: {a_old} (IPv{f_old}) and "
                   f"{a_new} (IPv{f_new}). Each family can have different services.")
        elif old.get("target") == new.get("target"):
            why = (f"The name '{new.get('target')}' resolved to different addresses: "
                   f"{a_old} and {a_new}.")
        else:
            why = f"The scans are of different addresses: {a_old} and {a_new}."
        if not allow_different_address:
            return _blocked(result, why + " They may not be the same system, so no "
                                          "drift comparison was made.", "address")
        warnings.append("Comparing different addresses on request. " + why +
                        " Results may not describe the same system.")
    elif old.get("target") != new.get("target"):
        notes.append(f"The scans were started with different names ('{old.get('target')}' "
                     f"and '{new.get('target')}') but both resolve to {a_new}.")

    # 3. Overlapping port ranges.
    lo = max(old_cfg["start_port"], new_cfg["start_port"])
    hi = min(old_cfg["end_port"], new_cfg["end_port"])
    if lo > hi:
        return _blocked(result,
                        f"The port ranges do not overlap ({old_cfg['start_port']}-"
                        f"{old_cfg['end_port']} and {new_cfg['start_port']}-{new_cfg['end_port']}), "
                        "so there is nothing to compare.", "ports")
    result["overlap"] = (lo, hi)
    if (old_cfg["start_port"], old_cfg["end_port"]) != (new_cfg["start_port"], new_cfg["end_port"]):
        notes.append(f"Only ports {lo}-{hi} were compared (scanned: "
                     f"{old_cfg['start_port']}-{old_cfg['end_port']} and "
                     f"{new_cfg['start_port']}-{new_cfg['end_port']}).")

    # 4. Settings that change what a comparison can claim.
    if old_cfg.get("scanner_version") != new_cfg.get("scanner_version"):
        warnings.append(f"Scanner versions differ ({_show(old_cfg.get('scanner_version'))} and "
                        f"{_show(new_cfg.get('scanner_version'))}); scan behavior may have changed.")
    if old_cfg.get("timeout") != new_cfg.get("timeout"):
        notes.append(f"Connection timeouts differ ({_show(old_cfg.get('timeout'))}s and "
                     f"{_show(new_cfg.get('timeout'))}s). Ports without a definite answer "
                     "in both scans are not compared.")
    if old_cfg.get("workers") != new_cfg.get("workers"):
        notes.append(f"Worker counts differ ({_show(old_cfg.get('workers'))} and "
                     f"{_show(new_cfg.get('workers'))}).")
    b_old, b_new = old_cfg.get("banner_timeout"), new_cfg.get("banner_timeout")
    if b_old is not None and b_new is not None and b_old != b_new:
        notes.append(f"Banner timeouts differ ({b_old}s and {b_new}s).")
    for scan, label in ((old, "first"), (new, "second")):
        if scan.get("id") is not None and scan.get("acknowledgment") is None and "acknowledgment" in scan:
            notes.append(f"Scan #{scan['id']} ({label}) is a pre-audit scan: no authorization record.")

    # 5. May service labels be compared at all?
    compare_labels = old_cfg.get("banner_grabbing") is True and new_cfg.get("banner_grabbing") is True
    if not compare_labels:
        notes.append("Service labels were not compared: banner grabbing was off or unknown "
                     "in at least one scan. Port states were still compared.")
    rules_old, rules_new = old_cfg.get("rules_version"), new_cfg.get("rules_version")
    rules_match = rules_old is not None and rules_old == rules_new
    if compare_labels and not rules_match:
        warnings.append(f"Identification rules differ (version {_show(rules_old)} and "
                        f"{_show(rules_new)}). Label changes may come from scanner updates, "
                        "not from the target.")
    reason = "target_changed" if rules_match else "rules_differ"

    # 6. Compare port by port.
    old_ports, new_ports = _by_port(old), _by_port(new)
    for port in range(lo, hi + 1):
        o, n = old_ports.get(port), new_ports.get(port)
        s_old = o["state"] if o else None
        s_new = n["state"] if n else None
        if s_old not in DEFINITE or s_new not in DEFINITE:
            result["unknown_ports"].append({"port": port, "old_state": s_old, "new_state": s_new})
            continue
        result["compared_ports"] += 1

        if s_old == "CLOSED" and s_new == "OPEN":
            result["newly_opened"].append(_summary(n))
        elif s_old == "OPEN" and s_new == "CLOSED":
            result["newly_closed"].append(_summary(o))
        elif s_old == "OPEN" and s_new == "OPEN" and compare_labels:
            lab_o, lab_n = _label(o), _label(n)
            if lab_o is None or lab_n is None:
                continue
            if lab_o != lab_n:
                result["service_changed"].append({
                    "port": port, "old_service": lab_o[0], "old_product": lab_o[1],
                    "new_service": lab_n[0], "new_product": lab_n[1], "reason": reason})
            sev_o = risk.assess_port(o)["severity"]  # always the CURRENT rules
            sev_n = risk.assess_port(n)["severity"]
            if sev_o != sev_n:
                result["severity_changed"].append({
                    "port": port, "old": sev_o, "new": sev_n, "reason": reason})

    result["has_drift"] = bool(
        result["newly_opened"] or result["newly_closed"]
        or any(c["reason"] == "target_changed" for c in result["service_changed"])
        or any(c["reason"] == "target_changed" for c in result["severity_changed"]))
    return result


# ---------- plain-text report ----------

def _port_text(item):
    parts = [f"Port {item['port']}"]
    if item.get("service"):
        parts.append(item["service"])
    if item.get("product"):
        parts.append(f"({item['product']})")
    return " ".join(parts)


def render(result):
    """Turn a comparison result into readable text."""
    line = "=" * 60
    out = [line, f" Drift report: {result['target']} ({result['address']})"]
    out.append(f" Scan #{result['old_id']} -> scan #{result['new_id']}")
    out.append(f" Older: {result['old_started']}")
    out.append(f" Newer: {result['new_started']}")
    out.append(line)

    if not result["comparable"]:
        out.append(" NOT COMPARED")
        out.append(f" {result['blocked_reason']}")
        out.append(line)
        return "\n".join(out)

    lo, hi = result["overlap"]
    out.append(f" Compared {result['compared_ports']} port(s) in range {lo}-{hi}.")
    rules_only = any(c["reason"] == "rules_differ"
                     for c in result["service_changed"] + result["severity_changed"])
    if result["has_drift"]:
        out.append(" RESULT: DRIFT DETECTED")
    elif rules_only:
        out.append(" RESULT: no drift in port states; label changes below come from "
                   "differing rules")
    else:
        out.append(" RESULT: no drift in the compared ports")
    out.append("-" * 60)

    def section(title, items, text):
        if items:
            out.append(f" {title}:")
            out.extend(f"   {text(i)}" for i in items)

    section("Newly opened ports", result["newly_opened"], _port_text)
    section("Newly closed ports", result["newly_closed"], _port_text)

    def label_text(c):
        old = c["old_service"] + (f" ({c['old_product']})" if c["old_product"] else "")
        new = c["new_service"] + (f" ({c['new_product']})" if c["new_product"] else "")
        why = ("" if c["reason"] == "target_changed"
               else "  [label changed, rules differ]")
        return f"Port {c['port']}: {old} -> {new}{why}"
    section("Service changes", result["service_changed"], label_text)

    def sev_text(c):
        why = "" if c["reason"] == "target_changed" else "  [rules differ]"
        return f"Port {c['port']}: {c['old']} -> {c['new']}{why}"
    section("Severity changes", result["severity_changed"], sev_text)

    if result["unknown_ports"]:
        ports = [str(u["port"]) for u in result["unknown_ports"]]
        shown = ", ".join(ports[:15]) + (" ..." if len(ports) > 15 else "")
        out.append(f" Not compared (no definite answer in one scan): {len(ports)} port(s): {shown}")

    for w in result["warnings"]:
        out.append(f" WARNING: {w}")
    for n in result["notes"]:
        out.append(f" Note: {n}")
    out.append(" A difference between two scans is evidence of change, not proof.")
    out.append(line)
    return "\n".join(out)
