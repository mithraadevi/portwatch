"""PortWatch authorization record.

Before every scan the user must confirm they own the system or have permission
to scan it. The confirmation is stored with the scan: who (the operating-system
username), when, and which version of the wording was shown.

Honest limits: the username is whatever the computer reports, not a login, and
the prompt is enforced by run_scan.py (and later the interface), not by
scanner.scan() itself. This is an audit safeguard, not proof of permission and
not a security boundary.
"""

import getpass
from datetime import datetime, timezone

# Raise this number whenever the wording below changes, so a stored record shows
# exactly which text the user agreed to.
ACK_VERSION = "1"
ACK_TEXT = "I confirm that I own {address} or have explicit permission to scan it."


def current_operator():
    """The operating-system username, or 'unknown' if it cannot be read."""
    try:
        name = getpass.getuser()
    except Exception:  # getpass can fail in unusual environments; never block on it
        return "unknown"
    return name or "unknown"


def require_acknowledgment(address, input_fn=input):
    """Ask the user to confirm authorization for this exact address.

    Returns the record to store with the scan, or None if the user did not
    answer 'y' or 'yes'.  input_fn is a parameter so tests can answer for us.
    """
    answer = input_fn(ACK_TEXT.format(address=address) + " (y/n): ").strip().lower()
    if answer not in ("y", "yes"):
        return None
    return {
        "operator": current_operator(),
        "acknowledged_at": datetime.now(timezone.utc).isoformat(),
        "text_version": ACK_VERSION,
    }
