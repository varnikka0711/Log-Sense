from datetime import datetime
import uuid

from app.models.security_event import SecurityEvent

FAILED_LOGIN_THRESHOLD = 5


def detect_bruteforce(logs):
    """
    Very simple brute-force detector based on failed logon events (4625).
    Returns a high-severity aggregate SecurityEvent when the threshold is hit.
    """
    failed = [log for log in logs if getattr(log, "event_id", None) == 4625]

    if len(failed) >= FAILED_LOGIN_THRESHOLD:
        first = failed[0]
        return SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            event_type="Login",
            severity="High",
            title="Possible brute-force login attempt",
            description=f"{len(failed)} failed login attempts detected",
            why_it_matters="Multiple failed logins may indicate an account compromise attempt.",
            remediation="Block the source IP, investigate the account, and enforce account lockout policies.",
            source_ip=getattr(first, "ip", None),
            user=getattr(first, "user", None),
            related_logs=[log.message for log in failed],
        )

    return None
