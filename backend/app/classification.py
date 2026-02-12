from dataclasses import dataclass

from app.models.log_entry import LogEntry


@dataclass
class ClassificationResult:
    """
    Simple rule-based classification result for a Windows log entry.
    """

    event_type: str       # Login / System / Policy / Process / Network
    severity: str         # Low / Medium / High
    title: str
    why_it_matters: str
    remediation: str


def classify_log(log: LogEntry) -> ClassificationResult:
    """
    Classify a single LogEntry into a SecurityEvent shape using
    simple, transparent rules. No AI/LLMs involved.
    """
    eid = log.event_id
    msg = (log.message or "").lower()

    # Defaults for unknown / routine events
    event_type = "System"
    severity = "Low"
    title = f"Windows Event ID {eid}"
    why = "Routine Windows event included for context and timeline analysis."
    remediation = "No immediate action required unless this activity looks unusual."

    # Login / authentication events (successful)
    if eid in (4624, 4634, 4647, 4672, 4776, 4768, 4769, 4771, 4778, 4779):
        event_type = "Login"
        severity = "Low"

        if eid == 4624:
            title = "Successful logon"
            why = "Tracks when an account signs in; useful to spot unusual or off-hours access."
            remediation = "Verify legitimacy for privileged or sensitive accounts."
        elif eid in (4634, 4647):
            title = "User logoff"
            why = "Shows when a session ends; helps reconstruct user activity."
            remediation = "No action unless timing, source host, or account looks suspicious."
        elif eid == 4672:
            severity = "Medium"
            title = "Privileged logon"
            why = "An account logged on with elevated or administrative privileges."
            remediation = "Confirm that this elevated access was expected and documented."
        else:
            title = "Authentication event"
            why = "General authentication activity for the account."
            remediation = "Review if coming from unexpected hosts or accounts."

    # Failed logon attempts and similar wording
    if eid == 4625 or "failed logon" in msg or "logon failure" in msg:
        event_type = "Login"
        severity = "Medium"
        title = "Failed logon attempt"
        why = "Repeated failed logons may indicate password guessing or brute-force attacks."
        remediation = "Investigate the source IP and account; enforce lockout and MFA where possible."

    # Policy / audit changes
    if eid in (
        4719,
        4732,
        4733,
        4735,
        4737,
        4739,
        4902,
        4907,
        4713,
        4715,
        4716,
        4717,
        4718,
        1102,
    ):
        event_type = "Policy"
        severity = "Medium"
        title = "Security policy change"
        why = "Security or audit configuration was modified, which may weaken monitoring or controls."
        remediation = "Validate that this change was approved and aligns with security policy."

        if eid == 1102:
            severity = "High"
            title = "Security audit log cleared"
            why = "Clearing the security log may indicate an attacker trying to hide their tracks."
            remediation = "Investigate immediately and review surrounding events for suspicious activity."

    # Process / execution
    if eid in (4688, 4689, 4690):
        event_type = "Process"
        severity = "Medium"
        title = "Process execution event"
        why = "New process activity can indicate tools, malware, or lateral movement."
        remediation = "Inspect the executable, command line, parent process, and user context."

    # Network / firewall
    if eid in (5152, 5153, 5155, 5156, 5157, 5158):
        event_type = "Network"
        severity = "Low"
        title = "Firewall network event"
        why = "Windows Firewall observed network traffic; useful for connection forensics."
        remediation = "Investigate blocked or unexpected connections from untrusted hosts."

    # Message-based fallback if event_type still System
    if event_type == "System":
        if any(k in msg for k in ("logon", "login", "authentication")):
            event_type = "Login"
        elif any(k in msg for k in ("policy", "audit", "privilege")):
            event_type = "Policy"
        elif any(k in msg for k in ("process", ".exe", "command line", "powershell")):
            event_type = "Process"
        elif any(k in msg for k in ("network", "connection", "firewall")):
            event_type = "Network"

    # Unknown logs are System/Low by design (requirements)
    return ClassificationResult(
        event_type=event_type,
        severity=severity,
        title=title,
        why_it_matters=why,
        remediation=remediation,
    )

