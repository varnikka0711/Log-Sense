import Evtx.Evtx as evtx
from xml.etree import ElementTree
from datetime import datetime

from app.models.log_entry import LogEntry


def _extract_source_user_ip(root: ElementTree.Element):
    """
    Best-effort extraction of source, user, and IP from a Windows Event XML node.
    Never raises.
    """
    source = None
    user = None
    ip = None

    try:
        provider = root.find(".//Provider")
        if provider is not None:
            source = provider.attrib.get("Name") or source

        channel_elem = root.find(".//Channel")
        if channel_elem is not None and channel_elem.text:
            source = channel_elem.text

        for data in root.findall(".//Data"):
            name = (data.attrib.get("Name") or "").lower()
            value = (data.text or "").strip()
            if not value:
                continue

            if name in (
                "targetusername",
                "targetuser",
                "subjectusername",
                "accountname",
                "user",
            ):
                user = value
            elif name in (
                "ipaddress",
                "clientaddress",
                "sourcenetworkaddress",
                "workstationname",
            ):
                ip = value
    except Exception:
        # Best-effort only
        pass

    return source, user, ip


def parse_evtx(file_path: str):
    """
    Parse a .evtx Windows Event log file.

    - Never crashes on malformed records.
    - Skips records missing required fields.
    - Always returns a list (possibly empty).
    """
    logs = []

    try:
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                    root = ElementTree.fromstring(xml)

                    event_id_elem = root.find(".//EventID")
                    time_elem = root.find(".//TimeCreated")

                    # If required fields are missing → skip safely
                    if event_id_elem is None or time_elem is None:
                        continue

                    system_time = time_elem.attrib.get("SystemTime")
                    if not system_time:
                        continue

                    timestamp = datetime.fromisoformat(system_time.replace("Z", ""))
                    source, user, ip = _extract_source_user_ip(root)

                    logs.append(
                        LogEntry(
                            timestamp=timestamp,
                            event_id=int(event_id_elem.text),
                            user=user,
                            ip=ip,
                            message=xml,
                        )
                    )
                except Exception:
                    # Never crash on malformed records
                    continue
    except Exception:
        # Entire file unreadable → just return what we have (likely empty)
        return logs

    return logs
