from xml.etree import ElementTree
from datetime import datetime
from typing import List

from app.models.log_entry import LogEntry


def _extract_source_user_ip(event: ElementTree.Element):
    source = None
    user = None
    ip = None

    try:
        provider = event.find(".//Provider")
        if provider is not None:
            source = provider.attrib.get("Name") or source

        channel_elem = event.find(".//Channel")
        if channel_elem is not None and channel_elem.text:
            source = channel_elem.text

        for data in event.findall(".//Data"):
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
        pass

    return source, user, ip


def parse_xml_logs(file_path: str) -> List[LogEntry]:
    """
    Parse an XML export of Windows Event logs.

    - Never crashes on malformed records.
    - Skips events with missing required fields.
    - Always returns a list (possibly empty).
    """
    logs: List[LogEntry] = []

    try:
        # Read XML file
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Parse XML content
        root = ElementTree.fromstring(content)
    except Exception:
        # Malformed XML → treat as empty
        return logs

    # Iterate through each Event
    for event in root.findall(".//Event"):
        event_id_elem = event.find(".//EventID")
        time_elem = event.find(".//TimeCreated")

        # Safety checks
        if event_id_elem is None or time_elem is None:
            continue

        try:
            timestamp = datetime.fromisoformat(
                time_elem.attrib["SystemTime"].replace("Z", "")
            )
            event_id = int(event_id_elem.text)
        except Exception:
            # Skip malformed records only
            continue

        source, user, ip = _extract_source_user_ip(event)

        logs.append(
            LogEntry(
                timestamp=timestamp,
                event_id=event_id,
                user=user,
                ip=ip,
                message=ElementTree.tostring(event, encoding="unicode"),
            )
        )

    return logs
