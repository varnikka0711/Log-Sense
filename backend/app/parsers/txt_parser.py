from datetime import datetime
from typing import List
import re

from app.models.log_entry import LogEntry


EVENT_ID_RE = re.compile(r"\b(\d{4})\b")


def parse_txt_logs(file_path: str) -> List[LogEntry]:
    """
    Parse plain-text or .log exports of Windows events.

    - Never crashes on malformed lines.
    - Always returns a list (possibly empty).
    """
    logs: List[LogEntry] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                text = line.strip()
                if not text:
                    continue

                # Try to find an Event ID in the line; fall back to 0 if unknown
                match = EVENT_ID_RE.search(text)
                event_id = int(match.group(1)) if match else 0

                logs.append(
                    LogEntry(
                        timestamp=datetime.now(),
                        event_id=event_id,
                        message=text,
                    )
                )
    except Exception:
        # On any file-level issue, just return what we have (possibly empty)
        return logs

    return logs
