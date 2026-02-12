from uuid import uuid4
from typing import List

from fastapi import APIRouter, UploadFile, HTTPException, status

from app.parsers.router import parse_logs
from app.store.memory import parsed_logs, security_events
from app.models.log_entry import LogEntry
from app.models.security_event import SecurityEvent
from app.classification import classify_log
from app.detectors.brute_force import detect_bruteforce

router = APIRouter()


@router.post("/logs/upload")
async def upload_logs(file: UploadFile):
    """
    Ingest a log file, parse events, classify them into SecurityEvents,
    and store them in the in-memory event store.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file uploaded.",
        )

    # 1. Parse uploaded file with automatic type detection
    try:
        logs: List[LogEntry] = parse_logs(file)
    except ValueError as exc:
        # Unsupported file type → reject gracefully
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception:
        # Generic parsing failure – still a controlled error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to parse log file.",
        )

    # Ensure parsers always give us a list
    if logs is None:
        logs = []

    # 2. Store raw logs in memory
    parsed_logs.extend(logs)

    new_events: List[SecurityEvent] = []

    # 3. Convert EVERY log into a SecurityEvent via rule-based classification
    for log in logs:
        cls = classify_log(log)

        event = SecurityEvent(
            id=str(uuid4()),
            timestamp=log.timestamp,
            event_type=cls.event_type,
            severity=cls.severity,
            title=cls.title,
            description=log.message,
            why_it_matters=cls.why_it_matters,
            remediation=cls.remediation,
            source_ip=log.ip,
            user=log.user,
            related_logs=[log.message],
        )

        security_events.append(event)
        new_events.append(event)

    # 4. Run aggregate detection (e.g., brute force) on all parsed logs so far
    brute_force_event = detect_bruteforce(parsed_logs)
    if brute_force_event:
        security_events.append(brute_force_event)
        new_events.append(brute_force_event)

    # 5. Confirm success – frontend only needs status, it fetches events separately
    return {
        "message": "Logs processed successfully",
        "events_created": len(new_events),
    }
