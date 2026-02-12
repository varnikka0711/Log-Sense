from typing import List, Optional

from fastapi import APIRouter, Query

from app.store.memory import security_events
from app.models.security_event import SecurityEvent

router = APIRouter()


@router.get("/events", response_model=List[SecurityEvent])
def get_events(
    severity: Optional[str] = Query(
        None, description="Low, Medium, High (case-insensitive)"
    ),
    event_type: Optional[str] = Query(
        None, alias="event_type", description="Login, System, Policy, Process, Network"
    ),
    ip: Optional[str] = Query(
        None, description="Filter by source IP (substring, case-insensitive)"
    ),
    user: Optional[str] = Query(
        None, description="Filter by user (substring, case-insensitive)"
    ),
):
    """
    Return security events from the in-memory store, with optional filters.

    - All filters are optional.
    - Filters are case-insensitive.
    - IP and user use 'contains' matching for convenience.
    """

    def matches(evt: SecurityEvent) -> bool:
        if severity:
            if (evt.severity or "").lower() != severity.lower():
                return False

        if event_type:
            if (evt.event_type or "").lower() != event_type.lower():
                return False

        if ip:
            if ip.lower() not in (evt.source_ip or "").lower():
                return False

        if user:
            if user.lower() not in (evt.user or "").lower():
                return False

        return True

    return [e for e in security_events if matches(e)]
