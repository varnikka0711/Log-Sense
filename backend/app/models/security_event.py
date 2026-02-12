from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional


class SecurityEvent(BaseModel):
    id: str
    timestamp: datetime
    event_type: str            # Login / System / Policy / Process / Network
    severity: str              # Low / Medium / High
    title: str
    description: str
    why_it_matters: str
    remediation: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    related_logs: List[str]
