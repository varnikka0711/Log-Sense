from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class LogEntry(BaseModel):
    timestamp: datetime
    event_id: int
    user: Optional[str] = None
    ip: Optional[str] = None
    message: str
