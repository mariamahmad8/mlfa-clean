from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class Recipient:
    id: Optional[int]
    inbox_id: int
    email: str
    label_recipient: str
    notes: Optional[str]
    created_at: datetime
    active: bool
