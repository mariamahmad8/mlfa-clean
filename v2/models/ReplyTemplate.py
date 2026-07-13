from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class ReplyTemplate:
    id: Optional[int]
    inbox_id: int
    name_template: str
    body_html: str
    created_at: datetime
    active: bool
