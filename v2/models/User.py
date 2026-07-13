from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class User:
    id: Optional[int]
    email: str
    display_name: Optional[str]
    microsoft_oid: Optional[str]
    role_user: str
    last_login_at: Optional[datetime]
    created_at: datetime
    active: bool
    assigned_inbox_ids: List[int] = field(default_factory=list)
