from dataclasses import dataclass, field
from typing import List
from datetime import datetime

@dataclass
class NormalizedMessage:
    message_id: str
    sender: str
    subject: str
    body: str
    received_at: datetime
    conversation_id: str
    thread_messages: List[str]
    existing_tags: List[str]
    thread_tags: List[str] = field(default_factory=list)
    needs_personal_reply: bool = False
