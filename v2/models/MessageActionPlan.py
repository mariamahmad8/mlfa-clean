from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class MessageActionPlan:
    move_to_folder: Optional[str]
    forward_to: List[str]
    send_reply: bool
    reply_text: Optional[str]
    mark_read: bool
    tag: Optional[str]
    requires_human_review: bool
    delete: bool
