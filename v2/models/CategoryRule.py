from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class CategoryRule:
    id: Optional[int]
    inbox_id: int
    key: str
    label: str
    rule_text: str
    mark_read: bool
    skip: bool
    auto_reply_safeguard: bool
    auto_reply_enabled: bool
    emails_to_forward: List[str]
    folder_path: str
    reply_template: str
    amount_threshold: Optional[float]
    priority: int
    active: bool
    skip_if_internal: bool = False
    delete_immediately: bool = False
    reply_template_personal: str = ""
    reply_template_id: Optional[int] = None
    reply_template_personal_id: Optional[int] = None
