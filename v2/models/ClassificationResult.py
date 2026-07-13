from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class ClassificationResult:
    categories: List[str]
    recipients: List[str]
    needs_personal_reply: bool
    escalation_reason: str
    name_sender: Optional[str]
    amount_money_detected: Optional[float]
