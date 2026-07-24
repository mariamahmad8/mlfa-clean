from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class ClassificationResult:
    categories: List[str]
    recipients: List[str]
    needs_personal_reply: bool
    escalation_reason: str
    name_sender: Optional[str]
    amount_money_detected: Optional[float]
    # Per-category justification from GPT — the "why" for each tag it applied.
    # Matches automate-email.py's `reason` field. Displayed in the review hub.
    reason: Dict[str, str] = field(default_factory=dict)
