from dataclasses import dataclass, field
from typing import List, Tuple, Optional

@dataclass
class InboxConfig:
    id: Optional[int]
    email_to_watch: str
    blocked_senders: List[str]
    automation_mode: bool
    skip_sender_pairs: List[Tuple[str, str]]
    display_name: str
    system_preamble: str
    global_guidelines: str
    internal_domains: List[str] = field(default_factory=list)
    backfill_days: int = 2
    use_thread_context: bool = True
    internal_reply_bridge_enabled: bool = False
    internal_reply_external_prefix: str = "[EXTERNAL]"
    internal_reply_internal_prefix: str = "[INTERNAL]"
    delta_token_inbox: Optional[str] = None
    delta_token_junk: Optional[str] = None
