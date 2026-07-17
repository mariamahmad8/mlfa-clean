"""
O365 adapter — the only file in v2/ that talks to Microsoft Outlook.

Everything here either fetches data from Microsoft or performs actions on
Microsoft (move folder, tag, mark read, send, forward). No business logic
lives here — the engine layer makes decisions, this layer executes them.

Every public function takes an InboxConfig so it knows which mailbox
to operate on. That's what makes this adapter multi-inbox capable.
"""

import os
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Set
from O365 import Account
from bs4 import BeautifulSoup

from models.InboxConfig import InboxConfig
from models.NormalizedMessage import NormalizedMessage


# ---------------------------------------------------------------------------
# Account setup
#
# We have ONE Azure app credential shared across all inboxes (same Microsoft
# tenant). The _account object holds the authenticated session. Per-inbox
# mailbox lookup happens via get_mailbox(inbox) below.
# ---------------------------------------------------------------------------

CLIENT_ID = os.getenv("O365_CLIENT_ID")
CLIENT_SECRET = os.getenv("O365_CLIENT_SECRET")
TENANT_ID = os.getenv("O365_TENANT_ID")

_account = Account((CLIENT_ID, CLIENT_SECRET), auth_flow_type="credentials", tenant_id=TENANT_ID)
if not _account.is_authenticated:
    _account.authenticate()

_last_auth_time = datetime.now(timezone.utc)


def reinitialize_account() -> None:
    """
    Rebuild the connection to Microsoft from scratch.

    Used when tokens go stale or the connection becomes invalid. The next
    request after this will use a brand-new authenticated session.
    """
    global _account, _last_auth_time
    _account = Account((CLIENT_ID, CLIENT_SECRET), auth_flow_type="credentials", tenant_id=TENANT_ID)
    _account.authenticate()
    _last_auth_time = datetime.now(timezone.utc)


def ensure_account_fresh(force: bool = False) -> None:
    """
    Proactively refresh the auth token before it can expire.

    Microsoft tokens last ~1 hour. We refresh every 50 minutes by default
    (configurable via AUTH_REFRESH_MIN env var) so we never get caught with
    an expired token mid-request. Pass force=True to refresh immediately
    regardless of age.
    """
    global _last_auth_time
    refresh_minutes = int(os.getenv("AUTH_REFRESH_MIN", "50"))
    age = (datetime.now(timezone.utc) - _last_auth_time).total_seconds() / 60
    if force or age >= refresh_minutes:
        reinitialize_account()


def get_mailbox(inbox: InboxConfig):
    """
    Get the Microsoft mailbox object for a specific inbox.

    The mailbox is what you use to read emails, send replies, move folders,
    etc. Pass info@mlfa.org's inbox config and you get back info@mlfa.org's
    mailbox. This is the key function that makes the system multi-inbox.
    """
    return _account.mailbox(inbox.email_to_watch)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _to_graph_utc(dt: datetime) -> str:
    """
    Format a datetime into the exact string Microsoft Graph expects.

    Microsoft requires dates like '2026-05-21T14:30:00Z'. Any other format
    gets rejected. Used when querying by date range.
    """
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Polling functions — fetch new messages from Microsoft
# ---------------------------------------------------------------------------

def _get_folder(mailbox, folder_name: str):
    """Get a folder by name, handling the special Inbox/JunkEmail cases."""
    if folder_name.lower() == "inbox":
        return mailbox.inbox_folder()
    if folder_name.lower() == "junkemail":
        return mailbox.junk_folder()
    return mailbox.get_folder(folder_name=folder_name)


def fetch_unread_since(
    inbox: InboxConfig,
    folder_name: str,
    since_dt: datetime,
    limit: int = 100,
) -> List[NormalizedMessage]:
    """
    First-time backfill: get unread emails from a folder since a date.

    Used on the very first run of the app when no delta token exists yet.
    Catches up on anything that arrived before polling started. After this
    runs once, ongoing sync switches to fetch_messages_delta.
    """
    mailbox = get_mailbox(inbox)
    folder = _get_folder(mailbox, folder_name)

    query = folder.new_query().on_attribute("isRead").equals(False)
    query = query.chain("and").on_attribute("receivedDateTime").greater_equal(since_dt)

    messages = folder.get_messages(query=query, limit=limit, download_attachments=False)

    # Skip messages already tagged as processed (PAIRActioned). Prevents
    # double-handling if a delta token gets invalidated and we backfill again.
    results: List[NormalizedMessage] = []
    for msg in messages:
        if any((t or "").startswith("PAIRActioned") for t in (msg.categories or [])):
            continue
        results.append(_to_normalized_message(msg))
    return results


def fetch_messages_delta(
    inbox: InboxConfig,
    folder_name: str,
    delta_url: Optional[str],
) -> Tuple[List[NormalizedMessage], Optional[str]]:
    """
    Ongoing sync: get changes since the last delta token.

    Microsoft remembers where you left off using the delta token (a string).
    Each call returns (changed messages, new token to save for next time).
    On first call pass delta_url=None to get a starting token.

    If the delta token is invalid (Microsoft expired it), returns ([], None)
    so the worker can fall back to fetch_unread_since.
    """
    mailbox = get_mailbox(inbox)
    folder = _get_folder(mailbox, folder_name)

    qs = folder.new_query()
    if delta_url:
        qs = qs.delta_token(delta_url)
    qs = qs.select([
        "id", "conversationId", "isRead", "receivedDateTime",
        "from", "sender", "subject", "categories",
    ])

    try:
        msgs = folder.get_messages(query=qs)
    except Exception as e:
        err = str(e)
        if any(tok in err for tok in ("401", "Unauthorized", "invalid_token", "expired", "invalid_client")):
            ensure_account_fresh(force=True)
        if any(tok in err for tok in ("SyncState", "delta", "410")):
            print(f"⚠️  Delta token invalid for {folder_name}, will resync on next run.")
            return [], None
        raise

    results: List[NormalizedMessage] = []
    for msg in msgs:
        if msg.is_read:
            continue
        if any((t or "").startswith("PAIRActioned") for t in (msg.categories or [])):
            continue
        try:
            msg.refresh()
        except Exception:
            pass
        results.append(_to_normalized_message(msg))

    new_token = getattr(msgs, "delta_token", None) or delta_url
    return results, new_token


# ---------------------------------------------------------------------------
# Delta token persistence
# ---------------------------------------------------------------------------

def load_last_delta(inbox: InboxConfig) -> Tuple[Optional[str], Optional[str]]:
    """
    Get the last-saved delta tokens for an inbox (one per folder).

    These are stored on the InboxConfig (loaded from the database) so the
    tokens survive restarts and Railway redeploys.
    """
    return inbox.delta_token_inbox, inbox.delta_token_junk


def save_last_delta(inbox: InboxConfig, inbox_token: Optional[str], junk_token: Optional[str]) -> None:
    """
    Persist the latest delta tokens for an inbox to the database.

    Called by the worker after each successful poll so we know where to
    pick up next time.
    """
    from storage.inbox import update_delta_tokens
    update_delta_tokens(inbox.id, inbox_token, junk_token)


# ---------------------------------------------------------------------------
# Folder management
# ---------------------------------------------------------------------------

def ensure_folder_path(inbox: InboxConfig, path_parts: List[str]):
    """
    Make sure a nested folder path exists under Inbox, creating any missing pieces.

    path_parts is a list like ["Donor_Related", "Grant"] which represents
    Inbox / Donor_Related / Grant. Returns the deepest folder object so the
    caller can move a message into it. If any step fails, returns None.

    Used right before moving a categorized email to its destination folder.
    """
    try:
        mailbox = get_mailbox(inbox)
        current = mailbox.inbox_folder()
        for name in path_parts:
            if not name:
                continue
            found = None
            try:
                found = current.get_folder(folder_name=name)
            except Exception:
                found = None
            if not found:
                try:
                    found = current.create_child_folder(name)
                    print(f"Created folder: {name}")
                except Exception as e:
                    print(f"Could not create folder '{name}': {e}")
                    return None
            current = found
        return current
    except Exception as e:
        print(f"ensure_folder_path error for {path_parts}: {e}")
        return None


# ---------------------------------------------------------------------------
# Per-message actions — these are what the engine asks the adapter to do
# after deciding what should happen with an email.
# ---------------------------------------------------------------------------

def tag_email(msg, categories: List[str]) -> None:
    """
    Apply Outlook tags (categories) to a message so we know we've already
    handled it. Combined with existing tags so we don't lose anything.

    Matches automate-email.py behavior: writes the umbrella 'PAIRActioned'
    tag plus one 'PAIRActioned/<category>' tag per category. There is no
    separate '/replied/<category>' tier — reply-vs-processed granularity
    lives in the audit log, not in Outlook categories.
    """
    existing = set(msg.categories or [])
    new_tags: Set[str] = set()

    for c in categories or []:
        c = (c or "").strip()
        if not c:
            continue
        new_tags.add(f"PAIRActioned/{c}")

    new_tags.add("PAIRActioned")

    merged = existing.union(new_tags)
    if merged != existing:
        msg.categories = sorted(merged)
        msg.save_message()


def remove_email_tags(msg, tags: List[str]) -> None:
    """Remove specific Outlook category tags without disturbing other labels."""
    existing = set(msg.categories or [])
    remove_set = {t for t in (tags or []) if t}
    if not remove_set:
        return

    updated = existing - remove_set
    if updated != existing:
        msg.categories = sorted(updated)
        msg.save_message()


def mark_as_read(msg) -> None:
    """Mark a message as read in Outlook."""
    try:
        msg.mark_as_read()
    except Exception as e:
        print(f"Could not mark as read: {e}")


def move_to_folder(inbox: InboxConfig, msg, path_parts: List[str]) -> bool:
    """
    Move a message into a folder, creating the folder path if needed.

    path_parts is the nested folder path (e.g. ["Donor_Related"]).
    Returns True if the move succeeded.
    """
    dest = ensure_folder_path(inbox, path_parts)
    if not dest:
        return False
    try:
        msg.move(dest)
        return True
    except Exception as e:
        print(f"Could not move message to {'/'.join(path_parts)}: {e}")
        return False


def move_to_trash(inbox: InboxConfig, msg) -> bool:
    """
    Move a message to the Deleted Items folder.

    Used for auto_reply, delete_internal categories, and reviewer rejections.
    """
    try:
        mailbox = get_mailbox(inbox)
        deleted = mailbox.deleted_folder()
        msg.move(deleted)
        return True
    except Exception as e:
        print(f"Could not move message to Deleted Items: {e}")
        return False


def send_email(inbox: InboxConfig, to: str, subject: str, body_html: str) -> None:
    """Send a fresh (non-reply) email from this inbox's mailbox."""
    mailbox = get_mailbox(inbox)
    m = mailbox.new_message()
    m.to.add(to)
    m.subject = subject
    m.body_type = "HTML"
    m.body = body_html
    m.send()


def send_reply(msg, body_html: str) -> None:
    """
    Send a reply to the original sender of a message.

    body_html is the reply text formatted as HTML. Replies only to the
    sender (not to_all) — that's the safe default for auto-replies.
    """
    reply = msg.reply(to_all=False)
    reply.body_type = "HTML"
    reply.body = body_html
    reply.send()


def forward_message(msg, recipients: List[str], comment_html: Optional[str] = None) -> None:
    """
    Forward a message to one or more recipients with an optional comment.

    Used for routing emails to internal staff (donor → give@mlfa.org, etc.).
    The comment is shown above the forwarded content if provided.
    """
    fwd = msg.forward()
    fwd.to.add(recipients)
    if comment_html:
        fwd.body_type = "HTML"
        fwd.body = comment_html + (fwd.body or "")
    fwd.send()


def fetch_message_safely(inbox: InboxConfig, message_id: str, fallback_msg=None):
    """
    Fetch a specific message by its Microsoft ID, or return the fallback.

    Used when the reviewer hub takes an action on a queued email — we need
    to load the original message from Outlook to act on it. If Microsoft
    doesn't find it (deleted, moved), we use the fallback if one was passed.
    """
    try:
        mailbox = get_mailbox(inbox)
        return mailbox.get_message(message_id)
    except Exception:
        return fallback_msg


# ---------------------------------------------------------------------------
# Sender / recipient helpers
#
# These look at addresses on messages to decide whether to skip processing.
# All of them are pure inspection — no API calls back to Microsoft.
# ---------------------------------------------------------------------------

def _extract_sender_address(msg) -> str:
    """Get the single best sender email address from a message."""
    try:
        sender = getattr(msg, "sender", None)
        if sender:
            addr = getattr(sender, "address", None)
            if addr:
                return str(addr).strip()
            if isinstance(sender, str):
                return sender.strip()
        frm = getattr(msg, "from_", None) or getattr(msg, "from", None)
        if frm:
            addr = getattr(frm, "address", None) or getattr(frm, "email", None)
            if addr:
                return str(addr).strip()
            if isinstance(frm, str):
                return frm.strip()
    except Exception:
        pass
    return ""


def _extract_sender_addresses(msg) -> Set[str]:
    """
    Get ALL possible sender addresses (lowercase) from a message.

    Email messages can have both 'sender' and 'from' fields that differ
    (e.g. forwarded emails). We collect everything for safety when
    matching against blocked sender lists.
    """
    addrs: Set[str] = set()
    try:
        sender = getattr(msg, "sender", None)
        if sender:
            addr = getattr(sender, "address", None)
            if addr:
                addrs.add(str(addr).strip().lower())
            elif isinstance(sender, str):
                addrs.add(sender.strip().lower())
        frm = getattr(msg, "from_", None) or getattr(msg, "from", None)
        if frm:
            addr = getattr(frm, "address", None) or getattr(frm, "email", None)
            if addr:
                addrs.add(str(addr).strip().lower())
            elif isinstance(frm, str):
                addrs.add(frm.strip().lower())
    except Exception:
        pass
    return addrs


def _extract_recipient_addresses(msg) -> Set[str]:
    """
    Get all recipient addresses (to + cc + bcc) lowercased.

    Used for the sender/recipient pair blocking — to detect specific
    sender→recipient combinations to skip.
    """
    addrs: Set[str] = set()
    for field in ("to", "cc", "bcc"):
        recips = getattr(msg, field, None) or []
        try:
            iterator = iter(recips)
        except Exception:
            continue
        for r in iterator:
            try:
                addr = getattr(r, "address", None) or getattr(r, "email", None)
                if addr:
                    addrs.add(str(addr).strip().lower())
                elif isinstance(r, str):
                    addrs.add(r.strip().lower())
            except Exception:
                pass
    return addrs


def _is_blocked_sender(inbox: InboxConfig, addr: Optional[str]) -> bool:
    """Check if an address is in the inbox's blocked_senders list."""
    if not addr:
        return False
    try:
        a = addr.strip().lower()
        blocked = [e.strip().lower() for e in (inbox.blocked_senders or [])]
        return a in blocked
    except Exception:
        return False


def _is_blocked_sender_recipient_pair(inbox: InboxConfig, msg) -> bool:
    """
    Check if the message matches a blocked sender→recipient pair.

    Used to skip specific automated forwards (e.g. info@mlfa.org sending
    to mariam.ahmad@pairsys.ai). Configured per inbox via skip_sender_pairs.
    """
    try:
        senders = _extract_sender_addresses(msg)
        if not senders:
            return False
        recipients = _extract_recipient_addresses(msg)
        for pair in (inbox.skip_sender_pairs or []):
            s_addr, r_addr = pair
            if s_addr.strip().lower() in senders and r_addr.strip().lower() in recipients:
                return True
        return False
    except Exception:
        return False


def _should_skip_message(inbox: InboxConfig, msg) -> bool:
    """
    Return True if this message should be silently skipped before processing.

    Two reasons we'd skip: the sender is in blocked_senders, or the
    sender+recipient pair is in skip_sender_pairs. Used by the worker
    to filter out junk before sending to GPT.
    """
    try:
        senders = _extract_sender_addresses(msg)
    except Exception:
        senders = set()
    if senders and any(_is_blocked_sender(inbox, s) for s in senders):
        return True
    return _is_blocked_sender_recipient_pair(inbox, msg)


def _is_internal_sender(inbox: InboxConfig, addr: Optional[str]) -> bool:
    """
    Return True if the sender belongs to one of the inbox's internal domains.

    Configured per inbox via inbox.internal_domains (list of domains like
    "mlfa.org"). Falls back to the watched mailbox's own domain if the
    list is empty.
    """
    if not addr:
        return False
    try:
        a = addr.strip().lower()
        domains = [(d or "").strip().lower().lstrip("@") for d in (inbox.internal_domains or []) if d]
        if not domains:
            domains = [inbox.email_to_watch.split("@")[-1].lower()]
        for d in domains:
            if a.endswith("@" + d):
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Message body extraction
# ---------------------------------------------------------------------------

def get_clean_message_text(msg) -> str:
    """
    Return just the new reply text from a message — no quoted history.

    Email replies often include the entire previous thread quoted below
    the new content. For classification we want only what the latest
    sender actually wrote. Prefers Microsoft's unique_body field if
    available, otherwise strips common quote markers from the full body.
    """
    QUOTE_SEPARATORS = [
        r"^\s*On .* wrote:\s*$",
        r"^\s*From:\s.*$",
        r"^\s*-----Original Message-----\s*$",
        r"^\s*De:\s.*$",
        r"^\s*Sent:\s.*$",
        r"^\s*To:\s.*$",
    ]

    raw = getattr(msg, "unique_body", None) or getattr(msg, "body", None) or ""
    if not raw:
        return ""

    text = raw
    try:
        soup = BeautifulSoup(raw, "html.parser")
        for sel in ["blockquote", "div.gmail_quote", "div[type=cite]", "div.moz-cite-prefix", "div.OutlookMessageHeader"]:
            for node in soup.select(sel):
                node.decompose()
        text = soup.get_text("\n")
    except Exception:
        pass

    lines = [ln.rstrip() for ln in text.splitlines()]
    out = []
    for ln in lines:
        if ln.strip().startswith(">"):
            break
        if any(re.match(pat, ln, flags=re.IGNORECASE) for pat in QUOTE_SEPARATORS):
            break
        out.append(ln)

    return "\n".join(out).strip()[:8000]


# ---------------------------------------------------------------------------
# Private helpers used internally
# ---------------------------------------------------------------------------

def _to_normalized_message(msg) -> NormalizedMessage:
    """
    Convert an O365 library message into our NormalizedMessage dataclass.

    Called by both fetch functions. After this, the rest of the system
    works with our clean dataclass and doesn't have to know about the
    O365 library at all.
    """
    return NormalizedMessage(
        message_id=msg.object_id,
        sender=msg.sender.address if msg.sender else "",
        subject=msg.subject or "",
        body=get_clean_message_text(msg),
        received_at=msg.received,
        conversation_id=msg.conversation_id,
        thread_messages=[],
        existing_tags=list(msg.categories or []),
    )


# ---------------------------------------------------------------------------
# Stubs left for later (phase 1 doesn't need them)
#
# - Thread context: classification works fine without prior messages.
#   When we add this back, the engine can populate msg.thread_messages.
# - Internal reply bridge: the SEND: prefix feature for staff replies.
#   Not core to phase 1 reusability work.
# ---------------------------------------------------------------------------

def get_thread_messages(inbox: InboxConfig, conversation_id: str, current_msg_id: str, limit: int = 20) -> List[str]:
    """
    Fetch earlier messages in the same conversation and return them as
    formatted strings for injection into the classification prompt.

    Skips the current message itself so it isn't duplicated in the prompt.
    """
    if not conversation_id:
        return []
    try:
        mailbox = get_mailbox(inbox)
        # Search across the whole mailbox for this conversation
        query = mailbox.new_query().on_attribute("conversationId").equals(conversation_id)
        messages = mailbox.get_messages(query=query, limit=limit, download_attachments=False)
        formatted = []
        for m in messages:
            if m.object_id == current_msg_id:
                continue
            sender = m.sender.address if m.sender else "unknown"
            received = m.received.strftime("%Y-%m-%d %H:%M") if getattr(m, "received", None) else ""
            body = get_clean_message_text(m)[:2000]  # cap length
            formatted.append(f"From: {sender}\nAt: {received}\nSubject: {m.subject or ''}\n\n{body}")
        return formatted
    except Exception as e:
        print(f"get_thread_messages error: {e}")
        return []


def get_thread_tags(inbox: InboxConfig, conversation_id: str) -> List[str]:
    """
    Return all tags across every message in a conversation.
    Used for thread-wide auto-reply safeguard checks.
    """
    if not conversation_id:
        return []
    try:
        mailbox = get_mailbox(inbox)
        query = mailbox.new_query().on_attribute("conversationId").equals(conversation_id)
        messages = mailbox.get_messages(query=query, limit=50, download_attachments=False)
        tags: set = set()
        for m in messages:
            for t in (m.categories or []):
                if t:
                    tags.add(t)
        return list(tags)
    except Exception as e:
        print(f"get_thread_tags error: {e}")
        return []


REPLY_ID_TAG = "Pair_Reply_Reference_ID"


def forward_with_reply_bridge(msg, recipients: List[str], comment_html: Optional[str] = None) -> None:
    """
    Forward a message with a hidden reply-reference ID embedded so staff
    replies via [EXTERNAL] / [INTERNAL] prefix can be relayed back to the
    original sender. Also prepends the human-visible instructions so staff
    know how to use the bridge.
    """
    fwd = msg.forward()
    fwd.to.add(recipients)
    original_id = msg.internet_message_id or msg.object_id or ""
    hidden_tag = f'<span style="display:none">{REPLY_ID_TAG}{original_id}</span>'
    instructions = (
        "<p><strong>Forwarding process:</strong> use <strong>Reply All</strong> in this thread.</p>"
        "<p>Start your message with <strong>[EXTERNAL]</strong> if the reply should be sent back to the original sender through MLFA.</p>"
        "<p>Start your message with <strong>[INTERNAL]</strong> if the reply should stay internal only.</p>"
        "<p>Without either prefix, the message stays a normal internal email and will not be sent back to the original sender.</p>"
        "<hr>"
    )
    prefix = (comment_html or "") + instructions + hidden_tag
    fwd.body_type = "HTML"
    fwd.body = prefix + (fwd.body or "")
    fwd.send()


def detect_internal_reply(inbox: InboxConfig, msg) -> Optional[str]:
    """
    Check if this message is a staff reply meant to be relayed to the
    original sender. Returns the mode ('internal', 'external') or None.

    Requirements:
      - Internal reply bridge is enabled for this inbox
      - Sender is an internal domain
      - Body contains our hidden REPLY_ID_TAG
      - Not already PAIRActioned
    """
    if not inbox.internal_reply_bridge_enabled:
        return None
    if not _is_internal_sender(inbox, _extract_sender_address(msg)):
        return None
    if any((c or "").startswith("PAIRActioned") for c in (msg.categories or [])):
        return None
    body = msg.body or ""
    if REPLY_ID_TAG not in body:
        return None

    clean = get_clean_message_text(msg).strip()
    external_prefix = (inbox.internal_reply_external_prefix or "[EXTERNAL]").strip()
    internal_prefix = (inbox.internal_reply_internal_prefix or "[INTERNAL]").strip()

    if internal_prefix and clean[:len(internal_prefix)].lower() == internal_prefix.lower():
        return "internal"
    if external_prefix and clean[:len(external_prefix)].lower() == external_prefix.lower():
        return "external"
    return None


def handle_internal_reply(inbox: InboxConfig, msg) -> bool:
    """
    Process a detected internal reply: extract the original message ID,
    strip the [EXTERNAL] prefix, and send the staff's response back to the
    original external sender. Returns True if handled.
    """
    mode = detect_internal_reply(inbox, msg)
    if mode is None:
        return False

    body = msg.body or ""
    match = re.search(fr"{REPLY_ID_TAG}([^<\s]+)", body)
    if not match:
        return False
    original_id = match.group(1).strip()

    clean = get_clean_message_text(msg).strip()

    # [INTERNAL] means keep it internal, just tag+file, don't relay
    if mode == "internal":
        tag_email(msg, ["internal_note"])
        mark_as_read(msg)
        return True

    # [EXTERNAL] means send the reply to the original sender
    external_prefix = (inbox.internal_reply_external_prefix or "[EXTERNAL]").strip()
    outbound = clean[len(external_prefix):].strip() if external_prefix else clean
    if not outbound:
        tag_email(msg, ["internal_note"])
        mark_as_read(msg)
        return True

    safe_html = (
        outbound.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace("\n", "<br>")
    )
    try:
        mailbox = get_mailbox(inbox)
        original_msg = mailbox.get_message(original_id)
        reply = original_msg.reply(to_all=False)
        reply.body_type = "HTML"
        reply.body = f"<div>{safe_html}</div>"
        reply.send()
        tag_email(msg, ["internal_reply_sent"])
        mark_as_read(msg)
        return True
    except Exception as e:
        print(f"handle_internal_reply send error: {e}")
        return False
