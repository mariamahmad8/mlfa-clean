"""
Worker — the polling loop that runs forever.

Every tick:
  1. Load all active inboxes from the database
  2. For each inbox, poll both Inbox and JunkEmail folders
  3. For each new message, run it through the pipeline

This is the only place that ties everything together. Storage, adapters,
engine, and pipeline are all called from here.
"""

import os
import time
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from models.InboxConfig import InboxConfig
from models.CategoryRule import CategoryRule
from models.NormalizedMessage import NormalizedMessage

from storage import inbox as inbox_storage
from storage import rules as rules_storage
from storage import queue as queue_storage
from adapters import o365
from engine import pipeline


# How long to sleep between polls (seconds)
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "10"))

# Days back to scan on a first-time backfill (per inbox)
BACKFILL_DAYS = int(os.getenv("BACKFILL_DAYS", "2"))


def run() -> None:
    """
    Main worker loop — runs forever.

    Sleeps POLL_INTERVAL seconds between ticks. Wraps each tick in
    a try/except so one bad inbox doesn't crash the whole worker.
    """
    print(f"Worker starting. Polling every {POLL_INTERVAL}s.")
    while True:
        try:
            tick()
        except Exception as e:
            print(f"⚠️ Worker tick error: {e}")
        time.sleep(POLL_INTERVAL)


def tick() -> None:
    """
    One iteration of the polling loop.

    Loads all active inboxes from the database and polls each one.
    Errors on one inbox don't affect the others.
    """
    inboxes = inbox_storage.get_active_inboxes()
    print(f"Polling {len(inboxes)} inbox(es)...")

    for inbox in inboxes:
        try:
            poll_inbox(inbox)
        except Exception as e:
            print(f"⚠️ Error polling {inbox.email_to_watch}: {e}")


def poll_inbox(inbox: InboxConfig) -> None:
    """
    Poll a single inbox — checks both the Inbox folder and the Junk folder.

    Loads category rules once, polls each folder, saves new delta tokens.
    """
    o365.ensure_account_fresh()
    rules = rules_storage.get_rules_for_inbox(inbox.id)

    # Clean up queue entries that have been externally handled (e.g. by the
    # old hub, another admin, or manually in Outlook). We detect this by
    # checking if the message now has a PAIRActioned tag on Outlook's side.
    _cleanup_stale_queue(inbox)

    # Process the main Inbox folder
    new_inbox_token = poll_folder(inbox, rules, "Inbox", inbox.delta_token_inbox)

    # Process the Junk Email folder
    new_junk_token = poll_folder(inbox, rules, "JunkEmail", inbox.delta_token_junk)

    # Save the updated tokens so we know where to pick up next time
    o365.save_last_delta(inbox, new_inbox_token, new_junk_token)


def poll_folder(
    inbox: InboxConfig,
    rules: List[CategoryRule],
    folder_name: str,
    current_token: Optional[str],
) -> Optional[str]:
    """
    Poll one folder for new messages and process each through the pipeline.

    Returns the new delta token to save. On first run (no token yet) does
    a backfill of unread messages from BACKFILL_DAYS ago, then a delta sync
    to establish a starting token for future runs.
    """

    # First-time backfill — catches messages that arrived before we had a token
    if not current_token:
        days_back = getattr(inbox, "backfill_days", None) or BACKFILL_DAYS
        since_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
        backfilled = o365.fetch_unread_since(inbox, folder_name, since_dt)
        print(f"[{folder_name}] Backfill found {len(backfilled)} message(s)")
        for normalized_msg in backfilled:
            _process_one(inbox, rules, normalized_msg)

    # Delta sync — gets changes since last token (or initial state if no token)
    messages, new_token = o365.fetch_messages_delta(inbox, folder_name, current_token)
    if messages:
        print(f"[{folder_name}] Delta sync found {len(messages)} message(s)")
    for normalized_msg in messages:
        _process_one(inbox, rules, normalized_msg)

    # Keep the new token if we got one, otherwise keep what we had
    return new_token or current_token


def _cleanup_stale_queue(inbox: InboxConfig) -> None:
    """
    Remove queue entries for messages that have been externally handled
    (tagged as PAIRActioned in Outlook) so the reviewer's queue matches reality.
    """
    try:
        pending = queue_storage.get_pending(inbox.id)
    except Exception as e:
        print(f"Queue cleanup: could not list pending: {e}")
        return

    for row in pending:
        message_id = row.get('message_id')
        if not message_id:
            continue
        try:
            raw_msg = o365.fetch_message_safely(inbox, message_id)
            if raw_msg is None:
                # Message deleted upstream — clean it out
                queue_storage.remove_from_queue(message_id)
                continue
            tags = getattr(raw_msg, 'categories', None) or []
            # Anything PAIRActioned* except our own "queued" placeholder means it's been handled elsewhere
            handled = any(
                (t or '').startswith('PAIRActioned') and (t or '') != 'PAIRActioned/queued' and (t or '') != 'PAIRActioned'
                for t in tags
            )
            if handled:
                queue_storage.remove_from_queue(message_id)
        except Exception as e:
            print(f"Queue cleanup error for {message_id}: {e}")


def _process_one(
    inbox: InboxConfig,
    rules: List[CategoryRule],
    normalized_msg: NormalizedMessage,
) -> None:
    """
    Run one message through the pipeline.

    Fetches the raw O365 message (needed to perform actions like reply/move),
    checks blocked sender / pair rules, then hands off to pipeline.process_message.
    """
    # Re-fetch the raw O365 message — we need it for actions (reply, move, etc.)
    raw_msg = o365.fetch_message_safely(inbox, normalized_msg.message_id)
    if raw_msg is None:
        print(f"⚠️ Could not fetch raw message {normalized_msg.message_id}")
        return

    # Silent skip for blocked senders or blocked sender/recipient pairs
    if o365._should_skip_message(inbox, raw_msg):
        return

    # Detect and handle staff SEND: replies before running classification
    if inbox.internal_reply_bridge_enabled:
        try:
            if o365.handle_internal_reply(inbox, raw_msg):
                return
        except Exception as e:
            print(f"Internal reply bridge error: {e}")

    print(f"📨 Processing: {normalized_msg.subject[:60]}")
    try:
        pipeline.process_message(normalized_msg, raw_msg, inbox, rules)
    except Exception as e:
        print(f"⚠️ Error processing message: {e}")
