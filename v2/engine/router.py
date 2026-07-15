"""
Router — converts a ClassificationResult + category rules into a
MessageActionPlan that the pipeline can execute.

This is where the actual routing decisions get made:
- Which folder does the email go to?
- Who gets it forwarded to?
- Does an auto-reply get sent?
- Does it need human review or auto-process?

The router doesn't talk to Microsoft or OpenAI — it just decides what
should happen. Execution is the pipeline/adapter's job.

TLDR takes the classifcaiton result and figure out what needs to be done using the json
"""

from datetime import datetime
from typing import List, Optional
import pytz

from models.InboxConfig import InboxConfig
from models.CategoryRule import CategoryRule
from models.NormalizedMessage import NormalizedMessage
from models.ClassificationResult import ClassificationResult
from models.MessageActionPlan import MessageActionPlan


def _sender_is_internal(inbox: InboxConfig, msg: NormalizedMessage) -> bool:
    """True if the message sender belongs to one of the inbox's internal domains."""
    if not msg.sender:
        return False
    sender = msg.sender.strip().lower()
    for domain in (inbox.internal_domains or []):
        d = (domain or "").strip().lower().lstrip("@")
        if not d:
            continue
        if sender.endswith("@" + d) or sender == d:
            return True
    return False


def decide(
    result: ClassificationResult,
    rules: List[CategoryRule],
    inbox: InboxConfig,
    msg: NormalizedMessage,
) -> MessageActionPlan:
    """
    Build a MessageActionPlan based on what GPT classified and the inbox's rules.

    Walks through:
      1. Find rules matching the returned categories
      2. Sort by priority (highest first)
      3. Decide folder from the top rule
      4. Collect forwarding recipients from all matching rules
      5. Pick auto-reply (if any) from highest-priority rule that has one
      6. Decide mark_read, tag, and human review flag
    """

    # --- Step 1: find matching active rules ---
    sender_internal = _sender_is_internal(inbox, msg)
    matching_rules = []
    for rule in rules:
        if not rule.active:
            continue
        if rule.key not in result.categories:
            continue
        # Skip this rule if the sender is internal and the rule opts to skip internal senders
        if rule.skip_if_internal and sender_internal:
            continue
        matching_rules.append(rule)

    # Unknown or invalid model output must always stop for human review,
    # including when the inbox normally runs in full-automation mode.
    if not matching_rules:
        return MessageActionPlan(
            move_to_folder=None,
            forward_to=[],
            send_reply=False,
            reply_text=None,
            mark_read=False,
            tag=None,
            requires_human_review=True,
            delete=False,
        )

    # --- Step 2: sort by priority (1 = highest) ---
    matching_rules.sort(key=_get_priority)
    top_rule = matching_rules[0]

    # If the top-priority matching rule is marked skip, do nothing at all
    if top_rule.skip:
        return MessageActionPlan(
            move_to_folder=None,
            forward_to=[],
            send_reply=False,
            reply_text=None,
            mark_read=False,
            tag=top_rule.key,
            requires_human_review=False,
            delete=False,
        )

    # --- Step 3: folder decision ---
    # "Deleted Items" is the sentinel for "delete this" (auto_reply, delete_internal).
    # Or if the rule has delete_immediately flag set, also delete.
    if top_rule.delete_immediately or top_rule.folder_path == "Deleted Items":
        delete = True
        move_to_folder = None
    else:
        delete = False
        move_to_folder = top_rule.folder_path

    # --- Step 4: collect forwarding recipients ---
    # Loop through all matching rules, gather their recipient lists,
    # filter out anything blocked by amount_threshold, then dedupe.
    forward_to_set = set() #so we don't worry about repeats
    for rule in matching_rules:
        if not rule.emails_to_forward:
            continue

        # Apply amount threshold filter (donor, invoice)
        # If the rule has a threshold and the detected amount is below it,
        # skip this rule's recipients entirely.
        if rule.amount_threshold is not None:
            amount = result.amount_money_detected
            if amount is None or amount < rule.amount_threshold:
                continue

        for email in rule.emails_to_forward:
            forward_to_set.add(email)

    forward_to = list(forward_to_set)

    # --- Step 5: pick auto-reply ---
    # Walk matching rules in priority order. First one that has a reply
    # template AND isn't blocked by the duplicate-reply safeguard wins.
    send_reply = False
    reply_text = None
    for rule in matching_rules:
        if not rule.auto_reply_enabled:
            continue
        if not rule.reply_template:
            continue

        # Safeguard: if this thread was already processed under this category,
        # skip sending another auto-reply. Checks PAIRActioned/<key> across
        # the whole thread (matches automate-email.py's behavior).
        if rule.auto_reply_safeguard:
            if _has_preexisting_category_tag(msg, rule.key):
                continue

        # Pick personal-variant template if GPT flagged this as needing a personal reply
        template_to_use = rule.reply_template
        if result.needs_personal_reply and getattr(rule, "reply_template_personal", ""):
            template_to_use = rule.reply_template_personal

        send_reply = True
        reply_text = _inject_greeting(template_to_use, result.name_sender)
        break

    # --- Step 6: mark read ---
    # Conservative: if ANY matching rule says don't mark read, leave unread
    mark_read = True
    for rule in matching_rules:
        if not rule.mark_read:
            mark_read = False
            break

    # --- Step 7: tag ---
    # Comma-joined keys of all matching rules. Used by the adapter to
    # apply PAIRActioned/<key> tags so we don't reprocess the message.
    tag_keys = []
    for rule in matching_rules:
        tag_keys.append(rule.key)
    tag = ",".join(tag_keys) if tag_keys else None

    # --- Step 8: human review or auto-execute ---
    requires_human_review = not inbox.automation_mode

    return MessageActionPlan(
        move_to_folder=move_to_folder,
        forward_to=forward_to,
        send_reply=send_reply,
        reply_text=reply_text,
        mark_read=mark_read,
        tag=tag,
        requires_human_review=requires_human_review,
        delete=delete,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_priority(rule: CategoryRule) -> int:
    """Helper for sort() — returns the priority number from a rule."""
    return rule.priority


def _has_preexisting_category_tag(msg: NormalizedMessage, category_key: str) -> bool:
    """
    Check if this message OR any other message in the same conversation was
    already processed under this category. Matches automate-email.py behavior:
    the safeguard looks for PAIRActioned/<key> since we never wrote the
    granular /replied/<key> variant.
    """
    target = f"PAIRActioned/{category_key}"
    all_tags = list(msg.existing_tags or []) + list(getattr(msg, "thread_tags", []) or [])
    for tag in all_tags:
        if tag == target:
            return True
    return False


def _inject_greeting(template: str, name_sender: Optional[str]) -> str:
    """
    Replace the {{greeting}} placeholder in a reply template.

    If we have a real sender name, use "Dear {name},".
    Otherwise fall back to "Good {morning/afternoon/evening},".
    """
    if name_sender and name_sender.strip() and name_sender.strip().lower() != "sender":
        greeting = f"Dear {name_sender.strip()},"
    else:
        greeting = f"Good {_tod_greeting()},"

    return template.replace("{{greeting}}", greeting)


def _tod_greeting() -> str:
    """Return 'morning', 'afternoon', or 'evening' based on Central Time."""
    try:
        central = pytz.timezone("America/Chicago")
        hour = datetime.now(central).hour
    except Exception:
        hour = 12  # safe default

    if 0 <= hour < 12:
        return "morning"
    if 12 <= hour < 18:
        return "afternoon"
    return "evening"
