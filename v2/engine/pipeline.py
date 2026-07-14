"""
Pipeline — the entry point the worker calls for every incoming email.

process_message() runs the full sequence:
    classify → decide → execute

execute_plan() reads the MessageActionPlan and calls the right
O365 adapter functions to actually perform the actions on the message.

Note: raw_msg here is the O365 library message object (not NormalizedMessage).
The adapter needs the real O365 object to act on it. The NormalizedMessage
is what classifier/router work with.
"""

from typing import List

from models.InboxConfig import InboxConfig
from models.CategoryRule import CategoryRule
from models.NormalizedMessage import NormalizedMessage
from models.MessageActionPlan import MessageActionPlan
from models.ClassificationResult import ClassificationResult

from engine import classifier, router
from adapters import o365
from storage import queue, audit


def process_message(
    normalized_msg: NormalizedMessage,
    raw_msg,
    inbox: InboxConfig,
    rules: List[CategoryRule],
) -> None:
    """
    Run one email through the full pipeline.

    Steps:
      1. Classify with GPT
      2. Decide on an action plan
      3. Either queue it for human review or execute the plan now
      4. Always log the outcome to the audit log

    normalized_msg is the clean dataclass for classification/routing.
    raw_msg is the underlying O365 library message for performing actions.
    """

    # Step 0 — enrich with thread context and thread-wide tags (for safeguards)
    if inbox.use_thread_context and normalized_msg.conversation_id:
        try:
            normalized_msg.thread_messages = o365.get_thread_messages(
                inbox, normalized_msg.conversation_id, normalized_msg.message_id
            )
            normalized_msg.thread_tags = o365.get_thread_tags(inbox, normalized_msg.conversation_id)
        except Exception as e:
            print(f"Thread enrichment error: {e}")

    # Step 1 — classify
    result = classifier.classify(normalized_msg, inbox, rules)
    # Flow needs_personal_reply back onto the message so router can pick the right template
    normalized_msg.needs_personal_reply = result.needs_personal_reply

    # Step 2 — decide
    plan = router.decide(result, rules, inbox, normalized_msg)

    # Step 3 — queue or execute
    if plan.requires_human_review:
        # Save the message + classification so a reviewer can act on it later
        classification_dict = {
            "categories": result.categories,
            "recipients": result.recipients,
            "needs_personal_reply": result.needs_personal_reply,
            "escalation_reason": result.escalation_reason,
            "name_sender": result.name_sender,
            "amount_detected": result.amount_money_detected,
        }
        queue.add_to_queue(normalized_msg, inbox.id, classification_dict)
        # Tag the message with PAIRActioned/queued so delta sync doesn't re-process it
        try:
            o365.tag_email(raw_msg, ["queued"], reply_tag=False)
        except Exception as e:
            print(f"Could not tag queued message: {e}")
        audit.log_event(
            inbox_id=inbox.id,
            email_id=normalized_msg.message_id,
            action="queued_for_review",
            actor="system",
            comment=",".join(result.categories),
        )
    else:
        # Auto-process: actually do the actions on Microsoft
        execute_plan(plan, inbox, raw_msg)
        audit.log_event(
            inbox_id=inbox.id,
            email_id=normalized_msg.message_id,
            action="auto_processed",
            actor="system",
            comment=plan.tag,
        )


def execute_plan(plan: MessageActionPlan, inbox: InboxConfig, raw_msg) -> None:
    """
    Take a MessageActionPlan and call the right O365 adapter functions.

    Order matters: delete first (skip everything else), otherwise do reply
    and forward and tag, then move/mark-read last so we don't try to act
    on a message we've already moved out of view.
    """

    o365.remove_email_tags(raw_msg, ["PAIRActioned/queued"])

    # 1. Delete → trash → done
    if plan.delete:
        o365.move_to_trash(inbox, raw_msg)
        return

    # 2. Send auto-reply (if any)
    if plan.send_reply and plan.reply_text:
        try:
            o365.send_reply(raw_msg, plan.reply_text)
        except Exception as e:
            print(f"⚠️ Could not send reply: {e}")

    # 3. Forward to recipients (if any). If the internal reply bridge is
    # enabled for this inbox, embed a hidden reference so staff SEND:
    # replies can be relayed back to the original sender.
    if plan.forward_to:
        try:
            if inbox.internal_reply_bridge_enabled:
                o365.forward_with_reply_bridge(raw_msg, plan.forward_to)
            else:
                o365.forward_message(raw_msg, plan.forward_to)
        except Exception as e:
            print(f"⚠️ Could not forward message: {e}")

    # 4. Apply tags so the message won't be reprocessed next poll
    if plan.tag:
        tag_categories = plan.tag.split(",")
        o365.tag_email(raw_msg, tag_categories, reply_tag=False)
        # Also tag the reply if we sent one
        if plan.send_reply:
            o365.tag_email(raw_msg, tag_categories, reply_tag=True)

    # 5. Mark as read (if appropriate for these categories)
    if plan.mark_read:
        o365.mark_as_read(raw_msg)

    # 6. Move to folder (last, so we still had the message in scope for above)
    if plan.move_to_folder:
        path_parts = plan.move_to_folder.split("/")
        o365.move_to_folder(inbox, raw_msg, path_parts)
