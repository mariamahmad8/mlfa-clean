"""
Classifier — builds the prompt from inbox config + category rules,
calls the OpenAI adapter, and returns a ClassificationResult.

The prompt assembly is the most important part to understand:
prompt = preamble + all active category rules + global guidelines + email.
That structure mirrors the original 1,080-line hardcoded prompt but now
it's built dynamically from database rows.
"""

from typing import List

from models.InboxConfig import InboxConfig
from models.CategoryRule import CategoryRule
from models.NormalizedMessage import NormalizedMessage
from models.ClassificationResult import ClassificationResult
from adapters import openai_client


def build_prompt(msg: NormalizedMessage, inbox: InboxConfig, rules: List[CategoryRule]) -> str:
    """
    Assemble the full classification prompt for one message.

    Pieces (in this order):
      1. inbox.system_preamble — role, context, escalation rules
      2. Each active rule's rule_text — sorted by priority (1 = highest)
      3. inbox.global_guidelines — conversation override + JSON output format
      4. Thread context if available (earlier messages in same conversation)
      5. The actual email subject + body
    """

    # Pull each chunk into its own variable for clarity
    preamble = inbox.system_preamble
    guidelines = inbox.global_guidelines
    subject = msg.subject
    body = msg.body

    # Skip disabled rules first
    active_rules = []
    for rule in rules:
        if rule.active:
            active_rules.append(rule)

    # Sort by priority (1 = highest)
    active_rules.sort(key=_get_priority)

    # Combine each rule's text into one block, separated by blank lines
    rules_section = ""
    for rule in active_rules:
        rules_section += rule.rule_text + "\n\n"
    rules_section = rules_section.strip()

    # Thread context is optional — only added if the message has earlier
    # messages attached AND the inbox has use_thread_context enabled.
    if msg.thread_messages and getattr(inbox, "use_thread_context", True):
        thread_section = (
            "These are earlier emails from the same thread. Use them as context "
            "to make the right routing decision.\n\n"
            "Thread context (older messages, oldest→newest):\n"
            + "\n\n".join(msg.thread_messages)
            + "\n\n"
        )
    else:
        thread_section = ""

    # Stitch the pieces together in the agreed order
    return f"""{preamble}
      ROUTING RULES & RECIPIENTS:

      {rules_section}
      {guidelines}
      {thread_section}Subject: {subject}
      Body:
      {body}
      """


def _get_priority(rule: CategoryRule) -> int:
    """Helper for sort() — returns the priority number from a rule."""
    return rule.priority


def classify(msg: NormalizedMessage, inbox: InboxConfig, rules: List[CategoryRule]) -> ClassificationResult:
    """
    Build the prompt and send it to the OpenAI adapter.

    The adapter handles the API call, JSON parsing, and translating the
    response into a ClassificationResult dataclass. This function just
    glues prompt-building to the adapter.
    """
    prompt = build_prompt(msg, inbox, rules)
    return openai_client.classify_email(prompt)
