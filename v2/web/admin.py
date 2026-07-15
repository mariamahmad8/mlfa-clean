"""
Admin API — the CRUD endpoints the admin hub UI calls.

Every button, form, and edit action in the admin hub sends an HTTP
request that hits one of these routes. Routes are grouped by resource:
inboxes, category rules, recipients, reply templates, users.

Plus two special endpoints:
  - Prompt preview: assemble the classification prompt for a given inbox
  - Test classification: run a fake email through classifier + router
    to see what would happen (without touching Outlook)
"""

import os
from typing import Optional
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, send_from_directory
from functools import wraps

from storage import inbox as inbox_storage
from storage import rules as rules_storage
from storage import recipients as recipients_storage
from storage import templates as templates_storage
from storage import users as users_storage
from storage import audit as audit_storage
from storage import queue as queue_storage

from models.InboxConfig import InboxConfig
from models.CategoryRule import CategoryRule
from models.Recipient import Recipient
from models.ReplyTemplate import ReplyTemplate
from models.User import User
from models.NormalizedMessage import NormalizedMessage

from engine import classifier, router


admin_bp = Blueprint("admin", __name__)
VALID_USER_ROLES = {"admin", "owner", "reviewer"}


# ---------------------------------------------------------------------------
# HTML page routes (serve the settings UI)
# ---------------------------------------------------------------------------

def _require_login_or_redirect():
    """For HTML routes: redirect to login instead of returning JSON."""
    if not session.get("logged_in"):
        return redirect(url_for("reviewer.login"))
    return None


def _require_settings_access_or_redirect():
    """For settings HTML routes: admins and owners can see settings.
    Reviewers get sent back to the hub."""
    if not session.get("logged_in"):
        return redirect(url_for("reviewer.login"))
    if session.get("role") not in {"admin", "owner"}:
        return redirect(url_for("reviewer.index"))
    return None


def _require_admin_or_redirect():
    """For admin-only HTML routes (user management)."""
    if not session.get("logged_in"):
        return redirect(url_for("reviewer.login"))
    if session.get("role") != "admin":
        return redirect(url_for("reviewer.index"))
    return None


def _accessible_inbox_ids():
    """Set of inbox ids the current user is allowed to touch.
    Admins → all active inboxes. Owners + reviewers → their assigned ids only."""
    role = session.get("role")
    all_inboxes = inbox_storage.get_active_inboxes()
    if role == "admin":
        return {ib.id for ib in all_inboxes}
    user_email = session.get("user_email")
    if not user_email:
        return set()
    user = users_storage.get_user_by_email(user_email)
    if not user:
        return set()
    assigned = set(user.assigned_inbox_ids or [])
    return {ib.id for ib in all_inboxes if ib.id in assigned}


def _current_user_can_access(inbox_id: int) -> bool:
    """True if the logged-in user is allowed to see/edit this inbox."""
    try:
        return int(inbox_id) in _accessible_inbox_ids()
    except (TypeError, ValueError):
        return False


def _resource_inbox_id(table: str, resource_id: int):
    """Look up the inbox_id that owns a specific rule / recipient / template row.
    Returns None if the row doesn't exist. Used to enforce owner scoping on
    resource-based routes like PATCH /api/rules/<id>."""
    from adapters.db import get_db_session
    from sqlalchemy import text
    allowed = {"category_rules", "recipients", "reply_templates"}
    if table not in allowed:
        return None
    session_db = get_db_session()
    try:
        row = session_db.execute(
            text(f"SELECT inbox_id FROM {table} WHERE id = :id"),
            {"id": resource_id},
        ).mappings().first()
        return row["inbox_id"] if row else None
    finally:
        session_db.close()


def _guard_resource_access(table: str, resource_id: int):
    """Verify the current user can touch the resource. Returns None if OK,
    a Flask jsonify tuple if forbidden — callers must `return` the value."""
    if session.get("role") == "admin":
        return None
    inbox_id = _resource_inbox_id(table, resource_id)
    if inbox_id is None:
        return jsonify({"error": "Not found"}), 404
    if not _current_user_can_access(inbox_id):
        return jsonify({"error": "You don't have access to that resource"}), 403
    return None


@admin_bp.route("/settings")
def settings_home():
    r = _require_settings_access_or_redirect()
    if r: return r
    return redirect("/settings/inboxes")


@admin_bp.route("/settings/inboxes")
def settings_inboxes():
    r = _require_settings_access_or_redirect()
    if r: return r
    return render_template("inboxes.html")


@admin_bp.route("/settings/categories")
def settings_categories():
    r = _require_settings_access_or_redirect()
    if r: return r
    return render_template("categories.html")


@admin_bp.route("/settings/recipients")
def settings_recipients():
    r = _require_settings_access_or_redirect()
    if r: return r
    return render_template("recipients.html")


@admin_bp.route("/settings/templates")
def settings_templates():
    r = _require_settings_access_or_redirect()
    if r: return r
    return render_template("templates.html")


@admin_bp.route("/settings/users")
def settings_users():
    # Admin only — user management is a global privilege
    r = _require_admin_or_redirect()
    if r: return r
    return render_template("users.html")


@admin_bp.route("/settings/audit")
def settings_audit():
    r = _require_settings_access_or_redirect()
    if r: return r
    return render_template("audit.html")


@admin_bp.route("/settings/preview")
def settings_preview():
    r = _require_settings_access_or_redirect()
    if r: return r
    return render_template("preview.html")




# ---------------------------------------------------------------------------
# Auth decorator — must be admin role (not reviewer)
# ---------------------------------------------------------------------------

def _audit(action: str, target: str, comment: str = "", inbox_id=None):
    """Convenience wrapper for admin-action audit entries."""
    try:
        audit_storage.log_event(
            inbox_id=inbox_id,
            email_id=target,
            action=action,
            actor=session.get('user_email', 'unknown'),
            comment=comment,
        )
    except Exception as e:
        print(f"Audit log error: {e}")


def admin_required(f):
    """Strict admin-only decorator — for user management, inbox create/delete,
    and anything that grants power beyond one inbox."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Authentication required"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


def settings_access_required(f):
    """Allow admins and owners; block reviewers.
    For settings CRUD that owners can perform on their assigned inboxes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Authentication required"}), 401
        if session.get("role") not in {"admin", "owner"}:
            return jsonify({"error": "Settings access required"}), 403
        return f(*args, **kwargs)
    return decorated


def inbox_scoped(f):
    """Decorator for routes that touch a specific inbox_id (in the URL).
    Enforces that owners can only touch their assigned inboxes.
    Admins pass through unchanged."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Authentication required"}), 401
        if session.get("role") == "admin":
            return f(*args, **kwargs)
        inbox_id = kwargs.get("inbox_id")
        if inbox_id is None or not _current_user_can_access(inbox_id):
            return jsonify({"error": "You don't have access to that inbox"}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# INBOXES
# ---------------------------------------------------------------------------

@admin_bp.route("/api/inboxes", methods=["GET"])
@settings_access_required
def list_inboxes():
    """Admins see all; owners see only their assigned inboxes."""
    inboxes = inbox_storage.get_active_inboxes()
    if session.get("role") != "admin":
        allowed = _accessible_inbox_ids()
        inboxes = [i for i in inboxes if i.id in allowed]
    return jsonify([_inbox_to_dict(i) for i in inboxes])


@admin_bp.route("/api/inboxes/<int:inbox_id>", methods=["GET"])
@settings_access_required
@inbox_scoped
def get_inbox(inbox_id):
    inbox = inbox_storage.get_inbox(inbox_id)
    if not inbox:
        return jsonify({"error": "Not found"}), 404
    return jsonify(_inbox_to_dict(inbox))


@admin_bp.route("/api/inboxes", methods=["POST"])
@admin_required
def create_inbox():
    data = request.get_json() or {}
    new = InboxConfig(
        id=None,
        email_to_watch=data.get("email_to_watch", ""),
        display_name=data.get("display_name", ""),
        automation_mode=bool(data.get("automation_mode", False)),
        blocked_senders=data.get("blocked_senders", []),
        skip_sender_pairs=data.get("skip_sender_pairs", []),
        system_preamble=data.get("system_preamble", ""),
        global_guidelines=data.get("global_guidelines", ""),
        internal_domains=data.get("internal_domains", []),
        backfill_days=int(data.get("backfill_days", 2)),
        use_thread_context=bool(data.get("use_thread_context", True)),
        internal_reply_bridge_enabled=bool(data.get("internal_reply_bridge_enabled", False)),
        internal_reply_external_prefix=data.get("internal_reply_external_prefix", "[EXTERNAL]"),
        internal_reply_internal_prefix=data.get("internal_reply_internal_prefix", "[INTERNAL]"),
    )
    inbox_storage.save_inbox(new)
    _audit("inbox_created", f"inbox:{new.email_to_watch}", f"Display: {new.display_name}")
    return jsonify({"status": "created"}), 201


@admin_bp.route("/api/inboxes/<int:inbox_id>", methods=["PATCH"])
@settings_access_required
@inbox_scoped
def update_inbox(inbox_id):
    inbox = inbox_storage.get_inbox(inbox_id)
    if not inbox:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    inbox.email_to_watch = data.get("email_to_watch", inbox.email_to_watch)
    inbox.display_name = data.get("display_name", inbox.display_name)
    inbox.automation_mode = data.get("automation_mode", inbox.automation_mode)
    inbox.blocked_senders = data.get("blocked_senders", inbox.blocked_senders)
    inbox.skip_sender_pairs = data.get("skip_sender_pairs", inbox.skip_sender_pairs)
    inbox.system_preamble = data.get("system_preamble", inbox.system_preamble)
    inbox.global_guidelines = data.get("global_guidelines", inbox.global_guidelines)
    inbox.internal_domains = data.get("internal_domains", inbox.internal_domains)
    inbox.backfill_days = int(data.get("backfill_days", inbox.backfill_days))
    inbox.use_thread_context = bool(data.get("use_thread_context", inbox.use_thread_context))
    inbox.internal_reply_bridge_enabled = bool(data.get("internal_reply_bridge_enabled", inbox.internal_reply_bridge_enabled))
    inbox.internal_reply_external_prefix = data.get("internal_reply_external_prefix", inbox.internal_reply_external_prefix)
    inbox.internal_reply_internal_prefix = data.get("internal_reply_internal_prefix", inbox.internal_reply_internal_prefix)
    inbox_storage.update_inbox(inbox)
    _audit("inbox_updated", f"inbox:{inbox.email_to_watch}", f"Display: {inbox.display_name}", inbox_id=inbox.id)
    return jsonify({"status": "updated"})


@admin_bp.route("/api/inboxes/<int:source_id>/clone", methods=["POST"])
@admin_required
def clone_inbox(source_id):
    """Create a new inbox by cloning an existing one's config, rules, recipients, and templates."""
    source = inbox_storage.get_inbox(source_id)
    if not source:
        return jsonify({"error": "Source inbox not found"}), 404

    data = request.get_json() or {}
    new_email = data.get("email_to_watch", "").strip()
    new_display = data.get("display_name", "").strip()
    if not new_email or not new_display:
        return jsonify({"error": "email_to_watch and display_name are required"}), 400

    new_inbox = InboxConfig(
        id=None,
        email_to_watch=new_email,
        display_name=new_display,
        automation_mode=False,
        blocked_senders=list(source.blocked_senders or []),
        skip_sender_pairs=list(source.skip_sender_pairs or []),
        system_preamble=source.system_preamble,
        global_guidelines=source.global_guidelines,
        internal_domains=list(source.internal_domains or []),
        backfill_days=source.backfill_days,
        use_thread_context=source.use_thread_context,
        internal_reply_bridge_enabled=source.internal_reply_bridge_enabled,
        internal_reply_external_prefix=source.internal_reply_external_prefix,
        internal_reply_internal_prefix=source.internal_reply_internal_prefix,
    )
    inbox_storage.save_inbox(new_inbox)

    # Find the new inbox by email to get its auto-generated id
    all_inboxes = inbox_storage.get_active_inboxes()
    created = next((i for i in all_inboxes if i.email_to_watch == new_email), None)
    if not created:
        return jsonify({"error": "Inbox saved but couldn't reload"}), 500

    # Clone templates first so category rules can point at the cloned ids.
    template_id_map = {}
    for tpl in templates_storage.get_templates_for_inbox(source_id):
        source_template_id = tpl.id
        tpl.id = None
        tpl.inbox_id = created.id
        template_id_map[source_template_id] = templates_storage.save_template(tpl)

    # Copy rules and remap their reusable template references.
    for rule in rules_storage.get_rules_for_inbox(source_id):
        rule.id = None
        rule.inbox_id = created.id
        rule.reply_template_id = template_id_map.get(rule.reply_template_id)
        rule.reply_template_personal_id = template_id_map.get(rule.reply_template_personal_id)
        rules_storage.save_rule(rule)

    # Copy recipients
    for recip in recipients_storage.get_recipients_for_inbox(source_id):
        recip.id = None
        recip.inbox_id = created.id
        recipients_storage.save_recipient(recip)

    _audit("inbox_cloned", f"inbox:{new_email}", f"Cloned from inbox_id {source_id}", inbox_id=created.id)
    return jsonify({"status": "cloned", "new_inbox_id": created.id}), 201


@admin_bp.route("/api/inboxes/<int:inbox_id>", methods=["DELETE"])
@admin_required
def delete_inbox(inbox_id):
    # Delete all rules for this inbox first (foreign key constraint)
    rules = rules_storage.get_rules_for_inbox(inbox_id)
    for rule in rules:
        rules_storage.delete_rule(rule.id)
    existing = inbox_storage.get_inbox(inbox_id)
    inbox_storage.delete_inbox(inbox_id)
    if existing:
        _audit("inbox_deleted", f"inbox:{existing.email_to_watch}", f"Display: {existing.display_name}")
    else:
        _audit("inbox_deleted", f"inbox_id:{inbox_id}")
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# CATEGORY RULES (nested under inbox)
# ---------------------------------------------------------------------------

@admin_bp.route("/api/inboxes/<int:inbox_id>/rules", methods=["GET"])
@settings_access_required
@inbox_scoped
def list_rules(inbox_id):
    rules = rules_storage.get_rules_for_inbox(inbox_id)
    return jsonify([_rule_to_dict(r) for r in rules])


@admin_bp.route("/api/rules/<int:rule_id>", methods=["GET"])
@settings_access_required
def get_rule(rule_id):
    denied = _guard_resource_access("category_rules", rule_id)
    if denied: return denied
    rule = rules_storage.get_rule(rule_id)
    if not rule:
        return jsonify({"error": "Not found"}), 404
    return jsonify(_rule_to_dict(rule))


@admin_bp.route("/api/inboxes/<int:inbox_id>/rules", methods=["POST"])
@settings_access_required
@inbox_scoped
def create_rule(inbox_id):
    data = request.get_json() or {}
    new_key = (data.get("key") or "").strip()
    if not new_key:
        return jsonify({"error": "Key is required"}), 400

    # Prevent duplicate key on the same inbox
    existing = rules_storage.get_rules_for_inbox(inbox_id)
    if any(r.key == new_key for r in existing):
        return jsonify({"error": f"A rule with key '{new_key}' already exists on this inbox"}), 400

    try:
        default_template_id, default_template_body = _resolve_template_selection(
            inbox_id, data.get("reply_template_id"), data.get("reply_template", "")
        )
        personal_template_id, personal_template_body = _resolve_template_selection(
            inbox_id,
            data.get("reply_template_personal_id"),
            data.get("reply_template_personal", ""),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    new = CategoryRule(
        id=None,
        inbox_id=inbox_id,
        key=new_key,
        label=data.get("label", ""),
        rule_text=data.get("rule_text", ""),
        mark_read=bool(data.get("mark_read", True)),
        skip=bool(data.get("skip", False)),
        auto_reply_safeguard=bool(data.get("auto_reply_safeguard", False)),
        auto_reply_enabled=bool(data.get("auto_reply_enabled", False)),
        emails_to_forward=data.get("emails_to_forward", []),
        folder_path=data.get("folder_path", ""),
        reply_template=default_template_body,
        amount_threshold=data.get("amount_threshold"),
        priority=int(data.get("priority", 999)),
        active=bool(data.get("active", True)),
        skip_if_internal=bool(data.get("skip_if_internal", False)),
        delete_immediately=bool(data.get("delete_immediately", False)),
        reply_template_personal=personal_template_body,
        reply_template_id=default_template_id,
        reply_template_personal_id=personal_template_id,
    )
    rules_storage.save_rule(new)
    _audit("rule_created", f"rule:{new.key}", f"Label: {new.label}", inbox_id=inbox_id)
    return jsonify({"status": "created"}), 201


@admin_bp.route("/api/rules/<int:rule_id>", methods=["PATCH"])
@settings_access_required
def update_rule(rule_id):
    denied = _guard_resource_access("category_rules", rule_id)
    if denied: return denied
    rule = rules_storage.get_rule(rule_id)
    if not rule:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}

    # If the key is being changed, check for collisions
    new_key = data.get("key")
    if new_key and new_key != rule.key:
        siblings = rules_storage.get_rules_for_inbox(rule.inbox_id)
        if any(r.key == new_key and r.id != rule_id for r in siblings):
            return jsonify({"error": f"Another rule on this inbox already uses key '{new_key}'"}), 400

    for field in ["key", "label", "rule_text", "mark_read", "skip", "auto_reply_safeguard",
                  "auto_reply_enabled", "emails_to_forward", "folder_path", "reply_template",
                  "amount_threshold", "priority", "active",
                  "skip_if_internal", "delete_immediately", "reply_template_personal"]:
        if field in data:
            setattr(rule, field, data[field])

    try:
        if "reply_template_id" in data:
            rule.reply_template_id, rule.reply_template = _resolve_template_selection(
                rule.inbox_id,
                data.get("reply_template_id"),
                data.get("reply_template", ""),
            )
        elif "reply_template" in data:
            # Backward-compatible behavior for older clients that submit only
            # custom body text: preserve the text but deliberately unlink it.
            rule.reply_template_id = None
        if "reply_template_personal_id" in data:
            rule.reply_template_personal_id, rule.reply_template_personal = _resolve_template_selection(
                rule.inbox_id,
                data.get("reply_template_personal_id"),
                data.get("reply_template_personal", ""),
            )
        elif "reply_template_personal" in data:
            rule.reply_template_personal_id = None
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    rules_storage.update_rule(rule)
    _audit("rule_updated", f"rule:{rule.key}", f"Label: {rule.label}", inbox_id=rule.inbox_id)
    return jsonify({"status": "updated"})


@admin_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@settings_access_required
def delete_rule(rule_id):
    denied = _guard_resource_access("category_rules", rule_id)
    if denied: return denied
    existing = rules_storage.get_rule(rule_id)
    rules_storage.delete_rule(rule_id)
    if existing:
        _audit("rule_deleted", f"rule:{existing.key}", f"Label: {existing.label}", inbox_id=existing.inbox_id)
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# RECIPIENTS (nested under inbox)
# ---------------------------------------------------------------------------

@admin_bp.route("/api/inboxes/<int:inbox_id>/recipients", methods=["GET"])
@settings_access_required
@inbox_scoped
def list_recipients(inbox_id):
    recips = recipients_storage.get_recipients_for_inbox(inbox_id)
    return jsonify([_recipient_to_dict(r) for r in recips])


@admin_bp.route("/api/inboxes/<int:inbox_id>/recipients", methods=["POST"])
@settings_access_required
@inbox_scoped
def create_recipient(inbox_id):
    data = request.get_json() or {}
    new = Recipient(
        id=None,
        inbox_id=inbox_id,
        label_recipient=data.get("label_recipient", ""),
        email=data.get("email", ""),
        notes=data.get("notes"),
        active=bool(data.get("active", True)),
        created_at=None,
    )
    recipients_storage.save_recipient(new)
    _audit("recipient_created", f"recipient:{new.email}", f"Label: {new.label_recipient}", inbox_id=inbox_id)
    return jsonify({"status": "created"}), 201


@admin_bp.route("/api/recipients/<int:recipient_id>", methods=["PATCH"])
@settings_access_required
def update_recipient(recipient_id):
    denied = _guard_resource_access("recipients", recipient_id)
    if denied: return denied
    resource_inbox_id = _resource_inbox_id("recipients", recipient_id)
    if resource_inbox_id is None:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    recip = Recipient(
        id=recipient_id,
        inbox_id=resource_inbox_id,
        label_recipient=data.get("label_recipient", ""),
        email=data.get("email", ""),
        notes=data.get("notes"),
        active=bool(data.get("active", True)),
        created_at=None,
    )
    recipients_storage.update_recipient(recip)
    _audit("recipient_updated", f"recipient:{recip.email}", f"Label: {recip.label_recipient}", inbox_id=recip.inbox_id)
    return jsonify({"status": "updated"})


@admin_bp.route("/api/recipients/<int:recipient_id>", methods=["DELETE"])
@settings_access_required
def delete_recipient(recipient_id):
    denied = _guard_resource_access("recipients", recipient_id)
    if denied: return denied
    # Find the recipient before deleting so we can log a readable name
    all_inboxes = inbox_storage.get_active_inboxes()
    target_recip = None
    for ib in all_inboxes:
        for r in recipients_storage.get_recipients_for_inbox(ib.id):
            if r.id == recipient_id:
                target_recip = r
                break
        if target_recip:
            break
    recipients_storage.delete_recipient(recipient_id)
    if target_recip:
        _audit("recipient_deleted", f"recipient:{target_recip.email}", f"Label: {target_recip.label_recipient}", inbox_id=target_recip.inbox_id)
    else:
        _audit("recipient_deleted", f"recipient_id:{recipient_id}")
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# REPLY TEMPLATES (nested under inbox)
# ---------------------------------------------------------------------------

@admin_bp.route("/api/inboxes/<int:inbox_id>/templates", methods=["GET"])
@settings_access_required
@inbox_scoped
def list_templates(inbox_id):
    tpls = templates_storage.get_templates_for_inbox(inbox_id)
    return jsonify([_template_to_dict(t) for t in tpls])


@admin_bp.route("/api/inboxes/<int:inbox_id>/templates", methods=["POST"])
@settings_access_required
@inbox_scoped
def create_template(inbox_id):
    data = request.get_json() or {}
    new = ReplyTemplate(
        id=None,
        inbox_id=inbox_id,
        name_template=data.get("name_template", ""),
        body_html=data.get("body_html", ""),
        active=bool(data.get("active", True)),
        created_at=None,
    )
    templates_storage.save_template(new)
    _audit("template_created", f"template:{new.name_template}", inbox_id=inbox_id)
    return jsonify({"status": "created"}), 201


@admin_bp.route("/api/templates/<int:template_id>", methods=["PATCH"])
@settings_access_required
def update_template(template_id):
    denied = _guard_resource_access("reply_templates", template_id)
    if denied: return denied
    resource_inbox_id = _resource_inbox_id("reply_templates", template_id)
    if resource_inbox_id is None:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    tpl = ReplyTemplate(
        id=template_id,
        inbox_id=resource_inbox_id,
        name_template=data.get("name_template", ""),
        body_html=data.get("body_html", ""),
        active=bool(data.get("active", True)),
        created_at=None,
    )
    templates_storage.update_template(tpl)
    _audit("template_updated", f"template:{tpl.name_template}", inbox_id=tpl.inbox_id)
    return jsonify({"status": "updated"})


@admin_bp.route("/api/templates/<int:template_id>", methods=["DELETE"])
@settings_access_required
def delete_template(template_id):
    denied = _guard_resource_access("reply_templates", template_id)
    if denied: return denied
    references = templates_storage.count_template_references(template_id)
    if references:
        return jsonify({
            "error": (
                f"This template is used by {references} category setting(s). "
                "Choose another template on those categories before deleting it."
            )
        }), 409

    all_inboxes = inbox_storage.get_active_inboxes()
    target_tpl = None
    for ib in all_inboxes:
        for t in templates_storage.get_templates_for_inbox(ib.id):
            if t.id == template_id:
                target_tpl = t
                break
        if target_tpl:
            break
    templates_storage.delete_template(template_id)
    if target_tpl:
        _audit("template_deleted", f"template:{target_tpl.name_template}", inbox_id=target_tpl.inbox_id)
    else:
        _audit("template_deleted", f"template_id:{template_id}")
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# USERS (global, not per-inbox)
# ---------------------------------------------------------------------------

@admin_bp.route("/api/users", methods=["GET"])
@admin_required
def list_users():
    users = users_storage.get_all_users()
    return jsonify([_user_to_dict(u) for u in users])


@admin_bp.route("/api/inboxes/<int:inbox_id>/stats", methods=["GET"])
@settings_access_required
@inbox_scoped
def inbox_stats(inbox_id):
    """Efficiency metrics for one inbox."""
    from datetime import datetime
    import pytz
    central = pytz.timezone('America/Chicago')
    today_start_ct = datetime.now(central).replace(hour=0, minute=0, second=0, microsecond=0)
    today_start_utc = today_start_ct.astimezone(pytz.utc).replace(tzinfo=None)

    stats = audit_storage.get_stats(inbox_id, today_start_utc)
    inbox = inbox_storage.get_inbox(inbox_id)
    in_review_now = len(queue_storage.get_pending(inbox_id))
    return jsonify({
        "inbox_id": inbox_id,
        "display_name": inbox.display_name if inbox else "",
        "email_to_watch": inbox.email_to_watch if inbox else "",
        "in_review_now": in_review_now,
        "today": {
            "processed": stats.get("processed_today", 0),
            "rejected": stats.get("rejected_today", 0),
            "dismissed": stats.get("dismissed_today", 0),
            "duration_ms": int(stats.get("duration_ms_today") or 0),
            "avg_duration_ms": int(stats.get("avg_duration_ms_today") or 0),
        },
        "all_time": {
            "processed": stats.get("processed_all", 0),
            "rejected": stats.get("rejected_all", 0),
            "dismissed": stats.get("dismissed_all", 0),
            "duration_ms": int(stats.get("duration_ms_all") or 0),
            "avg_duration_ms": int(stats.get("avg_duration_ms_all") or 0),
        },
    })


@admin_bp.route("/api/inboxes/<int:inbox_id>/audit", methods=["GET"])
@settings_access_required
@inbox_scoped
def list_audit(inbox_id):
    events = audit_storage.get_events(inbox_id, limit=200)
    return jsonify([
        {
            "id": e.get("id"),
            "email_id": e.get("email"),
            "action": e.get("action_taken"),
            "actor": e.get("actor"),
            "comment": e.get("comment"),
            "created_at": e["created_at"].isoformat() if e.get("created_at") else None,
        }
        for e in events
    ])


@admin_bp.route("/api/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(user_id):
    data = request.get_json() or {}
    role_user = data.get("role_user", "reviewer")
    if role_user not in VALID_USER_ROLES:
        return jsonify({"error": "Invalid role"}), 400
    users_storage.update_user(
        user_id,
        role_user=role_user,
        active=bool(data.get("active", True)),
        assigned_inbox_ids=data.get("assigned_inbox_ids", []),
    )
    # Look up the email so the audit target is readable
    all_users = users_storage.get_all_users()
    target = next((u for u in all_users if u.id == user_id), None)
    _audit(
        "user_updated",
        f"user:{target.email}" if target else f"user_id:{user_id}",
        f"Role: {data.get('role_user')}"
    )
    return jsonify({"status": "updated"})


@admin_bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    all_users = users_storage.get_all_users()
    target = next((u for u in all_users if u.id == user_id), None)
    users_storage.delete_user(user_id)
    if target:
        _audit("user_deleted", f"user:{target.email}", f"Role: {target.role_user}")
    else:
        _audit("user_deleted", f"user_id:{user_id}")
    return jsonify({"status": "deleted"})


@admin_bp.route("/api/users", methods=["POST"])
@admin_required
def create_user():
    data = request.get_json() or {}
    role_user = data.get("role_user", "reviewer")
    if role_user not in VALID_USER_ROLES:
        return jsonify({"error": "Invalid role"}), 400
    new = User(
        id=None,
        email=data.get("email", ""),
        display_name=None,
        microsoft_oid=None,
        role_user=role_user,
        last_login_at=None,
        created_at=None,
        active=bool(data.get("active", True)),
        assigned_inbox_ids=data.get("assigned_inbox_ids", []),
    )
    users_storage.save_user(new)
    _audit("user_created", f"user:{new.email}", f"Role: {new.role_user}")
    return jsonify({"status": "created"}), 201


# ---------------------------------------------------------------------------
# PROMPT PREVIEW
# ---------------------------------------------------------------------------

@admin_bp.route("/api/inboxes/<int:inbox_id>/prompt_preview", methods=["GET"])
@settings_access_required
@inbox_scoped
def prompt_preview(inbox_id):
    """Assemble and return what the classification prompt looks like for an inbox."""
    inbox = inbox_storage.get_inbox(inbox_id)
    if not inbox:
        return jsonify({"error": "Not found"}), 404
    rules = rules_storage.get_rules_for_inbox(inbox_id)

    # Dummy message so the prompt has a placeholder for the email
    fake_msg = NormalizedMessage(
        message_id="preview",
        sender="example@sender.com",
        subject="[Example subject]",
        body="[Example email body]",
        received_at=None,
        conversation_id="",
        thread_messages=[],
        existing_tags=[],
    )
    prompt_string = classifier.build_prompt(fake_msg, inbox, rules)
    return jsonify({"prompt": prompt_string})


# ---------------------------------------------------------------------------
# TEST CLASSIFICATION
# ---------------------------------------------------------------------------

@admin_bp.route("/api/inboxes/<int:inbox_id>/test_classification", methods=["POST"])
@settings_access_required
@inbox_scoped
def test_classification(inbox_id):
    """Run a fake email through the classifier + router without touching Outlook."""
    inbox = inbox_storage.get_inbox(inbox_id)
    if not inbox:
        return jsonify({"error": "Not found"}), 404

    data = request.get_json() or {}
    fake_msg = NormalizedMessage(
        message_id="test",
        sender=data.get("sender", "test@example.com"),
        subject=data.get("subject", ""),
        body=data.get("body", ""),
        received_at=None,
        conversation_id="",
        thread_messages=[],
        existing_tags=[],
    )
    rules = rules_storage.get_rules_for_inbox(inbox_id)
    result = classifier.classify(fake_msg, inbox, rules)
    plan = router.decide(result, rules, inbox, fake_msg)
    return jsonify({
        "classification": {
            "categories": result.categories,
            "recipients": result.recipients,
            "needs_personal_reply": result.needs_personal_reply,
            "escalation_reason": result.escalation_reason,
            "name_sender": result.name_sender,
            "amount_detected": result.amount_money_detected,
        },
        "plan": {
            "move_to_folder": plan.move_to_folder,
            "forward_to": plan.forward_to,
            "send_reply": plan.send_reply,
            "reply_text": plan.reply_text,
            "mark_read": plan.mark_read,
            "tag": plan.tag,
            "requires_human_review": plan.requires_human_review,
            "delete": plan.delete,
        },
    })


# ---------------------------------------------------------------------------
# Helpers — convert model dataclasses to plain dicts for JSON responses
# ---------------------------------------------------------------------------

def _resolve_template_selection(inbox_id, raw_template_id, legacy_body=""):
    """Validate a template belongs to the rule's inbox and return its live body."""
    if raw_template_id in (None, ""):
        return None, legacy_body or ""
    try:
        template_id = int(raw_template_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid reply template selection") from exc

    template = templates_storage.get_template(template_id)
    if template is None or template.inbox_id != int(inbox_id):
        raise ValueError("Reply template does not belong to this inbox")
    return template.id, template.body_html

def _inbox_to_dict(inbox):
    return {
        "id": inbox.id,
        "email_to_watch": inbox.email_to_watch,
        "display_name": inbox.display_name,
        "automation_mode": inbox.automation_mode,
        "blocked_senders": inbox.blocked_senders,
        "skip_sender_pairs": inbox.skip_sender_pairs,
        "system_preamble": inbox.system_preamble,
        "global_guidelines": inbox.global_guidelines,
        "internal_domains": inbox.internal_domains,
        "backfill_days": inbox.backfill_days,
        "use_thread_context": inbox.use_thread_context,
        "internal_reply_bridge_enabled": inbox.internal_reply_bridge_enabled,
        "internal_reply_external_prefix": inbox.internal_reply_external_prefix,
        "internal_reply_internal_prefix": inbox.internal_reply_internal_prefix,
    }


def _rule_to_dict(rule):
    return {
        "id": rule.id,
        "inbox_id": rule.inbox_id,
        "key": rule.key,
        "label": rule.label,
        "rule_text": rule.rule_text,
        "mark_read": rule.mark_read,
        "skip": rule.skip,
        "auto_reply_safeguard": rule.auto_reply_safeguard,
        "auto_reply_enabled": rule.auto_reply_enabled,
        "emails_to_forward": rule.emails_to_forward,
        "folder_path": rule.folder_path,
        "reply_template": rule.reply_template,
        "amount_threshold": rule.amount_threshold,
        "priority": rule.priority,
        "active": rule.active,
        "skip_if_internal": rule.skip_if_internal,
        "delete_immediately": rule.delete_immediately,
        "reply_template_personal": rule.reply_template_personal,
        "reply_template_id": rule.reply_template_id,
        "reply_template_personal_id": rule.reply_template_personal_id,
    }


def _recipient_to_dict(recipient):
    return {
        "id": recipient.id,
        "inbox_id": recipient.inbox_id,
        "label_recipient": recipient.label_recipient,
        "email": recipient.email,
        "notes": recipient.notes,
        "active": recipient.active,
    }


def _template_to_dict(template):
    return {
        "id": template.id,
        "inbox_id": template.inbox_id,
        "name_template": template.name_template,
        "body_html": template.body_html,
        "active": template.active,
    }


def _user_to_dict(user):
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role_user": user.role_user,
        "active": user.active,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "assigned_inbox_ids": user.assigned_inbox_ids or [],
    }
