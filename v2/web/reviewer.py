"""
Reviewer web routes — the approval hub Flask API.

Endpoints:
  /              → serves the HTML
  /login, /logout
  /api/emails    → list pending emails for review
  /api/emails/<id>/approve     → execute the action plan
  /api/emails/<id>/reject      → move to trash
  /api/emails/<id>/dismiss     → mark read, no action
  /api/emails/approve_all      → approve everything in the queue
  /api/settings/automation     → toggle automation mode per inbox

All routes require login. Routes operate on the first active inbox for now
(MLFA only in phase 1). Phase 2 admin hub will take an inbox_id parameter.
"""

import os
import re
import hmac
import hashlib
import secrets
from functools import wraps
from flask import Blueprint, request, session, redirect, url_for, render_template, send_from_directory, jsonify

from storage import inbox as inbox_storage
from storage import rules as rules_storage
from storage import queue as queue_storage
from storage import audit as audit_storage
from storage import users as users_storage
from storage import login_tokens as tokens_storage
from adapters import o365
from engine import router, pipeline


reviewer_bp = Blueprint('reviewer', __name__)

ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH', '')


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def verify_password(plain_password: str) -> bool:
    """Compare a plain password against the stored SHA-256 hash."""
    stored = (ADMIN_PASSWORD_HASH or '').strip()
    if not stored:
        return False
    try:
        if stored.lower().startswith('sha256:'):
            hexhash = stored.split(':', 1)[1].strip()
        elif re.fullmatch(r'[A-Fa-f0-9]{64}', stored):
            hexhash = stored
        else:
            return False
        calc = hashlib.sha256(plain_password.encode('utf-8')).hexdigest()
        return hmac.compare_digest(calc, hexhash.lower())
    except Exception:
        return False


def login_required(f):
    """Decorator — requires logged-in session. API routes get JSON 401, others redirect."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for('reviewer.login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

def _hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode('utf-8')).hexdigest()


@reviewer_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Magic-link login: enter email, get a login link sent to your inbox."""
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        if not email:
            return render_template('login.html', error='Please enter your email or password.')

        user = users_storage.get_user_by_email(email)
        if not user or not user.active:
            # Deliberately generic message so we don't leak which emails exist
            return render_template('login.html', info='If that email is authorized, a login link is on its way.')

        # Generate a token, hash it, save the hash, send the plaintext in the email
        plaintext_token = secrets.token_urlsafe(32)
        token_hash = _hash_token(plaintext_token)
        tokens_storage.create_token(email, token_hash, expires_in_minutes=15)

        # Build the login link
        base = request.host_url.rstrip('/')
        link = f"{base}/login/verify?token={plaintext_token}"

        # Send via the first active inbox (uses the MLFA mailbox to send)
        inboxes = inbox_storage.get_active_inboxes()
        if inboxes:
            try:
                o365.send_email(
                    inboxes[0],
                    to=email,
                    subject="Your MLFA hub sign-in link",
                    body_html=f"""
                        <p>Hi,</p>
                        <p>Click the link below to sign in to the MLFA hub. It expires in 15 minutes.</p>
                        <p><a href="{link}">{link}</a></p>
                        <p>If you didn't request this, you can ignore this email.</p>
                    """,
                )
            except Exception as e:
                print(f"Login email send error: {e}")

        return render_template('login.html', info='Login link sent. Check your inbox.')

    return render_template('login.html')


@reviewer_bp.route('/login/verify', methods=['GET'])
def login_verify():
    """Click-through from a magic-link email — verify the token and set session."""
    plaintext = (request.args.get('token') or '').strip()
    if not plaintext:
        return render_template('login.html', error='Invalid or missing link.')

    token_hash = _hash_token(plaintext)
    row = tokens_storage.get_valid_token(token_hash)
    if not row:
        return render_template('login.html', error='Link is invalid or expired.')

    tokens_storage.mark_used(token_hash)

    user = users_storage.get_user_by_email(row['email'])
    if not user or not user.active:
        return render_template('login.html', error='Account is no longer active.')

    # Record login time (and fill in oid/display_name if not set yet)
    try:
        users_storage.update_last_login(
            user.id,
            oid=user.microsoft_oid or "",
            display_name=user.display_name or user.email.split('@')[0],
        )
    except Exception as e:
        print(f"update_last_login error: {e}")

    session['logged_in'] = True
    session['role'] = user.role_user
    session['user_email'] = user.email
    session['user_id'] = user.id
    session.permanent = True
    return redirect(url_for('reviewer.index'))


@reviewer_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('reviewer.login'))


def _accessible_inboxes():
    """Return list of inboxes the current user can access.
    Admins see all. Reviewers only see their assigned ones."""
    all_inboxes = inbox_storage.get_active_inboxes()
    if session.get('role') == 'admin':
        return all_inboxes
    # Reviewer — filter to assigned only
    user_email = session.get('user_email')
    if not user_email:
        return []
    user = users_storage.get_user_by_email(user_email)
    if not user:
        return []
    assigned = set(user.assigned_inbox_ids or [])
    return [ib for ib in all_inboxes if ib.id in assigned]


# ---------------------------------------------------------------------------
# Reviewer routes
# ---------------------------------------------------------------------------

@reviewer_bp.route('/')
@login_required
def index():
    """Serve the review hub HTML with the current user info."""
    return render_template(
        'hub.html',
        current_role=session.get('role', 'reviewer'),
        current_email=session.get('user_email', ''),
    )


@reviewer_bp.route('/static/shared.css')
def shared_css():
    """Serve the shared CSS to any page under this blueprint."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(os.path.join(base_dir, '..', 'templates'), 'shared.css')


@reviewer_bp.route('/mlfa-favicon.png')
def favicon():
    """Serve the MLFA logo used in the browser tab."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(
        os.path.join(base_dir, '..'),
        'mlfa_favicon.png',
        mimetype='image/png',
    )


@reviewer_bp.route('/api/my_inboxes')
@login_required
def my_inboxes():
    """Return the inboxes this user can access (all for admin, assigned for reviewer)."""
    inboxes = _accessible_inboxes()
    return jsonify([
        {"id": ib.id, "display_name": ib.display_name, "email_to_watch": ib.email_to_watch}
        for ib in inboxes
    ])


@reviewer_bp.route('/api/emails')
@login_required
def get_emails():
    """
    Return pending emails formatted for the UI.

    For phase 1: returns pending emails for the first active inbox (MLFA).
    """
    inbox = _get_current_inbox()
    if inbox is None:
        return jsonify([])

    pending_rows = queue_storage.get_pending(inbox.id)
    emails = []
    for row in pending_rows:
        classification = row.get('classification') or {}
        categories = classification.get('categories', [])
        recipients = classification.get('recipients', [])
        amount = classification.get('amount_detected')

        emails.append({
            "id": row['message_id'],
            "meta": f"FROM: {row.get('received_at', '')} | {row.get('sender', '')} | {row.get('subject_email', '')}",
            "senderName": classification.get('name_sender') or 'Unknown',
            "category": ', '.join(c.replace('_', ' ').title() for c in categories),
            "amountDetected": str(amount) if amount is not None else 'None',
            "recipients": ', '.join(recipients) if recipients else 'None',
            "needsReply": "Yes" if classification.get('needs_personal_reply') else "No",
            "reason": classification.get('escalation_reason') or 'None',
            "escalation": classification.get('escalation_reason') or 'None',
            "originalContent": row.get('body_email', ''),
            "status": "pending",
        })
    return jsonify(emails)


@reviewer_bp.route('/api/emails/<email_id>/approve', methods=['POST'])
@login_required
def approve_email(email_id):
    """
    Approve a queued email — execute its action plan.

    Re-runs the router against current rules so any rule changes since
    queuing are honored. Removes the row from the queue and logs the action.
    """
    inbox = _get_current_inbox()
    if inbox is None:
        return jsonify({"error": "No active inbox"}), 400

    raw_msg = o365.fetch_message_safely(inbox, email_id)
    if raw_msg is None:
        queue_storage.remove_from_queue(email_id)
        return jsonify({"error": "Original message not found"}), 404

    # Optional reviewer comment — sent to REVIEW_NOTIFY_EMAIL if set
    data = request.get_json(silent=True) or {}
    reviewer_comment = (data.get('comment') or '').strip()

    # Re-run router using current rules + the queued classification
    pending_rows = queue_storage.get_pending(inbox.id)
    matching = [r for r in pending_rows if r['message_id'] == email_id]
    if not matching:
        return jsonify({"error": "Not in queue"}), 404
    row = matching[0]
    classification_dict = row.get('classification') or {}

    rules = rules_storage.get_rules_for_inbox(inbox.id)
    normalized_msg = _build_normalized_from_row(row)
    classification_result = _classification_from_dict(classification_dict)
    plan = router.decide(classification_result, rules, inbox, normalized_msg)

    try:
        pipeline.execute_plan(plan, inbox, raw_msg)
    except Exception as e:
        return jsonify({"error": f"Execution failed: {e}"}), 500

    # If reviewer left a comment, send a notification email summarizing the action
    if reviewer_comment:
        notify_to = os.getenv('REVIEW_NOTIFY_EMAIL', '')
        if notify_to:
            try:
                o365.send_email(
                    inbox,
                    to=notify_to,
                    subject=f"[Review] Approved: {row.get('subject_email', '')}",
                    body_html=(
                        f"<p><strong>Reviewer:</strong> {session.get('user_email', 'unknown')}</p>"
                        f"<p><strong>Comment:</strong> {reviewer_comment}</p>"
                        f"<p><strong>Categories:</strong> {plan.tag or 'none'}</p>"
                        f"<p><strong>Subject:</strong> {row.get('subject_email', '')}</p>"
                        f"<p><strong>From:</strong> {row.get('sender', '')}</p>"
                    ),
                )
            except Exception as e:
                print(f"Review notify email error: {e}")

    queue_storage.remove_from_queue(email_id)
    audit_storage.log_event(
        inbox_id=inbox.id,
        email_id=email_id,
        action="approved",
        actor=session.get('user_email', 'unknown'),
        comment=reviewer_comment or plan.tag,
    )
    return jsonify({"status": "approved"})


@reviewer_bp.route('/api/emails/<email_id>/reject', methods=['POST'])
@login_required
def reject_email(email_id):
    """Reject a queued email — move to Trash, log the reason."""
    inbox = _get_current_inbox()
    if inbox is None:
        return jsonify({"error": "No active inbox"}), 400

    data = request.get_json(silent=True) or {}
    reason = data.get('reason', '')

    raw_msg = o365.fetch_message_safely(inbox, email_id)
    if raw_msg is not None:
        o365.remove_email_tags(raw_msg, ['PAIRActioned/queued'])
        o365.move_to_trash(inbox, raw_msg)
        o365.tag_email(raw_msg, ['dismissed'], reply_tag=False)

    queue_storage.remove_from_queue(email_id)
    audit_storage.log_event(
        inbox_id=inbox.id,
        email_id=email_id,
        action="rejected",
        actor=session.get('user_email', 'unknown'),
        comment=reason,
    )
    return jsonify({"status": "rejected"})


@reviewer_bp.route('/api/emails/<email_id>/dismiss', methods=['POST'])
@login_required
def dismiss_email(email_id):
    """Dismiss a queued email — mark as read, no other action."""
    inbox = _get_current_inbox()
    if inbox is None:
        return jsonify({"error": "No active inbox"}), 400

    raw_msg = o365.fetch_message_safely(inbox, email_id)
    if raw_msg is not None:
        o365.remove_email_tags(raw_msg, ['PAIRActioned/queued'])
        o365.mark_as_read(raw_msg)
        o365.tag_email(raw_msg, ['dismissed'], reply_tag=False)

    queue_storage.remove_from_queue(email_id)
    audit_storage.log_event(
        inbox_id=inbox.id,
        email_id=email_id,
        action="dismissed",
        actor=session.get('user_email', 'unknown'),
        comment=None,
    )
    return jsonify({"status": "dismissed"})


@reviewer_bp.route('/api/emails/approve_all', methods=['POST'])
@login_required
def approve_all_emails():
    """Approve every pending email in one shot."""
    inbox = _get_current_inbox()
    if inbox is None:
        return jsonify({"error": "No active inbox"}), 400

    pending_rows = queue_storage.get_pending(inbox.id)
    processed = 0
    errors = []
    for row in pending_rows:
        email_id = row['message_id']
        try:
            raw_msg = o365.fetch_message_safely(inbox, email_id)
            if raw_msg is None:
                queue_storage.remove_from_queue(email_id)
                continue
            rules = rules_storage.get_rules_for_inbox(inbox.id)
            normalized_msg = _build_normalized_from_row(row)
            classification_result = _classification_from_dict(row.get('classification') or {})
            plan = router.decide(classification_result, rules, inbox, normalized_msg)
            pipeline.execute_plan(plan, inbox, raw_msg)
            queue_storage.remove_from_queue(email_id)
            audit_storage.log_event(
                inbox_id=inbox.id,
                email_id=email_id,
                action="approved_bulk",
                actor=session.get('user_email', 'unknown'),
                comment=plan.tag,
            )
            processed += 1
        except Exception as e:
            errors.append({"id": email_id, "error": str(e)})

    return jsonify({"processed": processed, "errors": errors})


# ---------------------------------------------------------------------------
# Automation toggle (phase 2 will move this to admin.py)
# ---------------------------------------------------------------------------

@reviewer_bp.route('/api/settings/automation', methods=['GET'])
@login_required
def get_automation_setting():
    """Return the current automation mode for the active inbox."""
    inbox = _get_current_inbox()
    if inbox is None:
        return jsonify({"automationEnabled": False})
    return jsonify({"status": "success", "automationEnabled": bool(inbox.automation_mode)})


@reviewer_bp.route('/api/settings/automation', methods=['POST'])
@login_required
def update_automation_setting():
    if session.get('role') != 'admin':
        return jsonify({"error": "Admin access required"}), 403
    """Toggle automation mode. If turning ON, also process anything already queued."""
    inbox = _get_current_inbox()
    if inbox is None:
        return jsonify({"error": "No active inbox"}), 400

    data = request.get_json(silent=True) or {}
    enabled = bool(data.get('automationEnabled', False))
    inbox_storage.update_automation_mode(inbox.id, enabled)

    processed = 0
    if enabled:
        # Refresh the inbox to get updated automation_mode, then process the queue
        fresh = inbox_storage.get_inbox(inbox.id)
        rules = rules_storage.get_rules_for_inbox(inbox.id)
        pending = queue_storage.get_pending(inbox.id)
        for row in pending:
            email_id = row['message_id']
            try:
                raw_msg = o365.fetch_message_safely(fresh, email_id)
                if raw_msg is None:
                    queue_storage.remove_from_queue(email_id)
                    continue
                normalized_msg = _build_normalized_from_row(row)
                classification_result = _classification_from_dict(row.get('classification') or {})
                plan = router.decide(classification_result, rules, fresh, normalized_msg)
                pipeline.execute_plan(plan, fresh, raw_msg)
                queue_storage.remove_from_queue(email_id)
                audit_storage.log_event(
                    inbox_id=fresh.id,
                    email_id=email_id,
                    action="auto_processed_on_toggle",
                    actor=session.get('user_email', 'unknown'),
                    comment=plan.tag,
                )
                processed += 1
            except Exception as e:
                print(f"process on toggle error for {email_id}: {e}")

    return jsonify({"status": "success", "automationEnabled": enabled, "processed": processed})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_current_inbox():
    """Return the inbox specified in ?inbox_id=... or the first accessible one for this user."""
    accessible = _accessible_inboxes()
    accessible_ids = {ib.id for ib in accessible}
    requested = request.args.get('inbox_id') or (request.get_json(silent=True) or {}).get('inbox_id')
    if requested:
        try:
            req_id = int(requested)
            if req_id in accessible_ids:
                return inbox_storage.get_inbox(req_id)
        except Exception:
            pass
    return accessible[0] if accessible else None


def _build_normalized_from_row(row):
    """Reconstruct a NormalizedMessage from a pending_queue row."""
    from models.NormalizedMessage import NormalizedMessage
    return NormalizedMessage(
        message_id=row['message_id'],
        sender=row.get('sender', ''),
        subject=row.get('subject_email', ''),
        body=row.get('body_email', ''),
        received_at=row.get('received_at'),
        conversation_id='',
        thread_messages=[],
        existing_tags=[],
    )


def _classification_from_dict(d):
    """Reconstruct a ClassificationResult from the stored JSONB dict."""
    from models.ClassificationResult import ClassificationResult
    return ClassificationResult(
        categories=d.get('categories', []),
        recipients=d.get('recipients', []),
        needs_personal_reply=d.get('needs_personal_reply', False),
        escalation_reason=d.get('escalation_reason', ''),
        name_sender=d.get('name_sender'),
        amount_money_detected=d.get('amount_detected'),
    )
