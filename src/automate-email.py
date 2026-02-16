from O365 import Account, FileSystemTokenBackend
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
import os, time, openai, json
from openai import OpenAI
import textwrap
import re
import pytz
from bs4 import BeautifulSoup
from flask import Flask, jsonify, send_from_directory, request, session, render_template, redirect, url_for
from flask_cors import CORS
import threading
import hashlib, hmac


# Load default .env from CWD, then also load src/.env for robustness
load_dotenv()
try:
    _here = os.path.dirname(os.path.abspath(__file__))
    load_dotenv(os.path.join(_here, '.env'), override=False)
except Exception:
    pass

### CONSTANTS

START_TIME = datetime.now(timezone.utc) 
# Start of current day in America/Chicago (converted to UTC)
CENTRAL_TZ = pytz.timezone('America/Chicago')
START_OF_TODAY = datetime.now(CENTRAL_TZ).replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)
# Process window start: beginning of the day two days ago in Central Time
# Backfill window: configurable via BACKFILL_DAYS (default 2)
BACKFILL_DAYS = int(os.getenv('BACKFILL_DAYS', '2'))
BACKFILL_MAX_PAGES = int(os.getenv('BACKFILL_MAX_PAGES', '20'))
PROCESS_SINCE = (datetime.now(CENTRAL_TZ)
                 .replace(hour=0, minute=0, second=0, microsecond=0)
                 - timedelta(days=BACKFILL_DAYS))
PROCESS_SINCE = PROCESS_SINCE.astimezone(timezone.utc)
# Persist tokens next to this script to avoid CWD confusion
TOKEN_DIR = os.path.dirname(os.path.abspath(__file__))
# Re-auth interval (minutes) to proactively refresh tokens
AUTH_REFRESH_MIN = int(os.getenv('AUTH_REFRESH_MIN', '50'))
last_auth_time = datetime.now(timezone.utc)
processed_messages = set()

def load_processed_messages():
    """Load processed messages from file to prevent reprocessing on restart"""
    try:
        with open('processed_messages.txt', 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()

def save_processed_messages():
    """Save processed messages to file"""
    try:
        with open('processed_messages.txt', 'w') as f:
            for msg_id in processed_messages:
                f.write(f"{msg_id}\n")
    except Exception as e:
        print(f"⚠️ Could not save processed messages: {e}")

 

# Load processed messages at startup
processed_messages = load_processed_messages()
print(f"📚 Loaded {len(processed_messages)} processed messages from previous runs")

CLIENT_ID = os.getenv("O365_CLIENT_ID")
CLIENT_SECRET = os.getenv("O365_CLIENT_SECRET")
TENANT_ID = os.getenv("O365_TENANT_ID")
REPLY_ID_TAG = "Pair_Reply_Reference_ID"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
EMAIL_TO_WATCH = os.getenv("EMAIL_TO_WATCH")
REVIEW_NOTIFY_EMAIL = os.getenv("REVIEW_NOTIFY_EMAIL", "mariam.ahmad@pairsys.ai")


EMAILS_TO_FORWARD = [
    'Mujahid.rasul@mlfa.org',
    'Syeda.sadiqa@mlfa.org',
    'Arshia.ali.khan@mlfa.org',
    'Maria.laura@mlfa.org',
    'info@mlfa.org',
    'aisha.ukiu@mlfa.org',
    'shawn@strategichradvisory.com',
    'mediarequests@mlfa.org',
    'maryam.libdi@mlfa.org'
]
NONREAD_CATEGORIES = {"marketing"}  # Keep these unread
SKIP_CATEGORIES = {'spam', 'cold_outreach', 'irrelevant_other'}

# Exact email addresses to silently skip processing (lowercase)
BLOCKED_SENDERS = [
    'abesammour@yahoo.com',
    'info@mlfa.org',
]
SKIP_SENDER_RECIPIENT_PAIRS = [
    ("info@mlfa.org", "mariam.ahmad@pairsys.ai"),
]

HUMAN_CHECK = True  # Enable human check for approval hub
USE_THREAD_CONTEXT = os.getenv('USE_THREAD_CONTEXT', 'true').strip().lower() == 'true'  # Include thread context in GPT
DEBUG_CLASSIFY_PROMPT = os.getenv('DEBUG_CLASSIFY_PROMPT', 'false').strip().lower() == 'true'

# Storage for multiple pending emails
pending_emails = {}  # Dictionary to store multiple emails by ID
current_email_id = None  # Track which email is currently being shown

# Flask app for approval hub
app = Flask(__name__, static_folder='.', template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', 'mlfa-email-hub-2024')  # Change this in production
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').strip().lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
allowed_origins = os.getenv('ALLOWED_ORIGINS', '').strip()
if allowed_origins:
    origins = [o.strip() for o in allowed_origins.split(',') if o.strip()]
    CORS(app, supports_credentials=True, origins=origins)
else:
    CORS(app, supports_credentials=True)

# Simple password (provided via ADMIN_PASSWORD_HASH in environment)
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH')
if not ADMIN_PASSWORD_HASH:
    raise RuntimeError('ADMIN_PASSWORD_HASH environment variable must be set for the approval hub.')

def verify_password(plain_password: str) -> bool:
    """Verify the provided password against ADMIN_PASSWORD_HASH using hashlib (SHA-256).
    Supports two formats for ADMIN_PASSWORD_HASH:
    - "sha256:<hex>"
    - "<64-hex>" (bare SHA-256 digest)
    """
    stored = (ADMIN_PASSWORD_HASH or '').strip()
    try:
        # sha256:<hex> format
        if stored.lower().startswith('sha256:'):
            hexhash = stored.split(':', 1)[1].strip()
            calc = hashlib.sha256(plain_password.encode('utf-8')).hexdigest()
            return hmac.compare_digest(calc, hexhash.lower())

        # bare 64-hex (assume sha256)
        if re.fullmatch(r'[A-Fa-f0-9]{64}', stored):
            calc = hashlib.sha256(plain_password.encode('utf-8')).hexdigest()
            return hmac.compare_digest(calc, stored.lower())

        # Unknown format
        print('⚠️ ADMIN_PASSWORD_HASH must be sha256:<hex> or a 64-hex SHA-256 digest')
        return False
    except Exception as e:
        print(f"⚠️ Password verification error: {e}")
        return False

def login_required(f):
    def decorated_function(*args, **kwargs):
        logged_in = session.get('logged_in')
        print(f"🔍 Checking auth for {request.path}: logged_in={logged_in}, session={dict(session)}")
        
        if not logged_in:
            if request.path.startswith('/api/'):
                # For API calls, return JSON error instead of redirect
                print(f"❌ API call denied - not logged in")
                return jsonify({"error": "Authentication required"}), 401
            print(f"❌ Redirecting to login")
            return redirect(url_for('login'))
        
        print(f"✅ Authentication passed")
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function




###CONNECTING


def require_env(var_name: str, value: str):
    if not value:
        raise RuntimeError(f"Missing required environment variable: {var_name}")

require_env('O365_CLIENT_ID', CLIENT_ID)
require_env('O365_CLIENT_SECRET', CLIENT_SECRET)
require_env('O365_TENANT_ID', TENANT_ID)
require_env('EMAIL_TO_WATCH', EMAIL_TO_WATCH)
require_env('OPENAI_API_KEY', OPENAI_API_KEY)

openai.api_key = OPENAI_API_KEY
# New-style OpenAI client (openai==1.x)
openai_client = OpenAI(api_key=OPENAI_API_KEY)
credentials = (CLIENT_ID, CLIENT_SECRET)
account = Account(credentials, auth_flow_type="credentials", tenant_id=TENANT_ID)

if not account.is_authenticated:
    account.authenticate()

def reinitialize_account():
    """Rebuild the account connection and mailbox folders (for stale tokens)."""
    global account, mailbox, inbox_folder, junk_folder, last_auth_time
    try:
        account = Account((CLIENT_ID, CLIENT_SECRET), auth_flow_type="credentials", tenant_id=TENANT_ID)
        account.authenticate()
        mailbox = account.mailbox(resource=EMAIL_TO_WATCH)
        inbox_folder = mailbox.inbox_folder()
        junk_folder = mailbox.junk_folder()
        last_auth_time = datetime.now(timezone.utc)
        print("🔐 Reinitialized account and refreshed tokens.")
    except Exception as e:
        print(f"❌ Failed to reinitialize account: {e}")

def ensure_account_fresh(force: bool = False):
    """Ensure the auth token is refreshed proactively every AUTH_REFRESH_MIN minutes."""
    global last_auth_time
    now = datetime.now(timezone.utc)
    age_min = (now - last_auth_time).total_seconds() / 60.0
    if force or age_min >= AUTH_REFRESH_MIN:
        print(f"⏳ Auth age {age_min:.1f}m >= {AUTH_REFRESH_MIN}m; refreshing…")
        reinitialize_account()

mailbox = account.mailbox(resource=EMAIL_TO_WATCH)
inbox_folder = mailbox.inbox_folder()
junk_folder = mailbox.junk_folder()


def _to_graph_utc(dt: datetime) -> str:
    try:
        aware = dt.astimezone(timezone.utc)
    except Exception:
        aware = datetime.now(timezone.utc)
    return aware.strftime('%Y-%m-%dT%H:%M:%SZ')


def backfill_unread_since(folder_obj, folder_name: str, since_dt: datetime, max_pages: int = 6) -> int:
    """Fetch and process unread messages since a given datetime (UTC).
    Returns number of messages processed. This complements delta by catching
    older-but-unread emails that haven’t produced recent delta signals.
    """
    try:
        con = account.con
        base = f"https://graph.microsoft.com/v1.0/users/{EMAIL_TO_WATCH}/mailFolders/{folder_name}/messages"
        select = "$select=id,conversationId,isRead,receivedDateTime,from,sender,subject,categories"
        since_iso = _to_graph_utc(since_dt)
        # Include both read and unread; we will skip ones already tagged/processed
        filt = f"receivedDateTime ge {since_iso}".replace(' ', '%20')
        order = "$orderby=receivedDateTime%20asc"
        top = "$top=50"
        url = f"{base}?{select}&$filter={filt}&{order}&{top}"

        count = 0
        pages = 0
        while url and pages < max_pages:
            pages += 1
            resp = con.get(url)
            if not resp or getattr(resp, 'status_code', 0) // 100 != 2:
                try:
                    sc = getattr(resp, 'status_code', None)
                    bt = ''
                    try:
                        bt = resp.text or ''
                    except Exception:
                        bt = ''
                    print(f"⚠️ Backfill HTTP error for {folder_name}: status={sc} body_len={len(bt)}")
                except Exception:
                    pass
                break
            data = resp.json() or {}
            if not isinstance(data, dict):
                try:
                    data = json.loads(data) if isinstance(data, str) else {}
                except Exception:
                    data = {}
            vals = data.get('value', []) if isinstance(data, dict) else []
            if isinstance(vals, dict):
                vals = [vals]
            if isinstance(vals, str):
                try:
                    parsed_vals = json.loads(vals)
                    vals = parsed_vals if isinstance(parsed_vals, list) else []
                except Exception:
                    vals = []

            for it in vals:
                try:
                    if not isinstance(it, dict):
                        continue
                    mid = it.get('id')
                    if not mid:
                        continue
                    msg = folder_obj.get_message(object_id=mid)
                    if not msg:
                        continue
                    dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
                    if dedup_key in processed_messages:
                        continue
                    try:
                        msg.refresh()
                    except Exception:
                        pass
                    # Skip if already processed via categories
                    if any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                        processed_messages.add(dedup_key)
                        continue
                    # Skip if older than PROCESS_SINCE safety window
                    try:
                        if getattr(msg, 'received', None) and msg.received < PROCESS_SINCE:
                            processed_messages.add(dedup_key)
                            continue
                    except Exception:
                        pass
                    # Internal reply detection
                    sender_addr = _extract_sender_address(msg).lower()
                    sender_is_staff = sender_addr in [e.lower() for e in EMAILS_TO_FORWARD]
                    is_automated_reply = bool(re.search(fr"{REPLY_ID_TAG}\s*([^\s<]+)", msg.body or "", flags=re.I|re.S))
                    if sender_is_staff and is_automated_reply and not any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                        handle_internal_reply(msg)
                        processed_messages.add(dedup_key)
                        count += 1
                        continue

                    # Skip internal MLFA senders (e.g., Sent Items picked up by mailbox-wide scan)
                    if _is_internal_sender(sender_addr):
                        try:
                            tag_email(msg, ['internal_outgoing'], replyTag=False)
                            mark_as_read(msg)
                        except Exception:
                            pass
                        processed_messages.add(dedup_key)
                        count += 1
                        continue

                    # Skip internal MLFA senders
                    if _is_internal_sender(sender_addr):
                        try:
                            tag_email(msg, ['internal_outgoing'], replyTag=False)
                            mark_as_read(msg)
                        except Exception:
                            pass
                        processed_messages.add(dedup_key)
                        count += 1
                        continue

                    # Classification path (include read messages too if not already processed)
                    body_to_analyze = get_clean_message_text(msg)
                    if _should_skip_message(msg):
                        processed_messages.add(dedup_key)
                        continue

                    print(f"\nBACKFILL: [{folder_name}] {msg.received.strftime('%Y-%m-%d %H:%M') if getattr(msg, 'received', None) else ''} | "
                          f"{msg.sender.address if msg.sender else 'UNKNOWN'} | {msg.subject}")

                    # Optional thread context
                    if USE_THREAD_CONTEXT and getattr(msg, 'conversation_id', None):
                        try:
                            thread_ctx = build_thread_context(folder_obj, msg)
                            if not thread_ctx:
                                thread_ctx = build_thread_context_across_mailbox(msg)
                        except Exception:
                            thread_ctx = ""
                    else:
                        thread_ctx = ""

                    composite_body = (
                        ("These are earlier emails from the same thread. Use them as context to make the right routing decision.\n\n"
                         + f"Thread context (older messages, oldest→newest):\n{thread_ctx}\n\n" if thread_ctx else "")
                        + f"Latest message body:\n{body_to_analyze}"
                    )

                    preexisting_legal = _has_preexisting_legal_tag(msg)
                    preexisting_jail_mail = _has_preexisting_jail_mail_tag(msg)
                    result = classify_email(msg.subject, composite_body)
                    try:
                        result["is_legal_preexisting"] = preexisting_legal
                        result["is_jail_mail_preexisting"] = preexisting_jail_mail
                    except Exception:
                        pass

                    if HUMAN_CHECK:
                        print(json.dumps(result, indent=2))
                        email_id = msg.object_id
                        if email_id not in pending_emails:
                            pending_emails[email_id] = {
                                "subject": msg.subject,
                                "body": body_to_analyze,
                                "classification": result if isinstance(result, dict) else {},
                                "sender": msg.sender.address if msg.sender else '',
                                "received": msg.received.strftime('%Y-%m-%d %H:%M') if getattr(msg, 'received', None) else '',
                                "message_obj": msg
                            }
                            print(f"📧 Email stored for approval: {msg.subject}")
                    else:
                        print(json.dumps(result, indent=2))
                        handle_new_email(msg, result if isinstance(result, dict) else {})

                    processed_messages.add(dedup_key)
                    count += 1
                except Exception as inner_e:
                    try:
                        print(f"⚠️ Backfill error for {folder_name} item: {inner_e}")
                    except Exception:
                        pass

            url = data.get('@odata.nextLink') if isinstance(data, dict) else None

        if count:
            print(f"✅ Backfill processed {count} message(s) from {folder_name} since {since_iso}")
            return count

        # Fallback via SDK query if HTTP path found nothing
        try:
            print(f"🔎 Backfill fallback via SDK for {folder_name} since {since_iso}")
            q = folder_obj.new_query().select([
                'id','conversationId','internetMessageId','isRead','receivedDateTime','from','sender','subject','categories','uniqueBody','body'
            ])
            # Fetch a window and filter locally
            items = list(folder_obj.get_messages(query=q, order_by='receivedDateTime asc', limit=500))
            for msg in items:
                try:
                    ts = getattr(msg, 'received', None) or getattr(msg, 'created', None)
                    if ts and ts < since_dt:
                        continue
                    dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
                    if dedup_key in processed_messages:
                        continue
                    try:
                        msg.refresh()
                    except Exception:
                        pass
                    if any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                        processed_messages.add(dedup_key)
                        continue

                    sender_addr = _extract_sender_address(msg).lower()
                    sender_is_staff = sender_addr in [e.lower() for e in EMAILS_TO_FORWARD]
                    is_automated_reply = bool(re.search(fr"{REPLY_ID_TAG}\s*([^\s<]+)", msg.body or "", flags=re.I|re.S))
                    if sender_is_staff and is_automated_reply and not any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                        handle_internal_reply(msg)
                        processed_messages.add(dedup_key)
                        count += 1
                        continue

                    body_to_analyze = get_clean_message_text(msg)
                    if _should_skip_message(msg):
                        processed_messages.add(dedup_key)
                        continue

                    print(f"\nBACKFILL(SDK): [{folder_name}] {msg.received.strftime('%Y-%m-%d %H:%M') if getattr(msg, 'received', None) else ''} | "
                          f"{msg.sender.address if msg.sender else 'UNKNOWN'} | {msg.subject}")

                    thread_ctx = ""
                    if USE_THREAD_CONTEXT and getattr(msg, 'conversation_id', None):
                        try:
                            thread_ctx = build_thread_context(folder_obj, msg)
                            if not thread_ctx:
                                thread_ctx = build_thread_context_across_mailbox(msg)
                        except Exception:
                            thread_ctx = ""

                    composite_body = (
                        ("These are earlier emails from the same thread. Use them as context to make the right routing decision.\n\n"
                         + f"Thread context (older messages, oldest→newest):\n{thread_ctx}\n\n" if thread_ctx else "")
                        + f"Latest message body:\n{body_to_analyze}"
                    )

                    preexisting_legal = _has_preexisting_legal_tag(msg)
                    preexisting_jail_mail = _has_preexisting_jail_mail_tag(msg)
                    result = classify_email(msg.subject, composite_body)
                    try:
                        result["is_legal_preexisting"] = preexisting_legal
                        result["is_jail_mail_preexisting"] = preexisting_jail_mail
                    except Exception:
                        pass

                    if HUMAN_CHECK:
                        print(json.dumps(result, indent=2))
                        email_id = msg.object_id
                        if email_id not in pending_emails:
                            pending_emails[email_id] = {
                                "subject": msg.subject,
                                "body": body_to_analyze,
                                "classification": result if isinstance(result, dict) else {},
                                "sender": msg.sender.address if msg.sender else '',
                                "received": msg.received.strftime('%Y-%m-%d %H:%M') if getattr(msg, 'received', None) else '',
                                "message_obj": msg
                            }
                            print(f"📧 Email stored for approval: {msg.subject}")
                    else:
                        print(json.dumps(result, indent=2))
                        handle_new_email(msg, result if isinstance(result, dict) else {})

                    processed_messages.add(dedup_key)
                    count += 1
                except Exception as inner_e2:
                    try:
                        print(f"⚠️ Backfill SDK error for {folder_name} item: {inner_e2}")
                    except Exception:
                        pass

            if count:
                print(f"✅ Backfill(SDK) processed {count} message(s) from {folder_name} since {since_iso}")
            else:
                print(f"ℹ️  Backfill(SDK) still found no messages in {folder_name} since {since_iso}")
            return count
        except Exception as e2:
            print(f"⚠️ Backfill SDK path error for {folder_name}: {e2}")
            return count
    except Exception as e:
        print(f"⚠️ Backfill error for {folder_name}: {e}")
        return 0


def backfill_mailbox_since(since_dt: datetime, max_pages: int = 12) -> int:
    """Mailbox-wide backfill across all folders. Fetches messages received since
    since_dt and processes those not already PAIRActioned/processed.
    """
    try:
        con = account.con
        base = f"https://graph.microsoft.com/v1.0/users/{EMAIL_TO_WATCH}/messages"
        select = "$select=id,conversationId,isRead,receivedDateTime,from,sender,subject,categories,parentFolderId"
        since_iso = _to_graph_utc(since_dt)
        filt = f"receivedDateTime ge {since_iso}".replace(' ', '%20')
        order = "$orderby=receivedDateTime%20asc"
        top = "$top=50"
        url = f"{base}?{select}&$filter={filt}&{order}&{top}"

        count = 0
        pages = 0
        while url and pages < max_pages:
            pages += 1
            resp = con.get(url)
            if not resp or getattr(resp, 'status_code', 0) // 100 != 2:
                try:
                    sc = getattr(resp, 'status_code', None)
                    bt = ''
                    try:
                        bt = resp.text or ''
                    except Exception:
                        bt = ''
                    print(f"⚠️ Backfill(all) HTTP error: status={sc} body_len={len(bt)}")
                except Exception:
                    pass
                break
            data = resp.json() or {}
            if not isinstance(data, dict):
                try:
                    data = json.loads(data) if isinstance(data, str) else {}
                except Exception:
                    data = {}
            vals = data.get('value', []) if isinstance(data, dict) else []
            if isinstance(vals, dict):
                vals = [vals]
            if isinstance(vals, str):
                try:
                    parsed_vals = json.loads(vals)
                    vals = parsed_vals if isinstance(parsed_vals, list) else []
                except Exception:
                    vals = []

            for it in vals:
                try:
                    if not isinstance(it, dict):
                        continue
                    mid = it.get('id')
                    if not mid:
                        continue
                    msg = mailbox.get_message(object_id=mid)
                    if not msg:
                        continue
                    dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
                    if dedup_key in processed_messages:
                        continue
                    try:
                        msg.refresh()
                    except Exception:
                        pass
                    if any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                        processed_messages.add(dedup_key)
                        continue

                    # Skip very old beyond safety window
                    try:
                        if getattr(msg, 'received', None) and msg.received < PROCESS_SINCE:
                            processed_messages.add(dedup_key)
                            continue
                    except Exception:
                        pass

                    sender_addr = _extract_sender_address(msg).lower()
                    sender_is_staff = sender_addr in [e.lower() for e in EMAILS_TO_FORWARD]
                    is_automated_reply = bool(re.search(fr"{REPLY_ID_TAG}\s*([^\s<]+)", msg.body or "", flags=re.I|re.S))
                    if sender_is_staff and is_automated_reply and not any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                        handle_internal_reply(msg)
                        processed_messages.add(dedup_key)
                        count += 1
                        continue

                    body_to_analyze = get_clean_message_text(msg)
                    if _should_skip_message(msg):
                        processed_messages.add(dedup_key)
                        continue

                    print(f"\nBACKFILL(ALL): [{getattr(msg, 'conversation_id', '')}] {msg.received.strftime('%Y-%m-%d %H:%M') if getattr(msg, 'received', None) else ''} | "
                          f"{msg.sender.address if msg.sender else 'UNKNOWN'} | {msg.subject}")

                    thread_ctx = ""
                    if USE_THREAD_CONTEXT and getattr(msg, 'conversation_id', None):
                        try:
                            thread_ctx = build_thread_context_across_mailbox(msg)
                        except Exception:
                            thread_ctx = ""

                    composite_body = (
                        ("These are earlier emails from the same thread. Use them as context to make the right routing decision.\n\n"
                         + f"Thread context (older messages, oldest→newest):\n{thread_ctx}\n\n" if thread_ctx else "")
                        + f"Latest message body:\n{body_to_analyze}"
                    )

                    preexisting_legal = _has_preexisting_legal_tag(msg)
                    preexisting_jail_mail = _has_preexisting_jail_mail_tag(msg)
                    result = classify_email(msg.subject, composite_body)
                    try:
                        result["is_legal_preexisting"] = preexisting_legal
                        result["is_jail_mail_preexisting"] = preexisting_jail_mail
                    except Exception:
                        pass

                    if HUMAN_CHECK:
                        print(json.dumps(result, indent=2))
                        email_id = msg.object_id
                        if email_id not in pending_emails:
                            pending_emails[email_id] = {
                                "subject": msg.subject,
                                "body": body_to_analyze,
                                "classification": result if isinstance(result, dict) else {},
                                "sender": msg.sender.address if msg.sender else '',
                                "received": msg.received.strftime('%Y-%m-%d %H:%M') if getattr(msg, 'received', None) else '',
                                "message_obj": msg
                            }
                            print(f"📧 Email stored for approval: {msg.subject}")
                    else:
                        print(json.dumps(result, indent=2))
                        handle_new_email(msg, result if isinstance(result, dict) else {})

                    processed_messages.add(dedup_key)
                    count += 1
                except Exception as inner_e:
                    try:
                        print(f"⚠️ Backfill(all) error for item: {inner_e}")
                    except Exception:
                        pass

            url = data.get('@odata.nextLink') if isinstance(data, dict) else None

        if count:
            print(f"✅ Backfill(all) processed {count} message(s) since {since_iso}")
        else:
            print(f"ℹ️  Backfill(all) found no messages since {since_iso}")
        return count
    except Exception as e:
        print(f"⚠️ Backfill(all) error: {e}")
        return 0




def read_token(filename):
    full_path = filename if os.path.isabs(filename) else os.path.join(TOKEN_DIR, filename)
    if os.path.exists(full_path):
        with open(full_path, "r") as f:
            return f.read().strip()
    return None

def load_last_delta():
    inbox_token = read_token("delta_token_inbox.txt")
    junk_token = read_token("delta_token_junk.txt")
    return inbox_token, junk_token


def save_last_delta(inbox_token, junk_token):
    inbox_path = os.path.join(TOKEN_DIR, "delta_token_inbox.txt")
    junk_path = os.path.join(TOKEN_DIR, "delta_token_junk.txt")
    # Persist or clear inbox token
    if inbox_token:
        open(inbox_path, "w").write(inbox_token)
        try:
            print(f"Δ Saved Inbox delta token to {inbox_path} ({len(inbox_token)} chars)")
        except Exception:
            pass
    else:
        try:
            os.remove(inbox_path)
        except FileNotFoundError:
            pass
    # Persist or clear junk token
    if junk_token:
        open(junk_path, "w").write(junk_token)
        try:
            print(f"Δ Saved Junk delta token to {junk_path} ({len(junk_token)} chars)")
        except Exception:
            pass
    else:
        try:
            os.remove(junk_path)
        except FileNotFoundError:
            pass


#Passes the subject and body of the email to chat gpt, which figures out how to handle the email. 
#Chat-GPT nicely returns the information in json format. 

#Args:
#subject (str): The subject of the email. 
#body (str): The body of the email. 

#Returns:
#A json script that includes the category of the email, who it needs to be forwarded to, and why. 

def classify_email(subject, body):
    prompt = f"""You are an email routing assistant for MLFA (Muslim Legal Fund of America), a nonprofit organization focused on legal advocacy for Muslims in the United States.

    Your job is to classify incoming emails based on their **content, sender intent, and relevance** to MLFA’s mission. Do not rely on keywords alone. Use the routing rules below to assign one or more categories and determine appropriate recipients if applicable.
    Additionally, **identify the sender’s name** when possible and include it as `name_sender` in the JSON. Prefer the “From” display name; if unavailable or generic, use a clear sign-off/signature in the body. If you cannot determine the name confidently, set `name_sender` to null.

    When prior messages or quoted threads are included, the model must carefully review them to determine the relationship and relevance of the latest email. The classification should always be based on the most recent sender’s intent, but informed by the context of the earlier conversation (e.g., to distinguish between legitimate follow-ups vs. new cold outreach or thank-you closings).
   
    IMPORTANT TAGGING CONSTRAINT:
    ⚠️ **"jail_mail" is a SPECIALIZED SUBSET of legal-related communication, but it is a DISTINCT AND EXCLUSIVE ROUTING CATEGORY.**
    - While jail mail may involve legal issues, incarceration, or court matters, it must be routed separately.
    - An email **CANNOT** be tagged as both `"legal"` and `"jail_mail"`.
    - If an email meets **any** criteria for `"jail_mail"`, it **MUST be classified ONLY as `"jail_mail"` and NOT as `"legal"`**.
    - The `"legal"` category is reserved strictly for **non-incarcerated individuals or third parties explicitly requesting legal help**.
    - You must choose **one or the other**, never both.

    HUMAN-STYLE REPLY ESCALATION (IMPORTANT):
    Flag emails that should NOT get a generic auto-reply because they are personal/referral-like or contain substantial case detail.
    Set `needs_personal_reply=true` if ANY of these are present:
    - **Referral signals:** mentions of being referred by a person/org (e.g., imam, attorney, community leader, “X told me to contact you,” CC’ing a referrer).
    - **Personal narrative with specifics:** detailed timeline, names, dates, locations, docket/case numbers, court filings, detention/deportation details, attorney names, or attached evidence.
    - **Clearly individualized appeal:** tone reads as one-to-one help-seeking rather than a form blast.
    - **Brevity & Generic Content safeguard:** If the email is *short, vague, and generic* (e.g., “I need legal help” or “Please assist”), and does **not** include referral language or specific personal details, then set `needs_personal_reply=false` even if it asks for help.

    If none of the above apply, set `needs_personal_reply=false`.

    ROUTING RULES & RECIPIENTS:
    
    - **JAIL MAIL. Categorize the email as `"jail_mail"` if ANY of the following are true:
    -The email is generated by CorrLinks or references CorrLinks.
    -The email states that a person is in federal custody, prison, jail, or incarcerated.
    -The email is a system-generated notification about an inmate requesting to add a contact.
    -The email indicates electronic messaging with a person in custody.
     Note: Jail mail may are legal emails but with the specifications above. For routing purposes it is **always classified ONLY as `"jail_mail"` and never as `"legal"`.

    JAIL_MAIL CONTEXT OVERRIDE (CRITICAL)

    The "jail_mail" classification must be determined ONLY from the current email message.
    Do NOT use prior messages, quoted threads, or earlier classifications to infer or maintain a "jail_mail" tag.
    Classify as "jail_mail" ONLY IF the current message:
    - explicitly references incarceration, prison, jail, federal custody, CorrLinks, or inmate messaging, AND
    - explicitly asks MLFA for help, legal assistance, representation, or intervention
    OR is a system-generated inmate/jail communication.
    If the current message does NOT meet the above conditions, it must NOT be classified as "jail_mail", even if earlier emails in the thread were jail_mail.
    Closing messages, thank-yous, acknowledgments, or availability statements in a jail-related thread should be in the general_communication.

    -**Legal inquiries** → If someone is explicitly **ASKING for legal help, representation, or legal assistance**, categorize as `"legal". Mentioning the word legal does not equate to asking for legal help.`.
    These include emails where the sender is SEEKING support with a case, asking for a lawyer, describing a legal issue they need help with, or inquiring about eligibility for MLFA assistance.
        **Do NOT classify as "legal"** if:
        - The email is **only expressing gratitude** or appreciation for prior help on a legal case.
        - The sender mentions a legal case merely in **passing** (e.g., “Thank you for helping with my legal case” or “Appreciate your support during my case”).
        - The message contains **no new request for help or representation**.
    These users should be referred to MLFA’s "Apply for Help" form (no forwarding needed) only when they are *REQUESTING* legal help. Legal categorization is only if an email is ASKING for legal help, not emails regarding legal topics generally.
   


    --- ADDITIONAL CLARIFICATIONS ---

    ⚠️ DO NOT classify as "legal" if the email is a **legal notice**, **copyright or DMCA complaint**, **policy violation alert**, or **cease and desist letter** directed *at* MLFA.
    These messages are fundamentally different from help requests — they are **enforcement or warning communications**, not assistance-seeking emails.

    Common examples that should NOT be tagged as "legal":
    - Copyright infringement notices (e.g., from law firms or record labels).
    - DMCA or IP violation notifications.
    - Cease-and-desist or trademark enforcement emails.
    - Terms-of-service or content removal warnings from platforms like Meta, YouTube, or Google.
    - Legal complaints, subpoenas, or compliance correspondence **sent to** MLFA (not *from* someone seeking MLFA’s help).

    Such messages must **never** trigger a `"legal"` classification or auto-response.

    Instead, categorize them under a new label:
    - **Violation or Legal Notice emails** → Categorize as `"violation_notice"` if the sender is **not requesting help**, but is **informing or warning MLFA** about an alleged violation or legal issue.
        Examples include:
        - “We represent [Company] regarding unauthorized use of copyrighted material…”
        - “Your post infringes on our intellectual property rights.”
        - “Notice of policy breach or DMCA claim.”

        These emails are not client or community outreach — they are compliance or legal enforcement notices.
        Forward all `"violation_notice"` emails to:
        Arshia.ali.khan@mlfa.org, Maria.laura@mlfa.org



    Remember:
    - “Legal” = someone asking MLFA for help. 
    - “Violation notice” = someone warning MLFA about a potential violation.

    - **Donor-related inquiries** → Categorize as `"donor"` only if the **sender is a donor** or is asking about a **specific donation**, such as issues with payment, receipts, or donation follow-ups. Forward to:
    Mujahid.rasul@mlfa.org, Syeda.sadiqa@mlfa.org
    IMPORTANT DISTINCTION:
    If the sender is asking MLFA FOR money, funding, sponsorship, the email must be categorized as `"sponsorship"`, NOT `"donor"`, regardless of donor-related keywords used.
    If an email could otherwise appear donor-related but the intent is requesting financial support from MLFA, override `"donor"` and classify as `"financial_aid"`.

    - **Sponsorship requests** → If someone is **requesting sponsorship, fundraiser, from MLFA**, categorize as `"sponsorship"`. 

    - **Financial_Aid** -> if someone is requesting ANY sort of financial support, it is NOT sponsorship, rather it is categorized as `"financial_aid"`.


    - **Fellowship inquiries** → If someone is **applying for, asking about, or offering a fellowship** (legal, advocacy, or nonprofit-focused), categorize as `"fellowship"`. Forward to:
    aisha.ukiu@mlfa.org

    - **Organizational questions** → If the sender is asking about **MLFA's internal operations**, such as leadership, partnerships, collaboration, or continuing an ongoing, **legitimate and relevant exchange** with MLFA, categorize as `"organizational"`.
        This includes **genuine follow-up emails** that relate to a prior valid conversation with MLFA (e.g., “Following up on my partnership proposal,” or “Checking in about our meeting last week”).=
        The model must use the **context provided** — including quoted or prior messages — to assess whether the follow-up continues a **legitimate and relevant** thread. This means that if prior emails are available (as part of the thread context), they must be analyzed to decide if the new message is a meaningful continuation or just noise.
        **Not all follow-ups qualify:**
            - If the previous thread or earlier messages were categorized as `"spam"`, `"cold_outreach"`, `"marketing"`, `"out_of_office"`, `"irrelevant_other"`, **or any test, placeholder, or nonsense content**, then a follow-up on that thread should **not** be marked as `"organizational"`.
            - In such cases, classify based on the *current message’s actual content or purpose* (e.g., `"irrelevant_other"` if still meaningless).
            - A message like “Just following up on my last email” **only counts as organizational** if the last email was legitimate and relevant to MLFA’s work.

        Forward to:
        Nobody/No recipients. 

    - **Volunteer inquiries** → If someone is **offering to volunteer** their time or skills to MLFA **or** is **asking about volunteering** (for themselves or on behalf of someone else), categorize as `"volunteer"`. Forward to:
    maryam.libdi@mlfa.org

    - **Job applications** → If someone is **applying for a paid job**, sending a resume, or asking about open employment positions, categorize as `"job_application"`. Forward to:
    shawn@strategichradvisory.com

    - **Internship applications** → If someone is **applying for an internship** (paid or unpaid), sending a resume for an internship program, or inquiring about internship opportunities, categorize as `"internship"`. Forward to:
    aisha.ukiu@mlfa.org

    - **Media inquiries** → If the sender is a **reporter or journalist asking for comments, interviews, or statements**, categorize as `"media"`. Forward to:
    mediarequests@mlfa.org

    - **Out-of-office / automatic replies** → If the email indicates the sender is away or unavailable — including automatic replies like "Automatic reply:", "Out of Office", "Auto-Reply", "OOO", "Away from office" or manual notes like "I'm out of the office until …", "I will have limited access …" — categorize as `"out_of_office"`. Do not forward. These should be moved to Trash.

    - **Microsoft Teams forwarded messages (delete)** → Categorize as `"delete_internal"` if the email is a forwarded or auto-generated message originating from Microsoft Teams.
    These emails are internal notification artifacts and provide no standalone communication value. They should be classified as `"delete_internal"` and deleted. They should not be forwarded, replied to, or categorized under any other label.

    - **Email marketing/sales** → If the sender is **offering a product, service, or software**, categorize as `"marketing"` only if:
    1) The offering is **relevant to MLFA’s nonprofit or legal work**, **and**
    2) The sender shows **clear contextual awareness** (e.g., refers to MLFA’s legal mission, Muslim families, or nonprofit context), **and**
    3) The product is **niche-specific**, such as legal case management, zakat compliance tools, intake systems for nonprofits, or Islamic legal software.
    Move to the "Sales emails" folder.
    **Do not treat generic, untargeted, or mass-promotional emails as marketing.**

    TRUSTED PARTNER RULE (EXPLICIT)

    The following organization is a TRUSTED MLFA PARTNER:
    - Pure Hands (also written as "PureHands", "Pure Hands, Inc.", or emails from domains including purehands.org or purehands.ccsend.com)

    For emails from this trusted partner:
    - The categories "cold_outreach", "spam", and "irrelevant_other" are NOT permitted.
    - Mass-email indicators (e.g., Constant Contact formatting, mailing lists, or the presence of "unsubscribe") must be ignored.

    Trusted partner status applies ONLY to the explicitly listed organization above.


    - **Spam** → Obvious scams, phishing, AI-generated nonsense, or malicious intent. Move to Junk.

    - **Statements / receipts / statements** → Categorize as `"statements"` if the email contains receipts, billing statements, proofs of purchase, or expense documentation.
    This explicitly includes:
    - Staples receipts. Anything from staples but be put in this category
    - SBA statements or SBA-related documentation
    Forward all `"statements"` emails to:
    Syeda.sadiqa@mlfa.org

    - **General communications** → Categorize as `"general_communication"` for legitimate, non-spam email threads or replies that do not fit any other defined category but are still relevant and meaningful to MLFA. This category exists to ensure valid conversations are not misclassified as `"irrelevant_other"`. Use `"general_communication"` when the email:
    -If it contains attachments or the words "please let me know if you receive this" that is likely a reply to an ongoing/existing conversation, even if it is sent independently and not as part of a thread. 
    - Does not meet the criteria for any other category, AND
    -It is a message to "Rachel" or "Rachel Smith" "Ms. Smith" (some form of that), or it says some form of "hi" but with a SPECIFIC NAME after it (just because it has an extra name though doesn't mean its automatically general communications). 
    - Is coherent, doesn't seem like cold outreach, but seems to be apart of some conversation, or serves a legitimate conversational or administrative purpose (e.g., clarifications, acknowledgments, coordination, brief responses, logistics). Do NOT use `"general_communication"` for spam, marketing, cold outreach, automated messages, test emails, or content with no meaningful purpose. If none of the above apply, classify as `"irrelevant_other"`.
       
    - **Cold outreach** → Any **unsolicited sales email** that lacks clear tailoring to MLFA's work. Categorize as `"cold_outreach"` if:
        - The sender shows **no meaningful awareness** of MLFA's mission
        - The offer is **broad, mass-marketed, or hype-driven**
        - The email uses commercial hooks like "Act now," "800% increase," "Only $99/month," or "Click here"
        Even if the topic sounds legal or nonprofit-adjacent, if it **feels generic**, classify it as cold outreach.
        **IMPORTANT: Do NOT classify follow-up emails as cold outreach** - if someone is following up on previous correspondence with MLFA (even if brief), classify as `"organizational"` instead.
        Mark as read; **do not** treat as marketing.
        Bulk content like PR updates, blog digests, or mass announcements not addressed to MLFA directly. Place in 
        If the email contains the word “UNSUBSCRIBE” anywhere in the body, it MUST be categorized as `"cold_outreach"` regardless of other content.There can be a few exceptions to that rule for example it might be from an organization that is asking for a donation/fundraising which would then be sponsorship. 
        EXCLUSIVITY RULE:
        If an email is classified as `"cold_outreach"`, it may NOT be assigned any additional categories.
        Cold outreach must always be the ONLY category.


    - **Irrelevant (other)** → Anything that doesn't match the above and is unrelated to MLFA’s mission — e.g., misdirected emails, general inquiries, or off-topic messages. Mark as read and ignore.

    IMPORTANT GUIDELINES:
    1. Focus on **relevance and specificity**, not just keywords. The more the sender understands MLFA, the more likely it is to be legitimate.
    2. If an email is a **niche legal tech offer clearly crafted for MLFA or Muslim nonprofits**, treat it as `"marketing"` — even if unsolicited.
    3. If the offer is **generic or clearly sent in bulk**, it’s `"cold_outreach"` — even if it references legal themes or Muslim communities.
    4. Never mark cold outreach or mass sales emails as `"marketing"`, even if they reference MLFA’s field.
    5. If someone is **offering legal services**, classify as `"organizational"` only if relevant and serious (not promotional).
    6. Emails can and should have **multiple categories** when appropriate (e.g., a donor asking to volunteer → `"donor"` and `"volunteer"`).
    7. Use `all_recipients` only for forwarded categories: `"donor"`, `"fellowship"`, `"volunteer"`, `"job_application"`, `"internship"`, `"media"`, `"statements"`.
    8. For `"legal"`, `"marketing"`, `"violation_notice"`,`"out_of_office"`, `"delete_internal"`, `"general_communication"`, `"jail_mail"`, `"organizational"` and all `"irrelevant"` types, leave `all_recipients` empty.

    PRIORITY & TIES:
    - If `"legal"` applies, **still include all other relevant categories** — `"legal"` is additive, never exclusive.
    - `"marketing"` vs `"cold_outreach"`: choose only one based on tailoring (see rules above).

    Return a JSON object with:
    - `categories`: array from ["legal","violation_notice","donor","sponsorship","fellowship","organizational","volunteer","job_application","internship","media","marketing","out_of_office","spam","cold_outreach","irrelevant_other", “statements”, “general_communication”, "delete_internal", "jail_mail", "financial_aid"]
    - `all_recipients`: list of MLFA email addresses (may be empty)
    - `needs_personal_reply`: boolean per the Escalation section
    - `reason`: dictionary mapping each category to a brief justification
    - `escalation_reason`: brief string explaining why `needs_personal_reply` is true (empty string if false)
    - `name_sender`: the sender’s name if confidently identified; otherwise null

    Subject: {subject}

    Body:
    {body}
    """

    try:
        # Use the 1.x client API
        response = openai_client.chat.completions.create(
            model="gpt-5.2",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        raw = (response.choices[0].message.content or "").strip()
        # Strip common markdown fences
        if raw.startswith("```json"):
            raw = raw[len("```json"):].strip()
        if raw.endswith("```"):
            raw = raw[:-3].strip()

        # Try strict JSON parse first
        try:
            parsed = json.loads(raw)
        except Exception:
            # Try to salvage JSON object from within a string
            try:
                start = raw.find('{')
                end = raw.rfind('}')
                if start != -1 and end != -1 and end > start:
                    parsed = json.loads(raw[start:end+1])
                else:
                    parsed = {}
            except Exception:
                parsed = {}

        # Ensure we always return a dict so downstream .get() calls are safe
        if isinstance(parsed, dict):
            return parsed
        # If model returned a list with a single dict, accept it
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            return parsed[0]
        # Fallback: wrap raw content so routes don't break
        return {"raw": raw}
    except Exception as e:
        print(f"Classification error: {e}")
        return {}


def build_thread_context(folder_obj, current_msg) -> str:
    """
    Build a chronological context from earlier messages in the same conversation.
    - Includes only messages in the same folder and conversation as current_msg
    - Excludes the current message and anything newer than it
    - No explicit count/size limits (SDK will paginate as needed)
    """
    try:
        conv_id = getattr(current_msg, 'conversation_id', None)
        if not conv_id:
            return ""

        q = (folder_obj.new_query()
             .on_attribute('conversationId').equals(conv_id)
             .select([
                 'id','conversationId','internetMessageId',
                 'isRead','receivedDateTime',
                 'from','sender','subject','categories','uniqueBody','body'
             ]))

        # Iterate all messages in the conversation in this folder
        items = list(folder_obj.get_messages(query=q))

        # Determine current timestamp for ordering filter
        try:
            cur_ts = getattr(current_msg, 'received', None) or getattr(current_msg, 'created', None)
        except Exception:
            cur_ts = None

        def is_older(m):
            if m.object_id == current_msg.object_id:
                return False
            ts = getattr(m, 'received', None) or getattr(m, 'created', None)
            if cur_ts and ts:
                return ts <= cur_ts
            return m.object_id != current_msg.object_id

        older = [m for m in items if is_older(m)]
        older.sort(key=lambda m: getattr(m, 'received', None) or getattr(m, 'created', None))

        # Build plain-text snippets oldest→newest
        snippets = []
        for m in older:
            try:
                m.refresh()
            except Exception:
                pass
            sender = ''
            try:
                sender = (m.sender.address or '').strip()
            except Exception:
                sender = ''
            ts_str = ''
            try:
                if getattr(m, 'received', None):
                    ts_str = m.received.strftime('%Y-%m-%d %H:%M')
            except Exception:
                ts_str = ''
            body_snip = get_clean_message_text(m)
            entry = f"[{ts_str} | {sender}] {m.subject or ''}\n{body_snip or ''}"
            snippets.append(entry.strip())

        if not snippets:
            return ""

        return "\n\n---\n\n".join(snippets)
    except Exception as e:
        try:
            print(f"⚠️ build_thread_context error: {e}")
        except Exception:
            pass
        return ""


    

def build_thread_context_across_mailbox(current_msg) -> str:
    """
    Cross-folder fallback: build chronological context from all folders
    for messages in the same conversation, excluding Deleted Items (Trash).
    No artificial limits are applied here beyond the built-in cleanup in
    get_clean_message_text.
    """
    try:
        conv_id = getattr(current_msg, 'conversation_id', None)
        if not conv_id:
            return ""

        # Determine the Deleted Items folder id to exclude
        try:
            deleted_folder = mailbox.deleted_folder()
            deleted_folder_id = getattr(deleted_folder, 'object_id', None)
        except Exception:
            deleted_folder_id = None

        con = account.con
        # Fetch all messages across mailbox matching this conversationId
        base = f"https://graph.microsoft.com/v1.0/users/{EMAIL_TO_WATCH}/messages"
        # Select parentFolderId so we can exclude Deleted Items
        select = (
            "$select=id,conversationId,receivedDateTime,parentFolderId,from,sender,subject&"
            f"$filter=conversationId eq '{conv_id}'&$top=50"
        )
        url = f"{base}?{select}"

        items = []
        safety = 0
        while url and safety < 100:
            safety += 1
            resp = con.get(url)
            if not resp or resp.status_code // 100 != 2:
                break
            data = resp.json() or {}
            if not isinstance(data, dict):
                try:
                    data = json.loads(data) if isinstance(data, str) else {}
                except Exception:
                    data = {}
            vals = data.get('value', []) if isinstance(data, dict) else []
            if isinstance(vals, dict):
                vals = [vals]
            if isinstance(vals, str):
                try:
                    parsed_vals = json.loads(vals)
                    vals = parsed_vals if isinstance(parsed_vals, list) else []
                except Exception:
                    vals = []
            for it in vals:
                if not isinstance(it, dict):
                    continue
                # Exclude items in Deleted Items by parentFolderId
                if deleted_folder_id and it.get('parentFolderId') == deleted_folder_id:
                    continue
                items.append(it)
            url = data.get('@odata.nextLink') if isinstance(data, dict) else None

        # Determine current message timestamp
        try:
            cur_ts = getattr(current_msg, 'received', None) or getattr(current_msg, 'created', None)
        except Exception:
            cur_ts = None

        from datetime import datetime

        def parse_iso(ts: str):
            try:
                if not ts:
                    return None
                # Graph returns e.g. 2024-10-05T12:34:56Z
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except Exception:
                return None

        # Keep only older-than-current and exclude the current message
        filtered = []
        for it in items:
            if it.get('id') == getattr(current_msg, 'object_id', None):
                continue
            its = parse_iso(it.get('receivedDateTime'))
            if cur_ts and its and its > cur_ts:
                continue
            filtered.append((its, it))

        # Sort oldest -> newest
        filtered.sort(key=lambda pair: pair[0] or parse_iso('1970-01-01T00:00:00Z'))

        # Build snippets using full Message fetch for robust body handling
        snippets = []
        for _, it in filtered:
            try:
                m = mailbox.get_message(object_id=it.get('id'))
                if not m:
                    continue
                try:
                    m.refresh()
                except Exception:
                    pass
                sender = ''
                try:
                    sender = (m.sender.address or '').strip()
                except Exception:
                    sender = ''
                ts_str = ''
                try:
                    if getattr(m, 'received', None):
                        ts_str = m.received.strftime('%Y-%m-%d %H:%M')
                except Exception:
                    ts_str = ''
                body_snip = get_clean_message_text(m)
                entry = f"[{ts_str} | {sender}] {m.subject or ''}\n{body_snip or ''}"
                snippets.append(entry.strip())
            except Exception:
                continue

        if not snippets:
            return ""
        return "\n\n---\n\n".join(snippets)
    except Exception as e:
        try:
            print(f"⚠️ build_thread_context_across_mailbox error: {e}")
        except Exception:
            pass
        return ""


def process_folder(folder, name, delta_token):
    """
    Delta items are treated as signals only.
    For each changed conversation, fetch ALL unread child messages and process
    them individually (oldest -> newest), never reprocessing the original/root.
    Internal replies are detected and handled before classification.
    """
    # Build delta query (optionally select a few cheap fields to reduce "shallow" items)
    qs = folder.new_query()
    if delta_token:
        qs = qs.delta_token(delta_token)
    qs = qs.select([
        'id', 'conversationId', 'isRead', 'receivedDateTime', 'from', 'sender', 'subject', 'categories'
    ])

    try:
        msgs = folder.get_messages(query=qs)

        for msg in msgs:
            # For each conversation that changed, act ONLY on unread children
            conv_id = getattr(msg, 'conversation_id', None)
            if not conv_id:
                # Fallback: skip if no conversation id (rare)
                dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
                if dedup_key in processed_messages:
                    print(f"⏭️  Already processed message (dedup), skipping: {getattr(msg, 'subject', 'Unknown')}")
                    continue
                try:
                    msg.refresh()
                except Exception:
                    pass
                
                # Skip if already processed (marked with PAIRActioned)
                if any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                    print(f"⏭️  Already processed message (categories), skipping: {msg.subject}")
                    processed_messages.add(dedup_key)
                    continue
                
                # If this solitary item is unread, process it as a last resort
                if not msg.is_read:
                    # Internal-reply detection (rare path)
                    sender_addr = _extract_sender_address(msg).lower()
                    sender_is_staff = sender_addr in [e.lower() for e in EMAILS_TO_FORWARD]
                    is_automated_reply = bool(re.search(fr"{REPLY_ID_TAG}\s*([^\s<]+)", msg.body or "", flags=re.I|re.S))
                    if sender_is_staff and is_automated_reply and not any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                        handle_internal_reply(msg)
                        processed_messages.add(dedup_key)
                        continue

                    # Skip internal MLFA senders
                    if _is_internal_sender(sender_addr):
                        try:
                            tag_email(msg, ['internal_outgoing'], replyTag=False)
                            mark_as_read(msg)
                        except Exception:
                            pass
                        processed_messages.add(dedup_key)
                        continue

                    # Skip all MLFA internal senders from approval/classification
                    if _is_internal_sender(sender_addr):
                        try:
                            tag_email(msg, ['internal_outgoing'], replyTag=False)
                            mark_as_read(msg)
                        except Exception:
                            pass
                        processed_messages.add(dedup_key)
                        continue

                    # Skip messages older than PROCESS_SINCE
                    try:
                        if getattr(msg, 'received', None) and msg.received < PROCESS_SINCE:
                            processed_messages.add(dedup_key)
                            continue
                    except Exception:
                        pass

                    body_to_analyze = get_clean_message_text(msg)

                    # Silent skip for blocked senders or blocked sender/recipient pairs
                    if _should_skip_message(msg):
                        processed_messages.add(dedup_key)
                        continue

                    print(f"\nNEW:  [{name}] {msg.received.strftime('%Y-%m-%d %H:%M')} | "
                          f"{msg.sender.address if msg.sender else 'UNKNOWN'} | {msg.subject}")
                    if DEBUG_CLASSIFY_PROMPT:
                        try:
                            print("\n===== GPT CLASSIFY CONTEXT (NO THREAD ID) START =====")
                            print(f"Subject: {msg.subject}")
                            print(f"Message ID: {msg.object_id}")
                            print(f"Latest message body:\n{body_to_analyze}")
                            print("===== GPT CLASSIFY CONTEXT END =====\n")
                        except Exception:
                            pass
                    # Check preexisting legal/jail mail tags before classification
                    preexisting_legal = _has_preexisting_legal_tag(msg)
                    preexisting_jail_mail = _has_preexisting_jail_mail_tag(msg)
                    result = classify_email(msg.subject, body_to_analyze)
                    # Attach the preexisting flags to the result for downstream handling
                    try:
                        result["is_legal_preexisting"] = preexisting_legal
                        result["is_jail_mail_preexisting"] = preexisting_jail_mail
                    except Exception:
                        pass
                    if HUMAN_CHECK: 
                        print(json.dumps(result, indent=2))
                        # Skip if this email is already in pending queue (prevent duplicates)
                        email_id = msg.object_id
                        if email_id not in pending_emails:
                            pending_emails[email_id] = {
                                "subject": msg.subject,
                                "body": body_to_analyze,
                                "classification": result,
                                "sender": msg.sender.address,
                                "received": msg.received.strftime('%Y-%m-%d %H:%M'),
                                "message_obj": msg
                            }
                            print(f"📧 Email stored for approval: {msg.subject}")
                        else:
                            print(f"⏭️  Email already in pending queue, skipping: {msg.subject}")
                        processed_messages.add(dedup_key)
                    else: 
                        print(json.dumps(result, indent=2))
                        handle_new_email(msg, result)
                        processed_messages.add(dedup_key)
                continue  # done with this delta item

            # Normal path: fetch unread messages in this conversation
            try:
                unread_msgs = unread_in_conversation(folder, mailbox, conv_id)
            except Exception as e:
                print(f"   Could not fetch unread children for {conv_id}: {e}")
                continue

            if not unread_msgs:
                # No unread children → nothing to do for this conversation
                continue

            # Process each unread child once, oldest -> newest
            for child in unread_msgs:
                dedup_key = getattr(child, 'internet_message_id', None) or child.object_id
                if dedup_key in processed_messages:
                    print(f"⏭️  Already processed message (dedup), skipping: {child.subject}")
                    continue

                # Skip messages older than PROCESS_SINCE
                try:
                    if getattr(child, 'received', None) and child.received < PROCESS_SINCE:
                        processed_messages.add(dedup_key)
                        continue
                except Exception:
                    pass

                # Make sure we have up-to-date fields on the child
                try:
                    child.refresh()
                except Exception:
                    pass

                # Skip if already processed (marked with PAIRActioned)
                if any((c or '').startswith('PAIRActioned') for c in (child.categories or [])):
                    print(f"⏭️  Already processed message (categories), skipping: {child.subject}")
                    processed_messages.add(dedup_key)
                    continue

                # 1) Internal reply path (staff replies captured by your hidden REPLY_ID_TAG)
                sender_addr = _extract_sender_address(child).lower()
                sender_is_staff = sender_addr in [e.lower() for e in EMAILS_TO_FORWARD]
                is_automated_reply = bool(re.search(fr"{REPLY_ID_TAG}\s*([^\s<]+)", child.body or "", flags=re.I|re.S))
                if sender_is_staff and is_automated_reply and not any(
                    (c or '').startswith('PAIRActioned') for c in (child.categories or [])
                ):
                    handle_internal_reply(child)
                    processed_messages.add(dedup_key)
                    continue

                # 2) Skip any internal MLFA senders (outgoing items landing in Inbox)
                if _is_internal_sender(sender_addr):
                    try:
                        tag_email(child, ['internal_outgoing'], replyTag=False)
                        mark_as_read(child)
                    except Exception:
                        pass
                    processed_messages.add(dedup_key)
                    continue

                # 3) Classify using reply-only text, then handle
                body_to_analyze = get_clean_message_text(child)
                # Silent skip for blocked senders or blocked sender/recipient pairs
                if _should_skip_message(child):
                    processed_messages.add(dedup_key)
                    continue

                print(f"\nNEW:  [{name}] {child.received.strftime('%Y-%m-%d %H:%M')} | "
                      f"{child.sender.address if child.sender else 'UNKNOWN'} | {child.subject}")
                # Optionally include thread context for better classification
            if USE_THREAD_CONTEXT and getattr(child, 'conversation_id', None):
                try:
                    thread_ctx = build_thread_context(folder, child)
                    if not thread_ctx:
                        thread_ctx = build_thread_context_across_mailbox(child)
                except Exception:
                    thread_ctx = ""
            else:
                thread_ctx = ""

                composite_body = (
                    ("These are earlier emails from the same thread. Use them as context to make the right routing decision.\n\n"
                     + f"Thread context (older messages, oldest→newest):\n{thread_ctx}\n\n" if thread_ctx else "")
                    + f"Latest message body:\n{body_to_analyze}"
                )
                if DEBUG_CLASSIFY_PROMPT:
                    try:
                        print("\n===== GPT CLASSIFY CONTEXT (THREAD CHILD) START =====")
                        print(f"Subject: {child.subject}")
                        print(f"Message ID: {child.object_id}")
                        print(composite_body)
                        print("===== GPT CLASSIFY CONTEXT END =====\n")
                    except Exception:
                        pass
                # Check preexisting legal/jail mail tags before classification
                preexisting_legal = _has_preexisting_legal_tag(child)
                preexisting_jail_mail = _has_preexisting_jail_mail_tag(child)
                result = classify_email(child.subject, composite_body)
                # Attach the preexisting flags to the result for downstream handling
                try:
                    result["is_legal_preexisting"] = preexisting_legal
                    result["is_jail_mail_preexisting"] = preexisting_jail_mail
                except Exception:
                    pass
                print(json.dumps(result, indent=2))
                
                if HUMAN_CHECK:
                    # Skip if this email is already in pending queue (prevent duplicates)
                    email_id = child.object_id
                    if email_id not in pending_emails:
                        pending_emails[email_id] = {
                            "subject": child.subject,
                            "body": body_to_analyze,
                            "classification": result,
                            "sender": child.sender.address,
                            "received": child.received.strftime('%Y-%m-%d %H:%M'),
                            "message_obj": child
                        }
                        print(f"📧 Email stored for approval: {child.subject}")
                    else:
                        print(f"⏭️  Email already in pending queue, skipping: {child.subject}")
                else:
                    handle_new_email(child, result)

                # 4) Dedup remember
                processed_messages.add(dedup_key)

        # Return latest delta token (if present) to persist
        new_token = getattr(msgs, 'delta_token', None)
        print(f"🔍 [{name}] Delta token check: msgs has delta_token = {hasattr(msgs, 'delta_token')}")
        if new_token:
            print(f"🔍 [{name}] New delta token: {new_token[:50]}...")
        else:
            print(f"🔍 [{name}] No new delta token, using old: {delta_token[:50] if delta_token else 'None'}")
        return new_token or delta_token

    except Exception as e:
        err_text = str(e)
        print(f" Error accessing {name}: {err_text}")
        # Handle expired/invalid auth: trigger immediate re-auth
        if any(tok in err_text for tok in ("401", "Unauthorized", "invalid_token", "expired", "invalid_client")):
            ensure_account_fresh(force=True)
        # Handle invalid/expired delta token: reset token so we resync
        if any(tok in err_text for tok in ("SyncState", "delta", "410")):
            print(f" ⚠️  Resetting delta token for {name} due to invalid sync state.")
            return None
        return delta_token


def fetch_messages_delta(folder_name: str, delta_url: str | None):
    """Fetch message changes using Graph delta query. Returns (ids, new_delta_url).
    Stores full @odata.deltaLink URL as the delta token.
    """
    try:
        con = account.con
        base = f"https://graph.microsoft.com/v1.0/users/{EMAIL_TO_WATCH}/mailFolders/{folder_name}/messages/delta"
        # Select minimal fields to reduce payload and pull in pages of 50
        select = "$select=id,conversationId,isRead,receivedDateTime,from,sender,subject,categories&$top=50"
        url = delta_url or f"{base}?{select}"
        print(f"Δ Starting delta for {folder_name} using {'existing' if delta_url else 'new'} token…")
        ids = []
        new_delta = None
        safety_counter = 0
        while url and safety_counter < 50:  # avoid infinite loops
            safety_counter += 1
            resp = con.get(url)
            if not resp:
                break
            # Handle expired/invalid delta tokens explicitly
            try:
                status = getattr(resp, 'status_code', 0)
                if status == 410:
                    print(f"Δ {folder_name}: 410 Gone (expired delta token). Forcing fresh sync next cycle.")
                    return [], None
                if status and status >= 400:
                    # Inspect body for sync state errors
                    body_text = ''
                    try:
                        body_text = resp.text or ''
                    except Exception:
                        body_text = ''
                    if any(tok in body_text for tok in ("SyncState", "sync state", "delta", "Gone")):
                        print(f"Δ {folder_name}: sync state invalid. Forcing fresh sync next cycle.")
                        return [], None
            except Exception:
                pass
            data = resp.json()
            # Some Graph errors can return plain strings; normalize to dict
            if not isinstance(data, dict):
                try:
                    data = json.loads(data) if isinstance(data, str) else {}
                except Exception:
                    data = {}
            vals = data.get('value', []) if isinstance(data, dict) else []
            if isinstance(vals, dict):
                # Occasionally some Graph libs return a single object instead of an array
                vals = [vals]
            if isinstance(vals, str):
                # Malformed payload where 'value' is a string
                try:
                    parsed_vals = json.loads(vals)
                    vals = parsed_vals if isinstance(parsed_vals, list) else []
                except Exception:
                    vals = []
            for item in vals:
                if not isinstance(item, dict):
                    continue
                mid = item.get('id')
                if mid:
                    ids.append(mid)
            try:
                value_count = len(vals)
            except Exception:
                value_count = 0
            print(f"Δ {folder_name}: page returned {value_count} changes (total {len(ids)})")
            url = data.get('@odata.nextLink') if isinstance(data, dict) else None
            if not url:
                new_delta = data.get('@odata.deltaLink', new_delta) if isinstance(data, dict) else new_delta
                if new_delta:
                    print(f"Δ {folder_name}: obtained deltaLink ({len(new_delta)} chars)")
                break
        return ids, new_delta or delta_url
    except Exception as e:
        err_text = str(e)
        print(f"⚠️ Delta fetch error for {folder_name}: {e}")
        if any(tok in err_text for tok in ("410", "SyncState", "sync state", "Gone")): 
            return [], None
        return [], delta_url


def process_folder_via_delta(folder_obj, folder_name: str, delta_url: str | None):
    """Process changes via Graph delta; returns updated delta_url."""
    ids, new_delta = fetch_messages_delta(folder_name, delta_url)
    # If this is the initial seed (no delta_url) and we obtained a new deltaLink,
    # write it immediately so the token file appears quickly during first sync.
    try:
        if not delta_url and new_delta:
            if folder_name.lower().startswith('inbox'):
                ipath = os.path.join(TOKEN_DIR, "delta_token_inbox.txt")
                open(ipath, "w").write(new_delta)
                print(f"Δ Saved Inbox delta token (immediate) to {ipath} ({len(new_delta)} chars)")
            elif folder_name.lower().startswith('junk'):
                jpath = os.path.join(TOKEN_DIR, "delta_token_junk.txt")
                open(jpath, "w").write(new_delta)
                print(f"Δ Saved Junk delta token (immediate) to {jpath} ({len(new_delta)} chars)")
    except Exception as e:
        print(f"⚠️ Could not write immediate delta token for {folder_name}: {e}")
    if not ids:
        return new_delta

    for mid in ids:
        try:
            msg = folder_obj.get_message(object_id=mid)
            if not msg:
                continue
            dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
            if dedup_key in processed_messages:
                continue

            # Refresh to ensure categories and body present
            try:
                msg.refresh()
            except Exception:
                pass

            # Skip if already processed via categories
            if any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                processed_messages.add(dedup_key)
                continue

            # Skip messages older than PROCESS_SINCE
            try:
                if getattr(msg, 'received', None) and msg.received < PROCESS_SINCE:
                    processed_messages.add(dedup_key)
                    continue
            except Exception:
                pass

            # Internal reply detection
            sender_addr = _extract_sender_address(msg).lower()
            sender_is_staff = sender_addr in [e.lower() for e in EMAILS_TO_FORWARD]
            is_automated_reply = bool(re.search(fr"{REPLY_ID_TAG}\s*([^\s<]+)", msg.body or "", flags=re.I|re.S))
            if sender_is_staff and is_automated_reply and not any((c or '').startswith('PAIRActioned') for c in (msg.categories or [])):
                handle_internal_reply(msg)
                processed_messages.add(dedup_key)
                continue

            # Skip internal MLFA senders entirely
            if _is_internal_sender(sender_addr):
                try:
                    tag_email(msg, ['internal_outgoing'], replyTag=False)
                    mark_as_read(msg)
                except Exception:
                    pass
                processed_messages.add(dedup_key)
                continue

            # Classify and handle
            body_to_analyze = get_clean_message_text(msg)
            # Silent skip for blocked senders or blocked sender/recipient pairs
            if _should_skip_message(msg):
                processed_messages.add(dedup_key)
                continue

            print(f"\nNEW:  [{folder_name}] {msg.received.strftime('%Y-%m-%d %H:%M') if getattr(msg, 'received', None) else ''} | "
                  f"{msg.sender.address if msg.sender else 'UNKNOWN'} | {msg.subject}")
            # Optionally include thread context for better classification
            if USE_THREAD_CONTEXT and getattr(msg, 'conversation_id', None):
                try:
                    thread_ctx = build_thread_context(folder_obj, msg)
                    if not thread_ctx:
                        thread_ctx = build_thread_context_across_mailbox(msg)
                except Exception:
                    thread_ctx = ""
            else:
                thread_ctx = ""
            composite_body = (
                ("These are earlier emails from the same thread. Use them as context to make the right routing decision.\n\n"
                 + f"Thread context (older messages, oldest→newest):\n{thread_ctx}\n\n" if thread_ctx else "")
                + f"Latest message body:\n{body_to_analyze}"
            )
            if DEBUG_CLASSIFY_PROMPT:
                try:
                    print("\n===== GPT CLASSIFY CONTEXT (DELTA ITEM) START =====")
                    print(f"Subject: {msg.subject}")
                    print(f"Message ID: {msg.object_id}")
                    print(composite_body)
                    print("===== GPT CLASSIFY CONTEXT END =====\n")
                except Exception:
                    pass
            # Check preexisting legal/jail mail tags before classification
            preexisting_legal = _has_preexisting_legal_tag(msg)
            preexisting_jail_mail = _has_preexisting_jail_mail_tag(msg)
            result = classify_email(msg.subject, composite_body)
            # Attach the preexisting flags to the result for downstream handling
            try:
                result["is_legal_preexisting"] = preexisting_legal
                result["is_jail_mail_preexisting"] = preexisting_jail_mail
            except Exception:
                pass
            if HUMAN_CHECK:
                print(json.dumps(result, indent=2))
                email_id = msg.object_id
                if email_id not in pending_emails:
                    pending_emails[email_id] = {
                        "subject": msg.subject,
                        "body": body_to_analyze,
                        "classification": result,
                        "sender": msg.sender.address if msg.sender else '',
                        "received": msg.received.strftime('%Y-%m-%d %H:%M') if getattr(msg, 'received', None) else '',
                        "message_obj": msg
                    }
                    print(f"📧 Email stored for approval: {msg.subject}")
            else:
                print(json.dumps(result, indent=2))
                handle_new_email(msg, result)

            processed_messages.add(dedup_key)

        except Exception as e:
            print(f"⚠️ Error processing delta item {mid}: {e}")

    return new_delta


def handle_new_email(msg, result):
    """
    Takes a message and its AI classification result, then acts on it.
    It does NOT call the AI again.
    """
    categories = result.get("categories", [])
    recipients_set = set(result.get("all_recipients", []))
    name_sender = result.get("name_sender")
    preexisting_legal = bool(result.get("is_legal_preexisting"))
    preexisting_jail_mail = bool(result.get("is_jail_mail_preexisting"))

    # Hard stop: internal deletes take precedence over all actions
    if 'delete_internal' in set(categories or []):
        try:
            msg.delete()
            print("🗑️ Deleted email due to delete_internal category")
        except Exception as e:
            print(f"⚠️ Could not delete email (delete_internal): {e}")
        return

    # If this email already had a legal or jail mail tag before analysis and
    # the classifier also marked it the same way, do not auto-reply or modify it.
    # Leave the message exactly as-is and move on.
    if preexisting_legal and ("legal" in categories):
        try:
            print("⏭️  Skipping auto-reply: preexisting legal tag detected and classified as legal.")
        except Exception:
            pass
        return
    if preexisting_jail_mail and ("jail_mail" in categories):
        try:
            print("⏭️  Skipping auto-reply: preexisting jail_mail tag detected and classified as jail_mail.")
        except Exception:
            pass
        return
    
    # We pass the message and its categories to be tagged
    tag_email(msg, categories, replyTag=False)
    # We use the results to perform specific actions
    handle_emails(categories, result, recipients_set, msg, name_sender)

    # No follow-up recipient merging; rely on classification and runtime participants

    if recipients_set:
        fwd = msg.forward()
        # Forward to the actual recipients determined by classification
        fwd.to.add(list(recipients_set))
        # Add the hidden tracking ID into the top of the forwarded body
        instruction_html = f"""<div style=\"display:none;\">{REPLY_ID_TAG}{msg.object_id}</div>"""

        # Prepend to the auto-generated forward body (HTML)
        fwd.body = (
            "<p>Please click 'Reply All' to reply to info@mlfa.org. "
            "Your email will automatically be sent to the correct person.</p>"
            + instruction_html
        )
        fwd.body_type = 'HTML'

        # Send the forward
        fwd.send()

        # No persistence of recipients per thread


    if not set(categories).issubset(NONREAD_CATEGORIES):
        mark_as_read(msg)


def ensure_folder_path(path_parts):
    """Ensure a nested folder path exists under Inbox and return it.
    path_parts is a list like ["Irrelevant", "Spam"].
    """
    try:
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
                    print(f"📁 Created folder: {name} under {getattr(current, 'name', 'Inbox')}")
                except Exception as e:
                    print(f"⚠️ Could not create folder '{name}' under {getattr(current, 'name', 'Inbox')}: {e}")
                    return None
            current = found
        return current
    except Exception as e:
        print(f"⚠️ ensure_folder_path error for {path_parts}: {e}")
        return None


def handle_emails(categories, result, recipients_set, msg, name_sender): 
    move_target_path = None  # Decide one destination per message
    special_moved = False  # Marketing/out_of_office handled separately
    category_set = set(categories or [])

    for category in categories:
        if category in ("legal", "jail_mail"):
            reply_message = msg.reply(to_all=False)
            reply_message.body_type = "HTML"
            needs_personal = result.get("needs_personal_reply", False)

            # Greeting logic: use Dear {Name} when name is present; otherwise time-of-day greeting
            has_real_name = bool(name_sender and name_sender.strip() and name_sender.strip().lower() != 'sender')
            greeting_html = (
                f"<p>Dear {name_sender},</p>" if has_real_name else f"<p>Good {_tod_greeting()},</p>"
            )

            if needs_personal:
                reply_message.body = f"""
                    {greeting_html}

                    <p>Thank you for contacting the Muslim Legal Fund of America (MLFA). 
                    We are grateful that you reached out and placed your trust in us to potentially support your legal matter.</p>

                    <p>If you have not already done so, please submit a formal application for legal assistance through our website:<br>
                    <a href=\"https://mlfa.org/application-for-legal-assistance/\">https://mlfa.org/application-for-legal-assistance/</a></p>

                    <p>Once submitted, our team will carefully review your application and follow up with next steps. 
                    If you have any questions about the application process or need help completing it, please don't hesitate to reach out.</p>

                    <p>We appreciate your patience as we work through applications, and we look forward to learning more about how we might be able to help.</p>

                    <p>Warm regards,<br>
                    The MLFA Team<br>
                    Muslim Legal Fund of America</p>
                """
            else:
                reply_message.body = f"""
                    {greeting_html}

                    <p>Thank you for contacting the Muslim Legal Fund of America (MLFA).</p>

                    <p>If you have not already done so, please submit a formal application for legal assistance 
                    through our website:<br>
                    <a href=\"https://mlfa.org/application-for-legal-assistance/\">https://mlfa.org/application-for-legal-assistance/</a></p>

                    <p>This ensures our legal team has the information needed to review your case promptly.</p>

                    <p>Sincerely,<br>
                    The MLFA Team</p>
                """
            reply_message.send()

        elif category == "financial_aid":
            reply_message = msg.reply(to_all=False)
            reply_message.body_type = "HTML"
            reply_message.body = f"""
                    <p>Assalamu alaikum,</p>
                    <p>Thank you for reaching out to the Muslim Legal Fund of America (MLFA).</p>
                    <p>We would like to clarify that our organization does not provide direct personal financial assistance. Rather, MLFA supports and funds legal representation in select cases that impact the civil liberties and constitutional rights of Muslims in America. For this reason, we are not able to offer the type of financial assistance you are requesting.
                    </p>
                    <p>If you have a legal matter that you would like us to consider, you may complete an official inquiry for our attorneys to review:<br>
                    <a href=\"https://mlfa.org/application-for-legal-assistance/\">https://mlfa.org/application-for-legal-assistance/</a></p>

                    <p>We sincerely hope that you are able to find the resources and support you need, and we pray for ease and better days ahead.</p>

                    <p>Sincerely,<br>
                    The Muslim Legal Fund of America</p>
                """
            reply_message.send()


        elif category == "violation_notice":
            # Forward legal/DMCA/policy violation notices to Arshia and Maria, then file
            recipients_set.update([f"{EMAILS_TO_FORWARD[2]}", f"{EMAILS_TO_FORWARD[3]}"])

        elif category == "donor":
            recipients_set.update([f"{EMAILS_TO_FORWARD[0]}", f"{EMAILS_TO_FORWARD[1]}"]) 

        elif category == "sponsorship":
            recipients_set.update([f"{EMAILS_TO_FORWARD[2]}", f"{EMAILS_TO_FORWARD[3]}"])

        elif category == "organizational":
            recipients_set.update([f"{EMAILS_TO_FORWARD[2]}", f"{EMAILS_TO_FORWARD[3]}"])

        elif category == "volunteer":
            recipients_set.update([f"{EMAILS_TO_FORWARD[8]}"])

        elif category == "internship":
            recipients_set.update([f"{EMAILS_TO_FORWARD[5]}"])

        elif category == "job_application":
            recipients_set.update([f"{EMAILS_TO_FORWARD[6]}"])

        elif category == "fellowship":
            recipients_set.update([f"{EMAILS_TO_FORWARD[5]}"])

        elif category == "media":
            recipients_set.update([f"{EMAILS_TO_FORWARD[7]}"])

        elif category == "out_of_office":
            try:
                deleted = mailbox.deleted_folder()
                msg.move(deleted)
                print("🗑️ Moved email to Deleted Items (Trash)")
                special_moved = True
            except Exception as e:
                print(f"⚠️ Could not move to Deleted Items (Trash): {e}")

        elif category == "marketing":
            try:
                inbox = mailbox.inbox_folder()
                sales_folder = inbox.get_folder(folder_name="Sales emails")
                print("Moving to sales emails folder.")
                msg.move(sales_folder)
                special_moved = True
            except Exception as e:
                print(f"⚠️ Could not move to 'Sales emails' folder: {e}")

        #elif category == "newsletter":
        #    if move_target_path is None:
        #        move_target_path = ["Newsletters"]

        elif category == "statements":
            # Forward statements to Syeda and Mujahid, then file
            recipients_set.update([f"{EMAILS_TO_FORWARD[1]}"])
        

        elif category == "general_communication":
            # Route general communications to the General Communication folder
            pass

        elif category == "spam":
            pass

        elif category == "cold_outreach":
            pass

        elif category == "irrelevant_other":
            pass

    if not special_moved:
        priority = [
            "jail_mail",
            "legal",
            "violation_notice",
            "donor",
            "sponsorship",
            "organizational",
            "volunteer",
            "internship",
            "job_application",
            "fellowship",
            "media",
            "statements",
            "general_communication",
            "spam",
            "cold_outreach",
            "irrelevant_other",
        ]
        category_to_folder = {
            "jail_mail": ["Jail_Mail"],
            "legal": ["Apply for help"],
            "violation_notice": ["Violation_Notices"],
            "donor": ["Donor_Related"],
            "sponsorship": ["Sponsorship"],
            "organizational": ["Organizational_Inquiries"],
            "volunteer": ["Volunteer"],
            "internship": ["Internship"],
            "job_application": ["Job_Application"],
            "fellowship": ["Fellowship"],
            "media": ["Media"],
            "statements": ["Statements"],
            "general_communication": ["General Communication"],
            "spam": ["Irrelevant", "Spam"],
            "cold_outreach": ["Irrelevant", "Cold_Outreach"],
            "irrelevant_other": ["Irrelevant", "Other"],
        }
        for cat in priority:
            if cat in category_set:
                move_target_path = category_to_folder.get(cat)
                break

    if move_target_path:
        try:
            try:
                print(f"📌 Routing by priority: categories={sorted(category_set)} -> {'/'.join(move_target_path)}")
            except Exception:
                pass
            dest = ensure_folder_path(move_target_path)
            if dest:
                msg.move(dest)
                print(f"📁 Moved email to: {'/'.join(move_target_path)}")
            else:
                print(f"⚠️ No destination folder found for: {'/'.join(move_target_path)}")
        except Exception as e:
            print(f"⚠️ Could not move email to {'/'.join(move_target_path)}: {e}")

def tag_email(msg, categories, replyTag):
    # 1) Load existing categories safely
    existing = set((msg.categories or []))

    # 2) Build new tags for this operation
    new_tags = set()
    for c in categories or []:
        c = (c or "").strip()
        if not c:
            continue
        if replyTag:
            new_tags.add(f"PAIRActioned/replied/{c}")
        else:
            if c in ('spam', 'cold_outreach', 'newsletter'):
                new_tags.add(f"PAIRActioned/irrelevant/{c}")
            else:
                new_tags.add(f"PAIRActioned/{c}")

    # Always keep the umbrella marker
    new_tags.add("PAIRActioned")
    merged = existing.union(new_tags)
    if merged != existing:
        msg.categories = sorted(merged)
        msg.save_message()


 

def _tod_greeting() -> str:
    """Return 'morning', 'afternoon', or 'evening' based on hour of day."""
    try:
        central = pytz.timezone("America/Chicago")  
        now_central = datetime.now(central)
        hour = now_central.hour
    except Exception:
        hour = None
    if hour is None:
        central = pytz.timezone("America/Chicago")  
        now_central = datetime.now(central)
        hour = now_central.hour
    if 0 <= hour < 12:
        return 'morning'
    if 12 <= hour < 18:
        return 'afternoon'
    return 'evening'


def mark_as_read(msg): 
    print("   Marking email as read...")
    try:
        msg.mark_as_read()
        print("   Marked as read")
    except Exception as e:
        print(f"    Could not mark as read: {e}")

def handle_internal_reply(msg): 
    print(f"\nREPLY DETECTED: From {msg.sender.address} | {msg.subject}")
    body_parts = msg.body.split(REPLY_ID_TAG)
    if len(body_parts) < 2:
        print(" ERROR: Could not find the reply id, therefore, we cannot reply. ")
        return

    html_chunk = body_parts[0]
    soup = BeautifulSoup(html_chunk, 'html.parser')
    reply_content = str(soup)

    if not reply_content: 
        print("   WARNING: Reply appears to be empty. Not sending. ")
        #We need to maybe re-email the person who wrote the reply to the forwarded email to try again. 
        return

    match = re.search(f"{REPLY_ID_TAG}(.+?)</", msg.body)
    if not match: 
        print("   ERROR: Could not find the original message ID.")
        return
    original_message_id = match.group(1).strip()
    
    try:
        original_msg = mailbox.get_message(original_message_id)
        # Include all original participants on the final reply
        final_reply = original_msg.reply(to_all=True)
        final_reply.body = reply_content
        final_reply.body_type = "HTML"
        final_reply.send()
        print(f"   Sent reply to original sender: {original_msg.sender.address}")
    except Exception as e:
        print(f"   ERROR: Could not send final reply. Error: {e}")
        return

    msg.mark_as_read()
    print("   Cleanup complete. Reply process finished.")


def _has_preexisting_legal_tag(msg) -> bool:
    """Return True if the message already carries a 'legal' tag/category.
    Detects plain 'legal' or any category ending with '/legal' (e.g. 'PAIRActioned/legal').
    """
    try:
        cats = [c.lower() for c in (msg.categories or [])]
        return any(c == 'legal' or c.endswith('/legal') for c in cats)
    except Exception:
        return False


def _has_preexisting_jail_mail_tag(msg) -> bool:
    """Return True if the message already carries a 'jail_mail' tag/category.
    Detects plain 'jail_mail' or any category ending with '/jail_mail' (e.g. 'PAIRActioned/jail_mail').
    """
    try:
        cats = [c.lower() for c in (msg.categories or [])]
        return any(c == 'jail_mail' or c.endswith('/jail_mail') for c in cats)
    except Exception:
        return False


def _is_blocked_sender(addr: str | None) -> bool:
    """Return True if addr matches an entry in BLOCKED_SENDERS (case-insensitive)."""
    if not addr:
        return False
    try:
        a = addr.strip().lower()
        return a in [e.strip().lower() for e in (BLOCKED_SENDERS or [])]
    except Exception:
        return False


def _extract_recipient_addresses(msg) -> set[str]:
    """Collect lowercase recipient email addresses from to/cc/bcc."""
    addrs: set[str] = set()
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


def _is_blocked_sender_recipient_pair(msg) -> bool:
    """Return True if sender/recipient matches a blocked pair."""
    try:
        senders = _extract_sender_addresses(msg)
        if not senders:
            return False
        recipients = _extract_recipient_addresses(msg)
        for s_addr, r_addr in (SKIP_SENDER_RECIPIENT_PAIRS or []):
            s_norm = s_addr.strip().lower()
            r_norm = r_addr.strip().lower()
            if s_norm in senders and r_norm in recipients:
                return True
        return False
    except Exception:
        return False


def _should_skip_message(msg) -> bool:
    """Return True if message should be silently skipped."""
    try:
        senders = _extract_sender_addresses(msg)
    except Exception:
        senders = set()
    if senders and any(_is_blocked_sender(s) for s in senders):
        return True
    return _is_blocked_sender_recipient_pair(msg)


# (Blocked sender helper removed per request)


def _extract_sender_address(msg) -> str:
    """Best-effort extract sender email address from a Message."""
    try:
        if getattr(msg, 'sender', None):
            try:
                addr = getattr(msg.sender, 'address', None)
                if addr:
                    return str(addr).strip()
            except Exception:
                pass
            if isinstance(msg.sender, str):
                return msg.sender.strip()
        # Try 'from' alias used by O365 as from_
        frm = getattr(msg, 'from_', None) or getattr(msg, 'from', None)
        if frm:
            try:
                addr = getattr(frm, 'address', None) or getattr(frm, 'email', None)
                if addr:
                    return str(addr).strip()
            except Exception:
                if isinstance(frm, str):
                    return frm.strip()
    except Exception:
        pass
    return ""

def _extract_sender_addresses(msg) -> set[str]:
    """Collect sender and from addresses (lowercase) from a Message."""
    addrs: set[str] = set()
    try:
        if getattr(msg, 'sender', None):
            try:
                addr = getattr(msg.sender, 'address', None)
                if addr:
                    addrs.add(str(addr).strip().lower())
            except Exception:
                pass
            if isinstance(msg.sender, str):
                addrs.add(msg.sender.strip().lower())
        frm = getattr(msg, 'from_', None) or getattr(msg, 'from', None)
        if frm:
            try:
                addr = getattr(frm, 'address', None) or getattr(frm, 'email', None)
                if addr:
                    addrs.add(str(addr).strip().lower())
            except Exception:
                if isinstance(frm, str):
                    addrs.add(frm.strip().lower())
    except Exception:
        pass
    return addrs

def _is_internal_sender(addr: str | None) -> bool:
    """Return True for MLFA internal senders so we can skip routing/approval.
    Considers any address at @mlfa.org, the watched mailbox itself, or any
    of the configured forward recipients.
    """
    if not addr:
        return False
    try:
        a = addr.strip().lower()
        domain = a.split('@')[-1]
        if domain == 'mlfa.org':
            return True
        if EMAIL_TO_WATCH and a == EMAIL_TO_WATCH.strip().lower():
            return True
        fset = {e.strip().lower() for e in (EMAILS_TO_FORWARD or [])}
        return a in fset
    except Exception:
        return False


def newest_unread_in_conversation(folder, mailbox, conversation_id):
    """
    Return the newest unread message in the given conversation (or None).
    Uses server-side filter/order and limits to 1 item.
    """
    if not conversation_id:
        return None

    # Build the query FIRST
    q = (mailbox.new_query()
         .on_attribute('conversationId').equals(conversation_id)
         .chain('and').on_attribute('isRead').equals(False)
         .order_by('receivedDateTime', ascending=False)  # newest first
         .select([
             # Use Graph field names in $select (camelCase)
             'id', 'conversationId', 'internetMessageId',
             'isRead', 'receivedDateTime',
             'from', 'sender', 'subject',
             'categories', 'uniqueBody', 'body'
         ]))

    # Then execute with a limit of 1 (SDK-compatible way to "top(1)")
    items = list(folder.get_messages(query=q, limit=1, order_by='receivedDateTime desc'))
    if not items:
        return None

    msg = items[0]

    # Hydrate to ensure properties like categories/unique_body are fresh
    try:
        # If you prefer a full re-fetch by id instead of refresh():
        # msg = folder.get_message(object_id=msg.object_id) or msg
        msg.refresh()
    except Exception:
        pass

    return msg


def unread_in_conversation(folder, mailbox, conversation_id, page_limit=30):
    if not conversation_id:
        return []

    q = (mailbox.new_query()
         .on_attribute('conversationId').equals(conversation_id)
         .select([
             'id','conversationId','internetMessageId',
             'isRead','receivedDateTime',
             'from','sender','subject',
             'categories','uniqueBody','body'
         ]))

    items = list(folder.get_messages(query=q, limit=page_limit))
    unread = [m for m in items if not getattr(m, 'is_read', False)]
    unread.sort(key=lambda m: m.received or m.created)  # oldest→newest unread
    for m in unread:
        try: m.refresh()
        except: pass
    return unread

def get_clean_message_text(msg):
    """
    Return only the reply content for this message.
    Prefer Graph's unique_body (just the new text),
    otherwise strip quoted history from the full body.
    """
    QUOTE_SEPARATORS = [
        r'^\s*On .* wrote:\s*$',              
        r'^\s*From:\s.*$',                    
        r'^\s*-----Original Message-----\s*$',
        r'^\s*De:\s.*$',                      
        r'^\s*Sent:\s.*$',
        r'^\s*To:\s.*$',
    ]

    def strip_quoted_reply(html_or_text: str) -> str:
        if not html_or_text:
            return ""
        text = html_or_text
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_or_text, 'html.parser')
            for sel in [
                'blockquote',
                'div.gmail_quote',
                'div[type=cite]',
                'div.moz-cite-prefix',
                'div.OutlookMessageHeader',
            ]:
                for node in soup.select(sel):
                    node.decompose()
            text = soup.get_text("\n")
        except Exception:
            pass

        import re
        lines = [ln.rstrip() for ln in text.splitlines()]
        out = []
        for ln in lines:
            if ln.strip().startswith('>'):
                break
            if any(re.match(pat, ln, flags=re.IGNORECASE) for pat in QUOTE_SEPARATORS):
                break
            out.append(ln)

        return "\n".join(out).strip()[:8000]

    body = getattr(msg, 'unique_body', None) or getattr(msg, 'body', None) or ""
    return strip_quoted_reply(body)




# Flask routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password and verify_password(password):
            session['logged_in'] = True
            session.permanent = True
            print(f"✅ User logged in successfully, session ID: {session.get('logged_in')}")
            return redirect(url_for('index'))
        else:
            print(f"❌ Login failed: invalid password")
            return render_template('login.html', error='Invalid password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Serve the approval hub HTML from the same directory as this script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(base_dir, 'approval-hub.html')

@app.route('/api/emails')
@login_required
def get_emails():
    print(f"📧 API call to /api/emails - pending emails count: {len(pending_emails)}")
    emails = []
    for email_id, email_data in pending_emails.items():
        # Format data for the interface
        classification = email_data.get("classification")
        if not isinstance(classification, dict):
            classification = {}
        categories = classification.get('categories', [])
        category_display = ', '.join([cat.replace('_', ' ').title() for cat in categories])
        
        recipients = classification.get('all_recipients', [])
        recipients_display = ', '.join(recipients) if recipients else 'None'
        
        reasons = classification.get('reason', {})
        reason_display = '; '.join(reasons.values()) if isinstance(reasons, dict) and reasons else 'No reason provided'
        
        sender_name = classification.get('name_sender')
        if not sender_name or (isinstance(sender_name, str) and not sender_name.strip()):
            sender_name = 'Unknown'

        email = {
            "id": email_id,
            "meta": f"FROM: [INBOX] {email_data['received']} | {email_data['sender']} | {email_data['subject']}",
            "senderName": sender_name,
            "category": category_display,
            "recipients": recipients_display,
            "needsReply": "Yes" if classification.get('needs_personal_reply', False) else "No",
            "reason": reason_display,
            "escalation": classification.get('escalation_reason') or 'None',
            "originalContent": email_data["body"],
            "status": "pending"
        }
        emails.append(email)
    return jsonify(emails)

@app.route('/api/emails/<email_id>/approve', methods=['POST'])
@login_required
def approve_email(email_id):
    try:
        data = request.get_json(silent=True) or {}
        comment = (data.get('comment') or '').strip()
        comment_send_error = None
        if email_id in pending_emails:
            email_data = pending_emails[email_id]
            # Resolve message safely (handles 404/deleted/moved)
            msg = _fetch_message_safely(email_id, email_data.get("message_obj"))
            if msg is None:
                _remove_from_pending(email_id)
                processed_messages.add(email_id)
                return jsonify({
                    "status": "success",
                    "message": "Email no longer exists (deleted/moved). Removed from queue."
                })

            classification = email_data.get("classification")
            if not isinstance(classification, dict):
                classification = {}

            print(f"✅ Email approved: {email_data.get('subject', '(no subject)')} - Processing")
            try:
                # Process the email normally using the stored message and classification
                handle_new_email(msg, classification)
            except Exception as ex:
                # If the message was deleted/moved between fetch and action, treat as success
                err = str(ex)
                if ('404' in err) or ('Not Found' in err) or ('object was not found' in err) or ('The specified object was not found' in err):
                    _remove_from_pending(email_id)
                    try:
                        processed_messages.add(getattr(msg, 'internet_message_id', None) or getattr(msg, 'object_id', email_id))
                    except Exception:
                        pass
                    processed_messages.add(email_id)
                    return jsonify({
                        "status": "success",
                        "message": "Email no longer exists (deleted/moved). Removed from queue."
                    })
                # Otherwise: best-effort cleanup so UI never blocks on backend errors
                try:
                    mark_as_read(msg)
                except Exception:
                    pass
                _remove_from_pending(email_id)
                processed_messages.add(getattr(msg, 'internet_message_id', None) or msg.object_id)
                processed_messages.add(email_id)
                return jsonify({
                    "status": "success",
                    "message": f"Approved with warnings; downstream action failed: {str(ex)[:180]}"
                })

            if comment:
                try:
                    note = mailbox.new_message()
                    note.to.add([REVIEW_NOTIFY_EMAIL])
                    subj = (msg.subject or '').strip() or '(no subject)'
                    note.subject = f"Accepted with comment: {subj}"
                    note.body_type = 'HTML'
                    safe_comment = (comment or '').replace('\n', '<br>')
                    clean_text = get_clean_message_text(msg) or ''
                    safe_text = (clean_text.replace('&', '&amp;')
                                           .replace('<', '&lt;')
                                           .replace('>', '&gt;'))
                    from_addr = ''
                    try:
                        from_addr = (msg.sender.address or '').strip()
                    except Exception:
                        pass
                    categories = ''
                    try:
                        cats = classification.get("categories") or []
                        if isinstance(cats, list):
                            categories = ", ".join([str(c) for c in cats if c])
                    except Exception:
                        categories = ''
                    received_str = ''
                    try:
                        if getattr(msg, 'received', None):
                            received_str = msg.received.strftime('%Y-%m-%d %H:%M')
                    except Exception:
                        pass
                    note.body = (
                        "<div style='font-family:Inter,Segoe UI,Arial,sans-serif;font-size:14px;color:#0d1117'>"
                        f"<p><strong>Comment:</strong> {safe_comment or 'No details provided.'}</p>"
                        f"<p><strong>From:</strong> {from_addr or 'Unknown'}<br>"
                        f"<strong>Subject:</strong> {subj}<br>"
                        f"<strong>Received:</strong> {received_str or 'Unknown'}<br>"
                        f"<strong>Classified as:</strong> {categories or 'Unknown'}</p>"
                        f"<h4 style='margin:12px 0 6px 0;'>Original content</h4>"
                        f"<pre style='white-space:pre-wrap;background:#f6f8fa;padding:12px;border-radius:6px;border:1px solid #d0d7de'>{safe_text}</pre>"
                        "</div>"
                    )
                    note.send()
                    print("📤 Sent acceptance comment to reviewer")
                except Exception as e:
                    comment_send_error = str(e)
                    print(f"⚠️ Could not send acceptance comment: {e}")

            # Mark processed and remove from queue
            dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
            processed_messages.add(dedup_key)
            processed_messages.add(email_id)
            _remove_from_pending(email_id)

        response = {"status": "success", "message": "Email approved"}
        if comment and comment_send_error:
            response["warning"] = "Approved, but failed to send comment notification"
        return jsonify(response)
    except Exception as e:
        # If the underlying error indicates the message no longer exists, 
        # silently remove it and return success to avoid blocking the UI.
        err = str(e)
        if ('404' in err) or ('Not Found' in err) or ('object was not found' in err) or ('The specified object was not found' in err):
            try:
                _remove_from_pending(email_id)
                processed_messages.add(email_id)
            except Exception:
                pass
            return jsonify({
                "status": "success",
                "message": "Email no longer exists (deleted/moved). Removed from queue."
            })
        print(f"❌ Error approving email {email_id}: {e}")
        return jsonify({"status": "error", "message": f"Server error while approving: {e}"}), 500

@app.route('/api/emails/approve_all', methods=['POST'])
@login_required
def approve_all_emails():
    try:
        ids = list(pending_emails.keys())
        approved = 0
        errors = []
        for email_id in ids:
            try:
                email_data = pending_emails.get(email_id)
                if not email_data:
                    continue
                # Resolve message safely per item
                msg = _fetch_message_safely(email_id, email_data.get("message_obj"))
                if msg is None:
                    _remove_from_pending(email_id)
                    processed_messages.add(email_id)
                    approved += 1
                    continue
                classification = email_data["classification"]
                if not isinstance(classification, dict):
                    classification = {}
                try:
                    handle_new_email(msg, classification)
                    dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
                    processed_messages.add(dedup_key)
                    processed_messages.add(email_id)
                    _remove_from_pending(email_id)
                    approved += 1
                except Exception as ex:
                    # best-effort cleanup on failure and keep queue moving
                    try:
                        mark_as_read(msg)
                    except Exception:
                        pass
                    _remove_from_pending(email_id)
                    processed_messages.add(getattr(msg, 'internet_message_id', None) or getattr(msg, 'object_id', email_id))
                    processed_messages.add(email_id)
                    approved += 1
            except Exception as inner_e:
                errors.append({"id": email_id, "error": str(inner_e)})
        return jsonify({"status": "success", "approved": approved, "errors": errors})
    except Exception as e:
        print(f"❌ Error approving all emails: {e}")
        return jsonify({"status": "error", "message": f"Server error while approving all: {e}"}), 500

@app.route('/api/emails/<email_id>/reject', methods=['POST'])
@login_required
def reject_email(email_id):
    try:
        data = request.get_json(silent=True) or {}
        reason = data.get('reason', 'No reason provided')

        if email_id in pending_emails:
            email_data = pending_emails[email_id]
            msg = _fetch_message_safely(email_id, email_data.get("message_obj"))
            if msg is None:
                _remove_from_pending(email_id)
                processed_messages.add(email_id)
                return jsonify({"status": "success", "message": "Email no longer exists; removed from queue"})
            print(f"❌ Email rejected: {email_data['subject']} - Reason: {reason}")

            # Compose a new email to reviewer with reason and original content (not a forward)
            try:
                # Send a clean note with reason + original content (stripped of quoted history)
                note = mailbox.new_message()
                note.to.add([REVIEW_NOTIFY_EMAIL])
                subj = (msg.subject or '').strip() or '(no subject)'
                note.subject = f"Rejected: {subj}"
                note.body_type = 'HTML'
                safe_reason = (reason or '').replace('\n', '<br>')
                clean_text = get_clean_message_text(msg) or ''
                # Escape to keep the composed HTML safe
                safe_text = (clean_text.replace('&', '&amp;')
                                       .replace('<', '&lt;')
                                       .replace('>', '&gt;'))
                # Include some metadata for quick triage
                from_addr = ''
                try:
                    from_addr = (msg.sender.address or '').strip()
                except Exception:
                    pass
                classification = email_data.get("classification") if isinstance(email_data, dict) else None
                categories = ""
                try:
                    if isinstance(classification, dict):
                        cats = classification.get("categories") or []
                        if isinstance(cats, list):
                            categories = ", ".join([str(c) for c in cats if c])
                except Exception:
                    categories = ""
                received_str = ''
                try:
                    if getattr(msg, 'received', None):
                        received_str = msg.received.strftime('%Y-%m-%d %H:%M')
                except Exception:
                    pass
                note.body = (
                    "<div style='font-family:Inter,Segoe UI,Arial,sans-serif;font-size:14px;color:#0d1117'>"
                    f"<p><strong>Reason:</strong> {safe_reason or 'No details provided.'}</p>"
                    f"<p><strong>From:</strong> {from_addr or 'Unknown'}<br>"
                    f"<strong>Subject:</strong> {subj}<br>"
                    f"<strong>Received:</strong> {received_str or 'Unknown'}<br>"
                    f"<strong>Classified as:</strong> {categories or 'Unknown'}</p>"
                    f"<h4 style='margin:12px 0 6px 0;'>Original content</h4>"
                    f"<pre style='white-space:pre-wrap;background:#f6f8fa;padding:12px;border-radius:6px;border:1px solid #d0d7de'>{safe_text}</pre>"
                    "</div>"
                )
                note.send()
                print("📤 Sent rejection reason + original content to reviewer")
            except Exception as e:
                print(f"⚠️ Could not send rejection note: {e}")

            # Move rejected email to special folder
            try:
                inbox = mailbox.inbox_folder()
                rejected_folder = None

                # Try to find existing "declined" folder
                try:
                    rejected_folder = inbox.get_folder(folder_name="declined")
                    print(f"📁 Found existing 'declined' folder")
                except:
                    try:
                        rejected_folder = inbox.get_folder(folder_name="Declined")
                        print(f"📁 Found existing 'Declined' folder")
                    except:
                        print(f"⚠️ Could not find 'declined' or 'Declined' folder")

                # Move the email to rejected folder
                if rejected_folder:
                    try:
                        msg.move(rejected_folder)
                        print(f"📁 Moved email to 'declined' folder")
                    except Exception as e:
                        print(f"⚠️ Could not move email to rejected folder: {e}")

                # Just mark as processed without adding new tags
                try:
                    existing_cats = set(msg.categories or [])
                    existing_cats.add("PAIRActioned")  # Only add the standard processed marker
                    msg.categories = sorted(existing_cats)
                    msg.save_message()
                    print(f"📋 Marked email as processed (rejected)")
                except Exception as e:
                    print(f"⚠️ Could not update email categories: {e}")

                # Mark as read and add to processed messages to prevent reprocessing
                try:
                    mark_as_read(msg)
                    dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
                    processed_messages.add(dedup_key)
                    processed_messages.add(email_id)  # Also add the email_id itself
                    print(f"✅ Marked email as processed")
                except Exception as e:
                    print(f"⚠️ Could not mark as processed: {e}")

            except Exception as e:
                print(f"❌ Error handling rejected email: {e}")

            # Remove from pending emails
            _remove_from_pending(email_id)

        return jsonify({"status": "success", "message": f"Email rejected: {reason}"})
    except Exception as e:
        print(f"❌ Error rejecting email {email_id}: {e}")
        return jsonify({"status": "error", "message": f"Server error while rejecting: {e}"}), 500


@app.route('/api/emails/<email_id>/dismiss', methods=['POST'])
@login_required
def dismiss_email(email_id):
    """Dismiss an email from the approval queue without forwarding or replying.
    Marks it as processed (PAIRActioned) and read to prevent reappearance.
    """
    try:
        email_data = pending_emails.get(email_id)
        if not email_data:
            return jsonify({"status": "success", "message": "Already dismissed"})

        msg = _fetch_message_safely(email_id, email_data.get("message_obj"))
        if msg is None:
            _remove_from_pending(email_id)
            processed_messages.add(email_id)
            return jsonify({"status": "success", "message": "Email no longer exists; removed from queue"})

        # Best effort: mark processed and read, but never fail the request
        try:
            tag_email(msg, ["dismissed"], replyTag=False)
        except Exception:
            pass
        try:
            mark_as_read(msg)
        except Exception:
            pass
        try:
            dedup_key = getattr(msg, 'internet_message_id', None) or msg.object_id
            processed_messages.add(dedup_key)
            processed_messages.add(email_id)
        except Exception:
            pass

        _remove_from_pending(email_id)
        return jsonify({"status": "success", "message": "Email dismissed"})
    except Exception as e:
        # On any unexpected error, still remove from queue and return success
        try:
            _remove_from_pending(email_id)
            processed_messages.add(email_id)
        except Exception:
            pass
        print(f"⚠️ Dismiss encountered error but continued: {e}")
        return jsonify({"status": "success", "message": "Email dismissed"})


def start_web_server():
    """Start the Flask web server in a separate thread"""
    def run_server():
        print("🌐 Starting approval hub at http://localhost:5000")
        port = int(os.getenv("PORT", "5000"))
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()


# Start the web server
start_web_server()

inbox_delta, junk_delta = load_last_delta()
print(f"Monitoring inbox + junk for: {EMAIL_TO_WATCH} … Ctrl-C to stop.")
print(f"📧 Approval hub available at: http://localhost:5000")

# ---- Robust helpers for approval actions ----
def _fetch_message_safely(email_id: str, fallback_msg=None):
    """Try to fetch a message reliably by id; fall back to stored object.
    Returns a hydrated message object or None if not retrievable (deleted/moved).
    """
    msg = None
    # First try direct fetch by id
    try:
        msg = mailbox.get_message(object_id=email_id)
        if msg:
            try:
                msg.refresh()
            except Exception:
                pass
            return msg
    except Exception as e:
        # Known case: 404 from Graph for missing item
        err = str(e)
        if ('404' in err) or ('Not Found' in err) or ('object was not found' in err):
            msg = None
        # For other errors, still fall through to fallback

    # Fallback to stored object if any, but treat 404 refresh as missing
    try:
        if fallback_msg is not None:
            try:
                fallback_msg.refresh()
            except Exception as e:
                err = str(e)
                if ('404' in err) or ('Not Found' in err) or ('object was not found' in err) or ('The specified object was not found' in err):
                    return None
            return fallback_msg
    except Exception:
        pass

    return None

def _remove_from_pending(email_id: str):
    try:
        if email_id in pending_emails:
            del pending_emails[email_id]
            return True
        return False
    except Exception:
        return False

# One-time backfill to catch older-but-unread messages since PROCESS_SINCE
_did_backfill = False

while True:
    # Proactively refresh authentication on an interval
    ensure_account_fresh()
    print(f"🔄 Checking for new emails... (Pending: {len(pending_emails)}, Processed: {len(processed_messages)})")
    # Perform backfill once per run
    if not _did_backfill:
        try:
            total_bf = 0
            total_bf += backfill_unread_since(inbox_folder, "Inbox", PROCESS_SINCE, max_pages=BACKFILL_MAX_PAGES)
            total_bf += backfill_unread_since(junk_folder, "JunkEmail", PROCESS_SINCE, max_pages=BACKFILL_MAX_PAGES)
            if total_bf == 0:
                # As last resort, scan entire mailbox
                total_bf += backfill_mailbox_since(PROCESS_SINCE, max_pages=BACKFILL_MAX_PAGES)
            _did_backfill = True
            if total_bf:
                print(f"🧹 Backfill completed, processed {total_bf} message(s).")
        except Exception as e:
            print(f"⚠️ Backfill run error: {e}")
    # Prefer delta processing for large mailboxes
    inbox_delta = process_folder_via_delta(inbox_folder, "Inbox", inbox_delta)
    junk_delta = process_folder_via_delta(junk_folder, "JunkEmail", junk_delta)
    #gets the new delta tokens and then saves them,
    save_last_delta(inbox_delta, junk_delta)
    # Also save processed messages regularly
    save_processed_messages()
    time.sleep(10)
