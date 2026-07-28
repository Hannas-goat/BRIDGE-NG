import base64
import datetime
import hashlib
import hmac
import html
import http.server
import io
import json
import mimetypes
import os
import re
import secrets
import socketserver
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.fernet import Fernet, InvalidToken

# On hosts like Render, stdout isn't a real terminal, so Python block-buffers print() output
# instead of flushing per line — logs can end up delayed indefinitely or never show up at all.
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "bridgeng.db")
PORT = int(os.environ.get("PORT", 8000))

STATIC_FILES = {"index.html", "auth.html", "shared.js", "styles.css", "admin-jobs-sync.html", "privacy.html", "terms.html",
                 "about.html", "careers.html", "support.html", "contact.html", "pricing.html"}
STATIC_DIRS = {"images"}

PBKDF2_ITERATIONS = 200_000
SESSION_COOKIE = "bridge_session"
# Separate cookie from the candidate session — the same person could plausibly hold both a
# candidate account and an employer account, so the two identities are kept fully independent
# rather than trying to overload one session/cookie for both roles.
EMPLOYER_SESSION_COOKIE = "bridge_employer_session"
SESSION_TTL_SECONDS = 7 * 24 * 3600  # a stolen/leaked cookie shouldn't work forever

# Field-level encryption for PII at rest (profile name/DOB/sex/phone/address/resume), so a raw
# database file leak doesn't hand over readable personal data — only password verification
# (already PBKDF2-hashed, separately) needs no key at all. Fernet is AES-128-CBC + HMAC, which is
# fine for this: values are looked up by user_id (never searched/filtered on), so there's no need
# for a searchable/deterministic scheme, just confidentiality + tamper-evidence.
#
# ENCRYPTION_KEY MUST be set (and persisted) in any real deployment. Without it, this generates a
# fresh key for this process only — anything encrypted under it becomes unreadable the moment the
# process restarts, which is only acceptable for local/throwaway dev.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode("ascii")
    print("WARNING: ENCRYPTION_KEY is not set. Generated a temporary key for THIS PROCESS ONLY — "
          "set ENCRYPTION_KEY to a persisted value (e.g. Fernet.generate_key()) in your environment, "
          "or previously-encrypted profile data will become unreadable on the next restart.")
_fernet = Fernet(ENCRYPTION_KEY.encode("ascii") if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

ENCRYPTED_PROFILE_COLUMNS = (
    "full_name", "dob", "sex", "phone", "address",
    "resume_text", "resume_filename", "resume_file_base64",
    "pitch_media_base64", "whatsapp_number",
)


def encrypt_field(value):
    if not value:
        return value or ""
    return _fernet.encrypt(value.encode("utf-8")).decode("ascii")


def is_encrypted_field(value):
    if not value:
        return True  # nothing to decrypt, so it's not "still plaintext" either
    try:
        _fernet.decrypt(value.encode("ascii"))
        return True
    except (InvalidToken, ValueError, UnicodeEncodeError):
        return False


def _looks_like_fernet_token(value):
    # Fernet.decrypt() raises the same InvalidToken for "wrong/rotated key" and "not a token at
    # all" — it doesn't distinguish them. Structurally, a real token is base64url of >= 57 bytes
    # (1 version + 8 timestamp + 16 IV + ciphertext + 32 HMAC) starting with the version byte 0x80.
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception:
        return False
    return len(raw) >= 57 and raw[0:1] == b"\x80"


def decrypt_field(value):
    if not value:
        return value or ""
    try:
        return _fernet.decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeEncodeError, UnicodeDecodeError):
        if _looks_like_fernet_token(value):
            # This really was encrypted at some point but isn't readable with the CURRENT
            # ENCRYPTION_KEY (almost always: the key was never persisted and rotated on a
            # restart). Showing the raw ciphertext would be confusing and would still leak that
            # PII exists there — show nothing instead of garbage. The data itself is genuinely
            # unrecoverable; the affected field will just read as blank until re-entered.
            return ""
        # Doesn't even look like a token — genuine pre-migration plaintext, safe to show as-is.
        return value


# ---------- brute-force lockout ----------
# Repeated failed logins against one account lock it out AND kill every currently-active session
# for that account — someone guessing a password is treated the same as someone who already has a
# stolen-but-valid session cookie; both lose access immediately rather than just being slowed down.
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60

login_attempts_lock = threading.Lock()
failed_login_attempts = {}  # email -> [failure timestamps within the current window]
account_lockouts = {}  # email -> unix time the lockout lifts


def is_account_locked(email):
    with login_attempts_lock:
        unlock_time = account_lockouts.get(email)
        if unlock_time and time.time() < unlock_time:
            return True
        if unlock_time:
            del account_lockouts[email]
            failed_login_attempts.pop(email, None)
        return False


def record_failed_login(email):
    """Returns True the moment this failure is the one that trips the lockout threshold."""
    now = time.time()
    with login_attempts_lock:
        attempts = [t for t in failed_login_attempts.get(email, []) if now - t < LOGIN_ATTEMPT_WINDOW_SECONDS]
        attempts.append(now)
        failed_login_attempts[email] = attempts
        if len(attempts) >= LOGIN_ATTEMPT_LIMIT:
            account_lockouts[email] = now + LOGIN_LOCKOUT_SECONDS
            return True
    return False


def clear_failed_logins(email):
    with login_attempts_lock:
        failed_login_attempts.pop(email, None)
        account_lockouts.pop(email, None)

# NVIDIA's build.nvidia.com API catalog is OpenAI-compatible and grants free trial credits on
# signup — no live web search available, so job lookups are best-effort from pasted text only.
# WhatsApp alerts via Twilio's WhatsApp API — same "closed until an operator opts in" pattern as
# NVIDIA_API_KEY below. Unset by default; sends silently no-op (logged, not raised) until a real
# Twilio account is configured, since a candidate's own alert preference shouldn't error out just
# because the operator hasn't set this up yet.
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_FROM = os.environ.get("TWILIO_WHATSAPP_FROM")  # e.g. "whatsapp:+14155238886"
WHATSAPP_CONFIGURED = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_WHATSAPP_FROM)


# Zoom Server-to-Server OAuth — same "closed until an operator opts in" pattern. Without these,
# scheduling still works via a standard .ics calendar file (needs no API keys, opens in any
# calendar app); a real Zoom link is added on top only when configured.
ZOOM_ACCOUNT_ID = os.environ.get("ZOOM_ACCOUNT_ID")
ZOOM_CLIENT_ID = os.environ.get("ZOOM_CLIENT_ID")
ZOOM_CLIENT_SECRET = os.environ.get("ZOOM_CLIENT_SECRET")
ZOOM_CONFIGURED = bool(ZOOM_ACCOUNT_ID and ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET)


# Paystack — same "closed until an operator opts in" pattern as the integrations above. Bridge NG
# never touches a card number: PAYSTACK_SECRET_KEY only ever calls server-to-server endpoints
# (initialize a transaction, resolve a bank account, verify a webhook signature); the actual card
# entry happens entirely on Paystack's own hosted checkout page. PAYSTACK_PLAN_CODE_PRO_GROWTH is
# a Plan object that has to be created once in the Paystack dashboard (or via their API) before
# recurring billing can reference it — there's no way to fabricate a working one from here.
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
PAYSTACK_PLAN_CODE_PRO_GROWTH = os.environ.get("PAYSTACK_PLAN_CODE_PRO_GROWTH")
PAYSTACK_WEBHOOK_SECRET = os.environ.get("PAYSTACK_WEBHOOK_SECRET")  # Paystack signs webhooks with the secret key itself, but a separate var lets it be rotated independently
PAYSTACK_CONFIGURED = bool(PAYSTACK_SECRET_KEY)
PRO_GROWTH_MONTHLY_NGN = 90000
PRO_GROWTH_ANNUAL_NGN = 864000  # 12 * 90,000 * 0.8 — two months free, same discount shown on the pricing page


def call_paystack(method, path, data=None, timeout=20):
    """Raw REST call to Paystack's API — no SDK, matching every other integration in this file.
    Raises urllib.error.HTTPError on a non-2xx response; callers already handle that the same way
    they handle every other external call here."""
    req = urllib.request.Request(
        f"https://api.paystack.co{path}",
        data=json.dumps(data).encode("utf-8") if data is not None else None,
        headers={
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


NIGERIAN_BANKS = [
    {"name": "Access Bank", "code": "044"}, {"name": "Citibank Nigeria", "code": "023"},
    {"name": "Ecobank Nigeria", "code": "050"}, {"name": "Fidelity Bank", "code": "070"},
    {"name": "First Bank of Nigeria", "code": "011"}, {"name": "First City Monument Bank", "code": "214"},
    {"name": "Globus Bank", "code": "00103"}, {"name": "Guaranty Trust Bank", "code": "058"},
    {"name": "Heritage Bank", "code": "030"}, {"name": "Keystone Bank", "code": "082"},
    {"name": "Kuda Bank", "code": "50211"}, {"name": "Moniepoint MFB", "code": "50515"},
    {"name": "Opay", "code": "999992"}, {"name": "Palmpay", "code": "999991"},
    {"name": "Polaris Bank", "code": "076"}, {"name": "Providus Bank", "code": "101"},
    {"name": "Stanbic IBTC Bank", "code": "221"}, {"name": "Standard Chartered Bank", "code": "068"},
    {"name": "Sterling Bank", "code": "232"}, {"name": "Union Bank of Nigeria", "code": "032"},
    {"name": "United Bank for Africa", "code": "033"}, {"name": "Unity Bank", "code": "215"},
    {"name": "Wema Bank", "code": "035"}, {"name": "Zenith Bank", "code": "057"},
]


def create_zoom_meeting(topic, start_iso, duration_minutes=30):
    """Best-effort: returns a real Zoom join URL if configured and successful, else None.
    Never raises — callers treat a missing link as 'no Zoom link available', not an error."""
    if not ZOOM_CONFIGURED:
        return None
    try:
        auth = base64.b64encode(f"{ZOOM_CLIENT_ID}:{ZOOM_CLIENT_SECRET}".encode("utf-8")).decode("ascii")
        token_req = urllib.request.Request(
            f"https://zoom.us/oauth/token?grant_type=account_credentials&account_id={ZOOM_ACCOUNT_ID}",
            method="POST",
        )
        token_req.add_header("Authorization", f"Basic {auth}")
        with urllib.request.urlopen(token_req, timeout=10) as resp:
            access_token = json.loads(resp.read().decode("utf-8"))["access_token"]

        meeting_payload = json.dumps({
            "topic": topic, "type": 2, "start_time": start_iso, "duration": duration_minutes,
            "settings": {"join_before_host": True, "approval_type": 2},
        }).encode("utf-8")
        meeting_req = urllib.request.Request(
            "https://api.zoom.us/v2/users/me/meetings", data=meeting_payload, method="POST",
        )
        meeting_req.add_header("Authorization", f"Bearer {access_token}")
        meeting_req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(meeting_req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8")).get("join_url")
    except Exception as e:
        print(f"[zoom] Failed to create meeting: {e}")
        return None


def build_ics_invite(uid, summary, description, start_dt, duration_minutes=30, location=""):
    """A minimal, standards-compliant iCalendar VEVENT — opens in any real calendar app
    (Google Calendar, Outlook, Apple Calendar), no API keys or third-party service needed."""
    def fmt(dt):
        return dt.strftime("%Y%m%dT%H%M%S")
    end_dt = start_dt + datetime.timedelta(minutes=duration_minutes)
    escaped_desc = (description or "").replace("\\", "\\\\").replace("\n", "\\n").replace(",", "\\,").replace(";", "\\;")
    escaped_summary = (summary or "").replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;")
    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Bridge NG//Interview Scheduler//EN",
        "BEGIN:VEVENT",
        f"UID:{uid}@bridgeng",
        f"DTSTAMP:{fmt(datetime.datetime.utcnow())}Z",
        f"DTSTART:{fmt(start_dt)}",
        f"DTEND:{fmt(end_dt)}",
        f"SUMMARY:{escaped_summary}",
    ]
    if location:
        lines.append(f"LOCATION:{location}")
    if escaped_desc:
        lines.append(f"DESCRIPTION:{escaped_desc}")
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines) + "\r\n"


def send_whatsapp_alert(to_number, body):
    """Best-effort: never raises. No-ops silently if Twilio isn't configured, or if the
    candidate hasn't provided/opted into a WhatsApp number."""
    if not WHATSAPP_CONFIGURED or not to_number:
        return
    try:
        payload = urllib.parse.urlencode({
            "From": TWILIO_WHATSAPP_FROM,
            "To": f"whatsapp:{to_number}",
            "Body": body,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json",
            data=payload, method="POST",
        )
        auth = base64.b64encode(f"{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}".encode("utf-8")).decode("ascii")
        req.add_header("Authorization", f"Basic {auth}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as e:
        print(f"[whatsapp] Failed to send alert: {e}")


NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY")
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "meta/llama-3.2-11b-vision-instruct")
# A bigger, more capable model for the resume/cover-letter writing itself (the part users actually
# read and download). Not every NVIDIA account has access to every catalog model, and bigger
# models can be slow, so this is tried first (with a longer timeout) and falls back to NVIDIA_MODEL
# on any failure — wrong/inaccessible model name or timeout alike — rather than erroring out.
NVIDIA_RESUME_MODEL = os.environ.get("NVIDIA_RESUME_MODEL", "meta/llama-3.2-90b-vision-instruct")
NVIDIA_CHAT_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    import libsql_client
except ImportError:
    libsql_client = None

# Optional: Turso (libSQL) for a database that survives redeploys. Render's free tier has no
# persistent disk, so bridgeng.db normally resets to empty on every deploy. Set both env vars to
# switch persistence to Turso instead; leave unset to keep using the local sqlite3 file as before.
TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
USE_TURSO = bool(TURSO_DATABASE_URL and TURSO_AUTH_TOKEN and libsql_client)

# Shared secret required to import jobs (POST /api/jobs/import). Unset by default so the
# endpoint is closed until an operator deliberately opts in — same pattern as NVIDIA_API_KEY.
IMPORT_TOKEN = os.environ.get("IMPORT_TOKEN")

CHAT_FALLBACK_MESSAGE = "Bridge AI is having trouble answering right now. Please try again in a moment."

CAREER_MATCH_SYSTEM_PROMPT = """You are "NaijaCareer AI," an intelligent, highly localized career and educational path matching engine designed specifically for Nigerian students, fresh graduates, and early-career professionals. Your objective is to behave like a global opportunity matching tool (similar to Jakpar) but optimized natively for the Nigerian educational and professional landscape.

When a user submits their academic profile, skill list, and professional objectives, you must perform three main functions:
1. International & Local Opportunity Matching (Scholarships, Admissions, Global Remote Jobs, Visas).
2. Localized Educational Alignment (Accounting for Nigerian university systems, grading structures, and the NYSC cycle).
3. Skill Gap Analysis & Upskilling Recommendations.

CRITICAL LOCALIZATION RULES FOR NIGERIA:
- GRADING SYSTEMS: Correctly interpret Nigerian university classification brackets. Translate a 5.0 CGPA scale or 4.0 CGPA scale accurately against global requirements (e.g., mapping a First Class, Second Class Upper [2:1], or Second Class Lower [2:2] to equivalent US/UK GPA standards or European grading requirements).
- NYSC STATUS: Factor in the National Youth Service Corps (NYSC). If the user is currently a "corper" or a fresh graduate, prioritize entry-level roles, graduate trainee programs, or global master's scholarships that align with their completion timeline. Do not recommend local full-time executive tracks to active corpers.
- FINANCIAL & TEST CONSTRAINTS: Proactively segment scholarship recommendations. Flag opportunities that do NOT require IELTS/TOEFL (leveraging English-taught background certificates from Nigerian universities) or those that offer full funding/stipends, as foreign exchange volatility is a significant factor for Nigerian applicants.
- POPULAR FIELDS: Pay close attention to high-density Nigerian professional sectors like Tech (Software/Data), Finance/Fintech, Healthcare, and Engineering, matching them against remote-friendly global work or fully-funded migration pathways.

OUTPUT STRUCTURE REQUIREMENT:
For every user profile input, structure your response into the following clear segments, using "### " for each segment heading and "- " for each list item so it renders correctly:

### 1. Recommended Pathways & Matches
- Scholarships/Fellowships: List 2-3 specific global scholarships (e.g., Commonwealth, Mastercard Foundation, Chevening, DAAD) they qualify for based on their current degree classification.
- Global Remote & Local Jobs: Identify 2-3 specific global entry-level tech/corporate job titles or specialized programs (like localized graduate trainee tracks) they should target.
- Visa/Migration Trajectories: Suggest the most straightforward visa routes based on their skillset (e.g., UK Global Talent Visa, Canadian Express Entry tech streams, or student routes).

### 2. Skill Gap & Profile Analysis
- Identify what their target international profiles/jobs have that their current profile lacks.
- Call out specific technical skills, professional certifications (e.g., ICAN for finance, AWS/Azure for tech), or portfolio necessities.

### 3. Actionable Next Steps
- Provide exactly 3 short, punchy, immediate actions they can take this week to make their profile competitive (e.g., "Draft your Statement of Purpose focusing on X project," "Enroll in a specific free AI/Tech certification route," "Optimize your CV format to bypass global ATS filters").

TONE:
Encouraging, professional, street-smart yet authoritative. Use universal, accessible English, avoiding hyper-complex jargon. Do not use "##" (only "###"), numbered-list markdown, tables, or code fences — plain "### " headings and "- " bullets only, so the output renders correctly."""

# Public, unauthenticated job-board APIs — no account/API key needed for either.
GREENHOUSE_JOBS_URL = "https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true"
LEVER_JOBS_URL = "https://api.lever.co/v0/postings/{slug}?mode=json"
SYNC_FALLBACK_MESSAGE = "Couldn't sync jobs from that board right now. Double-check the company slug and try again."

# Real Nigerian/Africa-based companies with verified public Greenhouse/Lever boards
# (confirmed live and returning real postings — not every Nigerian company runs one of
# these two ATS platforms, so this is a starting set, not "every job in Nigeria"). Most
# Nigerian companies simply don't have a public Greenhouse/Lever board to sync from — this
# was checked against ~110 real company slugs; oneacrefund and jumia were the only additional
# genuine hits. oneacrefund in particular currently has real listings in Bauchi, Nasarawa,
# and Niger states, which is why it's included even though it's not Nigeria-headquartered.
# Add more as "ats:slug" pairs, comma-separated, via the AUTO_SYNC_COMPANIES env var,
# or just leave the default — it's already a real, working list.
DEFAULT_AUTO_SYNC_COMPANIES = "greenhouse:moniepoint,greenhouse:carbon,greenhouse:oneacrefund,greenhouse:jumia"
AUTO_SYNC_COMPANIES = os.environ.get("AUTO_SYNC_COMPANIES", DEFAULT_AUTO_SYNC_COMPANIES)

# Real, verified remote-first global companies (open to hiring from anywhere, including
# the Nigerian diaspora) — for the explicit "I want to work remotely" signup preference.
DEFAULT_AUTO_SYNC_REMOTE_COMPANIES = "greenhouse:gitlab,greenhouse:mozilla,greenhouse:webflow,greenhouse:postscript"
AUTO_SYNC_REMOTE_COMPANIES = os.environ.get("AUTO_SYNC_REMOTE_COMPANIES", DEFAULT_AUTO_SYNC_REMOTE_COMPANIES)

AUTO_SYNC_INTERVAL_HOURS = float(os.environ.get("AUTO_SYNC_INTERVAL_HOURS", "6"))

# Duplicated from shared.js SKILLS — used only for lightweight keyword-based skill
# extraction out of synced job descriptions (Greenhouse/Lever don't provide structured skills).
PY_SKILLS = ["JavaScript", "Python", "SQL", "Data Analysis", "Excel", "Software Development", "Cloud Computing",
             "Accounting", "Financial Modeling", "Digital Marketing", "Content Writing", "Graphic Design", "UI/UX Design",
             "Social Media Management", "Civil Engineering", "Mechanical Engineering", "Electrical Engineering",
             "Renewable Energy", "Project Management", "Customer Service", "Sales", "Business Development",
             "Supply Chain", "Procurement", "Logistics", "Agronomy", "Nursing", "Pharmacy", "Medical Lab Science",
             "Human Resources", "Recruiting", "Networking", "Cybersecurity", "Petroleum Engineering", "Teaching",
             "Legal Practice", "Hospitality Management", "Public Administration", "Architecture", "Quantity Surveying",
             "Insurance Underwriting", "Banking Operations", "Journalism", "Video Editing"]

db_lock = threading.Lock()


def create_session(user_id):
    token = secrets.token_hex(24)
    with db_lock:
        conn = get_db()
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, time.time() + SESSION_TTL_SECONDS),
        )
        conn.commit()
        conn.close()
    return token


def create_employer_session(employer_id):
    token = secrets.token_hex(24)
    with db_lock:
        conn = get_db()
        conn.execute(
            "INSERT INTO employer_sessions (token, employer_id, expires_at) VALUES (?, ?, ?)",
            (token, employer_id, time.time() + SESSION_TTL_SECONDS),
        )
        conn.commit()
        conn.close()
    return token


def revoke_sessions_for_user(user_id):
    """'Disconnects' an account's data from the site — every currently-active session tied to
    that user_id is killed, so a session cookie that was already valid (stolen or otherwise)
    stops working immediately. Used when repeated failed logins suggest someone other than the
    account owner is trying to get in."""
    with db_lock:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()

# Recent AI-call failures (capped), for the /api/debug/ai-errors endpoint — a direct way to see
# why a resume-tailoring/job-lookup call failed without having to find the right line in Render's
# log viewer, whose time-range filter can silently cut off the moment you actually care about.
ai_error_lock = threading.Lock()
LAST_AI_ERRORS = []


def record_ai_error(source, model, status, detail):
    with ai_error_lock:
        LAST_AI_ERRORS.append({
            "time": datetime.datetime.utcnow().isoformat() + "Z",
            "source": source, "model": model, "status": status, "detail": detail[:500],
        })
        del LAST_AI_ERRORS[:-15]

# The mobile app's WebView can't turn a client-side Blob (jsPDF/docx output) into a real device
# download — Android's WebView only hands a download off to the OS when it's a genuine HTTP
# response with a Content-Disposition header, not an in-page blob: URL. So for the app, the
# already-generated file is base64-posted here, held briefly in memory, and served back as a
# real downloadable URL. Not popped on read (in case the WebView's own probe request and the
# follow-up Linking.openURL both hit it) — a short TTL is enough since the token is unguessable.
download_relay_lock = threading.Lock()
DOWNLOAD_RELAY = {}
DOWNLOAD_RELAY_TTL_SECONDS = 300
MAX_DOWNLOAD_RELAY_BYTES = 15 * 1024 * 1024
MAX_SAVED_RESUME_BYTES = 8 * 1024 * 1024
MAX_PITCH_MEDIA_BYTES = 15 * 1024 * 1024


def _prune_download_relay():
    now = time.time()
    for token in [t for t, entry in DOWNLOAD_RELAY.items() if entry["expires"] < now]:
        del DOWNLOAD_RELAY[token]

_turso_client = None
_turso_client_lock = threading.Lock()


def _turso_http_url(url):
    """libsql_client defaults libsql:// URLs to a WebSocket connection (wss://), which can fail
    the handshake behind some platforms' networking (seen on Render: WSServerHandshakeError 400).
    Using the plain HTTP-based protocol instead is more universally compatible and doesn't need a
    persistent connection upgrade — same database, just a different transport."""
    if url.startswith("libsql://"):
        return "https://" + url[len("libsql://"):]
    return url


def _get_turso_client():
    """Lazily creates one shared libsql_client connection for the whole process. Spinning up a
    new client per request would open a new background thread each time (expensive and
    pointless), so every caller reuses this same client instead."""
    global _turso_client
    if _turso_client is None:
        with _turso_client_lock:
            if _turso_client is None:
                _turso_client = libsql_client.create_client_sync(
                    url=_turso_http_url(TURSO_DATABASE_URL), auth_token=TURSO_AUTH_TOKEN
                )
    return _turso_client


class TursoCursor:
    """Shim so conn.execute(...).fetchall()/.fetchone() and cur.lastrowid keep working exactly
    like they did with sqlite3, backed by libsql_client's ResultSet. libsql_client's own Row type
    already supports row["col"] / row[0] access the same way sqlite3.Row does, so rows need no
    further wrapping."""
    def __init__(self, result_set):
        self._result_set = result_set
        self.lastrowid = result_set.last_insert_rowid

    def fetchall(self):
        return list(self._result_set.rows)

    def fetchone(self):
        rows = self._result_set.rows
        return rows[0] if rows else None


class TursoConnection:
    """Wraps the shared libsql_client connection so it's a drop-in replacement for a
    sqlite3.Connection everywhere else in this file — conn.execute(sql, params), conn.commit(),
    conn.close() all keep working unchanged, whichever backend is actually in use."""
    def __init__(self, client):
        self._client = client

    def execute(self, sql, params=()):
        return TursoCursor(self._client.execute(sql, list(params)))

    def commit(self):
        pass  # each statement is already committed individually over Turso's API

    def close(self):
        pass  # the underlying client is shared across requests and stays open for the process


def is_duplicate_key_error(e):
    """True if `e` represents a UNIQUE-constraint violation, under either sqlite3 (local dev)
    or libsql_client/Turso — the two backends raise different exception types (sqlite3.IntegrityError
    vs libsql_client.LibsqlError) for the same underlying condition, so callers that only checked
    for sqlite3.IntegrityError would let a Turso duplicate-key error crash the request uncaught."""
    if isinstance(e, sqlite3.IntegrityError):
        return True
    if libsql_client and isinstance(e, libsql_client.LibsqlError):
        return "UNIQUE" in str(e)
    return False


def get_db():
    if USE_TURSO:
        return TursoConnection(_get_turso_client())
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY REFERENCES users(id),
            full_name TEXT DEFAULT '',
            dob TEXT DEFAULT '',
            sex TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            address TEXT DEFAULT '',
            education TEXT DEFAULT '',
            career_level TEXT DEFAULT '',
            field_of_study TEXT DEFAULT '',
            preferred_location TEXT DEFAULT '',
            skills TEXT DEFAULT '[]',
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS imported_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            company TEXT NOT NULL,
            location TEXT DEFAULT '',
            level TEXT DEFAULT '',
            sector TEXT DEFAULT '',
            skills TEXT DEFAULT '[]',
            pay_min INTEGER DEFAULT 0,
            pay_max INTEGER DEFAULT 0,
            description TEXT DEFAULT '',
            application_link TEXT DEFAULT '',
            posted_date TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS saved_searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            label TEXT DEFAULT '',
            skills TEXT DEFAULT '[]',
            level TEXT DEFAULT '',
            location TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS followed_companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            company TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(user_id, company)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            kind TEXT NOT NULL,
            message TEXT NOT NULL,
            job_title TEXT DEFAULT '',
            company TEXT DEFAULT '',
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            company TEXT NOT NULL,
            role TEXT DEFAULT '',
            appt_date TEXT NOT NULL,
            appt_time TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'requested',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    ensure_column(conn, "appointments", "zoom_join_url", "zoom_join_url TEXT DEFAULT ''")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_user_id INTEGER NOT NULL REFERENCES users(id),
            company TEXT NOT NULL,
            job_title TEXT DEFAULT '',
            employer_token TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL REFERENCES conversations(id),
            sender_role TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            read_by_candidate INTEGER NOT NULL DEFAULT 0,
            read_by_employer INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS salary_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT NOT NULL,
            role_title TEXT NOT NULL,
            level TEXT DEFAULT '',
            monthly_pay INTEGER NOT NULL,
            has_housing_allowance INTEGER NOT NULL DEFAULT 0,
            has_transport_allowance INTEGER NOT NULL DEFAULT 0,
            culture_rating INTEGER NOT NULL,
            review_text TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checkins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            checkin_date TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(user_id, checkin_date)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            job_title TEXT NOT NULL,
            company TEXT NOT NULL,
            application_link TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(user_id, job_title, company)
        )
    """)
    ensure_column(conn, "applications", "status", "status TEXT NOT NULL DEFAULT 'applied'")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS employer_posted_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            company TEXT NOT NULL,
            level TEXT DEFAULT '',
            location TEXT DEFAULT '',
            skills TEXT DEFAULT '[]',
            pay_min INTEGER DEFAULT 0,
            pay_max INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    # Sessions used to live in an in-memory dict, which meant every server restart (every deploy,
    # and on Render's free tier every idle-spindown too) silently signed every single user out —
    # the cookie in their browser was still there, just no longer recognized by the new process.
    # Storing them here instead means they survive a restart exactly as long as the database does.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            expires_at REAL NOT NULL
        )
    """)
    # Real employer accounts — the rest of the employer side (handle_post_employer_job etc.) has
    # deliberately never had login, since posting a job and viewing matches didn't need a durable
    # identity. A paid subscription does: something has to persist "who is Pro Growth" across
    # sessions, so this is the first real auth surface on the employer side of the app.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS employers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            company_name TEXT NOT NULL,
            corporate_domain TEXT DEFAULT '',
            paystack_customer_code TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS employer_sessions (
            token TEXT PRIMARY KEY,
            employer_id INTEGER NOT NULL REFERENCES employers(id),
            expires_at REAL NOT NULL
        )
    """)
    # tier: 'sme_starter' | 'pro_growth' | 'enterprise'. status/billing_cycle/period fields are
    # never set by the client — they only ever change from a verified Paystack webhook event
    # (see handle_paystack_webhook), so "is this employer actually paying" can't be spoofed by
    # calling the API directly.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employer_id INTEGER NOT NULL REFERENCES employers(id),
            tier TEXT NOT NULL DEFAULT 'sme_starter',
            status TEXT NOT NULL DEFAULT 'inactive',
            billing_cycle TEXT DEFAULT '',
            paystack_subscription_code TEXT DEFAULT '',
            paystack_email_token TEXT DEFAULT '',
            current_period_end TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(employer_id)
        )
    """)
    # Tier limits are enforced by counting rows here, not by trusting a client-sent count —
    # period_key groups usage by calendar month (e.g. "2026-07") so limits reset naturally.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feature_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employer_id INTEGER NOT NULL REFERENCES employers(id),
            period_key TEXT NOT NULL,
            job_posts_count INTEGER NOT NULL DEFAULT 0,
            whatsapp_messages_count INTEGER NOT NULL DEFAULT 0,
            UNIQUE(employer_id, period_key)
        )
    """)
    # account_number/account_name are real bank PII (NUBAN-resolvable to a real person/company) —
    # encrypted at rest with the exact same encrypt_field() used for candidate PII, never the
    # client-submitted account_name, only whatever Paystack's /bank/resolve actually returned.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bank_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employer_id INTEGER NOT NULL REFERENCES employers(id),
            bank_code TEXT NOT NULL,
            bank_name TEXT NOT NULL,
            account_number TEXT NOT NULL,
            account_name TEXT NOT NULL,
            verified_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(employer_id)
        )
    """)
    # A real, persistent hiring pipeline — only available to employers with a real account
    # (the employers table above), since the anonymous job-posting flow has no durable identity
    # to hang stage history off of. One row per (employer, candidate) pair; moving a candidate
    # through stages is what triggers the WhatsApp/in-app notification below.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS candidate_pipeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employer_id INTEGER NOT NULL REFERENCES employers(id),
            candidate_user_id INTEGER NOT NULL REFERENCES users(id),
            stage TEXT NOT NULL DEFAULT 'shortlisted',
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(employer_id, candidate_user_id)
        )
    """)
    # CREATE TABLE IF NOT EXISTS is a no-op on a table that already exists on disk from
    # an earlier version of this schema, so new columns need an explicit, safe migration.
    ensure_column(conn, "profiles", "open_to_remote", "open_to_remote INTEGER DEFAULT 0")
    ensure_column(conn, "imported_jobs", "remote_friendly", "remote_friendly INTEGER DEFAULT 0")
    # Saved resume — lets Resume Studio auto-load the candidate's existing resume instead of
    # asking them to re-upload/re-paste it on every single visit.
    ensure_column(conn, "profiles", "resume_text", "resume_text TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "resume_file_kind", "resume_file_kind TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "resume_file_media_type", "resume_file_media_type TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "resume_file_base64", "resume_file_base64 TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "resume_filename", "resume_filename TEXT DEFAULT ''")
    # Self-declared only — Bridge NG has no way to verify NYSC status or university enrollment
    # against any real registry, so these are never labeled "verified" anywhere in the UI.
    ensure_column(conn, "profiles", "university", "university TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "nysc_status", "nysc_status TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "ppa_state", "ppa_state TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "ppa_lga", "ppa_lga TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "pitch_media_kind", "pitch_media_kind TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "pitch_media_type", "pitch_media_type TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "pitch_media_base64", "pitch_media_base64 TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "whatsapp_number", "whatsapp_number TEXT DEFAULT ''")
    ensure_column(conn, "profiles", "whatsapp_alerts_enabled", "whatsapp_alerts_enabled INTEGER DEFAULT 0")
    # verified_badges: only ever written by handle_submit_skill_challenge after a real server-side
    # scored quiz — never trust a client-submitted score. portfolio_link is self-declared, same
    # honesty rule as nysc_status/university above (Bridge NG can't verify it against anything real).
    ensure_column(conn, "profiles", "verified_badges", "verified_badges TEXT DEFAULT '[]'")
    ensure_column(conn, "profiles", "portfolio_link", "portfolio_link TEXT DEFAULT ''")
    # Employer-declared, self-reported like everything else on this side of the app (no way to
    # audit an office's actual power/internet setup) — real value for candidates in a market where
    # grid power and connectivity are genuinely inconsistent, not decorative.
    ensure_column(conn, "employer_posted_jobs", "perks", "perks TEXT DEFAULT '[]'")
    conn.commit()
    migrate_encrypt_existing_profiles(conn)
    conn.close()


def migrate_encrypt_existing_profiles(conn):
    """One-time-per-row upgrade: any profile column that predates field-level encryption is still
    sitting on disk as plaintext. Re-checked (cheaply) on every startup rather than gated behind a
    one-shot flag, since that's simpler and idempotent — a column already encrypted is detected via
    is_encrypted_field() and left untouched.

    Critical: is_encrypted_field() returning False means "didn't decrypt under the CURRENT key" —
    that's true both for genuine plaintext AND for real ciphertext encrypted under a since-rotated
    key (e.g. ENCRYPTION_KEY not persisted across a restart). Blindly encrypting anything that
    fails that check would take already-undecryptable ciphertext and wrap it in ANOTHER layer of
    encryption under the new key, permanently overwriting the one copy that a restored key could
    otherwise still have recovered. _looks_like_fernet_token() tells the two apart structurally
    (independent of any key) — only genuine, never-encrypted plaintext gets touched here."""
    rows = conn.execute(
        f"SELECT user_id, {', '.join(ENCRYPTED_PROFILE_COLUMNS)} FROM profiles"
    ).fetchall()
    migrated = 0
    for row in rows:
        updates = {}
        for col in ENCRYPTED_PROFILE_COLUMNS:
            value = row[col] or ""
            if value and not is_encrypted_field(value) and not _looks_like_fernet_token(value):
                updates[col] = encrypt_field(value)
        if updates:
            set_clause = ", ".join(f"{c}=?" for c in updates)
            conn.execute(f"UPDATE profiles SET {set_clause} WHERE user_id=?",
                         (*updates.values(), row["user_id"]))
            migrated += 1
    if migrated:
        conn.commit()
        print(f"[security] Encrypted previously-plaintext profile PII for {migrated} account(s).")


def compute_streak(checkin_dates):
    """checkin_dates: a set of datetime.date. A streak isn't broken until a full day is
    skipped — checking in every day up to and including yesterday still counts as 'alive'
    even before today's check-in happens."""
    if not checkin_dates:
        return 0
    today = datetime.date.today()
    yesterday = today - datetime.timedelta(days=1)
    if today not in checkin_dates and yesterday not in checkin_dates:
        return 0
    streak = 0
    cursor = today if today in checkin_dates else yesterday
    while cursor in checkin_dates:
        streak += 1
        cursor -= datetime.timedelta(days=1)
    return streak


def ensure_column(conn, table, column, add_column_ddl):
    existing = [row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {add_column_ddl}")


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return salt, digest.hex()


def verify_password(password, salt, expected_hash):
    _, computed = hash_password(password, salt)
    return secrets.compare_digest(computed, expected_hash)


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Real, fixed 5-question banks — deterministic scoring, no AI involved. The correct-answer index
# never leaves the server (handle_get_skill_challenge strips it before responding); scoring only
# ever happens in handle_submit_skill_challenge against this same dict, so a badge can't be earned
# by reading the page source or replaying a guessed score from the client.
SKILL_CHALLENGE_PASS_THRESHOLD = 4  # out of 5 (80%) to earn the verified badge

# Hiring pipeline stages available to employers with a real account (see candidate_pipeline
# table). "rejected" deliberately never triggers an automated candidate-facing notification —
# an automated "you didn't get it" bot message is worse than silence; an employer who wants to
# tell someone can still use the existing message composer in their own words.
PIPELINE_STAGES = ["shortlisted", "interviewing", "offer", "hired", "rejected"]
PIPELINE_STAGE_LABELS = {
    "shortlisted": "shortlisted you", "interviewing": "moved you to the interview stage",
    "offer": "extended you an offer", "hired": "marked you as hired",
}

# Employer-declared workplace infrastructure perks — real value in a market with inconsistent
# grid power and connectivity, self-reported like everything else on the employer side (there's
# no employer login/verification system to audit these against).
PERK_LABELS = {
    "power": "⚡ 24/7 power backup",
    "internet": "📶 Fiber internet",
    "transport": "🚌 Company transport",
}
SKILL_CHALLENGES = {
    "Python": [
        {"q": "What does `len([1, 2, 3])` return?", "options": ["2", "3", "4", "Error"], "answer": 1},
        {"q": "Which keyword defines a function in Python?", "options": ["func", "def", "function", "lambda"], "answer": 1},
        {"q": "What is the output of `3 // 2`?", "options": ["1.5", "1", "2", "0"], "answer": 1},
        {"q": "Which data type is immutable in Python?", "options": ["list", "dict", "tuple", "set"], "answer": 2},
        {"q": "What does `range(5)` produce values for?", "options": ["1 to 5", "0 to 4", "0 to 5", "1 to 4"], "answer": 1},
    ],
    "SQL": [
        {"q": "Which SQL clause filters rows before grouping?", "options": ["HAVING", "WHERE", "GROUP BY", "ORDER BY"], "answer": 1},
        {"q": "Which JOIN returns only matching rows from both tables?", "options": ["LEFT JOIN", "RIGHT JOIN", "INNER JOIN", "FULL OUTER JOIN"], "answer": 2},
        {"q": "Which statement removes rows from a table?", "options": ["DROP", "DELETE", "REMOVE", "TRUNCATE ONLY"], "answer": 1},
        {"q": "What does `COUNT(*)` return?", "options": ["Sum of a column", "Number of rows", "Number of columns", "Average of a column"], "answer": 1},
        {"q": "Which clause filters groups after GROUP BY?", "options": ["WHERE", "HAVING", "FILTER", "ON"], "answer": 1},
    ],
    "Excel": [
        {"q": "Which function looks up a value in a table by row?", "options": ["SUMIF", "VLOOKUP", "CONCAT", "INDEX only"], "answer": 1},
        {"q": "What does pressing F4 do to a selected cell reference in a formula?", "options": ["Deletes it", "Toggles absolute/relative references", "Copies it", "Sorts the column"], "answer": 1},
        {"q": "Which function counts cells matching a condition?", "options": ["COUNTIF", "SUMPRODUCT", "IFERROR", "COUNTBLANK"], "answer": 0},
        {"q": "What does `$A$1` mean in a formula?", "options": ["Relative row and column", "Absolute row and column", "Named range", "External reference"], "answer": 1},
        {"q": "Which feature summarizes large datasets interactively?", "options": ["Conditional formatting", "PivotTable", "Data validation", "Text to Columns"], "answer": 1},
    ],
    "Customer Service": [
        {"q": "A customer is angry about a late delivery. What's the best first step?", "options": ["Explain company policy immediately", "Acknowledge their frustration and listen", "Transfer them to another department", "Offer a discount right away"], "answer": 1},
        {"q": "What does \"first-call resolution\" mean?", "options": ["Answering the phone quickly", "Solving the issue in the first contact", "Escalating every call", "Following a script exactly"], "answer": 1},
        {"q": "A customer asks for something outside policy. Best approach?", "options": ["Refuse and end the call", "Explain what you CAN do, and check if an exception is possible", "Ignore the request", "Promise it will be done regardless"], "answer": 1},
        {"q": "What's an example of active listening?", "options": ["Interrupting to solve faster", "Paraphrasing back what the customer said", "Multitasking while they talk", "Reading from a script without pausing"], "answer": 1},
        {"q": "Why is tone important in written support (e.g. email/chat)?", "options": ["It isn't, only accuracy matters", "It affects how the message is perceived even without voice cues", "Only spoken tone matters", "Formal tone always works best"], "answer": 1},
    ],
    "JavaScript": [
        {"q": "Which keyword declares a block-scoped variable?", "options": ["var", "let", "global", "static"], "answer": 1},
        {"q": "What does `===` check that `==` doesn't?", "options": ["Nothing, they're the same", "Type, in addition to value", "Only value, not type", "Reference equality only"], "answer": 1},
        {"q": "What does `Array.map()` return?", "options": ["The original array, mutated", "A new array of transformed values", "A single value", "undefined"], "answer": 1},
        {"q": "What is a Promise used for?", "options": ["Styling elements", "Handling asynchronous operations", "Declaring variables", "Looping over arrays"], "answer": 1},
        {"q": "What does `typeof null` return in JavaScript?", "options": ["\"null\"", "\"object\"", "\"undefined\"", "\"boolean\""], "answer": 1},
    ],
}

PROFILE_FIELDS = ["fullName", "dob", "sex", "phone", "address", "education",
                   "careerLevel", "fieldOfStudy", "preferredLocation"]
PROFILE_COLUMNS = ["full_name", "dob", "sex", "phone", "address", "education",
                    "career_level", "field_of_study", "preferred_location"]


def profile_row_to_json(row):
    if row is None:
        # Defensive: a user row should always have a matching profile row, but don't crash
        # the whole request if that invariant is ever violated — return a blank profile instead.
        return {
            "fullName": "", "dob": "", "sex": "", "phone": "", "address": "", "education": "",
            "careerLevel": "", "fieldOfStudy": "", "preferredLocation": "", "skills": [],
            "openToRemote": False, "resumeText": "", "resumeFile": None, "resumeFilename": "",
            "university": "", "nyscStatus": "", "ppaState": "", "ppaLga": "", "pitchMedia": None,
            "whatsappNumber": "", "whatsappAlertsEnabled": False,
            "verifiedBadges": [], "portfolioLink": "",
        }
    resume_file_kind = row["resume_file_kind"] or ""
    resume_file = None
    if resume_file_kind:
        decrypted_resume_b64 = decrypt_field(row["resume_file_base64"] or "")
        resume_file = {
            "kind": resume_file_kind,
            "mediaType": row["resume_file_media_type"] or "",
            "base64": decrypted_resume_b64,
            # kind is set (a file WAS saved) but decrypt_field came back empty — the ciphertext
            # itself is fine (Turso doesn't lose bytes), it just isn't readable under the CURRENT
            # ENCRYPTION_KEY. Flagged here so the frontend can say so immediately at profile-load
            # time instead of only surfacing a confusing "Couldn't read that PDF" later, deep in
            # the AI-tailoring flow, once it tries to decode empty bytes as a PDF.
            "unreadable": not decrypted_resume_b64,
        }
    pitch_media = None
    if row["pitch_media_kind"]:
        decrypted_pitch_b64 = decrypt_field(row["pitch_media_base64"] or "")
        pitch_media = {
            "kind": row["pitch_media_kind"],
            "mediaType": row["pitch_media_type"] or "",
            "base64": decrypted_pitch_b64,
            "unreadable": not decrypted_pitch_b64,
        }
    return {
        "fullName": decrypt_field(row["full_name"]),
        "dob": decrypt_field(row["dob"]),
        "sex": decrypt_field(row["sex"]),
        "phone": decrypt_field(row["phone"]),
        "address": decrypt_field(row["address"]),
        "education": row["education"],
        "careerLevel": row["career_level"],
        "fieldOfStudy": row["field_of_study"],
        "preferredLocation": row["preferred_location"],
        "skills": json.loads(row["skills"] or "[]"),
        "openToRemote": bool(row["open_to_remote"]),
        "resumeText": decrypt_field(row["resume_text"] or ""),
        "resumeFile": resume_file,
        "resumeFilename": decrypt_field(row["resume_filename"] or ""),
        "university": row["university"] or "",
        "nyscStatus": row["nysc_status"] or "",
        "ppaState": row["ppa_state"] or "",
        "ppaLga": row["ppa_lga"] or "",
        "pitchMedia": pitch_media,
        "whatsappNumber": decrypt_field(row["whatsapp_number"] or ""),
        "whatsappAlertsEnabled": bool(row["whatsapp_alerts_enabled"]),
        "verifiedBadges": json.loads(row["verified_badges"] or "[]"),
        "portfolioLink": row["portfolio_link"] or "",
    }


def employer_row_to_json(row):
    return {
        "id": row["id"], "email": row["email"], "companyName": row["company_name"],
        "corporateDomain": row["corporate_domain"] or "",
    }


def subscription_row_to_json(row):
    if row is None:
        return {"tier": "sme_starter", "status": "active", "billingCycle": "", "currentPeriodEnd": ""}
    return {
        "tier": row["tier"], "status": row["status"], "billingCycle": row["billing_cycle"] or "",
        "currentPeriodEnd": row["current_period_end"] or "",
    }


def bank_account_row_to_json(row):
    if row is None:
        return None
    return {
        "bankCode": row["bank_code"], "bankName": row["bank_name"],
        "accountNumber": decrypt_field(row["account_number"]),
        "accountName": decrypt_field(row["account_name"]),
        "verifiedAt": row["verified_at"],
    }


def imported_job_row_to_json(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "company": row["company"],
        "location": row["location"],
        "level": row["level"],
        "sector": row["sector"],
        "skills": json.loads(row["skills"] or "[]"),
        "payMin": row["pay_min"],
        "payMax": row["pay_max"],
        "description": row["description"],
        "applicationLink": row["application_link"],
        "postedDate": row["posted_date"],
        "createdAt": row["created_at"],
        "remoteFriendly": bool(row["remote_friendly"]),
    }


def saved_search_row_to_json(row):
    return {
        "id": row["id"],
        "label": row["label"],
        "skills": json.loads(row["skills"] or "[]"),
        "level": row["level"],
        "location": row["location"],
        "createdAt": row["created_at"],
    }


def notification_row_to_json(row):
    return {
        "id": row["id"],
        "kind": row["kind"],
        "message": row["message"],
        "jobTitle": row["job_title"],
        "company": row["company"],
        "read": bool(row["is_read"]),
        "createdAt": row["created_at"],
    }


APPOINTMENT_STATUSES = ("requested", "confirmed", "reminder_set", "completed")


def appointment_row_to_json(row):
    return {
        "id": row["id"],
        "company": row["company"],
        "role": row["role"],
        "date": row["appt_date"],
        "time": row["appt_time"],
        "notes": row["notes"],
        "status": row["status"],
        "createdAt": row["created_at"],
        "zoomJoinUrl": row["zoom_join_url"] or "",
    }


APPLICATION_STATUSES = ("applied", "interviewing", "offer", "archived")


MAX_MESSAGE_LENGTH = 2000


def message_row_to_json(row):
    return {
        "id": row["id"],
        "senderRole": row["sender_role"],
        "body": row["body"],
        "createdAt": row["created_at"],
    }


def application_row_to_json(row):
    return {
        "id": row["id"],
        "jobTitle": row["job_title"],
        "company": row["company"],
        "applicationLink": row["application_link"],
        "createdAt": row["created_at"],
        "status": row["status"] if row["status"] in APPLICATION_STATUSES else "applied",
    }


def generate_notifications_for_job(conn, job):
    """Insert notification rows for any saved search or followed company the given
    (already-inserted) imported job matches. Does not commit — caller commits once."""
    job_skills = {s.lower() for s in job["skills"]}

    for row in conn.execute("SELECT * FROM saved_searches").fetchall():
        saved_skills = {s.lower() for s in json.loads(row["skills"] or "[]")}
        if not (saved_skills & job_skills):
            continue
        level_ok = not row["level"] or row["level"] == job["level"]
        loc_ok = not row["location"] or row["location"] in ("Any location", "Any region") or row["location"] == job["location"]
        if level_ok and loc_ok:
            message = f'New role matching your saved search "{row["label"] or "Untitled search"}": {job["title"]} at {job["company"]}.'
            conn.execute(
                "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, ?, ?)",
                (row["user_id"], "saved_search", message, job["title"], job["company"]),
            )

    for row in conn.execute(
        "SELECT * FROM followed_companies WHERE lower(company) = lower(?)", (job["company"],)
    ).fetchall():
        message = f'{job["company"]} just posted a new role: {job["title"]}.'
        conn.execute(
            "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, ?, ?)",
            (row["user_id"], "followed_company", message, job["title"], job["company"]),
        )


def call_nvidia(messages, max_tokens=1400, model=None, timeout=45):
    """Calls NVIDIA's OpenAI-compatible chat completions API and returns the reply text.
    Raises urllib.error.HTTPError on a non-2xx response, or (KeyError, IndexError) if the response
    doesn't contain the expected shape — callers already handle both."""
    payload = {"model": model or NVIDIA_MODEL, "messages": messages, "max_tokens": max_tokens}
    req = urllib.request.Request(
        NVIDIA_CHAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {NVIDIA_API_KEY}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    return result["choices"][0]["message"]["content"]


def call_nvidia_with_fallbacks(messages, models, max_tokens=1400, timeout=45, source="resume-generate"):
    """Tries each model in `models`, in order, falling back to the next on ANY failure — not just
    an HTTP error (account lacks catalog access, bad model name), but also a timeout or connection
    error, which bigger/slower models hit more often. Without catching those too, a timeout on a
    middle model would propagate immediately instead of ever reaching the last, known-working
    model. Raises the last error if every model in the list fails."""
    last_error = None
    for i, model in enumerate(models):
        try:
            return call_nvidia(messages, max_tokens=max_tokens, model=model, timeout=timeout)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            note = f"falling back to '{models[i + 1]}'" if i + 1 < len(models) else "no more fallbacks"
            print(f"NVIDIA model '{model}' unavailable ({e.code}: {detail}) — {note}.")
            record_ai_error(source, model, e.code, detail)
            last_error = e
        except Exception as e:
            note = f"falling back to '{models[i + 1]}'" if i + 1 < len(models) else "no more fallbacks"
            print(f"NVIDIA model '{model}' failed ({e}) — {note}.")
            record_ai_error(source, model, "error", str(e))
            last_error = e
    raise last_error


def parse_job_info_json(reply, fallback_text):
    """Parses the AI job-lookup's JSON reply, tolerating markdown code fences, and falls back to
    a best-effort shape (rather than erroring out) if the model didn't return valid JSON."""
    cleaned = reply.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
    try:
        data = json.loads(cleaned)
        if not isinstance(data, dict):
            data = {}
    except json.JSONDecodeError:
        data = {}
    return {
        "title": data.get("title") or fallback_text[:80],
        "company": data.get("company") or "",
        "location": data.get("location") or "",
        "level": data.get("level") or "",
        "isNigeria": bool(data.get("isNigeria")),
        "isRemote": bool(data.get("isRemote")),
        "applicationLink": data.get("applicationLink") or "",
        "skills": data.get("skills") if isinstance(data.get("skills"), list) else [],
        "summary": data.get("summary") or fallback_text[:300],
    }


def parse_job_match_json(reply, valid_ids):
    """Parses the AI job-match reply, tolerating markdown fences, and strictly drops any id the
    model didn't actually see in the provided job list — a hallucinated id must never reach the
    client as if it were a real, currently-open role."""
    cleaned = reply.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        data = {}
    raw_matches = data.get("matches") if isinstance(data, dict) else None
    if not isinstance(raw_matches, list):
        return []
    matches = []
    for m in raw_matches:
        if not isinstance(m, dict):
            continue
        job_id = m.get("id")
        if job_id not in valid_ids:
            continue
        matches.append({"id": job_id, "reason": str(m.get("reason") or "")[:400]})
    return matches[:3]


VALID_EDUCATION_LEVELS = {
    "Secondary school", "OND / HND (Polytechnic)", "NCE (College of Education)",
    "Bachelor's degree (B.Sc / B.A / B.Eng)", "Master's degree", "Doctorate (Ph.D)",
    "Professional certification",
}
VALID_CAREER_LEVELS = {"Student", "Early career (0-3 yrs)", "Mid career (4-8 yrs)"}


def parse_cv_extraction_json(reply):
    """Same markdown-fence tolerance as parse_job_match_json above. Any field the model got wrong
    shape on, or any enum value that isn't one of the app's real options, is dropped to "" rather
    than passed through — the frontend pre-fills whatever came back and leaves the rest for the
    candidate to fill in themselves, same as an empty form field."""
    cleaned = reply.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}

    def text_field(key, max_len=200):
        v = data.get(key)
        return str(v).strip()[:max_len] if isinstance(v, (str, int, float)) else ""

    education = text_field("education")
    career_level = text_field("careerLevel")
    skills = data.get("skills")
    return {
        "fullName": text_field("fullName"),
        "email": text_field("email"),
        "phone": text_field("phone"),
        "university": text_field("university"),
        "fieldOfStudy": text_field("fieldOfStudy"),
        "education": education if education in VALID_EDUCATION_LEVELS else "",
        "careerLevel": career_level if career_level in VALID_CAREER_LEVELS else "",
        "address": text_field("address", max_len=300),
        "skills": [str(s).strip()[:60] for s in skills if isinstance(s, (str, int, float)) and str(s).strip()][:15]
                  if isinstance(skills, list) else [],
    }


def level_distance(a, b):
    """Python port of index.html's levelDistance() — kept in sync deliberately so a
    real candidate match score means the same thing as the sample-data match score."""
    def norm(s):
        s = s or ""
        if s.startswith("Student"):
            return 0
        if s.startswith("Early"):
            return 1
        return 2
    return abs(norm(a) - norm(b))


def match_score(required_skills, candidate_skills, req_level, cand_level, req_loc, cand_loc):
    """Python port of index.html's matchScore() — same formula, same 2-99 range."""
    req = set(required_skills)
    cand = set(candidate_skills)
    intersection = len(req & cand)
    union = len(req | cand)
    skill_score = 0 if union == 0 else intersection / union
    level_penalty = level_distance(req_level, cand_level) * 0.12
    loc_bonus = 0.05 if (req_loc in ("Any location", "") or cand_loc == req_loc or req_loc == "Remote") else 0
    score = skill_score * 0.8 + 0.2 - level_penalty + loc_bonus
    return max(2, min(99, round(score * 100)))


def compute_reliability_stats(conn, user_id):
    """Real behavioral signal, not a fabricated score: walks this candidate's actual message
    history and measures how long they typically take to reply to an employer, in hours. Returns
    None (not a fake 0% or "N/A") when there isn't at least one real employer->candidate reply
    pair to measure — an untested candidate gets no badge at all rather than a misleading one."""
    conv_ids = [r["id"] for r in conn.execute(
        "SELECT id FROM conversations WHERE candidate_user_id=?", (user_id,)
    ).fetchall()]
    if not conv_ids:
        return None

    reply_hours = []
    for conv_id in conv_ids:
        messages = conn.execute(
            "SELECT sender_role, created_at FROM messages WHERE conversation_id=? ORDER BY created_at ASC",
            (conv_id,),
        ).fetchall()
        pending_employer_ts = None
        for m in messages:
            ts = None
            try:
                ts = datetime.datetime.strptime(m["created_at"], "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                continue
            if m["sender_role"] == "employer":
                pending_employer_ts = ts
            elif m["sender_role"] == "candidate" and pending_employer_ts is not None:
                reply_hours.append((ts - pending_employer_ts).total_seconds() / 3600)
                pending_employer_ts = None

    if not reply_hours:
        return None
    avg_hours = sum(reply_hours) / len(reply_hours)
    return {"avgReplyHours": round(avg_hours, 1), "repliedCount": len(reply_hours)}


def job_already_imported(conn, company, title, application_link):
    """True if this exact role looks already present — used so re-syncing the same
    ATS board on a schedule doesn't re-insert (and re-notify about) the same jobs."""
    if application_link:
        row = conn.execute(
            "SELECT 1 FROM imported_jobs WHERE company = ? AND application_link = ?",
            (company, application_link),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT 1 FROM imported_jobs WHERE company = ? AND title = ?",
            (company, title),
        ).fetchone()
    return row is not None


def location_indicates_remote(location):
    """True only if the location text itself reads as remote/anywhere-work — e.g. 'Remote',
    'Remote - Nigeria', 'Anywhere', or blank (many ATS boards omit location for fully-remote
    roles). A real city name is NOT treated as remote here, even if paired with an ATS/import
    'remoteFriendly' flag — that flag alone has proven unreliable."""
    loc = (location or "").strip().lower()
    if not loc:
        return True
    return any(kw in loc for kw in ("remote", "anywhere", "worldwide", "global"))


NIGERIAN_PLACE_NAMES = (
    "nigeria", "lagos", "abuja", "kano", "ibadan", "port harcourt", "kaduna",
    "enugu", "benin city", "jos", "abeokuta", "owerri", "warri", "calabar",
    "uyo", "onitsha", "maiduguri", "sokoto", "bauchi", "minna", "lafia",
    "makurdi", "akure", "osogbo", "ilorin", "yola", "gombe", "jalingo",
    "damaturu", "dutse", "katsina", "gusau", "birnin kebbi", "asaba", "yenagoa",
)


def location_indicates_nigeria(location):
    """True if the location text plausibly refers to a Nigerian city/state. Real ATS listings
    for Nigeria-based roles almost always include the word 'Nigeria' explicitly; the place-name
    list catches listings that name a city/state without the country."""
    loc = (location or "").strip().lower()
    if not loc:
        return False
    return any(place in loc for place in NIGERIAN_PLACE_NAMES)


def job_passes_relevance_filter(location, relevance):
    """Used only for automated/unattended sync (not the manual admin tool, which should be free
    to pull in any company's full board for a human to review). 'nigeria_or_remote' is for the
    main Nigeria company list — some of those companies (e.g. pan-African NGOs) also post roles
    in other countries that aren't relevant here. 'remote_only' is for the remote-first company
    list, where an on-site role in some other country isn't reachable by a Nigeria-based seeker
    either."""
    if relevance == "remote_only":
        return location_indicates_remote(location)
    if relevance == "nigeria_or_remote":
        return location_indicates_nigeria(location) or location_indicates_remote(location)
    return True


def insert_job(conn, job):
    """Insert a normalized job dict into imported_jobs. Does not commit or notify —
    caller commits once after the batch and decides how to generate notifications."""
    skills = job.get("skills") or []
    try:
        pay_min = int(job.get("payMin") or 0)
        pay_max = int(job.get("payMax") or 0)
    except (TypeError, ValueError):
        pay_min, pay_max = 0, 0
    location = job.get("location", "")
    remote_friendly = 1 if location_indicates_remote(location) else 0
    cur = conn.execute(
        """INSERT INTO imported_jobs (title, company, location, level, sector, skills,
           pay_min, pay_max, description, application_link, posted_date, remote_friendly)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (job["title"], job["company"], location, job.get("level", ""),
         job.get("sector", "General"), json.dumps(skills), pay_min, pay_max,
         job.get("description", ""), job.get("applicationLink", ""), job.get("postedDate", ""),
         remote_friendly),
    )
    return {
        "id": cur.lastrowid, "title": job["title"], "company": job["company"],
        "location": location, "level": job.get("level", ""),
        "sector": job.get("sector", "General"), "skills": skills,
        "remoteFriendly": bool(remote_friendly),
    }


def insert_job_and_notify(conn, job):
    """insert_job() plus per-job notifications — right for the manual JSON import
    endpoint, where an operator is adding a handful of specific jobs at a time."""
    job_record = insert_job(conn, job)
    generate_notifications_for_job(conn, job_record)
    return job_record


def generate_bulk_notifications(conn, company, inserted_jobs):
    """Aggregate version of generate_notifications_for_job for bulk ATS syncs, where
    a single sync can insert hundreds of jobs — one notification per matching saved
    search / followed company instead of flooding the user with one per job."""
    if not inserted_jobs:
        return
    count = len(inserted_jobs)
    example = inserted_jobs[0]["title"]

    for row in conn.execute("SELECT * FROM followed_companies WHERE lower(company) = lower(?)", (company,)).fetchall():
        message = (f'{company} just posted {count} new roles — including "{example}".' if count > 1
                   else f'{company} just posted a new role: {example}.')
        conn.execute(
            "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, ?, ?)",
            (row["user_id"], "followed_company", message, example, company),
        )

    for row in conn.execute("SELECT * FROM saved_searches").fetchall():
        saved_skills = {s.lower() for s in json.loads(row["skills"] or "[]")}
        matches = []
        for job in inserted_jobs:
            job_skills = {s.lower() for s in job["skills"]}
            if not (saved_skills & job_skills):
                continue
            level_ok = not row["level"] or row["level"] == job["level"]
            loc_ok = not row["location"] or row["location"] in ("Any location", "Any region") or row["location"] == job["location"]
            if level_ok and loc_ok:
                matches.append(job)
        if not matches:
            continue
        match_count = len(matches)
        match_example = matches[0]["title"]
        label = row["label"] or "Untitled search"
        message = (f'{match_count} new roles match your saved search "{label}" — including "{match_example}" at {company}.'
                   if match_count > 1 else
                   f'New role matching your saved search "{label}": {match_example} at {company}.')
        conn.execute(
            "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, ?, ?)",
            (row["user_id"], "saved_search", message, match_example, company),
        )


TAG_RE = re.compile(r"<[^>]+>")


def strip_html(text):
    if not text:
        return ""
    no_tags = TAG_RE.sub(" ", html.unescape(text))
    return re.sub(r"\s+", " ", no_tags).strip()


def guess_level(title):
    t = (title or "").lower()
    if any(k in t for k in ("intern", "internship", "graduate", "trainee", "entry level", "entry-level")):
        return "Student"
    if any(k in t for k in ("senior", "sr.", "lead", "principal", "staff", "director", "head of", "manager",
                             "vp,", "vp ", "vice president", "chief", "svp", "evp", "president", "executive")):
        return "Mid career (4-8 yrs)"
    return "Early career (0-3 yrs)"


def extract_skills(text, limit=8):
    text_lower = (text or "").lower()
    return [s for s in PY_SKILLS if s.lower() in text_lower][:limit]


def normalize_greenhouse_job(raw, company_override, slug):
    title = raw.get("title") or ""
    description = strip_html(raw.get("content") or "")
    departments = raw.get("departments") or []
    location = (raw.get("location") or {}).get("name") or "Remote"
    posted = (raw.get("first_published") or raw.get("updated_at") or "")[:10]
    company = company_override or raw.get("company_name") or slug.replace("-", " ").title()
    return {
        "title": title,
        "company": company,
        "location": location,
        "level": guess_level(title),
        "sector": departments[0]["name"] if departments else "General",
        "skills": extract_skills(title + " " + description),
        "payMin": 0,
        "payMax": 0,
        "description": description[:600],
        "applicationLink": raw.get("absolute_url") or "",
        "postedDate": posted,
    }


def normalize_lever_job(raw, company_override, slug):
    title = raw.get("text") or ""
    categories = raw.get("categories") or {}
    description = raw.get("descriptionPlain") or strip_html(raw.get("description") or "")
    posted = ""
    posted_ms = raw.get("createdAt")
    if posted_ms:
        try:
            posted = datetime.datetime.fromtimestamp(posted_ms / 1000).strftime("%Y-%m-%d")
        except (TypeError, ValueError, OSError):
            posted = ""
    return {
        "title": title,
        "company": company_override or slug.replace("-", " ").title(),
        "location": categories.get("location") or "Remote",
        "level": guess_level(title),
        "sector": categories.get("team") or "General",
        "skills": extract_skills(title + " " + description),
        "payMin": 0,
        "payMax": 0,
        "description": description[:600],
        "applicationLink": raw.get("hostedUrl") or "",
        "postedDate": posted,
    }


def sync_company_jobs(ats, slug, company_override="", relevance="any"):
    """Fetch + normalize + dedup-insert + notify for one company's public ATS board.
    Used by both the on-demand /api/jobs/sync endpoint and the background auto-sync
    loop, so a scheduled refresh behaves identically to a manual one. `relevance`
    defaults to "any" (no filtering) for the manual admin tool, which should be free to
    pull in a company's full board for a human to review — see job_passes_relevance_filter
    for the filtered modes used by unattended auto-sync.
    Returns (inserted_count, error_message_or_None, inserted_jobs_as_json)."""
    url_template = GREENHOUSE_JOBS_URL if ats == "greenhouse" else LEVER_JOBS_URL
    url = url_template.format(slug=urllib.parse.quote(slug))
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"ATS sync failed for {ats}/{slug}:", e)
        return 0, SYNC_FALLBACK_MESSAGE, []

    if ats == "greenhouse":
        raw_jobs = payload.get("jobs") or []
        normalize = lambda raw: normalize_greenhouse_job(raw, company_override, slug)
    else:
        raw_jobs = payload if isinstance(payload, list) else []
        normalize = lambda raw: normalize_lever_job(raw, company_override, slug)

    inserted = []
    with db_lock:
        conn = get_db()
        for raw in raw_jobs:
            job = normalize(raw)
            if not job["title"]:
                continue
            if not job_passes_relevance_filter(job["location"], relevance):
                continue
            if job_already_imported(conn, job["company"], job["title"], job["applicationLink"]):
                continue
            inserted.append(insert_job(conn, job))
        if inserted:
            generate_bulk_notifications(conn, inserted[0]["company"], inserted)
        conn.commit()
        ids = [j["id"] for j in inserted]
        rows = []
        if ids:
            placeholders = ",".join("?" * len(ids))
            rows = conn.execute(
                f"SELECT * FROM imported_jobs WHERE id IN ({placeholders}) ORDER BY id", ids
            ).fetchall()
        conn.close()

    return len(inserted), None, [imported_job_row_to_json(r) for r in rows]


def parse_company_list(raw):
    companies = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        ats, slug = entry.split(":", 1)
        ats, slug = ats.strip().lower(), slug.strip().lower()
        if ats in ("greenhouse", "lever") and slug:
            companies.append((ats, slug))
    return companies


def parse_auto_sync_companies():
    return parse_company_list(AUTO_SYNC_COMPANIES)


def parse_auto_sync_remote_companies():
    return parse_company_list(AUTO_SYNC_REMOTE_COMPANIES)


def run_auto_sync_loop():
    """Background thread: periodically re-syncs the curated company lists (Nigeria-based
    + remote-first global) so the site picks up new postings on its own — no admin
    needs to click anything."""
    companies = parse_auto_sync_companies()
    remote_companies = parse_auto_sync_remote_companies()
    if not companies and not remote_companies:
        return
    interval_seconds = max(AUTO_SYNC_INTERVAL_HOURS, 0.05) * 3600

    while True:
        for (ats, slug), relevance in (
            [(cs, "nigeria_or_remote") for cs in companies]
            + [(cs, "remote_only") for cs in remote_companies]
        ):
            try:
                count, error, _ = sync_company_jobs(ats, slug, relevance=relevance)
                if error:
                    print(f"[auto-sync] {ats}/{slug} failed: {error}")
                elif count:
                    print(f"[auto-sync] {ats}/{slug}: added {count} new job(s)")
                else:
                    print(f"[auto-sync] {ats}/{slug}: already up to date")
            except Exception as e:
                print(f"[auto-sync] {ats}/{slug} crashed:", e)
        time.sleep(interval_seconds)


class Handler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0 (no keep-alive): each request gets its own fresh connection, closed immediately
    # after the response. HTTP/1.1 keep-alive reuses one connection for many requests, and in
    # production — behind Render's own reverse proxy, which pools its own connections to this
    # origin independently of anything this app does — that reuse was intermittently corrupting
    # unrelated requests (observed as the chat widget failing with garbled "Bad request syntax"
    # errors). A per-app body-drain fix closed one source of this, but a further layer appears to
    # sit outside this code's control, so the surer fix is removing persistent connections
    # entirely rather than continuing to chase corruption across infrastructure boundaries. The
    # extra per-request TCP handshake cost is negligible for this app's traffic level.
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def handle_one_request(self):
        # BaseHTTPRequestHandler reuses this same instance across every request on a persistent
        # (HTTP/1.1 keep-alive) connection — handle_one_request() runs once per request, but
        # `self` itself lives for the whole connection. _drain_request_body()'s cache must reset
        # here, at the start of each new request cycle: without this, request #2 on a reused
        # connection would see the flag already set from request #1, skip reading its own body
        # from the socket entirely, and leave those bytes unread to corrupt request #3's parse.
        self._raw_body_read = False
        self._raw_body = b""
        super().handle_one_request()

    def send_error(self, code, message=None, explain=None):
        # Covers every path that leads to an error response, including ones with no do_X method
        # at all (a bot/scanner sending OPTIONS, HEAD, DELETE, etc. — common on a public site —
        # falls through to Python's own "Unsupported method" 501 here, which otherwise never
        # reads the body). This connection stays alive between requests (HTTP/1.1), so any
        # undrained body would sit in the socket and corrupt the next request read on it.
        try:
            self._drain_request_body()
        except Exception:
            pass
        super().send_error(code, message, explain)

    # ---------- helpers ----------

    def send_json(self, status, obj, set_cookie=None, clear_cookie=False, cookie_name=SESSION_COOKIE):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header("Set-Cookie", f"{cookie_name}={set_cookie}; Path=/; HttpOnly; SameSite=Lax")
        if clear_cookie:
            self.send_header("Set-Cookie", f"{cookie_name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        self.end_headers()
        self.wfile.write(body)

    def _drain_request_body(self):
        """Reads (and caches, for *this* request only — see handle_one_request's reset above)
        the full request body exactly once, regardless of whether any route handler actually
        asks for it. This connection stays alive between requests (protocol_version = HTTP/1.1),
        so a request that 404s without ever reading its body — e.g. a POST/PUT to an unmatched
        path — would otherwise leave those bytes sitting unread in the socket, corrupting the
        start of the next request read on that same connection. do_POST/do_PUT call this
        unconditionally before routing so that can't happen; read_json_body() below just reuses
        the cached bytes."""
        if not self._raw_body_read:
            length = int(self.headers.get("Content-Length", 0) or 0)
            self._raw_body = self.rfile.read(length) if length else b""
            self._raw_body_read = True
        return self._raw_body

    def read_json_body(self):
        raw = self._drain_request_body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def get_cookie(self, name):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        for part in cookie_header.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == name:
                    return v
        return None

    def current_user_id(self):
        token = self.get_cookie(SESSION_COOKIE)
        if not token:
            return None
        with db_lock:
            conn = get_db()
            row = conn.execute(
                "SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)
            ).fetchone()
            if row is not None and time.time() > row["expires_at"]:
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                row = None
            conn.close()
        return row["user_id"] if row is not None else None

    def current_employer_id(self):
        token = self.get_cookie(EMPLOYER_SESSION_COOKIE)
        if not token:
            return None
        with db_lock:
            conn = get_db()
            row = conn.execute(
                "SELECT employer_id, expires_at FROM employer_sessions WHERE token=?", (token,)
            ).fetchone()
            if row is not None and time.time() > row["expires_at"]:
                conn.execute("DELETE FROM employer_sessions WHERE token=?", (token,))
                conn.commit()
                row = None
            conn.close()
        return row["employer_id"] if row is not None else None

    # ---------- routing ----------

    def do_GET(self):
        self._drain_request_body()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/me":
            return self.handle_me()
        if parsed.path == "/api/debug/db":
            return self.handle_debug_db(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/api/debug/ai-errors":
            return self.handle_debug_ai_errors()
        if parsed.path == "/api/jobs":
            return self.handle_list_jobs()
        if parsed.path == "/api/saved-searches":
            return self.handle_list_saved_searches()
        if parsed.path == "/api/followed-companies":
            return self.handle_list_followed_companies()
        if parsed.path == "/api/notifications":
            return self.handle_list_notifications()
        if parsed.path == "/api/checkin":
            return self.handle_checkin_status()
        if parsed.path == "/api/campus-count":
            return self.handle_campus_count(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/api/salary-reviews":
            return self.handle_list_salary_reviews(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/api/candidate-pitch":
            return self.handle_get_candidate_pitch(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/api/skill-challenge":
            return self.handle_get_skill_challenge(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/api/employer/me":
            return self.handle_employer_me()
        if parsed.path == "/api/employer/banks":
            return self.handle_list_banks()
        if parsed.path == "/api/employer/bank/resolve":
            return self.handle_bank_resolve(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/api/employer/pipeline":
            return self.handle_get_pipeline()
        if parsed.path == "/api/skills/known":
            return self.handle_known_skills()
        if parsed.path == "/api/appointments/ics":
            return self.handle_appointment_ics(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/api/messages":
            return self.handle_list_conversations()
        if parsed.path == "/api/messages/employer-thread":
            return self.handle_employer_message_thread(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/api/appointments":
            return self.handle_list_appointments()
        if parsed.path == "/api/applications":
            return self.handle_list_applications()
        if parsed.path.startswith("/api/download-relay/"):
            return self.handle_download_relay_fetch(parsed.path.rsplit("/", 1)[-1])
        if parsed.path.startswith("/api/"):
            return self.send_json(404, {"error": "Not found"})
        return self.serve_static(parsed.path)

    def do_POST(self):
        self._drain_request_body()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/signup":
            return self.handle_signup()
        if parsed.path == "/api/login":
            return self.handle_login()
        if parsed.path == "/api/logout":
            return self.handle_logout()
        if parsed.path == "/api/account/delete":
            return self.handle_delete_account()
        if parsed.path == "/api/employer/signup":
            return self.handle_employer_signup()
        if parsed.path == "/api/employer/login":
            return self.handle_employer_login()
        if parsed.path == "/api/employer/logout":
            return self.handle_employer_logout()
        if parsed.path == "/api/employer/subscribe":
            return self.handle_employer_subscribe()
        if parsed.path == "/api/employer/bank":
            return self.handle_save_bank_account()
        if parsed.path == "/api/employer/pipeline":
            return self.handle_set_pipeline_stage()
        if parsed.path == "/api/webhooks/paystack":
            return self.handle_paystack_webhook()
        if parsed.path == "/api/chat":
            return self.handle_chat()
        if parsed.path == "/api/jobs/import":
            return self.handle_import_jobs()
        if parsed.path == "/api/jobs/sync":
            return self.handle_sync_jobs()
        if parsed.path == "/api/saved-searches":
            return self.handle_create_saved_search()
        if parsed.path == "/api/saved-searches/delete":
            return self.handle_delete_saved_search()
        if parsed.path == "/api/follow-company":
            return self.handle_follow_company()
        if parsed.path == "/api/unfollow-company":
            return self.handle_unfollow_company()
        if parsed.path == "/api/notifications/read":
            return self.handle_mark_notifications_read()
        if parsed.path == "/api/checkin":
            return self.handle_checkin()
        if parsed.path == "/api/appointments":
            return self.handle_create_appointment()
        if parsed.path == "/api/appointments/cancel":
            return self.handle_cancel_appointment()
        if parsed.path == "/api/applications":
            return self.handle_create_application()
        if parsed.path == "/api/employer-jobs":
            return self.handle_post_employer_job()
        if parsed.path == "/api/messages/start":
            return self.handle_message_start()
        if parsed.path == "/api/messages/employer-reply":
            return self.handle_employer_message_reply()
        if parsed.path == "/api/messages/reply":
            return self.handle_reply_to_conversation()
        if parsed.path == "/api/messages/read":
            return self.handle_mark_conversation_read()
        if parsed.path == "/api/salary-reviews":
            return self.handle_create_salary_review()
        if parsed.path == "/api/resume/find-job":
            return self.handle_resume_find_job()
        if parsed.path == "/api/job-match":
            return self.handle_job_match()
        if parsed.path == "/api/resume/tailor":
            return self.handle_resume_generate()
        if parsed.path == "/api/resume/extract-profile":
            return self.handle_extract_cv_profile()
        if parsed.path == "/api/career-match":
            return self.handle_career_match()
        if parsed.path == "/api/download-relay":
            return self.handle_download_relay_create()
        if parsed.path == "/api/skill-challenge/submit":
            return self.handle_submit_skill_challenge()
        return self.send_json(404, {"error": "Not found"})

    def do_PUT(self):
        self._drain_request_body()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/profile":
            return self.handle_save_profile()
        if parsed.path == "/api/profile/resume":
            return self.handle_save_resume()
        if parsed.path == "/api/profile/pitch":
            return self.handle_save_pitch()
        if parsed.path == "/api/applications/status":
            return self.handle_update_application_status()
        if parsed.path == "/api/appointments/status":
            return self.handle_update_appointment_status()
        return self.send_json(404, {"error": "Not found"})

    # ---------- static files ----------

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        rel_path = urllib.parse.unquote(path).lstrip("/")
        top_level = rel_path.split("/", 1)[0]
        if rel_path not in STATIC_FILES and top_level not in STATIC_DIRS:
            self.send_json(404, {"error": "Not found"})
            return
        full_path = os.path.normpath(os.path.join(BASE_DIR, rel_path))
        if not full_path.startswith(BASE_DIR) or not os.path.isfile(full_path):
            self.send_json(404, {"error": "Not found"})
            return
        content_type, _ = mimetypes.guess_type(full_path)
        with open(full_path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        # This is an actively-edited local prototype — always revalidate rather than
        # letting the browser silently serve a stale cached HTML/CSS/JS file.
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    # ---------- API handlers ----------

    def handle_signup(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if not EMAIL_RE.match(email):
            return self.send_json(400, {"error": "Enter a valid email address."})
        if len(password) < 6:
            return self.send_json(400, {"error": "Password must be at least 6 characters."})
        if not (data.get("fullName") or "").strip():
            return self.send_json(400, {"error": "Full name is required."})

        salt, pw_hash = hash_password(password)

        with db_lock:
            conn = get_db()
            try:
                cur = conn.execute(
                    "INSERT INTO users (email, salt, password_hash) VALUES (?, ?, ?)",
                    (email, salt, pw_hash),
                )
                user_id = cur.lastrowid
                skills = data.get("skills") or []
                conn.execute(
                    """INSERT INTO profiles (user_id, full_name, dob, sex, phone, address,
                       education, career_level, field_of_study, preferred_location, skills, open_to_remote,
                       university, nysc_status, ppa_state, ppa_lga, whatsapp_number, whatsapp_alerts_enabled)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (user_id, encrypt_field(data.get("fullName", "")), encrypt_field(data.get("dob", "")),
                     encrypt_field(data.get("sex", "")), encrypt_field(data.get("phone", "")),
                     encrypt_field(data.get("address", "")), data.get("education", ""),
                     data.get("careerLevel", ""), data.get("fieldOfStudy", ""),
                     data.get("preferredLocation", ""), json.dumps(skills),
                     1 if data.get("openToRemote") else 0,
                     (data.get("university") or "").strip(), (data.get("nyscStatus") or "").strip(),
                     (data.get("ppaState") or "").strip(), (data.get("ppaLga") or "").strip(),
                     encrypt_field((data.get("whatsappNumber") or "").strip()),
                     1 if data.get("whatsappAlertsEnabled") else 0),
                )
                conn.commit()
            except Exception as e:
                conn.close()
                if is_duplicate_key_error(e):
                    return self.send_json(409, {"error": "An account with this email already exists."})
                raise
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()

        token = create_session(user_id)
        self.send_json(200, {"ok": True, "email": email, "profile": profile_row_to_json(row)}, set_cookie=token)

    def handle_login(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if is_account_locked(email):
            return self.send_json(423, {"error": "Too many failed sign-in attempts. This account is temporarily locked — try again in a few minutes."})

        with db_lock:
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user is None or not verify_password(password, user["salt"], user["password_hash"]):
                conn.close()
                just_locked = record_failed_login(email)
                if just_locked and user is not None:
                    revoke_sessions_for_user(user["id"])
                    print(f"[security] {email}: locked out after repeated failed logins — active sessions revoked.")
                return self.send_json(401, {"error": "Incorrect email or password."})
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user["id"],)).fetchone()
            conn.close()

        clear_failed_logins(email)
        token = create_session(user["id"])
        self.send_json(200, {"ok": True, "email": email, "profile": profile_row_to_json(row)}, set_cookie=token)

    def handle_logout(self):
        token = self.get_cookie(SESSION_COOKIE)
        if token:
            with db_lock:
                conn = get_db()
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                conn.close()
        self.send_json(200, {"ok": True}, clear_cookie=True)

    def handle_delete_account(self):
        """NDPR-style "right to be forgotten": a real, permanent delete of everything tied to this
        account, not a soft-delete flag. Requires re-entering the password (not just an active
        session) since this is irreversible. salary_reviews is deliberately untouched — it has no
        user_id column at all by design, so there's nothing there to attribute to this account."""
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        password = data.get("password") or ""

        with db_lock:
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if user is None or not verify_password(password, user["salt"], user["password_hash"]):
                conn.close()
                return self.send_json(401, {"error": "Incorrect password."})

            email = user["email"]
            conv_ids = [r["id"] for r in conn.execute(
                "SELECT id FROM conversations WHERE candidate_user_id=?", (user_id,)
            ).fetchall()]
            for cid in conv_ids:
                conn.execute("DELETE FROM messages WHERE conversation_id=?", (cid,))
            conn.execute("DELETE FROM conversations WHERE candidate_user_id=?", (user_id,))
            conn.execute("DELETE FROM saved_searches WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM followed_companies WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM notifications WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM appointments WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM checkins WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM applications WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM profiles WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
            conn.close()

        revoke_sessions_for_user(user_id)
        clear_failed_logins(email)
        self.send_json(200, {"ok": True}, clear_cookie=True)

    def handle_me(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(200, {"loggedIn": False})
        with db_lock:
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if user is None:
                conn.close()
                return self.send_json(200, {"loggedIn": False})
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()
        self.send_json(200, {"loggedIn": True, "email": user["email"], "profile": profile_row_to_json(row)})

    def handle_debug_db(self, query):
        """Operator-only (same shared-secret pattern as /api/jobs/import): reports which DB backend
        is actually live and how many accounts exist there. Exists purely to make "is Turso really
        active?" answerable with one request instead of cross-referencing dashboards and deploy
        logs by hand — but account counts and the DB path shouldn't be handed to anyone who asks,
        so it requires the same IMPORT_TOKEN as the other operator-only endpoints."""
        if not IMPORT_TOKEN or query.get("token", [None])[0] != IMPORT_TOKEN:
            return self.send_json(401, {"error": "Invalid or missing import token."})
        info = {"backend": "turso" if USE_TURSO else "sqlite", "dbPath": DB_PATH if not USE_TURSO else None}
        try:
            with db_lock:
                conn = get_db()
                row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
                info["userCount"] = row["c"]
                conn.close()
        except Exception as e:
            info["error"] = str(e)
        self.send_json(200, info)

    def handle_debug_ai_errors(self):
        """Unauthenticated, read-only: the last several AI-call failures (which model, what
        status/detail NVIDIA returned), newest first — a direct substitute for hunting through
        Render's log viewer, whose time-range filter can cut off the exact moment you care about."""
        with ai_error_lock:
            errors = list(reversed(LAST_AI_ERRORS))
        self.send_json(200, {"errors": errors})

    def handle_download_relay_create(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        filename = re.sub(r'[\r\n"]', "", (data.get("filename") or "download").strip())[:150] or "download"
        mime = (data.get("mime") or "application/octet-stream").strip()
        try:
            file_bytes = base64.b64decode(data.get("base64") or "", validate=True)
        except Exception:
            return self.send_json(400, {"error": "Invalid file data."})
        if not file_bytes or len(file_bytes) > MAX_DOWNLOAD_RELAY_BYTES:
            return self.send_json(400, {"error": "File is empty or too large to download."})
        token = secrets.token_urlsafe(24)
        with download_relay_lock:
            _prune_download_relay()
            DOWNLOAD_RELAY[token] = {
                "data": file_bytes, "mime": mime, "filename": filename,
                "expires": time.time() + DOWNLOAD_RELAY_TTL_SECONDS,
            }
        self.send_json(200, {"url": f"/api/download-relay/{token}"})

    def handle_download_relay_fetch(self, token):
        with download_relay_lock:
            _prune_download_relay()
            entry = DOWNLOAD_RELAY.get(token)
        if entry is None:
            return self.send_json(404, {"error": "This download link has expired. Please try downloading again."})
        self.send_response(200)
        self.send_header("Content-Type", entry["mime"])
        self.send_header("Content-Length", str(len(entry["data"])))
        self.send_header("Content-Disposition", f'attachment; filename="{entry["filename"]}"')
        self.end_headers()
        self.wfile.write(entry["data"])

    def handle_save_profile(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        skills = data.get("skills") or []
        with db_lock:
            conn = get_db()
            conn.execute(
                """UPDATE profiles SET full_name=?, dob=?, sex=?, phone=?, address=?,
                   education=?, career_level=?, field_of_study=?, preferred_location=?,
                   skills=?, open_to_remote=?, university=?, nysc_status=?, ppa_state=?, ppa_lga=?,
                   whatsapp_number=?, whatsapp_alerts_enabled=?, portfolio_link=?,
                   updated_at=datetime('now') WHERE user_id=?""",
                (encrypt_field(data.get("fullName", "")), encrypt_field(data.get("dob", "")),
                 encrypt_field(data.get("sex", "")), encrypt_field(data.get("phone", "")),
                 encrypt_field(data.get("address", "")), data.get("education", ""),
                 data.get("careerLevel", ""), data.get("fieldOfStudy", ""),
                 data.get("preferredLocation", ""), json.dumps(skills),
                 1 if data.get("openToRemote") else 0,
                 (data.get("university") or "").strip(), (data.get("nyscStatus") or "").strip(),
                 (data.get("ppaState") or "").strip(), (data.get("ppaLga") or "").strip(),
                 encrypt_field((data.get("whatsappNumber") or "").strip()),
                 1 if data.get("whatsappAlertsEnabled") else 0,
                 (data.get("portfolioLink") or "").strip(), user_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "profile": profile_row_to_json(row)})

    def handle_save_resume(self):
        """Persists whatever resume (pasted text or uploaded file) the candidate currently has in
        Resume Studio, so it auto-loads on their next visit instead of asking them to re-supply it
        every time. A blank/empty payload (e.g. after "Remove file") clears the saved resume too."""
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        resume_text = (data.get("resumeText") or "").strip()
        resume_file = data.get("resumeFile") or None
        resume_filename = (data.get("resumeFilename") or "").strip()

        file_kind, file_media_type, file_base64 = "", "", ""
        if resume_file:
            file_kind = resume_file.get("kind") or ""
            file_media_type = resume_file.get("mediaType") or ""
            file_base64 = resume_file.get("base64") or ""
            try:
                decoded_len = len(base64.b64decode(file_base64, validate=True)) if file_base64 else 0
            except Exception:
                return self.send_json(400, {"error": "Invalid resume file data."})
            if decoded_len > MAX_SAVED_RESUME_BYTES:
                return self.send_json(400, {"error": "That resume file is too large to save (max 8MB)."})

        with db_lock:
            conn = get_db()
            conn.execute(
                """UPDATE profiles SET resume_text=?, resume_file_kind=?, resume_file_media_type=?,
                   resume_file_base64=?, resume_filename=?, updated_at=datetime('now') WHERE user_id=?""",
                (encrypt_field(resume_text), file_kind, file_media_type,
                 encrypt_field(file_base64), encrypt_field(resume_filename), user_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "profile": profile_row_to_json(row)})

    def handle_save_pitch(self):
        """Saves a candidate's recorded 30-second video/audio pitch. A blank payload (after
        'Discard') clears it, same pattern as the resume save above."""
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        kind = (data.get("kind") or "").strip()
        media_type = (data.get("mediaType") or "").strip()
        base64_data = data.get("base64") or ""
        if kind and kind not in ("video", "audio"):
            return self.send_json(400, {"error": "Pitch kind must be 'video' or 'audio'."})
        if base64_data:
            try:
                decoded_len = len(base64.b64decode(base64_data, validate=True))
            except Exception:
                return self.send_json(400, {"error": "Invalid pitch media data."})
            if decoded_len > MAX_PITCH_MEDIA_BYTES:
                return self.send_json(400, {"error": "That recording is too large to save (max 15MB — try a shorter clip)."})

        with db_lock:
            conn = get_db()
            conn.execute(
                """UPDATE profiles SET pitch_media_kind=?, pitch_media_type=?, pitch_media_base64=?,
                   updated_at=datetime('now') WHERE user_id=?""",
                (kind, media_type, encrypt_field(base64_data), user_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "profile": profile_row_to_json(row)})

    def handle_get_skill_challenge(self, query):
        """Returns the 5 questions for a skill with the correct-answer index stripped out — the
        client never sees which option is right, so a badge can't be earned by inspecting this
        response; scoring only happens server-side in handle_submit_skill_challenge below."""
        skill = (query.get("skill", [None])[0] or "").strip()
        bank = SKILL_CHALLENGES.get(skill)
        if not bank:
            return self.send_json(404, {"error": "No challenge is available for that skill yet."})
        questions = [{"q": item["q"], "options": item["options"]} for item in bank]
        self.send_json(200, {"skill": skill, "questions": questions})

    def handle_submit_skill_challenge(self):
        """Scores a candidate's answers against the real answer key (never the client-submitted
        score) and, at 4/5 or better, adds or refreshes a verified badge on their profile."""
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        skill = (data.get("skill") or "").strip()
        answers = data.get("answers") or []
        bank = SKILL_CHALLENGES.get(skill)
        if not bank:
            return self.send_json(404, {"error": "No challenge is available for that skill yet."})
        if not isinstance(answers, list) or len(answers) != len(bank):
            return self.send_json(400, {"error": f"Expected {len(bank)} answers."})

        correct = sum(1 for given, item in zip(answers, bank) if given == item["answer"])
        passed = correct >= SKILL_CHALLENGE_PASS_THRESHOLD

        with db_lock:
            conn = get_db()
            row = conn.execute("SELECT verified_badges FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            badges = json.loads(row["verified_badges"] or "[]") if row else []
            if passed:
                badges = [b for b in badges if b.get("skill") != skill]
                badges.append({
                    "skill": skill,
                    "score": correct,
                    "total": len(bank),
                    "date": datetime.date.today().isoformat(),
                })
                conn.execute(
                    "UPDATE profiles SET verified_badges=?, updated_at=datetime('now') WHERE user_id=?",
                    (json.dumps(badges), user_id),
                )
                conn.commit()
            conn.close()

        self.send_json(200, {"score": correct, "total": len(bank), "passed": passed, "badges": badges})

    def handle_get_candidate_pitch(self, query):
        """Employer-side lookup of one candidate's pitch by user id — same unauthenticated trust
        model as the rest of the employer-facing endpoints (handle_post_employer_job already
        hands out full names/skills to anyone who posts a job)."""
        candidate_user_id = query.get("userId", [None])[0]
        if not candidate_user_id:
            return self.send_json(400, {"error": "Missing candidate id."})
        with db_lock:
            conn = get_db()
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (candidate_user_id,)).fetchone()
            conn.close()
        if row is None or not row["pitch_media_kind"]:
            return self.send_json(404, {"error": "No pitch available for this candidate."})
        self.send_json(200, {
            "kind": row["pitch_media_kind"],
            "mediaType": row["pitch_media_type"] or "",
            "base64": decrypt_field(row["pitch_media_base64"] or ""),
        })

    # ---------- job import & board ----------

    def handle_import_jobs(self):
        if not IMPORT_TOKEN:
            return self.send_json(500, {"error": "Job import isn't configured yet — set the IMPORT_TOKEN environment variable and restart the server."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        if data.get("token") != IMPORT_TOKEN:
            return self.send_json(401, {"error": "Invalid or missing import token."})

        jobs = data.get("jobs") if isinstance(data.get("jobs"), list) else [data]
        inserted = []
        with db_lock:
            conn = get_db()
            for j in jobs:
                title = (j.get("title") or "").strip()
                company = (j.get("company") or "").strip()
                if not title or not company:
                    continue
                if job_already_imported(conn, company, title, (j.get("applicationLink") or "").strip()):
                    continue
                job = dict(j)
                job["title"] = title
                job["company"] = company
                inserted.append(insert_job_and_notify(conn, job))
            conn.commit()
            conn.close()

        if not inserted:
            return self.send_json(400, {"error": "No valid jobs to import — each job needs at least a title and company."})
        self.send_json(200, {"ok": True, "imported": len(inserted)})

    def handle_sync_jobs(self):
        if not IMPORT_TOKEN:
            return self.send_json(500, {"error": "Job import isn't configured yet — set the IMPORT_TOKEN environment variable and restart the server."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        if data.get("token") != IMPORT_TOKEN:
            return self.send_json(401, {"error": "Invalid or missing import token."})

        ats = (data.get("ats") or "").strip().lower()
        slug = (data.get("slug") or "").strip().lower()
        company_override = (data.get("company") or "").strip()
        if ats not in ("greenhouse", "lever"):
            return self.send_json(400, {"error": "ats must be 'greenhouse' or 'lever'."})
        if not slug:
            return self.send_json(400, {"error": "Enter a company board slug."})

        count, error, jobs = sync_company_jobs(ats, slug, company_override)
        if error:
            return self.send_json(502, {"error": error})
        if count == 0:
            return self.send_json(200, {"ok": True, "imported": 0, "message": "No new listings on that board right now — it may already be fully synced."})
        self.send_json(200, {"ok": True, "imported": count, "source": ats, "slug": slug, "jobs": jobs})

    def handle_list_jobs(self):
        with db_lock:
            conn = get_db()
            rows = conn.execute("SELECT * FROM imported_jobs ORDER BY id DESC").fetchall()
            conn.close()
        self.send_json(200, {"jobs": [imported_job_row_to_json(r) for r in rows]})

    # ---------- saved searches ----------

    def handle_create_saved_search(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        skills = data.get("skills") or []
        if not skills:
            return self.send_json(400, {"error": "Select at least one skill to save this search."})
        label = (data.get("label") or "").strip() or ", ".join(skills[:3])

        with db_lock:
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO saved_searches (user_id, label, skills, level, location) VALUES (?, ?, ?, ?, ?)",
                (user_id, label, json.dumps(skills), data.get("level", ""), data.get("location", "")),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM saved_searches WHERE id = ?", (cur.lastrowid,)).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "search": saved_search_row_to_json(row)})

    def handle_list_saved_searches(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(200, {"searches": []})
        with db_lock:
            conn = get_db()
            rows = conn.execute("SELECT * FROM saved_searches WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()
            conn.close()
        self.send_json(200, {"searches": [saved_search_row_to_json(r) for r in rows]})

    def handle_delete_saved_search(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if not data or not data.get("id"):
            return self.send_json(400, {"error": "Missing search id."})
        with db_lock:
            conn = get_db()
            conn.execute("DELETE FROM saved_searches WHERE id = ? AND user_id = ?", (data["id"], user_id))
            conn.commit()
            conn.close()
        self.send_json(200, {"ok": True})

    # ---------- followed companies ----------

    def handle_follow_company(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        company = (data.get("company") or "").strip() if data else ""
        if not company:
            return self.send_json(400, {"error": "Missing company name."})
        with db_lock:
            conn = get_db()
            try:
                conn.execute("INSERT INTO followed_companies (user_id, company) VALUES (?, ?)", (user_id, company))
                conn.commit()
            except Exception as e:
                if not is_duplicate_key_error(e):
                    conn.close()
                    raise
                # already following
            conn.close()
        self.send_json(200, {"ok": True})

    def handle_unfollow_company(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        company = (data.get("company") or "").strip() if data else ""
        with db_lock:
            conn = get_db()
            conn.execute("DELETE FROM followed_companies WHERE user_id = ? AND company = ?", (user_id, company))
            conn.commit()
            conn.close()
        self.send_json(200, {"ok": True})

    def handle_list_followed_companies(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(200, {"companies": []})
        with db_lock:
            conn = get_db()
            rows = conn.execute("SELECT company FROM followed_companies WHERE user_id = ?", (user_id,)).fetchall()
            conn.close()
        self.send_json(200, {"companies": [r["company"] for r in rows]})

    # ---------- notifications ----------

    def handle_list_notifications(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(200, {"notifications": [], "unread": 0})
        with db_lock:
            conn = get_db()
            rows = conn.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50", (user_id,)).fetchall()
            unread = conn.execute("SELECT COUNT(*) c FROM notifications WHERE user_id = ? AND is_read = 0", (user_id,)).fetchone()["c"]
            conn.close()
        self.send_json(200, {"notifications": [notification_row_to_json(r) for r in rows], "unread": unread})

    def handle_mark_notifications_read(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        with db_lock:
            conn = get_db()
            conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()
        self.send_json(200, {"ok": True})

    # ---------- daily check-in streak ----------

    def handle_campus_count(self, query):
        """How many other Bridge NG members share this (self-declared) university — an
        aggregate count only, never a list of who they are, so this can't be used to identify
        individuals."""
        university = (query.get("university", [""])[0] or "").strip()
        if not university:
            return self.send_json(200, {"count": 0})
        user_id = self.current_user_id()
        with db_lock:
            conn = get_db()
            if user_id is not None:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM profiles WHERE lower(university) = lower(?) AND user_id != ?",
                    (university, user_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM profiles WHERE lower(university) = lower(?)",
                    (university,),
                ).fetchone()
            conn.close()
        self.send_json(200, {"count": row["c"]})

    # ---------- salary & culture reviews ----------
    # Truly anonymous at the storage layer: the salary_reviews table has no user_id column at
    # all, so even Bridge NG's own database can't tie a review back to who submitted it. Sign-in
    # is required only as a lightweight spam gate on submission, not to identify reviewers.
    # Labeled "community-submitted" everywhere, never "verified" — nothing here is checked
    # against real payslips or employment records.

    def handle_create_salary_review(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "Sign in first (just to prevent spam — your review itself stays anonymous)."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        company = (data.get("company") or "").strip()
        role_title = (data.get("roleTitle") or "").strip()
        level = (data.get("level") or "").strip()
        review_text = (data.get("reviewText") or "").strip()[:1000]
        try:
            monthly_pay = int(data.get("monthlyPay") or 0)
            culture_rating = int(data.get("cultureRating") or 0)
        except (TypeError, ValueError):
            return self.send_json(400, {"error": "Monthly pay and culture rating must be numbers."})
        if not company or not role_title or monthly_pay <= 0:
            return self.send_json(400, {"error": "Company, role, and a real monthly pay figure are required."})
        if not 1 <= culture_rating <= 5:
            return self.send_json(400, {"error": "Culture rating must be between 1 and 5."})

        with db_lock:
            conn = get_db()
            conn.execute(
                """INSERT INTO salary_reviews (company, role_title, level, monthly_pay,
                   has_housing_allowance, has_transport_allowance, culture_rating, review_text)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (company, role_title, level, monthly_pay,
                 1 if data.get("hasHousingAllowance") else 0, 1 if data.get("hasTransportAllowance") else 0,
                 culture_rating, review_text),
            )
            conn.commit()
            conn.close()
        self.send_json(200, {"ok": True})

    def handle_list_salary_reviews(self, query):
        company = (query.get("company", [""])[0] or "").strip()
        if not company:
            return self.send_json(400, {"error": "Enter a company name to look up."})
        with db_lock:
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM salary_reviews WHERE lower(company) = lower(?) ORDER BY id DESC",
                (company,),
            ).fetchall()
            conn.close()
        if not rows:
            return self.send_json(200, {"count": 0, "reviews": []})
        pays = [r["monthly_pay"] for r in rows]
        ratings = [r["culture_rating"] for r in rows]
        self.send_json(200, {
            "count": len(rows),
            "avgPay": round(sum(pays) / len(pays)),
            "minPay": min(pays),
            "maxPay": max(pays),
            "avgCultureRating": round(sum(ratings) / len(ratings), 1),
            "reviews": [{
                "roleTitle": r["role_title"], "level": r["level"], "monthlyPay": r["monthly_pay"],
                "hasHousingAllowance": bool(r["has_housing_allowance"]),
                "hasTransportAllowance": bool(r["has_transport_allowance"]),
                "cultureRating": r["culture_rating"], "reviewText": r["review_text"],
                "createdAt": r["created_at"],
            } for r in rows],
        })

    def handle_checkin_status(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(200, {"streak": 0, "checkedInToday": False})
        with db_lock:
            conn = get_db()
            rows = conn.execute(
                "SELECT checkin_date FROM checkins WHERE user_id = ? ORDER BY checkin_date DESC LIMIT 400",
                (user_id,),
            ).fetchall()
            conn.close()
        dates = {datetime.date.fromisoformat(r["checkin_date"]) for r in rows}
        today = datetime.date.today()
        self.send_json(200, {"streak": compute_streak(dates), "checkedInToday": today in dates})

    def handle_checkin(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        today_str = datetime.date.today().isoformat()
        with db_lock:
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO checkins (user_id, checkin_date) VALUES (?, ?)", (user_id, today_str)
                )
                conn.commit()
            except Exception as e:
                if not is_duplicate_key_error(e):
                    conn.close()
                    raise
                # already checked in today — not an error, just a no-op
            rows = conn.execute(
                "SELECT checkin_date FROM checkins WHERE user_id = ? ORDER BY checkin_date DESC LIMIT 400",
                (user_id,),
            ).fetchall()
            conn.close()
        dates = {datetime.date.fromisoformat(r["checkin_date"]) for r in rows}
        self.send_json(200, {"ok": True, "streak": compute_streak(dates), "checkedInToday": True})

    # ---------- appointments ----------

    def handle_create_appointment(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        company = (data.get("company") or "").strip()
        date = (data.get("date") or "").strip()
        if not company or not date:
            return self.send_json(400, {"error": "Enter a company and a preferred date."})

        with db_lock:
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO appointments (user_id, company, role, appt_date, appt_time, notes) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, company, (data.get("role") or "").strip(), date,
                 (data.get("time") or "").strip(), (data.get("notes") or "").strip()),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM appointments WHERE id = ?", (cur.lastrowid,)).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "appointment": appointment_row_to_json(row)})

    def handle_list_appointments(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(200, {"appointments": []})
        with db_lock:
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM appointments WHERE user_id = ? ORDER BY appt_date, appt_time", (user_id,)
            ).fetchall()
            conn.close()
        self.send_json(200, {"appointments": [appointment_row_to_json(r) for r in rows]})

    def handle_update_appointment_status(self):
        """Backs the appointment status timeline. There's no employer portal yet to drive this
        automatically, so the seeker-side UI exposes an explicit 'advance' control that walks
        through APPOINTMENT_STATUSES in order — a stand-in until a real employer-facing update
        exists."""
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        appt_id = data.get("id")
        status = (data.get("status") or "").strip().lower()
        if not appt_id or status not in APPOINTMENT_STATUSES:
            return self.send_json(400, {"error": "Missing or invalid appointment id/status."})

        with db_lock:
            conn = get_db()
            existing = conn.execute(
                "SELECT * FROM appointments WHERE id = ? AND user_id = ?", (appt_id, user_id)
            ).fetchone()
            conn.close()
        if existing is None:
            return self.send_json(404, {"error": "Appointment not found."})

        # Best-effort, outside any db_lock hold — a slow/failed Zoom call must never block other
        # requests or the status update itself (create_zoom_meeting already never raises).
        zoom_join_url = existing["zoom_join_url"] or ""
        if status == "confirmed" and not zoom_join_url:
            try:
                start_dt = datetime.datetime.strptime(
                    f"{existing['appt_date']} {existing['appt_time'] or '09:00'}", "%Y-%m-%d %H:%M"
                )
                zoom_join_url = create_zoom_meeting(
                    f"Interview: {existing['role'] or 'Role'} at {existing['company']}",
                    start_dt.strftime("%Y-%m-%dT%H:%M:%S"),
                ) or ""
            except ValueError:
                pass  # malformed stored date/time — skip the Zoom link, .ics still works

        with db_lock:
            conn = get_db()
            conn.execute(
                "UPDATE appointments SET status = ?, zoom_join_url = ? WHERE id = ? AND user_id = ?",
                (status, zoom_join_url, appt_id, user_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM appointments WHERE id = ? AND user_id = ?", (appt_id, user_id)
            ).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "appointment": appointment_row_to_json(row)})

    def handle_appointment_ics(self, query):
        """Serves a standard .ics calendar invite for one appointment — works in any real
        calendar app with no API keys. Includes a real Zoom link in the description/location
        if one was created (see handle_update_appointment_status), otherwise just the interview
        details."""
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        appt_id = query.get("id", [None])[0]
        if not appt_id:
            return self.send_json(400, {"error": "Missing appointment id."})
        with db_lock:
            conn = get_db()
            row = conn.execute(
                "SELECT * FROM appointments WHERE id = ? AND user_id = ?", (appt_id, user_id)
            ).fetchone()
            conn.close()
        if row is None:
            return self.send_json(404, {"error": "Appointment not found."})

        try:
            start_dt = datetime.datetime.strptime(
                f"{row['appt_date']} {row['appt_time'] or '09:00'}", "%Y-%m-%d %H:%M"
            )
        except ValueError:
            start_dt = datetime.datetime.strptime(row["appt_date"], "%Y-%m-%d")

        location = row["zoom_join_url"] or ""
        description = row["notes"] or ""
        if location:
            description = (description + "\n\nJoin: " + location).strip()
        ics_text = build_ics_invite(
            uid=f"appt-{row['id']}",
            summary=f"Interview: {row['role'] or 'Role'} at {row['company']}",
            description=description,
            start_dt=start_dt,
            location=location,
        )
        body = ics_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/calendar; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="interview-{row["id"]}.ics"')
        self.end_headers()
        self.wfile.write(body)

    def handle_cancel_appointment(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if not data or not data.get("id"):
            return self.send_json(400, {"error": "Missing appointment id."})
        with db_lock:
            conn = get_db()
            conn.execute("DELETE FROM appointments WHERE id = ? AND user_id = ?", (data["id"], user_id))
            conn.commit()
            conn.close()
        self.send_json(200, {"ok": True})

    # ---------- applications ----------

    def handle_create_application(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        job_title = (data.get("jobTitle") or "").strip()
        company = (data.get("company") or "").strip()
        if not job_title or not company:
            return self.send_json(400, {"error": "Missing job title or company."})

        with db_lock:
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO applications (user_id, job_title, company, application_link) VALUES (?, ?, ?, ?)",
                    (user_id, job_title, company, (data.get("applicationLink") or "").strip()),
                )
                conn.commit()
            except Exception as e:
                if not is_duplicate_key_error(e):
                    conn.close()
                    raise
                # already applied — treat as a no-op success, not an error
            row = conn.execute(
                "SELECT * FROM applications WHERE user_id = ? AND job_title = ? AND company = ?",
                (user_id, job_title, company),
            ).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "application": application_row_to_json(row)})

    def handle_list_applications(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(200, {"applications": []})
        with db_lock:
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM applications WHERE user_id = ? ORDER BY id DESC", (user_id,)
            ).fetchall()
            conn.close()
        self.send_json(200, {"applications": [application_row_to_json(r) for r in rows]})

    def handle_update_application_status(self):
        """Backs the Kanban board's drag-and-drop — moves one application to a new stage."""
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        app_id = data.get("id")
        status = (data.get("status") or "").strip().lower()
        if not app_id or status not in APPLICATION_STATUSES:
            return self.send_json(400, {"error": "Missing or invalid application id/status."})

        with db_lock:
            conn = get_db()
            conn.execute(
                "UPDATE applications SET status = ? WHERE id = ? AND user_id = ?",
                (status, app_id, user_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM applications WHERE id = ? AND user_id = ?", (app_id, user_id)
            ).fetchone()
            conn.close()
        if row is None:
            return self.send_json(404, {"error": "Application not found."})
        self.send_json(200, {"ok": True, "application": application_row_to_json(row)})

    # ---------- employer accounts, subscriptions, bank verification ----------

    def handle_employer_signup(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        company_name = (data.get("companyName") or "").strip()

        if not EMAIL_RE.match(email):
            return self.send_json(400, {"error": "Enter a valid email address."})
        if len(password) < 6:
            return self.send_json(400, {"error": "Password must be at least 6 characters."})
        if not company_name:
            return self.send_json(400, {"error": "Company name is required."})

        corporate_domain = email.split("@")[-1] if "@" in email else ""
        salt, pw_hash = hash_password(password)

        with db_lock:
            conn = get_db()
            try:
                cur = conn.execute(
                    "INSERT INTO employers (email, salt, password_hash, company_name, corporate_domain) VALUES (?, ?, ?, ?, ?)",
                    (email, salt, pw_hash, company_name, corporate_domain),
                )
                employer_id = cur.lastrowid
                conn.execute(
                    "INSERT INTO subscriptions (employer_id, tier, status) VALUES (?, 'sme_starter', 'active')",
                    (employer_id,),
                )
                conn.commit()
            except Exception as e:
                conn.close()
                if is_duplicate_key_error(e):
                    return self.send_json(409, {"error": "An employer account with this email already exists."})
                raise
            row = conn.execute("SELECT * FROM employers WHERE id = ?", (employer_id,)).fetchone()
            sub_row = conn.execute("SELECT * FROM subscriptions WHERE employer_id = ?", (employer_id,)).fetchone()
            conn.close()

        token = create_employer_session(employer_id)
        self.send_json(
            200, {"ok": True, "employer": employer_row_to_json(row), "subscription": subscription_row_to_json(sub_row)},
            set_cookie=token, cookie_name=EMPLOYER_SESSION_COOKIE,
        )

    def handle_employer_login(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if is_account_locked(email):
            return self.send_json(423, {"error": "Too many failed sign-in attempts. This account is temporarily locked — try again in a few minutes."})

        with db_lock:
            conn = get_db()
            employer = conn.execute("SELECT * FROM employers WHERE email = ?", (email,)).fetchone()
            if employer is None or not verify_password(password, employer["salt"], employer["password_hash"]):
                conn.close()
                record_failed_login(email)
                return self.send_json(401, {"error": "Incorrect email or password."})
            sub_row = conn.execute("SELECT * FROM subscriptions WHERE employer_id = ?", (employer["id"],)).fetchone()
            conn.close()

        clear_failed_logins(email)
        token = create_employer_session(employer["id"])
        self.send_json(
            200, {"ok": True, "employer": employer_row_to_json(employer), "subscription": subscription_row_to_json(sub_row)},
            set_cookie=token, cookie_name=EMPLOYER_SESSION_COOKIE,
        )

    def handle_employer_logout(self):
        token = self.get_cookie(EMPLOYER_SESSION_COOKIE)
        if token:
            with db_lock:
                conn = get_db()
                conn.execute("DELETE FROM employer_sessions WHERE token=?", (token,))
                conn.commit()
                conn.close()
        self.send_json(200, {"ok": True}, clear_cookie=True, cookie_name=EMPLOYER_SESSION_COOKIE)

    def handle_employer_me(self):
        employer_id = self.current_employer_id()
        if employer_id is None:
            return self.send_json(200, {"loggedIn": False})
        with db_lock:
            conn = get_db()
            employer = conn.execute("SELECT * FROM employers WHERE id = ?", (employer_id,)).fetchone()
            if employer is None:
                conn.close()
                return self.send_json(200, {"loggedIn": False})
            sub_row = conn.execute("SELECT * FROM subscriptions WHERE employer_id = ?", (employer_id,)).fetchone()
            bank_row = conn.execute("SELECT * FROM bank_accounts WHERE employer_id = ?", (employer_id,)).fetchone()
            conn.close()
        self.send_json(200, {
            "loggedIn": True,
            "employer": employer_row_to_json(employer),
            "subscription": subscription_row_to_json(sub_row),
            "bankAccount": bank_account_row_to_json(bank_row),
        })

    def handle_employer_subscribe(self):
        """Initializes a Paystack transaction against the Pro Growth plan and returns the hosted
        checkout URL — the employer completes payment entirely on Paystack's own page, so this
        server never sees a card number. The subscription itself only actually activates once
        handle_paystack_webhook receives and verifies a real charge.success/subscription.create
        event; this endpoint just starts that process."""
        if not PAYSTACK_CONFIGURED:
            return self.send_json(503, {"error": "Payments aren't set up yet — please check back soon."})
        if not PAYSTACK_PLAN_CODE_PRO_GROWTH:
            return self.send_json(503, {"error": "The Pro Growth plan isn't configured yet — please check back soon."})
        employer_id = self.current_employer_id()
        if employer_id is None:
            return self.send_json(401, {"error": "Sign in as an employer first."})
        data = self.read_json_body() or {}
        billing_cycle = data.get("billingCycle") if data.get("billingCycle") in ("monthly", "annual") else "monthly"

        with db_lock:
            conn = get_db()
            employer = conn.execute("SELECT * FROM employers WHERE id = ?", (employer_id,)).fetchone()
            conn.close()
        if employer is None:
            return self.send_json(401, {"error": "Sign in as an employer first."})

        amount_kobo = (PRO_GROWTH_ANNUAL_NGN if billing_cycle == "annual" else PRO_GROWTH_MONTHLY_NGN) * 100
        try:
            result = call_paystack("POST", "/transaction/initialize", {
                "email": employer["email"],
                "amount": amount_kobo,
                "plan": PAYSTACK_PLAN_CODE_PRO_GROWTH if billing_cycle == "monthly" else None,
                "metadata": {"employerId": employer_id, "billingCycle": billing_cycle, "tier": "pro_growth"},
            })
        except urllib.error.HTTPError as e:
            print("Paystack initialize error:", e.code, e.read().decode("utf-8", errors="replace"))
            return self.send_json(502, {"error": "Couldn't start checkout — please try again."})
        except Exception as e:
            print("Paystack initialize request failed:", e)
            return self.send_json(502, {"error": "Couldn't start checkout — please try again."})

        if not result.get("status"):
            return self.send_json(502, {"error": result.get("message") or "Couldn't start checkout — please try again."})
        self.send_json(200, {
            "authorizationUrl": result["data"]["authorization_url"],
            "reference": result["data"]["reference"],
        })

    def handle_paystack_webhook(self):
        """The only path that is ever allowed to actually change a subscription's status — never
        the client. Paystack signs every webhook body with HMAC-SHA512 using the secret key; a
        request without a valid x-paystack-signature header is dropped before touching the
        database, so a forged POST to this URL can't grant free access to Pro Growth."""
        raw_body = self._drain_request_body() or b""
        if not PAYSTACK_CONFIGURED:
            return self.send_json(503, {"error": "Payments aren't set up yet."})

        signing_key = PAYSTACK_WEBHOOK_SECRET or PAYSTACK_SECRET_KEY
        expected_sig = hmac.new(signing_key.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
        given_sig = self.headers.get("x-paystack-signature", "")
        if not given_sig or not hmac.compare_digest(expected_sig, given_sig):
            print("[security] Rejected a Paystack webhook with an invalid/missing signature.")
            return self.send_json(401, {"error": "Invalid signature."})

        try:
            event = json.loads(raw_body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self.send_json(400, {"error": "Malformed payload."})

        event_type = event.get("event")
        payload = event.get("data") or {}

        if event_type in ("charge.success", "subscription.create"):
            metadata = payload.get("metadata") or {}
            employer_id = metadata.get("employerId")
            if not employer_id:
                # Not one of our tagged checkout sessions (e.g. a Paystack test ping) — 200 so
                # Paystack doesn't keep retrying, but nothing to update.
                return self.send_json(200, {"ok": True})
            billing_cycle = metadata.get("billingCycle", "monthly")
            sub_code = payload.get("subscription_code") or (payload.get("plan") or {}).get("plan_code", "")
            period_days = 365 if billing_cycle == "annual" else 30
            period_end = (datetime.datetime.utcnow() + datetime.timedelta(days=period_days)).strftime("%Y-%m-%d %H:%M:%S")
            with db_lock:
                conn = get_db()
                conn.execute(
                    """UPDATE subscriptions SET tier='pro_growth', status='active', billing_cycle=?,
                       paystack_subscription_code=?, current_period_end=?, updated_at=datetime('now')
                       WHERE employer_id=?""",
                    (billing_cycle, sub_code, period_end, employer_id),
                )
                conn.commit()
                conn.close()
            print(f"[paystack] employer {employer_id} upgraded to Pro Growth ({billing_cycle}).")
        elif event_type in ("subscription.disable", "subscription.not_renew"):
            metadata = payload.get("metadata") or {}
            employer_id = metadata.get("employerId")
            if employer_id:
                with db_lock:
                    conn = get_db()
                    conn.execute(
                        "UPDATE subscriptions SET status='cancelled', updated_at=datetime('now') WHERE employer_id=?",
                        (employer_id,),
                    )
                    conn.commit()
                    conn.close()

        self.send_json(200, {"ok": True})

    def handle_list_banks(self):
        self.send_json(200, {"banks": NIGERIAN_BANKS})

    def handle_bank_resolve(self, query):
        """Read-only NUBAN lookup — no money moves, this only confirms whose name is registered
        against an account number, the standard Nigerian anti-fraud check before saving anyone's
        bank details."""
        if not PAYSTACK_CONFIGURED:
            return self.send_json(503, {"error": "Bank verification isn't set up yet — please check back soon."})
        account_number = (query.get("accountNumber", [""])[0] or "").strip()
        bank_code = (query.get("bankCode", [""])[0] or "").strip()
        if not re.fullmatch(r"\d{10}", account_number):
            return self.send_json(400, {"error": "Enter a 10-digit account number."})
        if not bank_code:
            return self.send_json(400, {"error": "Select a bank."})
        try:
            result = call_paystack("GET", f"/bank/resolve?account_number={account_number}&bank_code={bank_code}")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            print("Paystack bank-resolve error:", e.code, detail)
            if e.code == 422:
                return self.send_json(422, {"error": "Couldn't verify that account — double-check the number and bank."})
            return self.send_json(502, {"error": "Couldn't verify that account right now — please try again."})
        except Exception as e:
            print("Paystack bank-resolve request failed:", e)
            return self.send_json(502, {"error": "Couldn't verify that account right now — please try again."})
        if not result.get("status"):
            return self.send_json(422, {"error": result.get("message") or "Couldn't verify that account."})
        self.send_json(200, {"accountName": result["data"]["account_name"]})

    def handle_save_bank_account(self):
        """Only ever stores an account_name that Paystack itself resolved and returned in THIS
        request — never a client-submitted name, which would defeat the entire point of NUBAN
        verification (confirming who actually owns the account)."""
        if not PAYSTACK_CONFIGURED:
            return self.send_json(503, {"error": "Bank verification isn't set up yet — please check back soon."})
        employer_id = self.current_employer_id()
        if employer_id is None:
            return self.send_json(401, {"error": "Sign in as an employer first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        account_number = (data.get("accountNumber") or "").strip()
        bank_code = (data.get("bankCode") or "").strip()
        bank_name = (data.get("bankName") or "").strip()
        if not re.fullmatch(r"\d{10}", account_number) or not bank_code:
            return self.send_json(400, {"error": "Provide a valid 10-digit account number and bank."})

        try:
            result = call_paystack("GET", f"/bank/resolve?account_number={account_number}&bank_code={bank_code}")
        except Exception as e:
            print("Paystack bank-resolve (save) failed:", e)
            return self.send_json(502, {"error": "Couldn't verify that account right now — please try again."})
        if not result.get("status"):
            return self.send_json(422, {"error": result.get("message") or "Couldn't verify that account."})
        account_name = result["data"]["account_name"]

        with db_lock:
            conn = get_db()
            conn.execute(
                """INSERT INTO bank_accounts (employer_id, bank_code, bank_name, account_number, account_name, verified_at)
                   VALUES (?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(employer_id) DO UPDATE SET bank_code=excluded.bank_code, bank_name=excluded.bank_name,
                   account_number=excluded.account_number, account_name=excluded.account_name, verified_at=datetime('now')""",
                (employer_id, bank_code, bank_name, encrypt_field(account_number), encrypt_field(account_name)),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM bank_accounts WHERE employer_id = ?", (employer_id,)).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "bankAccount": bank_account_row_to_json(row)})

    def handle_get_pipeline(self):
        """Only ever available to employers with a real account — the anonymous job-posting flow
        has no durable identity to hang stage history off of."""
        employer_id = self.current_employer_id()
        if employer_id is None:
            return self.send_json(200, {"loggedIn": False, "stages": {}})
        with db_lock:
            conn = get_db()
            rows = conn.execute(
                "SELECT candidate_user_id, stage, updated_at FROM candidate_pipeline WHERE employer_id = ?",
                (employer_id,),
            ).fetchall()
            conn.close()
        stages = {str(r["candidate_user_id"]): {"stage": r["stage"], "updatedAt": r["updated_at"]} for r in rows}
        self.send_json(200, {"loggedIn": True, "stages": stages})

    def handle_set_pipeline_stage(self):
        employer_id = self.current_employer_id()
        if employer_id is None:
            return self.send_json(401, {"error": "Sign in as an employer first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        candidate_user_id = data.get("candidateUserId")
        stage = (data.get("stage") or "").strip().lower()
        if not candidate_user_id or stage not in PIPELINE_STAGES:
            return self.send_json(400, {"error": "A valid candidate and stage are required."})

        with db_lock:
            conn = get_db()
            employer = conn.execute("SELECT company_name FROM employers WHERE id = ?", (employer_id,)).fetchone()
            candidate = conn.execute(
                "SELECT whatsapp_number, whatsapp_alerts_enabled FROM profiles WHERE user_id = ?",
                (candidate_user_id,),
            ).fetchone()
            if candidate is None:
                conn.close()
                return self.send_json(404, {"error": "Candidate not found."})
            conn.execute(
                """INSERT INTO candidate_pipeline (employer_id, candidate_user_id, stage, updated_at)
                   VALUES (?, ?, ?, datetime('now'))
                   ON CONFLICT(employer_id, candidate_user_id) DO UPDATE SET stage=excluded.stage, updated_at=datetime('now')""",
                (employer_id, candidate_user_id, stage),
            )
            notif_message = None
            if stage in PIPELINE_STAGE_LABELS:
                notif_message = f"{employer['company_name']} has {PIPELINE_STAGE_LABELS[stage]}."
                conn.execute(
                    "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, '', ?)",
                    (candidate_user_id, "pipeline_stage", notif_message, employer["company_name"]),
                )
            conn.commit()
            conn.close()
        if notif_message and candidate["whatsapp_alerts_enabled"]:
            send_whatsapp_alert(decrypt_field(candidate["whatsapp_number"]), notif_message)
        self.send_json(200, {"ok": True, "stage": stage})

    def handle_known_skills(self):
        """Real autosuggest source for the free-text skill inputs — built entirely from skills
        that already exist in the app's real data (skill-challenge topics plus every distinct
        skill tag on a real or employer-posted job), never a fabricated master list."""
        skills = set(SKILL_CHALLENGES.keys())
        with db_lock:
            conn = get_db()
            for table in ("imported_jobs", "employer_posted_jobs"):
                for row in conn.execute(f"SELECT skills FROM {table}").fetchall():
                    for s in json.loads(row["skills"] or "[]"):
                        if s:
                            skills.add(s)
            conn.close()
        self.send_json(200, {"skills": sorted(skills, key=str.lower)})

    # ---------- employer job posting + real candidate matching ----------

    def handle_post_employer_job(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        title = (data.get("title") or "").strip()
        company = (data.get("company") or "").strip()
        if not title or not company:
            return self.send_json(400, {"error": "Job title and company are required."})

        skills = data.get("skills") or []
        level = (data.get("level") or "").strip()
        location = (data.get("location") or "").strip()
        ppa_state_filter = (data.get("ppaState") or "").strip()
        perks = [p for p in (data.get("perks") or []) if p in PERK_LABELS]
        try:
            pay_min = int(data.get("payMin") or 0)
            pay_max = int(data.get("payMax") or 0)
        except (TypeError, ValueError):
            pay_min, pay_max = 0, 0

        with db_lock:
            conn = get_db()
            cur = conn.execute(
                """INSERT INTO employer_posted_jobs (title, company, level, location, skills, pay_min, pay_max, perks)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (title, company, level, location, json.dumps(skills), pay_min, pay_max, json.dumps(perks)),
            )
            job_id = cur.lastrowid

            rows = conn.execute(
                "SELECT p.*, u.id AS uid FROM profiles p JOIN users u ON u.id = p.user_id"
            ).fetchall()

            matches = []
            notified = 0
            for row in rows:
                cand_skills = json.loads(row["skills"] or "[]")
                if not cand_skills:
                    continue  # skip accounts that haven't picked any skills yet — nothing real to match on
                if ppa_state_filter and (row["ppa_state"] or "").strip().lower() != ppa_state_filter.lower():
                    continue  # employer asked for a specific (self-declared) PPA state only
                score = match_score(skills, cand_skills, level, row["career_level"], location, row["preferred_location"])
                matches.append({
                    "userId": row["uid"],
                    "fullName": decrypt_field(row["full_name"]) or "Bridge NG member",
                    "careerLevel": row["career_level"],
                    "fieldOfStudy": row["field_of_study"],
                    "preferredLocation": row["preferred_location"],
                    "ppaState": row["ppa_state"] or "",
                    "nyscStatus": row["nysc_status"] or "",
                    "hasPitch": bool(row["pitch_media_kind"]),
                    "skills": cand_skills,
                    "score": score,
                    "verifiedBadges": json.loads(row["verified_badges"] or "[]"),
                    "portfolioLink": row["portfolio_link"] or "",
                    "reliability": compute_reliability_stats(conn, row["uid"]),
                })
                if score >= 60:
                    perk_note = (" (" + ", ".join(PERK_LABELS[p] for p in perks) + ")") if perks else ""
                    message = f"A new role matches your profile: {title} at {company} — {score}% match.{perk_note}"
                    conn.execute(
                        "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, ?, ?)",
                        (row["uid"], "employer_match", message, title, company),
                    )
                    notified += 1
                    if row["whatsapp_alerts_enabled"]:
                        send_whatsapp_alert(decrypt_field(row["whatsapp_number"]), message)
            conn.commit()
            conn.close()

        matches.sort(key=lambda m: m["score"], reverse=True)
        self.send_json(200, {
            "ok": True, "jobId": job_id,
            "realMatches": matches[:10],
            "notifiedCount": notified,
            "perks": perks,
        })

    # ---------- messaging (Smart Sourcing) ----------
    # There's no employer login anywhere in this app — the whole employer side is an
    # unauthenticated form (same trust model as handle_post_employer_job above: anyone can type
    # any company name). So the employer's identity for messaging is just "whoever holds this
    # conversation's private token", generated here and never guessable/enumerable, rather than
    # a real authenticated account. The candidate side IS behind real login, same as everywhere
    # else in the app.

    def handle_message_start(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        candidate_user_id = data.get("candidateUserId")
        company = (data.get("company") or "").strip()
        job_title = (data.get("jobTitle") or "").strip()
        body = (data.get("body") or "").strip()[:MAX_MESSAGE_LENGTH]
        if not candidate_user_id or not company or not body:
            return self.send_json(400, {"error": "Missing candidate, company, or message."})

        with db_lock:
            conn = get_db()
            candidate = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (candidate_user_id,)).fetchone()
            if candidate is None:
                conn.close()
                return self.send_json(404, {"error": "Candidate not found."})
            token = secrets.token_urlsafe(24)
            cur = conn.execute(
                "INSERT INTO conversations (candidate_user_id, company, job_title, employer_token) VALUES (?, ?, ?, ?)",
                (candidate_user_id, company, job_title, token),
            )
            conversation_id = cur.lastrowid
            conn.execute(
                "INSERT INTO messages (conversation_id, sender_role, body, read_by_employer) VALUES (?, 'employer', ?, 1)",
                (conversation_id, body),
            )
            notif_message = f"{company} sent you a message about {job_title or 'a role'}."
            conn.execute(
                "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, ?, ?)",
                (candidate_user_id, "employer_message", notif_message, job_title, company),
            )
            conn.commit()
            conn.close()
        if candidate["whatsapp_alerts_enabled"]:
            send_whatsapp_alert(decrypt_field(candidate["whatsapp_number"]), notif_message)
        self.send_json(200, {"ok": True, "conversationId": conversation_id, "employerToken": token})

    def handle_employer_message_thread(self, query):
        conversation_id = query.get("id", [None])[0]
        token = query.get("token", [None])[0]
        if not conversation_id or not token:
            return self.send_json(400, {"error": "Missing conversation id or token."})
        with db_lock:
            conn = get_db()
            convo = conn.execute(
                "SELECT * FROM conversations WHERE id = ? AND employer_token = ?", (conversation_id, token)
            ).fetchone()
            if convo is None:
                conn.close()
                return self.send_json(404, {"error": "Conversation not found."})
            rows = conn.execute(
                "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id", (conversation_id,)
            ).fetchall()
            conn.execute("UPDATE messages SET read_by_employer = 1 WHERE conversation_id = ?", (conversation_id,))
            conn.commit()
            conn.close()
        self.send_json(200, {
            "conversation": {"id": convo["id"], "company": convo["company"], "jobTitle": convo["job_title"]},
            "messages": [message_row_to_json(r) for r in rows],
        })

    def handle_employer_message_reply(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        conversation_id = data.get("conversationId")
        token = (data.get("token") or "").strip()
        body = (data.get("body") or "").strip()[:MAX_MESSAGE_LENGTH]
        if not conversation_id or not token or not body:
            return self.send_json(400, {"error": "Missing conversation, token, or message."})
        with db_lock:
            conn = get_db()
            convo = conn.execute(
                "SELECT * FROM conversations WHERE id = ? AND employer_token = ?", (conversation_id, token)
            ).fetchone()
            if convo is None:
                conn.close()
                return self.send_json(404, {"error": "Conversation not found."})
            conn.execute(
                "INSERT INTO messages (conversation_id, sender_role, body, read_by_employer) VALUES (?, 'employer', ?, 1)",
                (conversation_id, body),
            )
            notif_message = f"{convo['company']} replied to your conversation."
            conn.execute(
                "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, ?, ?)",
                (convo["candidate_user_id"], "employer_message", notif_message, convo["job_title"], convo["company"]),
            )
            candidate = conn.execute(
                "SELECT whatsapp_number, whatsapp_alerts_enabled FROM profiles WHERE user_id = ?",
                (convo["candidate_user_id"],),
            ).fetchone()
            conn.commit()
            conn.close()
        if candidate is not None and candidate["whatsapp_alerts_enabled"]:
            send_whatsapp_alert(decrypt_field(candidate["whatsapp_number"]), notif_message)
        self.send_json(200, {"ok": True})

    def handle_list_conversations(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(200, {"conversations": []})
        with db_lock:
            conn = get_db()
            convos = conn.execute(
                "SELECT * FROM conversations WHERE candidate_user_id = ? ORDER BY id DESC", (user_id,)
            ).fetchall()
            result = []
            for c in convos:
                messages = conn.execute(
                    "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id", (c["id"],)
                ).fetchall()
                result.append({
                    "id": c["id"], "company": c["company"], "jobTitle": c["job_title"], "createdAt": c["created_at"],
                    "messages": [message_row_to_json(m) for m in messages],
                    "unread": sum(1 for m in messages if m["sender_role"] == "employer" and not m["read_by_candidate"]),
                })
            conn.close()
        self.send_json(200, {"conversations": result})

    def handle_reply_to_conversation(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})
        conversation_id = data.get("conversationId")
        body = (data.get("body") or "").strip()[:MAX_MESSAGE_LENGTH]
        if not conversation_id or not body:
            return self.send_json(400, {"error": "Missing conversation or message."})
        with db_lock:
            conn = get_db()
            convo = conn.execute(
                "SELECT * FROM conversations WHERE id = ? AND candidate_user_id = ?", (conversation_id, user_id)
            ).fetchone()
            if convo is None:
                conn.close()
                return self.send_json(404, {"error": "Conversation not found."})
            conn.execute(
                "INSERT INTO messages (conversation_id, sender_role, body, read_by_candidate) VALUES (?, 'candidate', ?, 1)",
                (conversation_id, body),
            )
            conn.commit()
            conn.close()
        self.send_json(200, {"ok": True})

    def handle_mark_conversation_read(self):
        user_id = self.current_user_id()
        if user_id is None:
            return self.send_json(401, {"error": "You need to sign in first."})
        data = self.read_json_body()
        if not data or not data.get("conversationId"):
            return self.send_json(400, {"error": "Missing conversation id."})
        with db_lock:
            conn = get_db()
            convo = conn.execute(
                "SELECT id FROM conversations WHERE id = ? AND candidate_user_id = ?",
                (data["conversationId"], user_id),
            ).fetchone()
            if convo is not None:
                conn.execute(
                    "UPDATE messages SET read_by_candidate = 1 WHERE conversation_id = ?", (data["conversationId"],)
                )
                conn.commit()
            conn.close()
        self.send_json(200, {"ok": True})

    def handle_chat(self):
        if not NVIDIA_API_KEY:
            print("Chat request received but NVIDIA_API_KEY is not set — see startup message for how to enable it.")
            return self.send_json(
                503,
                {"error": "Ask Bridge AI is still getting set up and isn't quite ready yet — please check back soon!"},
            )
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": CHAT_FALLBACK_MESSAGE})

        messages = data.get("messages") or []
        context = data.get("context") or ""
        if not isinstance(messages, list) or not messages:
            return self.send_json(400, {"error": "I didn't catch a question there — try typing it again?"})

        system_prompt = (
            "You are Bridge AI, the assistant embedded in Bridge NG, a Nigerian job-matching platform. "
            "Answer any question about the website (what each tab does, how to use a feature), about the "
            "specific job, candidate, and remote-role listings using the reference data below, and general "
            "career/job-search questions for the Nigerian market. You do not have live internet access, so "
            "answer from the reference data and your own knowledge rather than claiming to browse the web. "
            "Keep answers concise, warm, and practical.\n\n"
            "Reference data about the website and its current listings:\n" + context
        )
        chat_messages = [{"role": "system", "content": system_prompt}] + messages

        try:
            reply = call_nvidia(chat_messages)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            print("NVIDIA chat error:", e.code, detail)
            record_ai_error("chat", NVIDIA_MODEL, e.code, detail)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except (KeyError, IndexError) as e:
            print("Unexpected NVIDIA chat response shape:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except Exception as e:
            print("NVIDIA chat request failed:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})

        self.send_json(200, {"reply": reply})

    def handle_resume_find_job(self):
        if not NVIDIA_API_KEY:
            return self.send_json(
                503,
                {"error": "Ask Bridge AI is still getting set up and isn't quite ready yet — please check back soon!"},
            )
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": CHAT_FALLBACK_MESSAGE})

        job_text = (data.get("jobText") or "").strip()
        if not job_text:
            return self.send_json(400, {"error": "Paste the job you're applying for first."})

        system_prompt = (
            "You classify job postings for Bridge NG, a Nigerian job-matching platform. You do not have live "
            "internet access — work only from the pasted text below and your own general knowledge. Identify "
            "the role, and judge whether it is based in Nigeria and/or offered as fully remote.\n\n"
            "Respond with ONLY a JSON object (no markdown fences, no commentary) matching exactly this shape:\n"
            '{"title": string, "company": string, "location": string, "level": string, '
            '"isNigeria": boolean, "isRemote": boolean, "applicationLink": string, '
            '"skills": [string, ...], "summary": string}\n\n'
            "Only set applicationLink if a real URL literally appears in the pasted text — never invent or "
            "guess one, since you can't verify it. skills should be 3-8 short skill names relevant to the role. "
            "summary should be 1-2 sentences."
        )
        try:
            reply = call_nvidia([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": job_text},
            ])
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            print("NVIDIA job-lookup error:", e.code, detail)
            record_ai_error("job-lookup", NVIDIA_MODEL, e.code, detail)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except (KeyError, IndexError) as e:
            print("Unexpected NVIDIA job-lookup response shape:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except Exception as e:
            print("NVIDIA job-lookup request failed:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})

        self.send_json(200, parse_job_info_json(reply, job_text))

    def handle_job_match(self):
        if not NVIDIA_API_KEY:
            return self.send_json(
                503,
                {"error": "Ask Bridge AI is still getting set up and isn't quite ready yet — please check back soon!"},
            )
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": CHAT_FALLBACK_MESSAGE})

        skills = data.get("skills") or []
        resume_text = (data.get("resumeText") or "").strip()
        resume_file = data.get("resumeFile") or None
        jobs = data.get("jobs") or []

        image_part = None
        if resume_file:
            kind = resume_file.get("kind")
            b64 = resume_file.get("base64") or ""
            if kind == "pdf":
                if PdfReader is None:
                    return self.send_json(
                        500,
                        {"error": "PDF resume support isn't installed on the server yet — try a JPG/PNG, or paste your resume text instead."},
                    )
                try:
                    pdf_bytes = base64.b64decode(b64)
                    reader = PdfReader(io.BytesIO(pdf_bytes))
                    resume_text = "\n".join((page.extract_text() or "") for page in reader.pages).strip()
                except Exception as e:
                    print("PDF extraction failed:", e)
                    return self.send_json(400, {"error": "Couldn't read that PDF. Try a JPG/PNG instead, or paste your resume text directly."})
                if len(resume_text) < 50:
                    return self.send_json(
                        400,
                        {"error": "Couldn't find readable text in that PDF (it may be a scanned image). Try a JPG/PNG instead, or paste your resume text directly."},
                    )
            elif kind == "image":
                media_type = resume_file.get("mediaType") or "image/jpeg"
                image_part = {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{b64}"}}

        if not resume_text and not image_part:
            return self.send_json(400, {"error": "Upload or paste your CV/resume first, in Resume Studio."})

        # Capped so the prompt stays a reasonable size no matter how large the synced jobs
        # list grows — this is a match against currently-open roles, not an archive search.
        trimmed_jobs = [
            {
                "id": j.get("id"),
                "title": j.get("title", ""),
                "company": j.get("company", ""),
                "location": j.get("loc", ""),
                "level": j.get("level", ""),
                "skills": j.get("skills") or [],
                "summary": (j.get("desc") or "")[:200],
            }
            for j in jobs[:60] if isinstance(j, dict) and j.get("id") is not None
        ]
        if not trimmed_jobs:
            return self.send_json(400, {"error": "No open roles available to match against right now."})

        system_prompt = (
            "You are Bridge AI, matching a Nigerian job seeker to the best-fitting currently-open "
            "role(s) from a FIXED list of real listings provided below. Only recommend jobs from "
            "this list — never invent a company, title, or role that isn't in it. If nothing in "
            "the list is a reasonable fit, say so honestly by returning an empty matches list "
            "rather than forcing a bad match.\n\n"
            "Return ONLY a JSON object (no markdown fences, no commentary) matching exactly this "
            'shape:\n{"matches": [{"id": <integer id from the list>, "reason": "one or two '
            'sentence explanation referencing specific skills/experience"}, ...]}\n\n'
            "Return at most 3 matches, best fit first. Only include a job if it's a genuinely "
            "reasonable fit given the skills/resume — do not pad the list to reach 3."
        )

        user_text = (
            f"Candidate's selected skills: {', '.join(skills) if skills else '(none selected)'}\n\n"
            f'Open roles (JSON — use the "id" field to refer to a role):\n{json.dumps(trimmed_jobs)}'
        )
        if resume_text:
            user_text += f'\n\nCandidate\'s resume:\n"""\n{resume_text}\n"""'
        else:
            user_text += "\n\nThe candidate's resume is attached as an image — read it directly."

        if image_part:
            user_content = [{"type": "text", "text": user_text}, image_part]
        else:
            user_content = user_text

        models_to_try = [NVIDIA_RESUME_MODEL, NVIDIA_MODEL]
        try:
            reply = call_nvidia_with_fallbacks(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                models_to_try, timeout=110, source="job-match",
            )
        except urllib.error.HTTPError as e:
            print("NVIDIA job-match error:", e.code, e.read().decode("utf-8", errors="replace"))
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except (KeyError, IndexError) as e:
            print("Unexpected NVIDIA job-match response shape:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except Exception as e:
            print("NVIDIA job-match request failed:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})

        valid_ids = {j["id"] for j in trimmed_jobs}
        self.send_json(200, {"matches": parse_job_match_json(reply, valid_ids)})

    def handle_resume_generate(self):
        if not NVIDIA_API_KEY:
            return self.send_json(
                503,
                {"error": "Ask Bridge AI is still getting set up and isn't quite ready yet — please check back soon!"},
            )
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": CHAT_FALLBACK_MESSAGE})

        mode = data.get("mode")
        if mode not in ("tailor", "cover"):
            return self.send_json(400, {"error": CHAT_FALLBACK_MESSAGE})

        job_info = data.get("jobInfo") or {}
        resume_text = (data.get("resumeText") or "").strip()
        resume_file = data.get("resumeFile") or None
        candidate_name = (data.get("candidateName") or "the candidate").strip()

        image_part = None
        if resume_file:
            kind = resume_file.get("kind")
            b64 = resume_file.get("base64") or ""
            if kind == "pdf":
                if PdfReader is None:
                    return self.send_json(
                        500,
                        {"error": "PDF resume support isn't installed on the server yet — try a JPG/PNG, or paste your resume text instead."},
                    )
                try:
                    pdf_bytes = base64.b64decode(b64)
                    reader = PdfReader(io.BytesIO(pdf_bytes))
                    resume_text = "\n".join((page.extract_text() or "") for page in reader.pages).strip()
                except Exception as e:
                    print("PDF extraction failed:", e)
                    return self.send_json(400, {"error": "Couldn't read that PDF. Try a JPG/PNG instead, or paste your resume text directly."})
                if len(resume_text) < 50:
                    return self.send_json(
                        400,
                        {"error": "Couldn't find readable text in that PDF (it may be a scanned image). Try a JPG/PNG instead, or paste your resume text directly."},
                    )
            elif kind == "image":
                media_type = resume_file.get("mediaType") or "image/jpeg"
                image_part = {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{b64}"}}

        if not resume_text and not image_part:
            return self.send_json(400, {"error": "Upload or paste your CV/resume first."})

        job_desc = (
            f"Job: {job_info.get('title','')} at {job_info.get('company','')}, {job_info.get('location','')}\n"
            f"Experience level: {job_info.get('level','')}\n"
            f"Key skills: {', '.join(job_info.get('skills') or [])}\n"
            f"Details: {job_info.get('summary','')}"
        )

        markup_rules = (
            "Format the output using this exact style, so it can be rendered with real structure "
            "instead of flat text:\n"
            '- Put the candidate\'s full name alone on the first line, in "**bold**".\n'
            '- Start each major section with its name alone on a line in "**bold**", ending with a '
            'colon (e.g. "**Contact Information:**", "**Professional Experience:**", "**Education:**", '
            '"**Technical Skills:**").\n'
            '- Use "* " at the start of a line for a bullet point (e.g. each contact detail, each '
            'skill, each job or degree entry).\n'
            '- For a bulleted entry that has its own sub-details (e.g. achievements under a job '
            'title), put those sub-details on their own lines starting with a tab then "+ ".\n'
            '- Wrap a bullet\'s lead-in text in "**bold**" when it names something specific, like a '
            'job title/company/dates line or a degree/institution line.\n'
            "- Write each bullet or paragraph as a single line — never wrap it across multiple lines.\n"
            '- Use no other markdown (no numbered lists, no italics, no tables, no code fences, no "##").'
        )

        if mode == "tailor":
            instruction = (
                "You are a professional resume writer helping a Nigerian job seeker tailor their CV for one "
                "specific role. Only reorder, re-emphasize, and rephrase what is already true in the resume — "
                "never invent employers, degrees, dates, or experience that isn't there.\n\n"
                f"{job_desc}\n\n"
                f"{markup_rules}\n\n"
                "Return only the tailored resume in this format — no commentary before or after."
            )
        else:
            instruction = (
                f'Write a concise, specific, professional cover letter (under 350 words) for {candidate_name}, '
                'applying to the role below. Base it only on the resume content given — do not invent experience. '
                'Warm and confident tone, no generic filler phrases like "I am writing to express my interest".\n\n'
                f"{job_desc}\n\n"
                "Write each paragraph as a single line (no manual line wrapping) and separate paragraphs with a "
                "blank line. Use no markdown headings or bullets — this is prose.\n\n"
                "Return only the cover letter text."
            )

        if image_part:
            user_content = [
                {"type": "text", "text": instruction + "\n\nThe candidate's resume is attached as an image — read it directly."},
                image_part,
            ]
        else:
            user_content = instruction + f'\n\nCandidate\'s current resume:\n"""\n{resume_text}\n"""'

        # The bigger model produces better writing but is slower — worth a longer timeout than
        # the default before falling back, rather than giving up at the same speed as a quick call.
        models_to_try = [NVIDIA_RESUME_MODEL, NVIDIA_MODEL]

        try:
            reply = call_nvidia_with_fallbacks(
                [{"role": "user", "content": user_content}], models_to_try, timeout=110
            )
        except urllib.error.HTTPError as e:
            print("NVIDIA resume-generate error:", e.code, e.read().decode("utf-8", errors="replace"))
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except (KeyError, IndexError) as e:
            print("Unexpected NVIDIA resume-generate response shape:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except Exception as e:
            print("NVIDIA resume-generate request failed:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})

        self.send_json(200, {"text": reply})

    def handle_extract_cv_profile(self):
        """Zero-form onboarding: parse an uploaded CV and hand back structured fields so the
        signup wizard can pre-fill itself instead of the candidate retyping everything that's
        already sitting in their resume. Reuses the exact same PDF/image handling as
        handle_resume_generate above. Every field the model can't actually find in the text comes
        back as an empty string/list — never fabricated, and the candidate reviews/edits before
        anything is submitted, so a wrong guess is just an inconvenience, not silent bad data."""
        if not NVIDIA_API_KEY:
            return self.send_json(
                503,
                {"error": "Ask Bridge AI is still getting set up and isn't quite ready yet — please check back soon!"},
            )
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": CHAT_FALLBACK_MESSAGE})

        resume_text = (data.get("resumeText") or "").strip()
        resume_file = data.get("resumeFile") or None

        image_part = None
        if resume_file:
            kind = resume_file.get("kind")
            b64 = resume_file.get("base64") or ""
            if kind == "pdf":
                if PdfReader is None:
                    return self.send_json(
                        500,
                        {"error": "PDF support isn't installed on the server yet — try a JPG/PNG, or paste your resume text instead."},
                    )
                try:
                    pdf_bytes = base64.b64decode(b64)
                    reader = PdfReader(io.BytesIO(pdf_bytes))
                    resume_text = "\n".join((page.extract_text() or "") for page in reader.pages).strip()
                except Exception as e:
                    print("PDF extraction failed:", e)
                    return self.send_json(400, {"error": "Couldn't read that PDF. Try a JPG/PNG instead, or paste your resume text directly."})
                if len(resume_text) < 50:
                    return self.send_json(
                        400,
                        {"error": "Couldn't find readable text in that PDF (it may be a scanned image). Try a JPG/PNG instead, or paste your resume text directly."},
                    )
            elif kind == "image":
                media_type = resume_file.get("mediaType") or "image/jpeg"
                image_part = {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{b64}"}}

        if not resume_text and not image_part:
            return self.send_json(400, {"error": "Upload or paste your CV/resume first."})

        system_prompt = (
            "Extract structured profile information from this Nigerian job seeker's resume/CV. "
            "Only extract what is genuinely present in the text — never invent or guess a missing detail.\n\n"
            "Respond with ONLY a JSON object (no markdown fences, no commentary) matching exactly this shape:\n"
            '{"fullName": "", "email": "", "phone": "", "university": "", "fieldOfStudy": "", '
            '"education": "", "careerLevel": "", "address": "", "skills": []}\n\n'
            'education must be exactly one of: "Secondary school", "OND / HND (Polytechnic)", '
            '"NCE (College of Education)", "Bachelor\'s degree (B.Sc / B.A / B.Eng)", "Master\'s degree", '
            '"Doctorate (Ph.D)", "Professional certification" — or "" if unclear.\n'
            'careerLevel must be exactly one of: "Student", "Early career (0-3 yrs)", "Mid career (4-8 yrs)" '
            '— inferred from work history length, or "" if unclear.\n'
            "skills: 3-15 concrete skill/tool/technology names actually mentioned or clearly demonstrated — "
            'not generic filler like "hardworking" or "team player".\n'
            'Leave any field "" (or [] for skills) if it genuinely is not findable in the text.'
        )
        if image_part:
            user_content = [
                {"type": "text", "text": "The candidate's resume is attached as an image — read it directly."},
                image_part,
            ]
        else:
            user_content = f'Resume text:\n"""\n{resume_text}\n"""'

        try:
            reply = call_nvidia_with_fallbacks(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                [NVIDIA_RESUME_MODEL, NVIDIA_MODEL], timeout=60, source="cv-extract",
            )
        except urllib.error.HTTPError as e:
            print("NVIDIA cv-extract error:", e.code, e.read().decode("utf-8", errors="replace"))
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except (KeyError, IndexError) as e:
            print("Unexpected NVIDIA cv-extract response shape:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except Exception as e:
            print("NVIDIA cv-extract request failed:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})

        self.send_json(200, {"profile": parse_cv_extraction_json(reply)})

    def handle_career_match(self):
        if not NVIDIA_API_KEY:
            return self.send_json(
                503,
                {"error": "Career Match AI is still getting set up and isn't quite ready yet — please check back soon!"},
            )
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": CHAT_FALLBACK_MESSAGE})

        skills = data.get("skills") or []
        objectives = (data.get("objectives") or "").strip()
        if not skills or not objectives:
            return self.send_json(400, {"error": "Add at least one skill and your career objectives first."})

        profile_lines = [
            f"University: {(data.get('university') or 'Not specified').strip()}",
            f"Degree & field of study: {(data.get('degree') or 'Not specified').strip()}",
            f"Degree classification: {data.get('classification') or 'Not specified'}",
            f"CGPA (self-reported, if given): {(data.get('cgpa') or 'Not specified').strip()}",
            f"NYSC status: {data.get('nyscStatus') or 'Not specified'}",
            f"English test status (IELTS/TOEFL): {data.get('englishTestStatus') or 'Not specified'}",
            f"Skills: {', '.join(skills)}",
            f"Career objectives: {objectives}",
        ]
        user_content = "Here is the user's profile:\n\n" + "\n".join(profile_lines)

        # Same bigger-model-first, slower-but-better tradeoff as resume tailoring.
        models_to_try = [NVIDIA_RESUME_MODEL, NVIDIA_MODEL]

        try:
            reply = call_nvidia_with_fallbacks(
                [
                    {"role": "system", "content": CAREER_MATCH_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                models_to_try, timeout=110, source="career-match",
            )
        except urllib.error.HTTPError as e:
            print("NVIDIA career-match error:", e.code, e.read().decode("utf-8", errors="replace"))
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except (KeyError, IndexError) as e:
            print("Unexpected NVIDIA career-match response shape:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except Exception as e:
            print("NVIDIA career-match request failed:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})

        self.send_json(200, {"result": reply})


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    init_db()
    server = ThreadingServer(("0.0.0.0", PORT), Handler)
    print(f"Bridge NG server running — open http://localhost:{PORT}/ in your browser")
    if USE_TURSO:
        print("Using Turso for persistent storage — accounts survive redeploys.")
    else:
        print(f"(Accounts are stored in {DB_PATH} — on Render's free tier this resets on every "
              f"redeploy. Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN to persist across deploys.)")
    if NVIDIA_API_KEY:
        print(f"Ask Bridge AI is live, using model '{NVIDIA_MODEL}'. Resume/cover-letter writing tries "
              f"'{NVIDIA_RESUME_MODEL}' first (110s timeout), falling back to '{NVIDIA_MODEL}' on any failure.")
    else:
        print("Ask Bridge AI is NOT configured — set the NVIDIA_API_KEY environment variable to enable it.")
    if IMPORT_TOKEN:
        print("Job import is enabled at POST /api/jobs/import and POST /api/jobs/sync (requires the IMPORT_TOKEN as a 'token' field).")
        print(f"Sync jobs from a live Greenhouse/Lever board at http://localhost:{PORT}/admin-jobs-sync.html")
    else:
        print("Job import is NOT configured — set the IMPORT_TOKEN environment variable to enable manual POST /api/jobs/import and /api/jobs/sync requests.")

    # Auto-sync is an internal scheduled task, not reachable over the network, so it
    # doesn't need IMPORT_TOKEN — it runs by default so the job board updates itself.
    auto_sync_companies = parse_auto_sync_companies()
    auto_sync_remote_companies = parse_auto_sync_remote_companies()
    if auto_sync_companies or auto_sync_remote_companies:
        names = ", ".join(f"{ats}/{slug}" for ats, slug in auto_sync_companies)
        remote_names = ", ".join(f"{ats}/{slug}" for ats, slug in auto_sync_remote_companies)
        print(f"Auto-sync is ON, every {AUTO_SYNC_INTERVAL_HOURS:g}h — Nigeria: {names or '(none)'} | Remote/diaspora: {remote_names or '(none)'}")
        threading.Thread(target=run_auto_sync_loop, daemon=True).start()
    else:
        print("Auto-sync has no companies configured.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
