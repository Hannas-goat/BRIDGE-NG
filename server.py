import base64
import datetime
import hashlib
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

# On hosts like Render, stdout isn't a real terminal, so Python block-buffers print() output
# instead of flushing per line — logs can end up delayed indefinitely or never show up at all.
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "bridgeng.db")
PORT = int(os.environ.get("PORT", 8000))

STATIC_FILES = {"index.html", "auth.html", "shared.js", "styles.css", "admin-jobs-sync.html", "privacy.html", "terms.html"}
STATIC_DIRS = {"images"}

PBKDF2_ITERATIONS = 200_000
SESSION_COOKIE = "bridge_session"

# NVIDIA's build.nvidia.com API catalog is OpenAI-compatible and grants free trial credits on
# signup — no live web search available, so job lookups are best-effort from pasted text only.
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY")
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "meta/llama-3.2-11b-vision-instruct")
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

# Public, unauthenticated job-board APIs — no account/API key needed for either.
GREENHOUSE_JOBS_URL = "https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true"
LEVER_JOBS_URL = "https://api.lever.co/v0/postings/{slug}?mode=json"
SYNC_FALLBACK_MESSAGE = "Couldn't sync jobs from that board right now. Double-check the company slug and try again."

# Real Nigerian/Africa-based companies with verified public Greenhouse/Lever boards
# (confirmed live and returning real postings — not every Nigerian company runs one of
# these two ATS platforms, so this is a starting set, not "every job in Nigeria").
# Add more as "ats:slug" pairs, comma-separated, via the AUTO_SYNC_COMPANIES env var,
# or just leave the default — it's already a real, working list.
DEFAULT_AUTO_SYNC_COMPANIES = "greenhouse:moniepoint,greenhouse:carbon"
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
sessions = {}  # token -> user_id

_turso_client = None
_turso_client_lock = threading.Lock()


def _get_turso_client():
    """Lazily creates one shared libsql_client connection for the whole process. Spinning up a
    new client per request would open a new background thread each time (expensive and
    pointless), so every caller reuses this same client instead."""
    global _turso_client
    if _turso_client is None:
        with _turso_client_lock:
            if _turso_client is None:
                _turso_client = libsql_client.create_client_sync(url=TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)
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
    # CREATE TABLE IF NOT EXISTS is a no-op on a table that already exists on disk from
    # an earlier version of this schema, so new columns need an explicit, safe migration.
    ensure_column(conn, "profiles", "open_to_remote", "open_to_remote INTEGER DEFAULT 0")
    ensure_column(conn, "imported_jobs", "remote_friendly", "remote_friendly INTEGER DEFAULT 0")
    conn.commit()
    conn.close()


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

PROFILE_FIELDS = ["fullName", "dob", "sex", "phone", "address", "education",
                   "careerLevel", "fieldOfStudy", "preferredLocation"]
PROFILE_COLUMNS = ["full_name", "dob", "sex", "phone", "address", "education",
                    "career_level", "field_of_study", "preferred_location"]


def profile_row_to_json(row):
    return {
        "fullName": row["full_name"],
        "dob": row["dob"],
        "sex": row["sex"],
        "phone": row["phone"],
        "address": row["address"],
        "education": row["education"],
        "careerLevel": row["career_level"],
        "fieldOfStudy": row["field_of_study"],
        "preferredLocation": row["preferred_location"],
        "skills": json.loads(row["skills"] or "[]"),
        "openToRemote": bool(row["open_to_remote"]),
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
    }


def application_row_to_json(row):
    return {
        "id": row["id"],
        "jobTitle": row["job_title"],
        "company": row["company"],
        "applicationLink": row["application_link"],
        "createdAt": row["created_at"],
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


def call_nvidia(messages, max_tokens=1400):
    """Calls NVIDIA's OpenAI-compatible chat completions API and returns the reply text.
    Raises urllib.error.HTTPError on a non-2xx response, or (KeyError, IndexError) if the response
    doesn't contain the expected shape — callers already handle both."""
    payload = {"model": NVIDIA_MODEL, "messages": messages, "max_tokens": max_tokens}
    req = urllib.request.Request(
        NVIDIA_CHAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {NVIDIA_API_KEY}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    return result["choices"][0]["message"]["content"]


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


def sync_company_jobs(ats, slug, company_override=""):
    """Fetch + normalize + dedup-insert + notify for one company's public ATS board.
    Used by both the on-demand /api/jobs/sync endpoint and the background auto-sync
    loop, so a scheduled refresh behaves identically to a manual one.
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
        for ats, slug in companies + remote_companies:
            try:
                count, error, _ = sync_company_jobs(ats, slug)
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
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    # ---------- helpers ----------

    def send_json(self, status, obj, set_cookie=None, clear_cookie=False):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}={set_cookie}; Path=/; HttpOnly; SameSite=Lax")
        if clear_cookie:
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
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
        return sessions.get(token)

    # ---------- routing ----------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/me":
            return self.handle_me()
        if parsed.path == "/api/jobs":
            return self.handle_list_jobs()
        if parsed.path == "/api/saved-searches":
            return self.handle_list_saved_searches()
        if parsed.path == "/api/followed-companies":
            return self.handle_list_followed_companies()
        if parsed.path == "/api/notifications":
            return self.handle_list_notifications()
        if parsed.path == "/api/appointments":
            return self.handle_list_appointments()
        if parsed.path == "/api/applications":
            return self.handle_list_applications()
        if parsed.path.startswith("/api/"):
            return self.send_json(404, {"error": "Not found"})
        return self.serve_static(parsed.path)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/signup":
            return self.handle_signup()
        if parsed.path == "/api/login":
            return self.handle_login()
        if parsed.path == "/api/logout":
            return self.handle_logout()
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
        if parsed.path == "/api/appointments":
            return self.handle_create_appointment()
        if parsed.path == "/api/appointments/cancel":
            return self.handle_cancel_appointment()
        if parsed.path == "/api/applications":
            return self.handle_create_application()
        if parsed.path == "/api/employer-jobs":
            return self.handle_post_employer_job()
        if parsed.path == "/api/resume/find-job":
            return self.handle_resume_find_job()
        if parsed.path == "/api/resume/tailor":
            return self.handle_resume_generate()
        return self.send_json(404, {"error": "Not found"})

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/profile":
            return self.handle_save_profile()
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
                       education, career_level, field_of_study, preferred_location, skills, open_to_remote)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (user_id, data.get("fullName", ""), data.get("dob", ""), data.get("sex", ""),
                     data.get("phone", ""), data.get("address", ""), data.get("education", ""),
                     data.get("careerLevel", ""), data.get("fieldOfStudy", ""),
                     data.get("preferredLocation", ""), json.dumps(skills),
                     1 if data.get("openToRemote") else 0),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                return self.send_json(409, {"error": "An account with this email already exists."})
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()

        token = secrets.token_hex(24)
        sessions[token] = user_id
        self.send_json(200, {"ok": True, "email": email, "profile": profile_row_to_json(row)}, set_cookie=token)

    def handle_login(self):
        data = self.read_json_body()
        if data is None:
            return self.send_json(400, {"error": "Malformed request body."})

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        with db_lock:
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user is None or not verify_password(password, user["salt"], user["password_hash"]):
                conn.close()
                return self.send_json(401, {"error": "Incorrect email or password."})
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user["id"],)).fetchone()
            conn.close()

        token = secrets.token_hex(24)
        sessions[token] = user["id"]
        self.send_json(200, {"ok": True, "email": email, "profile": profile_row_to_json(row)}, set_cookie=token)

    def handle_logout(self):
        token = self.get_cookie(SESSION_COOKIE)
        if token:
            sessions.pop(token, None)
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
                   skills=?, open_to_remote=?, updated_at=datetime('now') WHERE user_id=?""",
                (data.get("fullName", ""), data.get("dob", ""), data.get("sex", ""),
                 data.get("phone", ""), data.get("address", ""), data.get("education", ""),
                 data.get("careerLevel", ""), data.get("fieldOfStudy", ""),
                 data.get("preferredLocation", ""), json.dumps(skills),
                 1 if data.get("openToRemote") else 0, user_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()
        self.send_json(200, {"ok": True, "profile": profile_row_to_json(row)})

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
            except sqlite3.IntegrityError:
                pass  # already following
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
            except sqlite3.IntegrityError:
                pass  # already applied — treat as a no-op success, not an error
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
        try:
            pay_min = int(data.get("payMin") or 0)
            pay_max = int(data.get("payMax") or 0)
        except (TypeError, ValueError):
            pay_min, pay_max = 0, 0

        with db_lock:
            conn = get_db()
            cur = conn.execute(
                """INSERT INTO employer_posted_jobs (title, company, level, location, skills, pay_min, pay_max)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (title, company, level, location, json.dumps(skills), pay_min, pay_max),
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
                score = match_score(skills, cand_skills, level, row["career_level"], location, row["preferred_location"])
                matches.append({
                    "userId": row["uid"],
                    "fullName": row["full_name"] or "Bridge NG member",
                    "careerLevel": row["career_level"],
                    "fieldOfStudy": row["field_of_study"],
                    "preferredLocation": row["preferred_location"],
                    "skills": cand_skills,
                    "score": score,
                })
                if score >= 60:
                    message = f"A new role matches your profile: {title} at {company} — {score}% match."
                    conn.execute(
                        "INSERT INTO notifications (user_id, kind, message, job_title, company) VALUES (?, ?, ?, ?, ?)",
                        (row["uid"], "employer_match", message, title, company),
                    )
                    notified += 1
            conn.commit()
            conn.close()

        matches.sort(key=lambda m: m["score"], reverse=True)
        self.send_json(200, {
            "ok": True, "jobId": job_id,
            "realMatches": matches[:10],
            "notifiedCount": notified,
        })

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
            print("NVIDIA chat error:", e.code, e.read().decode("utf-8", errors="replace"))
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
            print("NVIDIA job-lookup error:", e.code, e.read().decode("utf-8", errors="replace"))
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except (KeyError, IndexError) as e:
            print("Unexpected NVIDIA job-lookup response shape:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})
        except Exception as e:
            print("NVIDIA job-lookup request failed:", e)
            return self.send_json(502, {"error": CHAT_FALLBACK_MESSAGE})

        self.send_json(200, parse_job_info_json(reply, job_text))

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

        try:
            reply = call_nvidia([{"role": "user", "content": user_content}])
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
        print(f"Ask Bridge AI is live, using model '{NVIDIA_MODEL}'.")
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
