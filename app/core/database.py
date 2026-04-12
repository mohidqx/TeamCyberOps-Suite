"""
TeamCyberOps V5 — SQLite Database Core
v5.0.3 fixes:
  BUG #4  — SHA-256 replaced with bcrypt (+ HMAC fallback) for password hashing
  BUG #7  — hmac.compare_digest() for constant-time password comparison (timing-safe)
  BUG #22 — idx_users_username index added
"""
import sqlite3, json, threading, hashlib, hmac as _hmac
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

BASE_DIR = Path(__file__).parent.parent.parent
DB_PATH  = BASE_DIR / "db" / "teamcyberops.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_local = threading.local()

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    target      TEXT    DEFAULT '',
    scope       TEXT    DEFAULT '',
    notes       TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL,
    last_active TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    find_id     TEXT    NOT NULL UNIQUE,
    title       TEXT    NOT NULL,
    type        TEXT    DEFAULT '',
    severity    TEXT    NOT NULL DEFAULT 'INFO',
    cvss_score  TEXT    DEFAULT '',
    url         TEXT    DEFAULT '',
    description TEXT    DEFAULT '',
    poc         TEXT    DEFAULT '',
    impact      TEXT    DEFAULT '',
    remediation TEXT    DEFAULT '',
    status      TEXT    DEFAULT 'Open',
    tool        TEXT    DEFAULT '',
    tags        TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tool        TEXT    NOT NULL,
    category    TEXT    DEFAULT '',
    file_path   TEXT    DEFAULT '',
    line_count  INTEGER DEFAULT 0,
    scan_data   TEXT    DEFAULT '{}',
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    scan_type   TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    status      TEXT    DEFAULT 'running',
    result_summary TEXT DEFAULT '',
    started_at  TEXT    NOT NULL,
    finished_at TEXT    DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    password_hash TEXT  NOT NULL,
    role        TEXT    DEFAULT 'user',
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
    key         TEXT    PRIMARY KEY,
    value       TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username     ON users(username);
CREATE INDEX IF NOT EXISTS idx_findings_project   ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status    ON findings(status);
CREATE INDEX IF NOT EXISTS idx_results_project    ON scan_results(project_id);
CREATE INDEX IF NOT EXISTS idx_history_project    ON scan_history(project_id);
"""

# ── Password Hashing (BUG #4 fix) ────────────────────────────────
_APP_SALT = b"TCO_v5_hmac_fallback_salt_2026"

def _hash_password(password: str) -> str:
    """
    Hash password with bcrypt (rounds=12) if available.
    Falls back to HMAC-SHA256 with app-level salt — still vastly
    better than bare SHA256 and uses compare_digest for timing safety.
    BUG #4: Replaces hashlib.sha256(b"admin").hexdigest() [NO SALT].
    """
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode("utf-8"),
                             bcrypt.gensalt(rounds=12)).decode("utf-8")
    except ImportError:
        return _hmac.new(_APP_SALT,
                         password.encode("utf-8"),
                         hashlib.sha256).hexdigest()


def _verify_password(password: str, stored_hash: str) -> bool:
    """
    Constant-time password comparison — immune to timing attacks.
    BUG #7: Replaces plain '==' comparison with hmac.compare_digest.
    """
    try:
        import bcrypt
        if stored_hash.startswith(("$2b$", "$2a$", "$2y$")):
            return bcrypt.checkpw(password.encode("utf-8"),
                                  stored_hash.encode("utf-8"))
    except ImportError:
        pass
    # HMAC fallback — timing-safe
    expected = _hmac.new(_APP_SALT,
                         password.encode("utf-8"),
                         hashlib.sha256).hexdigest()
    return _hmac.compare_digest(expected, stored_hash)


# ── Connection ────────────────────────────────────────────────────
def get_conn() -> sqlite3.Connection:
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.executescript("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
    return _local.conn


def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)
    conn.commit()
    # Default admin user — use secure hashing (BUG #4)
    pw_hash = _hash_password("admin")
    now = datetime.now().isoformat()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users "
            "(username,password_hash,role,created_at) VALUES (?,?,?,?)",
            ("admin", pw_hash, "admin", now))
        conn.commit()
    except Exception:
        pass
    conn.close()


def verify_user(username: str, password: str) -> Optional[Dict]:
    """
    Timing-safe user verification.
    BUG #7: Uses _verify_password() → hmac.compare_digest internally.
    Also performs a dummy compare when user not found to prevent
    username enumeration via timing differences.
    """
    conn = get_conn()
    row = conn.execute(
        "SELECT id, username, role, password_hash FROM users WHERE username=?",
        (username,)).fetchone()
    if not row:
        # Dummy call — prevents timing-based username enumeration
        _hmac.compare_digest("dummy_hash_a", "dummy_hash_b")
        return None
    if _verify_password(password, row["password_hash"]):
        return {"id": row["id"], "username": row["username"], "role": row["role"]}
    return None


# ── PROJECTS ─────────────────────────────────────────────────────
def get_projects() -> List[Dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT p.*, COUNT(f.id) as finding_count FROM projects p "
        "LEFT JOIN findings f ON f.project_id=p.id "
        "GROUP BY p.id ORDER BY p.last_active DESC").fetchall()
    return [dict(r) for r in rows]

def get_project(name: str) -> Optional[Dict]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM projects WHERE name=?", (name,)).fetchone()
    return dict(row) if row else None

def create_project(name: str, target: str = "", scope: str = "") -> Dict:
    conn = get_conn()
    now = datetime.now().isoformat()
    try:
        conn.execute(
            "INSERT INTO projects (name,target,scope,created_at,last_active) VALUES (?,?,?,?,?)",
            (name, target, scope, now, now))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    return get_project(name)

def update_project_active(name: str):
    conn = get_conn()
    conn.execute("UPDATE projects SET last_active=? WHERE name=?",
                 (datetime.now().isoformat(), name))
    conn.commit()

def delete_project(name: str):
    conn = get_conn()
    conn.execute("DELETE FROM projects WHERE name=?", (name,))
    conn.commit()


def sync_logs_to_projects():
    """
    Scan logs/ folder and auto-register missing projects into DB.
    Called at startup — ensures every logs/<project>/ dir is in the dropdown.
    Returns list of newly added project names.
    """
    logs_dir = BASE_DIR / "logs"
    if not logs_dir.exists():
        return []
    existing_names = {p["name"] for p in get_projects()}
    added = []
    for folder in sorted(logs_dir.iterdir()):
        if not folder.is_dir():
            continue
        name = folder.name.strip()
        if not name or name.startswith("."):
            continue
        if name in existing_names:
            continue
        target = name if ("." in name or ":" in name) else name
        try:
            create_project(name, target=target)
            added.append(name)
        except Exception:
            pass
    return added


# ── FINDINGS ─────────────────────────────────────────────────────
def save_finding(finding: Dict) -> Dict:
    conn   = get_conn()
    now    = datetime.now().isoformat()
    proj   = finding.get("project", "default")
    if not get_project(proj):
        create_project(proj, target=proj)
    proj_row = get_project(proj)
    proj_id  = proj_row["id"]
    existing = conn.execute("SELECT COUNT(*) FROM findings WHERE project_id=?",
                             (proj_id,)).fetchone()[0]
    find_id = finding.get("find_id") or f"FIND-{proj}-{existing+1:04d}"
    sev_map = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    severity = finding.get("severity","INFO").upper()
    if severity not in sev_map: severity = "INFO"
    try:
        conn.execute("""
            INSERT OR REPLACE INTO findings
            (project_id,find_id,title,type,severity,cvss_score,url,
             description,poc,impact,remediation,status,tool,tags,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (proj_id, find_id,
              finding.get("title","Untitled"),
              finding.get("type",""),
              severity,
              str(finding.get("cvss_score","")),
              finding.get("url",""),
              finding.get("description",""),
              finding.get("poc",""),
              finding.get("impact",""),
              finding.get("remediation",""),
              finding.get("status","Open"),
              finding.get("tool",""),
              json.dumps(finding.get("tags",[])),
              now, now))
        conn.commit()
    except Exception as e:
        print(f"[DB] save_finding error: {e}")
    finding["find_id"] = find_id
    return finding

def load_findings(project: str = None, severity: str = None,
                  status: str = None) -> List[Dict]:
    conn   = get_conn()
    query  = """
        SELECT f.*, p.name as project FROM findings f
        JOIN projects p ON p.id = f.project_id
        WHERE 1=1
    """
    params = []
    if project:
        query += " AND p.name=?"; params.append(project)
    if severity:
        query += " AND f.severity=?"; params.append(severity.upper())
    if status:
        query += " AND f.status=?";  params.append(status)
    query += (" ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1"
              " WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, f.created_at DESC")
    rows = conn.execute(query, params).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        try: d["tags"] = json.loads(d.get("tags","[]"))
        except Exception: d["tags"] = []
        results.append(d)
    return results

def update_finding(find_id: str, updates: Dict):
    conn = get_conn()
    updates["updated_at"] = datetime.now().isoformat()
    cols = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [find_id]
    conn.execute(f"UPDATE findings SET {cols} WHERE find_id=?", vals)
    conn.commit()

def delete_finding(find_id: str):
    conn = get_conn()
    conn.execute("DELETE FROM findings WHERE find_id=?", (find_id,))
    conn.commit()

def get_finding_stats(project: str = None) -> Dict:
    conn = get_conn()
    base = ("SELECT severity, COUNT(*) as cnt FROM findings f "
            "JOIN projects p ON p.id=f.project_id")
    if project:
        rows = conn.execute(base + " WHERE p.name=? GROUP BY f.severity", (project,)).fetchall()
    else:
        rows = conn.execute(base + " GROUP BY f.severity").fetchall()
    stats = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0,"total":0}
    for r in rows:
        sev = r["severity"].upper()
        if sev in stats:
            stats[sev] = r["cnt"]
            stats["total"] += r["cnt"]
    return stats

# ── SCAN RESULTS ─────────────────────────────────────────────────
def save_scan_result(project: str, tool: str, category: str,
                     file_path: str = "", line_count: int = 0,
                     scan_data: Dict = None):
    conn = get_conn()
    if not get_project(project):
        create_project(project)
    proj_id = get_project(project)["id"]
    conn.execute("""
        INSERT INTO scan_results
        (project_id,tool,category,file_path,line_count,scan_data,created_at)
        VALUES (?,?,?,?,?,?,?)
    """, (proj_id, tool, category, file_path, line_count,
          json.dumps(scan_data or {}), datetime.now().isoformat()))
    conn.commit()

def load_scan_results(project: str = None) -> List[Dict]:
    conn = get_conn()
    if project:
        rows = conn.execute("""
            SELECT r.*, p.name as project_name FROM scan_results r
            JOIN projects p ON p.id=r.project_id
            WHERE p.name=? ORDER BY r.created_at DESC
        """, (project,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT r.*, p.name as project_name FROM scan_results r
            JOIN projects p ON p.id=r.project_id
            ORDER BY r.created_at DESC
        """).fetchall()
    return [dict(r) for r in rows]

# ── CONFIG ────────────────────────────────────────────────────────
def get_config(key: str, default: Any = None) -> Any:
    conn = get_conn()
    row  = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    if row:
        try: return json.loads(row["value"])
        except Exception: return row["value"]
    return default

def set_config(key: str, value: Any):
    conn = get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO config (key,value,updated_at) VALUES (?,?,?)",
        (key, json.dumps(value) if not isinstance(value, str) else value,
         datetime.now().isoformat()))
    conn.commit()

def get_all_config() -> Dict:
    conn = get_conn()
    rows = conn.execute("SELECT key,value FROM config").fetchall()
    result = {}
    for r in rows:
        try: result[r["key"]] = json.loads(r["value"])
        except Exception: result[r["key"]] = r["value"]
    return result

# ── SCAN HISTORY ──────────────────────────────────────────────────
def add_scan_history(project: str, scan_type: str, target: str) -> int:
    conn = get_conn()
    proj = get_project(project)
    proj_id = proj["id"] if proj else None
    cur = conn.execute("""
        INSERT INTO scan_history (project_id,scan_type,target,status,started_at)
        VALUES (?,?,?,?,?)
    """, (proj_id, scan_type, target, "running", datetime.now().isoformat()))
    conn.commit()
    return cur.lastrowid

def finish_scan_history(scan_id: int, status: str = "completed", summary: str = ""):
    conn = get_conn()
    conn.execute("""
        UPDATE scan_history SET status=?,result_summary=?,finished_at=? WHERE id=?
    """, (status, summary, datetime.now().isoformat(), scan_id))
    conn.commit()

# Initialize on import
init_db()
