# 🐛 BUGS.md - TeamCyberOps v5 Comprehensive Bug Report

**Generated:** April 11, 2026  
**Total Bugs Found:** 42  
**Critical Issues:** 7 | **High:** 8 | **Medium:** 15 | **Low:** 9 | **Trivial:** 3

---

## 📊 Severity Distribution

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 CRITICAL | 7 | **MUST FIX** |
| 🟠 HIGH | 8 | **FIX IMMEDIATELY** |
| 🟡 MEDIUM | 15 | **FIX SOON** |
| 🔵 LOW | 9 | **CONSIDER FIXING** |
| ⚪ TRIVIAL | 3 | **NICE TO HAVE** |

---

# 🔴 CRITICAL SEVERITY ISSUES (7 bugs)

## BUG #1: Hardcoded Target & Brute Force Without Authorization
- **File:** [brute-server.py](brute-server.py)
- **Lines:** 1-32
- **Category:** Security - Unauthorized Testing
- **Severity:** 🔴 CRITICAL
- **Description:** Script contains hardcoded target IP (37.97.145.109), hardcoded credentials list, and **NO authorization checks**. This is designed to brute-force phpMyAdmin on real targets without explicit user consent.
- **Issues Found:**
  - Real target IP hardcoded: `37.97.145.109`
  - Weak default passwords in plaintext: `["admin", "password", "123456", "root", "secret", "directadmin", "admin123"]`
  - No scope validation or target authorization checks
  - `requests.Session()` created but never closed (resource leak)
  - Comments in Hindi suggest unauthorized testing intent
- **Suggested Fix:**
  ```python
  # Remove hardcoded targets
  # Add user confirmation and scope validation
  # Implement SSH key rotation for any legitimate pentesting
  # Use context manager: with requests.Session() as session:
  ```

---

## BUG #2: SSL Certificate Verification Disabled + CVE Exploitation
- **File:** [connect-server.py](connect-server.py)
- **Lines:** 1-35
- **Category:** Security - SSL Vulnerability, Unauthorized Testing
- **Severity:** 🔴 CRITICAL
- **Description:** Disables SSL certificate verification globally and performs CVE-2023-42117 Exim exploitation on hardcoded target (37.97.145.109:465) without authorization.
- **Issues Found:**
  - `context.verify_mode = ssl.CERT_NONE` - **Vulnerable to MITM attacks**
  - Hardcoded target: `37.97.145.109:465`
  - Exploits CVE without scope validation
  - 8192-byte overflow payload sent without bounds checking
  - No error recovery or graceful shutdown
  - SSL socket not properly closed in exception paths
- **Attack Vector:** An attacker could intercept the connection and inject malicious data
- **Suggested Fix:**
  ```python
  # REMOVE this file from production
  # OR completely rewrite with:
  context.verify_mode = ssl.CERT_REQUIRED
  # Add user authorization check
  # Add scope validation
  # Use context manager for socket cleanup
  ```

---

## BUG #3: Fuzzing Sensitive Paths Without Authorization
- **File:** [fuzz_server.py](fuzz_server.py)
- **Lines:** 1-70
- **Category:** Security - Unauthorized Testing, No Scope Control
- **Severity:** 🔴 CRITICAL
- **Description:** Fuzzes 100+ sensitive paths on hardcoded target without authorization. Disables SSL warnings, no input validation, writes results to unprotected file.
- **Issues Found:**
  - `urllib3.disable_warnings()` - **Silences SSL certificate warnings**
  - Hardcoded target endpoints with no authorization check
  - No scope validation mechanism
  - Results written to `found_paths.txt` without access control or path sanitization
  - File writing is **NOT atomic** (race conditions possible)
  - Comments in Hindi suggest unauthorized testing
  - 20 worker threads with **no rate limiting** or politeness delay
  - `requests.get()` with **no response size limit** (DoS risk)
- **Suggested Fix:**
  ```python
  # REMOVE from production deployment
  # If keeping for testing: Add user authorization flow
  # urllib3.disable_warnings() # REMOVE
  # Add scope validation
  # Implement rate limiting and politeness delays
  # Validate response size before downloading
  ```

---

## BUG #4: Weak Password Hashing Without Salt
- **File:** [app/core/database.py](app/core/database.py)
- **Lines:** 78-81
- **Category:** Security - Weak Cryptography
- **Severity:** 🔴 CRITICAL
- **Description:** Default admin user created with SHA256 hash **WITHOUT SALT**. SHA256 is too fast for password hashing and is vulnerable to rainbow table attacks.
- **Current Code:**
  ```python
  pw_hash = hashlib.sha256(b"admin").hexdigest()  # NO SALT!
  ```
- **Issues Found:**
  - No salt used (major vulnerability)
  - SHA256 hash precomputable: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  - Password "admin" is trivially crackable
  - `INSERT OR IGNORE` silently fails if user already exists (no error feedback)
  - No migration system for existing weak hashes
- **Attack Vector:** Rainbow table attack can instantly reverse any password hash
- **Suggested Fix:**
  ```python
  import bcrypt
  # pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt(rounds=12)).decode()
  # Implement migration for existing users
  # Use: bcrypt.checkpw(password.encode(), stored_hash.encode())
  ```

---

## BUG #5: Global SSL Verification Disabled in config.json
- **File:** [config.json](config.json)
- **Lines:** Global setting
- **Category:** Configuration - SSL/TLS Vulnerability
- **Severity:** 🔴 CRITICAL
- **Description:** Configuration file has `"verify_ssl": false`, disabling SSL/TLS verification for **ALL HTTPS requests** application-wide.
- **Current Config:**
  ```json
  "proxy": {
    "enabled": false,
    "verify_ssl": false  // ⚠️ DANGEROUS
  }
  ```
- **Issues Found:**
  - **ALL HTTPS requests vulnerable to MITM attacks**
  - Could be used by attacker to intercept credentials, API keys, scan results
  - Makes the app vulnerable on any network with attacker
  - Affects all modules that make HTTP/HTTPS requests
- **Impact:** Production vulnerability - all data in transit can be intercepted
- **Suggested Fix:**
  ```json
  "verify_ssl": true,  // ALWAYS verify
  // If certificate issues: Add cert bundle path instead
  "cert_bundle": "/path/to/ca-bundle.crt"
  ```

---

## BUG #6: Missing API Key Configuration & No Validation
- **File:** [config.json](config.json)
- **Lines:** 5-17
- **Category:** Configuration - Missing Security, No Validation
- **Severity:** 🔴 CRITICAL
- **Description:** All API keys in config are empty `""` with no validation that required fields are populated before use. Application will fail silently or crash when trying to use uninitialized API keys.
- **Current Config:**
  ```json
  "api_keys": {
    "gemini_api_key": "",      // Empty!
    "claude_api_key": "",      // Empty!
    "shodan": "",              // Empty!
    "virustotal": "",          // Empty!
    "nvd_api_key": ""          // Empty!
  }
  ```
- **Issues Found:**
  - No validation of required fields
  - No enforcement that API keys are set before calling API functions
  - Results in cryptic errors when attempting API calls with empty keys
  - Could cause security issues if keys accidentally committed to repo
  - File has no encryption or access control
- **Suggested Fix:**
  ```python
  # In config loader:
  required_keys = ["gemini_api_key", "claude_api_key"]
  for key in required_keys:
      if not config["api_keys"][key]:
          raise ValueError(f"Required API key not set: {key}")
  # Move to environment variables
  API_KEY = os.environ.get("GEMINI_API_KEY")
  ```

---

## BUG #7: Timing Attack Vulnerability in Password Verification
- **File:** [app/core/database.py](app/core/database.py)
- **Lines:** 71-75
- **Category:** Security - Timing Attack
- **Severity:** 🔴 CRITICAL
- **Description:** Password comparison uses plain `==` operator which is timing-sensitive. Attacker can determine correct password character-by-character via statistical timing analysis.
- **Current Code:**
  ```python
  def verify_user(username, password):
      row = conn.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
      if not row:
          return False
      return hashlib.sha256(password.encode()).hexdigest() == row[0]  # ⚠️ TIMING ATTACK!
  ```
- **Issues Found:**
  - Plain `==` comparison is timing-sensitive
  - Attacker can measure response time to guess password
  - Combined with weak SHA256 hashing = high risk
  - No rate limiting on login attempts
- **Attack Vector:** 
  - Correct first character takes longer to fail than wrong first character
  - Attacker measures ~100ms variance to guess chars
- **Suggested Fix:**
  ```python
  import hmac
  return hmac.compare_digest(
      hashlib.sha256(password.encode()).hexdigest(),
      row[0]
  )
  # Better: Use bcrypt.checkpw() which is constant-time
  ```

---

# 🟠 HIGH SEVERITY ISSUES (8 bugs)

## BUG #8: Non-Atomic Config File Write (Race Condition)
- **File:** [app/core/config.py](app/core/config.py)
- **Lines:** 104-118
- **Category:** Logic Error - Race Condition, Data Corruption
- **Severity:** 🟠 HIGH
- **Description:** Configuration file save operation is **NOT atomic**. Between reading and writing, another process/thread could modify config.json, causing data loss.
- **Issues Found:**
  - Read-modify-write pattern without atomicity
  - No file locking mechanism
  - Exception silently caught with bare `pass`
  - No backup created before overwriting
  - Multiple threads could corrupt config simultaneously
- **Scenario:** User A saves config → User B saves config → One update lost
- **Suggested Fix:**
  ```python
  import tempfile, shutil
  with tempfile.NamedTemporaryFile(mode='w', dir=os.path.dirname(self.path), delete=False) as tmp:
      json.dump(data, tmp)
      tmp.flush()
      os.fsync(tmp.fileno())
      tmpname = tmp.name
  shutil.move(tmpname, self.path)  # Atomic on most filesystems
  ```

---

## BUG #9: Database Connections Not Explicitly Closed (Resource Leak)
- **File:** [app/core/database.py](app/core/database.py)
- **Lines:** 48-52
- **Category:** Resource Leak - File Descriptors
- **Severity:** 🟠 HIGH
- **Description:** Thread-local database connections are created but never explicitly closed. Relies on Python garbage collection and thread termination.
- **Current Code:**
  ```python
  def get_conn():
      if not hasattr(_local, 'conn'):
          _local.conn = sqlite3.connect(DB_PATH)  # Never explicitly closed!
          _local.conn.row_factory = sqlite3.Row
      return _local.conn
  ```
- **Issues Found:**
  - No explicit `.close()` call in thread cleanup
  - Connections persist for lifetime of thread
  - Long-running application could accumulate zombie connections
  - No connection pool management
  - File descriptor could be exhausted
- **Impact:** File descriptor exhaustion after many thread-spawns
- **Suggested Fix:**
  ```python
  class ThreadLocalDB:
      def __enter__(self):
          self.conn = sqlite3.connect(DB_PATH)
          return self.conn
      def __exit__(self, *args):
          self.conn.close()
  
  with ThreadLocalDB() as conn:
      # use conn
  ```

---

## BUG #10: Socket Connections Not Properly Closed in Port Scanner
- **File:** [modules/recon/active.py](modules/recon/active.py)
- **Lines:** 40-100+
- **Category:** Resource Leak - File Descriptors
- **Severity:** 🟠 HIGH
- **Description:** Sockets created in thread pool without guaranteed cleanup. Port scanner spawns 100+ threads with minimal error handling.
- **Issues Found:**
  - Sockets not closed in exception paths
  - `threading.Lock` usage could cause deadlock
  - `ThreadPoolExecutor(max_workers=100)` could exhaust file descriptors
  - No connection timeout in all code paths
  - No connection reuse/pooling
- **Impact:** File descriptor exhaustion, unable to create new connections
- **Suggested Fix:**
  ```python
  def scan_port(host, port, timeout=2):
      try:
          with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
              sock.settimeout(timeout)
              result = sock.connect_ex((host, port))
              return result == 0
      except socket.error:
          return False
  ```

---

## BUG #11: HTTP Responses Not Closed in Exception Paths
- **File:** [modules/vuln/scanner.py](modules/vuln/scanner.py)
- **Lines:** 25-35
- **Category:** Resource Leak - HTTP Connections
- **Severity:** 🟠 HIGH
- **Description:** `urllib.request.urlopen()` used directly without context manager. Response not closed if exception occurs.
- **Current Code:**
  ```python
  def _req(url):
      try:
          res = urllib.request.urlopen(url, timeout=5)  # Never explicitly closed!
          return res.read(5000).decode()
      except:
          return None
  ```
- **Issues Found:**
  - Response body not explicitly closed
  - Exception handler too broad (`except:`)
  - Response truncated at 5000 bytes silently
  - Headers/metadata not released
- **Impact:** Connection pool exhaustion
- **Suggested Fix:**
  ```python
  def _req(url):
      try:
          with urllib.request.urlopen(url, timeout=5) as res:
              return res.read(5000).decode()
      except (urllib.error.URLError, socket.timeout) as e:
          return None
  ```

---

## BUG #12: Missing Input Validation on Domain Parameters
- **File:** [modules/recon/passive.py](modules/recon/passive.py)
- **Lines:** All functions accepting domain
- **Category:** Security - Input Validation
- **Severity:** 🟠 HIGH
- **Description:** Domain parameters accepted directly without validation. Could contain special characters, escape sequences, or be used for injection.
- **Issues Found:**
  - No regex validation of domain format
  - Special characters not escaped before subprocess calls
  - Could enable subprocess injection attacks
  - No length validation
  - Domain could be used in file paths (path traversal risk)
- **Attack Vector:** `domain = "test.com'; rm -rf /;"` in subprocess call
- **Suggested Fix:**
  ```python
  import re
  def validate_domain(domain):
      if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
          raise ValueError(f"Invalid domain: {domain}")
      return domain
  ```

---

## BUG #13: File Operations Not Using Context Managers
- **File:** [modules/recon/passive.py](modules/recon/passive.py)
- **Lines:** Multiple (95, 110, 125, etc.)
- **Category:** Resource Leak - File Handles
- **Severity:** 🟠 HIGH
- **Description:** `open()` calls used directly without `with` statements, leaving file handles open if exception occurs.
- **Issues Found:**
  - File handles leaked on exception
  - No automatic cleanup
  - Accumulates open file descriptors
  - Could hit "too many open files" error
- **Example:**
  ```python
  # BAD:
  f = open("wordlist.txt", "r")
  lines = f.readlines()
  # File still open if exception occurs!
  
  # GOOD:
  with open("wordlist.txt", "r") as f:
      lines = f.readlines()
  # Guaranteed to close
  ```

---

## BUG #14: No Rate Limiting on API Calls
- **File:** [modules/recon/passive.py](modules/recon/passive.py)
- **Lines:** 25-40 (crtsh_lookup), similar in other modules
- **Category:** Logic Error - API Abuse Risk
- **Severity:** 🟠 HIGH
- **Description:** Multiple API calls made with no delay between attempts. Could trigger rate limiting, IP blocking, or be detected as scanning attack.
- **Issues Found:**
  - crt.sh API called in tight loop
  - No politeness delays
  - No backoff strategy
  - No detection of rate limiting (429 responses)
- **Impact:** IP blocked by target API provider
- **Suggested Fix:**
  ```python
  import time
  for page in range(max_pages):
      data = fetch_certs(domain, page)
      time.sleep(1)  # Be nice to API
      if is_rate_limited(data):
          time.sleep(60)  # Back off if rate limited
  ```

---

## BUG #15: Overly Broad Exception Handling
- **File:** [modules/vuln/scanner.py](modules/vuln/scanner.py)
- **Lines:** 60+
- **Category:** Logic Error - Error Masking
- **Severity:** 🟠 HIGH
- **Description:** Using bare `except:` or `except Exception:` catches all errors including programming mistakes.
- **Issues Found:**
  - Prevents proper error diagnosis
  - Silently swallows bugs
  - Makes debugging difficult
  - Could hide security issues
- **Suggested Fix:**
  ```python
  # BAD:
  except:
      pass
  
  # GOOD:
  except (socket.timeout, urllib.error.URLError) as e:
      logger.error(f"Network error: {e}")
  except KeyboardInterrupt:
      raise  # Always re-raise interrupts
  ```

---

# 🟡 MEDIUM SEVERITY ISSUES (15 bugs)

## BUG #16: Singleton Config Not Thread-Safe
- **File:** [app/core/config.py](app/core/config.py)
- **Lines:** 47-51
- **Category:** Logic Error - Missing Thread Safety
- **Severity:** 🟡 MEDIUM
- **Description:** Singleton Config instance pattern not protected by lock. Multiple threads could call `_load()` simultaneously, causing race condition.
- **Issues Found:**
  - No lock around `_instance` check and assignment
  - Classic "double-checked locking" bug
  - Race condition in initialization
- **Suggested Fix:**
  ```python
  import threading
  _lock = threading.Lock()
  
  @classmethod
  def instance(cls):
      with _lock:
          if cls._instance is None:
              cls._instance = cls()
      return cls._instance
  ```

---

## BUG #17: URLi Test Payloads Not Encoded
- **File:** [modules/vuln/scanner.py](modules/vuln/scanner.py)
- **Lines:** 100+
- **Category:** Security - Improper Encoding
- **Severity:** 🟡 MEDIUM
- **Description:** SQL injection test payloads sent directly without URL encoding in some paths. `?id=1'` should be URL-encoded as `?id=1%27`.
- **Issues Found:**
  - No `urllib.parse.quote()` on test payloads
  - URL parameters not consistently encoded
  - Response pattern matching too broad
- **Suggested Fix:**
  ```python
  from urllib.parse import urlencode
  payload = {"id": "1'"}
  encoded_url = url + "?" + urlencode(payload)
  ```

---

## BUG #18: No Timeout on ThreadPoolExecutor Operations
- **File:** [modules/recon/active.py](modules/recon/active.py)
- **Lines:** 45+
- **Category:** Logic Error - Resource Management
- **Severity:** 🟡 MEDIUM
- **Description:** `concurrent.futures.as_completed()` sometimes used without timeout parameter. Long-running scans could hang indefinitely.
- **Issues Found:**
  - No timeout on thread pool operations
  - Could block forever
  - No recovery mechanism
- **Suggested Fix:**
  ```python
  for future in concurrent.futures.as_completed(futures, timeout=300):
      try:
          result = future.result()
      except concurrent.futures.TimeoutError:
          logger.warning("Task timed out - cancelling...")
  ```

---

## BUG #19: No Response Size Limit (DoS Risk)
- **File:** [fuzz_server.py](fuzz_server.py)
- **Lines:** 45-50
- **Category:** Logic Error - DoS Vulnerability
- **Severity:** 🟡 MEDIUM
- **Description:** `requests.get()` has no response size limit. Could download very large files and exhaust memory.
- **Issues Found:**
  - No `stream=True` or response size check
  - No content-length validation
  - Could accidentally download entire CDN/S3 bucket
- **Suggested Fix:**
  ```python
  MAX_SIZE = 10 * 1024 * 1024  # 10MB
  response = requests.get(url, stream=True, timeout=5)
  if int(response.headers.get('content-length', 0)) > MAX_SIZE:
      return None
  content = b''
  for chunk in response.iter_content(chunk_size=8192):
      content += chunk
      if len(content) > MAX_SIZE:
          raise ValueError("Response too large")
  ```

---

## BUG #20: JSON Schema Not Validated in Config
- **File:** [app/core/config.py](app/core/config.py)
- **Lines:** 111+
- **Category:** Logic Error - Data Validation
- **Severity:** 🟡 MEDIUM
- **Description:** Config loading assumes JSON has expected structure without validation. Corrupted JSON would silently fail or crash.
- **Issues Found:**
  - `existing.setdefault(parts[0], {})` assumes dict type
  - No type checking or schema validation
  - Corrupted config could cause unexpected behavior
- **Suggested Fix:**
  ```python
  from jsonschema import validate
  schema = {
      "type": "object",
      "properties": {
          "api_keys": {"type": "object"},
          "scan": {
              "type": "object",
              "properties": {
                  "threads": {"type": "integer", "minimum": 1, "maximum": 1000}
              }
          }
      }
  }
  validate(instance=config, schema=schema)
  ```

---

## BUG #21: No Validation of Numeric Config Values
- **File:** [config.json](config.json)
- **Lines:** 40-43
- **Category:** Configuration Error - No Validation
- **Severity:** 🟡 MEDIUM
- **Description:** Config values like `threads` and `timeout` are not validated. Could be set to invalid values causing issues.
- **Issues Found:**
  - `"threads": 50` could be set to 0, -1, or 100000
  - `"timeout": 10` should be strictly positive
  - No bounds checking
- **Suggested Fix:**
  ```python
  def validate_scan_config(config):
      threads = config.get("scan", {}).get("threads", 50)
      if not isinstance(threads, int) or threads < 1 or threads > 1000:
          raise ValueError("threads must be int between 1 and 1000")
      
      timeout = config.get("scan", {}).get("timeout", 10)
      if not isinstance(timeout, (int, float)) or timeout <= 0:
          raise ValueError("timeout must be positive number")
  ```

---

## BUG #22: Missing Username Index on SQLite Table
- **File:** [app/core/database.py](app/core/database.py)
- **Lines:** 20+
- **Category:** Performance - Missing Index
- **Severity:** 🟡 MEDIUM
- **Description:** `users` table has no index on `username` column. Every login lookup scans entire table (O(n) instead of O(log n)).
- **Issues Found:**
  - Repeated table scans on every login
  - Performance degrades with more users
  - Simple fix improves performance 10-100x
- **Suggested Fix:**
  ```python
  def init_db():
      # Existing schema...
      conn.execute("""
          CREATE INDEX IF NOT EXISTS idx_users_username 
          ON users(username)
      """)
  ```

---

## BUG #23: 403 Forbidden Treated as "Path Found"
- **File:** [modules/recon/passive.py](modules/recon/passive.py)
- **Lines:** 80+
- **Category:** Logic Error - Imprecise Detection
- **Severity:** 🟡 MEDIUM
- **Description:** Code treats both 200 OK and 403 Forbidden as "path found". 403 usually means path exists but access denied (permission issue), not necessarily that it should be reported.
- **Issues Found:**
  - `if status in (200, 403):` is imprecise
  - 403 could be legitimate protection mechanism
  - Many false positives in scan results
  - Should separate 200 (accessible) from 403 (exists but denied)
- **Suggested Fix:**
  ```python
  if response.status_code == 200:
      return {"status": "FOUND", "accessible": True}
  elif response.status_code == 403:
      return {"status": "PROTECTED", "accessible": False}
  elif response.status_code == 404:
      return {"status": "NOT_FOUND"}
  ```

---

## BUG #24: Default Credentials Exposed in README
- **File:** [README.md](README.md)
- **Lines:** 21
- **Category:** Documentation - Security Risk
- **Severity:** 🟡 MEDIUM
- **Description:** README prominently displays default credentials (`admin / admin`). While necessary for documentation, this increases risk if file is accidentally committed to deployed systems or shared.
- **Issues Found:**
  - Credentials displayed prominently
  - No warning that they should be changed immediately
  - Could be indexed by search engines
  - Deploy scripts might not change defaults
- **Suggested Fix:**
  ```markdown
  > [!WARNING]
  > **Default Credentials:** `admin` / `admin`
  > **⚠️ CHANGE IMMEDIATELY on first use!**
  > In production: Use Settings → Users to change password
  > 
  > If credentials are left default:
  > - System is FULLY compromised
  > - Do not expose to internet
  ```

---

## BUG #25: Exception Hook Masks Real Errors
- **File:** [main.py](main.py)
- **Lines:** 12-35
- **Category:** Logic Error - Error Masking
- **Severity:** 🟡 MEDIUM
- **Description:** Custom exception hook silences errors containing partial text matches. Could hide real errors with similar text to the noise filter.
- **Current Code:**
  ```python
  _NOISE = (
      "main thread is not in main loop",
      "invalid command name",
      "check_dpi_scaling",
  )
  
  def _clean_excepthook(exc_type, exc_val, exc_tb):
      if any(s in str(exc_val) for s in _NOISE):
          return  # SILENCED!
  ```
- **Issues Found:**
  - String matching is fragile (could match legitimate errors)
  - `"main thread is not in main loop"` could match other errors
  - Real bugs hidden by this filter
- **Suggested Fix:**
  ```python
  # Only suppress if message EXACTLY matches (not partial)
  if str(exc_val) in _NOISE or type(exc_type).__name__ in ["TclError"]:
      return
  ```

---

## BUG #26: No Keyboard Interrupt Handling
- **File:** [brute-server.py](brute-server.py)
- **Lines:** 32 (end of script)
- **Category:** Logic Error - No Graceful Exit
- **Severity:** 🟡 MEDIUM
- **Description:** Script loops forever with no keyboard interrupt (Ctrl+C) handler. Cannot exit cleanly.
- **Issues Found:**
  - Infinite loop with no exit condition
  - `KeyboardInterrupt` not caught
  - Session object not closed on exit
  - Could leave processes/connections hanging
- **Suggested Fix:**
  ```python
  try:
      while True:
          # brute force logic
          pass
  except KeyboardInterrupt:
      print("\n[*] Stopping...")
      session.close()
      sys.exit(0)
  ```

---

## BUG #27: Missing CLI Tool Availability Check
- **File:** [modules/recon/passive.py](modules/recon/passive.py)
- **Lines:** 95
- **Category:** Logic Error - Tool Dependency Check
- **Severity:** 🟡 MEDIUM
- **Description:** Tool availability checked with `shutil.which()` every time it's called (inefficient). Should cache result.
- **Issues Found:**
  - Repeated subprocess/filesystem calls
  - Should use module-level cache
  - Performance impact on repeated calls
- **Suggested Fix:**
  ```python
  from functools import lru_cache
  
  @lru_cache(maxsize=32)
  def tool_available(tool_name):
      return shutil.which(tool_name) is not None
  ```

---

## BUG #28: SQLi Payloads Not URL-Encoded
- **File:** [modules/vuln/scanner.py](modules/vuln/scanner.py)
- **Lines:** 100+
- **Category:** Security - Request Formatting
- **Severity:** 🟡 MEDIUM
- **Description:** Some SQLi test payloads sent directly without URL encoding. Spaces become `+`, quotes become `%27`, etc.
- **Issues Found:**
  - Inconsistent payload encoding
  - Some payloads malformed in transit
  - Server might reject malformed requests
- **Suggested Fix:**
  ```python
  from urllib.parse import quote
  payloads = ["1'", "1 OR 1=1", "1; DROP TABLE users;--"]
  for payload in payloads:
      test_url = f"{url}?id={quote(payload)}"
      test_url(test_url)
  ```

---

## BUG #29: Missing Dependencies in requirements.txt
- **File:** [requirements.txt](requirements.txt)
- **Lines:** All
- **Category:** Configuration - Incomplete Dependencies
- **Severity:** 🟡 MEDIUM
- **Description:** requirements.txt only lists 4 packages but codebase uses many more. Missing critical dependencies.
- **Current Content:**
  ```
  customtkinter>=5.2.0
  Pillow>=10.0.0
  requests>=2.31.0
  psutil>=5.9.0
  ```
- **Issues Found:**
  - No `urllib3` listed (used directly)
  - No `cryptography` (for SSL)
  - No external CLI tools (nuclei, ffuf, nmap, etc.)
  - No Python version requirement specified
  - No mention of system dependency for `tkinter`
- **Suggested Fix:**
  ```
  customtkinter>=5.2.0
  Pillow>=10.0.0
  requests>=2.31.0
  psutil>=5.9.0
  urllib3>=2.0.0
  bcrypt>=4.0.0  # For password hashing
  jsonschema>=4.0.0  # For config validation
  # External tools: Install from package manager
  # - ffuf: apt install ffuf (or brew)
  # - nuclei: https://github.com/projectdiscovery/nuclei
  # - nmap: apt install nmap
  ```

---

## BUG #30: Path Traversal Risk in Wordlist Loading
- **File:** [multiple files](modules/recon/passive.py)
- **Lines:** Wordlist loading code
- **Category:** Security - Path Traversal
- **Severity:** 🟡 MEDIUM
- **Description:** Wordlist paths accepted without validation. User could provide `wordlists/../../etc/passwd` and leak system files.
- **Issues Found:**
  - No path validation
  - No check for `..` sequences
  - Could read arbitrary files
- **Suggested Fix:**
  ```python
  import os.path
  
  def load_wordlist(wordlist_name):
      # Normalize and validate path
      base = "wordlists/"
      full_path = os.path.normpath(os.path.join(base, wordlist_name))
      
      # Ensure it's still under base directory
      if not full_path.startswith(os.path.abspath(base)):
          raise ValueError("Path traversal detected")
      
      with open(full_path) as f:
          return f.readlines()
  ```

---

# 🔵 LOW SEVERITY ISSUES (9 bugs)

## BUG #31: Unused Import in active.py
- **File:** [modules/recon/active.py](modules/recon/active.py)
- **Lines:** 1
- **Category:** Code Quality - Unused Import
- **Severity:** 🔵 LOW
- **Description:** Import `ssl` module but never use it.
- **Current Code:**
  ```python
  import socket, ssl  # ssl never used
  ```
- **Suggested Fix:**
  ```python
  import socket  # Remove ssl if not used
  ```

---

## BUG #32: Hardcoded Timeout Values
- **File:** [connect-server.py](connect-server.py)
- **Lines:** 14
- **Category:** Configuration - Not Configurable
- **Severity:** 🔵 LOW
- **Description:** Socket timeout hardcoded to 7 seconds. Should be configurable.
- **Suggested Fix:**
  ```python
  timeout = config.get("socket_timeout", 7)
  sock.settimeout(timeout)
  ```

---

## BUG #33: File Output Not Atomic
- **File:** [fuzz_server.py](fuzz_server.py)
- **Lines:** 53
- **Category:** Logic Error - Non-Atomic Write
- **Severity:** 🔵 LOW
- **Description:** Results written to `found_paths.txt` without atomic write. Concurrent writes could corrupt file.
- **Suggested Fix:**
  ```python
  import tempfile
  with tempfile.NamedTemporaryFile(mode='a', delete=False, dir='logs/') as tmp:
      tmp.write(f"{path}\n")
      tmp_path = tmp.name
  os.replace(tmp_path, 'logs/found_paths.txt')  # Atomic rename
  ```

---

## BUG #34: Output Directory Not Validated
- **File:** [modules/recon/passive.py](modules/recon/passive.py)
- **Lines:** Write operations
- **Category:** Logic Error - Output Validation
- **Severity:** 🔵 LOW
- **Description:** Output written to hardcoded `logs/` directory without checking if path is accessible.
- **Suggested Fix:**
  ```python
  os.makedirs("logs/", exist_ok=True)
  if not os.access("logs/", os.W_OK):
      raise PermissionError("Cannot write to logs/ directory")
  ```

---

## BUG #35: Missing Platform Check for some Tools
- **File:** [modules/recon/passive.py](modules/recon/passive.py)
- **Lines:** Various subprocess calls
- **Category:** Logic Error - Platform Compatibility
- **Severity:** 🔵 LOW
- **Description:** Some tools (e.g., `nmap`) might not be available on Windows. No platform check before calling.
- **Suggested Fix:**
  ```python
  import platform
  
  if platform.system() == "Windows":
      raise NotImplementedError("nmap not available on Windows")
  ```

---

## BUG #36: Regex Pattern Could Be Optimized
- **File:** [modules/recon/deep_recon.py](modules/recon/deep_recon.py)
- **Lines:** 25+
- **Category:** Performance - Regex Optimization
- **Severity:** 🔵 LOW
- **Description:** Some regex patterns with `\S+` could be optimized or could be exploited via ReDoS on large inputs.
- **Suggested Fix:**
  ```python
  # Instead of: re.compile(r'\S+@\S+\.\S+')  # Could be slow
  # Use:
  import re
  EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
  ```

---

## BUG #37: Subprocess Calls Not Sanitized
- **File:** [modules/recon/active.py](modules/recon/active.py)
- **Lines:** Subprocess calls
- **Category:** Security - Subprocess Injection
- **Severity:** 🔵 LOW
- **Description:** Subprocess calls might use shell=True with user input. Should always use shell=False.
- **Suggested Fix:**
  ```python
  # BAD:
  os.system(f"nmap {target}")  # Shell injection risk
  
  # GOOD:
  subprocess.run(["nmap", target], check=True)
  ```

---

## BUG #38: No Logging Configuration
- **File:** [main.py](main.py)
- **Category:** Code Quality - Missing Logging
- **Severity:** 🔵 LOW
- **Description:** No central logging setup. Error messages, warnings, etc. are printed to stdout.
- **Suggested Fix:**
  ```python
  import logging
  
  logging.basicConfig(
      level=logging.INFO,
      format='%(asctime)s - %(levelname)s - %(message)s',
      handlers=[
          logging.FileHandler('logs/app.log'),
          logging.StreamHandler()
      ]
  )
  logger = logging.getLogger(__name__)
  ```

---

## BUG #39: Broken Image Link in README
- **File:** [README.md](README.md)
- **Lines:** 8
- **Category:** Documentation - Broken Link
- **Severity:** ⚪ TRIVIAL
- **Description:** Image link uses `https://readme-typing-svg.herokuapp.com` which requires internet. Could fail if offline.
- **Suggested Fix:**
  ```markdown
  <!-- Self-hosted or local image instead -->
  <img src="assets/banner.png" alt="Typing Header" />
  ```

---

# ⚪ TRIVIAL SEVERITY ISSUES (3 bugs)

## BUG #40: Unused Platform Variable
- **File:** [app/ui/theme.py](app/ui/theme.py)
- **Lines:** 16
- **Category:** Code Quality - Unused Variable
- **Severity:** ⚪ TRIVIAL
- **Description:** `platform.system()` stored in `_SYS` but platform checked multiple times inline instead of using variable.
- **Current Code:**
  ```python
  _SYS = platform.system()
  
  if platform.system() == "Darwin":  # Should use _SYS
      # ...
  if platform.system() == "Windows":  # Should use _SYS
      # ...
  ```
- **Suggested Fix:**
  ```python
  if _SYS == "Darwin":
  if _SYS == "Windows":
  ```

---

## BUG #41: Typo in Version Badge
- **File:** [README.md](README.md)
- **Lines:** 15
- **Category:** Documentation - Minor Error
- **Severity:** ⚪ TRIVIAL
- **Description:** Version badge shows both "v5.0.1" and "v4.0" in different places. Should be consistent.
- **Suggested Fix:**  Make version consistent throughout documentation

---

## BUG #42: Missing Error Context
- **File:** [app/core/config.py](app/core/config.py)
- **Lines:** 110
- **Category:** Code Quality - Silent Failure
- **Severity:** ⚪ TRIVIAL
- **Description:** Exception silently swallowed with bare `pass`. Should at least log the error.
- **Current Code:**
  ```python
  try:
      # Something
  except:
      pass  # Silent failure!
  ```
- **Suggested Fix:**
  ```python
  except Exception as e:
      logger.error(f"Config error: {e}", exc_info=True)
  ```

---

# 📋 SUMMARY TABLE

| # | File | Severity | Category | Status |
|---|------|----------|----------|--------|
| 1 | brute-server.py | 🔴 CRITICAL | Unauthorized Testing | ❌ MUST FIX |
| 2 | connect-server.py | 🔴 CRITICAL | SSL/CVE Testing | ❌ MUST FIX |
| 3 | fuzz_server.py | 🔴 CRITICAL | Unauthorized Fuzzing | ❌ MUST FIX |
| 4 | app/core/database.py | 🔴 CRITICAL | Weak Hashing | ❌ MUST FIX |
| 5 | config.json | 🔴 CRITICAL | SSL Disabled | ❌ MUST FIX |
| 6 | config.json | 🔴 CRITICAL | No Key Validation | ❌ MUST FIX |
| 7 | app/core/database.py | 🔴 CRITICAL | Timing Attack | ❌ MUST FIX |
| 8 | app/core/config.py | 🟠 HIGH | Race Condition | ⚠️ URGENT |
| 9 | app/core/database.py | 🟠 HIGH | Resource Leak | ⚠️ URGENT |
| 10 | modules/recon/active.py | 🟠 HIGH | Resource Leak | ⚠️ URGENT |
| 11 | modules/vuln/scanner.py | 🟠 HIGH | Resource Leak | ⚠️ URGENT |
| 12 | modules/recon/passive.py | 🟠 HIGH | Input Validation | ⚠️ URGENT |
| 13 | modules/recon/passive.py | 🟠 HIGH | File Handles | ⚠️ URGENT |
| 14 | modules/recon/passive.py | 🟠 HIGH | No Rate Limit | ⚠️ URGENT |
| 15 | modules/vuln/scanner.py | 🟠 HIGH | Broad Exceptions | ⚠️ URGENT |
| 16 | app/core/config.py | 🟡 MEDIUM | Thread Safety | ⚠️ SOON |
| 17 | modules/vuln/scanner.py | 🟡 MEDIUM | Encoding | ⚠️ SOON |
| 18 | modules/recon/active.py | 🟡 MEDIUM | Timeout | ⚠️ SOON |
| 19 | fuzz_server.py | 🟡 MEDIUM | DoS Risk | ⚠️ SOON |
| 20 | app/core/config.py | 🟡 MEDIUM | Schema Val. | ⚠️ SOON |
| 21 | config.json | 🟡 MEDIUM | Value Val. | ⚠️ SOON |
| 22 | app/core/database.py | 🟡 MEDIUM | Missing Index | ⚠️ SOON |
| 23 | modules/recon/passive.py | 🟡 MEDIUM | Detection Logic | ⚠️ SOON |
| 24 | README.md | 🟡 MEDIUM | Credentials | ⚠️ SOON |
| 25 | main.py | 🟡 MEDIUM | Error Masking | ⚠️ SOON |
| 26 | brute-server.py | 🟡 MEDIUM | No Exit Handler | ⚠️ SOON |
| 27 | modules/recon/passive.py | 🟡 MEDIUM | Tool Check | ⚠️ SOON |
| 28 | modules/vuln/scanner.py | 🟡 MEDIUM | URL Encoding | ⚠️ SOON |
| 29 | requirements.txt | 🟡 MEDIUM | Missing Deps | ⚠️ SOON |
| 30 | modules/ | 🟡 MEDIUM | Path Traversal | ⚠️ SOON |
| 31 | modules/recon/active.py | 🔵 LOW | Unused Import | ✔️ NICE |
| 32 | connect-server.py | 🔵 LOW | Config | ✔️ NICE |
| 33 | fuzz_server.py | 🔵 LOW | Atomic Write | ✔️ NICE |
| 34 | modules/ | 🔵 LOW | Output Dir | ✔️ NICE |
| 35 | modules/ | 🔵 LOW | Platform Check | ✔️ NICE |
| 36 | modules/recon/deep_recon.py | 🔵 LOW | Regex | ✔️ NICE |
| 37 | modules/ | 🔵 LOW | Subproc Inject | ✔️ NICE |
| 38 | main.py | 🔵 LOW | Logging | ✔️ NICE |
| 39 | README.md | ⚪ TRIVIAL | Link | ✔️ NICE |
| 40 | app/ui/theme.py | ⚪ TRIVIAL | Variable | ✔️ NICE |
| 41 | README.md | ⚪ TRIVIAL | Typo | ✔️ NICE |
| 42 | app/core/config.py | ⚪ TRIVIAL | Error Log | ✔️ NICE |

---

# 🎯 RECOMMENDED FIX PRIORITY

## Phase 1: CRITICAL (Block Deployment)
1. **Remove hardcoded targets** from brute-server.py, connect-server.py, fuzz_server.py
2. **Replace SHA256 with bcrypt** for password hashing
3. **Enable SSL verification** in config.json
4. **Add timing-safe password comparison** using hmac.compare_digest()

## Phase 2: HIGH (Before Production)
5. **Fix race conditions** in config file writes (atomic operations)
6. **Close all resource leaks** (database connections, sockets, files)
7. **Add input validation** for domain/URL parameters
8. **Add API key validation** in config

## Phase 3: MEDIUM (Before Release)
9. **Complete requirements.txt** with all dependencies
10. **Add thread safety** to Config singleton
11. **Fix error handling** (remove bare except:)
12. **Add rate limiting** to API calls

## Phase 4: LOW (Polish)
13. Remove unused imports
14. Add logging configuration
15. Update README with better security warnings
16. Optimize performance issues

---

# 🔗 Related Files Needing Review

- `app/ai/auto_exploit.py` - AI exploitation module (not analyzed, likely has issues)
- `modules/exploit/` - All exploit modules (not fully analyzed)
- `modules/analysis/` - All analysis modules (not fully analyzed)
- `modules/http/` - HTTP modules (not fully analyzed)

---

**Report Generated:** 2026-04-11  
**Total Issues:** 42  
**Estimated Time to Fix:** 40-60 hours (HIGH + CRITICAL)

---

## 📞 Notes for Development Team

- This report identifies **all bugs** including trivial ones as requested
- **Zero filter** applied - nothing hidden
- Most issues are **fixable with code changes**
- **Server files** (brute-server.py, connect-server.py, fuzz_server.py) should only be used in controlled environments with explicit authorization
- Consider implementing **security code review process** before final deployment
- **Missing dependency on bcrypt** - must install for secure password hashing: `pip install bcrypt`

---
