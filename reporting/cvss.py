"""
TeamCyberOps Suite v3 — CVSS v3.1 Calculator
Full CVSS 3.1 base score computation
"""

# CVSS 3.1 metric weights
WEIGHTS = {
    "AV":  {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC":  {"L": 0.77, "H": 0.44},
    "PR":  {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_S":{"N": 0.85, "L": 0.68, "H": 0.50},  # when Scope Changed
    "UI":  {"N": 0.85, "R": 0.62},
    "C":   {"N": 0.00, "L": 0.22, "H": 0.56},
    "I":   {"N": 0.00, "L": 0.22, "H": 0.56},
    "A":   {"N": 0.00, "L": 0.22, "H": 0.56},
}

METRIC_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}

METRIC_NAMES = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S":  "Scope",
    "C":  "Confidentiality Impact",
    "I":  "Integrity Impact",
    "A":  "Availability Impact",
}


def calculate_cvss(AV, AC, PR, UI, S, C, I, A) -> dict:
    """
    Calculate CVSS v3.1 Base Score.
    All params are single-letter abbreviations as per CVSS spec.
    Returns dict with score, severity, vector string.
    """
    scope_changed = (S == "C")

    av = WEIGHTS["AV"][AV]
    ac = WEIGHTS["AC"][AC]
    pr = WEIGHTS["PR_S"][PR] if scope_changed else WEIGHTS["PR"][PR]
    ui = WEIGHTS["UI"][UI]
    c  = WEIGHTS["C"][C]
    i  = WEIGHTS["I"][I]
    a  = WEIGHTS["A"][A]

    # ISS (Impact Sub-Score)
    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    # Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    else:
        if scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10)
        else:
            base_score = min(impact + exploitability, 10)
        base_score = _roundup(base_score)

    severity = score_to_severity(base_score)
    vector = f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}"

    return {
        "score":       base_score,
        "severity":    severity,
        "vector":      vector,
        "impact":      round(impact, 2),
        "exploitability": round(exploitability, 2),
        "iss":         round(iss, 2),
    }


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup function — round up to 1 decimal place."""
    import math
    return math.ceil(x * 10) / 10


def score_to_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"


def severity_color(severity: str) -> str:
    colors = {
        "Critical": "#f85149",
        "High":     "#d29922",
        "Medium":   "#58a6ff",
        "Low":      "#3fb950",
        "None":     "#8b949e",
    }
    return colors.get(severity, "#8b949e")


def parse_vector(vector_string: str) -> dict:
    """Parse a CVSS vector string back into metrics."""
    try:
        parts = vector_string.split("/")[1:]  # skip CVSS:3.1
        return {p.split(":")[0]: p.split(":")[1] for p in parts}
    except Exception:
        return {}


def quick_score_examples() -> list:
    """Return common vulnerability CVSS examples."""
    return [
        {"vuln": "RCE via unauthenticated endpoint",
         "params": {"AV":"N","AC":"L","PR":"N","UI":"N","S":"C","C":"H","I":"H","A":"H"},
         "expected": 10.0},
        {"vuln": "SQL Injection (auth bypass)",
         "params": {"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"H"},
         "expected": 9.8},
        {"vuln": "Stored XSS",
         "params": {"AV":"N","AC":"L","PR":"L","UI":"R","S":"C","C":"L","I":"L","A":"N"},
         "expected": 5.4},
        {"vuln": "Reflected XSS",
         "params": {"AV":"N","AC":"L","PR":"N","UI":"R","S":"C","C":"L","I":"L","A":"N"},
         "expected": 6.1},
        {"vuln": "SSRF (internal network)",
         "params": {"AV":"N","AC":"L","PR":"N","UI":"N","S":"C","C":"H","I":"N","A":"N"},
         "expected": 8.6},
        {"vuln": "Open Redirect",
         "params": {"AV":"N","AC":"L","PR":"N","UI":"R","S":"U","C":"L","I":"N","A":"N"},
         "expected": 4.3},
        {"vuln": "Missing HSTS",
         "params": {"AV":"N","AC":"H","PR":"N","UI":"R","S":"U","C":"L","I":"N","A":"N"},
         "expected": 3.1},
    ]
