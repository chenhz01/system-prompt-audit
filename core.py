#!/usr/bin/env python3
"""system-prompt-audit: defensive static auditor for LLM system prompts.

Scans prompt text for four risk classes: leak surfaces, hardcoded secrets,
unscoped destructive/privileged commands, and contradictory constraints
(always/never conflicts, conflicting numeric maxima). Static pattern
matching only — contains no attack payloads, performs no network or model
calls, and redacts secret matches in its own output.
"""
import argparse
import json
import re
import sys

RULES = [
    {"id": "LEAK-001", "cat": "leak_surface", "severity": "high",
     "regex": r"(?i)\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(?:instructions?|rules?|prompts?)\b",
     "message": "instruction to disregard prior instructions (leak surface)"},
    {"id": "LEAK-002", "cat": "leak_surface", "severity": "high",
     "regex": r"(?i)\b(?:reveal|print|show|repeat|output|disclose|verbatim)\b[^.\n]{0,30}\b(?:system\s+prompt|instructions?|rules?|directives?)\b",
     "message": "instruction that surfaces the prompt itself"},
    {"id": "SECRET-001", "cat": "secret", "severity": "critical",
     "regex": r"\bsk-[A-Za-z0-9_-]{20,}",
     "message": "hardcoded API-key-like token (sk-...)"},
    {"id": "SECRET-002", "cat": "secret", "severity": "critical",
     "regex": r"\bAKIA[0-9A-Z]{16}\b",
     "message": "hardcoded AWS access key id pattern"},
    {"id": "SECRET-003", "cat": "secret", "severity": "critical",
     "regex": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
     "message": "hardcoded GitHub token pattern"},
    {"id": "SECRET-004", "cat": "secret", "severity": "critical",
     "regex": r"(?i)\b(?:password|passwd|api[_-]?key|secret|token)\b\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
     "message": "hardcoded credential assignment"},
    {"id": "DESTRUCT-001", "cat": "unscoped_destructive", "severity": "high",
     "regex": r"(?i)\b(?:rm\s+-rf|drop\s+table|truncate\s+table|delete\s+from\s+\w+|mkfs|dd\s+if=|format\s+c:)",
     "message": "destructive command reference without scoping"},
    {"id": "PRIV-001", "cat": "privilege", "severity": "medium",
     "regex": r"(?i)\b(?:sudo|chmod\s+0?777|setenforce\s+0)\b",
     "message": "privilege-escalation command reference"},
    {"id": "NET-001", "cat": "exfil_surface", "severity": "medium",
     "regex": r"(?i)\b(?:curl|wget|nc|netcat)\b\s+\S+",
     "message": "network fetch command in prompt (possible exfil channel)"},
]

SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

# Phrases that turn a leak-sounding sentence into a *defensive* directive,
# e.g. "never reveal your system prompt". Matches preceded by these within
# a short window are downgraded from high to info.
DEFENSIVE_PREFIXES = ("never ", "do not ", "don't ", "dont ", "avoid ",
                      "refuse ", "without ")
DEFENSIVE_WINDOW = 16

ALWAYS_RE = re.compile(r"(?i)\balways\s+([a-z][a-z \-]{2,40}?)(?=[.,;\n]|$)")
NEVER_RE = re.compile(r"(?i)\bnever\s+([a-z][a-z \-]{2,40}?)(?=[.,;\n]|$)")
MAX_RE = re.compile(r"(?i)\bmax(?:imum)?\s+([a-z][a-z_ \-]{1,30}?)\s*"
                    r"(?:of|=|:|is)?\s*(\d{1,12})\b")


def _normalize(s):
    return " ".join(s.lower().split())


def _excerpt(text, start, end, cap=40):
    s = max(0, start - 8)
    e = min(len(text), end + 8)
    out = text[s:e].replace("\n", " ")
    return out[:cap] if len(out) <= cap else out[: cap - 3] + "..."


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _is_defensive(line, start):
    window = line[max(0, start - DEFENSIVE_WINDOW):start].lower()
    return any(p in window for p in DEFENSIVE_PREFIXES)


def scan_line(line, lineno):
    findings = []
    for rule in RULES:
        for m in re.finditer(rule["regex"], line):
            category = rule["cat"]
            severity = rule["severity"]
            excerpt = ("[redacted pattern match]"
                       if category == "secret" else _excerpt(line, m.start(), m.end()))
            detail = ""
            if category == "leak_surface" and _is_defensive(line, m.start()):
                severity = "info"
                detail = " (defensive directive; downgraded)"
            findings.append({"id": rule["id"], "category": category,
                             "severity": severity, "line": lineno,
                             "col": m.start() + 1,
                             "message": rule["message"] + detail,
                             "excerpt": excerpt})
    return findings


def find_contradictions(text):
    findings = []
    always = {}
    for m in ALWAYS_RE.finditer(text):
        always.setdefault(_normalize(m.group(1)), m.start())
    for m in NEVER_RE.finditer(text):
        obj = _normalize(m.group(1))
        if obj in always:
            findings.append({"id": "CONTRA-001", "category": "contradiction",
                             "severity": "medium", "line": _line_of(text, m.start()),
                             "col": 1,
                             "message": "conflicting always/never directive for %r"
                                        % obj,
                             "excerpt": _excerpt(text, m.start(), m.end() + 10)})
    return findings


def find_max_conflicts(text):
    seen = {}
    findings = []
    for m in MAX_RE.finditer(text):
        noun = _normalize(m.group(1))
        val = int(m.group(2))
        if noun in seen and seen[noun] != val:
            findings.append({"id": "CONTRA-002", "category": "contradiction",
                             "severity": "medium",
                             "line": _line_of(text, m.start()), "col": 1,
                             "message": "conflicting max values for %r: %d vs %d"
                                        % (noun, seen[noun], val),
                             "excerpt": _excerpt(text, m.start(), m.end())})
        else:
            seen.setdefault(noun, val)
    return findings


def scan_prompt(text):
    """Audit prompt text; returns a findings list sorted by position."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        findings.extend(scan_line(line, lineno))
    findings.extend(find_contradictions(text))
    findings.extend(find_max_conflicts(text))
    findings.sort(key=lambda f: (f["line"], f["col"], f["id"]))
    return findings


def summarize(findings):
    by_sev, by_cat = {}, {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        cat = f.get("category", "unknown")
        by_cat[cat] = by_cat.get(cat, 0) + 1
    risk_score = sum(SEVERITY_WEIGHT.get(s, 0) * n for s, n in by_sev.items())
    return {"count": len(findings), "by_severity": by_sev,
            "by_category": by_cat, "risk_score": risk_score,
            "blocking": any(s in ("critical", "high") for s in by_sev)}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="system-prompt-audit",
        description="Defensive static audit of system prompts (no model "
                    "calls, no attack payloads).")
    parser.add_argument("file", help="prompt file ('-' for stdin)")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    parser.add_argument("--exit-zero", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.file == "-":
            text = sys.stdin.read()
        else:
            with open(args.file, "r", encoding="utf-8") as f:
                text = f.read()
    except OSError as e:
        print("error: cannot read prompt: %s" % e, file=sys.stderr)
        return 2
    findings = scan_prompt(text)
    summary = summarize(findings)
    if args.format == "text":
        for f in findings:
            print("%s:%d %s[%s] %s" % (f["id"], f["line"], f["severity"],
                                       f["category"], f["message"]))
        print("summary: %s" % json.dumps(summary, sort_keys=True))
    else:
        print(json.dumps({"findings": findings, "summary": summary},
                         ensure_ascii=True, indent=2, sort_keys=True))
    if args.exit_zero:
        return 0
    return 1 if summary["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
