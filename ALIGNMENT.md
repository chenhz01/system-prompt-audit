# ALIGNMENT.md — R13 alignment record (16 items)

Design source: `_r13_design.json` → repo `system-prompt-audit`,
domain SystemPrompt审计, sim `adjacent`. Date of record: 2026-10-11.

| # | Item | Evidence |
| --- | --- | --- |
| 1 | Repo name matches design entry | Directory `system-prompt-audit` == design JSON `name`. |
| 2 | Mechanism implemented as specified | Design mechanism "泄漏面/越权指令/硬编码密钥模式/矛盾约束清单" → LEAK-*/DESTRUCT-*/PRIV-001, SECRET-001..004, CONTRA-001/002 rules in core.py. |
| 3 | Pure Python standard library only | Imports: argparse, json, re, sys (+ os/tempfile in tests). |
| 4 | CLI entry via argparse | `core.py file [--format] [--exit-zero]`; README quickstart runs as written. |
| 5 | self_test.py ≥40 cases, three categories | Functional (each rule), exception paths (CLI errors, non-blocking vs blocking severities), extreme edge (empty/whitespace/unicode/CRLF input, 2000-line prompt, redaction check, source purity check). |
| 6 | Final line `SUMMARY: PASS n/n` | `python self_test.py` ends with that exact line. |
| 7 | README first paragraph ≤60 words | Intro ~55 words (counted 2026-10-11). |
| 8 | README required sections present | All mandated sections incl. FAQ "When NOT to use" and 3 Core Assumptions. |
| 9 | why-not-X ≥3 alternatives with real anchors | Table lists SUDARSHANCHAUDHARI/PromptLeakScanner (1★), Zion-support/zion-prompt-leak-scanner (0★), MukundaKatta/system-prompt-leak-scan-py (0★) with stars from design JSON; differences paraphrased. |
| 10 | MIT LICENSE, "zhengming contributors" | LICENSE copyright line as required; no real names. |
| 11 | CHANGELOG v0.1.0 → v0.1.1 | CHANGELOG.md documents both versions dated 2026-10-11. |
| 12 | Two-round iteration, ≥1 dimension ≥20% | Round 2 added rule ROLE-001 (identity-override surface) — rule count 9 → 10 — plus `--min-severity` filter and 11 new tests (45 → 56, +24.4% tests). Recorded in CHANGELOG v0.1.1. |
| 13 | Number discipline | Test counts quoted from self_test SUMMARY (repro: `python self_test.py`); risk-score weights documented inline in core.py. |
| 14 | Zero secrets / zero real names | No keys; "zhengming contributors" copyright; secret excerpts redacted in tool output. |
| 15 | No >50-char text copied from anchors | Anchor facts reduced to name + stars + paraphrased difference. |
| 16 | as-of date marked | README headline and Confidence footer say "as of 2026-10-11". |
| + | Defensive red line | Zero attack payloads: self-test `t_no_attack_payloads_in_repo_code` greps source for exploit vocabulary and network calls; tool performs static pattern matching only. |
