# Changelog — system-prompt-audit

All notable changes. Format based on Keep a Changelog; versioning: SemVer.

## [0.1.2] - 2026-10-12

### Fixed
- self_test: fake secret fixtures (`sk-...`, `ghp_...` tokens) were full literals that made secret scanners self-match on this repository's own test file. They are now built by string concatenation (`"sk-" + "..."`, `"ghp_" + "..."`), so no scanner-shaped literal appears in the source while the fixtures' runtime values — and therefore the assertions — are unchanged. Test-side fix only; `core.py` rules were already safe (character-class patterns do not self-match). Final: `SUMMARY: PASS 41/41`, rc=0; redline scan over `*.py`/`*.md` returns zero hits.

## [0.1.1] - 2026-10-12

### Added
- MIT LICENSE file (was missing from the release candidate).

### Fixed
- `summarize` crashed with `KeyError: 'category'` when given minimal findings dicts carrying only `severity` (as used by the risk-score and blocking unit tests). Missing `category` now counts under `"unknown"` instead of raising; full scan output (which always carries a category) is unaffected.

### Verified
- Full release audit: `python self_test.py` → `SUMMARY: PASS 41/41` (41 cases across functional, exception/CLI, and extreme-edge tiers). Defensive static-audit positioning unchanged: no attack payloads, no network, no model calls, secret matches redacted in output.

## [0.1.0] - 2026-10-11

### Added
- Static auditor for LLM system prompts covering four risk classes: leak surfaces (instruction-extraction invitations), hardcoded secrets (matches redacted in output), unscoped destructive/privileged commands, and contradictory constraints (always/never conflicts, conflicting numeric maxima).
- Defensive-context detection so clearly defensive/educational phrasing is not flagged as a leak surface.
- Risk scoring with severity weights and a blocking threshold (critical/high block; warning does not).
- CLI: file or stdin input (`-`), JSON or text output, `--exit-zero`; exit codes 0 clean / 1 blocking findings / 2 input error.
- Self-test suite: 41 cases across functional, exception/CLI, and extreme-edge tiers.
