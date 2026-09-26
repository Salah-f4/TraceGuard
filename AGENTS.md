# TraceGuard development contract

## Approved state and Phase 6 scope

Phases 1–5 are implemented. Phase 6 release preparation is approved as documented
in docs/phase6-plan.md. MIT, copyright 2026 Salahuddin Alrowaili; provisional source
URL https://github.com/Salah-f4/TraceGuard. Security contact is GitHub private
vulnerability reporting, enabled by the owner later; publish no personal email.

Read-only dependency-advisory queries and official package/tool downloads are
approved for locking/building/validation. No live VirusTotal, AbuseIPDB, URLhaus or
Groq calls. No commits, pushes, repository creation, tags, releases or publication.
Do not access or modify the real .env or live reports; preserve .venv and .venv312.
Use .venv312 for the Python 3.12 suite; isolated build environments belong in build/.

## Product and architecture

Reusable Python core independent from Typer/Rich CLI, HTTP adapters and future web
API. Extract/normalize/validate/deduplicate IPv4/IPv6, domains, URLs, emails and
MD5/SHA-1/SHA-256 with source provenance. Strict input/occurrence limits; no silent
truncation. See docs/product.md and docs/architecture.md for current contracts.
No website, persistence, authentication, new providers or remediation in Phase 6.

Enrichment requires --enrich; existing-report lookups only, eligible normalized
IOCs without raw context. No files/scans, non-public IPs or email disclosure.
Credentials stay out of source, logs, errors and tests. Provider failures retain
partial reports. Keys are inherited environment values or current-directory .env
only; no interpolation, parent discovery or mutation. Default operation is offline.

Scoring/correlation follow docs/phase4-plan.md exactly. Pure deterministic functions;
separate risk and confidence; zero/not_found never means safe. No failure penalty.
Preserve original provider evidence and full explainable breakdowns.

AI requires --ai; Groq qwen/qwen3.8-27b, TRACEGUARD_GROQ_API_KEY. Compact value-free
projection, strict flat ordered alias output, frozen local destinations and local
wording. Preserve ownership, mandatory uncertainty, global duplicate/count limits,
4,000/1,000 token caps, safe diagnostics and full fallback. No tools or streaming.
Raw model output is never logged/saved. No scoring or AI behavior changes unless a
failing regression proves a defect; document any minimal fix and request policy
approval for intentional changes.

## Development rules

Keep src/tests/docs separate. Preserve user work. Tests use temporary cwd, cleared
credentials, synthetic data and mocked HTTP only. Independently block networking in
installed-wheel subprocesses. No live markers, real provider responses or secrets
in fixtures/screenshots. Use Ruff, strict mypy, pytest with branch coverage, pip
check, compilation and CLI checks. Pin release tools and hash-lock dependencies.
Inspect wheel/sdist contents and explicit release candidate files; never git add
or clean broadly. Secret scans must redact output. Run pip-audit without --fix.
Update current docs rather than appending conflicting implementation claims.
