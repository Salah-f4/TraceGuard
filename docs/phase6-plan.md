# Phase 6 plan: final validation and portfolio release preparation

Status: PROPOSED — planning only, 2026-09-26. Awaiting user approval.
No implementation, commits, pushes, publication, live intelligence calls or AI calls
are authorized by this plan. All new tests must use mocked transports. Documentation
review used public reference pages only; no provider endpoints or vulnerability
services were queried. No secret scan or vulnerability audit has run during planning.

## Scope and protected behavior

Prepare the existing CLI MVP for review and reproducible installation. Preserve
Phase 4 numerical policies and Phase 5 flat alias selection, immutable local
section routing, strict validation, safe diagnostics, privacy filters, limits and
complete deterministic fallback. A suspected defect must first have a failing
mocked regression and a documented minimal fix; no policy tuning disguised as cleanup.
No website, database, authentication, new provider, agent tools, persistence,
remediation, scanning, URL visits, DNS resolution or major feature is proposed.
Future implementation approval does not authorize publication, commits or pushes.

## Inspection baseline and concrete gaps

- Git: unborn `master`; no commits, tracked files or staged changes. Source, tests,
  docs and configuration templates are untracked. `git log` has no HEAD to show.
  No generated file needs removal from tracking today. Preserve the local working
  tree; do not use git clean, broad deletion or automatic git add.
- `.env`, `.venv`, `.venv312`, live-smoke-report.json, live-ai-smoke-report.json and
  standard tool caches are ignored and untracked. A pytest-cache-files-* directory
  also exists; inspect its purpose before proposing ignore/cleanup. Do not delete
  either environment or the user's reports.
- `.env.example` contains blank values for all four current keys plus obsolete
  TRACEGUARD_AI_API_KEY. Values were not displayed. Propose removing only that
  unused legacy name and documenting optional provider/model settings accurately.
- pyproject has setuptools, bounded runtime/dev ranges, >=3.12, version 0.1.0 and
  the CLI entry point, but no license, project URLs, platform classifiers or locks.
  Description still says offline extraction only; build dependency is unbounded.
- No LICENSE, SECURITY.md, CONTRIBUTING.md or GitHub Actions workflow exists.
- README contains contradictory historical statements that AI is absent, multiple
  validation counts and both .venv/.venv312 setup paths. AGENTS/product/architecture
  also contain superseded phase restrictions. Consolidation is needed.
- Existing coverage includes CLI, offline integration, provider resilience, pure
  scoring, AI privacy/budget/diagnostics and 11-alias local routing. The most recent
  recorded full suite is 540 tests, 98.11% combined statement/branch coverage on
  Python 3.12. These are prior results, not a new Phase 6 test run.
- Tests already clear inherited keys, use temporary cwd and block HTTP/DNS sockets.
  Review subprocess coverage: pytest monkeypatches do not protect child processes.
- Existing mixed.log is synthetic but includes a real IDNA domain and a token-like
  URL query example. Replace public demo material with reserved/defanged samples;
  do not copy live enrichment reports into fixtures or screenshots.
- The complete CLI → enrichment → assessment → Groq transport → local validation
  path needs a single integrated mocked regression; some AI CLI tests currently
  replace the assessment function. Add coverage around those component boundaries.

## Proposed work sequence

1. Freeze contracts and build an acceptance matrix referencing existing tests.
2. Add synthetic fixtures and missing complete mocked pipeline tests.
3. Review CLI messages and fresh Windows setup; fix only demonstrated defects.
4. Consolidate user/developer documentation and generate synthetic examples.
5. Add reproducible dependency inputs/locks, packaging validation and CI definition.
6. Run secret and dependency review under the network policy below; inspect exact
   candidate release contents and built archives.
7. Produce a local release-readiness record and stop for review. No commit, tag,
   repository creation, push, release or package upload occurs automatically.

## End-to-end validation matrix

| Mode | Proposed cases | Required result |
| --- | --- | --- |
| Offline | text/file/stdin; all IOC types, invalid, overlapping and defanged; Unicode/BOM/CRLF | Correct normalization/provenance and schema 1.2; no credential loading or network |
| Offline --ai | absent evidence, with synthetic credentials present | No model request; schema 1.3 with complete local fallback |
| Enrichment | enabled/missing keys, supported/unsupported IOCs, 200 found/not_found, 401/403/429/5xx, malformed/oversized bodies | Existing-report endpoints only; attributed outcomes and unchanged input evidence; partial failure preserved |
| Privacy | private/reserved IPs, emails, URL credentials/query/fragment, injected provider text | Skip reasons and fragment behavior match contract; no excluded values/context leave the boundary |
| Enrichment + AI | whole CLI pipeline with HTTPX MockTransport for all adapters; valid flat alias response | Model receives only compact allowlisted data; exact model/no tools/no streaming; correct local routing and original evidence preserved |
| AI failures | all diagnostic enum cases, refusal, missing key, budget, timeout, cancellation, retry exhaustion | Strict rejection and complete fallback; safe numeric diagnostics; no model text or exception content in output |
| Invariance | identical frozen evidence and scoring_as_of across AI success/failure/offline selection | Assessments, labels, confidence, relationships and evidence exactly equal |
| Limits | 1,000,000-byte and 10,000-occurrence boundaries, 4,000/1,000 AI token caps, 80 selections/per-section limits, large reports | Explicit rejection/skipped_budget; no truncation; deterministic report complete |
| Export | stdout/stderr, JSON/terminal parity, existing/invalid/unwritable path, cancelled request | No overwritten files; valid JSON on stdout; exit codes 0/2/130 retained |
| Installed package | wheel-installed CLI with cwd outside checkout, no editable source dependence | Help, inert offline input and JSON export work without network |

Keep fake clocks/randomness controlled and compare semantic JSON rather than volatile
wall-clock fields. Test 11 distinct valid aliases routed locally, global duplicates,
mandatory uncertainties, mutated ownership/destination, and two-IOC input-budget
regression. Explicitly reject legacy sectioned model output. Prove exact request
counts, stop/no retry on authentication and validation failure, and bounded retry
only under the approved transport policy. Do not change that policy during polishing.

Network safety: no live provider/AI tests, even behind an optional marker. Keep
socket/HTTP guards, synthetic keys, isolated cwd and fail-fast unexpected requests.
Installed offline subprocess tests need an independent network-denial boundary;
never assume parent monkeypatches carry into them. Use cached local wheels after
setup. Test artifacts must not contain real .env, live reports or account information.

## Fixture policy

Use TEST-NET IPv4, documentation IPv6, reserved example domains and defanged URLs,
fictional example-domain email addresses and hashes of clearly documented harmless
strings. No malware files, executable payloads, copied provider responses, real
people, access tokens or live malicious endpoints. Add a fixture manifest explaining
purpose, expected IOC types, invalid variants, provenance and expected privacy skips.
Defanging alone is not an isolation mechanism.

Reserved inputs intentionally fail public-enrichment eligibility. Exercise successful
provider transport with separately labelled inert synthetic domains/hashes accepted
by the parser and mocked transports, or existing benign public-address constants
inside isolated unit tests; do not relax production eligibility to make fixtures pass.
Public README examples use reserved offline inputs. Synthetic provider evidence
must be labelled fabricated for testing, never a verdict about a real organization.

## CLI and Windows usability

Use .venv312 consistently, preserving the existing .venv. Document PowerShell
commands with explicit executable paths so activation/execution-policy changes are
unnecessary. Cover `py -3.12`, environment creation, dependency installation,
`--help`, one input option, --file for reliable Unicode, PowerShell -Raw/stdin vs
cmd.exe type, new output directories and no-overwrite behavior. Include command
examples with inert inputs and label --enrich/--ai as external opt-ins with quotas.

Check errors for empty/binary/oversized input, unsupported suffix/encoding, missing
file, mutually exclusive inputs, output permissions, missing keys, provider limits,
AI skipped_budget and safe validation reasons. Avoid raw exceptions/provider text.
Clarify that optional-provider failure can exit 0 with a complete deterministic
report; cancellation exits 130. Current output reservation happens after enrichment
but before AI: document this behavior and test it; do not silently promise zero
provider requests for invalid export destinations.

## README and documentation design

Proposed README order: purpose and current MVP; one inert quick start; capabilities
and mode/privacy table; Windows setup; CLI examples; report interpretation and
fallback; configuration; architecture; testing; limitations/responsible use;
provider terms; license and contribution/security links. Remove historical status
contradictions; retain dated validation records in docs rather than the quick start.

Create two or three screenshots from synthetic fixtures only: offline result,
mock-enriched evidence/scoring, and mock AI/fallback. Mark mocked examples plainly;
exclude usernames, local absolute paths, browser account UI and secret values.
Include accessible text equivalents and a small annotated synthetic JSON excerpt.
No fake CI badge or unsupported claim of production readiness. Repo/CI badges and
URLs depend on the owner-selected GitHub repository, which is not yet configured.

Architecture diagram: CLI input → pure extraction/assessment → opt-in TI service
and replaceable HTTP adapters → pure AI projection/catalogue → optional Groq adapter
→ strict local validation/routing → terminal/JSON. Distinguish outbound boundaries,
immutable deterministic results, and future web reuse as out of scope.

## Configuration, secrets and Git hygiene

Keep blank current key names in .env.example; no example-looking token values.
Document cwd-only .env loading, inherited environment precedence (including blanks),
no interpolation, no parent search, and fixed Groq model defaults. CI uses no
repository/provider credentials. Never publish .env, local reports or raw AI output.

Inspect explicit candidate paths and archive manifests before any future staging.
Run git check-ignore and git ls-files --cached --ignored --exclude-standard; zero
sensitive/generated tracked files is required. If files become tracked later,
propose explicit index-only removals preserving local copies. Today the index is
empty. Use no broad git clean or recursive workspace deletion. Narrowly extend
ignore rules only for confirmed generated paths; do not hide test fixtures or
blank templates. Existing .env and report files stay untouched.

Propose pinned Gitleaks CLI in directory mode for the release candidate now, plus
history scanning once history exists. Always redact findings and suppress snippets;
retain only rule IDs, safe repository-relative paths, counts and disposition. Use
an explicit candidate manifest including currently untracked source/docs; a Git-only
scan of this empty repository would miss everything. Keep .env/venvs/live reports
outside that candidate. Small reviewed suppressions may cover synthetic test tokens,
never broad exclusion of all fixtures. Verify scanner behavior with a synthetic
canary and never upload findings. Git ignore is not a secret scan. See
[Gitleaks documentation](https://github.com/gitleaks/gitleaks).

Credentials previously disclosed outside a secret store need owner-managed rotation
before publication/further routine use; do not retrieve, repeat or rotate them here.
No scan can retroactively prove they were never exposed.

## Reproducible packaging and dependency review

Keep setuptools, pip and the existing runtime libraries. Recommend pip-tools to
compile hashed exact runtime, development and build-tool locks from pyproject plus
small tool inputs, separately for Windows/Python 3.12 and Linux/Python 3.12 when
platform markers differ. Keep package dependency ranges for consumers; test releases
against checked-in locks. Pin compiler/build tooling and record Python/platform
versions and lock-update procedure. Do not freeze the whole developer environment.

Install locked dependencies with hash checking; install local editable source or a
built wheel using --no-deps, with separately pinned build tooling and no build
isolation fetching unpinned dependencies. Build wheel and sdist, run metadata checks,
inspect both archives, and install the wheel into a clean separate environment.
Exclude .env, tests' generated outputs, caches and reports from distribution archives.
Test lock regeneration for stable results on its target environment. No PyPI upload.
References: [pip-tools](https://pip-tools.readthedocs.io/en/latest/),
[pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/).

Propose updated description, CLI keywords/classifiers, supported Python statement,
license expression/files and owner-approved source/issues URLs. Keep 0.1.0 unless
the owner chooses otherwise. Confirm package/repository naming before any future
publication; do not claim name availability. Initially claim tested Python 3.12,
not every newer interpreter merely because metadata allows it. Follow
[PyPA metadata guidance](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/).

pip check checks dependency consistency, not vulnerabilities. Propose a separate
pinned pip-audit review of exact runtime/dev/build locks, recording advisory IDs,
installed/fixed versions and reviewed dispositions. No automatic --fix. The normal
audit queries external advisory APIs, so it must not run in planning or automated
tests under the present restriction. An explicitly approved later security review
can retrieve advisories; a fully offline CI audit needs a trusted dated advisory
snapshot and a compatible scanner. Do not pretend pip-audit is offline or mark an
unavailable/stale audit clean. Release readiness requires a completed current audit
or a documented owner-approved exception. See [pip-audit](https://github.com/pypa/pip-audit).

## Proposed GitHub Actions CI (definition only until approved)

Plan .github/workflows/ci.yml for pull_request, push and workflow_dispatch, targeting
Windows and Ubuntu with Python 3.12. Use contents: read, no secrets, no publishing,
no pull_request_target execution of untrusted code, timeouts and concurrency limits.
Pin actions to reviewed full commit SHAs with readable version comments. Pin setup
and install dependencies through reviewed locks; cache pip downloads by OS/Python/
lock hash, never entire environments, .env or reports. See
[GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use).

Each validation job runs Ruff format/check, strict mypy, pytest with branch coverage,
pip check and compileall. Keep the existing 90% combined coverage floor and review
regressions against the 98.11% baseline; do not reduce the gate or mask failures.
Add coverage XML/JUnit only from synthetic tests with short artifact retention;
inspect outputs for path/secret leakage. Test both wheel and source modes without
unintended source imports. Install/setup may require package downloads when later
approved; tests themselves cannot call services. Offline secret scanning is a
separate job; any networked advisory audit is separate and approval-dependent.
No workflow runs, repository setting changes, protection rules or badges are applied
now. Later recommend required validation checks and secret push protection where
available, with the owner selecting settings and branch name.

## License, provider terms and responsible use

Recommend MIT for original TraceGuard code: simple permissive reuse suited to a
portfolio CLI. Apache-2.0 is an alternative if an explicit patent grant is desired.
Owner must select the license and copyright holder before adding LICENSE/metadata;
do not invent a legal name or silently apply a license. See
[license comparison](https://choosealicense.com/licenses/).

Code licensing does not grant rights to provider data or services. Document:

- VirusTotal Public API is restricted to non-commercial/academic use; business
  deployments need appropriate terms/access. Preserve attribution. See
  [VirusTotal API distinction](https://docs.virustotal.com/docs/difference-public-private).
- URLhaus community access is subject to fair use; commercial needs may require
  paid access. See [URLhaus policy](https://urlhaus.abuse.ch/api/).
- AbuseIPDB usage follows its current account/API terms and quotas. No assumption
  of permission to redistribute collected reports. See
  [AbuseIPDB legal terms](https://www.abuseipdb.com/legal).
- Groq service/model access, costs, retention controls and quotas are separate from
  this project's license. Free-tier limits can change; do not promise zero retention.
  See [Groq data policy](https://console.groq.com/docs/your-data) and
  [Groq legal terms](https://console.groq.com/docs/legal).

Responsible-use text: analyze only data you are authorized to handle; extraction
is syntactic and can be ambiguous; risk/confidence are provisional heuristics,
not probabilities; zero/not_found/harmless do not mean safe. Associations do not
prove communication or compromise. AI only selects vetted claims; local reports
still contain sensitive source/evidence even though external projections exclude
it. Protect exported files. No autonomous remediation, scanning or execution.
Document provider outages, stale evidence, biased/non-independent intelligence,
conservative budget skips, incomplete global reputation coverage and mocked-test
limits. A prior successful live smoke test is not an accuracy benchmark.

## Proposed files (not implementation in this phase)

- Consolidate README.md, AGENTS.md, docs/product.md, docs/architecture.md and old
  phase-status sections; add docs/testing.md, docs/release-checklist.md and
  docs/provider-terms.md if needed to keep README concise.
- Add LICENSE after owner decision, SECURITY.md, CONTRIBUTING.md, synthetic
  docs/examples/ and docs/images/ with provenance/alt text.
- Update pyproject.toml, blank .env.example and narrowly scoped .gitignore.
- Add requirements/ lock inputs and generated hashes, workflow definition and
  minimal secret-scan config. Add dev/build/audit tools only with approval.
- Extend tests/integration, tests/cli and fixtures for missing boundaries;
  reuse existing unit tests. Touch src only for a demonstrated defect with a
  regression and an explicit explanation, not to expand capabilities.

## Release acceptance checklist

- [ ] Complete offline, enrichment and AI mode matrix passes under mocked transport.
- [ ] No provider/AI requests or live credentials in any automated test or CI job.
- [ ] All Phase 4 examples/invariants and Phase 5 routing/privacy/fallback tests pass.
- [ ] Tests prove identical deterministic results before/after accepted/rejected AI.
- [ ] Size/count/token limits, privacy skips and all diagnostic codes remain covered.
- [ ] Windows Python 3.12 fresh setup and wheel installation work from outside checkout.
- [ ] Ruff, strict mypy, branch coverage gate, pip check, compilation and CLI checks pass.
- [ ] Hash-locked installs/build tooling reproduce on Windows and Linux targets.
- [ ] Wheel/sdist manifests contain only intended public files.
- [ ] Candidate-tree secret scan passes; every finding is fixed or narrowly reviewed.
- [ ] Dependency vulnerabilities audited with date/tool/source; no unresolved high or
      critical finding without a documented owner-approved exception and mitigation.
- [ ] .env/live reports/caches/venvs remain ignored and untracked; no copied real data.
- [ ] README examples and screenshots are synthetic, labelled and reproducible.
- [ ] Current architecture/mode/schema/model docs agree with implementation.
- [ ] Owner-approved license, copyright holder, repository URLs and security contact.
- [ ] Provider licensing/privacy warnings and limitations are visible.
- [ ] CI definitions reviewed locally; later hosted runs required before claiming CI green.
- [ ] A final local validation record lists commands, versions, results and remaining risks.
- [ ] Owner reviews exact proposed release file list before separate commit/publish approval.

## Decisions and risks for approval

Recommended defaults: MIT (holder pending), pip-tools hashed locks, Windows+Ubuntu
Python 3.12 CI, existing 90% coverage floor, and no automatic publishing. Owner must
supply repository URL/copyright identity/security contact before public-facing
metadata is finalized. Choose whether a later separate advisory-service query is
authorized or an offline advisory snapshot will be provided; no current audit is
claimed. Exact action/tool versions will be verified during approved implementation.

Main risks: stale docs misrepresenting capability; untracked files bypassing Git-only
scans; secrets in screenshots/artifacts; child processes escaping test network mocks;
platform-dependent lockfiles; provider licensing constraints; security audits that
silently skip unavailable data. Each has a corresponding gate above. No implementation
or release action begins until approval of this plan.
