# Phase 5 implementation validation

Validated on Python 3.12.10 in `.venv312`, 2026-09-26.

- pytest: **523 passed**, with branch coverage enabled; combined coverage **97.47%**.
- Ruff lint and format check: passed, 56 files formatted.
- Strict mypy: passed, 56 source/test files.
- pip check: no broken requirements.
- compileall on src/tests: passed.
- Installed CLI root/analyze help: passed; CLI opt-in/export/cancellation tests passed.
- `.env` and `live-smoke-report.json`: Git-ignored and untracked.
- Existing `.venv` and credentials were not modified. No live AI or intelligence
  requests were made. Tests remove inherited credentials, change into temporary
  directories, and block real HTTP/DNS connections.

## Files added or updated for Phase 5

Application:

- src/traceguard/core/ai_contracts.py
- src/traceguard/core/ai_reporting.py
- src/traceguard/ai_config.py
- src/traceguard/ai_service.py
- src/traceguard/adapters/ai/__init__.py
- src/traceguard/adapters/ai/groq.py
- src/traceguard/adapters/cli/app.py
- src/traceguard/adapters/cli/reporting.py

Tests:

- tests/conftest.py
- tests/ai_support.py
- tests/unit/test_ai_reporting.py
- tests/unit/test_groq.py
- tests/unit/test_ai_cli.py

Documentation:

- AGENTS.md
- README.md
- docs/product.md
- docs/architecture.md
- docs/phase5-plan.md
- docs/phase5-validation.md

No dependencies were added. The repository already contains untracked project
files, so this list describes this phase's work, not a clean committed Git diff.

## Behavior and limitations

Groq qwen/qwen3.8-27b uses strict structured outputs, disabled reasoning, no tools,
no streaming and a fixed HTTPS origin. The adapter interface remains provider-neutral.
4000 input / 1000 completion token limits and a two-attempt cost reservation apply.
Only HTTP 429/502/503/504 can retry once; authentication, malformed output and
ambiguous transport failures never trigger repair/retry loops.

The external payload contains request-local aliases, bounded numbers/enums and
claim choices, never actual IOC values, source context or provider prose. The key
is used only in the authentication header. Deterministic local reports retain
original evidence and source data; save them in an appropriately protected location.
This implementation does not assert a provider-side zero-retention guarantee.

Every accepted model selection resolves to locally prevalidated templates and
existing IOC/evidence IDs. Invalid output is discarded in full. Unknown, zero and
not-found never mean safe. All deterministic fields remain unchanged. For example,
a synthetic VirusTotal six-adverse-vote fixture retains risk **65**, regardless of
AI success, refusal, timeout or other reporting failure. Its report displays the
recorded risk and limitations using local templates, not model-written numbers.

The model only selects and orders claims; it cannot generate novel prose or new
investigation hypotheses. It may duplicate a claim across appropriate sections.
Relations without citable eligible evidence stay local. Offline-only --ai returns
a complete local fallback without making an AI call.

Input accounting uses a conservative UTF-8 byte upper estimate plus framing reserve,
including the schema; it can reject reports that would fit a model tokenizer.
Multi-provider/larger reports often fall back. No input is silently truncated.
Completion fit is bounded by the provider token cap and checked on return; truncated
or incomplete mandatory content falls back, rather than being repaired. Token usage
is unknown when no usable usage metadata arrives. Pricing assumptions and free-tier
limits may change. Exact model compatibility, response quality, and service behavior
remain unverified by live tests. Phase 6 was not started.


## Compact AI projection revision

The approved 4,000-input / 1,000-output limits remain unchanged. The wire protocol
now sends short I1/E1/R1/C1 aliases and compact positional facts, a deduplicated
vetted template dictionary, and claim rows. Provider aliases V/A/U represent
VirusTotal/AbuseIPDB/URLhaus. Uncertainty/conflict flags reference the template
dictionary. Freshness uses current/reduced/unweighted categories, without dates.

The strict model response contains only six ordered arrays of C aliases. It cannot
supply citations, categories, prose or risk values. The request-local ownership
map stays in memory; validation rebuilds the projection from the deterministic
snapshot and resolves selected aliases to original IOC/evidence/relationship IDs.
Unknown/duplicate aliases, wrong sections, missing mandatory claims and tampered
ownership fail closed. Local templates render all text. No cross-request cache is
used. Schema 1.3 remains the local report format, never the external payload.

Local ai_reporting.token_estimates contains integer byte-based conservative token
bounds for system_prompt, schema, projection, catalogue, framing_and_escaping,
input_total and output_reserve. Components sum to input_total; output reserve is
separate. Diagnostics include no IOC values or payload text. This is an upper
estimate, not measured tokenizer usage. Provider-reported usage stays separate.

Offline re-projection of the saved two-IOC smoke report estimates 3,857 input tokens
(previously 8,714): prompt 586, schema 726, facts 704, catalogue 965, framing/escaping
876. Output reserve remains 1,000. A synthetic two-IOC regression requires <4,000.
Larger reports still skip without truncating evidence or fallback. A 20-IOC
regression verifies zero requests and unchanged deterministic findings.
No live requests were made for this revision; Phase 6 remains out of scope.

Compact revision validation (Python 3.12.10): **526 tests passed**, **98.08%**
combined statement/branch coverage. Ruff lint/format, strict mypy (58 files), pip
check, compilation and CLI help passed. Added core/ai_wire.py and
unit/test_ai_wire.py; updated AI contracts/projection, Groq transport budgeting,
AI service diagnostics, synthetic fixtures and rejection tests. Existing saved live
report was read locally for numeric diagnostics only and was not changed.


## Safe validation diagnostics

AI reports now include nullable invalid_output_reason and validation_counts with
returned_claim_count, unknown_alias_count and duplicate_count. Codes distinguish
provider_refusal, missing_structured_response, json_schema_validation_failure,
unknown_claim_alias, duplicate_claim_alias, invalid_section_assignment,
citation_ownership_validation_failure, missing_mandatory_uncertainty,
ordering_count_limit_violation and other_validation_failure. Counts default to
zero when structured claims could not be parsed. Duplicate counts are per section;
valid reuse across different allowed sections is unchanged. No aliases, raw model
output, exception text, IOC values or payload contents are recorded in diagnostics.
Provider refusals retain status refused; the reason field supplies the category.
Existing strict validation and deterministic fallback are unchanged.

Validation on Python 3.12: 538 tests passed, 98.03% branch-inclusive coverage.
All ten categories have mocked tests; transport is mocked and no live requests
were made. Ruff, strict mypy (59 files), dependency checks, compilation and CLI
checks passed. Phase 6 remains out of scope.

Previous smoke-test diagnostic loss: run_ai called validate_output inside a broad
except Exception block that assigned status invalid_output without retaining a
reason. GroqAdapter.generate also returned invalid_output for envelope/content
checks and its broad exception handler. The prior report recorded token usage,
so failures before usage parsing are excluded; later adapter checks or the local
validator catch remain possible. The discarded response and missing stage/reason
metadata make the exact historical failed rule unrecoverable. No guessed diagnosis
or reconstruction is presented as fact; the new reason codes distinguish future
failures without retaining model content.


## Flat AI selection and local section routing

The strict response is now exactly {"claims": ["C1", "C2", ...]}: one flat ordered
list. Additional fields, including section names, fail schema validation. Prompt
and compact wire metadata expose no destination section names or indices. Each
local frozen ClaimSpec and catalogue candidate has one immutable destination.
Where a template belongs in multiple sections, separate vetted aliases represent
each destination. TraceGuard routes aliases locally, preserving within-section
model order except the existing deterministic investigation-priority sort.

The catalogue explicitly marks mandatory claims and required section coverage.
Validation rebuilds ownership/routing against the unchanged snapshot, rejects
unknown aliases and global duplicates, enforces all mandatory uncertainties and
other mandatory claims, and applies the existing total 80 and per-section caps.
Failures retain the complete deterministic fallback. Counts on successful output
now record selected claims before any local privacy-excluded supplements.
No model output is logged or persisted. Prompt/projection versions are v3;
local report schema stays 1.3. Model and token limits are unchanged.

A mocked 11-distinct-valid-alias case demonstrates rejection of the old wrongly
sectioned shape and successful routing of the flat list, including full mocked
service completion and unchanged deterministic findings. This is a synthetic
reproduction of the failure class, not a replay of the discarded live response.
A separate test checks frozen destinations and rejects tampered ownership/routing.
The two-IOC budget regression and large-investigation fallback regression remain.
No live requests were made; Phase 6 remains out of scope.

Local-routing validation: Python 3.12, **540 tests passed**, **98.11%** combined
statement/branch coverage. Ruff lint/format, strict mypy (60 files), pip check,
compilation and installed CLI help passed. Updated contracts, catalogue/validator,
wire projection, prompt, service counts and fixtures; added test_ai_routing.py.
