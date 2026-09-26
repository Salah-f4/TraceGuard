# Phase 5: optional evidence-grounded AI reporting

Status: IMPLEMENTED WITH MOCKED VALIDATION, revised 2026-09-25. Groq is the first provider.
Implementation and mocked tests are authorized; no live AI requests or real credential changes.
Phase 4 policy phase4-v1 and all deterministic results remain authoritative.

## Recommended scope and trust boundary

Complete the deterministic schema 1.2 report first. Build an immutable,
allowlisted projection; call one configured AI adapter only with explicit --ai;
validate its response locally; append a separate reporting result. AI cannot
calculate or modify risk, labels, confidence, evidence, relationships, policies,
or scoring timestamps. No AI callback enters scoring or enrichment.

Recommended MVP: AI selects and organizes prevalidated claim IDs; TraceGuard
renders their wording locally from versioned templates and immutable values.
No model-written facts, numbers, URLs, commands, or free-form analyst notes are
accepted. This deliberately trades expressive prose for verifiable grounding.
AI adds selection, emphasis, and ordering, not new hypotheses or intelligence.
This constrained product choice was explicitly approved.

Valid citations alone do not establish that prose is supported. Even structured
outputs can contain mistakes. [Official structured-output guidance](https://developers.openai.com/api/docs/guides/structured-outputs).
A second model or prompt alone cannot guarantee arbitrary prose is correct.
Free-form generation would need a separate future proposal. The constrained
catalogue permits deterministic checks of every accepted claim's preconditions.

No tools, intelligence searches, IOC DNS resolution, URL visits, downloads,
execution, blocking, remediation, persistence, or new intelligence providers.
Transport to the configured AI API is the only new network capability proposed.

## Existing contracts inspected

The actual core/assessment.py schema 1.2 contracts provide:

- IOCassessment: stable ioc_id, score/label/confidence, contributions, coverage,
  tensions, policy version, and scoring time.
- EvidenceReference: evidence_id, provider/IOC/outcome indices, lookup value,
  field_values/pointers, timestamps, and report reference.
- Relationship: kind/source_id/target_id/pointers, but no relationship_id.
  RelationshipGroup has group_id, members and potentially source metadata.

Never serialize these objects wholesale into an AI request: field_values may
include an entire provider outcome and normalized IOC; groups contain filenames,
offsets, and occurrence details. Build a new projection field by field.

Offline-only IOCs have no provider evidence IDs. Non-found outcomes can have
existing contribution reference IDs, but those identify outcome provenance, not
positive threat evidence. Do not invent evidence to satisfy a citation requirement.
Assign local aliases/pointers to existing relationship edges without changing them.

## Provider-neutral contract and architecture

Proposed port: async generate(AIReportRequest, AIRequestLimits) -> AIAdapterResult.
Pure core functions build the projection/catalogue, validate citations, and render
templates. An application service alone handles I/O, configuration and deadlines.

AIReportRequest contains only the validated projection, trusted prompt/schema
versions and catalogue. No full report, source text, credentials, CLI, filesystem,
or tool interfaces. Adapters declare structured-JSON support, token estimation,
output/storage controls, a fixed origin and an explicit model allowlist.

AIAdapterResult contains either bounded untrusted JSON plus validated usage
metadata or a normalized failure enum. Never pass HTTP envelopes, headers, raw
errors, SDK objects, or arbitrary exception strings into reports. No streaming
to the terminal before validation. No conversation state, prompt/response logs,
tracing upload, caching, history, or storage beyond an explicitly exported final
report. Raw drafts and request bodies remain in memory and are discarded.

Use HTTPX and Pydantic; no agent framework required. Proposed first adapter:
Groq Chat Completions API, fixed api.groq.com origin, strict JSON schema
with strict=true, model qwen/qwen3.8-27b, and no tools or streaming. No automatic failover.

The selected AI key exists only in the infrastructure adapter as SecretStr.
Authentication necessarily sends that key to its own provider in a TLS authorization
header; it is never model content, evidence, prompt data, or report data. No
intelligence-provider key is transmitted to the AI service. Credentials are not
part of the core port. No cross-origin redirects or key forwarding.

## Minimum external data and privacy policy

Exclude email IOCs and email-domain links entirely. Exclude invalid, non-public,
privacy-skipped, and uncitable IOCs from AI projection. They remain fully present
in the local deterministic report. No raw-log opt-in is added in Phase 5.

Never send raw logs, original/normalized IOC values, filenames, source labels,
lines, columns, offsets, occurrence times, provider URLs, tags, signatures, ISP,
country, file metadata, comments, raw responses, arbitrary reason strings, local
paths, API keys, or terminal renderings. This also excludes public IP/domain/URL/
hash values: numeric evidence and types suffice for the proposed organization task.
Values can be displayed locally using the original report after validation.

Send request-local aliases I001/E001/R001/C001 instead of existing IOC/evidence/
group IDs. Existing IDs are unsalted data-derived hashes and may permit guessing
or linkage; do not send them or a hash of the full original report. Retain an
in-memory alias-to-existing-ID/pointer map. Final AI claims cite full EXISTING
ioc_id and evidence_id values after local resolution. Aliases are not new evidence.
A random request nonce binds the response to this map. Aliasing reduces disclosure;
numeric patterns and provider account metadata are not guaranteed anonymous.

Allow only:

| Projection | Allowlisted data |
| --- | --- |
| IOC | Alias/type, immutable score/label/confidence, policy version, fixed flags |
| Evidence | Alias/provider/status, linked IOC aliases, rule ID, numeric scoring fields, base/weighted contributions, coarse age/freshness, role, fixed tensions |
| Relationship | Alias/kind and eligible endpoint aliases, existing provenance bindings; no source/line labels |
| Catalogue | Fixed template keys/categories, required citations, applicable sections, preconditions and priority tiers |

VT: present malicious/suspicious/harmless counts; missing never becomes zero.
AbuseIPDB: abuseConfidenceScore and totalReports only. URLhaus: url_count when
present, match scope derived from validated IOC type, and mapped enum online/
offline/other_or_missing. No unrecognized status string passes through. Age buckets
come from recorded assessment fields, not model calculations. Optional metadata
such as numDistinctUsers is unnecessary and omitted.

Projection errors yield privacy_blocked fallback. Secret/PII scans supplement the
allowlist; regex redaction alone is insufficient. Load only AI configuration for
--ai; load intelligence keys only if --enrich also requests them. Future AI config
uses the existing ignored local .env/inherited-variable precedence, with no writes.
Do not inspect, change or copy real credentials during planning or tests.

## Structured input: ai-input-v1

All objects forbid additional properties, use strict types, finite numbers,
bounded arrays, fixed enums, and explicit nullable fields. Identifiers must match
locally generated alias/nonce patterns; no arbitrary provider-derived strings.

| Object | Fields |
| --- | --- |
| AIReportRequest | input_version, request_nonce, prompt_version, catalogue_version, policy_version, iocs[], evidence[], relations[], admissible_claims[] |
| IOCView | ioc_alias, type (no email), risk_score 0-100, label, evidence_confidence 0-95, evidence_aliases[], flags[] |
| EvidenceView | evidence_alias, provider, status, linked_ioc_aliases[], rule_id, numeric_fields (strict provider-specific union), freshness_percent, age_bucket, base_score, weighted_score, role |
| RelationView | relation_alias, kind, member_ioc_aliases[], evidence_aliases[] |
| ClaimSpec | claim_alias, kind, template_key, allowed_sections[], ioc_aliases[], evidence_aliases[], relation_aliases[], mandatory, action_priority (nullable enum) |

Every candidate claim must map to at least one existing IOC AND evidence ID.
Every referenced IOC in a multi-IOC claim needs linked evidence provenance.
Relationship claims also need an existing relation with correct endpoints. A node
without evidence cannot be included merely because it shares a line with another.
Never infer ownership, resolution, campaigns, compromise, or causation from groups.

## Admissible claims and semantic preconditions

The catalogue builder evaluates these against the frozen original report before
sending them. All wording comes from reviewed local templates, not the model.

| Template | Kind | Preconditions and limits |
| --- | --- | --- |
| assessment_snapshot | fact | Existing assessment and linked outcome ID; copy all values exactly |
| provider_adverse | fact | Selected positive contribution and its provider fields; attribute to provider, no compromise claim |
| no_adverse_or_no_match | uncertainty | Existing zero-adverse/not_found outcome; always state safety remains unknown |
| partial_coverage | uncertainty | Existing failure/disabled/skip outcome; fixed status only, no numeric penalty |
| stale_or_ambiguous | uncertainty | Recorded freshness/flags; preserve URLhaus timestamp limitation |
| conflicting_evidence | uncertainty | Existing tension and every relevant evidence ID; retain both sides |
| corroboration | interpretation | Recorded K/bonus/references; distinct providers, not proven upstream independence |
| recorded_relationship | fact | Existing edge/group with citable eligible endpoints; association only |
| review_existing_telemetry | recommended_step | Referenced adverse evidence or explicit evidence gap; manual review if accessible, never assert telemetry exists |
| reconcile_existing_evidence | recommended_step | Existing tension/freshness limitation; review collected reports, no new search |
| capture_local_context | recommended_step | Unknown/incomplete assessment; document locally, do not upload logs |
| reputation_limit | uncertainty | Existing assessment/evidence; reputation does not establish environmental compromise, mandatory for all projected IOCs |
| analyst_caution | interpretation | Referenced assessment/evidence; heuristic, not probability or proof of compromise |

No commands, visits, scanning, execution, remediation, or search actions enter
the catalogue. Suggestions never execute. Priority is local presentation metadata:
high for malicious, medium for suspicious, routine for low/unknown. AI may order
within tiers but cannot change them. The renderer preserves tier order. This is
not a new risk score. Generic cautions are bound to the IOC/evidence they qualify.

## Structured output and local report envelope

Model output ai-output-v1 has exactly:

- output_version literal and request_nonce equal to the submitted nonce.
- Six required arrays: executive_summary, ioc_findings, correlations, uncertainties,
  prioritized_investigation_steps, analyst_notes.
- Items: ClaimSelection {claim_alias, kind, ioc_aliases[], evidence_aliases[],
  relation_aliases[]}. Citation sets, kind and section must match the catalogue.

No free text, titles, new numbers, URLs, markdown, edits, commands, arbitrary
citations, extra sections, or model-authored priority ranks. Empty arrays are
allowed only when applicable content is absent; local section notes are not AI
claims. At least one valid selection is necessary for completed status.

Require exactly one assessment snapshot per projected IOC in findings. Applicable
uncertainties are mandatory: gaps, freshness, conflicts and no-safety caveats may
not be omitted. Mandatory analyst cautions belong in analyst_notes. No duplicate
claims within a section; a catalogue-approved fact can appear in summary and
findings. No markdown-fence stripping, type coercion or JSON repair.

Proposed schema change: no --ai retains schema 1.2 unchanged. With --ai use 1.3,
preserving all deterministic fields/values and adding ai_reporting. Local metadata:
requested, status, origin (ai_assisted/deterministic_fallback), safe provider/model,
prompt/projection/catalogue versions, start/end UTC, attempts, validated token
usage, and local projected/omitted IOC IDs and fixed reason codes. No request
body, alias map, raw draft, chain of thought, secrets or provider request IDs.

The root envelope schema_version changing from 1.2 to 1.3 is the sole permitted
change to an existing top-level value; all other deterministic fields must compare
equal. Mutation tests explicitly exclude that declared version change and the
new ai_reporting field, not any score, evidence, relationship, or timestamp.

RenderedClaim contains claim_id, kind, locally generated text, full ioc_ids[],
evidence_ids[], relation_refs[], template_key, and local action_priority. The model
cannot set metadata or provenance. Rendering references local immutable values;
it never accepts model-supplied replacements for deterministic data.

Fallback sections are clearly origin=deterministic_fallback. For offline IOCs
without provider IDs, local fallback uses assessment/relationship pointers with
empty evidence_ids. These are NOT AI claims. Never fabricate evidence to satisfy
the AI citation requirement. Full original evidence always remains in the report.

## Citation validation and injection defenses

1. Bound bytes/depth before parsing. Reject malformed/fenced/trailing JSON,
   duplicate keys, NaN/Infinity, truncation, refusals and tool/function-call output.
2. Apply strict local Pydantic schema; native provider schemas are supplementary.
3. Bind to nonce/version. Every alias must exist in this request, not another run.
4. Resolve claim and require exact kind, section and IOC/evidence/relation sets.
   Check ownership, fragment-equivalent provenance and relationship membership.
5. Re-evaluate catalogue preconditions and mandatory coverage locally. Existing
   citations attached to irrelevant assertions are invalid.
6. Render only trusted versioned templates; resolve to actual existing IDs and
   copy numbers locally. Escape Rich/ANSI/HTML/Markdown appropriately.
7. Assert original deterministic fields are unchanged. Any violation rejects the
   WHOLE AI response, yielding fallback. Do not salvage unvalidated text or ask a
   second model to repair it. Raw rejected output is never displayed or saved.

Fixed application-owned system instructions state that input is untrusted data,
not instructions. Supply projection as a separate JSON data message. Never splice
provider/input text into system roles, prompts, schemas or templates. URLs, tags
and prose are removed rather than trusted after superficial escaping. Allowlisted
numeric/enum values are revalidated. No tools, browsing, MCP, file access, history,
remote prompts, dynamic endpoints or external citation fetching.

Use fixed TLS-verified origins, redirects off, implicit proxy/netrc and HTTP/SDK
body logging off. No telemetry uploads or automatic SDK retries. Never execute
model output. No secondary AI validator, embeddings, search or recursive enrichment.

An injected sentence with legitimate citations still fails because prose is
forbidden. Selecting an inapplicable template fails its predicate. This protects
the finite claim catalogue, not arbitrary natural-language entailment. Template
defects and misleading ordering remain risks: review templates and enforce coverage.

## CLI, fallback, failure and retries

Proposed examples only; not commands executed during planning:

```text
traceguard analyze --file sample.log --ai
traceguard analyze --text "1.1.1.1" --enrich --ai --format json --output report.json
```

--ai and --enrich are independent. Without --ai, never load AI keys or create
AI clients. --ai alone has no provider evidence in the current CLI: return
skipped_no_citable_evidence, zero model calls, and local six-section fallback.
--enrich --ai uses only the explicitly requested existing enrichment snapshot;
AI cannot request more intelligence. No import-report or include-raw-log CLI now.

Proposed configuration names only: TRACEGUARD_AI_PROVIDER, TRACEGUARD_AI_MODEL,
TRACEGUARD_GROQ_API_KEY. Require explicit allowlisted provider/model, no automatic
default or model-discovery call. Missing/blank keys disable AI. AI-only config
errors must not break deterministic analysis. No .env edits during planning.

Preflight order: finish deterministic analysis, check output destination, determine
citable/privacy-eligible projection, check sizes, then validate AI configuration,
credentials and budget. No citable evidence takes precedence over a missing AI key
and can return without loading AI credentials. This makes combined-failure statuses
predictable and avoids unnecessary secret access.

Statuses: completed, disabled_missing_key, invalid_configuration,
skipped_no_citable_evidence, privacy_blocked, skipped_budget, auth_error,
rate_limited, timeout, network_error, provider_error, refused, invalid_output,
response_too_large, cancelled. All non-completed outcomes retain the full report
and deterministic six-section fallback. Emit only a sanitized stderr warning.
AI failure alone retains exit 0; CLI/input/export errors remain exit 2, cancellation
exit 130 with completed deterministic output preserved where possible.

Fallback uses the same trusted catalogue, fixed category order and existing risk
descending/IOC-ID tie breaking. Include ALL local IOCs, including AI-excluded ones;
mark model coverage honestly. Offline unsupported claims use local pointers,
never invented provider citations. Never imply fallback was AI-generated.
Validate output destination before billed calls; preserve no-overwrite behavior.
Terminal/JSON contain identical validated claims, full citations and original
deterministic breakdown. No response appears before validation succeeds.

Defaults: one provider, one logical request, at most TWO HTTP attempts; overall
45s deadline, per attempt 20s, connect/pool 3s, write 5s, read 15s, bounded by remaining
time. Retry once only for explicit 429/502/503/504. Honor Retry-After only if <=10s
and the next attempt fits; otherwise return status. Without header wait 1s plus
injectable jitter <=250ms. No retry for auth, permissions, invalid request/model,
TLS error, refusal, malformed/truncated output, or ambiguous timeout/network failure
after dispatch. No repair loop or provider/model failover; SDK retries disabled.
A retry may still be billed, so reserve both attempts; do not promise exactly-once
provider execution. Cancellation stops future attempts.

Limits: full eligible projection <=20 IOCs, 80 evidence entries, 40 relationships,
120 catalogue claims, 64KiB serialized input, 4,000 total input tokens including
prompt/schema. Output <=1,000 tokens, 64KiB decoded body, depth 8, 80 selections
total. Section caps: summary 6, findings 20, correlations 20, uncertainties 40, steps 20,
notes 20, also subject to total cap. If mandatory content cannot fit, skip AI.
No silent truncation, top-N selection, automatic batching or extra requests;
oversized cases receive skipped_budget and complete local fallback.

Recommend $0.05/run configured ceiling, using a reviewed local price table and
token bounds reserving both attempts. An adapter must have a conservative local
token estimator; missing price/estimate means skipped_budget, not a false bound.
No runtime pricing lookup. Validate returned usage only for reporting; billing
may differ, so account spend controls remain useful. Never truncate deterministic
reports to meet AI limits. Model changes require reviewed pricing/configuration.

## Model/provider choices: cost and privacy

Official documentation checked 2026-09-25. Standard text USD per million input/
output tokens; examples use 4,000 input and 1,000 billed output tokens. Excludes
taxes, retries, tools, caching, and extra reasoning usage. No benchmarking or
model requests were performed. Verify lifecycle, account access and terms before use.

| Option | Input/output | Example cost | Trade-off |
| --- | ---: | ---: | --- |
| OpenAI gpt-4.1-mini-2025-04-14 | $0.40/$1.60 | $0.0032 | Recommended initial adapter for bounded selection: structured output, pinned snapshot, no reasoning step; not claimed newest/best |
| Anthropic claude-haiku-4-5-20251001 | $1/$5 | $0.0090 | Alternative with higher listed cost here; same validation required, lifecycle needs review |
| Paid Gemini 3.1 Flash-Lite | $0.25/$1.50 | $0.0025 | Lower listed example cost; billed thinking can change totals; paid data-use setting matters |
| Operator-managed local instruct model | Hardware-dependent | Not estimated | Can avoid external transfer with controlled egress/logging; hardware, licensing, quality and schema reliability need evaluation |

OpenAI rates, snapshot and capabilities: [GPT-4.1 mini](https://developers.openai.com/api/docs/models/gpt-4.1-mini).
API data is not used for training by default without opt-in. Default abuse
monitoring may retain content up to 30 days with documented exceptions; ZDR needs
approval/eligibility. store=false avoids Responses application-state storage,
not all possible retention. [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data).

Anthropic rates/ID: [Claude models](https://platform.claude.com/docs/en/models/overview).
Anthropic documents no training on retained data without express permission and
feature/model-specific retention and ZDR arrangements. Verify the exact account,
feature and model; no-training does not mean no-retention.
[Claude retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention).

Google lists the stated standard rates and free-tier product-improvement use
versus paid-tier non-use. Paid API remains third-party processing, not a blanket
zero-retention guarantee. No search/maps grounding enabled.
[Gemini pricing/data-use table](https://ai.google.dev/gemini-api/docs/pricing).

Recommendation: implement the port, fallback and ONE explicitly selected Groq
adapter after approval. Keep other options as alternatives, not concurrent calls
or auto-fallbacks. Evaluate every model with the same synthetic citation/selection
cases. Mock tests validate contracts, not actual model quality; any later live
synthetic evaluation needs separate authorization.

## Example reports

I1/E1 notation here abbreviates existing IDs for readability. Actual local output
resolves every model-selected claim to the full existing IDs. Fixed section headers
and status notices are local presentation, not uncited AI claims.

### A. Recent two-provider adverse evidence

I1: existing IP; E1: VT M=6; E2: AbuseIPDB A=80,totalReports=20. Existing Phase 4
assessment is 70/malicious/confidence 80. No AI calculation:

- Executive summary — [Fact; I1; E1,E2] TraceGuard records 70/malicious and
  evidence confidence 80 under phase4-v1; these are provisional heuristics.
- IOC findings — [Fact; I1; E1] VT reports six malicious votes.
  [Fact; I1; E2] AbuseIPDB reports confidence score 80 and 20 reports.
- Correlations — [Interpretation; I1; E1,E2] Recorded corroboration uses two
  distinct providers; upstream independence is unverified.
- Uncertainties — [Uncertainty; I1; E1,E2] Reputation evidence does not prove
  compromise in this environment.
- Prioritized steps — [Recommended step; high; I1; E1,E2] Manually review
  existing internal telemetry for this IOC if available. No action was run.
- Analyst notes — [Interpretation; I1; E1,E2] Review preserved evidence and
  the deterministic breakdown before drawing an incident conclusion.

### B. No matches / zero adverse evidence

I2: score 0/unknown; E3: URLhaus not_found; E4: VT M=0,S=0.

- Summary/findings — [Fact; I2; E3,E4] TraceGuard records 0/unknown; safety is unknown.
- Correlations — local section note: no applicable existing correlation selected.
- Uncertainties — [Uncertainty; I2; E3] No URLhaus match was returned.
  [Uncertainty; I2; E4] Zero adverse votes do not establish benignness.
- Steps — [Recommended step; routine; I2; E3,E4] Document context locally and
  review existing internal telemetry if available.
- Notes — [Interpretation; I2; E3,E4] Do not close an investigation solely on zero risk.

### C. Conflict and input co-occurrence

I3: VT-positive E5 and AbuseIPDB-zero E6, recorded 80/malicious/confidence 70.
I4: zero-adverse E7. Existing R1 links them by input co-occurrence.

- [Fact; I3; E5,E6] The recorded score is 80 and confidence 70.
- [Uncertainty; I3; E5,E6] Providers show contrasting evidence; both remain visible.
- [Fact; I3,I4; E5,E6,E7; R1] These IOCs co-occur in the input; that is not proof
  of communication, compromise, or a shared campaign.
- [Recommended step; high; I3; E5,E6] Review the already-collected conflicting evidence.

### D. Offline-only / missing key / invalid output

Status skipped_no_citable_evidence, disabled_missing_key or invalid_output;
origin=deterministic_fallback. Produce six local sections, preserve every IOC.
Offline findings state 0/unknown/no provider evidence, cite assessment pointers,
and have empty evidence IDs. Explicitly state AI did not produce a validated
report. No new searches or fabricated citations fill the gaps.

Reject E999, E1 attached to unrelated I2, stale nonce, new relationship, changed
priority or missing required conflict. Reject free prose claiming safety,
compromise, score changes, visits or execution even with valid IDs. Discard raw
invalid output and render deterministic fallback only.

## Acceptance criteria and mocked tests after approval

1. No --ai preserves schema 1.2 and never reads AI keys/clients. Test all --ai/
   --enrich combinations; --ai cannot enable intelligence queries.
2. Deep-compare every deterministic field before/after success, failure,
   cancellation and adversarial responses; no mutation anywhere.
3. Assert exact MockTransport bodies contain only allowed fields. Nested, encoded,
   Unicode, multiline, URL, email, source and metadata secret/PII canaries never
   reach requests, reports, errors or logs. Real .env/report files are not fixtures.
4. Synthetic AI key only in its provider auth header; no intelligence keys sent.
   Fixed endpoints/TLS/no redirects/tools/state/tracing/implicit retries asserted.
5. Golden examples A-D cover six sections and categories; every AI claim resolves
   existing IDs/ownership, copies deterministic values and describes existing links.
6. Reject irrelevant but valid citations, unknown/cross-run aliases, fragment
   misuse, altered categories/sections/priorities, missing mandatory cautions,
   duplicate selections and failed semantic preconditions.
7. Reject malformed/fenced/trailing JSON, duplicate keys, coercion, nonfinite
   numbers, excess depth/bytes/items, refusal, tool calls and truncation. No partial
   rendering, repair loop or free-form command execution.
8. Injection fixtures in provider text/URLs/tags/source content never enter
   trusted prompts. Score overrides, new facts and action attempts fail locally.
9. Unknown/not_found/zero/harmless never yields safe/clean. Provider failures do
   not change deterministic risk/confidence. Suggestions never imply completion.
10. Mixed privacy eligibility preserves every local node and reports omissions;
    offline evidence gaps never receive invented citations or model calls.
11. Test every size/token/cost boundary, absent estimates and unfit mandatory
    content, including 10,000 IOCs. Explicit fallback; no truncation/chunking.
12. Fake clocks cover deadlines, bounded one-time status retry/Retry-After,
    cancellation, auth no-retry and ambiguous failure no-retry. Block network.
13. Terminal/JSON/export parity, full citations and fallback origin; existing/
    unwritable destination avoids unnecessary AI calls; exit 0/2/130 preserved.
14. Stable projection/catalogue/fallback across hash seeds except nonce/aliases;
    correct alias resolution; accepted AI choices may vary but cannot escape
    the admissible catalogue. Mock tests cannot establish live model quality.
15. After implementation approval run full .venv312 pytest branch coverage, Ruff,
    strict mypy, dependency checks, compilation and CLI regression suite. Planning
    itself changes documents only, with no new test/code implementation or calls.

## Implementation status

The constrained design and Groq revision below are approved and implemented.
The original provider comparison is historical context; Groq is the only implemented
adapter. See [validation and limitations](phase5-validation.md). No live AI requests
or subsequent phase is authorized.

## Approved Groq revision (supersedes OpenAI-first recommendations above)

The first implementation is Groq, model qwen/qwen3.8-27b, using only
TRACEGUARD_GROQ_API_KEY for authentication. Provider/model are pinned in the
adapter; optional TRACEGUARD_AI_PROVIDER/MODEL settings must match groq and the
approved model if supplied. No OpenAI adapter or credential is loaded. Keep the
core adapter port provider-neutral for later separately approved implementations.

POST https://api.groq.com/openai/v1/chat/completions with strict JSON Schema
response_format.json_schema.strict=true, stream=false, no tools, and a maximum
of 1,000 completion tokens. Limit input including instructions/schema to 4,000
tokens. Disable reasoning for this selection-only workload using the documented
reasoning_effort=none setting. One logical request/report, at most one retry for
explicit transient HTTP 429/502/503/504, preserving other approved deadline and
privacy controls. No browsing, code execution, model discovery or external actions.

Record provider, exact model ID and validated prompt/completion/total token usage
locally, including usage on discarded responses where safely available. Every AI
failure, missing key or budget failure preserves the full deterministic fallback.
All testing uses mocks; no live AI calls or Phase 6 work is authorized.

Free-tier limits can change and are account/model-dependent. Handle rate limits
without assuming fixed free capacity. Documentation confirms model support for
strict structured outputs; schema compliance does not guarantee semantic accuracy.
[Groq structured outputs](https://console.groq.com/docs/structured-outputs),
[model](https://console.groq.com/docs/model/qwen/qwen3.8-27b),
[reasoning](https://console.groq.com/docs/reasoning),
[rate limits](https://console.groq.com/docs/rate-limits).


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
