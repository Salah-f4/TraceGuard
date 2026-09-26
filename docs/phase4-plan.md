# Phase 4 proposal: deterministic scoring and local relationships

Status: APPROVED AND IMPLEMENTED, 2026-09-25. Policy version phase4-v1.
This is the approved Phase 4 contract. Numerical weights remain provisional heuristics.
No AI scoring, persistence, new providers, DNS resolution, URL visits, downloads,
or new enrichment requests are part of Phase 4. All examples below are policy
calculations, not security verdicts or live lookups. Weights are initial analyst
heuristics, not calibrated probabilities of compromise.

## Evidence inspected

Inspected the actual parsers in src/traceguard/adapters/intelligence/{virustotal,
abuseipdb,urlhaus}.py, core/intelligence.py, core/models.py, and the existing local
live-smoke-report.json. No credential values or raw response bodies were copied.

All outcomes retain provider_id, ioc_index, status, reason, attempted/attempts,
HTTP status, retrieval/completion timestamps, fragment_stripped, and reused.
Evidence retains attributes, observed_at, observed_at_original, and reference.
Scoring accepts only identity-validated status=found outcomes with evidence.
HTTP 200 alone is not evidence of a match or safety.

| Provider | Actual retained attributes | Timestamp semantics and limitations |
| --- | --- | --- |
| VirusTotal | last_analysis_stats (malicious, suspicious, harmless, undetected, timeout, confirmed-timeout, failure, type-unsupported when supplied), report_id | observed_at comes from last_analysis_date; counts lack individual vendor identities or report lineage |
| AbuseIPDB | abuseConfidenceScore, totalReports, optional numDistinctUsers, countryCode, usageType, isp; maxAgeInDays=90 | observed_at comes from lastReportedAt; last report time is not a timestamp for every report in the window |
| URLhaus | optional url_status, threat, signature, file_type, file_size, url_count, tags | observed_at selects lastseen, then date_added, then firstseen; source field name is NOT retained; attributes may be empty even for a valid exact match |

URLhaus validates returned url/host/md5_hash/sha256_hash against the normalized
lookup, but does not retain those identity fields in attributes. Its found status
plus linked IOC type and normalized lookup are the match evidence. Host listings
must not be interpreted as exact malicious URL or file matches. Provider reference
links are attribution only, never fetched.

The saved smoke report contains VT IP counts 0 malicious / 0 suspicious / 56
harmless / 33 undetected and URL counts 0 / 0 / 60 / 30 respectively. AbuseIPDB
has abuseConfidenceScore=0, totalReports=58, numDistinctUsers=27 for the IP.
URLhaus has not_found for both. Under this proposal both IOCs are 0/unknown,
with zero confidence in a positive risk finding. Successful coverage is reported
separately. Report counts, harmless votes, and not_found do not prove safety.

No DNS answers, resolved IP lists, downloaded payload identities, per-vendor
verdicts, URLhaus URL arrays, or provider relationship graphs are retained.
Do not invent relationships requiring those fields.

## Risk score and labels

For each valid IOC produce integer risk_score in [0,100], evidence_confidence
in [0,100], label, policy_version, and scoring_as_of (explicit UTC input).
Invalid and unenriched IOCs also receive 0/unknown, with an explicit reason.
Zero means no weighted adverse evidence available, NEVER clean or safe.

1. Select at most one outcome per provider and canonical lookup identity. Reused
   or fragment-equivalent evidence is one source, not additional votes. For imported
   duplicate outcomes use latest fetched_at, then stable evidence ID as tie breaker;
   malformed/missing identity mappings are excluded with a diagnostic.
2. Determine each provider base score B from the tables. Record all relevant
   field pointers, including zero-point and excluded evidence.
3. Apply freshness factor F: contribution P = floor(B * F).
4. Let K be the number of distinct providers with P >= 20 and F >= 0.75.
   Correlation bonus C = min(10, 5 * max(0, K - 1)). Each bonus references all
   qualifying provider evidence IDs. VT is ONE provider regardless of engine count.
5. Final risk = min(100, max(P, default=0) + C). Providers below the maximum
   remain in the breakdown as corroborating or non-additive evidence. Never sum
   all provider base scores. Show the maximum selection, bonus, and cap explicitly.

Request failures, missing keys, not_found, skipped types, and absent providers
have no numerical score contribution and no penalty. Replacing any non-evidence
outcome with another must leave risk unchanged. Removing previously available
positive evidence is a different input and can change the score; do not describe
that as a failure penalty.

| Label | Rule | Intended reading |
| --- | --- | --- |
| unknown | score=0 | No weighted adverse evidence; safety unknown |
| low | 1-29 | Weak or old adverse evidence merits context checking |
| suspicious | 30-69 | Material adverse evidence requiring investigation |
| malicious | 70-100 | Strong adverse reputation evidence under this policy |

The malicious label is a reputation assessment, not proof of compromise in the
user's environment. The 70 threshold allows one fresh, strong exact match or a
strong multi-vendor report; weak host association alone cannot reach it. There is
no clean label and no negative score contribution. Confidence never changes labels.

## Provider-specific base score tables

### VirusTotal

Let M=last_analysis_stats.malicious and S=last_analysis_stats.suspicious. Missing
M or S is unknown, not an explicit zero. A present positive M can select a malicious
band without S; S can select the suspicious band when no positive M is supplied.
Missing fields are reported. Select one highest matching band, never add bands.

| Evidence | Base B | Base support Q |
| --- | ---: | ---: |
| M >= 10 | 80 | 80 |
| M = 5-9 | 65 | 70 |
| M = 2-4 | 45 | 60 |
| M = 1 | 20 | 40 |
| No positive M; S >= 3 | 30 | 45 |
| No positive M; S = 1-2 | 10 | 25 |
| No positive M or S available | 0 | 0 |

Harmless/undetected counts do not subtract risk. Timeout/failure/unsupported
engine counts do not affect risk. Do not use them in a denominator: differing
engine coverage must not silently change an adverse vote's weight. VT aggregates
may contain dependent sources; these thresholds are conservative heuristics and
must be revisited with labeled validation data before operational reliance.

### AbuseIPDB (IP only)

Require totalReports > 0 and abuseConfidenceScore A > 0 before awarding points.
The provider's confidence score is an input, NOT TraceGuard evidence confidence.

| Evidence | Base B | Base support Q |
| --- | ---: | ---: |
| A = 90-100, totalReports > 0 | 70 | 70 |
| A = 50-89, totalReports > 0 | 50 | 60 |
| A = 10-49, totalReports > 0 | 25 | 45 |
| A = 1-9, totalReports > 0 | 10 | 30 |
| A = 0 or totalReports = 0 | 0 | 0 |

numDistinctUsers, totalReports beyond the positive-report guard, countryCode,
usageType, and isp add zero points. Missing optional fields never become invented
values. A > 0 with zero reports is an inconsistency flag, not a score. A=0 with
positive report count is visible context, not automatically a contradictory fact.

### URLhaus

| Evidence from identity-validated found outcome | Base B | Base support Q |
| --- | ---: | ---: |
| Exact URL, url_status=online | 95 | 90 |
| Exact URL, url_status=offline, absent, or another value | 85 | 80 |
| Exact MD5 or SHA-256 payload match | 95 | 90 |
| IPv4/domain host association, url_count > 0 | 30 | 45 |
| IPv4/domain found without a positive url_count | 15 | 30 |
| not_found or no usable found evidence | 0 | 0 |

An offline URL still has adverse historical evidence. Online is a provider field,
not a claim TraceGuard checked availability. Counts do not scale host risk.
Threat/tags/signature/type/size are displayed but add no points: they are arbitrary
metadata, not calibrated severity signals. An exact match must use the same
normalized lookup identity that was validated, including the fragment policy.
No risk transfer from an exact URL to a domain, IP, sibling URL, or file.

## Freshness

Use a fixed scoring_as_of, never the wall clock inside the scoring function.
Age is max(0, scoring_as_of - observed_at) in exact UTC durations. Apply the first
matching upper bound; boundaries are inclusive, not rounded calendar dates.

| Age | Factor F |
| --- | ---: |
| <= 7 days | 1.00 |
| <= 30 days | 0.90 |
| <= 90 days | 0.75 |
| <= 365 days | 0.50 |
| > 365 days | 0.25 |
| Missing/invalid timestamp or > 5 minutes in the future | 0.50 with explicit flag |

Up to five minutes of future skew is age zero. fetched_at never replaces
observed_at: newly retrieving old evidence cannot refresh it. Missing/future
fetch timestamps are flagged in coverage metadata, not used to increase risk.
Store percentages as integers and floor B*percent/100 to avoid floating ambiguity.

Current URLhaus timestamp provenance is ambiguous. For all URLhaus evidence,
cap F at 0.75, even if the timestamp appears recent. This is intentionally
conservative and prevents treating date_added as a recent malicious sighting.
An optional future adapter change could retain observed_at_source using the same
response, but is not required or assumed by this plan. Unknown dates cannot
qualify for the corroboration bonus. Aged positive evidence retains a historical
contribution; decay must not silently turn it into a safe verdict.

## Confidence, coverage, and conflicts

Evidence confidence measures support for a positive risk assessment, not safety
and not a statistical probability. For each positive contribution compute
q=floor(Q*F) using the table's Q. Let K be the same qualified-provider count as
above. Confidence = clamp(max(q, default=0) + min(20,10*max(0,K-1)) - D, 0,95).
Return 0 when there is no positive evidence. The 95 ceiling explicitly avoids
certainty. Provider failures/not_found do not enter this formula. Show provider
coverage separately (found/not_found/failed/disabled/skipped counts and freshness).

Distinct provider IDs are a proxy for corroboration, not proven independent
upstream intelligence. Count each once; never count individual VT engines as
independent providers. If provenance later identifies a shared upstream source,
collapse that source group before counting K. No independence claim can currently
be verified beyond distinct adapters; record this limitation in the report.

Record tensions without deleting or subtracting adverse evidence:
- Cross-provider no-adverse tension: one provider has P>0 while another found
  outcome explicitly has VT M=0 and S=0, or AbuseIPDB A=0. not_found, missing
  fields, and failure are NOT counterevidence. Apply D=10 once regardless of count.
- VT mixed verdicts: positive M/S alongside harmless>0; show counts, no extra
  penalty (common within aggregate verdicts; avoid double-counting).
- Provider internal inconsistencies, missing fields, unknown URL statuses, and
  future timestamps remain visible diagnostic flags. They produce only the
  explicit guards/freshness rules above, no unlisted adjustments.

With no-adverse tension, keep score and label, reduce confidence only, and show
both evidence references. A zero-adverse lookup never establishes benignness.

## IOC relationships without network access

Relationships are descriptive; they add ZERO score or confidence and never
propagate malicious labels. Link existing valid IOC nodes only. Do not synthesize
new extracted IOCs or schedule enrichment for derived values.

- url_has_host: syntactically parse a URL and match its normalized host to an
  existing domain/IP IOC. IP literals use strict canonical parsing, no DNS.
- email_has_domain: match email domain to an existing domain IOC locally only;
  email remains ineligible for provider transmission.
- same_lookup: link URLs differing only by stripped fragments, recording reused
  evidence. These remain distinct offline IOCs but never independent votes.
- same_source_line: group IOC IDs with equal source and line from occurrences;
  include occurrence IDs, offsets, and columns, not a copied raw log line.
  Co-occurrence means only shared input location, not causation or communication.
- same_input: a single investigation-level membership group, not an all-pairs graph.

Use groups for line/input co-occurrence to avoid quadratic edge explosions with
10,000 IOCs. Store all memberships without silent truncation. Repeated identical
occurrences do not create extra relationships or votes. Sort nodes/edges/groups
canonically. Do not infer IP-domain resolution, hash equivalence across algorithms,
common malware family, shared infrastructure, ownership, or host-to-payload links
from tags, ISP, country, reference URLs, or unretained provider arrays.

## Worked examples

All timestamps are recent (<=7 days) unless specified; URLhaus still uses its
0.75 provenance cap. Provider fields named in each row are the evidence references
for the synthetic calculation; implementation will use JSON pointers and IDs.

| Example | Provider evidence and calculation | Final risk / label / confidence |
| --- | --- | --- |
| 1. No matches | Every provider not_found; no contributions or bonus | 0 / unknown / 0 |
| 2. Saved smoke IP | VT M=0,S=0; Abuse A=0,reports=58; URLhaus not_found | 0 / unknown / 0 |
| 3. Single weak VT vote | VT M=1: P=20,Q=40; others missing/failing; K=1 | 20 / low / 40 |
| 4. Exact active URL | URLhaus found URL, online: floor(95*.75)=71; q=floor(90*.75)=67; K=1 | 71 / malicious / 67 |
| 5. Host association only | URLhaus found domain,url_count=500: floor(30*.75)=22; q=floor(45*.75)=33 | 22 / low / 33 |
| 6. Two-source IP agreement | VT M=6:65,q70; Abuse A=80,reports=20:50,q60; K=2,C=5 | 70 / malicious / 80 |
| 7. Conflicting IP evidence | VT M=10:80,q80; Abuse A=0,reports=0; K=1,D=10 | 80 / malicious / 70; tension visible |
| 8. Old exact payload | URLhaus found SHA-256,200 days old:95*.5 floored=47;q=45; K=0 | 47 / suspicious / 45 |
| 9. Three-provider agreement | VT M=10:80,q80; Abuse A=95,reports=30:70,q70; URLhaus host,count=2:22,q33; K=3,C=10 | 90 / malicious / 95 (confidence capped) |
| 10. Unknown timestamp | VT M=6 with no observed_at:floor(65*.5)=32;q=35; K=0 | 32 / suspicious / 35 |
| 11. Historical offline URL | URLhaus exact URL,offline,recent:floor(85*.75)=63;q=60 | 63 / suspicious / 60 |

If example 6's unrelated URLhaus failure is changed to not_found or disabled,
its score remains 70 and confidence 80. If a new found zero-adverse result creates
a tension, only the stated confidence penalty applies. Under current provider
caps the largest reachable score is 90; the explicit cap at 100 is a contract
for future policy versions, not a reason to inflate current weights.

## Approved contracts and integration

Implemented as pure core functions in scoring.py and correlation.py, with
Pydantic models for ScoringPolicy, EvidenceReference, ScoreContribution,
IOCassessment, EvidenceTension, Relationship, and RelationshipGroup. No CLI,
HTTP, credentials, AI, or storage imports. Input: immutable report plus policy
and scoring_as_of. Output: new report; never mutate provider evidence.

Evidence references contain stable evidence ID, provider_id, outcome index,
ioc_index, normalized lookup identity, report reference, timestamp fields, and
JSON pointer(s) to actual fields such as /provider_results/0/evidence/attributes/
last_analysis_stats/malicious. A URLhaus match also references outcome status,
IOC type, and the derived eligible lookup identity. No extra outbound context.

Assessed report schema 1.2 adds assessments and relationships while
preserving Phase 3 provider_results. Breakdown stores rule ID/version, evidence
references and field values, base B/Q, age/freshness factor and rationale, weighted
P/q, selection role, corroboration references, conflict penalty, unclamped totals,
final totals, zero-point/excluded reasons, and limitations. Canonical IDs must
not depend on Python hash randomization. Preserve terminal escaping of untrusted
provider text. Never hide contributions with ellipses or top-N truncation.

Approved integration: analyze applies deterministic assessment
to available evidence; --enrich remains the sole network opt-in. Offline-only
analysis emits 0/unknown with no-provider-evidence rationale and local relationships.
Terminal and JSON must contain the same full breakdown and conflict references,
including non-additive providers and unknown outcomes. No global investigation
score or automatic remediation. Do not add arbitrary imported-report execution
or another CLI mode in this phase; the pure core is reusable by a future API.

## Acceptance criteria and tests

1. Golden synthetic fixtures reproduce every worked example exactly, including
   all evidence references and max/bonus/floor calculations.
2. Parameterize every provider band boundary, M/S absent versus zero, totals=0,
   optional metadata, URL status variants, identity mismatch, unsupported types,
   invalid IOCs, missing evidence, and internal inconsistencies.
3. Verify 0/29/30/69/70/100 label boundaries, cap invariants, and zero always
   unknown. Verify explicit clamping with synthetic policy boundary inputs even
   though current real-provider maxima reach only 90.
4. Freeze UTC time; test every freshness boundary just before/at/after, absent
   dates, timezone offsets, five-minute future skew, and URLhaus provenance cap.
   Re-fetching identical evidence must not change freshness or risk.
5. Substitute every failure/skip/disabled/not_found status without changing
   positive evidence: risk and confidence remain invariant; coverage changes only.
   A successful zero-adverse lookup never labels clean or safe.
6. Same provider repeats, fragments, and reused outcomes never increase K or risk.
   Order-independent equivalent inputs produce equivalent scores and sorted links;
   rule tie breaking and policy version/as-of support replay across processes.
7. Positive/no-adverse tensions preserve both sides, leave risk unchanged, and
   apply only one confidence penalty. Harmless votes never subtract risk.
8. Relationships use existing IDs and occurrences; test IDNA/IPv6 hosts, email
   privacy, repeated lines, distinct sources, invalid values, fragment reuse,
   and 10,000-IOC single-line groups without quadratic pair expansion.
9. Terminal/JSON parity includes every scoring component and source pointer;
   exported evidence remains unchanged. Host relationships never transfer scores.
10. Block sockets/DNS/HTTP in scoring tests; mock enrichment integration only.
    Real .env and smoke reports are never fixtures. Add secret-canary tests to
    ensure new rendering preserves redaction and safe terminal output.
11. Run the full .venv312 pytest branch-coverage gate, Ruff format/lint, strict
    mypy, dependency checks, compilation, and CLI tests after implementation.

## Implementation record

All proposed decisions were approved, including schema 1.2 and automatic offline
assessments. Core contracts live in assessment.py; scoring.py and correlation.py
are pure functions. The CLI supplies an aware UTC time and renders complete
assessments without adding network requests. Offline extraction's AnalysisReport
remains an internal input contract; assessed CLI reports always use schema 1.2.

same_lookup uses a membership group (rather than an all-pairs clique), with shared
evidence IDs. Per-line groups retain occurrence locations without raw log lines.
Each contribution carries rule ID; its enclosing assessment carries policy version.
Non-found duplicate outcomes remain visible but cannot replace available found
evidence or affect the numeric calculation. Among usable found duplicates, latest
fetched_at and stable evidence ID select the winner. Original provider outcomes
are retained without mutation. This interpretation preserves failure invariance.

Identity checks rely on Phase 3's validated adapter boundary for URLhaus and
hashes, whose exact response identity fields are not retained. Retained VT URL,
IP, and domain IDs are also rechecked. No arbitrary imported-report command was
added; fabricated in-memory provider evidence is not authenticated by scoring.

Thresholds remain provisional until evaluated on labeled investigations; upstream
source independence is unverified. URLhaus timestamp provenance remains ambiguous.
Complete terminal audit blocks can be large. No live enrichment was performed for
this implementation, and Phase 5 remains out of scope.


### Phase 4 validation result

Validated on Python 3.12.10 in .venv312: 437 tests passed, 98.47% combined
statement/branch coverage (90% gate); Ruff formatting/linting, strict mypy
(47 source/test files), pip check, compileall, and installed CLI help passed.
All provider tests were mocked; no live enrichment requests were made. .env and
live-smoke-report.json remain Git-ignored and untracked, and neither was modified.
The existing .venv was preserved. Phase 5 was not started.


### Phase 4 changed-file inventory

- src/traceguard/core/assessment.py (new): schema 1.2 and typed assessment contracts.
- src/traceguard/core/scoring.py: pure versioned provider scoring and provenance.
- src/traceguard/core/correlation.py: local relationships and occurrence groups.
- src/traceguard/adapters/cli/app.py: automatic assessment and explicit UTC time.
- src/traceguard/adapters/cli/reporting.py: summaries and complete escaped audit output.
- tests/unit/test_scoring.py (new): worked examples, bands, freshness and invariants.
- tests/unit/test_correlation.py (new): relationships, provenance and 10,000-IOC grouping.
- tests/cli/test_assessment.py (new): schema, parity, replay and synthetic secret redaction.
- tests/cli/test_analyze.py: update terminal assessment contract expectation.
- tests/cli/test_enrich.py: update offline schema expectation to 1.2.
- AGENTS.md, README.md, docs/product.md, docs/architecture.md, docs/phase4-plan.md:
  approved scope, implemented contracts, operating guidance and validation record.
