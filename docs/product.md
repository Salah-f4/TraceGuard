# Product contract

TraceGuard helps SOC analysts and cybersecurity students investigate raw security
text using a CLI around a reusable Python core. This is an early 0.1.0 MVP, not an
accuracy-certified detection product. A future web interface is outside this release.

## Inputs and offline behavior

Exactly one of --text, --file or --stdin; UTF-8 .txt/.log, optional BOM. Maximum
1,000,000 input bytes and 10,000 extracted occurrences before deduplication. Empty,
binary, unsupported and oversized inputs produce clear errors; never truncate.
Recognize IPv4/IPv6, domains, URLs, email and MD5/SHA-1/SHA-256; refang hxxp/hxxps,
[.], (.) and [:]. Preserve original and normalized values, validity/message,
defanged flags, first location and every occurrence. Deduplicate type+normalized value.

Strict IP parsing and canonical IPv6; lowercase/IDNA domains; lowercase URL
scheme/host while retaining path/query spelling; preserve email local spelling and
normalize domain; exact-length hexadecimal hashes lowercased. URL/email spans own
embedded indicators. Locations are Unicode offsets into original decoded text.
No DNS, public-suffix lookup, URL access, execution or download occurs.

## Intelligence and deterministic assessment

--enrich retrieves existing reports through VirusTotal, AbuseIPDB and URLhaus.
Eligible normalized indicators only; never logs, filenames, source lines, emails
or non-public IPs. URL userinfo/queries cause privacy skips; lookup fragments are
removed. Missing keys disable individual providers. Timeouts/rate limits/retries
are bounded and each attributed outcome/evidence is preserved independently.

Schema 1.2 automatically includes deterministic assessments and relationships.
Versioned heuristic tables, thresholds, freshness, max-plus-capped-bonus rules and
worked examples remain in phase4-plan.md. Scores 0–100 and evidence confidence
are distinct heuristics, not probabilities. Labels: unknown/low/suspicious/malicious.
Provider failures never change risk/confidence; zero/not_found/harmless never means
safe. Descriptive associations do not establish causation, compromise or campaigns.

## Optional constrained AI reporting

--ai adds schema 1.3 metadata and executive summary, IOC findings, correlations,
uncertainties, prioritized investigation steps and analyst notes. Without evidence
citations, no model call occurs. Groq qwen/qwen3.8-27b receives only compact enums,
numbers and temporary aliases, never actual IOC values, provider prose or raw input.
Strict output is a flat claims array. Frozen local destinations determine sections;
local templates render wording. Model output cannot modify deterministic fields.
Unknown/duplicate claims, ownership errors, omitted mandatory claims or exceeded
limits reject the entire response. Missing key/refusal/timeout/budget/validation
failure retains the complete deterministic report and local fallback. Diagnostics
contain fixed codes and numeric counts/usage, not raw responses or exception text.
4,000 input/1,000 output tokens; conservative accounting may skip otherwise fitting
reports. No tools, streaming, actions or autonomous investigation.

## CLI and boundaries

Terminal and JSON include full scoring/evidence breakdowns. New output files only;
create directories first. Export path checking is after enrichment and before AI.
stdout holds reports, stderr holds warnings/errors. Input/export failures exit 2;
cancellation exits 130; recoverable optional-service failure can exit 0 with fallback.

Extraction is syntactic: dotted filenames may look like domains, terminal punctuation
can be ambiguous, scoped IPv6 and CIDR suffix semantics are unsupported. Email
supports unquoted ASCII dot-atom local parts, not SMTPUTF8/quoted locals. URLs must
be hierarchical scheme://host. No accuracy guarantee, definitive clean verdict,
accounts, database, SIEM integration, sandboxing, blocking or permanent hosting.

Protect local exports, which still contain input/evidence. Provider data can be
stale/incomplete/conflicting/non-independent; AI is selection of vetted claims, not
new intelligence. See provider-terms.md, testing.md and phase6-validation.md.
