# Provider terms and responsible use

Reviewed for documentation on 2026-09-26; recheck terms before deployment.
TraceGuard's MIT license covers its original code, not provider services or data.
No provider has endorsed this project; do not redistribute real reports as fixtures.

- VirusTotal Public API is restricted to non-commercial/academic use. Commercial
  workflows require suitable provider authorization/access. Keep source attribution:
  https://docs.virustotal.com/docs/difference-public-private
- URLhaus community use follows fair-use rules; commercial needs may require paid
  access: https://urlhaus.abuse.ch/api/
- AbuseIPDB account/API terms, quotas and redistribution restrictions apply:
  https://www.abuseipdb.com/legal
- Groq model/service terms, access, billing and retention controls are independent:
  https://console.groq.com/docs/legal and https://console.groq.com/docs/your-data
  Free-tier limits can change; the client cannot promise provider-side zero retention.

No live API use occurs in tests or CI validation. Use --enrich/--ai only intentionally
with data you are authorized to handle. Reputation and model-selected claims cannot
establish safety or prove an incident; a human must assess context. Local reports
can be sensitive even when outbound data is minimized. No automatic blocking,
remediation, malware execution, file upload, scan submission or URL visit is offered.
