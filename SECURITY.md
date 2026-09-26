# Security policy

TraceGuard 0.1.x is an early CLI MVP. There is no production support SLA.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/Salah-f4/TraceGuard/security/advisories/new)
after the repository exists and its owner enables that feature. The repository URL
is provisional and private reporting is not yet verified as enabled. If the page is
unavailable, wait for the owner to enable private reporting; do not post sensitive
details in public issues. No personal email address is published.

Include affected version, impact, reproduction using synthetic data, and proposed
mitigation if known. Do not include credentials, private logs, personal information,
real malicious URLs or provider responses. Never test against third-party services
or systems without authorization. Public issues may describe nonsensitive bugs.

Local JSON reports preserve input/evidence and should be treated as sensitive.
The AI projection excludes raw values, but this does not anonymize local reports.
Use a secret store or ignored local .env; never put tokens into shell examples,
commits, screenshots or bug reports. Rotate credentials exposed elsewhere.

Release preparation includes local secret scanning and dependency advisory review.
These checks cannot prove absence of all vulnerabilities. See docs/provider-terms.md
for separate service restrictions and privacy considerations.
