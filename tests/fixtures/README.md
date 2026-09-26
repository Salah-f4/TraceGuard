# Synthetic fixture manifest

mixed.log is manually authored, contains no live threat intelligence or personal
information, and exercises all eight IOC types plus invalid syntax and deduplication.
192.0.2.1 and 2001:db8::1 are documentation ranges. Domains use example.com/.example;
email is fictional. Repeated A/B/C hash strings are deliberately synthetic syntax
candidates, not malware fingerprints. Defanged URL query values are inert examples.
Expected: 10 extracted occurrences, 9 unique indicators, one invalid IPv4 candidate.
Reserved addresses/domains and emails must be skipped for external enrichment.

The full CLI integration test hashes a documented harmless byte string and generates
provider responses in memory. Its MockTransport handlers never contact services.
Other historical tests include benign public-address constants to exercise public
eligibility under network-denial guards. These are not public demonstration verdicts.
Never replace fixtures with downloaded reports, malware or credentials.
