# Release review gates

See phase6-validation.md for actual results. No commit, push, repository creation,
release or upload is authorized by this checklist.

- [ ] Review exact docs/release-files.txt; no .env, live reports, caches or environments.
- [ ] Review changes; application behavior/source and existing venvs remain preserved.
- [ ] Complete mocked mode matrix, policy tests, Ruff, strict types and coverage pass.
- [ ] Windows hash-locked install, archive inspection and installed-wheel smoke pass.
- [ ] Linux lock/artifact resolution reviewed; native Linux CI still must pass.
- [ ] Secret scan/canary and all advisory results reviewed; no hidden skipped findings.
- [ ] Synthetic captures match accessible examples; no real input or account details.
- [ ] MIT holder/year and provisional repo URL correct; private reporting enabled later.
- [ ] Provider terms and limitations are clear; zero/unknown is never called safe.
- [ ] Previously disclosed credentials rotated outside this task before routine use.
- [ ] Exact candidate file list approved before a separate commit/publication action.
- [ ] Hosted validation passes before any CI-success claim.
