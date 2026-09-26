# Phase 6 changed-file inventory

These are changes during this phase, not a Git diff: the repository has no commits
and its index is empty. The exact complete proposed Git release manifest is
[release-files.txt](release-files.txt), which also includes unchanged application/tests.

## Modified existing files

- .env.example
- .gitignore
- AGENTS.md
- README.md
- docs/architecture.md
- docs/phase6-plan.md
- docs/product.md
- pyproject.toml
- tests/fixtures/mixed.log

## Created release files

- .github/workflows/audit.yml
- .github/workflows/ci.yml
- CONTRIBUTING.md
- LICENSE
- MANIFEST.in
- SECURITY.md
- docs/examples/README.md
- docs/examples/mocked-ai.txt
- docs/examples/offline.txt
- docs/examples/report-excerpt.json
- docs/images/mocked-ai.svg
- docs/images/offline.svg
- docs/phase6-changes.md
- docs/phase6-validation.md
- docs/provider-terms.md
- docs/release-checklist.md
- docs/release-files.txt
- docs/testing.md
- requirements/README.md
- requirements/linux-py312-dev.txt
- requirements/linux-py312-runtime.txt
- requirements/linux-py312-tooling.txt
- requirements/tooling.in
- requirements/windows-py312-dev.txt
- requirements/windows-py312-runtime.txt
- requirements/windows-py312-tooling.txt
- tests/fixtures/README.md
- tests/integration/test_complete_cli.py
- tools/download_scanner.py
- tools/generate_examples.py
- tools/inspect_archives.py
- tools/release_manifest.py
- tools/secret_scan.py
- tools/wheel_smoke.py

## Preserved and excluded

Every src/traceguard Python file is byte-identical to the phase-start SHA-256
inventory. No scoring or AI behavior was changed. Existing phase4/phase5 historical
documents remain unchanged. The original .venv was untouched; .venv312 received
approved hash-locked development/build tools and updated local editable metadata.
Neither environment nor any local report was deleted. The real .env, reports and
credential values were never accessed. No commits, staging, pushes or publication.

Ignored outputs: build/phase6 holds isolated tool/wheel environments, candidate
copies, advisory/scan summaries, test logs and downloaded official artifacts;
dist contains wheel/sdist and their content manifests. Existing generated caches
remain local and ignored. Nonempty test directories' obsolete .gitkeep placeholders
are omitted from the proposed Git manifest without deleting user files.
