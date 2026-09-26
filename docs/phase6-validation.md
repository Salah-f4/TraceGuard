# Phase 6 local validation record

Prepared 2026-09-27 on Windows, Python 3.12.10. This is local release preparation,
not a published release or a claim of hosted CI success.

## Results

| Check | Result |
| --- | --- |
| Full mocked pytest suite | 544 passed |
| Combined statement/branch coverage | 98.11%; existing 90% gate retained |
| Ruff format/lint | Passed; 68 Python files |
| Strict mypy | Passed; 67 source/test/tool files |
| pip check and compileall | Passed |
| Installed CLI help | Passed |
| Complete mocked CLI→providers→scoring→Groq→validation | Success and three failure cases pass |
| Application source preservation | Every source Python file byte-identical to phase-start inventory |
| Windows hashed runtime/dev/tooling locks | Installed successfully; all three regenerate byte-identically |
| Linux target locks | Cross-resolved; all three regenerate byte-identically; 75 Linux wheels downloaded with hash verification |
| Wheel and source build on Windows | Passed; wheel built from sdist using pinned tooling, no isolation downloads |
| Twine package metadata | Both archives passed |
| Archive content review | Wheel/sdist manifests inspected; no real .env, live reports, environments or caches |
| Fresh wheel install | Runtime dependencies installed from local hashed wheelhouse; wheel installed with --no-deps |
| Independent installed-wheel smoke | Help, offline JSON, AI fallback/export and network-denial pass outside checkout |
| Gitleaks 8.30.1 | Synthetic canary detected; zero release-candidate findings; no suppressions |
| pip-audit 2.10.1 Windows | 72 distinct packages; zero known vulnerabilities; zero skipped |
| pip-audit 2.10.1 Linux target | 75 distinct packages; zero known vulnerabilities; zero skipped |
| Actions static validation | actionlint 1.7.12 passed both workflow definitions |
| Git index/history | Empty index, no commits; nothing staged, pushed, tagged or published |

Windows locks contain 20 runtime, 31 dev (including runtime), and 50 tooling pins.
Linux locks contain 19 runtime, 30 dev and 53 tooling pins. Every pinned name/version
in all six files is covered by the corresponding combined advisory review. Results
are time-specific known-advisory checks, not a security guarantee. No automatic
vulnerability fixes or ignored findings were used.

## Packaging and reproducibility

The pinned tool environment uses pip 26.2.1, pip-tools 7.6.1, pip-audit 2.10.1,
build 1.6.1, setuptools 84.0.0, wheel 0.46.3, twine 6.2.0 and uv 0.11.21.
All direct/transitive artifacts are hash-locked. Wheels and source archives retain
MIT/license metadata, approved author and provisional repository links. Public
examples are synthetic; their fabricated evidence/usage is labelled. .env.example
contains blank current names only and is safe to distribute.

Exact archive members are written to dist/*.contents.txt by tools/inspect_archives.py.
The proposed Git file list is docs/release-files.txt; changed/created files are in
phase6-changes.md. The archived source contains necessary source/tests/docs/tooling,
not local environments or investigation data. Builds were inspected locally and
nothing was uploaded. Reproducible dependency resolution was checked; byte-identical
wheel/sdist rebuilding across platforms is not claimed.

## Resolved preparation issues

The initial Windows build exposed CP1252 documentation bytes; affected public docs
were normalized to UTF-8 and both builds/metadata checks then passed. Source code
was unchanged. Installing pinned build tools resolved a missing local setuptools
backend for the editable install. A secret-scan canary with low-entropy placeholder
text was not detected; it was replaced with a generated inert high-entropy canary,
which the pinned scanner detects. One prose README sentence triggered a generic
secret rule; it was rephrased and rescanned, without weakening scanner rules.

## Remaining limits and owner actions

- Native Linux execution is unavailable: WSL has no distribution and Docker is not
  installed. Linux lock resolution/wheel availability/audit are verified, but native
  Linux install, build, tests and wheel smoke remain required on the Ubuntu CI job.
  This is the principal incomplete release gate; no system-wide Linux installation
  was performed merely to hide that limitation.
- Linux locks use pinned uv for cross-platform marker resolution because pip-tools
  cannot natively resolve Linux from this host. Windows remains pip-tools based.
  This bounded tooling adjustment does not change application dependencies/policies.
- GitHub repository URL is provisional. Repository creation, Actions execution,
  branch protection and enabling private vulnerability reporting require separate
  owner action. SECURITY.md does not claim that private reporting is already enabled.
- No package-name availability or hosted CI success is claimed; no badges added.
- No history exists to scan. The explicit candidate-tree scan includes untracked
  public files; scan future Git history after an approved initial commit.
- Tool/dependency downloads and read-only advisory queries occurred only through
  official sources. No VirusTotal, AbuseIPDB, URLhaus or Groq requests occurred.
- Real .env, live reports and credential contents were neither read nor modified;
  both existing virtual environments and all local reports remain present. Any
  previously disclosed credentials need owner-managed rotation outside this task.
- Automated checks do not measure real-world intelligence accuracy or eliminate
  third-party terms/privacy obligations. No numerical policy or AI behavior changed.

The owner should review this record and exact file manifest before separately
authorizing any commit, repository creation, push, publication or release.
