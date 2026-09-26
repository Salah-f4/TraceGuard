# Testing and release validation

Use Python 3.12. Preserve .venv; use .venv312 for application validation. Tooling can
instead be isolated under build/phase6/tools-env. Package downloads and advisory
queries are authorized; no intelligence or AI requests are allowed.

## Full Windows checks

After README's hash-locked setup:

```powershell
.\.venv312\Scripts\python -m ruff format --check src tests tools
.\.venv312\Scripts\python -m ruff check src tests tools
.\.venv312\Scripts\python -m mypy
.\.venv312\Scripts\python -m pytest
.\.venv312\Scripts\python -m pip check
.\.venv312\Scripts\python -m compileall -q src tests tools
.\.venv312\Scripts\traceguard --help
```

The 90% combined statement/branch coverage gate is unchanged. Tests clear inherited
keys, use temporary cwd and block real HTTP/DNS. test_complete_cli.py exercises the
actual CLI, parsers, scoring, Groq transport and local validation with MockTransport.
Other suites cover privacy, limits, normalization, deadlines, retries, export,
flat routing, safe diagnostics and deterministic invariance.

## Regenerate locks with the pinned tool environment

Runtime/dev inputs come from pyproject.toml; tooling.in pins build/security tools.
Run from repository root, using that tool environment's python and uv executables.

```powershell
$env:CUSTOM_COMPILE_COMMAND = 'python -m piptools compile --generate-hashes pyproject.toml'
python -m piptools compile --generate-hashes --strip-extras --no-emit-index-url --no-emit-trusted-host -o requirements/windows-py312-runtime.txt pyproject.toml
$env:CUSTOM_COMPILE_COMMAND = 'python -m piptools compile --generate-hashes --extra dev pyproject.toml'
python -m piptools compile --generate-hashes --strip-extras --extra dev --no-emit-index-url --no-emit-trusted-host -c requirements/windows-py312-runtime.txt -o requirements/windows-py312-dev.txt pyproject.toml
$env:CUSTOM_COMPILE_COMMAND = 'python -m piptools compile --generate-hashes --allow-unsafe requirements/tooling.in'
python -m piptools compile --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url --no-emit-trusted-host -c requirements/windows-py312-dev.txt -o requirements/windows-py312-tooling.txt requirements/tooling.in
```

Linux resolution on this Windows host uses uv 0.11.21; it is not native Linux testing:

```powershell
uv pip compile pyproject.toml --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --no-emit-index-url --no-header -c requirements/windows-py312-runtime.txt -o requirements/linux-py312-runtime.txt
uv pip compile pyproject.toml --extra dev --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --no-emit-index-url --no-header -c requirements/linux-py312-runtime.txt -o requirements/linux-py312-dev.txt
uv pip compile requirements/tooling.in --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --no-emit-index-url --no-header -c requirements/linux-py312-dev.txt -o requirements/linux-py312-tooling.txt
```

Review exact versions/hashes and regenerate twice before accepting. Do not freeze
unrelated installed packages. Official index: https://pypi.org/simple. No private
index credentials belong in locks. Native Linux builds/tests remain a CI gate.

## Build and independently test the wheel

With pinned tooling installed, run `python -m build --no-isolation`,
`python -m twine check dist/*`, and `python tools/inspect_archives.py`.
The frontend builds the wheel from the sdist. Inspect both manifests: no .env,
local environments, live reports or generated investigation data. Deliberately
synthetic docs/examples are the only distributed example reports.

Download runtime wheels with --require-hashes --only-binary=:all: into build/wheels.
Create a NEW build/wheel-env. Install runtime lock using --no-index --find-links
build/wheels --require-hashes, then install the local wheel with --no-deps.
Run that environment's Python with `-I tools/wheel_smoke.py`. It verifies import
origin, changes cwd outside checkout, removes TraceGuard environment names and
installs independent socket/HTTP/process guards. Only asyncio's internal wakeup
socket pair is permitted. It checks help, offline JSON, AI fallback and export.
Parent pytest monkeypatches are not assumed to protect this process. Real .env is
never read. No package upload occurs.

## Secret and dependency checks

`python tools/release_manifest.py build/release-candidate` copies only explicit
public roots into a NEW directory; it writes docs/release-files.txt without Git
staging. It never traverses .env, venvs, live reports or .git.
`python tools/download_scanner.py` obtains Gitleaks 8.30.1 from its official release
and checks pinned SHA-256. `python tools/secret_scan.py <binary> <candidate>` first
checks a generated inert canary, then scans all candidate files with full redaction.
Only rule/path/line metadata remains; snippets are discarded, not printed. There
are no broad fixture suppressions. With no commits yet, history scanning is empty;
repeat history scanning after a future authorized commit creates history.

pip-audit 2.10.1 runs read-only advisory requests, never provider/AI requests:
`python -m pip_audit --disable-pip --no-deps --require-hashes -r <lock> -f json -o <ignored-build-result>`.
Audit runtime/dev/tooling locks, inspect skipped packages and findings, never use
--fix automatically. pip check tests consistency, not vulnerabilities. A clean
advisory result means no known reported vulnerabilities at that time, not safety.

## GitHub Actions

ci.yml defines Windows/Ubuntu Python 3.12 jobs with pinned action SHAs, read-only
permissions, no secrets, hashed installs, offline tests, archive/wheel checks and
a separate secret scan. Only synthetic coverage/JUnit/manifests are uploaded for
seven days. audit.yml is manual-only for advisory queries. No hosted workflow has
run here and no success badge is present. The owner must create/configure the repo,
enable private vulnerability reporting and require validation checks separately.
