# Contributing

The repository URL is provisional. No hosted CI success or release is claimed.
Use Python 3.12 and the locked setup in README.md. Preserve .venv and local reports.

Run the full checks in docs/testing.md before proposing a change. Tests use synthetic
inputs, generated inert credentials and mocked HTTP transports only. Real provider
and AI requests are forbidden, including optional "live" test markers. Do not load
the developer's .env. Do not copy live reports into tests or documentation.

Core code stays independent from the CLI. Scoring is a versioned deterministic
heuristic; changes need a documented regression and explicit policy approval.
AI only selects vetted aliases; local routing, ownership, required uncertainties,
limits and complete fallback must remain. Never log raw model output or exception
text. No new providers, persistence or web frontend is part of this release.

Keep fixes focused and meaningful tests at the boundary being changed. Run Ruff
format/check, strict mypy, pytest with branch coverage, pip check and compilation.
Regenerate locks with the pinned tooling and commands in docs/testing.md. Review
lock changes and advisory findings; never use an automatic vulnerability --fix.

Use SECURITY.md for private vulnerability reports once the owner enables GitHub
private reporting. Contributions must be compatible with the MIT license.
