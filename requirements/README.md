# Locked release dependencies

Runtime and dev inputs are pyproject.toml. tooling.in pins release tool versions.
Windows locks: Python 3.12.10, pip-tools 7.6.1, pip 26.2.1. Exact versions and hashes,
including pip/setuptools (--allow-unsafe includes packaging tools, not a bypass).
Tooling is constrained by dev; dev includes runtime. Install both for validation.

Linux locks: uv 0.11.21 cross-resolves Python 3.12 x86_64-unknown-linux-gnu with
Windows runtime versions constrained. Platform-specific Linux tooling dependencies
are independently resolved. This bounded tooling adjustment is necessary because
there is no Linux runtime here and pip-tools cannot natively evaluate Linux markers
on Windows. Linux wheels are checked for availability and hashes; native builds/tests
await Ubuntu CI. See docs/testing.md. Integrity hashes do not replace vulnerability
checks. pip-audit 2.10.1 reviews known advisories without automatic fixes.
