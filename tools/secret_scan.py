"""Scan an explicit public candidate, retaining only safe finding metadata."""

import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def scan(binary: Path, target: Path, output: Path) -> list[dict[str, Any]]:
    run = subprocess.run(
        [
            str(binary),
            "dir",
            str(target),
            "--redact=100",
            "--no-banner",
            "--log-level",
            "error",
            "--report-format",
            "json",
            "--report-path",
            str(output),
        ],
        capture_output=True,
        check=False,
    )
    if run.returncode not in {0, 1}:
        raise SystemExit("Scanner execution failed; output suppressed.")
    findings = json.loads(output.read_text(encoding="utf-8"))
    # Scanner report is redacted but still discard lines/snippets and never print them.
    safe = [
        {
            "rule": f["RuleID"],
            "file": Path(f["File"]).relative_to(target).as_posix()
            if Path(f["File"]).is_absolute()
            else Path(f["File"]).as_posix(),
            "line": f["StartLine"],
        }
        for f in findings
    ]
    output.write_text(json.dumps(safe, indent=2) + "\n", encoding="utf-8")
    return safe


def main() -> None:
    binary = Path(sys.argv[1]).resolve()
    target = Path(sys.argv[2]).resolve()
    out = Path("build/phase6")
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="traceguard-scan-canary-") as tmp:
        p = Path(tmp)
        # Inert test token assembled here; never a real credential or tracked canary.
        (p / "canary.txt").write_text(
            'github_token = "' + "ghp_" + secrets.token_hex(18) + '"', encoding="utf-8"
        )
        canary = scan(binary, p, out / "scanner-canary.json")
        if not canary:
            raise SystemExit("Scanner failed synthetic canary check.")
    found = scan(binary, target, out / "secret-scan.json")
    print(
        json.dumps({"canary_detected": True, "candidate_findings": len(found), "findings": found})
    )
    if found:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
