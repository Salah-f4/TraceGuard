"""Inspect built archives using names only, never local credentials or reports."""

import sys
import tarfile
import zipfile
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    files = sorted(root.glob("*.whl")) + sorted(root.glob("*.tar.gz"))
    if len(files) != 2:
        raise SystemExit("Expected one wheel and one source archive.")
    for archive in files:
        if archive.suffix == ".whl":
            with zipfile.ZipFile(archive) as z:
                names = sorted(z.namelist())
        else:
            with tarfile.open(archive) as t:
                names = sorted(m.name for m in t.getmembers() if m.isfile())
        for name in names:
            parts = Path(name).parts
            if any(part.startswith(".env") and part != ".env.example" for part in parts):
                raise SystemExit("Private configuration in archive.")
            if any(
                p in {".env", ".venv", ".venv312", "__pycache__", ".git", "reports", ".validation"}
                for p in parts
            ):
                raise SystemExit("Forbidden archive member.")
            if (
                "live-smoke-report" in name
                or "live-ai-smoke-report" in name
                or name.endswith((".pyc", ".db"))
            ):
                raise SystemExit("Generated investigation data in archive.")
            if name.startswith("/") or ".." in parts:
                raise SystemExit("Unsafe archive path.")
        if not any(name.endswith("LICENSE") for name in names):
            raise SystemExit("Missing license.")
        if not any(name.endswith("traceguard/core/scoring.py") for name in names):
            raise SystemExit("Missing application code.")
        output = root / (archive.name + ".contents.txt")
        output.write_text("\n".join(names) + "\n", encoding="utf-8")
        print(f"{archive.name}: {len(names)} files; manifest checks passed")


if __name__ == "__main__":
    main()
