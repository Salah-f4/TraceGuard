"""Enumerate only approved release roots; do not traverse local data or environments."""

import shutil
import sys
from pathlib import Path

ROOT_FILES = {
    ".env.example",
    ".gitignore",
    "AGENTS.md",
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "MANIFEST.in",
    "pyproject.toml",
    ".gitleaks.toml",
}
ROOTS = (".github", "docs", "requirements", "src/traceguard", "tests", "tools")


def release_files(root: Path) -> list[str]:
    found = {name for name in ROOT_FILES if (root / name).is_file()}
    for base in ROOTS:
        for p in (root / base).rglob("*"):
            if p.is_symlink():
                raise ValueError("Release tree must not contain symlinks.")
            if (
                not p.is_file()
                or p.name == ".gitkeep"
                or "__pycache__" in p.parts
                or p.suffix in {".pyc", ".pyo"}
            ):
                continue
            found.add(p.relative_to(root).as_posix())
    return sorted(found)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = root / "docs/release-files.txt"
    manifest.touch(exist_ok=True)
    names = release_files(root)
    manifest.write_text("\n".join(names) + "\n", encoding="utf-8")
    if len(sys.argv) > 1:
        target = Path(sys.argv[1]).resolve()
        if not target.is_relative_to(root / "build") or target.exists():
            raise SystemExit("Candidate destination must be a new path under build/.")
        for name in names:
            dest = target / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, dest)
    print(f"{len(names)} proposed Git files; no Git index changes.")


if __name__ == "__main__":
    main()
