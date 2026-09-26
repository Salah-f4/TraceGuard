"""Pinned official Gitleaks download; never fetch investigation data."""

import hashlib
import os
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "8.30.1"
DIGESTS = {
    "windows_x64.zip": "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    "linux_x64.tar.gz": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
}


def main() -> None:
    suffix = "windows_x64.zip" if os.name == "nt" else "linux_x64.tar.gz"
    root = Path("build/scanner")
    root.mkdir(parents=True, exist_ok=True)
    name = f"gitleaks_{VERSION}_{suffix}"
    data = urllib.request.urlopen(
        f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/{name}", timeout=60
    ).read()
    if hashlib.sha256(data).hexdigest() != DIGESTS[suffix]:
        raise SystemExit("Scanner checksum mismatch.")
    archive = root / name
    archive.write_bytes(data)
    binary = "gitleaks.exe" if os.name == "nt" else "gitleaks"
    if os.name == "nt":
        with zipfile.ZipFile(archive) as z:
            (root / binary).write_bytes(z.read(binary))
    else:
        with tarfile.open(archive) as t:
            member = t.extractfile(binary)
            assert member is not None
            (root / binary).write_bytes(member.read())
        (root / binary).chmod(0o755)
    print(f"Gitleaks {VERSION}: official release SHA-256 verified.")


if __name__ == "__main__":
    main()
