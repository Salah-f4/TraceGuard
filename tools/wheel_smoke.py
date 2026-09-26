"""Independent installed-wheel smoke with blocked networking and isolated cwd."""

import json
import os
import socket
import sys
import tempfile
from pathlib import Path
from typing import NoReturn


def main() -> None:
    original_pair = socket.socketpair
    allow_wakeup = False

    def audit(event: str, args: tuple[object, ...]) -> None:
        if (
            event in {"socket.connect", "socket.getaddrinfo", "socket.bind", "subprocess.Popen"}
            and not allow_wakeup
        ):
            raise RuntimeError("Network/process access blocked in installed-wheel smoke.")

    sys.addaudithook(audit)

    def wakeup_pair() -> tuple[socket.socket, socket.socket]:
        nonlocal allow_wakeup
        allow_wakeup = True
        try:
            return original_pair()
        finally:
            allow_wakeup = False

    wakeup_name = "socketpair"
    setattr(socket, wakeup_name, wakeup_pair)
    for name in tuple(os.environ):
        if name.startswith("TRACEGUARD_"):
            del os.environ[name]
    import httpx
    from typer.testing import CliRunner

    from traceguard.adapters.cli.app import app
    from traceguard.core import scoring

    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        raise RuntimeError("HTTP blocked in installed-wheel smoke.")

    async def async_forbidden(*args: object, **kwargs: object) -> NoReturn:
        forbidden()

    sync_method = "handle_request"
    setattr(httpx.HTTPTransport, sync_method, forbidden)
    async_method = "handle_async_request"
    setattr(httpx.AsyncHTTPTransport, async_method, async_forbidden)
    assert Path(scoring.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    try:
        socket.getaddrinfo("example.invalid", 443)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Network guard not active.")
    with tempfile.TemporaryDirectory(prefix="traceguard-wheel-") as tmp:
        os.chdir(tmp)
        runner = CliRunner()
        assert runner.invoke(app, ["--help"]).exit_code == 0
        result = runner.invoke(app, ["analyze", "--text", "192.0.2.1", "--format", "json"])
        assert result.exit_code == 0
        assert json.loads(result.stdout)["schema_version"] == "1.2"
        result = runner.invoke(
            app,
            [
                "analyze",
                "--text",
                "192.0.2.1",
                "--ai",
                "--format",
                "json",
                "--output",
                "report.json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(Path("report.json").read_text(encoding="utf-8"))
        assert data["ai_reporting"]["attempts"] == 0
        assert data["ai_reporting"]["origin"] == "deterministic_fallback"
        os.chdir(sys.prefix)
    print("Installed wheel: help, offline JSON, AI fallback, export and network-denial passed.")


if __name__ == "__main__":
    main()
