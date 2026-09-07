"""Launch and supervise llama-server processes for the base and guardian models."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

from . import BIN_DIR, read_lock
from .hardware import Host, threads, gpu_layers


def server_binary(host: Host) -> Path:
    tag = read_lock().get("llama_cpp", {}).get("tag")
    if not tag:
        raise RuntimeError("manifest.lock has no llama_cpp entry; run: palisade install")
    name = "llama-server.exe" if host.os == "windows" else "llama-server"
    p = BIN_DIR / tag / name
    if not p.exists():
        raise RuntimeError(f"{p} missing; run: palisade install")
    return p


class LlamaProcess:
    def __init__(self, name: str, binary: Path, model: Path, port: int, host: Host,
                 settings: dict, ctx: int):
        rt = settings["runtime"]
        self.name, self.port = name, port
        self.cmd = [
            str(binary),
            "--model", str(model),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--ctx-size", str(ctx),
            "--threads", str(threads(host, rt["threads"])),
            "--n-gpu-layers", str(gpu_layers(host, rt["gpu_layers"])),
            "--parallel", "1",
            "--no-webui",
        ]
        self.proc: subprocess.Popen | None = None
        self.log = model.parent / f"{name}-server.log"

    def start(self) -> None:
        env = dict(os.environ)
        # Shared libraries sit next to the binary.
        env["LD_LIBRARY_PATH"] = str(Path(self.cmd[0]).parent) + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        env["DYLD_LIBRARY_PATH"] = str(Path(self.cmd[0]).parent)
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        self.proc = subprocess.Popen(
            self.cmd, stdout=open(self.log, "ab"), stderr=subprocess.STDOUT,
            env=env, creationflags=creationflags,
        )

    def wait_healthy(self, timeout: int) -> None:
        deadline = time.time() + timeout
        url = f"http://127.0.0.1:{self.port}/health"
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} llama-server exited early; see {self.log}")
            try:
                if httpx.get(url, timeout=2).status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError(f"{self.name} llama-server did not become healthy in {timeout}s; see {self.log}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"
