"""Launch and supervise llama-server processes for the base and guardian models.

Each model server is locked down so that only Palisade can use it. Otherwise any program
on the machine, or a web page in a browser, could send prompts straight to the model and
skip the guardian and the audit log.

  - macOS and Linux: the server listens on a Unix socket inside a folder only Palisade's
    account can open (mode 0700). No TCP port exists, so nothing can squat on the port
    or connect from another account.
  - Windows: the server listens on 127.0.0.1. Palisade checks the port is free before
    starting and that the server answering is the process it started.
  - Every platform: a fresh random API key per launch, passed in the environment, because
    other accounts can read a command line from the process list.
  - The environment is rebuilt from an allowlist. llama-server reads LLAMA_ARG_* variables,
    one of which turns on built-in shell and file tools; none of those pass through.
  - Flags turn off the web UI, the slots endpoint, network downloads, agent tools, and
    pin CORS to an origin no browser can have.
"""
from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import httpx

from . import LOGS_DIR, STATE_DIR, POSIX, read_lock, secure_mkdir, server_dir
from .hardware import Host, threads, gpu_layers

# Environment variables a model server may inherit. Everything else is dropped.
ENV_ALLOW = {
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TEMP", "TMP",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "LOCALAPPDATA",
    "APPDATA", "PROGRAMDATA", "PROGRAMFILES", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "XDG_RUNTIME_DIR",
    # GPU device selection only
    "CUDA_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES", "GGML_VK_VISIBLE_DEVICES", "VK_ICD_FILENAMES",
    "VK_DRIVER_FILES",
}

LOCKDOWN_FLAGS = [
    "--no-webui",
    "--no-slots",
    "--offline",
    "--no-agent",
    "--cors-origins", "http://palisade.invalid",
    "--timeout", "900",
]

UDS_MAX = 100   # sun_path is 104 bytes on macOS, 108 on Linux


def clean_env(base: Optional[dict] = None) -> dict[str, str]:
    src = os.environ if base is None else base
    return {k: v for k, v in src.items() if k.upper() in ENV_ALLOW}


def socket_dir() -> Path:
    """A private folder for the model-server sockets."""
    d = STATE_DIR / "run"
    if len(str(d / "guardian.sock")) <= UDS_MAX:
        try:
            secure_mkdir(d, 0o700)
            os.chmod(d, 0o700)
            return d
        except OSError:
            pass
    return Path(tempfile.mkdtemp(prefix="palisade-"))   # mkdtemp is mode 0700


class Endpoint:
    """Where a model server listens and how to call it. Clients made here carry the key."""

    def __init__(self, url: str = "http://model", uds: Optional[Path] = None, api_key: str = ""):
        self.uds, self.api_key = uds, api_key
        self.url = "http://model" if uds else url.rstrip("/")

    @property
    def transport(self) -> str:
        return "private socket" if self.uds else "loopback with key"

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

    def client(self, timeout: float) -> httpx.Client:
        kw: dict[str, Any] = {"base_url": self.url, "headers": self.headers, "timeout": timeout}
        if self.uds:
            kw["transport"] = httpx.HTTPTransport(uds=str(self.uds))
        return httpx.Client(**kw)


def as_endpoint(x: Any) -> Any:
    """Accept an Endpoint, or a plain URL (tests and older callers)."""
    return Endpoint(url=x) if isinstance(x, str) else x


def server_binary(host: Host) -> Path:
    tag = read_lock().get("llama_cpp", {}).get("tag")
    if not tag:
        raise RuntimeError("manifest.lock has no llama_cpp entry; run: palisade install")
    name = "llama-server.exe" if host.os == "windows" else "llama-server"
    p = server_dir(tag) / name
    if not p.exists():
        raise RuntimeError(f"{p} missing; run: palisade install")
    return p


def _port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


class LlamaProcess:
    def __init__(self, name: str, binary: Path, model: Path, port: int, host: Host,
                 settings: dict, ctx: int, use_socket: Optional[bool] = None):
        rt = settings["runtime"]
        self.name, self.port, self.model = name, port, model
        self.api_key = secrets.token_urlsafe(32)
        self.use_socket = POSIX if use_socket is None else use_socket
        if self.use_socket:
            self.sock = socket_dir() / f"{name}.sock"
            listen = ["--host", str(self.sock)]
        else:
            self.sock = None
            listen = ["--host", "127.0.0.1", "--port", str(port)]
        self.cmd = [
            str(binary),
            "--model", str(model),
            *listen,
            "--ctx-size", str(ctx),
            "--threads", str(threads(host, rt["threads"])),
            "--n-gpu-layers", str(gpu_layers(host, rt["gpu_layers"])),
            "--parallel", "1",
            *LOCKDOWN_FLAGS,
        ]
        self.proc: subprocess.Popen | None = None
        # Logs go to the writable logs directory, never next to the (read-only) models.
        self.log = secure_mkdir(LOGS_DIR) / f"{name}-server.log"
        self.endpoint = Endpoint(url=f"http://127.0.0.1:{port}", uds=self.sock, api_key=self.api_key)

    def start(self) -> None:
        if self.sock is not None:
            try:
                self.sock.unlink()          # stale socket from an unclean stop
            except FileNotFoundError:
                pass
        elif not _port_free(self.port):
            raise RuntimeError(f"port {self.port} is already in use on 127.0.0.1; another program may be "
                               f"impersonating the {self.name} model server. Stop it, or change "
                               f"runtime.{'base' if self.name == 'base' else 'guardian'}_port in settings.yaml.")
        env = clean_env()
        env["LLAMA_API_KEY"] = self.api_key
        # Shared libraries sit next to the binary.
        libdir = str(Path(self.cmd[0]).parent)
        env["LD_LIBRARY_PATH"] = libdir
        env["DYLD_LIBRARY_PATH"] = libdir
        creationflags = 0
        if sys.platform == "win32":
            # no console window when Palisade itself runs without one (desktop launcher, service)
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x08000000  # CREATE_NO_WINDOW
        self.proc = subprocess.Popen(
            self.cmd, stdout=open(self.log, "ab"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            env=env, creationflags=creationflags,
        )

    def _verify_identity(self, client: httpx.Client) -> None:
        """The server answering must be ours: it refuses a request without the key and
        accepts one with it. An impostor that answers everything fails the first test."""
        with Endpoint(self.endpoint.url, self.endpoint.uds, api_key="").client(5) as anon:
            r_no = anon.get("/v1/models")
        if r_no.status_code != 401:
            raise RuntimeError(f"{self.name} model server accepted a request without its key; refusing to use it")
        r_yes = client.get("/v1/models")
        if r_yes.status_code != 200:
            raise RuntimeError(f"{self.name} model server rejected Palisade's key (HTTP {r_yes.status_code})")
        if self.proc is not None and self.proc.poll() is not None:
            raise RuntimeError(f"{self.name} llama-server exited; see {self.log}")

    def wait_healthy(self, timeout: int) -> None:
        deadline = time.time() + timeout
        client = self.endpoint.client(2)
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} llama-server exited early; see {self.log}")
            try:
                if client.get("/health").status_code == 200:
                    self._verify_identity(client)
                    return
            except httpx.HTTPError:
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
        if self.sock is not None:
            try:
                self.sock.unlink()
            except OSError:
                pass

    @property
    def url(self) -> str:
        return self.endpoint.url
