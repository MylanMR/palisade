"""Detect the host platform and pick a llama.cpp backend and a model tier."""
from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass, asdict

import psutil


@dataclass
class Host:
    os: str            # macos | linux | windows
    arch: str          # arm64 | x64
    ram_gb: float
    cores: int
    gpu: str           # none | nvidia | amd | intel | apple
    vram_gb: float
    backend: str       # metal | cuda | vulkan | cpu
    asset_key: str     # key into models.yaml llama_cpp.assets

    def as_dict(self) -> dict:
        return asdict(self)


def _os() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s == "windows":
        return "windows"
    return "linux"


def _arch() -> str:
    m = platform.machine().lower()
    return "arm64" if m in ("arm64", "aarch64") else "x64"


def _nvidia_vram_gb() -> float:
    if not shutil.which("nvidia-smi"):
        return 0.0
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip().splitlines()
        return max(float(x) for x in out) / 1024 if out else 0.0
    except Exception:
        return 0.0


def _other_gpu(os_name: str) -> str:
    """Best-effort detection of AMD or Intel discrete GPUs without vendor tooling."""
    try:
        if os_name == "linux" and shutil.which("lspci"):
            out = subprocess.run(["lspci"], capture_output=True, text=True, timeout=10).stdout.lower()
            vga = [l for l in out.splitlines() if "vga" in l or "3d controller" in l or "display" in l]
            joined = " ".join(vga)
            if "amd" in joined or "radeon" in joined:
                return "amd"
            if "arc" in joined and "intel" in joined:
                return "intel"
        if os_name == "windows":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=20,
            ).stdout.lower()
            if "radeon" in out or "amd" in out:
                return "amd"
            if "arc" in out:
                return "intel"
    except Exception:
        pass
    return "none"


def detect() -> Host:
    os_name, arch = _os(), _arch()
    ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    cores = psutil.cpu_count(logical=False) or psutil.cpu_count() or 2

    if os_name == "macos":
        gpu = "apple" if arch == "arm64" else "none"
        backend = "metal" if arch == "arm64" else "cpu"
        # Apple silicon shares RAM with the GPU; treat ~70% as usable for models.
        vram = ram_gb * 0.7 if arch == "arm64" else 0.0
        return Host(os_name, arch, ram_gb, cores, gpu, vram, backend, f"macos-{arch}")

    vram = _nvidia_vram_gb()
    if vram > 0:
        gpu = "nvidia"
        backend = "cuda" if os_name == "windows" else "vulkan"
    else:
        gpu = _other_gpu(os_name)
        backend = "vulkan" if gpu in ("amd", "intel") else "cpu"
        vram = 0.0

    return Host(os_name, arch, ram_gb, cores, gpu, vram, backend, f"{os_name}-{arch}-{backend}")


def choose_tier(host: Host, tiers: dict, override: str = "auto") -> str:
    if override and override != "auto":
        if override not in tiers:
            raise ValueError(f"tier '{override}' not defined in models.yaml")
        return override
    if host.ram_gb >= tiers["standard"]["min_ram_gb"] or host.vram_gb >= 8:
        return "standard"
    return "small"


def threads(host: Host, setting) -> int:
    if setting == "auto":
        return max(1, host.cores - 1)
    return int(setting)


def gpu_layers(host: Host, setting) -> int:
    if setting == "auto":
        return 999 if host.backend != "cpu" else 0
    return int(setting)
