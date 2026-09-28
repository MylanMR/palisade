"""Human-readable descriptions of models and settings for the Runtime panel."""
from __future__ import annotations

import re
from typing import Any

_QUANT = re.compile(r"[._-](I?Q\d(?:_[A-Z0-9]+)*|F16|BF16|F32)(?=\.gguf$)", re.IGNORECASE)


_BRANDS = {"shieldgemma": "ShieldGemma", "olmo": "OLMo", "gemma": "Gemma", "granite": "Granite"}


def quant_of(filename: str) -> str:
    m = _QUANT.search(filename or "")
    return m.group(1).upper() if m else "unknown"


def label_of(model_id: str, meta: dict[str, Any]) -> str:
    """Prefer an explicit `label` in models.yaml; otherwise derive one from the file name."""
    if meta.get("label"):
        return str(meta["label"])
    stem = re.sub(r"\.gguf$", "", meta.get("file", model_id), flags=re.IGNORECASE)
    stem = _QUANT.sub("", stem + ".gguf").removesuffix(".gguf") if _QUANT.search(stem + ".gguf") else stem
    stem = re.sub(r"[-_.](it|instruct)$", "", stem, flags=re.IGNORECASE)
    words = [w for w in re.split(r"[-_]+", stem) if w]
    out = []
    for w in words:
        if re.fullmatch(r"\d+(\.\d+)?[bBmM]", w):
            out.append(w[:-1] + w[-1].upper())
        elif w.isdigit() or re.fullmatch(r"[eE]\d+[bB]", w):
            out.append(w.upper() if not w.isdigit() else w)
        elif w.lower() in _BRANDS:
            out.append(_BRANDS[w.lower()])
        else:
            out.append(w[:1].upper() + w[1:])
    return " ".join(out)


BACKEND_LABEL = {"metal": "Metal GPU", "cuda": "CUDA GPU", "vulkan": "Vulkan GPU", "cpu": "CPU"}


def mode_text(mode: str) -> str:
    return {"combined": "one check covering all categories",
            "per_category": "one check per category (slower, names the category)"}.get(mode, mode)
