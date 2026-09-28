"""Append-only, hash-chained audit log.

Each record is one JSON line. Its `hash` is SHA-256 over (previous record hash +
canonical JSON of the record without `hash`). Deleting, reordering, or editing any
record breaks the chain from that point forward, which `verify()` reports.

Files rotate by size. The first record of a new file carries the last hash of the
previous file in `prev_hash`, so the chain spans files.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator

from . import canonical_json, sha256_text, secure_mkdir, FILE_MODE, DIR_MODE, POSIX

GENESIS = "0" * 64


@dataclass
class GuardianVerdict:
    stage: str                 # input | output
    model: str
    mode: str                  # combined | per_category
    p_violation: float
    threshold: float
    violated: bool
    categories: list[str] = field(default_factory=list)   # attributed categories (per_category mode)
    action: str = "allow"      # block | flag | allow
    latency_ms: int = 0


@dataclass
class AuditRecord:
    seq: int
    ts: str
    request_id: str
    manifest_hash: str
    policy_version: str
    base_model: str
    guardian_model: str
    decision: str              # answered | blocked_input | blocked_output | flagged
    prompt_sha256: str
    response_sha256: str
    verdicts: list[dict]
    latency_ms: int
    prompt: str | None = None
    response: str | None = None
    prev_hash: str = GENESIS
    hash: str = ""


class AuditLog:
    def __init__(self, directory: Path, rotate_mb: int = 64,
                 file_mode: int = FILE_MODE, dir_mode: int = DIR_MODE):
        self.dir = Path(directory)
        self.file_mode, self.dir_mode = file_mode, dir_mode
        secure_mkdir(self.dir, dir_mode)
        self.rotate_bytes = rotate_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._seq, self._last_hash, self._current = self._recover()

    # ---- state recovery ----
    def _files(self) -> list[Path]:
        return sorted(self.dir.glob("audit-*.jsonl"))

    def _recover(self) -> tuple[int, str, Path | None]:
        files = self._files()
        if not files:
            return 0, GENESIS, None   # first file is created on first append
        last = files[-1]
        seq, h = 0, GENESIS
        for rec in self._iter_file(last):
            seq, h = rec["seq"], rec["hash"]
        if seq == 0:  # empty last file; look further back
            for f in reversed(files[:-1]):
                for rec in self._iter_file(f):
                    seq, h = rec["seq"], rec["hash"]
                if seq:
                    break
        return seq, h, last

    def _new_file(self) -> Path:
        p = self.dir / f"audit-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.jsonl"
        # Create with the restrictive mode from the start so the file is never world-readable.
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, self.file_mode)
        os.close(fd)
        if POSIX:
            os.chmod(p, self.file_mode)
        return p

    def apply_permissions(self) -> list[str]:
        """Bring existing audit files and the directory to the configured modes.
        Returns a list of paths that could not be changed (owned by another account)."""
        failed = []
        if not POSIX:
            return failed
        for target, mode in [(self.dir, self.dir_mode)] + [(f, self.file_mode) for f in self._files()]:
            try:
                os.chmod(target, mode)
            except PermissionError:
                failed.append(str(target))
        return failed

    @staticmethod
    def _iter_file(path: Path) -> Iterator[dict]:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    # ---- writing ----
    @staticmethod
    def compute_hash(prev_hash: str, record: dict[str, Any]) -> str:
        body = {k: v for k, v in record.items() if k != "hash"}
        return sha256_text(prev_hash + canonical_json(body))

    def append(self, rec: AuditRecord) -> AuditRecord:
        with self._lock:
            if self._current is None or self._current.stat().st_size >= self.rotate_bytes:
                self._current = self._new_file()
            self._seq += 1
            rec.seq = self._seq
            rec.prev_hash = self._last_hash
            d = asdict(rec)
            d["hash"] = self.compute_hash(self._last_hash, d)
            with open(self._current, "a", encoding="utf-8") as f:
                f.write(canonical_json(d) + "\n")
                f.flush()
            self._last_hash = d["hash"]
            rec.hash = d["hash"]
            return rec

    # ---- reading ----
    def tail(self, n: int = 50) -> list[dict]:
        out: list[dict] = []
        for f in reversed(self._files()):
            out = list(self._iter_file(f)) + out
            if len(out) >= n:
                break
        return out[-n:]

    def records(self, decision: str | None = None, limit: int = 100,
                before_seq: int | None = None) -> list[dict]:
        """Newest-first page of records, optionally filtered by decision.
        decision may be a single value or 'blocked' (either blocked stage)."""
        out: list[dict] = []
        for f in reversed(self._files()):
            for rec in reversed(list(self._iter_file(f))):
                if before_seq is not None and rec["seq"] >= before_seq:
                    continue
                d = rec.get("decision")
                if decision == "blocked" and not str(d).startswith("blocked"):
                    continue
                if decision and decision != "blocked" and d != decision:
                    continue
                out.append(rec)
                if len(out) >= limit:
                    return out
        return out

    def all_records(self) -> Iterator[dict]:
        for f in self._files():
            yield from self._iter_file(f)

    def verify(self) -> dict[str, Any]:
        """Walk every file in order and recompute the chain."""
        prev, count, first_bad = GENESIS, 0, None
        expected_seq = 0
        for f in self._files():
            for rec in self._iter_file(f):
                expected_seq += 1
                ok = (rec.get("prev_hash") == prev
                      and rec.get("seq") == expected_seq
                      and self.compute_hash(prev, rec) == rec.get("hash"))
                if not ok and first_bad is None:
                    first_bad = {"file": f.name, "seq": rec.get("seq")}
                prev = rec.get("hash", "")
                count += 1
        return {"records": count, "intact": first_bad is None, "first_break": first_bad,
                "head_hash": prev}


def new_request_id() -> str:
    return uuid.uuid4().hex


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
