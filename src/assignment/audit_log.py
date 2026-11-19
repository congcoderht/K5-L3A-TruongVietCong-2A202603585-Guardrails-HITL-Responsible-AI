"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Start an auditable request record and return its request ID."""
        request_id = request_id or uuid.uuid4().hex
        started_at = utc_now_iso()
        self.logs.append({
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "started_at": started_at,
            "output": None,
            "blocked": False,
            "layer": None,
            "latency_ms": None,
        })
        self._open[request_id] = (len(self.logs) - 1, time.perf_counter())
        return request_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete a request record with output and decision metadata."""
        opened = self._open.pop(request_id, None) if request_id else None
        if opened is None:
            opened = next(
                ((idx, started) for key, (idx, started) in reversed(list(self._open.items()))
                 if self.logs[idx].get("user_id") == user_id),
                None,
            )
            if opened is not None:
                request_id = self.logs[opened[0]]["request_id"]
                self._open.pop(request_id, None)

        if opened is None:
            request_id = request_id or uuid.uuid4().hex
            entry = {
                "request_id": request_id,
                "user_id": user_id,
                "input": None,
                "started_at": utc_now_iso(),
            }
            self.logs.append(entry)
            elapsed = 0.0
        else:
            index, started = opened
            entry = self.logs[index]
            elapsed = (time.perf_counter() - started) * 1000

        entry.update({
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "completed_at": utc_now_iso(),
            "latency_ms": round(elapsed, 3),
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
