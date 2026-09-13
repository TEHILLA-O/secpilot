from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from secpilot.config.settings import AppPaths
from secpilot.models import SessionEvent


class SessionRecord(BaseModel):
    session_id: str
    label: str
    target: str
    mode: str
    created_at: datetime
    directory: str
    findings: int = 0


class SessionStore:
    def __init__(self, paths: AppPaths | None = None) -> None:
        self.paths = paths or AppPaths()
        self.paths.ensure()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.paths.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    directory TEXT NOT NULL,
                    findings INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.commit()

    def create(self, session_id: str, label: str, target: str, mode: str) -> SessionRecord:
        stamp = datetime.now(UTC)
        slug = f"{stamp.date().isoformat()}-{label}"
        directory = self.paths.sessions_dir / slug
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "events.jsonl").touch()
        record = SessionRecord(
            session_id=session_id,
            label=label,
            target=target,
            mode=mode,
            created_at=stamp,
            directory=str(directory),
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions
                (session_id, label, target, mode, created_at, directory, findings)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.session_id,
                    record.label,
                    record.target,
                    record.mode,
                    record.created_at.isoformat(),
                    record.directory,
                    0,
                ),
            )
            conn.commit()
        return record

    def get(self, session_id: str) -> SessionRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ? OR label = ?",
                (session_id, session_id),
            ).fetchone()
        if row is None:
            return None
        return SessionRecord(
            session_id=row["session_id"],
            label=row["label"],
            target=row["target"],
            mode=row["mode"],
            created_at=datetime.fromisoformat(row["created_at"]),
            directory=row["directory"],
            findings=row["findings"],
        )

    def list(self) -> list[SessionRecord]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
        return [
            SessionRecord(
                session_id=row["session_id"],
                label=row["label"],
                target=row["target"],
                mode=row["mode"],
                created_at=datetime.fromisoformat(row["created_at"]),
                directory=row["directory"],
                findings=row["findings"],
            )
            for row in rows
        ]

    def set_findings(self, session_id: str, count: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET findings = ? WHERE session_id = ?",
                (count, session_id),
            )
            conn.commit()

    def append_event(self, directory: str, event: SessionEvent) -> None:
        path = Path(directory) / "events.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")

    def events(self, directory: str) -> list[SessionEvent]:
        path = Path(directory) / "events.jsonl"
        if not path.exists():
            return []
        items: list[SessionEvent] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(SessionEvent.model_validate_json(line))
        return items
