from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .models import Outcome, ScoredCandidate, Seed


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  target TEXT NOT NULL,
  config_json TEXT NOT NULL,
  status TEXT NOT NULL,
  stop_reason TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  root_seed_id TEXT NOT NULL,
  parent_id TEXT,
  generation INTEGER NOT NULL,
  prompt TEXT NOT NULL,
  category TEXT NOT NULL,
  operator TEXT NOT NULL,
  expected TEXT NOT NULL,
  success_indicators_json TEXT NOT NULL,
  frameworks_json TEXT NOT NULL DEFAULT '[]',
  control_ids_json TEXT NOT NULL DEFAULT '[]',
  technique_id TEXT NOT NULL DEFAULT '',
  technique_name TEXT NOT NULL DEFAULT '',
  external_technique_ids_json TEXT NOT NULL DEFAULT '[]',
  oracle TEXT NOT NULL DEFAULT 'manual',
  capability TEXT NOT NULL DEFAULT 'prompt',
  tags_json TEXT NOT NULL DEFAULT '[]',
  outcome TEXT NOT NULL,
  blocked INTEGER,
  guardrail_passed INTEGER,
  model_complied INTEGER,
  output_passed INTEGER,
  answer TEXT NOT NULL,
  reason TEXT NOT NULL,
  attack_type TEXT NOT NULL,
  risk_score REAL,
  http_status INTEGER,
  latency_ms REAL NOT NULL,
  estimated_cost_usd REAL NOT NULL,
  provider_cost_usd REAL,
  metadata_json TEXT NOT NULL,
  semantic_similarity REAL NOT NULL,
  novelty REAL NOT NULL,
  fitness REAL NOT NULL,
  selected INTEGER NOT NULL,
  FOREIGN KEY(run_id) REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS idx_candidates_run_gen ON candidates(run_id, generation);
CREATE INDEX IF NOT EXISTS idx_candidates_outcome ON candidates(outcome);
CREATE INDEX IF NOT EXISTS idx_candidates_technique ON candidates(run_id, technique_id);
CREATE TABLE IF NOT EXISTS operator_snapshots (
  run_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  stats_json TEXT NOT NULL,
  PRIMARY KEY(run_id, generation)
);
CREATE TABLE IF NOT EXISTS seeds (
  run_id TEXT NOT NULL,
  seed_id TEXT NOT NULL,
  prompt TEXT NOT NULL,
  category TEXT NOT NULL,
  technique TEXT NOT NULL,
  reasoning TEXT NOT NULL,
  expected TEXT NOT NULL,
  success_indicators_json TEXT NOT NULL,
  source TEXT NOT NULL,
  frameworks_json TEXT NOT NULL DEFAULT '[]',
  control_ids_json TEXT NOT NULL DEFAULT '[]',
  technique_id TEXT NOT NULL DEFAULT '',
  technique_name TEXT NOT NULL DEFAULT '',
  external_technique_ids_json TEXT NOT NULL DEFAULT '[]',
  oracle TEXT NOT NULL DEFAULT 'manual',
  capability TEXT NOT NULL DEFAULT 'prompt',
  tags_json TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(run_id, seed_id),
  FOREIGN KEY(run_id) REFERENCES runs(id)
);
CREATE TABLE IF NOT EXISTS manual_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id TEXT NOT NULL,
  reviewed_at TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  verdict TEXT NOT NULL,
  note TEXT NOT NULL,
  prior_outcome TEXT NOT NULL,
  FOREIGN KEY(candidate_id) REFERENCES candidates(id)
);
"""


MIGRATION_COLUMNS = {
    "candidates": {
        "frameworks_json": "TEXT NOT NULL DEFAULT '[]'",
        "control_ids_json": "TEXT NOT NULL DEFAULT '[]'",
        "technique_id": "TEXT NOT NULL DEFAULT ''",
        "technique_name": "TEXT NOT NULL DEFAULT ''",
        "external_technique_ids_json": "TEXT NOT NULL DEFAULT '[]'",
        "oracle": "TEXT NOT NULL DEFAULT 'manual'",
        "capability": "TEXT NOT NULL DEFAULT 'prompt'",
        "tags_json": "TEXT NOT NULL DEFAULT '[]'",
    },
    "seeds": {
        "frameworks_json": "TEXT NOT NULL DEFAULT '[]'",
        "control_ids_json": "TEXT NOT NULL DEFAULT '[]'",
        "technique_id": "TEXT NOT NULL DEFAULT ''",
        "technique_name": "TEXT NOT NULL DEFAULT ''",
        "external_technique_ids_json": "TEXT NOT NULL DEFAULT '[]'",
        "oracle": "TEXT NOT NULL DEFAULT 'manual'",
        "capability": "TEXT NOT NULL DEFAULT 'prompt'",
        "tags_json": "TEXT NOT NULL DEFAULT '[]'",
    },
}


def _bool(value: bool | None) -> int | None:
    return None if value is None else int(value)


class RunStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def connection(self):
        """Transactional connection that is always closed after use."""
        conn = self.connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        for table, columns in MIGRATION_COLUMNS.items():
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for name, definition in columns.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    def start_run(self, run_id: str, target: str, config: dict[str, object]) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO runs(id, created_at, target, config_json, status) VALUES(?,?,?,?,?)",
                (run_id, datetime.now(timezone.utc).isoformat(), target, json.dumps(config), "running"),
            )

    def save_seeds(self, run_id: str, seeds: list[Seed]) -> None:
        with self.connection() as conn:
            conn.executemany(
                """INSERT INTO seeds(
                  run_id,seed_id,prompt,category,technique,reasoning,expected,
                  success_indicators_json,source,frameworks_json,control_ids_json,
                  technique_id,technique_name,external_technique_ids_json,oracle,
                  capability,tags_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        run_id, seed.id, seed.prompt, seed.category, seed.technique,
                        seed.reasoning, seed.expected, json.dumps(seed.success_indicators), seed.source,
                        json.dumps(seed.frameworks), json.dumps(seed.control_ids), seed.technique_id,
                        seed.technique_name, json.dumps(seed.external_technique_ids), seed.oracle,
                        seed.capability, json.dumps(seed.tags),
                    )
                    for seed in seeds
                ],
            )

    def save_candidate(self, item: ScoredCandidate) -> None:
        c, e = item.candidate, item.evaluation
        with self.connection() as conn:
            conn.execute(
                """INSERT INTO candidates (
                  id, run_id, root_seed_id, parent_id, generation, prompt, category, operator,
                  expected, success_indicators_json, frameworks_json, control_ids_json,
                  technique_id, technique_name, external_technique_ids_json, oracle, capability,
                  tags_json, outcome, blocked, guardrail_passed, model_complied, output_passed,
                  answer, reason, attack_type, risk_score, http_status, latency_ms,
                  estimated_cost_usd, provider_cost_usd, metadata_json,
                  semantic_similarity, novelty, fitness, selected
                ) VALUES (
                  :id, :run_id, :root_seed_id, :parent_id, :generation, :prompt, :category,
                  :operator, :expected, :success_indicators_json, :frameworks_json,
                  :control_ids_json, :technique_id, :technique_name,
                  :external_technique_ids_json, :oracle, :capability, :tags_json,
                  :outcome, :blocked, :guardrail_passed, :model_complied, :output_passed,
                  :answer, :reason, :attack_type, :risk_score, :http_status, :latency_ms,
                  :estimated_cost_usd, :provider_cost_usd, :metadata_json,
                  :semantic_similarity, :novelty, :fitness, :selected
                )""",
                {
                    "id": c.id, "run_id": c.run_id, "root_seed_id": c.root_seed_id,
                    "parent_id": c.parent_id, "generation": c.generation, "prompt": c.prompt,
                    "category": c.category, "operator": c.operator, "expected": c.expected,
                    "success_indicators_json": json.dumps(c.success_indicators),
                    "frameworks_json": json.dumps(c.frameworks),
                    "control_ids_json": json.dumps(c.control_ids),
                    "technique_id": c.technique_id, "technique_name": c.technique_name,
                    "external_technique_ids_json": json.dumps(c.external_technique_ids),
                    "oracle": c.oracle, "capability": c.capability, "tags_json": json.dumps(c.tags),
                    "outcome": e.outcome.value, "blocked": _bool(e.blocked),
                    "guardrail_passed": _bool(e.guardrail_passed),
                    "model_complied": _bool(e.model_complied),
                    "output_passed": _bool(e.output_passed), "answer": e.answer,
                    "reason": e.reason, "attack_type": e.attack_type,
                    "risk_score": e.risk_score, "http_status": e.http_status,
                    "latency_ms": e.latency_ms, "estimated_cost_usd": e.estimated_cost_usd,
                    "provider_cost_usd": e.provider_cost_usd,
                    "metadata_json": json.dumps(e.metadata),
                    "semantic_similarity": item.semantic_similarity, "novelty": item.novelty,
                    "fitness": item.fitness, "selected": int(item.selected),
                },
            )

    def mark_selected(self, candidate_ids: list[str]) -> None:
        if not candidate_ids:
            return
        marks = ",".join("?" for _ in candidate_ids)
        with self.connection() as conn:
            conn.execute(f"UPDATE candidates SET selected=1 WHERE id IN ({marks})", candidate_ids)

    def save_operator_snapshot(self, run_id: str, generation: int, stats: dict[str, object]) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO operator_snapshots VALUES(?,?,?)",
                (run_id, generation, json.dumps(stats)),
            )

    def finish_run(self, run_id: str, status: str, stop_reason: str = "") -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE runs SET status=?, stop_reason=? WHERE id=?", (status, stop_reason, run_id)
            )

    def review_candidate(
        self, candidate_id: str, verdict: str, *, reviewer: str, note: str = ""
    ) -> None:
        if verdict not in {"success", "failure"}:
            raise ValueError("El veredicto debe ser success o failure.")
        with self.connection() as conn:
            row = conn.execute(
                """SELECT outcome, expected, guardrail_passed, output_passed, answer
                FROM candidates WHERE id=?""", (candidate_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"No existe el candidato {candidate_id}.")
            eligible_outcomes = {
                Outcome.ACCEPTED_UNVERIFIED.value,
                Outcome.MODEL_REFUSAL.value,
            }
            if (
                row["expected"] == "benign"
                or row["guardrail_passed"] != 1
                or row["output_passed"] != 1
                or not str(row["answer"]).strip()
                or row["outcome"] not in eligible_outcomes
            ):
                raise ValueError(
                    "Solo se pueden revisar respuestas adversariales que atravesaron entrada y salida."
                )
            conn.execute(
                """INSERT INTO manual_reviews(
                  candidate_id,reviewed_at,reviewer,verdict,note,prior_outcome
                ) VALUES(?,?,?,?,?,?)""",
                (
                    candidate_id, datetime.now(timezone.utc).isoformat(), reviewer,
                    verdict, note, row["outcome"],
                ),
            )
