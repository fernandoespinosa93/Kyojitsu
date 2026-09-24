from __future__ import annotations

import math
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


class BudgetExceeded(RuntimeError):
    pass


@contextmanager
def _sqlite_connection(path: Path, *, timeout: float = 5.0):
    conn = sqlite3.connect(path, timeout=timeout)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


@dataclass(slots=True)
class Budget:
    max_usd: float | None
    max_requests: int
    estimated_cost_per_request: float
    ledger_path: Path | None = None
    requests: int = 0
    estimated_spend_usd: float = 0.0
    reported_spend_usd: float = 0.0

    def __post_init__(self) -> None:
        values = (self.estimated_cost_per_request,) + (() if self.max_usd is None else (self.max_usd,))
        if not all(math.isfinite(value) and value >= 0 for value in values):
            raise ValueError("Los valores monetarios deben ser números finitos y no negativos.")
        if self.max_requests < 1:
            raise ValueError("max_requests debe ser mayor o igual a 1.")
        if self.ledger_path is not None:
            self.ledger_path = Path(self.ledger_path)
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with _sqlite_connection(self.ledger_path) as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS budget_ledger (id INTEGER PRIMARY KEY CHECK(id=1), estimated_spend REAL NOT NULL, requests INTEGER NOT NULL)"
                )
                conn.execute(
                    "INSERT OR IGNORE INTO budget_ledger(id, estimated_spend, requests) VALUES(1,0,0)"
                )

    def reserve(self) -> float:
        if self.requests >= self.max_requests:
            raise BudgetExceeded(f"Se alcanzó el límite de {self.max_requests} solicitudes.")
        projected = self.estimated_spend_usd + self.estimated_cost_per_request
        if self.ledger_path is not None:
            with _sqlite_connection(self.ledger_path, timeout=30) as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT estimated_spend, requests FROM budget_ledger WHERE id=1"
                ).fetchone()
                cumulative = float(row[0])
                if self.max_usd is not None and cumulative + self.estimated_cost_per_request > self.max_usd + 1e-12:
                    raise BudgetExceeded(
                        f"La siguiente solicitud superaría el límite estimado acumulado de USD ${self.max_usd:.2f}."
                    )
                conn.execute(
                    "UPDATE budget_ledger SET estimated_spend=?, requests=? WHERE id=1",
                    (cumulative + self.estimated_cost_per_request, int(row[1]) + 1),
                )
        elif self.max_usd is not None and projected > self.max_usd + 1e-12:
            raise BudgetExceeded(
                f"La siguiente solicitud superaría el límite estimado de USD ${self.max_usd:.2f}."
            )
        self.requests += 1
        self.estimated_spend_usd = projected
        return self.estimated_cost_per_request

    def record_provider_cost(self, amount: float | None) -> None:
        if amount is not None and math.isfinite(amount) and amount >= 0:
            self.reported_spend_usd += amount

    def cumulative_estimated_spend(self) -> float:
        if self.ledger_path is None:
            return self.estimated_spend_usd
        with _sqlite_connection(self.ledger_path) as conn:
            row = conn.execute(
                "SELECT estimated_spend FROM budget_ledger WHERE id=1"
            ).fetchone()
        return float(row[0])

    def snapshot(self) -> dict[str, float | int]:
        return {
            "requests": self.requests,
            "max_requests": self.max_requests,
            "estimated_spend_usd": round(self.estimated_spend_usd, 6),
            "cumulative_estimated_spend_usd": round(self.cumulative_estimated_spend(), 6),
            "reported_spend_usd": round(self.reported_spend_usd, 6),
            "max_usd": self.max_usd,
            "estimated_cost_per_request": self.estimated_cost_per_request,
        }
