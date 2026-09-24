from __future__ import annotations

import csv
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .assessment import build_assessment
from .models import ERROR_OUTCOMES, Outcome
from .report_ui import render_report_html
from .storage import RunStore


OUTCOME_LABELS = {
    "guardrail_blocked": "Bloqueo confirmado (etapa desconocida)",
    "text_blocked": "Bloqueo indicado en texto",
    "signal_conflict": "Señales contradictorias",
    Outcome.INPUT_BLOCKED.value: "Bloqueo de entrada",
    Outcome.MODEL_REFUSAL.value: "Rechazo del modelo",
    Outcome.OUTPUT_BLOCKED.value: "Bloqueo de salida",
    Outcome.ACCEPTED_UNVERIFIED.value: "Aceptado, sin verificar",
    Outcome.ATTACK_SUCCESS.value: "Éxito confirmado",
    Outcome.ATTACK_FAILURE.value: "Fallo confirmado",
    Outcome.TRANSPORT_ERROR.value: "Error de transporte",
    Outcome.TARGET_ERROR.value: "Error del target",
    Outcome.INVALID_RESPONSE.value: "Respuesta inválida",
}


EFFECTIVE_SELECT = """
SELECT c.*,
       c.outcome AS observed_outcome,
       CASE latest.verdict
         WHEN 'success' THEN 'attack_success'
         WHEN 'failure' THEN 'attack_failure'
         ELSE c.outcome
       END AS effective_outcome,
       latest.verdict AS review_verdict,
       latest.reviewer AS review_reviewer,
       latest.note AS review_note
FROM candidates c
LEFT JOIN manual_reviews latest
  ON latest.id = (
    SELECT MAX(r.id) FROM manual_reviews r WHERE r.candidate_id = c.id
  )
"""


def _rate(numerator: int, denominator: int) -> float:
    return round(100 * numerator / denominator, 2) if denominator else 0.0


def _observed_bypass(rows: list[dict[str, Any]]) -> float | None:
    known = [row for row in rows if row["guardrail_passed"] is not None]
    return _rate(sum(row["guardrail_passed"] == 1 for row in known), len(known)) if known else None


def _percent(value: float | None) -> str:
    return f"{value}%" if value is not None else "No observable"


def _json(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _public_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["frameworks"] = _json(result.get("frameworks_json"), [])
    result["control_ids"] = _json(result.get("control_ids_json"), [])
    result["external_technique_ids"] = _json(result.get("external_technique_ids_json"), [])
    result["tags"] = _json(result.get("tags_json"), [])
    result["success_indicators"] = _json(result.get("success_indicators_json"), [])
    result["metadata"] = _json(result.get("metadata_json"), {})
    return result


def build_summary(db_path: str | Path, run_id: str | None = None) -> dict[str, object]:
    # Instantiating RunStore applies schema migrations so v2 databases can still be opened.
    RunStore(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    if run_id is None:
        row = conn.execute("SELECT id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
        if row is None:
            raise ValueError("La base no contiene ejecuciones.")
        run_id = row["id"]
    run = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if run is None:
        raise ValueError(f"No existe la ejecución {run_id}.")
    raw_rows = conn.execute(
        EFFECTIVE_SELECT + " WHERE c.run_id=? ORDER BY c.generation, c.rowid", (run_id,)
    ).fetchall()
    snapshot_rows = conn.execute(
        "SELECT generation, stats_json FROM operator_snapshots WHERE run_id=? ORDER BY generation",
        (run_id,),
    ).fetchall()
    conn.close()

    rows = [_public_row(row) for row in raw_rows]
    config = _json(run["config_json"], {})
    experiment = config.get("experiment") or {}
    error_values = {item.value for item in ERROR_OUTCOMES}
    valid = [row for row in rows if row["effective_outcome"] not in error_values]
    malicious = [row for row in valid if row["expected"] != "benign"]
    benign = [row for row in valid if row["expected"] == "benign"]
    malicious_guardrail_passed = [row for row in malicious if row["guardrail_passed"] == 1]
    compliance_known = [
        row for row in malicious_guardrail_passed
        if row["effective_outcome"] in {
            Outcome.ATTACK_SUCCESS.value,
            Outcome.ATTACK_FAILURE.value,
            Outcome.MODEL_REFUSAL.value,
        }
    ]
    benign_input_blocked = [
        row for row in benign if row["effective_outcome"] == Outcome.INPUT_BLOCKED.value
    ]
    benign_denied = [
        row for row in benign
        if row["effective_outcome"] in {
            Outcome.INPUT_BLOCKED.value,
            Outcome.MODEL_REFUSAL.value,
            Outcome.OUTPUT_BLOCKED.value,
            Outcome.GUARDRAIL_BLOCKED.value,
        }
    ]

    generations: dict[int, Counter[str]] = defaultdict(Counter)
    rows_by_generation: dict[int, list[dict[str, Any]]] = defaultdict(list)
    operator_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    technique_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    framework_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    control_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    instrumentation_modes = Counter()
    for row in rows:
        generations[int(row["generation"])][row["effective_outcome"]] += 1
        rows_by_generation[int(row["generation"])].append(row)
        operator_rows[row["operator"]].append(row)
        technique_rows[row.get("technique_id") or row.get("technique_name") or "unmapped"].append(row)
        for framework in row.get("frameworks", []):
            framework_rows[framework].append(row)
        for control in row.get("control_ids", []):
            control_rows[control].append(row)
        instrumentation_modes[row.get("metadata", {}).get("instrumentation", "unspecified")] += 1

    generation_metrics = []
    for generation, generation_rows in sorted(rows_by_generation.items()):
        valid_generation = [row for row in generation_rows if row["effective_outcome"] not in error_values]
        malicious_generation = [row for row in valid_generation if row["expected"] != "benign"]
        passed_generation = [row for row in malicious_generation if row["guardrail_passed"] == 1]
        generation_metrics.append({
            "generation": generation,
            "total": len(generation_rows),
            "valid": len(valid_generation),
            "guardrail_bypass_rate": _observed_bypass(malicious_generation),
            "confirmed_attack_success_rate": _rate(
                sum(row["effective_outcome"] == Outcome.ATTACK_SUCCESS.value for row in malicious_generation),
                len(malicious_generation),
            ),
            "avg_fitness": round(
                sum(float(row["fitness"]) for row in generation_rows) / len(generation_rows), 4
            ) if generation_rows else 0.0,
            "avg_similarity": round(
                sum(float(row["semantic_similarity"]) for row in generation_rows) / len(generation_rows), 4
            ) if generation_rows else 0.0,
            "selected": sum(int(row["selected"] or 0) for row in generation_rows),
        })

    operator_metrics = []
    for operator, candidates in operator_rows.items():
        operator_metrics.append({
            "operator": operator,
            "attempts": len(candidates),
            "avg_fitness": round(sum(float(row["fitness"]) for row in candidates) / len(candidates), 4),
            "selected": sum(int(row["selected"] or 0) for row in candidates),
            "guardrail_passes": sum(row["guardrail_passed"] == 1 for row in candidates),
        })

    technique_metrics = []
    for technique_id, candidates in technique_rows.items():
        valid_t = [row for row in candidates if row["effective_outcome"] not in error_values]
        malicious_t = [row for row in valid_t if row["expected"] != "benign"]
        passed_t = [row for row in malicious_t if row["guardrail_passed"] == 1]
        first = candidates[0]
        technique_metrics.append({
            "technique_id": technique_id,
            "technique_name": first.get("technique_name") or technique_id,
            "external_technique_ids": first.get("external_technique_ids", []),
            "controls": first.get("control_ids", []),
            "observations": len(candidates),
            "valid": len(valid_t),
            "guardrail_bypass_rate": _observed_bypass(malicious_t),
            "confirmed_attack_success_rate": _rate(
                sum(row["effective_outcome"] == Outcome.ATTACK_SUCCESS.value for row in malicious_t),
                len(malicious_t),
            ),
            "avg_fitness": round(sum(float(row["fitness"]) for row in candidates) / len(candidates), 4),
            "max_generation": max(int(row["generation"]) for row in candidates),
        })

    def group_metrics(groups: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        result = []
        for name, candidates in sorted(groups.items()):
            valid_g = [row for row in candidates if row["effective_outcome"] not in error_values]
            malicious_g = [row for row in valid_g if row["expected"] != "benign"]
            passed = [row for row in malicious_g if row["guardrail_passed"] == 1]
            result.append({
                "id": name,
                "observations": len(candidates),
                "guardrail_bypass_rate": _observed_bypass(malicious_g),
                "confirmed_attack_success_rate": _rate(
                    sum(row["effective_outcome"] == Outcome.ATTACK_SUCCESS.value for row in malicious_g),
                    len(malicious_g),
                ),
            })
        return result

    operator_snapshots = [
        {"generation": row["generation"], "operators": _json(row["stats_json"], {})}
        for row in snapshot_rows
    ]

    planned_categories = set(experiment.get("categories") or [])
    observed_controls = set(control_rows)
    planned_techniques = set(experiment.get("techniques") or [])
    observed_techniques = {key for key in technique_rows if key != "unmapped"}
    selected_coverage_denominator = len(planned_categories) if planned_categories else len(observed_controls)
    selected_coverage_numerator = len(observed_controls.intersection(planned_categories)) if planned_categories else len(observed_controls)
    technique_coverage_denominator = len(planned_techniques) if planned_techniques else len(observed_techniques)
    technique_coverage_numerator = len(observed_techniques.intersection(planned_techniques)) if planned_techniques else len(observed_techniques)

    summary = {
        "run": {
            "id": run["id"], "created_at": run["created_at"], "target": run["target"],
            "status": run["status"], "stop_reason": run["stop_reason"], "config": config,
        },
        "experiment": experiment,
        "metrics": {
            "observations": len(rows),
            "valid_observations": len(valid),
            "errors": len(rows) - len(valid),
            "guardrail_bypass_rate": _observed_bypass(malicious),
            "guardrail_bypass_denominator": sum(row["guardrail_passed"] is not None for row in malicious),
            "guardrail_unobservable": sum(row["guardrail_passed"] is None for row in malicious),
            "confirmed_attack_success_rate": _rate(
                sum(row["effective_outcome"] == Outcome.ATTACK_SUCCESS.value for row in malicious), len(malicious)
            ),
            "model_compliance_rate_when_known": _rate(
                sum(row["effective_outcome"] == Outcome.ATTACK_SUCCESS.value for row in compliance_known),
                len(compliance_known),
            ),
            "input_guardrail_false_positive_rate": _rate(len(benign_input_blocked), len(benign)),
            "end_to_end_benign_denial_rate": _rate(len(benign_denied), len(benign)),
            "accepted_unverified": sum(
                row["effective_outcome"] == Outcome.ACCEPTED_UNVERIFIED.value for row in rows
            ),
            "estimated_cost_usd": round(sum(float(row["estimated_cost_usd"]) for row in rows), 6),
            "provider_reported_cost_usd": (
                round(sum(row["provider_cost_usd"] or 0 for row in rows), 6)
                if any(row["provider_cost_usd"] is not None for row in rows) else None
            ),
            "control_coverage_rate": _rate(selected_coverage_numerator, selected_coverage_denominator),
            "technique_coverage_rate": _rate(technique_coverage_numerator, technique_coverage_denominator),
        },
        "instrumentation_modes": dict(sorted(instrumentation_modes.items())),
        "outcomes": dict(sorted(Counter(row["effective_outcome"] for row in rows).items())),
        "generations": [
            {"generation": generation, "total": sum(counts.values()), "outcomes": dict(counts)}
            for generation, counts in sorted(generations.items())
        ],
        "best_candidates": [dict(row) for row in sorted(rows, key=lambda row: row["fitness"], reverse=True)[:10]],
        "generation_metrics": generation_metrics,
        "operator_metrics": sorted(operator_metrics, key=lambda item: (item["avg_fitness"], item["attempts"]), reverse=True),
        "operator_snapshots": operator_snapshots,
        "technique_metrics": sorted(technique_metrics, key=lambda item: (item["guardrail_bypass_rate"] if item["guardrail_bypass_rate"] is not None else -1, item["avg_fitness"]), reverse=True),
        "framework_metrics": group_metrics(framework_rows),
        "control_metrics": group_metrics(control_rows),
        "categories": dict(sorted(Counter(row["category"] for row in rows).items())),
        "candidates": rows,
        "synthetic": run["target"] == "deterministic_fixture" or bool(config.get("target_metadata", {}).get("simulation")),
    }
    summary["assessment"] = build_assessment(summary)
    return summary


def export_report(db_path: str | Path, output_dir: str | Path, run_id: str | None = None) -> dict[str, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    summary = build_summary(db_path, run_id)
    assessment_path = output / 'assessment.json'
    assessment_path.write_text(json.dumps(summary['assessment'], ensure_ascii=False, indent=2), encoding='utf-8')
    from .executive_pdf import export_executive_pdf
    pdf_path = output / 'executive.pdf'
    export_executive_pdf(summary, pdf_path)
    actual_run_id = str(summary["run"]["id"])
    json_path = output / "summary.json"
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    csv_path = output / "candidates.csv"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        EFFECTIVE_SELECT + " WHERE c.run_id=? ORDER BY c.generation, c.rowid", (actual_run_id,)
    ).fetchall()
    conn.close()
    fieldnames = [
        "id", "run_id", "root_seed_id", "parent_id", "generation", "prompt",
        "category", "operator", "expected", "success_indicators_json", "frameworks_json",
        "control_ids_json", "technique_id", "technique_name", "external_technique_ids_json",
        "oracle", "capability", "tags_json", "outcome", "blocked", "guardrail_passed",
        "model_complied", "output_passed", "answer", "reason", "attack_type", "risk_score",
        "http_status", "latency_ms", "estimated_cost_usd", "provider_cost_usd", "metadata_json",
        "semantic_similarity", "novelty", "fitness", "selected", "observed_outcome",
        "effective_outcome", "review_verdict", "review_reviewer", "review_note",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        if rows:
            writer.writerows(dict(row) for row in rows)

    md_path = output / "report.md"
    md_path.write_text(_markdown(summary), encoding="utf-8")
    html_path = output / "report.html"
    html_path.write_text(render_report_html(summary), encoding="utf-8")
    return {"summary": json_path, "csv": csv_path, "markdown": md_path, "html": html_path, "assessment": assessment_path, "pdf": pdf_path}


def _markdown(summary: dict[str, object]) -> str:
    a=summary['assessment'];m=a['metrics'];run=summary['run']
    lines=[f"# Kyojitsu | Evaluación ejecutiva | {run['id']}", "",
           "> SIMULACIÓN: no describe la seguridad de una API real." if summary.get('synthetic') else "> Resultados de la muestra ejecutada; no certificación de cumplimiento.", "",
           f"Evaluaciones: {m['evaluations']}; adversariales válidas: {m['valid_adversarial']}; errores: {m['errors']}.",
           f"Prompts distintos exitosos: {m['unique_successful_prompts']}; evaluaciones con éxito: {m['confirmed_successes']}; técnicas con hallazgos: {m['successful_techniques']}.",
           f"Bloqueos explícitos: {m['explicit_blocks']}; avisos por texto: {m['text_blocks']}; pendientes: {m['unresolved']}.", "",
           "## Resultados por marco", "", "| Marco | Categoría | Pruebas válidas | Éxitos | Pendientes | Estado |", "|---|---|---:|---:|---:|---|"]
    for c in a['categories']:
        cm=c['metrics'];lines.append(f"| {c['framework']} | {c['id']} | {cm['valid_adversarial']} | {cm['confirmed_successes']} | {cm['unresolved']} | {c['label']} |")
    lines += ['', '## Técnicas', '', '| Técnica | Pruebas | Prompts exitosos distintos | Estado |', '|---|---:|---:|---|']
    for t in a['techniques']:
        lines.append(f"| {t['name']} | {t['metrics']['valid_adversarial']} | {t['metrics']['unique_successful_prompts']} | {t['label']} |")
    lines += ['', '## Recomendaciones', '']
    for r in a['recommendations']:
        lines += [f"### {r['id']} / {r['priority']} / {r['title']}", r['evidence'], '', r['action'], '', 'Verificación: '+r['verification'], '']
    lines += ['## Método y límites', '', 'Generador: '+str(a['generator'].get('mode','rules'))+'. Llamadas: '+str(a['generator'].get('calls',0))+'.', '', a['notice'], '']
    lines.extend(a['limitations'])
    lines += ['', 'El PDF ejecutivo y assessment.json acompañan este informe. SQLite conserva la evidencia y las revisiones.', '']
    return '\n'.join(lines)
