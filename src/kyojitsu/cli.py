from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from . import __version__
from .budget import Budget
from .dataset import DatasetError, dataset_summary, deduplicate, load_seeds
from .engine import EvolutionConfig, EvolutionEngine
from .frameworks import catalog_json
from .planner import PlannerConfig, build_plan
from .reporting import export_report
from .runner import ABSOLUTE_BUDGET_CAP_USD, run_campaign
from .storage import RunStore
from .targets import DeterministicFixtureTarget, GenericJsonTarget, GenericTargetProfile, IkigaiHttpTarget


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kyojitsu",
        description="Framework de AI Red Team para evaluación evolutiva de guardrails LLM.",
    )
    parser.add_argument("--version", action="version", version=f"Kyojitsu {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-dataset", help="Valida y resume un corpus JSON.")
    validate.add_argument("path", type=Path)

    catalog = sub.add_parser("catalog", help="Muestra frameworks, categorías y técnicas soportadas.")
    catalog.add_argument("--json", action="store_true", help="Salida JSON completa.")

    plan = sub.add_parser("plan", help="Genera un plan framework-driven sin ejecutar el target.")
    plan.add_argument("--framework", action="append", choices=["owasp_llm_2025", "mitre_atlas"])
    plan.add_argument("--category", action="append", default=[])
    plan.add_argument("--technique", action="append", default=[])
    plan.add_argument("--seeds-per-technique", type=int, default=2)
    plan.add_argument("--no-benign-controls", action="store_true")
    plan.add_argument("--secret-indicator", action="append", default=[])
    plan.add_argument("--output", type=Path)

    campaign = sub.add_parser("run-campaign", help="Ejecuta un campaign.json completo.")
    campaign.add_argument("--campaign", required=True, type=Path)
    campaign.add_argument("--output", required=True, type=Path)

    run = sub.add_parser("run", help="Ejecuta una campaña con un corpus explícito (modo compatible v2).")
    run.add_argument("--seeds", required=True, type=Path, help="Corpus JSON de semillas.")
    run.add_argument("--target", choices=["fixture", "ikigai", "generic"], default="fixture")
    run.add_argument("--url", help="URL completa del endpoint.")
    run.add_argument("--target-profile", type=Path, help="Perfil JSON para target=generic.")
    run.add_argument("--authorized", action="store_true", help="Confirma autorización explícita para probar el endpoint.")
    run.add_argument("--output", type=Path, default=Path("runs/latest"))
    run.add_argument("--run-id")
    run.add_argument("--generations", type=int, default=2, help="Generaciones posteriores a G0.")
    run.add_argument("--population", type=int, default=20)
    run.add_argument("--elite-fraction", type=float, default=0.25)
    run.add_argument("--random-seed", type=int, default=88)
    run.add_argument("--max-prompt-chars", type=int, default=6000)
    run.add_argument("--max-requests", type=int, default=50)
    run.add_argument("--budget-usd", type=float, default=10.0)
    run.add_argument(
        "--estimated-cost-per-request", type=float,
        help="Estimación conservadora por petición. Obligatoria para targets con costo.",
    )
    run.add_argument("--timeout", type=float, default=60.0)
    run.add_argument("--session-id", help="Fija una sesión para pruebas stateful; omitir para stateless.")
    run.add_argument(
        "--budget-ledger", type=Path, default=Path("runs/budget-ledger.db"),
        help="Registro acumulado de costo estimado entre campañas.",
    )
    run.add_argument("--keep-duplicates", action="store_true")

    report = sub.add_parser("report", help="Regenera los reportes desde SQLite.")
    report.add_argument("--db", required=True, type=Path)
    report.add_argument("--output", required=True, type=Path)
    report.add_argument("--run-id")

    review = sub.add_parser("review", help="Registra una revisión humana auditable.")
    review.add_argument("--db", required=True, type=Path)
    review.add_argument("--candidate-id", required=True)
    review.add_argument("--verdict", required=True, choices=["success", "failure"])
    review.add_argument("--reviewer", required=True)
    review.add_argument("--note", default="")

    studio = sub.add_parser("studio", help="Abre la interfaz local de configuración y ejecución.")
    studio.add_argument("--host", default="127.0.0.1")
    studio.add_argument("--port", type=int, default=8765)
    studio.add_argument("--runs-dir", type=Path, default=Path("runs"))
    studio.add_argument("--no-open", action="store_true")
    return parser


def cmd_validate(path: Path) -> int:
    seeds = load_seeds(path)
    print(json.dumps(dataset_summary(seeds), ensure_ascii=False, indent=2))
    return 0


def cmd_catalog(as_json: bool) -> int:
    catalog = catalog_json()
    if as_json:
        print(json.dumps(catalog, ensure_ascii=False, indent=2))
        return 0
    for framework in catalog["frameworks"]:
        print(f"\n{framework['name']} [{framework['version']}]")
        for category in framework["categories"]:
            marker = "prompt" if category["prompt_testable"] else "manual/integración"
            print(f"  {category['id']:<22} {category['name']}  ({marker})")
    print("\nTécnicas ejecutables")
    for technique in catalog["techniques"]:
        ids = [m["technique_id"] for m in technique["mappings"] if m.get("technique_id")]
        print(f"  {technique['id']:<34} {technique['name']}" + (f" [{', '.join(ids)}]" if ids else ""))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    result = build_plan(PlannerConfig(
        frameworks=args.framework or ["owasp_llm_2025", "mitre_atlas"],
        category_ids=args.category,
        technique_ids=args.technique,
        seeds_per_technique=args.seeds_per_technique,
        include_benign_controls=not args.no_benign_controls,
        secret_indicators=args.secret_indicator,
    ))
    payload = json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(args.output)
    else:
        print(payload)
    return 0


def _validate_common_limits(args: argparse.Namespace) -> None:
    if not math.isfinite(args.budget_usd) or not 0 <= args.budget_usd <= ABSOLUTE_BUDGET_CAP_USD:
        raise ValueError(f"budget-usd debe estar entre 0 y {ABSOLUTE_BUDGET_CAP_USD:.2f}.")
    if args.max_requests < 1:
        raise ValueError("max-requests debe ser mayor o igual a 1.")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("timeout debe ser un número finito mayor que 0.")


def cmd_run(args: argparse.Namespace) -> int:
    _validate_common_limits(args)
    if args.target == "ikigai":
        if not args.authorized:
            raise ValueError("target=ikigai requiere --authorized.")
        if not args.url:
            raise ValueError("target=ikigai requiere --url.")
        target = IkigaiHttpTarget(args.url, timeout_seconds=args.timeout, session_id=args.session_id)
        target.preflight()
        estimated_cost = args.estimated_cost_per_request
        if estimated_cost is None or not math.isfinite(estimated_cost) or estimated_cost < 0:
            raise ValueError("target=ikigai requiere --estimated-cost-per-request >= 0.")
        ledger_path = args.budget_ledger if estimated_cost > 0 else None
    elif args.target == "generic":
        if not args.authorized:
            raise ValueError("target=generic requiere --authorized.")
        if not args.target_profile:
            raise ValueError("target=generic requiere --target-profile.")
        profile = GenericTargetProfile.from_file(args.target_profile)
        if args.url:
            profile.url = args.url
        profile.timeout_seconds = args.timeout
        profile.session_id = args.session_id
        target = GenericJsonTarget(profile, authorization_confirmed=True)
        target.preflight()
        estimated_cost = args.estimated_cost_per_request or 0.0
        ledger_path = args.budget_ledger if estimated_cost > 0 else None
    else:
        target = DeterministicFixtureTarget()
        target.preflight()
        estimated_cost = 0.0
        ledger_path = None

    seeds = load_seeds(args.seeds)
    original_count = len(seeds)
    if not args.keep_duplicates:
        seeds = deduplicate(seeds)
    args.output.mkdir(parents=True, exist_ok=True)
    store = RunStore(args.output / "kyojitsu.db")
    budget = Budget(args.budget_usd, args.max_requests, estimated_cost, ledger_path=ledger_path)
    config = EvolutionConfig(
        generations=args.generations,
        population_size=args.population,
        elite_fraction=args.elite_fraction,
        random_seed=args.random_seed,
        max_prompt_chars=args.max_prompt_chars,
    )
    engine = EvolutionEngine(target=target, store=store, budget=budget, config=config)
    result = engine.run(seeds, run_id=args.run_id)
    paths = export_report(args.output / "kyojitsu.db", args.output, result.run_id)
    print(f"Ejecución: {result.run_id}")
    print(f"Estado: {result.status}")
    print(f"Evaluados: {result.evaluated}")
    if original_count != len(seeds):
        print(f"Duplicados eliminados: {original_count - len(seeds)}")
    if result.stop_reason:
        print(f"Motivo de cierre: {result.stop_reason}")
    print(f"Reporte HTML: {paths['html']}")
    print(f"Datos CSV: {paths['csv']}")
    return 0 if result.status in {"completed", "budget_exhausted"} and result.evaluated > 0 else 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-dataset":
            return cmd_validate(args.path)
        if args.command == "catalog":
            return cmd_catalog(args.json)
        if args.command == "plan":
            return cmd_plan(args)
        if args.command == "run-campaign":
            config = json.loads(args.campaign.read_text(encoding="utf-8"))
            result = run_campaign(config, output_dir=args.output)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "run":
            return cmd_run(args)
        if args.command == "report":
            paths = export_report(args.db, args.output, args.run_id)
            print("\n".join(f"{name}: {path}" for name, path in paths.items()))
            return 0
        if args.command == "review":
            store = RunStore(args.db)
            store.review_candidate(
                args.candidate_id, args.verdict, reviewer=args.reviewer, note=args.note
            )
            print(f"Revisión guardada para {args.candidate_id}: {args.verdict}")
            return 0
        if args.command == "studio":
            from .studio import serve_studio
            serve_studio(
                host=args.host,
                port=args.port,
                runs_dir=args.runs_dir,
                open_browser=not args.no_open,
            )
            return 0
    except (ValueError, DatasetError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 1


if __name__ == "__main__":
    sys.exit(main())
