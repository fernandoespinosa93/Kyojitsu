from __future__ import annotations

import json
import math
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from .generator import GeneratorConfig, ModelGenerator
from .budget import Budget
from .dataset import deduplicate
from .engine import EvolutionConfig, EvolutionEngine
from .models import Seed
from .planner import PlannerConfig, PlanResult, build_plan
from .reporting import export_report
from .storage import RunStore
from .rest_tools import redact_config
from .targets import DeterministicFixtureTarget, GenericJsonTarget, GenericTargetProfile, IkigaiHttpTarget, Target


# Legacy CLI default only; Campaign Studio does not use a monetary budget.
ABSOLUTE_BUDGET_CAP_USD = 10.0


def _list_str(value: Any) -> list[str]:
    if not value:
        return []
    if not isinstance(value, list):
        raise ValueError("Se esperaba una lista.")
    return [str(item) for item in value if str(item).strip()]


def _custom_seed(item: dict[str, Any], index: int) -> Seed:
    prompt = item.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError(f"custom_seeds[{index}] no contiene un prompt válido.")
    return Seed(
        id=str(item.get("id") or f"custom-{index+1}"),
        prompt=prompt.strip(),
        category=str(item.get("category") or "custom"),
        technique=str(item.get("technique") or "custom"),
        reasoning=str(item.get("reasoning") or ""),
        expected=str(item.get("expected") or "malicious").lower(),
        success_indicators=_list_str(item.get("success_indicators")),
        source="campaign_custom",
        frameworks=_list_str(item.get("frameworks")),
        control_ids=_list_str(item.get("control_ids")),
        technique_id=str(item.get("technique_id") or "custom"),
        technique_name=str(item.get("technique_name") or item.get("technique") or "Custom"),
        external_technique_ids=_list_str(item.get("external_technique_ids")),
        oracle=str(item.get("oracle") or "manual"),
        capability=str(item.get("capability") or "prompt"),
        tags=_list_str(item.get("tags")) or ["custom"],
    )


def build_target(target_cfg: dict[str, Any], *, authorization_confirmed: bool) -> tuple[Target, float]:
    target_type = str(target_cfg.get("type") or "")
    timeout = float(target_cfg.get("timeout_seconds", 60.0))
    if target_type == "fixture":
        return DeterministicFixtureTarget(), 0.0
    if not authorization_confirmed:
        raise ValueError("Debes confirmar que tienes autorización explícita para probar el endpoint.")
    estimated_cost = float(target_cfg.get("estimated_cost_per_request", 0.0) or 0.0)
    if not math.isfinite(estimated_cost) or estimated_cost < 0:
        raise ValueError("estimated_cost_per_request debe ser un número finito no negativo.")
    if target_type == "ikigai":
        url = str(target_cfg.get("url") or "")
        if not url:
            raise ValueError("target.type=ikigai requiere url.")
        target = IkigaiHttpTarget(
            url,
            timeout_seconds=timeout,
            session_id=target_cfg.get("session_id"),
        )
        return target, estimated_cost
    if target_type == "generic":
        profile_data = dict(target_cfg.get("profile") or {})
        if "url" not in profile_data and target_cfg.get("url"):
            profile_data["url"] = target_cfg["url"]
        if "name" not in profile_data:
            profile_data["name"] = str(target_cfg.get("name") or "custom-endpoint")
        profile_data.setdefault("timeout_seconds", timeout)
        profile = GenericTargetProfile.from_dict(profile_data)
        target = GenericJsonTarget(profile, authorization_confirmed=True)
        return target, estimated_cost
    raise ValueError(f"Tipo de target desconocido: {target_type}")


def build_campaign_plan(config: dict[str, Any]) -> PlanResult:
    selection = dict(config.get("selection") or {})
    planner = PlannerConfig(
        frameworks=_list_str(selection.get("frameworks")) or ["owasp_llm_2025", "mitre_atlas"],
        category_ids=_list_str(selection.get("category_ids")),
        technique_ids=_list_str(selection.get("technique_ids")),
        seeds_per_technique=int(selection.get("seeds_per_technique", 2)),
        include_benign_controls=bool(selection.get("include_benign_controls", True)),
        random_seed=int((config.get("evolution") or {}).get("random_seed", 88)),
        capabilities=_list_str(selection.get("capabilities")) or None,
        secret_indicators=_list_str(selection.get("secret_indicators")) or None,
    )
    return build_plan(planner)


def run_campaign(
    config: dict[str, Any],
    *,
    output_dir: str | Path,
    event_callback: Callable[[dict[str, object]], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    generator_cfg = GeneratorConfig.from_dict(config.get('generator'))
    generator = ModelGenerator(generator_cfg, event_callback) if generator_cfg.mode != 'rules' else None
    authorization_confirmed = bool(config.get("authorization_confirmed", False))
    target_cfg = dict(config.get("target") or {})
    if target_cfg.get('type') == 'fixture' and not config.get('simulation_confirmed'):
        raise ValueError('Confirma explícitamente la simulación local. No se probará una API real.')
    if event_callback:
        event_callback({'type': 'preflight_started', 'target_type': target_cfg.get('type')})
    target, estimated_cost = build_target(target_cfg, authorization_confirmed=authorization_confirmed)
    health = target.preflight()
    if event_callback:
        event_callback({'type': 'preflight_passed', 'health': health})
    if generator:
        generator.preflight()
    output.mkdir(parents=True, exist_ok=True)

    plan = build_campaign_plan(config)
    seeds = list(plan.seeds)
    custom = config.get("custom_seeds") or []
    if not isinstance(custom, list):
        raise ValueError("custom_seeds debe ser una lista.")
    seeds.extend(_custom_seed(item, index) for index, item in enumerate(custom) if isinstance(item, dict))
    seeds = deduplicate(seeds)

    limits = dict(config.get("limits") or {})
    max_requests = int(limits.get("max_requests", 80))
    max_usd = float(limits['budget_usd']) if limits.get('budget_usd') is not None else None
    if max_usd is not None and (not math.isfinite(max_usd) or max_usd < 0):
        raise ValueError('budget_usd debe ser un número no negativo.')
    if max_requests < 1 or max_requests > 5000:
        raise ValueError("max_requests debe estar entre 1 y 5000.")
    budget = Budget(
        max_usd=max_usd,
        max_requests=max_requests,
        estimated_cost_per_request=estimated_cost,
        ledger_path=(output.parent / "budget-ledger.db") if estimated_cost > 0 else None,
    )

    evo = dict(config.get("evolution") or {})
    evolution = EvolutionConfig(
        generations=int(evo.get("generations", 3)),
        population_size=int(evo.get("population_size", 20)),
        elite_fraction=float(evo.get("elite_fraction", 0.25)),
        random_seed=int(evo.get("random_seed", 88)),
        max_prompt_chars=int(evo.get("max_prompt_chars", 6000)),
        benign_control_limit=int(evo.get("benign_control_limit", 100)),
        request_interval_seconds=float(evo.get('request_interval_seconds', 0.25)),
    )

    experiment_metadata = {
        "name": str(config.get("name") or "Kyojitsu campaign"),
        "generator": generator.snapshot() if generator else {'mode': 'rules', 'calls': 0, 'trained_weights': False},
        "frameworks": plan.frameworks,
        "categories": plan.categories,
        "techniques": plan.techniques,
        "coverage": plan.coverage,
        "target_health": health,
        "authorization_confirmed": authorization_confirmed or target_cfg.get("type") == "fixture",
        "framework_mapping_notice": "OWASP/MITRE are used as evaluation taxonomies; this is not a compliance certification.",
    }
    store = RunStore(output / "kyojitsu.db")
    engine = EvolutionEngine(
        target=target,
        store=store,
        budget=budget,
        config=evolution,
        experiment_metadata=experiment_metadata,
        event_callback=event_callback,
        cancel_check=cancel_check,
        generator=generator,
    )
    result = engine.run(seeds, run_id=config.get("run_id"))
    paths = export_report(output / "kyojitsu.db", output, result.run_id)
    campaign_path = output / "campaign.json"
    # Do not expand env-based secrets: only the original profile placeholders are persisted.
    campaign_path.write_text(json.dumps(redact_config(config), ensure_ascii=False, indent=2), encoding="utf-8")
    plan_path = output / "plan.json"
    plan_path.write_text(json.dumps(plan.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "result": asdict(result),
        "paths": {name: str(path) for name, path in paths.items()},
        "campaign": str(campaign_path),
        "plan": str(plan_path),
        "target_health": health,
        "seed_count": len(seeds),
    }
