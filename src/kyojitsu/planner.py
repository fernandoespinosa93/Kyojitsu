from __future__ import annotations

import hashlib
import random
from dataclasses import asdict, dataclass
from typing import Iterable

from .frameworks import FRAMEWORKS, TECHNIQUE_BY_ID, TechniqueSpec, techniques_for
from .models import Seed


@dataclass(slots=True)
class PlannerConfig:
    frameworks: list[str]
    category_ids: list[str]
    technique_ids: list[str]
    seeds_per_technique: int = 2
    include_benign_controls: bool = True
    random_seed: int = 88
    capabilities: list[str] | None = None
    secret_indicators: list[str] | None = None

    def validate(self) -> None:
        unknown_frameworks = sorted(set(self.frameworks) - set(FRAMEWORKS))
        if unknown_frameworks:
            raise ValueError(f"Frameworks desconocidos: {', '.join(unknown_frameworks)}")
        if self.seeds_per_technique < 1 or self.seeds_per_technique > 20:
            raise ValueError("seeds_per_technique debe estar entre 1 y 20.")
        allowed_categories = {
            category.id
            for framework_id in self.frameworks
            for category in FRAMEWORKS[framework_id]["categories"]
        }
        unknown_categories = sorted(set(self.category_ids) - allowed_categories)
        if unknown_categories:
            raise ValueError(f"Categorías desconocidas para los frameworks seleccionados: {', '.join(unknown_categories)}")
        unknown = sorted(set(self.technique_ids) - set(TECHNIQUE_BY_ID))
        if unknown:
            raise ValueError(f"Técnicas desconocidas: {', '.join(unknown)}")


@dataclass(slots=True)
class PlanResult:
    seeds: list[Seed]
    frameworks: list[str]
    categories: list[str]
    techniques: list[str]
    coverage: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "frameworks": self.frameworks,
            "categories": self.categories,
            "techniques": self.techniques,
            "coverage": self.coverage,
            "seeds": [asdict(seed) for seed in self.seeds],
        }


def _canary(technique_id: str, index: int, random_seed: int) -> str:
    raw = f"kyojitsu|{technique_id}|{index}|{random_seed}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:10].upper()
    return f"KYOJITSU-{digest}"


def _selected_mappings(
    technique: TechniqueSpec,
    frameworks: set[str],
    category_ids: set[str],
) -> list[object]:
    mappings = [m for m in technique.mappings if m.framework in frameworks]
    if category_ids:
        # A selected risk identifies the technique. Retain its cross-framework
        # mapping when that other framework has no category filter of its own.
        if not any(category_ids.intersection(m.category_ids) for m in mappings):
            return []
        by_framework = {fw: category_ids.intersection(c.id for c in FRAMEWORKS[fw]["categories"])
                        for fw in frameworks}
        mappings = [m for m in mappings if not by_framework[m.framework]
                    or by_framework[m.framework].intersection(m.category_ids)]
    return mappings


def _category_label(technique: TechniqueSpec, mappings: list[object]) -> str:
    # Prefer the current OWASP risk ID as the compact category label when available.
    for framework_id in ("owasp_llm_2025",):
        for mapping in mappings:
            if mapping.framework == framework_id and mapping.category_ids:
                category_id = mapping.category_ids[0]
                category = next(
                    (c for c in FRAMEWORKS[framework_id]["categories"] if c.id == category_id),
                    None,
                )
                if category:
                    return f"{category.id} {category.name}"
    for mapping in mappings:
        if mapping.category_ids:
            return mapping.category_ids[0]
    return technique.name


def _oracle_for(technique: TechniqueSpec, secret_indicators: list[str]) -> tuple[str, list[str]]:
    if technique.oracle == "canary":
        return "canary", []
    if technique.oracle in {"manual_or_secret", "manual_or_tool_canary"} and secret_indicators:
        return "secret", list(secret_indicators)
    return "manual", []


def build_plan(config: PlannerConfig) -> PlanResult:
    config.validate()
    framework_set = set(config.frameworks)
    category_set = set(config.category_ids)
    capabilities = set(config.capabilities or ())
    secret_indicators = [item for item in (config.secret_indicators or []) if item.strip()]

    if config.technique_ids:
        specs = [TECHNIQUE_BY_ID[item] for item in config.technique_ids]
    else:
        specs = techniques_for(
            frameworks=config.frameworks,
            category_ids=config.category_ids,
            capabilities=config.capabilities,
        )
        specs = [item for item in specs if item.default_enabled]

    filtered: list[TechniqueSpec] = []
    for spec in specs:
        mappings = _selected_mappings(spec, framework_set, category_set)
        if not mappings:
            continue
        if capabilities and spec.capability not in capabilities and spec.capability != "prompt":
            continue
        filtered.append(spec)
    if not filtered:
        raise ValueError("La selección no contiene técnicas ejecutables para los frameworks/categorías elegidos.")

    rng = random.Random(config.random_seed)
    seeds: list[Seed] = []
    coverage: list[dict[str, object]] = []
    for spec in filtered:
        mappings = _selected_mappings(spec, framework_set, category_set)
        control_ids = sorted({control for mapping in mappings for control in mapping.category_ids})
        mapped_frameworks = sorted({mapping.framework for mapping in mappings})
        external_ids = sorted({mapping.technique_id for mapping in mappings if mapping.technique_id})
        category = _category_label(spec, mappings)
        base_oracle, inherited_indicators = _oracle_for(spec, secret_indicators)
        templates = list(spec.templates)
        rng.shuffle(templates)
        for index in range(config.seeds_per_technique):
            canary = _canary(spec.id, index, config.random_seed)
            template = templates[index % len(templates)]
            prompt = template.format(canary=canary)
            if base_oracle == "canary":
                indicators = [canary]
                oracle = "canary"
            else:
                indicators = list(inherited_indicators)
                oracle = base_oracle
            seed_id = f"fw-{spec.id}-{index+1:02d}"
            seeds.append(
                Seed(
                    id=seed_id,
                    prompt=prompt,
                    category=category,
                    technique=spec.name,
                    reasoning=spec.description,
                    expected="malicious",
                    success_indicators=indicators,
                    source="framework_planner",
                    frameworks=mapped_frameworks,
                    control_ids=control_ids,
                    technique_id=spec.id,
                    technique_name=spec.name,
                    external_technique_ids=external_ids,
                    oracle=oracle,
                    capability=spec.capability,
                    tags=["generated", "framework-driven", spec.capability],
                )
            )
        if config.include_benign_controls and spec.benign_templates:
            benign_prompt = spec.benign_templates[0].format(canary=_canary(spec.id, 99, config.random_seed))
            seeds.append(
                Seed(
                    id=f"benign-{spec.id}",
                    prompt=benign_prompt,
                    category=category,
                    technique=f"benign:{spec.name}",
                    reasoning=f"Control benigno cercano a {spec.name} para estimar falsos positivos.",
                    expected="benign",
                    source="framework_planner",
                    frameworks=mapped_frameworks,
                    control_ids=control_ids,
                    technique_id=spec.id,
                    technique_name=spec.name,
                    external_technique_ids=external_ids,
                    oracle="manual",
                    capability=spec.capability,
                    tags=["generated", "benign-control", spec.capability],
                )
            )
        coverage.append({
            "technique_id": spec.id,
            "technique_name": spec.name,
            "capability": spec.capability,
            "oracle": base_oracle,
            "frameworks": mapped_frameworks,
            "control_ids": control_ids,
            "external_technique_ids": external_ids,
            "notes": spec.notes,
        })

    return PlanResult(
        seeds=seeds,
        frameworks=sorted(framework_set),
        categories=sorted(category_set),
        techniques=[item.id for item in filtered],
        coverage=coverage,
    )
