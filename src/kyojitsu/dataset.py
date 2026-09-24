from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import Seed


class DatasetError(ValueError):
    pass


def _string_list(value: object, *, field: str, index: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise DatasetError(f"Registro {index}: {field} debe ser una lista de texto.")
    return [x for x in value if x.strip()]


def load_seeds(path: str | Path, *, source: str | None = None) -> list[Seed]:
    dataset_path = Path(path)
    try:
        raw = json.loads(dataset_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetError(f"No se pudo leer {dataset_path}: {exc}") from exc
    if not isinstance(raw, list):
        raise DatasetError("El dataset debe ser una lista JSON.")

    seeds: list[Seed] = []
    ids: set[str] = set()
    for index, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise DatasetError(f"Registro {index}: se esperaba un objeto JSON.")
        prompt = item.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise DatasetError(f"Registro {index}: falta un prompt de texto no vacío.")
        indicators = _string_list(item.get("success_indicators", []), field="success_indicators", index=index)
        seed_id = str(item.get("id", index))
        if seed_id in ids:
            raise DatasetError(f"Registro {index}: el id {seed_id!r} está repetido.")
        ids.add(seed_id)
        expected = str(item.get("expected", "malicious")).strip().lower()
        if expected not in {"malicious", "benign"}:
            raise DatasetError(f"Registro {index}: expected debe ser malicious o benign.")
        seeds.append(
            Seed(
                id=seed_id,
                prompt=prompt.strip(),
                category=str(item.get("category", "unknown")).strip() or "unknown",
                technique=str(item.get("technique", "seed")).strip() or "seed",
                reasoning=str(item.get("reasoning", "")),
                expected=expected,
                success_indicators=indicators,
                source=source or str(item.get("source", dataset_path.name)),
                frameworks=_string_list(item.get("frameworks", []), field="frameworks", index=index),
                control_ids=_string_list(item.get("control_ids", []), field="control_ids", index=index),
                technique_id=str(item.get("technique_id", "")).strip(),
                technique_name=str(item.get("technique_name", "")).strip(),
                external_technique_ids=_string_list(
                    item.get("external_technique_ids", []), field="external_technique_ids", index=index
                ),
                oracle=str(item.get("oracle", "manual")).strip() or "manual",
                capability=str(item.get("capability", "prompt")).strip() or "prompt",
                tags=_string_list(item.get("tags", []), field="tags", index=index),
            )
        )
    return seeds


def dataset_summary(seeds: list[Seed]) -> dict[str, object]:
    normalized = [" ".join(seed.prompt.lower().split()) for seed in seeds]
    frameworks = Counter(fw for seed in seeds for fw in seed.frameworks)
    controls = Counter(control for seed in seeds for control in seed.control_ids)
    technique_ids = Counter(seed.technique_id or seed.technique for seed in seeds)
    return {
        "records": len(seeds),
        "unique_prompts": len(set(normalized)),
        "duplicates": len(seeds) - len(set(normalized)),
        "categories": dict(sorted(Counter(s.category for s in seeds).items())),
        "techniques": dict(sorted(Counter(s.technique for s in seeds).items())),
        "technique_ids": dict(sorted(technique_ids.items())),
        "frameworks": dict(sorted(frameworks.items())),
        "controls": dict(sorted(controls.items())),
        "expected": dict(sorted(Counter(s.expected for s in seeds).items())),
    }


def deduplicate(seeds: list[Seed]) -> list[Seed]:
    seen: set[str] = set()
    unique: list[Seed] = []
    for seed in seeds:
        key = " ".join(seed.prompt.casefold().split())
        if key not in seen:
            seen.add(key)
            unique.append(seed)
    return unique
