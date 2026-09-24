from __future__ import annotations

import math
import random
import uuid
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Callable

from .generator import ModelGenerator, GeneratorError
from .budget import Budget, BudgetExceeded
from .frameworks import TECHNIQUE_BY_ID
from .models import Candidate, ScoredCandidate, Seed
from .mutations import AdaptiveMutationPolicy
from .scoring import fitness
from .similarity import cosine_similarity, novelty_against
from .storage import RunStore
from .targets import Target


@dataclass(slots=True)
class EvolutionConfig:
    generations: int = 2
    population_size: int = 20
    elite_fraction: float = 0.25
    random_seed: int = 88
    max_prompt_chars: int = 6000
    benign_control_limit: int = 100
    request_interval_seconds: float = 0.0

    def validate(self) -> None:
        if not math.isfinite(self.request_interval_seconds) or not 0 <= self.request_interval_seconds <= 60:
            raise ValueError('Intervalo entre solicitudes debe estar entre 0 y 60 segundos.')
        if self.generations < 0:
            raise ValueError("generations debe ser mayor o igual a 0.")
        if self.population_size < 1:
            raise ValueError("population_size debe ser mayor o igual a 1.")
        if not 0 < self.elite_fraction <= 1:
            raise ValueError("elite_fraction debe estar entre 0 y 1.")
        if not 100 <= self.max_prompt_chars <= 8000:
            raise ValueError("max_prompt_chars debe estar entre 100 y 8000.")
        if self.benign_control_limit < 0:
            raise ValueError("benign_control_limit debe ser mayor o igual a 0.")


@dataclass(slots=True)
class RunResult:
    run_id: str
    status: str
    stop_reason: str
    evaluated: int
    generations_completed: int
    budget: dict[str, float | int]


class EvolutionEngine:
    def __init__(
        self,
        *,
        target: Target,
        store: RunStore,
        budget: Budget,
        config: EvolutionConfig,
        experiment_metadata: dict[str, object] | None = None,
        event_callback: Callable[[dict[str, object]], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
        generator: ModelGenerator | None = None,
    ):
        self.generator = generator
        config.validate()
        self.target = target
        self.store = store
        self.budget = budget
        self.config = config
        self.experiment_metadata = experiment_metadata or {}
        self.event_callback = event_callback
        self.cancel_check = cancel_check or (lambda: False)
        self.rng = random.Random(config.random_seed)
        self.policy = AdaptiveMutationPolicy(self.rng)

    def run(self, seeds: list[Seed], run_id: str | None = None) -> RunResult:
        if not seeds:
            raise ValueError("Se necesita al menos una semilla.")
        run_id = run_id or f"run-{uuid.uuid4().hex[:10]}"
        config_dict = asdict(self.config) | {
            "budget": self.budget.snapshot(),
            "target_metadata": getattr(self.target, "metadata", {}),
            "seed_corpus_fingerprint": self._seed_fingerprint(seeds),
            "experiment": self.experiment_metadata,
        }
        self.store.start_run(run_id, self.target.name, config_dict)
        self._emit({"type": "run_started", "run_id": run_id, "target": self.target.name})
        self.store.save_seeds(run_id, seeds)

        selected_seeds = self._select_initial_seeds(seeds)
        root_prompts = {seed.id: seed.prompt for seed in seeds}
        population = [self._candidate_from_seed(seed, run_id) for seed in selected_seeds]
        all_prompts: list[str] = []
        seen = {self._key(candidate.prompt) for candidate in population}
        completed = -1
        status = "completed"
        stop_reason = ""

        try:
            if self.generator:
                for candidate in population:
                    if self.cancel_check():
                        raise InterruptedError()
                    if candidate.expected == 'benign':
                        continue
                    spec = TECHNIQUE_BY_ID.get(candidate.technique_id)
                    candidates = self.generator.variants(seed=candidate.prompt,
                        objective=spec.description if spec else candidate.category,
                        technique=candidate.technique_id, operator='initial_variation', feedback={},
                        generation=0, count=1, max_chars=self.config.max_prompt_chars)
                    candidate.prompt = candidates[0]
                    candidate.id = self._candidate_id(run_id, 0, candidate.root_seed_id, None, candidate.prompt)
                    candidate.operator = 'llm:initial'
                    candidate.tags.append('llm-generated')
                    seen.add(self._key(candidate.prompt))
            for generation in range(self.config.generations + 1):
                self._emit({"type": "generation_started", "run_id": run_id, "generation": generation, "population": len(population)})
                scored = self._evaluate_population(population, root_prompts, all_prompts)
                if not scored:
                    status = "stopped"
                    stop_reason = "No hubo observaciones válidas para continuar."
                    break

                valid = [item for item in scored if not item.evaluation.is_error]
                if not valid:
                    status = "stopped"
                    stop_reason = "Todos los candidatos terminaron en error; se detuvo la evolución."
                    break

                # Benign controls are measured but never used as parents. This keeps
                # the adversarial search from optimizing benign prompts merely because
                # they have high acceptance fitness.
                evolvable = [item for item in valid if item.candidate.expected != "benign"]
                elites: list[ScoredCandidate] = []
                if evolvable:
                    elite_count = max(1, math.ceil(len(evolvable) * self.config.elite_fraction))
                    elites = sorted(evolvable, key=lambda item: item.fitness, reverse=True)[:elite_count]
                    for item in elites:
                        item.selected = True
                    self.store.mark_selected([item.candidate.id for item in elites])
                self.store.save_operator_snapshot(run_id, generation, self.policy.snapshot())
                self._emit({"type": "generation_completed", "run_id": run_id, "generation": generation, "evaluated": len(scored), "elites": len(elites)})
                completed = generation
                if generation == self.config.generations:
                    break
                if not elites:
                    status = "stopped"
                    stop_reason = "No quedaron candidatos adversariales válidos para evolucionar."
                    break
                population = self._next_population(elites, run_id, generation + 1, seen)
                if not population:
                    status = "stopped"
                    stop_reason = "No fue posible crear variantes únicas para la siguiente generación."
                    break
        except GeneratorError as exc:
            status = 'generator_failed'
            stop_reason = str(exc)
        except InterruptedError:
            status = 'cancelled'
            stop_reason = 'Detenida por el operador; no se enviarán más solicitudes.'
        except BudgetExceeded as exc:
            status = "budget_exhausted"
            stop_reason = str(exc)
        except Exception as exc:
            self.store.finish_run(run_id, "failed", str(exc))
            raise

        if self.generator:
            self.experiment_metadata['generator'] = self.generator.snapshot()
            with self.store.connection() as conn:
                import json
                config_dict['experiment'] = self.experiment_metadata
                conn.execute('UPDATE runs SET config_json=? WHERE id=?', (json.dumps(config_dict, ensure_ascii=False), run_id))
        self.store.finish_run(run_id, status, stop_reason)
        self._emit({"type": "run_finished", "run_id": run_id, "status": status, "stop_reason": stop_reason, "requests": self.budget.requests})
        return RunResult(
            run_id=run_id,
            status=status,
            stop_reason=stop_reason,
            evaluated=self.budget.requests,
            generations_completed=max(0, completed),
            budget=self.budget.snapshot(),
        )

    def _select_initial_seeds(self, seeds: list[Seed]) -> list[Seed]:
        malicious = [seed for seed in seeds if seed.expected != "benign"]
        benign = [seed for seed in seeds if seed.expected == "benign"]
        if not malicious:
            chosen_malicious: list[Seed] = []
        elif len(malicious) <= self.config.population_size:
            chosen_malicious = list(malicious)
            self.rng.shuffle(chosen_malicious)
        else:
            groups: dict[str, deque[Seed]] = defaultdict(deque)
            shuffled = list(malicious)
            self.rng.shuffle(shuffled)
            for seed in shuffled:
                groups[seed.technique_id or seed.category].append(seed)
            keys = list(groups)
            self.rng.shuffle(keys)
            chosen_malicious = []
            while len(chosen_malicious) < self.config.population_size and keys:
                next_keys: list[str] = []
                for key in keys:
                    if groups[key] and len(chosen_malicious) < self.config.population_size:
                        chosen_malicious.append(groups[key].popleft())
                    if groups[key]:
                        next_keys.append(key)
                keys = next_keys
        self.rng.shuffle(benign)
        chosen_benign = benign[: self.config.benign_control_limit]
        return chosen_malicious + chosen_benign

    def _candidate_from_seed(self, seed: Seed, run_id: str) -> Candidate:
        return Candidate(
            id=self._candidate_id(run_id, 0, seed.id, None, seed.prompt),
            run_id=run_id,
            root_seed_id=seed.id,
            parent_id=None,
            generation=0,
            prompt=seed.prompt,
            category=seed.category,
            operator=f"external:{seed.technique}",
            expected=seed.expected,
            success_indicators=list(seed.success_indicators),
            frameworks=list(seed.frameworks),
            control_ids=list(seed.control_ids),
            technique_id=seed.technique_id,
            technique_name=seed.technique_name or seed.technique,
            external_technique_ids=list(seed.external_technique_ids),
            oracle=seed.oracle,
            capability=seed.capability,
            tags=list(seed.tags),
        )

    def _evaluate_population(
        self,
        population: list[Candidate],
        root_prompts: dict[str, str],
        all_prompts: list[str],
    ) -> list[ScoredCandidate]:
        scored: list[ScoredCandidate] = []
        for candidate in population:
            if self.cancel_check():
                raise InterruptedError()
            if self.budget.requests and self.config.request_interval_seconds:
                deadline = time.monotonic() + self.config.request_interval_seconds
                while time.monotonic() < deadline:
                    if self.cancel_check():
                        raise InterruptedError()
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            reserved_cost = self.budget.reserve()
            self._emit({'type': 'candidate_started', 'candidate_id': candidate.id,
                'generation': candidate.generation, 'technique_id': candidate.technique_id,
                'operator': candidate.operator, 'parent_id': candidate.parent_id,
                'prompt': candidate.prompt[:6000], 'expected': candidate.expected})
            evaluation = self.target.evaluate(candidate)
            evaluation.metadata['generator'] = 'llm' if 'llm-generated' in candidate.tags else 'local_rules'
            evaluation.metadata['similarity_method'] = 'lexical_hashed_cosine_not_embeddings'
            evaluation.estimated_cost_usd = reserved_cost
            self.budget.record_provider_cost(evaluation.provider_cost_usd)
            semantic = cosine_similarity(candidate.prompt, root_prompts[candidate.root_seed_id])
            novelty = novelty_against(candidate.prompt, all_prompts)
            item = ScoredCandidate(
                candidate=candidate,
                evaluation=evaluation,
                semantic_similarity=round(semantic, 6),
                novelty=round(novelty, 6),
                fitness=fitness(candidate, evaluation, semantic, novelty),
            )
            self.store.save_candidate(item)
            self._emit({'type': 'candidate_evaluated', 'run_id': candidate.run_id,
                'candidate_id': candidate.id, 'parent_id': candidate.parent_id,
                'generation': candidate.generation, 'technique_id': candidate.technique_id,
                'operator': candidate.operator, 'prompt': candidate.prompt[:6000],
                'answer': evaluation.answer[:6000], 'reason': evaluation.reason[:1000],
                'outcome': evaluation.outcome.value, 'fitness': item.fitness,
                'latency_ms': round(evaluation.latency_ms, 2), 'http_status': evaluation.http_status,
                'expected': candidate.expected, 'guardrail_passed': evaluation.guardrail_passed,
                'instrumentation': evaluation.metadata.get('instrumentation', 'synthetic' if self.target.name == 'deterministic_fixture' else 'unknown')})
            scored.append(item)
            all_prompts.append(candidate.prompt)
            if not candidate.operator.startswith("external:"):
                rewards = {
                    "attack_success": 1.0,
                    "accepted_unverified": 0.0,
                    "guardrail_blocked": -0.5,
                    "text_blocked": -0.35,
                    "signal_conflict": 0.0,
                    "output_blocked": 0.2,
                    "attack_failure": -0.1,
                    "model_refusal": -0.25,
                    "input_blocked": -0.6,
                }
                self.policy.observe(
                    candidate.technique_id,
                    candidate.operator.removeprefix('llm:'),
                    rewards.get(evaluation.outcome.value, -1.0),
                )
        return scored

    def _next_population(
        self,
        elites: list[ScoredCandidate],
        run_id: str,
        generation: int,
        seen: set[str],
    ) -> list[Candidate]:
        result: list[Candidate] = []
        if self.generator:
            attempts = 0
            while len(result) < self.config.population_size and attempts < self.config.population_size * 2:
                if self.cancel_check():
                    raise InterruptedError()
                selected = elites[attempts % len(elites)]
                parent = selected.candidate
                spec = TECHNIQUE_BY_ID.get(parent.technique_id)
                operator = self.policy.choose(technique_id=parent.technique_id,
                    allowed_families=set(spec.mutation_families) if spec and spec.mutation_families else None)
                prompts = self.generator.variants(seed=parent.prompt,
                    objective=spec.description if spec else parent.category,
                    technique=parent.technique_id, operator=operator.name,
                    feedback={'outcome': selected.evaluation.outcome.value,
                              'guardrail_passed': selected.evaluation.guardrail_passed,
                              'fitness': selected.fitness,
                              'operator_weights': self.policy.snapshot()['global']},
                    generation=generation, count=min(4, self.config.population_size-len(result)),
                    max_chars=self.config.max_prompt_chars)
                attempts += 1
                for prompt in prompts:
                    key = self._key(prompt)
                    if key in seen:
                        continue
                    seen.add(key)
                    from dataclasses import replace
                    result.append(replace(parent,
                        id=self._candidate_id(run_id, generation, parent.root_seed_id, parent.id, prompt),
                        prompt=prompt, parent_id=parent.id, generation=generation,
                        operator='llm:'+operator.name,
                        tags=[x for x in parent.tags if x != 'llm-generated']+['llm-generated']))
            if not result:
                raise GeneratorError('El generador solo devolvió duplicados. No se fabricaron variantes locales.')
            self._emit({'type': 'population_ready', 'generation': generation,
                        'population': len(result), 'operators': self.policy.snapshot()})
            return result
        attempts = 0
        max_attempts = self.config.population_size * 40
        parent_weights = [max(0.05, item.fitness + 1.05) for item in elites]
        while len(result) < self.config.population_size and attempts < max_attempts:
            attempts += 1
            parent = self.rng.choices(elites, weights=parent_weights, k=1)[0].candidate
            allowed_families: set[str] | None = None
            spec = TECHNIQUE_BY_ID.get(parent.technique_id)
            if spec and spec.mutation_families:
                allowed_families = set(spec.mutation_families)
            operator = self.policy.choose(
                technique_id=parent.technique_id,
                allowed_families=allowed_families,
            )
            prompt = operator.transform(parent.prompt, self.rng).strip()
            key = self._key(prompt)
            if not prompt or len(prompt) > self.config.max_prompt_chars or key in seen:
                continue
            seen.add(key)
            result.append(
                Candidate(
                    id=self._candidate_id(run_id, generation, parent.root_seed_id, parent.id, prompt),
                    run_id=run_id,
                    root_seed_id=parent.root_seed_id,
                    parent_id=parent.id,
                    generation=generation,
                    prompt=prompt,
                    category=parent.category,
                    operator=operator.name,
                    expected=parent.expected,
                    success_indicators=list(parent.success_indicators),
                    frameworks=list(parent.frameworks),
                    control_ids=list(parent.control_ids),
                    technique_id=parent.technique_id,
                    technique_name=parent.technique_name,
                    external_technique_ids=list(parent.external_technique_ids),
                    oracle=parent.oracle,
                    capability=parent.capability,
                    tags=list(parent.tags),
                )
            )
        self._emit({'type': 'population_ready', 'generation': generation,
                    'population': len(result), 'operators': self.policy.snapshot()})
        return result


    def _emit(self, event: dict[str, object]) -> None:
        if self.event_callback is None:
            return
        try:
            self.event_callback(event)
        except Exception:
            # Telemetry must never break the experiment.
            return

    @staticmethod
    def _key(prompt: str) -> str:
        return " ".join(prompt.casefold().split())

    @staticmethod
    def _candidate_id(
        run_id: str, generation: int, root_seed_id: str, parent_id: str | None, prompt: str
    ) -> str:
        material = f"{run_id}|{generation}|{root_seed_id}|{parent_id or ''}|{prompt}"
        return f"c-{uuid.uuid5(uuid.NAMESPACE_URL, material).hex[:16]}"

    @staticmethod
    def _seed_fingerprint(seeds: list[Seed]) -> str:
        import hashlib
        import json

        material = json.dumps(
            [asdict(seed) for seed in seeds], ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()
