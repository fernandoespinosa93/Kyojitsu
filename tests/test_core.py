from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import patch

from kyojitsu.budget import Budget, BudgetExceeded
from kyojitsu.dataset import dataset_summary, deduplicate, load_seeds
from kyojitsu.engine import EvolutionConfig, EvolutionEngine
from kyojitsu.frameworks import catalog_json
from kyojitsu.models import Candidate, Evaluation, Outcome, Seed
from kyojitsu.planner import PlannerConfig, build_plan
from kyojitsu.reporting import build_summary, export_report
from kyojitsu.runner import run_campaign
from kyojitsu.storage import RunStore
from kyojitsu.studio_ui import STUDIO_HTML
from kyojitsu.targets import (
    DeterministicFixtureTarget,
    GenericJsonTarget,
    GenericTargetProfile,
    IkigaiHttpTarget,
    Target,
    classify_answer,
)


class StudioUiTests(unittest.TestCase):
    def _script(self) -> str:
        return STUDIO_HTML.split("<script>", 1)[1].split("</script>", 1)[0]

    def test_generator_key_is_transient_ui_field(self) -> None:
        script = self._script()
        html = STUDIO_HTML.split('<script>',1)[0]
        self.assertNotIn('Bearer ${ENV:KYOJITSU_API_KEY}', STUDIO_HTML)
        self.assertIn('id="generatorApiKey"', html)
        self.assertIn("api_key:val('generatorApiKey')", script)
        self.assertIn("$('#generatorApiKey').value=''", script)

    @unittest.skipUnless(shutil.which("node"), "Node.js no disponible para validar sintaxis del frontend")
    def test_embedded_studio_javascript_parses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "studio.js"
            js.write_text(self._script(), encoding="utf-8")
            proc = subprocess.run(
                [shutil.which("node") or "node", "--check", str(js)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)


class DatasetTests(unittest.TestCase):
    def test_duplicate_detection_and_removal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seeds.json"
            path.write_text(json.dumps([
                {"id": 1, "prompt": "Test text", "category": "a"},
                {"id": 2, "prompt": "  test   TEXT ", "category": "a"},
            ]), encoding="utf-8")
            seeds = load_seeds(path)
            self.assertEqual(dataset_summary(seeds)["duplicates"], 1)
            self.assertEqual(len(deduplicate(seeds)), 1)


class BudgetTests(unittest.TestCase):
    def test_non_finite_cost_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Budget(max_usd=10, max_requests=3, estimated_cost_per_request=float("nan"))

    def test_ledger_accumulates_across_campaigns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "budget.db"
            first = Budget(1.0, 10, 0.4, ledger_path=ledger)
            first.reserve()
            second = Budget(1.0, 10, 0.4, ledger_path=ledger)
            second.reserve()
            with self.assertRaises(BudgetExceeded):
                second.reserve()


class PlannerTests(unittest.TestCase):
    def test_catalog_contains_owasp_and_atlas(self) -> None:
        catalog = catalog_json()
        ids = {item["id"] for item in catalog["frameworks"]}
        self.assertEqual(ids, {"owasp_llm_2025", "mitre_atlas"})
        techniques = {item["id"] for item in catalog["techniques"]}
        self.assertIn("direct_prompt_injection", techniques)
        self.assertIn("system_prompt_extraction", techniques)

    def test_framework_driven_plan_generates_mapped_canary_seeds(self) -> None:
        plan = build_plan(PlannerConfig(
            frameworks=["owasp_llm_2025", "mitre_atlas"],
            category_ids=["LLM01", "INITIAL_ACCESS"],
            technique_ids=["direct_prompt_injection"],
            seeds_per_technique=2,
            include_benign_controls=True,
            random_seed=88,
        ))
        self.assertEqual(plan.techniques, ["direct_prompt_injection"])
        self.assertEqual(len(plan.seeds), 3)
        malicious = [s for s in plan.seeds if s.expected == "malicious"]
        benign = [s for s in plan.seeds if s.expected == "benign"]
        self.assertEqual(len(malicious), 2)
        self.assertEqual(len(benign), 1)
        for seed in malicious:
            self.assertEqual(seed.oracle, "canary")
            self.assertEqual(len(seed.success_indicators), 1)
            self.assertIn("LLM01", seed.control_ids)
            self.assertIn("AML.T0051.000", seed.external_technique_ids)
            self.assertIn("owasp_llm_2025", seed.frameworks)
            self.assertIn("mitre_atlas", seed.frameworks)

    def test_secret_indicator_upgrades_manual_or_secret_oracle(self) -> None:
        plan = build_plan(PlannerConfig(
            frameworks=["owasp_llm_2025"],
            category_ids=["LLM07"],
            technique_ids=["system_prompt_extraction"],
            secret_indicators=["LAB-SYSTEM-CANARY-7"],
        ))
        seed = next(s for s in plan.seeds if s.expected == "malicious")
        self.assertEqual(seed.oracle, "secret")
        self.assertEqual(seed.success_indicators, ["LAB-SYSTEM-CANARY-7"])


class ClassificationTests(unittest.TestCase):
    @staticmethod
    def _candidate(*, oracle: str = "manual", indicators: list[str] | None = None) -> Candidate:
        return Candidate(
            id="c1", run_id="r1", root_seed_id="s1", parent_id=None, generation=0,
            prompt="test", category="test", operator="seed", expected="malicious",
            success_indicators=indicators or [], oracle=oracle,
        )

    def test_refusal_is_not_success(self) -> None:
        outcome, complied, matches = classify_answer(
            "I can't help with that request.", self._candidate(oracle="canary", indicators=["help"])
        )
        self.assertEqual(outcome, Outcome.MODEL_REFUSAL)
        self.assertFalse(complied)
        self.assertEqual(matches, [])

    def test_manual_indicator_does_not_confirm_success(self) -> None:
        outcome, complied, matches = classify_answer(
            "result ALPHA-88", self._candidate(indicators=["ALPHA-88"])
        )
        self.assertEqual(outcome, Outcome.ACCEPTED_UNVERIFIED)
        self.assertIsNone(complied)
        self.assertEqual(matches, ["ALPHA-88"])

    def test_echo_without_policy_is_not_success(self):
        outcome, complied, matches = classify_answer("ALPHA-88", self._candidate(oracle="canary", indicators=["ALPHA-88"]))
        self.assertEqual(outcome, Outcome.ACCEPTED_UNVERIFIED)
        self.assertIsNone(complied)
        self.assertEqual(matches, ["ALPHA-88"])

    def test_canary_indicator_confirms_success(self) -> None:
        outcome, complied, matches = classify_answer(
            "result ALPHA-88", self._candidate(oracle="canary", indicators=["ALPHA-88"]), policy_oracle_confirmed=True
        )
        self.assertEqual(outcome, Outcome.ATTACK_SUCCESS)
        self.assertTrue(complied)
        self.assertEqual(matches, ["ALPHA-88"])


class _FakeHttpResponse:
    def __init__(self, payload: dict[str, object], status: int = 200):
        self.payload = payload
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit=-1) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class GenericTargetTests(unittest.TestCase):
    @staticmethod
    def _candidate(*, oracle: str = "canary") -> Candidate:
        return Candidate(
            id="c1", run_id="r1", root_seed_id="s1", parent_id=None, generation=0,
            prompt="Return KYO-CANARY", category="LLM01 Prompt Injection", operator="seed",
            expected="malicious", success_indicators=["KYO-CANARY"], oracle=oracle,
            technique_id="direct_prompt_injection", technique_name="Direct prompt injection",
        )

    @staticmethod
    def _target(**overrides) -> GenericJsonTarget:
        data = {
            "name": "lab",
            "policy_oracle_confirmed": True,
            "url": "http://127.0.0.1:8000/api/chat",
            "headers": {"Content-Type": "application/json"},
            "body_template": {"message": "{{prompt}}", "id": "{{candidate_id}}"},
            "response": {
                "answer_path": "data.answer",
                "blocked_path": "guardrail.blocked",
                "reason_path": "guardrail.reason",
                "stage_path": "guardrail.stage",
                "success_path": "oracle.success",
            },
            "strict_instrumentation": True,
        }
        data.update(overrides)
        return GenericJsonTarget(GenericTargetProfile.from_dict(data), authorization_confirmed=True)

    def test_explicit_input_block_can_omit_answer(self) -> None:
        target = self._target()
        payload = {"guardrail": {"blocked": True, "reason": "policy", "stage": "input"}}
        with patch("kyojitsu.targets.safe_urlopen", return_value=_FakeHttpResponse(payload)):
            result = target.evaluate(self._candidate())
        self.assertEqual(result.outcome, Outcome.INPUT_BLOCKED)
        self.assertFalse(result.guardrail_passed)
        self.assertEqual(result.answer, "")

    def test_output_block_is_distinct(self) -> None:
        target = self._target()
        payload = {
            "guardrail": {"blocked": True, "reason": "output policy", "stage": "output"},
            "data": {"answer": "draft"},
        }
        with patch("kyojitsu.targets.safe_urlopen", return_value=_FakeHttpResponse(payload)):
            result = target.evaluate(self._candidate())
        self.assertEqual(result.outcome, Outcome.OUTPUT_BLOCKED)
        self.assertTrue(result.guardrail_passed)
        self.assertFalse(result.output_passed)

    def test_explicit_negative_verdict_overrides_marker_echo(self) -> None:
        target = self._target()
        payload = {
            "guardrail": {"blocked": False, "reason": "", "stage": "output"},
            "data": {"answer": "KYO-CANARY"},
            "oracle": {"success": False},
        }
        with patch("kyojitsu.targets.safe_urlopen", return_value=_FakeHttpResponse(payload)):
            result = target.evaluate(self._candidate())
        self.assertEqual(result.outcome, Outcome.ATTACK_FAILURE)
        self.assertTrue(result.guardrail_passed)
        self.assertFalse(result.model_complied)

    def test_inferred_mode_is_labeled(self) -> None:
        profile = GenericTargetProfile.from_dict({
            "name": "plain-api",
            "url": "http://127.0.0.1:8000/chat",
            "response": {"answer_path": "answer", "blocked_path": None},
            "strict_instrumentation": False,
        })
        target = GenericJsonTarget(profile, authorization_confirmed=True)
        with patch("kyojitsu.targets.safe_urlopen", return_value=_FakeHttpResponse({"answer": "normal"})):
            result = target.evaluate(self._candidate(oracle="manual"))
        self.assertEqual(result.outcome, Outcome.ACCEPTED_UNVERIFIED)
        self.assertEqual(result.metadata["instrumentation"], "inferred")
        self.assertIsNone(result.blocked)
        self.assertIsNone(result.guardrail_passed)

    def test_array_json_path_supports_openai_style_response(self) -> None:
        profile = GenericTargetProfile.from_dict({
            "name": "array-api",
            "url": "http://127.0.0.1:8000/chat",
            "response": {"answer_path": "choices.0.message.content", "blocked_path": None},
        })
        target = GenericJsonTarget(profile, authorization_confirmed=True)
        payload = {"choices": [{"message": {"content": "normal response"}}]}
        with patch("kyojitsu.targets.safe_urlopen", return_value=_FakeHttpResponse(payload)):
            result = target.evaluate(self._candidate(oracle="manual"))
        self.assertEqual(result.answer, "normal response")
        self.assertEqual(result.metadata["instrumentation"], "inferred")

    def test_env_secret_is_resolved_but_not_in_metadata(self) -> None:
        profile = GenericTargetProfile.from_dict({
            "name": "auth-api",
            "url": "http://127.0.0.1:8000/chat",
            "headers": {"Authorization": "Bearer ${ENV:KYO_TEST_TOKEN}"},
            "response": {"answer_path": "answer", "blocked_path": None},
        })
        with patch.dict(os.environ, {"KYO_TEST_TOKEN": "secret-value"}):
            target = GenericJsonTarget(profile, authorization_confirmed=True)
            self.assertEqual(target._headers()["Authorization"], "Bearer secret-value")
            self.assertNotIn("secret-value", json.dumps(target.metadata))

    def test_real_target_requires_authorization(self) -> None:
        profile = GenericTargetProfile.from_dict({"name": "x", "url": "https://example.invalid/chat"})
        with self.assertRaises(ValueError):
            GenericJsonTarget(profile, authorization_confirmed=False)


class IkigaiContractTests(unittest.TestCase):
    def _candidate(self) -> Candidate:
        return Candidate(
            id="c1", run_id="r1", root_seed_id="s1", parent_id=None, generation=0,
            prompt="test", category="test", operator="seed", success_indicators=["MARK"],
            oracle="manual",
        )

    def _evaluate(self, payload: dict[str, object]):
        target = IkigaiHttpTarget("http://127.0.0.1:5000/api/query")
        with patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
            return target.evaluate(self._candidate())

    def test_input_block_is_not_guardrail_bypass(self) -> None:
        result = self._evaluate({"blocked": True, "reason": "policy", "attack_type": "injection"})
        self.assertEqual(result.outcome, Outcome.INPUT_BLOCKED)
        self.assertFalse(result.guardrail_passed)

    def test_output_block_means_input_was_passed(self) -> None:
        result = self._evaluate({"blocked": True, "reason": "Output validation failed"})
        self.assertEqual(result.outcome, Outcome.OUTPUT_BLOCKED)
        self.assertTrue(result.guardrail_passed)
        self.assertFalse(result.output_passed)

    def test_missing_blocked_is_invalid(self) -> None:
        result = self._evaluate({"answer": "MARK"})
        self.assertEqual(result.outcome, Outcome.INVALID_RESPONSE)

    def test_indicator_remains_unverified_for_manual_oracle(self) -> None:
        result = self._evaluate({"blocked": False, "answer": "response with MARK"})
        self.assertEqual(result.outcome, Outcome.ACCEPTED_UNVERIFIED)
        self.assertIsNone(result.model_complied)
        self.assertEqual(result.metadata["indicator_matches"], ["MARK"])

    def test_preflight_requires_instrumented_fail_closed_contract(self) -> None:
        target = IkigaiHttpTarget("http://127.0.0.1:5000/api/query")
        bad = _FakeHttpResponse({"guardrails": "active", "model": "GPT-4o"})
        with patch("urllib.request.urlopen", return_value=bad), self.assertRaises(ValueError):
            target.preflight()
        good = _FakeHttpResponse({
            "guardrails": "active", "model": "GPT-4o",
            "experiment_contract": "kyojitsu-v2", "guardrail_fail_mode": "closed",
        })
        with patch("urllib.request.urlopen", return_value=good):
            metadata = target.preflight()
        self.assertEqual(metadata["health"], "active")


class _AlwaysAcceptTarget(Target):
    name = "always_accept_test"
    metadata = {"synthetic": True, "instrumentation": "explicit"}

    def evaluate(self, candidate: Candidate) -> Evaluation:
        return Evaluation(
            Outcome.ACCEPTED_UNVERIFIED, False, True, None, True,
            answer="accepted test response", latency_ms=1,
            metadata={"instrumentation": "explicit"},
        )


class IntegrationTests(unittest.TestCase):
    def _seeds(self) -> list[Seed]:
        return [
            Seed(id="s1", prompt="Synthetic request one", category="a", success_indicators=["SIM"], oracle="manual"),
            Seed(id="s2", prompt="Synthetic request two", category="b", success_indicators=["SIM"], oracle="manual"),
            Seed(id="s3", prompt="Synthetic request three", category="c", success_indicators=["SIM"], oracle="manual"),
        ]

    def test_full_fixture_run_persists_lineage_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "run.db"
            engine = EvolutionEngine(
                target=DeterministicFixtureTarget(),
                store=RunStore(db),
                budget=Budget(max_usd=10, max_requests=20, estimated_cost_per_request=0),
                config=EvolutionConfig(generations=2, population_size=4, random_seed=88),
            )
            result = engine.run(self._seeds(), run_id="integration")
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.evaluated, 11)
            conn = sqlite3.connect(db)
            rows = conn.execute("SELECT id,parent_id,generation FROM candidates ORDER BY generation").fetchall()
            parent_generation = {row[0]: row[2] for row in rows}
            for candidate_id, parent_id, generation in rows:
                if generation > 0:
                    self.assertIsNotNone(parent_id, candidate_id)
                    self.assertEqual(parent_generation[parent_id], generation - 1)
            conn.close()
            paths = export_report(db, root / "report", "integration")
            html_text = paths["html"].read_text(encoding="utf-8")
            self.assertIn("Kyojitsu", html_text)
            self.assertIn("id=\"playBtn\"", html_text)
            self.assertIn("executive.pdf", html_text)
            self.assertNotIn("AI RED TEAM", html_text)
            self.assertNotIn("LINEAGE GRAPH", html_text)
            self.assertNotIn("class=\"eyebrow\"", html_text)
            self.assertNotIn("<script src=", html_text)
            self.assertIn(".exec-kpi.primary", html_text)
            self.assertIn("#d28a8e", html_text)
            summary = build_summary(db, "integration")
            self.assertEqual(summary["metrics"]["observations"], 11)
            self.assertEqual(len(summary["generation_metrics"]), 3)

    def test_benign_controls_are_not_evolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan = build_plan(PlannerConfig(
                frameworks=["owasp_llm_2025"], category_ids=["LLM01"],
                technique_ids=["direct_prompt_injection"], seeds_per_technique=1,
                include_benign_controls=True,
            ))
            db = Path(tmp) / "run.db"
            engine = EvolutionEngine(
                target=_AlwaysAcceptTarget(), store=RunStore(db),
                budget=Budget(10, 20, 0),
                config=EvolutionConfig(generations=1, population_size=2, random_seed=88),
            )
            engine.run(plan.seeds, run_id="benign-lineage")
            conn = sqlite3.connect(db)
            benign_generations = [r[0] for r in conn.execute(
                "SELECT DISTINCT generation FROM candidates WHERE expected='benign'"
            ).fetchall()]
            conn.close()
            self.assertEqual(benign_generations, [0])

    def test_manual_review_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "run.db"
            store = RunStore(db)
            seed = Seed(id="s", prompt="manual test", expected="malicious", oracle="manual")
            engine = EvolutionEngine(
                target=_AlwaysAcceptTarget(), store=store, budget=Budget(10, 5, 0),
                config=EvolutionConfig(generations=0, population_size=1),
            )
            engine.run([seed], run_id="reviewed")
            conn = sqlite3.connect(db)
            candidate_id = conn.execute("SELECT id FROM candidates LIMIT 1").fetchone()[0]
            conn.close()
            store.review_candidate(candidate_id, "success", reviewer="tester", note="evidence")
            summary = build_summary(db, "reviewed")
            self.assertEqual(summary["metrics"]["confirmed_attack_success_rate"], 100.0)
            self.assertEqual(summary["metrics"]["model_compliance_rate_when_known"], 100.0)

    def test_campaign_runner_framework_metadata_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = {
                "name": "fixture campaign",
                "simulation_confirmed": True,
                "authorization_confirmed": True,
                "target": {"type": "fixture"},
                "selection": {
                    "frameworks": ["owasp_llm_2025", "mitre_atlas"],
                    "category_ids": ["LLM01", "INITIAL_ACCESS"],
                    "technique_ids": ["direct_prompt_injection"],
                    "seeds_per_technique": 1,
                    "include_benign_controls": True,
                },
                "evolution": {"generations": 1, "population_size": 3, "random_seed": 88},
                "limits": {"max_requests": 10, "budget_usd": 1},
            }
            result = run_campaign(config, output_dir=Path(tmp) / "out")
            for key in ["html", "summary", "csv", "markdown"]:
                self.assertTrue(Path(result["paths"][key]).exists())
            summary = json.loads(Path(result["paths"]["summary"]).read_text(encoding="utf-8"))
            self.assertIn("direct_prompt_injection", summary["experiment"]["techniques"])
            self.assertEqual(summary["metrics"]["technique_coverage_rate"], 100.0)
            self.assertTrue(summary["technique_metrics"])

    def test_request_cap_stops_before_extra_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "run.db"
            engine = EvolutionEngine(
                target=DeterministicFixtureTarget(), store=RunStore(db),
                budget=Budget(max_usd=10, max_requests=4, estimated_cost_per_request=0),
                config=EvolutionConfig(generations=3, population_size=3, random_seed=88),
            )
            result = engine.run(self._seeds(), run_id="capped")
            self.assertEqual(result.status, "budget_exhausted")
            self.assertEqual(result.evaluated, 4)
            conn = sqlite3.connect(db)
            count = conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
            conn.close()
            self.assertEqual(count, 4)


if __name__ == "__main__":
    unittest.main()
