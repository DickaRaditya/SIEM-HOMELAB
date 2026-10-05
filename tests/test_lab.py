"""Regression tests for trustworthy evidence and isolation (no Docker required)."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("lab", Path(__file__).resolve().parents[1] / "scripts/lab.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_root = lab.ROOT / ".cache/tests"
        cls.temp_root.mkdir(parents=True, exist_ok=True)

    def test_failure_is_never_reported_as_pass(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as tmp, patch.object(lab, "ROOT", Path(tmp)):
            passed = lab.save_report("test", [], [], {"endpoint connected": True, "rule indexed": False}, "start")
            report = json.loads((Path(tmp) / "evidence/runs/test/result.json").read_text())
            self.assertFalse(passed)
            self.assertFalse(report["passed"])
            self.assertEqual(report["alert_count"], 0)

    def test_exception_is_preserved_even_if_prior_checks_pass(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as tmp, patch.object(lab, "ROOT", Path(tmp)):
            self.assertFalse(lab.save_report("test", [], [], {"prior check": True}, "start", "indexer unavailable"))
            report = json.loads((Path(tmp) / "evidence/runs/test/result.json").read_text())
            self.assertEqual(report["error"], "indexer unavailable")

    def test_runs_do_not_share_correlation_keys(self):
        first, second = lab.make_events("run-a"), lab.make_events("run-b")
        self.assertTrue(all(e["synthetic"] for e in first + second))
        self.assertTrue({e["correlation_key"] for e in first}.isdisjoint({e["correlation_key"] for e in second}))
        self.assertEqual(sum(e.get("lab_case") == "benign" for e in first), 3)

    def test_search_scopes_to_run_and_endpoint(self):
        with patch.object(lab, "index_request", return_value={"hits": {"hits": []}}) as request:
            lab.search_alerts("run-a")
            query = request.call_args.args[1]["query"]["bool"]
            self.assertEqual(query["filter"], [{"term": {"agent.name": "lab-linux"}}])
            self.assertEqual(query["minimum_should_match"], 1)
            self.assertIn({"term": {"data.lab_run_id": "run-a"}}, query["should"])

    def test_api_path_rejects_shell_metacharacters(self):
        with self.assertRaises(ValueError):
            lab.index_request("_search; touch unwanted")

    def test_poll_returns_only_when_required_rule_is_observed(self):
        alerts = [{"rule": {"id": "100101"}}]
        with patch.object(lab, "search_alerts", return_value=alerts):
            self.assertEqual(lab.await_alerts("run-a", {"100101"}, timeout=1), alerts)

    def test_password_stdin_preserves_lf_on_windows(self):
        with patch.object(lab.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"ok", b"")) as process:
            lab.run(["docker", "run"], input="test-password\n", capture=True)
            self.assertEqual(process.call_args.kwargs["input"], b"test-password\n")
            self.assertNotIn("text", process.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
