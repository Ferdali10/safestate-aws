"""Tests for demo_agent.py without calling Bedrock.

All tests mock handle_invocation to avoid paid model inference.
Tests verify structured audit-based reporting, not LLM prose.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from io import StringIO
from unittest.mock import patch, MagicMock

import pytest

from demo_agent import (
    SCENARIOS,
    VALID_SCENARIO_NAMES,
    build_parser,
    count_audit_records,
    main_cli,
    print_audit_report,
    print_scenario_decisions,
    read_audit_records,
    run_scenario,
)


# ─────────────────────────────────────────────────────────────
# CLI argument parsing
# ─────────────────────────────────────────────────────────────

class TestArgParsing:
    def test_valid_read_ec2(self):
        parser = build_parser()
        args = parser.parse_args(["--scenario", "read-ec2"])
        assert args.scenario == "read-ec2"

    def test_valid_stop_production(self):
        parser = build_parser()
        args = parser.parse_args(["--scenario", "stop-production"])
        assert args.scenario == "stop-production"

    def test_valid_all(self):
        parser = build_parser()
        args = parser.parse_args(["--scenario", "all"])
        assert args.scenario == "all"

    def test_custom_audit_path(self):
        parser = build_parser()
        args = parser.parse_args(["--scenario", "read-ec2", "--audit-path", "/tmp/custom.jsonl"])
        assert args.audit_path == "/tmp/custom.jsonl"

    def test_default_audit_path(self):
        parser = build_parser()
        args = parser.parse_args(["--scenario", "read-ec2"])
        assert args.audit_path == "/tmp/safestate_strands_agent_audit.jsonl"

    def test_unknown_scenario_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--scenario", "unknown-scenario"])

    def test_missing_scenario_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


# ─────────────────────────────────────────────────────────────
# Scenario prompt construction
# ─────────────────────────────────────────────────────────────

class TestPromptConstruction:
    def test_read_ec2_prompt(self):
        scenario = SCENARIOS["read-ec2"]
        assert "EC2" in scenario["prompt"] or "ec2" in scenario["prompt"].lower()
        assert scenario["expected_rule"] == "R1"
        assert scenario["expected_status"] == "ALLOW"

    def test_stop_production_prompt(self):
        scenario = SCENARIOS["stop-production"]
        assert "i-prod-001" in scenario["prompt"]
        assert scenario["expected_rule"] == "R2"
        assert scenario["expected_status"] == "BLOCK"

    def test_all_scenarios_have_required_fields(self):
        for name, scenario in SCENARIOS.items():
            assert "prompt" in scenario, f"{name} missing prompt"
            assert "description" in scenario, f"{name} missing description"
            assert "expected_rule" in scenario, f"{name} missing expected_rule"
            assert "expected_status" in scenario, f"{name} missing expected_status"
            assert scenario["prompt"].strip(), f"{name} has empty prompt"


# ─────────────────────────────────────────────────────────────
# Structured R1 ALLOW reporting (using real SafeState Core)
# ─────────────────────────────────────────────────────────────

class TestStructuredR1Reporting:
    def test_r1_allow_produces_structured_decision(self, tmp_path):
        """Run the read-ec2 scenario with real SafeState Core (mocked Bedrock)
        and verify structured R1 ALLOW in the audit output."""
        audit_path = str(tmp_path / "r1_audit.jsonl")

        def _mock_handle(payload):
            from safestate_adapter import SafeStateRuntime
            from safestate_tools import set_runtime
            import os
            os.environ["SAFESTATE_AUDIT_PATH"] = audit_path
            rt = SafeStateRuntime(audit_path=audit_path)
            set_runtime(rt)
            rt.submit_action("LIST_INSTANCES")
            return {
                "response": "Listed instances.",
                "governance": {"agent_id": "safestate-strands-agent",
                               "mission_id": "cost-analysis-demo",
                               "audit_path": audit_path},
            }

        with patch("main.handle_invocation", side_effect=_mock_handle):
            with patch("main._runtime", None):
                result = run_scenario("read-ec2", audit_path)

        new_records = result["_audit_records"]
        assert len(new_records) >= 1
        r1 = new_records[0]
        assert r1["status"] == "ALLOW"
        assert r1["rule_id"] == "R1"
        assert r1["reason_code"] == "READ_WITHIN_MISSION"
        assert "decision_id" in r1
        assert "request_id" in r1

    def test_r1_printed_output_contains_structured_fields(self, tmp_path, capsys):
        audit_path = str(tmp_path / "r1_print_audit.jsonl")

        def _mock_handle(payload):
            from safestate_adapter import SafeStateRuntime
            from safestate_tools import set_runtime
            import os
            os.environ["SAFESTATE_AUDIT_PATH"] = audit_path
            rt = SafeStateRuntime(audit_path=audit_path)
            set_runtime(rt)
            rt.submit_action("LIST_INSTANCES")
            return {"response": "ok", "governance": {"audit_path": audit_path}}

        with patch("main.handle_invocation", side_effect=_mock_handle):
            with patch("main._runtime", None):
                run_scenario("read-ec2", audit_path)

        captured = capsys.readouterr()
        assert "ALLOW" in captured.out
        assert "R1" in captured.out
        assert "READ_WITHIN_MISSION" in captured.out
        assert "decision_id" in captured.out


# ─────────────────────────────────────────────────────────────
# Structured R2 BLOCK reporting (using real SafeState Core)
# ─────────────────────────────────────────────────────────────

class TestStructuredR2Reporting:
    def test_r2_block_produces_structured_decision(self, tmp_path):
        audit_path = str(tmp_path / "r2_audit.jsonl")

        def _mock_handle(payload):
            from safestate_adapter import SafeStateRuntime
            from safestate_tools import set_runtime
            import os
            os.environ["SAFESTATE_AUDIT_PATH"] = audit_path
            rt = SafeStateRuntime(audit_path=audit_path)
            set_runtime(rt)
            rt.submit_action("REQUEST_STOP_INSTANCE", resource_id="i-prod-001",
                             parameters={"reason": "test"})
            return {
                "response": "Blocked.",
                "governance": {"agent_id": "safestate-strands-agent",
                               "audit_path": audit_path},
            }

        with patch("main.handle_invocation", side_effect=_mock_handle):
            with patch("main._runtime", None):
                result = run_scenario("stop-production", audit_path)

        new_records = result["_audit_records"]
        assert len(new_records) >= 1
        r2 = new_records[0]
        assert r2["status"] == "BLOCK"
        assert r2["rule_id"] == "R2"
        assert r2["reason_code"] == "PRODUCTION_RESOURCE_PROTECTED"

    def test_r2_printed_output_contains_structured_fields(self, tmp_path, capsys):
        audit_path = str(tmp_path / "r2_print_audit.jsonl")

        def _mock_handle(payload):
            from safestate_adapter import SafeStateRuntime
            from safestate_tools import set_runtime
            import os
            os.environ["SAFESTATE_AUDIT_PATH"] = audit_path
            rt = SafeStateRuntime(audit_path=audit_path)
            set_runtime(rt)
            rt.submit_action("REQUEST_STOP_INSTANCE", resource_id="i-prod-001",
                             parameters={"reason": "test"})
            return {"response": "blocked", "governance": {"audit_path": audit_path}}

        with patch("main.handle_invocation", side_effect=_mock_handle):
            with patch("main._runtime", None):
                run_scenario("stop-production", audit_path)

        captured = capsys.readouterr()
        assert "BLOCK" in captured.out
        assert "R2" in captured.out
        assert "PRODUCTION_RESOURCE_PROTECTED" in captured.out


# ─────────────────────────────────────────────────────────────
# Historical records excluded from current-run results
# ─────────────────────────────────────────────────────────────

class TestHistoricalSeparation:
    def test_preexisting_records_excluded_from_scenario(self, tmp_path):
        audit_path = str(tmp_path / "hist_audit.jsonl")

        from safestate_adapter import SafeStateRuntime
        from safestate_tools import set_runtime
        rt = SafeStateRuntime(audit_path=audit_path)
        set_runtime(rt)
        rt.submit_action("LIST_INSTANCES")
        rt.submit_action("LIST_VOLUMES")
        pre_count = count_audit_records(audit_path)
        assert pre_count == 2

        def _mock_handle(payload):
            rt2 = SafeStateRuntime(audit_path=audit_path)
            set_runtime(rt2)
            rt2.submit_action("LIST_BUCKETS")
            return {"response": "ok", "governance": {"audit_path": audit_path}}

        with patch("main.handle_invocation", side_effect=_mock_handle):
            with patch("main._runtime", None):
                result = run_scenario("read-ec2", audit_path)

        new_records = result["_audit_records"]
        assert len(new_records) == 1
        assert new_records[0]["rule_id"] == "R1"
        assert result["_records_before"] == 2

    def test_audit_report_separates_historical_and_current(self, tmp_path, capsys):
        audit_path = str(tmp_path / "sep_audit.jsonl")

        from safestate_adapter import SafeStateRuntime
        from safestate_tools import set_runtime
        rt = SafeStateRuntime(audit_path=audit_path)
        set_runtime(rt)
        rt.submit_action("LIST_INSTANCES")
        rt.submit_action("REQUEST_STOP_INSTANCE", resource_id="i-prod-001",
                         parameters={"reason": "test"})

        print_audit_report(audit_path, historical_count=1)
        captured = capsys.readouterr()
        assert "Historical records (pre-existing): 1" in captured.out
        assert "Current-run records: 1" in captured.out


# ─────────────────────────────────────────────────────────────
# Two scenarios reported separately by 'all'
# ─────────────────────────────────────────────────────────────

class TestAllScenariosSeparation:
    @patch("demo_agent.run_scenario")
    @patch("demo_agent.print_audit_report")
    def test_all_runs_both_scenarios_sequentially(self, mock_report, mock_run, capsys):
        mock_run.return_value = {"response": "ok", "_audit_records": [], "_records_before": 0}
        exit_code = main_cli(["--scenario", "all"])
        assert exit_code == 0
        assert mock_run.call_count == 2
        scenario_names = [call[0][0] for call in mock_run.call_args_list]
        assert scenario_names == ["read-ec2", "stop-production"]

    def test_all_produces_separate_audit_records(self, tmp_path):
        audit_path = str(tmp_path / "all_audit.jsonl")
        call_count = [0]

        def _mock_handle(payload):
            from safestate_adapter import SafeStateRuntime
            from safestate_tools import set_runtime
            rt = SafeStateRuntime(audit_path=audit_path)
            set_runtime(rt)
            call_count[0] += 1
            if call_count[0] == 1:
                rt.submit_action("LIST_INSTANCES")
            else:
                rt.submit_action("REQUEST_STOP_INSTANCE", resource_id="i-prod-001",
                                 parameters={"reason": "test"})
            return {"response": "ok", "governance": {"audit_path": audit_path}}

        with patch("main.handle_invocation", side_effect=_mock_handle):
            with patch("main._runtime", None):
                r1 = run_scenario("read-ec2", audit_path)
                r2 = run_scenario("stop-production", audit_path)

        assert len(r1["_audit_records"]) == 1
        assert r1["_audit_records"][0]["status"] == "ALLOW"
        assert r1["_audit_records"][0]["rule_id"] == "R1"

        assert len(r2["_audit_records"]) == 1
        assert r2["_audit_records"][0]["status"] == "BLOCK"
        assert r2["_audit_records"][0]["rule_id"] == "R2"

    @patch("demo_agent.run_scenario")
    @patch("demo_agent.print_audit_report")
    def test_all_continues_after_first_failure(self, mock_report, mock_run, capsys):
        mock_run.side_effect = [RuntimeError("boom"),
                                {"response": "ok", "_audit_records": [], "_records_before": 0}]
        exit_code = main_cli(["--scenario", "all"])
        assert exit_code == 1
        assert mock_run.call_count == 2


# ─────────────────────────────────────────────────────────────
# Agent errors and missing audit records
# ─────────────────────────────────────────────────────────────

class TestErrorHandling:
    @patch("demo_agent.run_scenario")
    @patch("demo_agent.print_audit_report")
    def test_scenario_exception_returns_nonzero(self, mock_report, mock_run, capsys):
        mock_run.side_effect = RuntimeError("unexpected failure")
        exit_code = main_cli(["--scenario", "read-ec2"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "FATAL" in captured.out

    def test_valid_scenario_names(self):
        assert "read-ec2" in VALID_SCENARIO_NAMES
        assert "stop-production" in VALID_SCENARIO_NAMES
        assert "all" in VALID_SCENARIO_NAMES
        assert "unknown" not in VALID_SCENARIO_NAMES

    def test_scenario_with_no_audit_records(self, tmp_path, capsys):
        audit_path = str(tmp_path / "empty_audit.jsonl")

        with patch("main.handle_invocation") as mock_handle:
            with patch("main._runtime", None):
                mock_handle.return_value = {
                    "error": "AGENT_INVOCATION_FAILED",
                    "message": "Model access denied",
                }
                result = run_scenario("read-ec2", audit_path)

        assert result["error"] == "AGENT_INVOCATION_FAILED"
        assert len(result["_audit_records"]) == 0
        captured = capsys.readouterr()
        assert "No new audit records" in captured.out

    def test_print_scenario_decisions_empty(self, capsys):
        print_scenario_decisions([], "test")
        captured = capsys.readouterr()
        assert "No new audit records" in captured.out


# ─────────────────────────────────────────────────────────────
# Existing audit file preserved
# ─────────────────────────────────────────────────────────────

class TestAuditPreservation:
    def test_existing_validated_evidence_unchanged(self):
        import hashlib
        path = "/tmp/safestate_strands_agent_audit.jsonl"
        try:
            with open(path, "rb") as f:
                current_hash = hashlib.md5(f.read()).hexdigest()
            assert current_hash == "ae43c48b941bb2ee3dc42bab71d714b6"
        except FileNotFoundError:
            pytest.skip("Validated audit file not present in this environment")

    def test_audit_file_not_truncated_by_report(self, tmp_path):
        audit_path = str(tmp_path / "preserve_audit.jsonl")

        from safestate_adapter import SafeStateRuntime
        from safestate_tools import set_runtime
        rt = SafeStateRuntime(audit_path=audit_path)
        set_runtime(rt)
        rt.submit_action("LIST_INSTANCES")
        rt.submit_action("LIST_VOLUMES")

        before_count = count_audit_records(audit_path)
        print_audit_report(audit_path, historical_count=0)
        after_count = count_audit_records(audit_path)
        assert after_count == before_count

    def test_read_audit_records_on_missing_file(self):
        records = read_audit_records("/tmp/nonexistent_file_xyz.jsonl")
        assert records == []

    def test_count_audit_records_on_missing_file(self):
        assert count_audit_records("/tmp/nonexistent_file_xyz.jsonl") == 0


# ─────────────────────────────────────────────────────────────
# Blank-line robustness in JSONL reading
# ─────────────────────────────────────────────────────────────

class TestBlankLineRobustness:
    """Verify count_audit_records and read_audit_records stay consistent
    when the JSONL file contains blank lines."""

    def _write_lines(self, path: str, lines: list[str]) -> None:
        with open(path, "w") as f:
            for line in lines:
                f.write(line + "\n")

    def test_no_blank_lines(self, tmp_path):
        p = str(tmp_path / "clean.jsonl")
        self._write_lines(p, [
            '{"status":"ALLOW","rule_id":"R1"}',
            '{"status":"BLOCK","rule_id":"R2"}',
            '{"status":"ALLOW","rule_id":"R1"}',
        ])
        assert count_audit_records(p) == 3
        assert len(read_audit_records(p)) == 3
        assert len(read_audit_records(p, start=2)) == 1
        assert read_audit_records(p, start=2)[0]["rule_id"] == "R1"

    def test_blank_lines_before_records(self, tmp_path):
        p = str(tmp_path / "leading.jsonl")
        self._write_lines(p, [
            "",
            "",
            '{"status":"ALLOW","rule_id":"R1"}',
            '{"status":"BLOCK","rule_id":"R2"}',
        ])
        assert count_audit_records(p) == 2
        all_records = read_audit_records(p)
        assert len(all_records) == 2
        after_first = read_audit_records(p, start=1)
        assert len(after_first) == 1
        assert after_first[0]["rule_id"] == "R2"

    def test_blank_lines_between_records(self, tmp_path):
        p = str(tmp_path / "gaps.jsonl")
        self._write_lines(p, [
            '{"status":"ALLOW","rule_id":"R1"}',
            "",
            "",
            '{"status":"BLOCK","rule_id":"R2"}',
            "",
            '{"status":"ALLOW","rule_id":"R1"}',
        ])
        assert count_audit_records(p) == 3
        all_records = read_audit_records(p)
        assert len(all_records) == 3
        after_two = read_audit_records(p, start=2)
        assert len(after_two) == 1
        assert after_two[0]["rule_id"] == "R1"

    def test_historical_current_separation_with_blanks(self, tmp_path):
        p = str(tmp_path / "mixed.jsonl")
        self._write_lines(p, [
            '{"status":"ALLOW","rule_id":"R1","note":"historical"}',
            "",
            '{"status":"BLOCK","rule_id":"R2","note":"historical"}',
            "",
            "",
            '{"status":"ALLOW","rule_id":"R1","note":"current"}',
        ])
        historical_count = 2
        total = count_audit_records(p)
        assert total == 3

        historical = read_audit_records(p, start=0)[:historical_count]
        current = read_audit_records(p, start=historical_count)
        assert len(historical) == 2
        assert len(current) == 1
        assert all(r["note"] == "historical" for r in historical)
        assert current[0]["note"] == "current"


# ─────────────────────────────────────────────────────────────
# Audit verification reporting
# ─────────────────────────────────────────────────────────────

class TestAuditReport:
    def test_report_with_valid_audit_file(self, capsys):
        print_audit_report("/tmp/safestate_strands_agent_audit.jsonl")
        captured = capsys.readouterr()
        assert "Chain valid" in captured.out
        assert "Total records" in captured.out

    def test_report_with_missing_file(self, capsys):
        print_audit_report("/tmp/nonexistent_audit_file_12345.jsonl")
        captured = capsys.readouterr()
        assert "No audit records found" in captured.out

    def test_report_with_real_validated_evidence(self, capsys):
        print_audit_report("/tmp/safestate_strands_agent_audit.jsonl")
        captured = capsys.readouterr()
        assert "True" in captured.out

    def test_report_counts_decisions(self, tmp_path):
        audit_path = str(tmp_path / "test_audit.jsonl")
        from safestate_adapter import SafeStateRuntime
        from safestate_tools import set_runtime
        rt = SafeStateRuntime(audit_path=audit_path)
        set_runtime(rt)

        rt.submit_action("LIST_INSTANCES")
        rt.submit_action("LIST_VOLUMES")
        rt.submit_action("REQUEST_STOP_INSTANCE", resource_id="i-prod-001",
                         parameters={"reason": "test"})

        import sys
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        print_audit_report(audit_path, historical_count=0)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout

        assert "ALLOW" in output
        assert "BLOCK" in output
        assert "R1" in output
        assert "R2" in output
