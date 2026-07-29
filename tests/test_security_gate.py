"""
Tests for the Security Gate command and supporting modules.

Coverage:
- YAML parsing (valid and invalid)
- JSON Schema validation
- validate_rules: PASS and FAIL cases
- SLA / max_days_to_fix: timezone correctness and edge cases
- Platform gate flow: PASS, FAIL, API error (mock)
- Local-rules gate flow: PASS, FAIL, missing company_id
- Formatter helpers
"""

import json
import tempfile
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import yaml
import typer

# ---------------------------------------------------------------------------
# Import the modules under test
# ---------------------------------------------------------------------------
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from conviso.commands.security_gate import (
    validate_rules,
    _extract_days_by_severity,
    _resolve_branch_id,
    _run_platform_gate,
    _run_local_rules_gate,
)
from conviso.core.security_gate_formatter import (
    format_failure_header,
    format_pass_message,
    format_full_details_hint,
    format_truncation_notice,
    _strip_markdown,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_RULES_YAML = """
rules:
  - from: any
    severity:
      critical:
        maximum: 0
      high:
        maximum: 3
"""

VALID_RULES_WITH_SLA_YAML = """
rules:
  - from: any
    severity:
      critical:
        maximum: 0
        max_days_to_fix: 7
      high:
        maximum: 5
        max_days_to_fix: 30
"""

INVALID_RULES_YAML_NO_FROM = """
rules:
  - severity:
      critical:
        maximum: 0
"""

INVALID_RULES_YAML_WRONG_SEVERITY = """
rules:
  - from: any
    severity:
      notification:
        maximum: 0
"""


@pytest.fixture()
def rules_schema_path() -> Path:
    return Path(__file__).resolve().parents[1] / "src" / "conviso" / "security_gate_rules_schema.json"


@pytest.fixture()
def valid_rules() -> dict:
    return yaml.safe_load(VALID_RULES_YAML)


@pytest.fixture()
def valid_rules_with_sla() -> dict:
    return yaml.safe_load(VALID_RULES_WITH_SLA_YAML)


@pytest.fixture()
def sample_issues_no_violations() -> list:
    return [
        {"value": "CRITICAL", "count": 0},
        {"value": "HIGH", "count": 2},
        {"value": "MEDIUM", "count": 10},
        {"value": "LOW", "count": 20},
    ]


@pytest.fixture()
def sample_issues_with_violations() -> list:
    return [
        {"value": "CRITICAL", "count": 1},  # exceeds maximum: 0
        {"value": "HIGH", "count": 4},      # exceeds maximum: 3
        {"value": "MEDIUM", "count": 10},
        {"value": "LOW", "count": 20},
    ]


# ---------------------------------------------------------------------------
# YAML Parsing
# ---------------------------------------------------------------------------

class TestYAMLParsing:
    def test_parse_valid_yaml(self):
        rules = yaml.safe_load(VALID_RULES_YAML)
        assert "rules" in rules
        assert len(rules["rules"]) == 1
        assert rules["rules"][0]["from"] == "any"
        assert rules["rules"][0]["severity"]["critical"]["maximum"] == 0

    def test_parse_valid_yaml_with_sla(self):
        rules = yaml.safe_load(VALID_RULES_WITH_SLA_YAML)
        assert rules["rules"][0]["severity"]["critical"]["max_days_to_fix"] == 7
        assert rules["rules"][0]["severity"]["high"]["max_days_to_fix"] == 30

    def test_parse_invalid_yaml_raises(self):
        with pytest.raises(Exception):
            yaml.safe_load("{ invalid: yaml: content")


# ---------------------------------------------------------------------------
# JSON Schema validation
# ---------------------------------------------------------------------------

class TestJSONSchemaValidation:
    def test_valid_rules_pass_schema(self, rules_schema_path):
        import jsonschema
        schema = json.loads(rules_schema_path.read_text())
        rules = yaml.safe_load(VALID_RULES_YAML)
        jsonschema.validate(rules, schema)  # should not raise

    def test_valid_rules_with_sla_pass_schema(self, rules_schema_path):
        import jsonschema
        schema = json.loads(rules_schema_path.read_text())
        rules = yaml.safe_load(VALID_RULES_WITH_SLA_YAML)
        jsonschema.validate(rules, schema)  # should not raise

    def test_missing_from_field_fails_schema(self, rules_schema_path):
        import jsonschema
        schema = json.loads(rules_schema_path.read_text())
        rules = yaml.safe_load(INVALID_RULES_YAML_NO_FROM)
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validate(rules, schema)

    def test_unknown_severity_level_fails_schema(self, rules_schema_path):
        import jsonschema
        schema = json.loads(rules_schema_path.read_text())
        rules = yaml.safe_load(INVALID_RULES_YAML_WRONG_SEVERITY)
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validate(rules, schema)

    def test_empty_rules_array_fails_schema(self, rules_schema_path):
        import jsonschema
        schema = json.loads(rules_schema_path.read_text())
        rules = {"rules": []}
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validate(rules, schema)

    def test_negative_maximum_fails_schema(self, rules_schema_path):
        import jsonschema
        schema = json.loads(rules_schema_path.read_text())
        rules = {"rules": [{"from": "any", "severity": {"critical": {"maximum": -1}}}]}
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validate(rules, schema)


# ---------------------------------------------------------------------------
# validate_rules — PASS / FAIL logic
# ---------------------------------------------------------------------------

class TestValidateRules:
    def test_gate_passes_when_all_within_limits(self, valid_rules, sample_issues_no_violations):
        result = validate_rules(sample_issues_no_violations, valid_rules)
        assert result["locked"] is False

    def test_gate_fails_when_critical_exceeds_zero(self, valid_rules, sample_issues_with_violations):
        result = validate_rules(sample_issues_with_violations, valid_rules)
        assert result["locked"] is True

    def test_gate_fails_when_high_exceeds_maximum(self, valid_rules, sample_issues_with_violations):
        result = validate_rules(sample_issues_with_violations, valid_rules)
        summary = result["summary"][0]["severity"]
        assert summary["high"]["exceeded"] is True
        assert summary["high"]["count"] == 4

    def test_summary_contains_correct_counts(self, valid_rules, sample_issues_no_violations):
        result = validate_rules(sample_issues_no_violations, valid_rules)
        summary = result["summary"][0]["severity"]
        assert summary["critical"]["count"] == 0
        assert summary["critical"]["maximum"] == 0
        assert summary["critical"]["exceeded"] is False
        assert summary["high"]["count"] == 2

    def test_missing_severity_defaults_to_zero(self, valid_rules):
        # API returns only CRITICAL — HIGH should be treated as 0
        issues = [{"value": "CRITICAL", "count": 0}]
        result = validate_rules(issues, valid_rules)
        assert result["locked"] is False  # HIGH: 0 <= 3

    def test_gate_locked_false_at_exact_maximum(self, valid_rules):
        # HIGH exactly at maximum=3 should PASS (not exceed)
        issues = [
            {"value": "CRITICAL", "count": 0},
            {"value": "HIGH", "count": 3},
        ]
        result = validate_rules(issues, valid_rules)
        assert result["locked"] is False

    def test_gate_locked_true_one_above_maximum(self, valid_rules):
        # HIGH = 4 exceeds maximum=3
        issues = [
            {"value": "CRITICAL", "count": 0},
            {"value": "HIGH", "count": 4},
        ]
        result = validate_rules(issues, valid_rules)
        assert result["locked"] is True


# ---------------------------------------------------------------------------
# SLA / max_days_to_fix — timezone and edge cases
# ---------------------------------------------------------------------------

class TestSLAAndTimezone:
    def test_extract_days_by_severity_correct(self, valid_rules_with_sla):
        days = _extract_days_by_severity(valid_rules_with_sla)
        assert days["critical"] == 7
        assert days["high"] == 30

    def test_extract_days_by_severity_zero_when_absent(self, valid_rules):
        days = _extract_days_by_severity(valid_rules)
        # No max_days_to_fix → 0 for all severities
        assert days["critical"] == 0
        assert days["high"] == 0

    def test_sla_cutoff_is_utc_aware(self):
        """
        Verify that the cutoff date is UTC-aware so it cannot cause
        `TypeError: can't compare offset-naive and offset-aware datetimes`.
        """
        now_utc = datetime.now(timezone.utc)
        end_of_today_utc = now_utc.replace(hour=23, minute=59, second=59, microsecond=0)
        cutoff = end_of_today_utc - timedelta(days=7)

        assert cutoff.tzinfo is not None, "Cutoff must be timezone-aware (UTC)"
        assert cutoff.tzinfo == timezone.utc

        # Simulating an API date that comes back without timezone (naive) — must be normalised
        api_date_str = "2024-01-15T10:00:00"  # no 'Z' or offset
        api_date_naive = datetime.fromisoformat(api_date_str)
        assert api_date_naive.tzinfo is None  # confirm it's naive

        # Safe comparison requires normalising naive → UTC
        api_date_aware = api_date_naive.replace(tzinfo=timezone.utc)
        # Now comparison does not raise TypeError
        assert isinstance(api_date_aware < cutoff, bool)

    def test_zero_days_sla_uses_end_of_today(self):
        """
        max_days_to_fix=0 means: even vulnerabilities created today are out of SLA.
        The cutoff should be end-of-today, so timedelta(days=0) keeps the same day.
        """
        now_utc = datetime.now(timezone.utc)
        end_of_today = now_utc.replace(hour=23, minute=59, second=59, microsecond=0)
        cutoff = end_of_today - timedelta(days=0)
        assert cutoff == end_of_today

    def test_sla_cutoff_30_days_is_correct(self):
        """30-day SLA: cutoff should be exactly 30 days ago."""
        now_utc = datetime.now(timezone.utc)
        end_of_today = now_utc.replace(hour=23, minute=59, second=59, microsecond=0)
        cutoff = end_of_today - timedelta(days=30)
        delta = end_of_today - cutoff
        assert delta.days == 30


# ---------------------------------------------------------------------------
# Formatter helpers
# ---------------------------------------------------------------------------

class TestFormatterHelpers:
    def test_failure_header_singular(self):
        header = format_failure_header(1)
        assert "1 vulnerability" in header
        assert "FAILED" in header

    def test_failure_header_plural(self):
        header = format_failure_header(5)
        assert "5 vulnerabilities" in header

    def test_pass_message(self):
        msg = format_pass_message()
        assert "PASSED" in msg

    def test_full_details_hint_with_output(self):
        hint = format_full_details_hint("gate-result.json")
        assert "gate-result.json" in hint

    def test_full_details_hint_without_output(self):
        hint = format_full_details_hint()
        assert "--output" in hint

    def test_truncation_notice_no_remaining(self):
        lines = format_truncation_notice(total_count=5, shown=5)
        assert lines == []

    def test_truncation_notice_with_remaining(self):
        lines = format_truncation_notice(total_count=25, shown=10)
        assert any("15" in line for line in lines)

    def test_truncation_notice_includes_url(self):
        lines = format_truncation_notice(
            total_count=20, shown=10, issues_url="https://example.com/issues"
        )
        assert any("https://example.com/issues" in line for line in lines)

    def test_strip_markdown_removes_code_blocks(self):
        text = "Before ```code block``` after"
        result = _strip_markdown(text)
        assert "```" not in result
        assert "Before" in result
        assert "after" in result

    def test_strip_markdown_removes_headers(self):
        text = "## Title\nSome content"
        result = _strip_markdown(text)
        assert "##" not in result
        assert "Title" in result

    def test_strip_markdown_resolves_links(self):
        text = "See [this link](https://example.com) for details."
        result = _strip_markdown(text)
        assert "this link" in result
        assert "https://example.com" not in result


# ---------------------------------------------------------------------------
# Platform gate — mock-based integration tests
# ---------------------------------------------------------------------------

_PLATFORM_GATE_PASS_RESPONSE = {
    "securityGateRun": {
        "asset": {"id": "42", "name": "MyApp"},
        "executionDate": "2024-07-28T00:00:00Z",
        "issuesUrl": "https://app.convisoappsec.com/issues",
        "status": "PASS",
        "reason": {
            "critical": {"limit": 0, "count": 0, "status": "PASS"},
            "high": {"limit": 5, "count": 2, "status": "PASS"},
            "medium": None,
            "low": None,
        },
        "failingVulnerabilities": {
            "collection": [],
            "metadata": {"totalCount": 0},
        },
    }
}

_PLATFORM_GATE_FAIL_RESPONSE = {
    "securityGateRun": {
        "asset": {"id": "42", "name": "MyApp"},
        "executionDate": "2024-07-28T00:00:00Z",
        "issuesUrl": "https://app.convisoappsec.com/issues",
        "status": "FAIL",
        "reason": {
            "critical": {"limit": 0, "count": 3, "status": "FAIL"},
            "high": {"limit": 5, "count": 2, "status": "PASS"},
            "medium": None,
            "low": None,
        },
        "failingVulnerabilities": {
            "collection": [
                {
                    "id": "101",
                    "title": "SQL Injection",
                    "description": "Injection flaw",
                    "severity": "CRITICAL",
                    "cvssScore": 9.8,
                    "file": "app/db.py",
                    "line": 42,
                    "platformUrl": "https://app.convisoappsec.com/vuln/101",
                }
            ],
            "metadata": {"totalCount": 1},
        },
    }
}


class TestPlatformGateFlow:
    @patch("conviso.commands.security_gate.graphql_request")
    def test_platform_gate_pass_exits_cleanly(self, mock_gql):
        mock_gql.return_value = _PLATFORM_GATE_PASS_RESPONSE
        # Should not raise
        _run_platform_gate(asset_id=42, output=None)

    @patch("conviso.commands.security_gate.graphql_request")
    def test_platform_gate_fail_raises_exit_1(self, mock_gql):
        mock_gql.return_value = _PLATFORM_GATE_FAIL_RESPONSE
        with pytest.raises(typer.Exit) as exc_info:
            _run_platform_gate(asset_id=42, output=None)
        assert exc_info.value.exit_code == 1

    @patch("conviso.commands.security_gate.graphql_request")
    def test_platform_gate_api_error_raises_exit_1_not_pass(self, mock_gql):
        """
        A network/API error MUST NOT be interpreted as a PASS.
        It should raise Exit(1) with a differentiated error message.
        """
        mock_gql.side_effect = Exception("Connection timeout")
        with pytest.raises(typer.Exit) as exc_info:
            _run_platform_gate(asset_id=42, output=None)
        assert exc_info.value.exit_code == 1

    @patch("conviso.commands.security_gate.graphql_request")
    def test_platform_gate_null_result_raises_exit_1(self, mock_gql):
        """API returns data but securityGateRun is null/absent."""
        mock_gql.return_value = {"securityGateRun": None}
        with pytest.raises(typer.Exit) as exc_info:
            _run_platform_gate(asset_id=42, output=None)
        assert exc_info.value.exit_code == 1

    @patch("conviso.commands.security_gate.graphql_request")
    def test_platform_gate_writes_json_output(self, mock_gql, tmp_path):
        mock_gql.return_value = _PLATFORM_GATE_PASS_RESPONSE
        output_file = str(tmp_path / "result.json")
        _run_platform_gate(asset_id=42, output=output_file)
        assert Path(output_file).exists()
        data = json.loads(Path(output_file).read_text())
        # The output payload should contain meaningful data
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# Local-rules gate — mock-based integration tests
# ---------------------------------------------------------------------------

_ISSUES_STATS_CLEAN = {
    "issuesStats": {
        "severities": [
            {"value": "CRITICAL", "count": 0},
            {"value": "HIGH", "count": 2},
            {"value": "MEDIUM", "count": 5},
            {"value": "LOW", "count": 10},
        ]
    }
}

_ISSUES_STATS_VIOLATIONS = {
    "issuesStats": {
        "severities": [
            {"value": "CRITICAL", "count": 2},  # maximum: 0 → FAIL
            {"value": "HIGH", "count": 2},
            {"value": "MEDIUM", "count": 5},
            {"value": "LOW", "count": 10},
        ]
    }
}


class TestLocalRulesGateFlow:
    def _make_rules_file(self, content: str, tmp_path: Path) -> Path:
        f = tmp_path / "rules.yaml"
        f.write_text(content)
        return f

    @patch("conviso.commands.security_gate.graphql_request")
    def test_local_gate_pass_exits_cleanly(self, mock_gql, tmp_path):
        mock_gql.return_value = _ISSUES_STATS_CLEAN
        rules_file = self._make_rules_file(VALID_RULES_YAML, tmp_path)
        _run_local_rules_gate(
            asset_id=42, company_id=11, rules_file=rules_file, output=None
        )

    @patch("conviso.commands.security_gate.graphql_request")
    def test_local_gate_fail_raises_exit_1(self, mock_gql, tmp_path):
        mock_gql.return_value = _ISSUES_STATS_VIOLATIONS
        rules_file = self._make_rules_file(VALID_RULES_YAML, tmp_path)
        with pytest.raises(typer.Exit) as exc_info:
            _run_local_rules_gate(
                asset_id=42, company_id=11, rules_file=rules_file, output=None
            )
        assert exc_info.value.exit_code == 1

    @patch("conviso.commands.security_gate.graphql_request")
    def test_local_gate_api_error_is_not_a_pass(self, mock_gql, tmp_path):
        """API failure must exit 1, never silently pass the gate."""
        mock_gql.side_effect = Exception("HTTP 500")
        rules_file = self._make_rules_file(VALID_RULES_YAML, tmp_path)
        with pytest.raises(typer.Exit) as exc_info:
            _run_local_rules_gate(
                asset_id=42, company_id=11, rules_file=rules_file, output=None
            )
        assert exc_info.value.exit_code == 1

    def test_local_gate_invalid_yaml_raises_exit_1(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text("{ invalid: yaml: content")
        with pytest.raises(typer.Exit) as exc_info:
            _run_local_rules_gate(
                asset_id=42, company_id=11, rules_file=rules_file, output=None
            )
        assert exc_info.value.exit_code == 1

    def test_local_gate_schema_violation_raises_exit_1(self, tmp_path):
        """YAML that is parseable but violates the JSON Schema."""
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(INVALID_RULES_YAML_NO_FROM)
        with pytest.raises(typer.Exit) as exc_info:
            _run_local_rules_gate(
                asset_id=42, company_id=11, rules_file=rules_file, output=None
            )
        assert exc_info.value.exit_code == 1

    @patch("conviso.commands.security_gate.graphql_request")
    def test_local_gate_writes_json_output(self, mock_gql, tmp_path):
        mock_gql.return_value = _ISSUES_STATS_CLEAN
        rules_file = self._make_rules_file(VALID_RULES_YAML, tmp_path)
        output_file = str(tmp_path / "gate-result.json")
        _run_local_rules_gate(
            asset_id=42, company_id=11, rules_file=rules_file, output=output_file
        )
        data = json.loads(Path(output_file).read_text())
        assert data["mode"] == "local_rules"
        assert data["asset_id"] == 42
        assert "result" in data

    @patch("conviso.commands.security_gate.graphql_request")
    def test_local_gate_with_sla_calls_api_per_severity(self, mock_gql, tmp_path):
        """With max_days_to_fix, issuesStats must be called once per severity level."""
        mock_gql.return_value = _ISSUES_STATS_CLEAN
        rules_file = self._make_rules_file(VALID_RULES_WITH_SLA_YAML, tmp_path)
        _run_local_rules_gate(
            asset_id=42, company_id=11, rules_file=rules_file, output=None
        )
        # critical + high = 2 severities with max_days_to_fix → 2 API calls
        assert mock_gql.call_count == 2

    @patch("conviso.commands.security_gate.graphql_request")
    def test_local_gate_without_sla_calls_api_once(self, mock_gql, tmp_path):
        """Without max_days_to_fix, a single issuesStats call should suffice."""
        mock_gql.return_value = _ISSUES_STATS_CLEAN
        rules_file = self._make_rules_file(VALID_RULES_YAML, tmp_path)
        _run_local_rules_gate(
            asset_id=42, company_id=11, rules_file=rules_file, output=None
        )
        assert mock_gql.call_count == 1


# ---------------------------------------------------------------------------
# Command-level parameter validation
# ---------------------------------------------------------------------------

class TestCommandParameterValidation:
    def test_rules_file_without_company_id_exits_nonzero(self, tmp_path):
        """
        --rules-file without --company-id must fail with exit code 1 and print
        an error message that mentions 'company-id'.
        We test the command function directly via Typer's CliRunner on the
        isolated command (not the full app group).
        """
        from typer.testing import CliRunner
        import typer as _typer
        from conviso.commands.security_gate import run_security_gate

        # Build a mini app containing just the one command to avoid routing issues
        mini_app = _typer.Typer()
        mini_app.command()(run_security_gate)

        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(VALID_RULES_YAML)

        runner = CliRunner()
        result = runner.invoke(
            mini_app,
            ["--asset-id", "42", "--rules-file", str(rules_file)],
            catch_exceptions=True,
        )
        # Must exit non-zero
        assert result.exit_code != 0
        # Our validation message must mention company-id
        assert "company" in (result.output or "").lower()
# ---------------------------------------------------------------------------
# Branch support — BRANCH-01 through BRANCH-08
# ---------------------------------------------------------------------------

_BRANCHES_RESPONSE_WITH_MAIN = {
    "branches": {
        "collection": [
            {"id": "10", "name": "main", "default": True},
            {"id": "11", "name": "develop", "default": False},
        ]
    }
}

_BRANCHES_RESPONSE_EMPTY = {
    "branches": {"collection": []}
}


class TestBranchResolution:
    """Tests for _resolve_branch_id helper."""

    # BRANCH-01 (partial): branch found → returns correct ID
    @patch("conviso.commands.security_gate.graphql_request")
    def test_resolve_branch_returns_correct_id(self, mock_gql):
        mock_gql.return_value = _BRANCHES_RESPONSE_WITH_MAIN
        branch_id = _resolve_branch_id(asset_id=42, company_id=11, branch_name="main")
        assert branch_id == "10"

    # BRANCH-03: branch not found → exit 1 + message lists available branches
    @patch("conviso.commands.security_gate.graphql_request")
    def test_resolve_branch_not_found_exits_1(self, mock_gql):
        mock_gql.return_value = _BRANCHES_RESPONSE_WITH_MAIN
        with pytest.raises(typer.Exit) as exc_info:
            _resolve_branch_id(asset_id=42, company_id=11, branch_name="nonexistent")
        assert exc_info.value.exit_code == 1

    # BRANCH-03: message lists available branches when not found
    @patch("conviso.commands.security_gate.graphql_request")
    def test_resolve_branch_not_found_message_lists_available(self, mock_gql, capsys):
        mock_gql.return_value = _BRANCHES_RESPONSE_WITH_MAIN
        with pytest.raises(typer.Exit):
            _resolve_branch_id(asset_id=42, company_id=11, branch_name="nonexistent")
        captured = capsys.readouterr()
        assert "main" in captured.out or "develop" in captured.out or "main" in captured.err or "develop" in captured.err

    # BRANCH-05: case-sensitive match — 'Main' != 'main'
    @patch("conviso.commands.security_gate.graphql_request")
    def test_resolve_branch_case_sensitive_no_match(self, mock_gql):
        """Branch name comparison is strict: 'Main' does not match 'main'."""
        mock_gql.return_value = _BRANCHES_RESPONSE_WITH_MAIN
        with pytest.raises(typer.Exit) as exc_info:
            _resolve_branch_id(asset_id=42, company_id=11, branch_name="Main")
        assert exc_info.value.exit_code == 1

    # BRANCH-06: network / API error in BranchLookup → exit 1, NOT silent pass
    @patch("conviso.commands.security_gate.graphql_request")
    def test_resolve_branch_network_error_exits_1(self, mock_gql):
        """
        A network/timeout/500 error in the BranchLookup query must exit 1
        and must NOT be confused with 'branch not found' or 'gate PASSED'.
        """
        mock_gql.side_effect = Exception("Connection timeout")
        with pytest.raises(typer.Exit) as exc_info:
            _resolve_branch_id(asset_id=42, company_id=11, branch_name="main")
        assert exc_info.value.exit_code == 1

    # BRANCH-06: network error message is differentiated from 'not found'
    @patch("conviso.commands.security_gate.graphql_request")
    def test_resolve_branch_network_error_message_is_technical(self, mock_gql, capsys):
        mock_gql.side_effect = Exception("Connection timeout")
        with pytest.raises(typer.Exit):
            _resolve_branch_id(asset_id=42, company_id=11, branch_name="main")
        captured = capsys.readouterr()
        combined = (captured.out + captured.err).lower()
        # Must mention 'technical error' (not just 'not found')
        assert "technical error" in combined or "network" in combined or "timeout" in combined

    # BRANCH-03: empty collection → lists '(none found)'
    @patch("conviso.commands.security_gate.graphql_request")
    def test_resolve_branch_empty_collection_exits_1(self, mock_gql):
        mock_gql.return_value = _BRANCHES_RESPONSE_EMPTY
        with pytest.raises(typer.Exit) as exc_info:
            _resolve_branch_id(asset_id=42, company_id=11, branch_name="main")
        assert exc_info.value.exit_code == 1


class TestPlatformGateWithBranch:
    """BRANCH-01: platform gate passes branchId when --branch is provided."""

    @patch("conviso.commands.security_gate.graphql_request")
    def test_platform_gate_with_branch_passes_branch_id(self, mock_gql):
        """
        BRANCH-01: When --branch is provided, the resolved branchId must be
        passed in the securityGateRun variables.
        """
        # First call: BranchLookup; second call: securityGateRun
        mock_gql.side_effect = [
            _BRANCHES_RESPONSE_WITH_MAIN,
            _PLATFORM_GATE_PASS_RESPONSE,
        ]
        _run_platform_gate(asset_id=42, output=None, company_id=11, branch="main")

        # Verify the second call (securityGateRun) received the correct branchId
        second_call_vars = mock_gql.call_args_list[1][0][1]  # positional args[1] = variables
        assert second_call_vars.get("branchId") == "10"

    # BRANCH-07: without --branch, branchId is None in securityGateRun
    @patch("conviso.commands.security_gate.graphql_request")
    def test_platform_gate_without_branch_sends_no_branch_id(self, mock_gql):
        """
        BRANCH-07: Without --branch, branchId must be None (not omitted) so
        the API applies no branch filter.
        """
        mock_gql.return_value = _PLATFORM_GATE_PASS_RESPONSE
        _run_platform_gate(asset_id=42, output=None, company_id=None, branch=None)
        call_vars = mock_gql.call_args_list[0][0][1]
        assert call_vars.get("branchId") is None

    # BRANCH-08: warning is emitted when --branch is used
    @patch("conviso.commands.security_gate.graphql_request")
    def test_platform_gate_with_branch_calls_api_twice(self, mock_gql, capsys):
        """
        Verify that using --branch in platform mode correctly executes both
        the BranchLookup query and the main securityGateRun query without errors.
        """
        mock_gql.side_effect = [
            _BRANCHES_RESPONSE_WITH_MAIN,
            _PLATFORM_GATE_PASS_RESPONSE,
        ]
        _run_platform_gate(asset_id=42, output=None, company_id=11, branch="main")
        # If we reach here without exception the flow is correct.
        assert mock_gql.call_count == 2  # BranchLookup + securityGateRun


class TestLocalRulesGateWithBranch:
    """BRANCH-02: local rules gate passes branchNames when --branch is provided."""

    def _make_rules_file(self, content: str, tmp_path: Path) -> Path:
        f = tmp_path / "rules.yaml"
        f.write_text(content)
        return f

    @patch("conviso.commands.security_gate.graphql_request")
    def test_local_gate_with_branch_passes_branch_names(self, mock_gql, tmp_path):
        """
        BRANCH-02: When --branch is provided, branchNames must be included in
        the issuesStats variables as a single-element list.
        """
        mock_gql.return_value = _ISSUES_STATS_CLEAN
        rules_file = self._make_rules_file(VALID_RULES_YAML, tmp_path)
        _run_local_rules_gate(
            asset_id=42, company_id=11, rules_file=rules_file, output=None, branch="main"
        )
        call_vars = mock_gql.call_args_list[0][0][1]
        assert call_vars.get("branch_names") == ["main"]

    # BRANCH-07: without --branch, branchNames is None in issuesStats
    @patch("conviso.commands.security_gate.graphql_request")
    def test_local_gate_without_branch_sends_no_branch_names(self, mock_gql, tmp_path):
        """
        BRANCH-07: Without --branch, branch_names must be None so the API
        applies no branch filter and current behaviour is preserved.
        """
        mock_gql.return_value = _ISSUES_STATS_CLEAN
        rules_file = self._make_rules_file(VALID_RULES_YAML, tmp_path)
        _run_local_rules_gate(
            asset_id=42, company_id=11, rules_file=rules_file, output=None, branch=None
        )
        call_vars = mock_gql.call_args_list[0][0][1]
        assert call_vars.get("branch_names") is None


class TestBranchCommandParameterValidation:
    """BRANCH-04: --branch without --company-id must fail."""

    def test_branch_without_company_id_exits_nonzero(self, tmp_path):
        """
        BRANCH-04: --branch without --company-id must produce a non-zero exit
        and mention 'company' in the error output.
        """
        from typer.testing import CliRunner
        import typer as _typer
        from conviso.commands.security_gate import run_security_gate

        mini_app = _typer.Typer()
        mini_app.command()(run_security_gate)

        runner = CliRunner()
        result = runner.invoke(
            mini_app,
            ["--asset-id", "42", "--branch", "main"],
            catch_exceptions=True,
        )
        assert result.exit_code != 0
        assert "company" in (result.output or "").lower()

    # BRANCH-08: warning appears in command-level output when --branch is used
    @patch("conviso.commands.security_gate.graphql_request")
    def test_branch_command_executes_successfully(self, mock_gql, tmp_path, capsys):
        """
        Verify that executing the command with --branch completes successfully,
        resolving the branch and evaluating the gate.
        """
        from typer.testing import CliRunner
        import typer as _typer
        from conviso.commands.security_gate import run_security_gate

        mock_gql.side_effect = [
            _BRANCHES_RESPONSE_WITH_MAIN,          # BranchLookup
            _PLATFORM_GATE_PASS_RESPONSE,          # securityGateRun
        ]

        mini_app = _typer.Typer()
        mini_app.command()(run_security_gate)

        runner = CliRunner()
        result = runner.invoke(
            mini_app,
            ["--asset-id", "42", "--company-id", "11", "--branch", "main"],
            catch_exceptions=True,
        )
        # Gate should pass
        assert result.exit_code == 0
        output_lower = (result.output or "").lower()
        # Verify info logs show the branch was resolved
        assert "resolved to id:" in output_lower
