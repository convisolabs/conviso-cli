"""
Tests for batch findings functionality
"""

import pytest
import json
import tempfile
from pathlib import Path
from src.conviso.core.batch_loader import (
    load_findings_from_file,
    validate_findings,
    normalize_key
)


class TestNormalizeKey:
    """Tests for normalize_key function"""

    def test_snake_case_to_camel_case(self):
        assert normalize_key("file_name") == "fileName"

    def test_space_to_camel_case(self):
        assert normalize_key("asset id") == "assetId"

    def test_single_word(self):
        assert normalize_key("title") == "title"

    def test_with_leading_trailing_spaces(self):
        assert normalize_key("  impact_level  ") == "impactLevel"


class TestLoadFindingsFromJSON:
    """Tests for loading findings from JSON files"""

    def test_load_valid_json_list(self):
        findings = [
            {
                "title": "Test",
                "type": "WEB",
                "severity": "HIGH",
                "impactLevel": "HIGH",
                "probabilityLevel": "HIGH",
                "description": "Test",
                "solution": "Test"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(findings, f)
            f.flush()

            loaded = load_findings_from_file(Path(f.name))
            assert len(loaded) == 1
            assert loaded[0]['title'] == "Test"

            Path(f.name).unlink()

    def test_load_json_single_object(self):
        finding = {
            "title": "Test",
            "type": "WEB",
            "severity": "HIGH",
            "impactLevel": "HIGH",
            "probabilityLevel": "HIGH",
            "description": "Test",
            "solution": "Test"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(finding, f)
            f.flush()

            loaded = load_findings_from_file(Path(f.name))
            assert len(loaded) == 1
            assert loaded[0]['title'] == "Test"

            Path(f.name).unlink()

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_findings_from_file(Path("/nonexistent/file.json"))


class TestLoadFindingsFromCSV:
    """Tests for loading findings from CSV files"""

    def test_load_valid_csv(self):
        csv_content = "title,type,severity,impactLevel,probabilityLevel,description,solution\nTest,WEB,HIGH,HIGH,HIGH,Test desc,Test sol\n"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(csv_content)
            f.flush()

            loaded = load_findings_from_file(Path(f.name))
            assert len(loaded) == 1
            assert loaded[0]['title'] == "Test"
            assert loaded[0]['type'] == "WEB"

            Path(f.name).unlink()

    def test_csv_key_normalization(self):
        csv_content = "title,file_name,type,severity,impactLevel,probabilityLevel,description,solution,vulnerable_line,first_line,code_snippet\nTest,app.py,SOURCE,HIGH,HIGH,HIGH,Test,Test,10,5,print(var)\n"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(csv_content)
            f.flush()

            loaded = load_findings_from_file(Path(f.name))
            assert loaded[0]['fileName'] == "app.py"
            assert loaded[0]['vulnerableLine'] == "10"

            Path(f.name).unlink()

    def test_unsupported_format(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"test")
            f.flush()

            with pytest.raises(ValueError, match="Unsupported file format"):
                load_findings_from_file(Path(f.name))

            Path(f.name).unlink()


class TestValidateFindings:
    """Tests for validate_findings function"""

    def test_valid_web_finding(self):
        findings = [
            {
                "title": "SQL Injection",
                "type": "WEB",
                "severity": "CRITICAL",
                "impactLevel": "HIGH",
                "probabilityLevel": "HIGH",
                "description": "Test",
                "solution": "Test",
                "method": "POST",
                "scheme": "HTTPS",
                "url": "https://example.com",
                "port": "443",
                "request": "test",
                "response": "test"
            }
        ]

        errors = validate_findings(findings)
        assert len(errors) == 0

    def test_missing_required_field(self):
        findings = [
            {
                "title": "SQL Injection",
                "type": "WEB",
                "severity": "CRITICAL",
                # Missing impactLevel
                "probabilityLevel": "HIGH",
                "description": "Test",
                "solution": "Test",
                "method": "POST",
                "scheme": "HTTPS",
                "url": "https://example.com",
                "port": "443",
                "request": "test",
                "response": "test"
            }
        ]

        errors = validate_findings(findings)
        assert len(errors) > 0
        assert any("impactlevel" in e.lower() for e in errors)

    def test_invalid_severity(self):
        findings = [
            {
                "title": "Test",
                "type": "WEB",
                "severity": "INVALID_SEVERITY",
                "impactLevel": "HIGH",
                "probabilityLevel": "HIGH",
                "description": "Test",
                "solution": "Test",
                "method": "POST",
                "scheme": "HTTPS",
                "url": "https://example.com",
                "port": "443",
                "request": "test",
                "response": "test"
            }
        ]

        errors = validate_findings(findings)
        assert len(errors) > 0
        assert any("severity" in e.lower() for e in errors)

    def test_invalid_port(self):
        findings = [
            {
                "title": "Test",
                "type": "WEB",
                "severity": "HIGH",
                "impactLevel": "HIGH",
                "probabilityLevel": "HIGH",
                "description": "Test",
                "solution": "Test",
                "method": "POST",
                "scheme": "HTTPS",
                "url": "https://example.com",
                "port": "not_a_number",
                "request": "test",
                "response": "test"
            }
        ]

        errors = validate_findings(findings)
        assert len(errors) > 0
        assert any("port" in e.lower() for e in errors)

    def test_network_type_specific_validation(self):
        # Valid NETWORK finding
        findings = [
            {
                "title": "Open Port",
                "type": "NETWORK",
                "severity": "HIGH",
                "impactLevel": "HIGH",
                "probabilityLevel": "HIGH",
                "description": "Test",
                "solution": "Test",
                "address": "192.168.1.1",
                "protocol": "TCP",
                "port": "22",
                "attackvector": "NETWORK"
            }
        ]

        errors = validate_findings(findings)
        assert len(errors) == 0

        # Missing attackvector
        findings[0].pop("attackvector")
        errors = validate_findings(findings)
        assert len(errors) > 0
        assert any("attackvector" in e.lower() for e in errors)

    def test_source_type_specific_validation(self):
        # Valid SOURCE finding
        findings = [
            {
                "title": "Vulnerable Code",
                "type": "SOURCE",
                "severity": "HIGH",
                "impactLevel": "HIGH",
                "probabilityLevel": "HIGH",
                "description": "Test",
                "solution": "Test",
                "filename": "app.py",
                "vulnerableLine": "42",
                "firstLine": "40",
                "codesnippet": "vulnerable code"
            }
        ]

        errors = validate_findings(findings)
        assert len(errors) == 0

    def test_empty_findings_list(self):
        errors = validate_findings([])
        assert len(errors) > 0
        assert any("No findings" in e for e in errors)

    def test_case_insensitive_field_names(self):
        # Fields with different casing should still validate
        findings = [
            {
                "Title": "Test",  # Uppercase
                "Type": "WEB",
                "Severity": "HIGH",
                "ImpactLevel": "HIGH",
                "ProbabilityLevel": "HIGH",
                "Description": "Test",
                "Solution": "Test",
                "Method": "POST",
                "Scheme": "HTTPS",
                "Url": "https://example.com",
                "Port": "443",
                "Request": "test",
                "Response": "test"
            }
        ]

        errors = validate_findings(findings)
        assert len(errors) == 0
