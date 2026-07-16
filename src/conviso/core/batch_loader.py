"""
Batch file loading and validation utilities for bulk operations.
"""

import json
import csv
from pathlib import Path
from typing import List, Dict, Tuple


def load_findings_from_file(file: Path) -> List[Dict]:
    """
    Load findings from JSON or CSV file.

    Args:
        file: Path to JSON or CSV file

    Returns:
        List of finding dictionaries

    Raises:
        ValueError: If file format not supported
        FileNotFoundError: If file not found
    """

    if not file.exists():
        raise FileNotFoundError(f"File not found: {file}")

    if file.suffix.lower() == '.json':
        with open(file) as f:
            data = json.load(f)
            return data if isinstance(data, list) else [data]

    elif file.suffix.lower() == '.csv':
        findings = []
        with open(file, encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("CSV file is empty or malformed")

            for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is 1)
                # Normalize keys: remove spaces, convert to camelCase
                clean_row = {}
                for key, value in row.items():
                    if not key or not value:
                        continue
                    # Convert to camelCase: "file_name" -> "fileName"
                    normalized_key = normalize_key(key.strip())
                    clean_row[normalized_key] = value.strip()

                if clean_row:  # Only add non-empty rows
                    findings.append(clean_row)

        return findings

    else:
        raise ValueError(f"Unsupported file format: {file.suffix}. Use .json or .csv")


def normalize_key(key: str) -> str:
    """
    Convert snake_case or spaces to camelCase.

    Examples:
        "file_name" -> "fileName"
        "asset id" -> "assetId"
        "title" -> "title"
    """
    parts = key.strip().lower().replace(' ', '_').split('_')
    if len(parts) == 1:
        return parts[0]
    return parts[0] + ''.join(word.capitalize() for word in parts[1:])


def validate_findings(findings: List[Dict]) -> List[str]:
    """
    Validate findings before sending to API.

    Returns list of validation errors (empty if valid).
    """
    errors = []

    # Common required fields for all findings
    common_required = {'title', 'type', 'severity', 'impactlevel', 'probabilitylevel', 'description', 'solution'}

    # Type-specific required fields
    required_by_type = {
        'web': {'method', 'scheme', 'url', 'port', 'request', 'response'},
        'dast': {'method', 'scheme', 'url', 'port'},
        'network': {'address', 'protocol', 'port', 'attackvector'},
        'source': {'filename', 'vulnerableline', 'firstline', 'codesnippet'},
        'sast': set(),
        'sca': set(),
        'iac': {'filename', 'vulnerableline', 'firstline', 'codesnippet'},
        'container': set(),
        'secret': set(),
    }

    if not findings:
        return ["No findings provided"]

    for i, finding in enumerate(findings):
        # Normalize finding keys to lowercase for comparison
        finding_lower = {k.lower(): v for k, v in finding.items()}

        # Check common required fields
        for field in common_required:
            if field not in finding_lower or not finding_lower[field]:
                errors.append(f"Row {i}: missing required field '{field}'")

        # Check type-specific required fields
        finding_type = finding_lower.get('type', '').lower()
        if not finding_type:
            errors.append(f"Row {i}: missing 'type' field")
            continue

        if finding_type not in required_by_type:
            errors.append(f"Row {i}: invalid type '{finding_type}'. Use one of: {', '.join(required_by_type.keys())}")
            continue

        type_required = required_by_type[finding_type]
        for field in type_required:
            if field not in finding_lower or not finding_lower[field]:
                errors.append(f"Row {i} ({finding_type}): missing required field '{field}'")

        # Validate severity
        severity = finding_lower.get('severity', '').upper()
        allowed_severities = {'NOTIFICATION', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
        if severity not in allowed_severities:
            errors.append(f"Row {i}: invalid severity '{severity}'. Use one of: {', '.join(allowed_severities)}")

        # Validate port is numeric if present
        if 'port' in finding_lower and finding_lower['port']:
            try:
                int(finding_lower['port'])
            except ValueError:
                errors.append(f"Row {i}: 'port' must be numeric, got '{finding_lower['port']}'")

    return errors
