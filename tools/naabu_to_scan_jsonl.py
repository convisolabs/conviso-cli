#!/usr/bin/env python3
"""
Convert naabu JSON output (one JSON per line) into scan-json-lines.

Usage:
  naabu -list targets.txt -json | python tools/naabu_to_scan_jsonl.py
  cat naabu.jsonl | python tools/naabu_to_scan_jsonl.py
"""

from __future__ import annotations

import json
import sys


def _pick(d: dict, *keys):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _as_int(val):
    try:
        return int(val)
    except Exception:
        return None


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(raw, dict):
            continue

        ip = _pick(raw, "ip", "host", "address", "target")
        port = _as_int(_pick(raw, "port", "p"))
        proto = str(_pick(raw, "proto", "protocol") or "tcp").upper()
        service = _pick(raw, "service", "name")
        tls = _pick(raw, "tls", "ssl")

        if not ip or not port:
            # Cannot produce a meaningful NETWORK finding
            continue

        title = f"Open port {port}/{proto}"
        if service:
            title = f"{service} on {port}/{proto}"
        description = f"Discovered open port {port}/{proto} on {ip}."
        if service:
            description = f"Discovered {service} on port {port}/{proto} at {ip}."
        if tls:
            description += " TLS detected."

        finding = {
            "type": "NETWORK",
            "title": title,
            "description": description,
            "severity": "info",
            "asset": ip,
            "address": ip,
            "protocol": proto,
            "port": port,
            "attackVector": "N/A",
            "reference": raw.get("reference"),
        }

        out = {"finding": finding, "raw": raw}
        sys.stdout.write(json.dumps(out, ensure_ascii=True) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
