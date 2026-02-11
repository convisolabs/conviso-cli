# conviso/commands/tasks.py
"""
Task Command Module
-------------------
Executes YAML-defined tasks stored in requirement activities.
"""

from __future__ import annotations

import json
import html as html_lib
import hashlib
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import typer

from conviso.clients.client_graphql import graphql_request
from conviso.core.notifier import error, info, summary, warning, success

try:
    import yaml
except Exception:  # pragma: no cover - optional runtime dependency
    yaml = None

app = typer.Typer(help="Execute YAML tasks defined in requirement activities.")
approvals_app = typer.Typer(help="Manage approved task commands.")
app.add_typer(approvals_app, name="approvals")

TASK_PREFIX_DEFAULT = "TASK"
_ASSET_LOOKUP_WARNED = False
APPROVALS_DIR = os.path.join(os.path.expanduser("~"), ".config", "conviso")
APPROVALS_FILE = os.path.join(APPROVALS_DIR, "approved_tasks.json")


def _load_approved_commands() -> Dict[str, Dict[str, Any]]:
    try:
        with open(APPROVALS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _save_approved_commands(data: Dict[str, Dict[str, Any]]):
    os.makedirs(APPROVALS_DIR, exist_ok=True)
    with open(APPROVALS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _command_key(cmd: str) -> str:
    return hashlib.sha256(cmd.encode("utf-8")).hexdigest()


def _is_command_approved(cmd: str) -> bool:
    approvals = _load_approved_commands()
    return _command_key(cmd) in approvals


def _approve_command(cmd: str):
    approvals = _load_approved_commands()
    key = _command_key(cmd)
    approvals[key] = {"cmd": cmd, "approved_at": int(time.time())}
    _save_approved_commands(approvals)


@approvals_app.command("list")
def list_approvals():
    """List locally approved task commands."""
    approvals = _load_approved_commands()
    if not approvals:
        info("No approved commands found.")
        return
    rows = []
    for key, data in approvals.items():
        cmd = data.get("cmd") or ""
        approved_at = data.get("approved_at") or 0
        rows.append({"hash": key, "approvedAt": approved_at, "cmd": cmd})
    for row in rows:
        typer.echo(f"{row['hash']}  {row['approvedAt']}  {row['cmd']}")
    summary(f"{len(rows)} approved command(s).")


@approvals_app.command("clear")
def clear_approvals():
    """Clear locally approved task commands."""
    if os.path.exists(APPROVALS_FILE):
        try:
            os.remove(APPROVALS_FILE)
            info("Approved commands cleared.")
            return
        except Exception as exc:
            error(f"Failed to clear approvals: {exc}")
            raise typer.Exit(code=1)
    info("No approvals file found.")


@approvals_app.command("remove")
def remove_approval(
    hash_value: str = typer.Option(..., "--hash", "-h", help="Approval hash to remove."),
):
    """Remove a single approved command by hash."""
    approvals = _load_approved_commands()
    if hash_value not in approvals:
        warning("Approval hash not found.")
        raise typer.Exit(code=1)
    approvals.pop(hash_value, None)
    _save_approved_commands(approvals)
    info("Approval removed.")


def _require_yaml():
    if yaml is None:
        error("PyYAML not installed. Install with: pip install pyyaml")
        raise typer.Exit(code=1)


def _clean_description(desc: str) -> str:
    if not desc:
        return ""
    text = desc
    # Normalize common HTML block/line break tags into newlines (handles attributes too)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</?(div|p|li|tr|h\d)(\s+[^>]*)?>", "\n", text)
    # Strip all other tags
    text = re.sub(r"<[^>]+>", "", text)
    text = html_lib.unescape(text)
    text = text.replace("\u00a0", " ")
    # Collapse multiple blank lines
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _normalize_yaml_steps(text: str) -> str:
    lines = text.splitlines()
    step_idx = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*steps\s*:\s*$", line):
            step_idx = i
            break
    if step_idx is None:
        return text

    in_steps = True
    for i in range(step_idx + 1, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        if re.match(r"^\S", line):
            if line.startswith("- "):
                lines[i] = "  " + line
            else:
                in_steps = False
        if not in_steps:
            break
        if line.lstrip().startswith("- "):
            if not line.startswith("  "):
                lines[i] = "  " + line.lstrip()
        elif re.match(r"^\S", line) and in_steps:
            lines[i] = "  " + line
    return "\n".join(lines)


def _matches_prefix(label: str, prefix: str) -> bool:
    if not label:
        return False
    base = prefix.strip().rstrip(":").rstrip("-").strip()
    if not base:
        return False
    pattern = rf"^{re.escape(base)}(?:\s*[:\-]\s*)?.*"
    return re.match(pattern, label.strip(), flags=re.IGNORECASE) is not None


def _build_requirement_label(prefix: str, label: str) -> str:
    base_label = (label or "").strip()
    if not base_label:
        return base_label
    if not prefix or _matches_prefix(base_label, prefix):
        return base_label
    return f"{prefix.strip()} - {base_label}"


def _attach_requirement_to_project(company_id: int, project_id: int, requirement_id: int):
    fetch_query = """
    query Project($id: ID!, $companyId: ID!) {
      project(id: $id, companyId: $companyId) {
        id
        playbooks { id }
      }
    }
    """
    data = graphql_request(fetch_query, {"id": project_id, "companyId": company_id})
    project = data.get("project") or {}
    current_playbooks: List[int] = []
    for pb in project.get("playbooks") or []:
        pid = pb.get("id")
        if pid is None:
            continue
        try:
            current_playbooks.append(int(pid))
        except ValueError:
            warning(f"Requirement ID '{pid}' is not numeric; skipping.")

    if requirement_id in current_playbooks:
        info(f"Requirement {requirement_id} already attached to project {project_id}.")
        return

    merged = [*current_playbooks, requirement_id]
    mutation = """
    mutation UpdateProject($input: UpdateProjectInput!) {
      updateProject(input: $input) {
        project { id label }
      }
    }
    """
    graphql_request(mutation, {"input": {"id": project_id, "companyId": company_id, "playbooksIds": merged}})
    success(f"Requirement {requirement_id} attached to project {project_id}.")


def _normalize_activity_for_input(activity: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {"id", "label", "description", "reference", "item", "category", "actionPlan"}
    return {k: v for k, v in activity.items() if k in allowed and v is not None}


def _validate_task_yaml(desc: str) -> Dict[str, Any]:
    cleaned = _clean_description(desc)
    if not cleaned:
        return {"ok": False, "reason": "empty_description"}
    try:
        data = yaml.safe_load(cleaned)
    except Exception:
        data = None
    if not isinstance(data, dict):
        normalized = _normalize_yaml_steps(cleaned)
        if normalized != cleaned:
            try:
                data = yaml.safe_load(normalized)
            except Exception:
                data = None
        if not isinstance(data, dict):
            return {"ok": False, "reason": "invalid_yaml"}
    if not isinstance(data, dict):
        return {"ok": False, "reason": "not_a_mapping"}
    steps = data.get("steps")
    if not isinstance(steps, list):
        normalized = _normalize_yaml_steps(cleaned)
        if normalized != cleaned:
            try:
                data = yaml.safe_load(normalized)
            except Exception:
                data = None
            if isinstance(data, dict):
                steps = data.get("steps")
        if not isinstance(steps, list):
            return {"ok": False, "reason": "missing_steps"}
    if len(steps) != 1:
        return {"ok": False, "reason": f"steps={len(steps)}"}
    return {
        "ok": True,
        "reason": "",
        "name": data.get("name") or "",
        "steps": len(steps),
    }


def _get_path_value(path: str, record: Dict[str, Any], context: Dict[str, Any]) -> Optional[Any]:
    def _walk(obj: Any, parts: List[str]) -> Optional[Any]:
        cur = obj
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return None
        return cur

    parts = path.split(".")
    val = _walk(record, parts)
    if val is not None:
        return val
    return _walk(context, parts)


def _normalize_asset_key(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    s = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
    s = s.split("/", 1)[0]
    return s


_TEMPLATE_RE = re.compile(r"\$\{([^}]+)\}")


def _render_string(value: str, record: Dict[str, Any], context: Dict[str, Any]) -> str:
    def _replace(match: re.Match) -> str:
        key = match.group(1).strip()
        if key.startswith("assets.by_name:"):
            field = key.split(":", 1)[1]
            lookup_key = _get_path_value(field, record, context)
            if lookup_key is None:
                return ""
            assets_by_name = (context.get("assets") or {}).get("by_name") or {}
            normalized = _normalize_asset_key(lookup_key)
            found = assets_by_name.get(str(lookup_key), assets_by_name.get(normalized, ""))
            return str(found) if found is not None else ""
        val = _get_path_value(key, record, context)
        return "" if val is None else str(val)

    return _TEMPLATE_RE.sub(_replace, value)


def _render_value(value: Any, record: Dict[str, Any], context: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        return _render_string(value, record, context)
    if isinstance(value, list):
        return [_render_value(v, record, context) for v in value]
    if isinstance(value, dict):
        return {k: _render_value(v, record, context) for k, v in value.items()}
    return value


def _parse_nmap_xml(xml_text: str) -> List[Dict[str, Any]]:
    results = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                address = addr.get("addr")
                break
        if address is None:
            addr = host.find("address")
            if addr is not None:
                address = addr.get("addr")
        hostname = None
        h = host.find("hostnames/hostname")
        if h is not None:
            hostname = h.get("name")
        results.append({
            "host": {
                "address": address,
                "hostname": hostname,
            }
        })
    return results


def _extract_http_method(request: Optional[str]) -> Optional[str]:
    if not request:
        return None
    first_line = request.splitlines()[0].strip()
    if not first_line:
        return None
    parts = first_line.split()
    if not parts:
        return None
    return parts[0].upper()


def _infer_scheme_port(url: Optional[str], scheme: Optional[str], port: Optional[Any]) -> Dict[str, Optional[Any]]:
    resolved_scheme = (scheme or "").lower() or None
    resolved_port = port
    if url:
        try:
            if "://" in url:
                parsed = urlparse(url)
                if not resolved_scheme and parsed.scheme in ("http", "https"):
                    resolved_scheme = parsed.scheme.lower()
                if resolved_port in (None, "") and parsed.port:
                    resolved_port = parsed.port
            else:
                parsed = urlparse(f"http://{url}")
                if resolved_port in (None, "") and parsed.port:
                    resolved_port = parsed.port
        except Exception:
            pass
    if resolved_port in (None, "") and resolved_scheme in ("http", "https"):
        resolved_port = 443 if resolved_scheme == "https" else 80
    return {"scheme": resolved_scheme, "port": resolved_port}

def _classify_vuln_type(payload: Dict[str, Any], record: Dict[str, Any]) -> str:
    explicit = (payload.get("type") or payload.get("vtype") or "").upper()
    if explicit and explicit != "DAST":
        return explicit
    finding_type = (record.get("finding") or {}).get("type")
    finding_type = (str(finding_type).lower() if finding_type else "")
    if finding_type in {"dns", "ssl", "tcp", "udp", "network"}:
        return "NETWORK"
    raw_req = (record.get("raw") or {}).get("request")
    if isinstance(raw_req, str) and raw_req.lstrip().startswith(";;"):
        return "NETWORK"
    return "WEB"


def _parse_nuclei_json_lines(text: str) -> List[Dict[str, Any]]:
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        info_obj = raw.get("info") or {}
        url = raw.get("url") or raw.get("matched-at")
        method = raw.get("method") or _extract_http_method(raw.get("request"))
        inferred = _infer_scheme_port(url, raw.get("scheme"), raw.get("port"))
        scheme = inferred.get("scheme")
        port = inferred.get("port")
        if url and "://" not in url and scheme in ("http", "https"):
            url = f"{scheme}://{url}"
        remediation = info_obj.get("remediation")
        reference = info_obj.get("reference")
        if isinstance(reference, list):
            ref_val = reference[0] if reference else None
        else:
            ref_val = reference
        solution = remediation or ref_val
        finding = {
            "name": info_obj.get("name") or raw.get("template-id"),
            "description": info_obj.get("description"),
            "severity": info_obj.get("severity"),
            "type": raw.get("type"),
            "templateId": raw.get("template-id"),
            "matcherName": raw.get("matcher-name"),
            "host": raw.get("host"),
            "matchedAt": raw.get("matched-at"),
            "ip": raw.get("ip"),
            "url": url,
            "scheme": scheme,
            "port": port,
            "method": method,
            "request": raw.get("request"),
            "response": raw.get("response"),
            "solution": solution,
            "reference": reference,
            "timestamp": raw.get("timestamp"),
        }
        results.append({
            "finding": finding,
            "raw": raw,
        })
    return results


def _parse_scan_json_lines(text: str) -> List[Dict[str, Any]]:
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        finding = raw.get("finding") if isinstance(raw.get("finding"), dict) else dict(raw)
        # Normalize common fields for compatibility with existing maps
        if "name" not in finding and "title" in finding:
            finding["name"] = finding.get("title")
        if "host" not in finding and "asset" in finding:
            finding["host"] = finding.get("asset")
        if "url" not in finding and "matchedAt" in finding:
            finding["url"] = finding.get("matchedAt")
        results.append({
            "finding": finding,
            "raw": raw,
        })
    return results


def _read_parse_source(parse_cfg: Dict[str, Any], stdout: str) -> str:
    source = (parse_cfg.get("source") or "stdout").lower()
    if source == "stdout":
        return stdout
    if source == "file":
        file_path = parse_cfg.get("file")
        if not file_path:
            raise ValueError("parse.source=file requires parse.file")
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    raise ValueError(f"Unsupported parse.source: {source}")


def _fetch_assets(company_id: int, tags: Optional[str] = None) -> List[Dict[str, Any]]:
    query = """
    query Assets($companyId: ID!, $limit: Int, $page: Int, $search: AssetsSearch) {
      assets(companyId: $companyId, limit: $limit, page: $page, search: $search) {
        collection { id name }
        metadata { totalPages }
      }
    }
    """
    page = 1
    limit = 50
    all_assets = []
    search = {"tags": [t.strip() for t in tags.split(",") if t.strip()]} if tags else None
    while True:
        data = graphql_request(query, {"companyId": company_id, "limit": limit, "page": page, "search": search})
        assets = (data.get("assets") or {}).get("collection") or []
        meta = (data.get("assets") or {}).get("metadata") or {}
        all_assets.extend(assets)
        total_pages = meta.get("totalPages") or 1
        if page >= total_pages:
            break
        page += 1
    return all_assets


def _fetch_project_assets(company_id: int, project_id: int) -> List[Dict[str, Any]]:
    query_with_company = """
    query ProjectAssets($id: ID!, $companyId: ID!) {
      project(id: $id, companyId: $companyId) {
        id
        assets { id name }
      }
    }
    """
    query_no_company = """
    query ProjectAssets($id: ID!) {
      project(id: $id) {
        id
        assets { id name }
      }
    }
    """
    try:
        data = graphql_request(query_with_company, {"id": project_id, "companyId": company_id}, log_request=False)
    except Exception as exc:
        msg = str(exc)
        if "argument 'companyId'" in msg or "argumentNotAccepted" in msg:
            data = graphql_request(query_no_company, {"id": project_id}, log_request=False)
        else:
            raise
    project = data.get("project") or {}
    return project.get("assets") or []


def _fetch_project_targets(company_id: int, project_id: int) -> List[str]:
    # Primary: projectScopeUrls { url }
    query_scope_urls = """
    query ProjectTargets($id: ID!) {
      project(id: $id) {
        id
        projectScopeUrls { url }
      }
    }
    """
    try:
        data = graphql_request(query_scope_urls, {"id": project_id}, log_request=False)
        project = data.get("project") or {}
        scope_urls = project.get("projectScopeUrls") or []
        targets = []
        for item in scope_urls:
            if isinstance(item, dict):
                val = item.get("url")
                if val:
                    targets.append(str(val).strip())
        if targets:
            return targets
    except Exception:
        pass

    # Fallback: try a few likely field names
    candidates = ["targetUrls", "targetHosts", "targetUrlsOrHosts"]
    for field in candidates:
        query = f"""
        query ProjectTargets($id: ID!) {{
          project(id: $id) {{
            id
            {field}
          }}
        }}
        """
        try:
            data = graphql_request(query, {"id": project_id}, log_request=False)
        except Exception as exc:
            msg = str(exc)
            if "Cannot query field" in msg or ("Field" in msg and field in msg):
                continue
            raise
        project = data.get("project") or {}
        raw = project.get(field)
        if not raw:
            continue
        targets = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    targets.append(item.strip())
                elif isinstance(item, dict):
                    val = item.get("url") or item.get("host") or item.get("value") or item.get("target")
                    if val:
                        targets.append(str(val).strip())
        elif isinstance(raw, str):
            targets.append(raw.strip())
        return [t for t in targets if t]
    return []


def _targets_to_hosts(targets: List[str]) -> List[str]:
    hosts = []
    for t in targets:
        if not t:
            continue
        s = str(t).strip()
        if not s:
            continue
        if "://" not in s:
            s = f"http://{s}"
        try:
            parsed = urlparse(s)
            host = parsed.hostname or _normalize_asset_key(s)
        except Exception:
            host = _normalize_asset_key(s)
        if host:
            hosts.append(host)
    return hosts

def _create_asset(company_id: int, payload: Dict[str, Any], apply: bool) -> Optional[int]:
    if not apply:
        return None
    mutation = """
    mutation CreateAsset($input: CreateAssetInput!) {
      createAsset(input: $input) { asset { id name } }
    }
    """
    input_data = dict(payload)
    input_data["companyId"] = int(company_id)
    data = graphql_request(mutation, {"input": input_data})
    asset = (data.get("createAsset") or {}).get("asset") or {}
    asset_id = asset.get("id")
    asset_name = asset.get("name")
    if asset_id:
        success(f"Asset created: ID {asset_id} - {asset_name}")
        try:
            return int(asset_id)
        except Exception:
            return None
    warning("Asset creation returned no ID.")
    return None


def _update_asset(company_id: int, payload: Dict[str, Any], apply: bool) -> Optional[int]:
    if not apply:
        return None
    mutation = """
    mutation UpdateAsset($input: UpdateAssetInput!) {
      updateAsset(input: $input) { asset { id name } }
    }
    """
    input_data = dict(payload)
    input_data["companyId"] = int(company_id)
    data = graphql_request(mutation, {"input": input_data})
    asset = (data.get("updateAsset") or {}).get("asset") or {}
    asset_id = asset.get("id")
    asset_name = asset.get("name")
    if asset_id:
        success(f"Asset updated: ID {asset_id} - {asset_name}")
        try:
            return int(asset_id)
        except Exception:
            return None
    warning("Asset update returned no ID.")
    return None


def _find_asset_by_name(company_id: int, name: str) -> Optional[int]:
    if not name:
        return None
    query = """
    query Assets($companyId: ID!, $limit: Int, $page: Int, $search: AssetsSearch) {
      assets(companyId: $companyId, limit: $limit, page: $page, search: $search) {
        collection { id name }
        metadata { totalPages }
      }
    }
    """
    page = 1
    limit = 50
    search = {"name": name}
    try:
        while True:
            data = graphql_request(query, {"companyId": company_id, "limit": limit, "page": page, "search": search}, log_request=False)
            assets = (data.get("assets") or {}).get("collection") or []
            for a in assets:
                if (a.get("name") or "").strip() == name:
                    try:
                        return int(a.get("id"))
                    except Exception:
                        return None
            meta = (data.get("assets") or {}).get("metadata") or {}
            if page >= (meta.get("totalPages") or 1):
                break
            page += 1
    except Exception as exc:
        global _ASSET_LOOKUP_WARNED
        if not _ASSET_LOOKUP_WARNED:
            warning(f"Asset lookup failed; cannot auto-resolve existing assets ({exc}).")
            _ASSET_LOOKUP_WARNED = True
        return None
    return None


def _create_vulnerability(payload: Dict[str, Any], apply: bool):
    if not apply:
        return
    vtype = (payload.get("type") or payload.get("vtype") or "").upper()
    if not vtype:
        raise ValueError("vulns.create requires 'type'")

    common = {
        "assetId": payload.get("assetId"),
        "title": payload.get("title"),
        "description": payload.get("description"),
        "solution": payload.get("solution"),
        "impactLevel": payload.get("impactLevel"),
        "probabilityLevel": payload.get("probabilityLevel"),
        "severity": payload.get("severity"),
        "status": payload.get("status"),
        "category": payload.get("category"),
        "projectId": payload.get("projectId"),
        "companyId": payload.get("companyId"),
    }
    common = {k: v for k, v in common.items() if v not in (None, "")}

    if vtype == "DAST":
        required = ["assetId", "title", "description", "solution", "impactLevel", "probabilityLevel", "severity",
                    "method", "scheme", "url", "port", "request", "response"]
        for r in required:
            if payload.get(r) in (None, ""):
                raise ValueError(f"DAST requires {r}")
        mutation = """
        mutation CreateDast($input: CreateDastFindingInput!) {
          createDastFinding(input: $input) { issue { id title } }
        }
        """
        # CreateDastFindingInput does not accept status/companyId on some backends
        common = {k: v for k, v in common.items() if k not in {"status", "companyId"}}
        data = graphql_request(mutation, {"input": {
            **common,
            "method": str(payload.get("method")).upper(),
            "scheme": str(payload.get("scheme")).upper(),
            "url": payload.get("url"),
            "port": int(payload.get("port")),
            "request": payload.get("request"),
            "response": payload.get("response"),
            "parameters": payload.get("parameters"),
            "reference": payload.get("reference"),
        }})
        issue = ((data.get("createDastFinding") or {}).get("issue") or {})
        success(f"Created DAST vulnerability '{issue.get('title')}' (ID {issue.get('id')})")
        return

    if vtype == "WEB":
        required = ["assetId", "title", "description", "severity",
                    "method", "scheme", "url", "port", "request", "response"]
        for r in required:
            if payload.get(r) in (None, ""):
                raise ValueError(f"WEB requires {r}")
        mutation = """
        mutation CreateWeb($input: CreateWebVulnerabilityInput!) {
          createWebVulnerability(input: $input) { issue { id title } }
        }
        """
        common = {k: v for k, v in common.items() if k != "companyId"}
        data = graphql_request(mutation, {"input": {
            **common,
            "method": str(payload.get("method")).upper(),
            "scheme": str(payload.get("scheme")).upper(),
            "url": payload.get("url"),
            "port": int(payload.get("port")),
            "request": payload.get("request"),
            "response": payload.get("response"),
            "summary": payload.get("summary") or payload.get("title"),
            "impactDescription": payload.get("impactDescription") or payload.get("description"),
            "stepsToReproduce": payload.get("stepsToReproduce") or payload.get("description"),
            "parameters": payload.get("parameters"),
        }})
        issue = ((data.get("createWebVulnerability") or {}).get("issue") or {})
        success(f"Created WEB vulnerability '{issue.get('title')}' (ID {issue.get('id')})")
        return

    if vtype == "NETWORK":
        required = ["assetId", "title", "description", "solution", "impactLevel", "probabilityLevel", "severity",
                    "address", "protocol", "port", "attackVector"]
        for r in required:
            if payload.get(r) in (None, ""):
                raise ValueError(f"NETWORK requires {r}")
        mutation = """
        mutation CreateNetwork($input: CreateNetworkVulnerabilityInput!) {
          createNetworkVulnerability(input: $input) { issue { id title } }
        }
        """
        common = {k: v for k, v in common.items() if k != "companyId"}
        data = graphql_request(mutation, {"input": {
            **common,
            "address": payload.get("address"),
            "protocol": payload.get("protocol"),
            "port": int(payload.get("port")),
            "attackVector": payload.get("attackVector"),
            "summary": payload.get("summary") or payload.get("title"),
            "impactDescription": payload.get("impactDescription") or payload.get("description"),
            "stepsToReproduce": payload.get("stepsToReproduce") or payload.get("description"),
        }})
        issue = ((data.get("createNetworkVulnerability") or {}).get("issue") or {})
        success(f"Created NETWORK vulnerability '{issue.get('title')}' (ID {issue.get('id')})")
        return

    if vtype == "SOURCE":
        required = ["assetId", "title", "description", "solution", "impactLevel", "probabilityLevel", "severity",
                    "fileName", "vulnerableLine", "firstLine", "codeSnippet"]
        for r in required:
            if payload.get(r) in (None, ""):
                raise ValueError(f"SOURCE requires {r}")
        mutation = """
        mutation CreateSource($input: CreateSourceCodeVulnerabilityInput!) {
          createSourceCodeVulnerability(input: $input) { issue { id title } }
        }
        """
        data = graphql_request(mutation, {"input": {
            **common,
            "fileName": payload.get("fileName"),
            "vulnerableLine": int(payload.get("vulnerableLine")),
            "firstLine": int(payload.get("firstLine")),
            "codeSnippet": payload.get("codeSnippet"),
            "summary": payload.get("summary") or payload.get("title"),
            "impactDescription": payload.get("impactDescription") or payload.get("description"),
            "stepsToReproduce": payload.get("stepsToReproduce") or payload.get("description"),
            "reference": payload.get("reference"),
            "source": payload.get("source"),
            "sink": payload.get("sink"),
            "commitRef": payload.get("commitRef"),
            "deployId": payload.get("deployId"),
        }})
        issue = ((data.get("createSourceCodeVulnerability") or {}).get("issue") or {})
        success(f"Created SOURCE vulnerability '{issue.get('title')}' (ID {issue.get('id')})")
        return

    raise ValueError(f"Unsupported vulnerability type: {vtype}")


def _actions_from_parsed(actions: List[Dict[str, Any]], items: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
    planned = []
    for item in items:
        for action in actions:
            planned.append({
                "type": action.get("type"),
                "map": action.get("map") or {},
                "defaults": action.get("defaults") or {},
                "asset": action.get("asset") or {},
                "record": item,
                "context": context,
            })
    return planned


def _apply_actions(planned: List[Dict[str, Any]], company_id: int, apply: bool) -> Dict[str, int]:
    counts = {"created": 0, "skipped": 0, "assets_created": 0, "assets_updated": 0}
    for entry in planned:
        action_type = entry["type"]
        mapping = entry["map"]
        defaults = entry["defaults"]
        asset_cfg = entry.get("asset") or {}
        record = entry["record"]
        context = entry["context"]

        payload = {}
        for k, v in defaults.items():
            payload[k] = _render_value(v, record, context)
        for k, v in mapping.items():
            if k == "assetId" and payload.get("assetId") not in (None, ""):
                continue
            payload[k] = _render_value(v, record, context)

        if action_type == "assets.create":
            allowed = {"name", "description", "businessImpact", "dataClassification", "assetsTagList", "integrations", "environmentCompromised", "exploitability"}
            filtered = {k: payload.get(k) for k in allowed if payload.get(k) not in (None, "")}
            if "name" not in filtered:
                raise ValueError("assets.create requires 'name'")
            if isinstance(filtered.get("assetsTagList"), str):
                filtered["assetsTagList"] = [t.strip() for t in filtered["assetsTagList"].split(",") if t.strip()]
            if isinstance(filtered.get("integrations"), str):
                filtered["integrations"] = [t.strip() for t in filtered["integrations"].split(",") if t.strip()]
            if isinstance(filtered.get("businessImpact"), str):
                filtered["businessImpact"] = filtered["businessImpact"].upper()
            if isinstance(filtered.get("exploitability"), str):
                filtered["exploitability"] = filtered["exploitability"].upper()
            if isinstance(filtered.get("environmentCompromised"), str):
                filtered["environmentCompromised"] = filtered["environmentCompromised"].lower() == "true"
            created_id = _create_asset(company_id, filtered, apply)
            if created_id:
                counts["assets_created"] += 1
        elif action_type == "assets.update":
            allowed = {"id", "assetId", "name", "description", "businessImpact", "dataClassification", "assetsTagList", "integrations", "environmentCompromised", "exploitability"}
            filtered = {k: payload.get(k) for k in allowed if payload.get(k) not in (None, "")}
            asset_id = filtered.get("id") or filtered.get("assetId")
            if asset_id in (None, ""):
                raise ValueError("assets.update requires 'id' or 'assetId'")
            if isinstance(asset_id, str) and asset_id.isdigit():
                asset_id = int(asset_id)
            filtered["id"] = asset_id
            filtered.pop("assetId", None)
            if isinstance(filtered.get("assetsTagList"), str):
                filtered["assetsTagList"] = [t.strip() for t in filtered["assetsTagList"].split(",") if t.strip()]
            if isinstance(filtered.get("integrations"), str):
                filtered["integrations"] = [t.strip() for t in filtered["integrations"].split(",") if t.strip()]
            if isinstance(filtered.get("businessImpact"), str):
                filtered["businessImpact"] = filtered["businessImpact"].upper()
            if isinstance(filtered.get("exploitability"), str):
                filtered["exploitability"] = filtered["exploitability"].upper()
            if isinstance(filtered.get("environmentCompromised"), str):
                filtered["environmentCompromised"] = filtered["environmentCompromised"].lower() == "true"
            updated_id = _update_asset(company_id, filtered, apply)
            if updated_id:
                counts["assets_updated"] += 1
        elif action_type == "assets.enrich":
            asset_id = payload.get("id") or payload.get("assetId")
            asset_name = payload.get("name")
            if asset_id in (None, ""):
                resolved = None
                if asset_name:
                    assets_cache = (context.get("assets") or {}).get("by_name") or {}
                    normalized_name = _normalize_asset_key(str(asset_name))
                    if str(asset_name) in assets_cache:
                        resolved = assets_cache.get(str(asset_name))
                    elif normalized_name in assets_cache:
                        resolved = assets_cache.get(normalized_name)
                    else:
                        resolved = _find_asset_by_name(company_id, str(asset_name))
                if not resolved:
                    warning("Skipping assets.enrich: asset not found (use assets.create or provide assetId).")
                    counts["skipped"] += 1
                    continue
                asset_id = resolved
            if isinstance(asset_id, str) and asset_id.isdigit():
                asset_id = int(asset_id)
            payload["id"] = asset_id
            payload.pop("assetId", None)
            updated_id = _update_asset(company_id, payload, apply)
            if updated_id:
                counts["assets_updated"] += 1
        elif action_type == "vulns.create":
            # Normalize severity values from common scanners
            severity = payload.get("severity")
            if isinstance(severity, str):
                sev = severity.strip().upper()
                if sev in {"INFO", "INFORMATIONAL"}:
                    payload["severity"] = "NOTIFICATION"
                else:
                    payload["severity"] = sev

            asset_id = payload.get("assetId")
            if asset_id in (None, ""):
                create_if_missing = bool(asset_cfg.get("create_if_missing"))
                asset_map = asset_cfg.get("map") or {}
                if create_if_missing:
                    asset_payload = {}
                    for k, v in asset_map.items():
                        asset_payload[k] = _render_value(v, record, context)
                    name = asset_payload.get("name")
                    if not name:
                        req_label = (context.get("requirement") or {}).get("label") or ""
                        act_label = (context.get("activity") or {}).get("label") or ""
                        error(
                            "asset.create_if_missing requires asset.map.name to resolve asset. "
                            f"Requirement='{req_label}' Activity='{act_label}'."
                        )
                        raise typer.Exit(code=1)
                    existing_assets = (context.get("assets") or {}).get("by_name") or {}
                    normalized_name = _normalize_asset_key(str(name))
                    if str(name) in existing_assets:
                        asset_id = existing_assets.get(str(name))
                    elif normalized_name in existing_assets:
                        asset_id = existing_assets.get(normalized_name)
                    else:
                        lookup_existing = _find_asset_by_name(company_id, normalized_name)
                        if lookup_existing:
                            asset_id = lookup_existing
                            payload["assetId"] = asset_id
                        if not asset_id:
                            allowed = {"name", "description", "businessImpact", "dataClassification", "assetsTagList", "integrations", "environmentCompromised", "exploitability"}
                            filtered = {k: asset_payload.get(k) for k in allowed if asset_payload.get(k) not in (None, "")}
                            if isinstance(filtered.get("exploitability"), str):
                                filtered["exploitability"] = filtered["exploitability"].upper()
                            if apply:
                                created = _create_asset(company_id, filtered, apply=True)
                                if not created:
                                    lookup = _find_asset_by_name(company_id, normalized_name)
                                    if not lookup:
                                        error(
                                            "Failed to resolve asset for vulns.create (no ID returned). "
                                            f"Asset name='{name}'."
                                        )
                                        raise typer.Exit(code=1)
                                    asset_id = lookup
                                else:
                                    asset_id = created
                                if created:
                                    counts["assets_created"] += 1
                            else:
                                asset_id = "dry-run"
                    payload["assetId"] = asset_id
                    assets_cache = (context.get("assets") or {}).setdefault("by_name", {})
                    assets_cache[str(name)] = asset_id
                    assets_cache[normalized_name] = asset_id
                else:
                    req_label = (context.get("requirement") or {}).get("label") or ""
                    act_label = (context.get("activity") or {}).get("label") or ""
                    proj_id = (context.get("project") or {}).get("id")
                    error(
                        "vulns.create requires assetId (resolved from YAML or assets lookup). "
                        f"Project={proj_id} Requirement='{req_label}' Activity='{act_label}'."
                    )
                    raise typer.Exit(code=1)

            if payload.get("assetId") in (None, ""):
                req_label = (context.get("requirement") or {}).get("label") or ""
                act_label = (context.get("activity") or {}).get("label") or ""
                proj_id = (context.get("project") or {}).get("id")
                error(
                    "vulns.create requires assetId (resolved from YAML or assets lookup). "
                    f"Project={proj_id} Requirement='{req_label}' Activity='{act_label}'."
                )
                raise typer.Exit(code=1)
            if isinstance(payload.get("assetId"), str):
                aid = payload.get("assetId")
                if aid.isdigit():
                    payload["assetId"] = int(aid)

            if payload.get("description") in (None, ""):
                payload["description"] = payload.get("title") or "-"

            vtype = _classify_vuln_type(payload, record)
            if vtype == "DAST":
                warning("DAST is reserved for internal scans; using WEB for integrations.")
                vtype = "WEB"
            payload["type"] = vtype

            if vtype == "WEB":
                # Match bulk defaults for integrations (no template required)
                if payload.get("solution") in (None, ""):
                    payload["solution"] = payload.get("description") or payload.get("title") or "See description"
                if payload.get("impactLevel") in (None, ""):
                    payload["impactLevel"] = "LOW"
                if payload.get("probabilityLevel") in (None, ""):
                    payload["probabilityLevel"] = "LOW"
                if payload.get("summary") in (None, ""):
                    payload["summary"] = payload.get("title") or "-"
                if payload.get("impactDescription") in (None, ""):
                    payload["impactDescription"] = payload.get("description") or payload.get("title") or "-"
                if payload.get("stepsToReproduce") in (None, ""):
                    payload["stepsToReproduce"] = payload.get("description") or payload.get("title") or "-"

                if payload.get("method") in (None, ""):
                    payload["method"] = _extract_http_method(payload.get("request"))
                inferred = _infer_scheme_port(payload.get("url"), payload.get("scheme"), payload.get("port"))
                if payload.get("scheme") in (None, "") and inferred.get("scheme"):
                    payload["scheme"] = inferred.get("scheme")
                if payload.get("port") in (None, "") and inferred.get("port"):
                    payload["port"] = inferred.get("port")
                if payload.get("url") in (None, "") and payload.get("host"):
                    scheme = payload.get("scheme") or "https"
                    host = payload.get("host")
                    if payload.get("port") and str(payload.get("port")) not in {"80", "443"}:
                        payload["url"] = f"{scheme}://{host}:{payload.get('port')}"
                    else:
                        payload["url"] = f"{scheme}://{host}"
                if payload.get("url") and "://" not in str(payload.get("url")):
                    scheme = str(payload.get("scheme") or "https").lower()
                    payload["url"] = f"{scheme}://{payload.get('url')}"
                if payload.get("request") in (None, ""):
                    payload["request"] = "-"
                if payload.get("response") in (None, ""):
                    payload["response"] = "-"
                if payload.get("method") in (None, ""):
                    payload["method"] = "GET"
                allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"}
                if str(payload.get("method")).upper() not in allowed_methods:
                    payload["method"] = "GET"
                if payload.get("scheme") in (None, ""):
                    payload["scheme"] = "HTTPS"
                if payload.get("port") in (None, ""):
                    payload["port"] = 443

                required = ["assetId", "title", "description", "severity", "method", "scheme", "url", "port", "request", "response"]
                missing = [r for r in required if payload.get(r) in (None, "")]
                if missing:
                    req_label = (context.get("requirement") or {}).get("label") or ""
                    act_label = (context.get("activity") or {}).get("label") or ""
                    warning(
                        f"Skipping vulnerability (missing fields: {', '.join(missing)}). "
                        f"Requirement='{req_label}' Activity='{act_label}'."
                    )
                    counts["skipped"] += 1
                    continue
            elif vtype == "NETWORK":
                if payload.get("solution") in (None, ""):
                    payload["solution"] = payload.get("description") or payload.get("title") or "See description"
                if payload.get("impactLevel") in (None, ""):
                    payload["impactLevel"] = "LOW"
                if payload.get("probabilityLevel") in (None, ""):
                    payload["probabilityLevel"] = "LOW"
                if payload.get("summary") in (None, ""):
                    payload["summary"] = payload.get("title") or "-"
                if payload.get("impactDescription") in (None, ""):
                    payload["impactDescription"] = payload.get("description") or payload.get("title") or "-"
                if payload.get("stepsToReproduce") in (None, ""):
                    payload["stepsToReproduce"] = payload.get("description") or payload.get("title") or "-"

                if payload.get("address") in (None, ""):
                    fallback = payload.get("host") or payload.get("ip")
                    if not fallback:
                        for cand in (payload.get("matchedAt"), payload.get("url")):
                            if cand:
                                fallback = _normalize_asset_key(cand)
                                break
                    payload["address"] = fallback
                if payload.get("address"):
                    payload["address"] = _normalize_asset_key(payload.get("address"))
                if payload.get("protocol") in (None, ""):
                    ftype = (record.get("finding") or {}).get("type")
                    ftype = (str(ftype).lower() if ftype else "")
                    raw_req = (record.get("raw") or {}).get("request")
                    if ftype == "dns" or (isinstance(raw_req, str) and raw_req.lstrip().startswith(";;")):
                        payload["protocol"] = "UDP"
                    elif ftype in {"ssl", "tcp"}:
                        payload["protocol"] = "TCP"
                    else:
                        payload["protocol"] = "TCP"
                if payload.get("port") in (None, ""):
                    payload["port"] = 53 if payload.get("protocol") == "UDP" else 443
                if payload.get("attackVector") in (None, ""):
                    payload["attackVector"] = "N/A"

                required = ["assetId", "title", "description", "severity", "address", "protocol", "port", "attackVector"]
                missing = [r for r in required if payload.get(r) in (None, "")]
                if missing:
                    req_label = (context.get("requirement") or {}).get("label") or ""
                    act_label = (context.get("activity") or {}).get("label") or ""
                    warning(
                        f"Skipping vulnerability (missing fields: {', '.join(missing)}). "
                        f"Requirement='{req_label}' Activity='{act_label}'."
                    )
                    counts["skipped"] += 1
                    continue
            info(f"Creating vulnerability: {payload.get('title')}")
            payload["companyId"] = company_id
            _create_vulnerability(payload, apply)
            counts["created"] += 1
        else:
            raise ValueError(f"Unsupported action type: {action_type}")
    return counts


@app.command("create")
def create_task(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company/Scope ID."),
    label: str = typer.Option(..., "--label", "-n", help="Task label (defaults to activity label)."),
    yaml_text: Optional[str] = typer.Option(None, "--yaml", help="Inline YAML for the activity description."),
    yaml_file: Optional[str] = typer.Option(None, "--yaml-file", help="Path to YAML file for the activity description."),
    requirement_id: Optional[int] = typer.Option(None, "--requirement-id", help="Append activity to an existing requirement ID."),
    requirement_label: Optional[str] = typer.Option(None, "--requirement-label", help="Requirement label (new requirement only)."),
    requirement_description: Optional[str] = typer.Option(None, "--requirement-description", help="Requirement description (defaults to task label)."),
    activity_label: Optional[str] = typer.Option(None, "--activity-label", help="Activity label (defaults to task label)."),
    reference: Optional[str] = typer.Option(None, "--reference", help="Activity reference."),
    type_id: Optional[int] = typer.Option(None, "--type-id", help="Activity typeId."),
    requirement_prefix: str = typer.Option(TASK_PREFIX_DEFAULT, "--prefix", help="Requirement label prefix to use (new requirement)."),
    project_id: Optional[int] = typer.Option(None, "--project-id", "-p", help="Attach requirement to project."),
    global_flag: bool = typer.Option(False, "--global", help="Mark new requirement as global."),
):
    """Create a TASK requirement with a YAML activity (supports assets.create, assets.update, assets.enrich, vulns.create)."""
    _require_yaml()

    if bool(yaml_text) == bool(yaml_file):
        error("Provide exactly one of --yaml or --yaml-file.")
        raise typer.Exit(code=1)

    if requirement_id and requirement_label:
        warning("Ignoring --requirement-label because --requirement-id was provided.")

    if yaml_file:
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                yaml_text = f.read()
        except Exception as exc:
            error(f"Could not read YAML file '{yaml_file}': {exc}")
            raise typer.Exit(code=1)

    yaml_text = yaml_text or ""
    validation = _validate_task_yaml(yaml_text)
    if not validation.get("ok"):
        reason = validation.get("reason") or "invalid_yaml"
        error(f"Invalid task YAML: {reason}")
        raise typer.Exit(code=1)

    req_label_input = requirement_label or label
    req_label = _build_requirement_label(requirement_prefix, req_label_input)
    req_description = requirement_description if requirement_description is not None else label
    act_label = activity_label or label

    description_payload = f"<pre>{html_lib.escape(yaml_text)}</pre>"
    activity: Dict[str, Any] = {
        "label": act_label,
        "description": description_payload,
    }
    if reference:
        activity["reference"] = reference
    if type_id is not None:
        activity["typeId"] = type_id

    mutation = """
    mutation CreateOrUpdateRequirement($input: RequirementInput!) {
      createOrUpdateRequirement(input: $input) {
        requirement { id label }
      }
    }
    """

    activities_payload = [_normalize_activity_for_input(activity)]
    input_data: Dict[str, Any] = {
        "companyId": company_id,
        "label": req_label,
        "description": req_description,
        "type": "Procedures",
        "global": global_flag or None,
        "activities": activities_payload,
    }

    if requirement_id:
        fetch_query = """
        query Requirement($companyId: ID!, $id: ID!) {
          requirement(companyId: $companyId, id: $id) {
            id
            label
            description
            global
            check {
              id
              label
              description
              reference
              item
              category
              actionPlan
              sort
            }
          }
        }
        """
        try:
            fetched = graphql_request(fetch_query, {"companyId": company_id, "id": requirement_id}, log_request=False)
            req_data = fetched.get("requirement") or {}
        except Exception as fetch_err:
            error(f"Could not fetch existing requirement: {fetch_err}")
            raise typer.Exit(code=1)

        current_label = req_data.get("label")
        if current_label and not _matches_prefix(current_label, requirement_prefix):
            warning(
                f"Requirement {requirement_id} label '{current_label}' does not match prefix '{requirement_prefix}'. "
                "Tasks may not be picked up by list/run."
            )

        existing_activities = [_normalize_activity_for_input(a) for a in (req_data.get("check") or [])]
        input_data = {
            "id": requirement_id,
            "companyId": company_id,
            "label": requirement_label or current_label,
            "description": requirement_description if requirement_description is not None else req_data.get("description"),
            "activities": [*existing_activities, _normalize_activity_for_input(activity)],
        }

    input_data = {k: v for k, v in input_data.items() if v is not None}

    try:
        data = graphql_request(mutation, {"input": input_data})
        req = data["createOrUpdateRequirement"]["requirement"]
        req_id = req.get("id")
        success(f"Task created: requirement {req_id} - {req.get('label')}")
        if project_id and req_id:
            _attach_requirement_to_project(company_id, project_id, int(req_id))
    except Exception as e:
        error(f"Error creating task: {e}")
        raise typer.Exit(code=1)


@app.command("list")
def list_tasks(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company/Scope ID."),
    project_id: Optional[int] = typer.Option(None, "--project-id", "-P", help="Project ID (required)."),
    requirement_prefix: str = typer.Option(TASK_PREFIX_DEFAULT, "--prefix", help="Requirement label prefix to match."),
    show_invalid: bool = typer.Option(True, "--show-invalid/--only-valid", help="Include tasks with invalid/missing YAML."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for json/csv."),
):
    """List tasks defined as YAML in requirement activities."""
    _require_yaml()

    rows: List[Dict[str, Any]] = []

    if not project_id:
        error("You must provide --project-id to list tasks.")
        raise typer.Exit(code=1)

    info(f"Listing tasks for project {project_id} (company {company_id})...")
    project_query = """
    query ProjectRequirements($id: ID!) {
      project(id: $id) {
        id
        label
        playbooks {
          id
          label
          check { id label description }
        }
      }
    }
    """
    data = graphql_request(project_query, {"id": project_id})
    project = data.get("project") or {}
    playbooks = project.get("playbooks") or []
    for req in playbooks:
        label = (req.get("label") or "").strip()
        if not _matches_prefix(label, requirement_prefix):
            continue
        for act in req.get("check") or []:
            validation = _validate_task_yaml(act.get("description") or "")
            if not validation.get("ok") and not show_invalid:
                continue
            rows.append({
                "scope": "project",
                "projectId": project_id,
                "requirementId": req.get("id"),
                "requirementLabel": req.get("label"),
                "activityId": act.get("id"),
                "activityLabel": act.get("label"),
                "taskName": validation.get("name") or "",
                "steps": validation.get("steps") or "",
                "status": "ok" if validation.get("ok") else validation.get("reason"),
            })

    if not rows:
        typer.echo("No tasks found.")
        raise typer.Exit()

    from conviso.core.output_manager import export_data

    export_data(
        rows,
        schema=None,
        fmt=fmt,
        output=output,
        title=f"Tasks ({'Project ' + str(project_id) if project_id else 'Templates'})",
    )
    summary(f"{len(rows)} task(s) listed.")


@app.command("run")
def run_task(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company/Scope ID."),
    project_id: int = typer.Option(..., "--project-id", "-p", help="Project ID."),
    requirement_prefix: str = typer.Option(TASK_PREFIX_DEFAULT, "--prefix", help="Requirement label prefix to match."),
    dryrun: bool = typer.Option(True, "--dryrun/--apply", help="Run in dry-run mode (default). Use --apply to apply actions."),
    auto_approve: bool = typer.Option(False, "--auto-approve", help="Approve and persist task commands without confirmation."),
):
    """Execute tasks defined as YAML in activity descriptions."""
    _require_yaml()

    info(f"Loading tasks for project {project_id} (company {company_id})...")
    info("Sending GraphQL request to load project data...")

    query = """
    query ProjectRequirements($id: ID!) {
      project(id: $id) {
        id
        label
        playbooks {
          id
          label
          check { id label description }
        }
      }
    }
    """
    data = graphql_request(query, {"id": project_id}, log_request=False)
    project = data.get("project") or {}
    playbooks = project.get("playbooks") or []

    tasks_found = 0
    tasks_executed = 0

    base_context = {
        "company": {"id": company_id},
        "project": {"id": project_id, "label": project.get("label")},
        "assets": {"by_name": {}},
    }

    for req in playbooks:
        label = (req.get("label") or "").strip()
        if not _matches_prefix(label, requirement_prefix):
            continue
        tasks_found += 1
        info(f"Requirement '{label}' matched prefix '{requirement_prefix}'.")

        activities = req.get("check") or []
        for act in activities:
            desc = _clean_description(act.get("description") or "")
            if not desc:
                continue
            try:
                task_def = yaml.safe_load(desc)
                if not isinstance(task_def, dict) or not isinstance(task_def.get("steps"), list):
                    normalized = _normalize_yaml_steps(desc)
                    if normalized != desc:
                        task_def = yaml.safe_load(normalized)
            except Exception as exc:
                warning(f"Skipping activity {act.get('id')} (invalid YAML): {exc}")
                continue

            if not isinstance(task_def, dict) or "steps" not in task_def:
                warning(f"Skipping activity {act.get('id')} (YAML missing 'steps').")
                continue

            steps = task_def.get("steps") or []
            if not isinstance(steps, list) or not steps:
                warning(f"Skipping activity {act.get('id')} (empty steps).")
                continue
            if len(steps) != 1:
                req_label = req.get("label") or ""
                act_label = act.get("label") or ""
                error(
                    "Activity YAML must have exactly 1 step. "
                    f"Company={company_id} Project={project_id} "
                    f"Requirement='{req_label}' Activity='{act_label}' ID={act.get('id')} Steps={len(steps)}."
                )
                raise typer.Exit(code=1)

            info(f"Executing task from activity {act.get('id')} - {act.get('label')}")

            step = steps[0]
            step_id = step.get("id") or "step"
            step_name = step.get("name") or step_id
            info(f"Step: {step_name}")

            context = dict(base_context)
            context["requirement"] = {"id": req.get("id"), "label": req.get("label")}
            context["activity"] = {"id": act.get("id"), "label": act.get("label")}

            inputs = step.get("inputs") or {}
            if "assets" in inputs:
                assets_cfg = inputs.get("assets") or {}
                tags = assets_cfg.get("query", {}).get("tags")
                assets = _fetch_assets(company_id, tags=tags)
                by_name = {}
                for a in assets:
                    name = a.get("name")
                    if not name:
                        continue
                    by_name[str(name)] = a.get("id")
                    by_name[_normalize_asset_key(name)] = a.get("id")
                context["assets"] = {"list": assets, "by_name": by_name}

                export_cfg = assets_cfg.get("export") or {}
                file_path = export_cfg.get("file")
                field = export_cfg.get("field") or "name"
                if file_path:
                    dir_path = os.path.dirname(file_path)
                    if dir_path:
                        os.makedirs(dir_path, exist_ok=True)
                    with open(file_path, "w", encoding="utf-8") as f:
                        for a in assets:
                            val = a.get(field)
                            if val:
                                f.write(f"{val}\n")
                    context["assets"]["file"] = file_path

            if "targets" in inputs:
                targets_cfg = inputs.get("targets") or {}
                source = (targets_cfg.get("source") or "").lower()
                targets: List[str] = []
                if source in {"project.assets", "assets"}:
                    proj_assets = _fetch_project_assets(company_id, project_id)
                    for a in proj_assets:
                        name = a.get("name")
                        if name:
                            targets.append(str(name))
                elif source in {"project.target_urls", "project.targets", "target_urls", "targets"}:
                    targets = _fetch_project_targets(company_id, project_id)
                else:
                    warning("inputs.targets.source must be 'project.assets' or 'project.target_urls'.")

                targets = [t for t in targets if t]
                context["targets"] = {"list": targets}
                info(f"Resolved targets from project: {', '.join(targets) if targets else '-'}")

                export_cfg = targets_cfg.get("export") or {}
                file_path = export_cfg.get("file")
                mode = (export_cfg.get("mode") or "").lower()
                field = (export_cfg.get("field") or "value").lower()
                if file_path:
                    values = targets
                    if mode == "hosts" or field in {"host", "hostname"}:
                        values = _targets_to_hosts(targets)
                    dir_path = os.path.dirname(file_path)
                    if dir_path:
                        os.makedirs(dir_path, exist_ok=True)
                    with open(file_path, "w", encoding="utf-8") as f:
                        for t in values:
                            f.write(f"{t}\n")
                    context["targets"]["file"] = file_path
                    context["targets"]["hosts"] = values

            run_cfg = step.get("run") or {}
            cmd = run_cfg.get("cmd")
            if not cmd:
                warning(f"Skipping step {step_name}: missing run.cmd")
                continue

            cmd = _render_string(cmd, {}, context)
            info(f"Running: {cmd}")
            if not _is_command_approved(cmd):
                if auto_approve:
                    _approve_command(cmd)
                    info("Command approved and cached locally.")
                else:
                    info("Command requires approval to run.")
                    confirm = typer.confirm("Approve and run this command now?", default=False)
                    if not confirm:
                        warning("Command not approved. Skipping.")
                        continue
                    _approve_command(cmd)
                    info("Command approved and cached locally.")
            result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
            if result.returncode != 0:
                error(f"Command failed (code {result.returncode}): {result.stderr.strip()}")
                raise typer.Exit(code=1)

            parse_cfg = (run_cfg.get("parse") or {})
            fmt = (parse_cfg.get("format") or "").lower()
            parsed_items: List[Dict[str, Any]] = []
            if fmt:
                source_text = _read_parse_source(parse_cfg, result.stdout)
                if fmt == "nmap-xml":
                    parsed_items = _parse_nmap_xml(source_text)
                elif fmt == "nuclei-json-lines":
                    parsed_items = _parse_nuclei_json_lines(source_text)
                elif fmt == "scan-json-lines":
                    parsed_items = _parse_scan_json_lines(source_text)
                else:
                    error(f"Unsupported parse format: {fmt}")
                    raise typer.Exit(code=1)

            actions = step.get("actions") or []
            if not actions:
                warning(f"Step {step_name} has no actions; skipping.")
                continue

            planned = _actions_from_parsed(actions, parsed_items, context)

            do_apply = not dryrun
            counts = _apply_actions(planned, company_id, do_apply)
            summary(
                f"Vulnerabilities created={counts['created']} skipped={counts['skipped']} assets_created={counts['assets_created']} assets_updated={counts['assets_updated']}"
            )
            tasks_executed += 1

    if tasks_found == 0:
        warning("No requirements matched the prefix; nothing to do.")
    summary(f"Tasks matched: {tasks_found}. Steps executed: {tasks_executed}.")
