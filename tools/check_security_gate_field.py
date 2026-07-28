#!/usr/bin/env python3
"""
Ferramenta de diagnóstico: verifica se o campo `securityGateRun` existe no
schema GraphQL de https://api.convisoappsec.com/graphql.

Uso:
    # Com API key como variável de ambiente:
    CONVISO_API_KEY=<sua-key> python3 tools/check_security_gate_field.py

    # Ou coloque a key em .env na raiz do projeto e execute:
    python3 tools/check_security_gate_field.py
"""

import sys
import os
import json
from pathlib import Path

# Permite rodar de qualquer diretório
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

try:
    from dotenv import load_dotenv
    root_env = Path(__file__).resolve().parents[1] / ".env"
    if root_env.exists():
        load_dotenv(root_env, override=True)
    else:
        load_dotenv()
except ImportError:
    pass

try:
    import requests
except ImportError:
    print("ERROR: 'requests' não encontrado. Execute: pip install requests")
    sys.exit(1)

API_URL = "https://api.convisoappsec.com/graphql"

# Tenta ler a key de várias fontes (mesmo mecanismo do conviso-cli)
api_key = (
    os.getenv("CONVISO_API_KEY")
    or os.getenv("FLOW_API_KEY")
)

if not api_key:
    creds = Path.home() / ".config" / "conviso" / "credentials"
    if creds.exists():
        try:
            api_key = json.loads(creds.read_text()).get("api_key")
        except Exception:
            pass

if not api_key:
    print("ERRO: Nenhuma API key encontrada.")
    print("Defina CONVISO_API_KEY=<sua-key> ou execute 'conviso auth login'.")
    sys.exit(1)

print(f"API URL: {API_URL}")
print(f"API Key: {api_key[:8]}...{api_key[-4:]} ({len(api_key)} chars)")
print()

INTROSPECTION_QUERY = """
{
  __type(name: "Query") {
    fields {
      name
      description
    }
  }
}
"""

headers = {
    "Content-Type": "application/json",
    "x-api-key": api_key,
}

try:
    resp = requests.post(
        API_URL,
        json={"query": INTROSPECTION_QUERY},
        headers=headers,
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
except Exception as exc:
    print(f"ERRO de rede/HTTP: {exc}")
    sys.exit(1)

if "errors" in data:
    print("ERRO GraphQL:")
    for err in data["errors"]:
        print(f"  - {err.get('message')}")
    sys.exit(1)

type_data = (data.get("data") or {}).get("__type")
if not type_data:
    print("ERRO: Resposta inesperada — '__type' não encontrado.")
    print("Resposta raw:", json.dumps(data, indent=2)[:500])
    sys.exit(1)

fields = type_data.get("fields") or []
field_names = [f["name"] for f in fields]

print(f"Total de campos no tipo Query: {len(field_names)}")
print()

# Verificação específica do securityGateRun
target = "securityGateRun"
found = target in field_names
if found:
    desc = next((f.get("description") for f in fields if f["name"] == target), "")
    print(f"✅ '{target}' ENCONTRADO no schema!")
    if desc:
        print(f"   Descrição: {desc}")
else:
    print(f"❌ '{target}' NÃO encontrado no schema.")
    similar = [n for n in field_names if "security" in n.lower() or "gate" in n.lower()]
    if similar:
        print(f"   Campos similares encontrados: {similar}")

print()

# Campos relacionados a issues/stats
issue_fields = [n for n in field_names if "issue" in n.lower()]
print(f"Campos relacionados a 'issue': {issue_fields}")

print()
print("Todos os campos Query (ordenados):")
for name in sorted(field_names):
    print(f"  {name}")

print()
print("=" * 60)
if found:
    print("RESULTADO: CAMPO DISPONÍVEL — pode implementar os dois fluxos.")
else:
    print("RESULTADO: CAMPO AUSENTE — implemente apenas o fluxo YAML.")
