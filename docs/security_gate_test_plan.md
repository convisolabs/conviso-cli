# Security Gate — Plano de Testes

## Escopo

Este documento cobre os cenários de teste automatizados e manuais para o comando
`conviso security-gate assert-security-rules`, incluindo os fluxos de plataforma,
fluxo YAML local, SLA, timezone, e suporte a branch.

---

## Critérios de Saída

- [ ] Todos os testes automatizados passando (`pytest 78/78` ou mais).
- [ ] Nenhuma credencial real em nenhum arquivo de teste, doc ou script deste
      PR (revisão manual antes do merge).
- [ ] Todos os cenários BRANCH-01 a BRANCH-08 implementados e passando.
- [ ] `--help` do comando reflete todos os parâmetros e suas descrições.

---

## Casos de Teste — Fluxo Plataforma (Platform Gate)

| ID | Cenário | Resultado esperado | Status |
|----|---------|-------------------|--------|
| PLT-01 | `securityGateRun` retorna `PASS` | Exit 0, mensagem de sucesso | ✅ |
| PLT-02 | `securityGateRun` retorna `FAIL` | Exit 1, tabela de vulnerabilidades | ✅ |
| PLT-03 | Erro de rede/API na chamada principal | Exit 1, mensagem de erro técnico (não "gate falhou por política") | ✅ |
| PLT-04 | API retorna `securityGateRun: null` | Exit 1, mensagem sobre asset_id inválido | ✅ |
| PLT-05 | `--output` especificado | Arquivo JSON gerado | ✅ |

---

## Casos de Teste — Fluxo YAML Local (Local Rules Gate)

| ID | Cenário | Resultado esperado | Status |
|----|---------|-------------------|--------|
| YML-01 | YAML válido, sem violações | Exit 0 | ✅ |
| YML-02 | YAML válido, violação de threshold | Exit 1, resumo de severidades | ✅ |
| YML-03 | Erro de rede na chamada `issuesStats` | Exit 1, erro técnico (não "gate passou") | ✅ |
| YML-04 | YAML inválido (erro de parse) | Exit 1, mensagem de erro de parse | ✅ |
| YML-05 | YAML válido mas viola JSON Schema | Exit 1, mensagem de validação | ✅ |
| YML-06 | `--output` especificado | Arquivo JSON gerado com `mode: local_rules` | ✅ |
| YML-07 | Com `max_days_to_fix`: chamada por severidade | API chamada N vezes (uma por severidade com SLA) | ✅ |
| YML-08 | Sem `max_days_to_fix`: chamada única | API chamada 1 vez | ✅ |

---

## Casos de Teste — SLA e Timezone

| ID | Cenário | Resultado esperado | Status |
|----|---------|-------------------|--------|
| SLA-01 | `max_days_to_fix: 30` → cutoff correto | `end_date` = hoje - 30 dias (UTC) | ✅ |
| SLA-02 | `max_days_to_fix: 0` → usa fim do dia UTC | `end_date` = 23:59:59 UTC de hoje | ✅ |
| SLA-03 | Data de criação sem timezone (naive) | Normalizada para UTC antes de comparar | ✅ |
| SLA-04 | Timezone UTC explícito em `now_utc` | `datetime.now(timezone.utc)` utilizado | ✅ |

---

## Casos de Teste — Validação de Parâmetros

| ID | Cenário | Resultado esperado | Status |
|----|---------|-------------------|--------|
| PRM-01 | `--rules-file` sem `--company-id` | Exit 1 ou 2, mensagem menciona `company-id` | ✅ |

---

## Casos de Teste — Suporte a Branch

| ID | Cenário | Resultado esperado | Status |
|----|---------|-------------------|--------|
| BRANCH-01 | `--branch` informada e encontrada (fluxo plataforma) | `branchId` correto é passado para `securityGateRun` | ✅ |
| BRANCH-02 | `--branch` informada e encontrada (fluxo YAML) | `branchNames: ["<branch>"]` passado para `issuesStats` | ✅ |
| BRANCH-03 | `--branch` informada mas não encontrada | Exit 1, mensagem lista branches disponíveis | ✅ |
| BRANCH-04 | `--branch` sem `--company-id` | Exit 1 (ou 2), mensagem menciona `company-id` | ✅ |
| BRANCH-05 | Nome com case diferente (`Main` vs `main`) | Tratado como "não encontrada" (sem match case-insensitive silencioso) | ✅ |
| BRANCH-06 | Falha de rede/timeout na query `BranchLookup` | Exit 1, mensagem de "erro técnico" — não confundida com "branch não encontrada" nem com FAIL de política | ✅ |
| BRANCH-07 | Sem `--branch` (comportamento default) | `branchId`/`branchNames` são `null`/`None` nas queries — comportamento atual preservado | ✅ |
| BRANCH-08 | `--branch` usada com sucesso | Warning exibido sobre exclusão de vulnerabilidades legacy sem branch | ✅ |

---

## Casos de Teste — Formatter

| ID | Cenário | Status |
|----|---------|--------|
| FMT-01 | Header de falha (singular/plural) | ✅ |
| FMT-02 | Mensagem de sucesso | ✅ |
| FMT-03 | Hint de saída completa | ✅ |
| FMT-04 | Aviso de truncamento | ✅ |
| FMT-05 | Strip de markdown | ✅ |

---

## Notas de Implementação

### BranchLookup — Latência Extra
Toda execução com `--branch` incorre em **uma chamada GraphQL adicional** antes da
chamada principal do gate (resolve nome → ID via `branches(companyId, assetId)`).
Isso é um trade-off aceito. Futura otimização poderia cachear ou combinar o lookup.

### Auto-detecção de Branch (Follow-up)
Não implementado neste PR. Possível follow-up: fallback automático para variáveis
de ambiente de CI quando `--branch`/`CONVISO_BRANCH` não forem informados:
- `GITHUB_REF_NAME`
- `GITHUB_HEAD_REF`
- `CI_COMMIT_REF_NAME`
- `BITBUCKET_BRANCH`
- `BRANCH_NAME`

### Credenciais em Testes
Nenhum valor real de API key ou URL de ambiente deve aparecer em arquivos de teste,
documentação ou scripts deste repositório. Use sempre placeholders:
```bash
export CONVISO_API_KEY="<YOUR_API_KEY>"
export CONVISO_API_URL="https://api.convisoappsec.com"
```
