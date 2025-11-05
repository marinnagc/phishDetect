# Projeto: PhishDetect — Ferramenta para detecção de Phishing (Conceito B)

**Aluno:** [SEU NOME]  
**Disciplina:** [Nome da disciplina]  
**Data:** [DATA]

## 1. Objetivo
Descrever objetivo: avaliar heurísticas para detecção de phishing, implementar ferramenta local que analisa URLs e páginas, e propor mitigação. Destacar caráter ético (ambiente controlado, consentimento).

## 2. Contexto e conceitos
Definir phishing, spearphishing, whaling. Explicar controles SPF/DKIM/DMARC (breve) e por que não são suficientes isoladamente.

## 3. Metodologia
- Ambiente: VM/local, SQLite para histórico, Streamlit UI, FastAPI backend.
- Fontes e limites: consultas WHOIS, SSL, redirecionamentos, conteúdo (form detection), listas públicas (PhishTank placeholder).
- Ética: não enviar campanhas, somente análises de URLs públicas ou domínios de teste.

## 4. Implementação
- Arquitetura: frontend Streamlit, backend FastAPI, módulo de análise (`analysis.py`), banco SQLite para histórico.
- Principais checagens implementadas:
  - Validação sintática de URL
  - Expansão de shorteners
  - Consulta WHOIS → idade do domínio
  - Verificação SSL (validade, emissor)
  - Redirecionamentos
  - Detecção de formulários/login
  - Distância de Levenshtein para marcas conhecidas
  - Scoring: explicar pesos usados

## 5. Resultados (Evidências)
Apresentar 3 análises (prints):
1. URL legítima (ex.: https://www.google.com) — interpretar por que score baixo.
2. URL redirecionada (ex.: httpbin redirect) — interpretar.
3. URL com formulário (ex.: httpbin forms) — interpretar.

Incluir tabela com métricas (score, flags, idade do domínio, SSL).

## 6. Discussão e limitações
- Whois inconsistent across TLDs, TLS handshake pode falhar por bloqueios, heurísticas false positives/negatives.
- Necessidade de APIs (PhishTank/OpenPhish) para cobertura real; ML para A-level.

## 7. Recomendações
- Técnico: aplicar SPF/DKIM/DMARC, bloqueio por listas, sandboxing de anexos, validação de OAuth apps.
- Organizacional: campanhas de awareness, simulações autorizadas regulares, playbooks de resposta.

## 8. Conclusão
Resumo e próximos passos (ex.: coletar dataset rotulado, treinar modelo, plugin navegador A-level).

## Anexos
- CSV com histórico (exportado do Streamlit).
- Trechos do JSON `raw` de 3 análises (anonimizados).
- Prints do dashboard.

## Referências
- NIST, CISA, OWASP, GoPhish docs, PhishTank (incluir links).
