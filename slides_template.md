# Slide 1
PhishDetect — Ferramenta para detecção de Phishing (Conceito B)
Aluno: [NOME] — Data: [DATA]

# Slide 2
Objetivo
- Avaliar vulnerabilidade a phishing
- Implementar ferramenta de análise (heurística)

# Slide 3
Arquitetura
- FastAPI (backend)
- Streamlit (frontend)
- SQLite (histórico)

# Slide 4
Metodologia
- WHOIS (idade do domínio)
- SSL (validade)
- Redirecionamentos
- Levenshtein (similaridade)
- Detecção de formulários

# Slide 5
Exemplo de análise — URL legítima
- Score: X
- Flags: none
- Interpretação

# Slide 6
Exemplo — URL suspeita / redirecionamento
- Score: Y
- Flags: redirects, young_domain
- Interpretação

# Slide 7
Métricas & Evidências
- Histograma de scores (incluir screenshot)
- CSV exportado

# Slide 8
Recomendações
- SPF/DKIM/DMARC, sandboxing, treinamento, políticas

# Slide 9
Limitações e próximos passos
- Cobertura via listas, false positives, evolução para ML

# Slide 10
Perguntas
