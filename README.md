# PhishDetect - Conceito B (Entrega para prova)

Implementação mínima para a Opção 3 (Conceito B) — ferramenta de detecção/análise de phishing.

## Requisitos
- Python 3.11+
- pip

## Instalação
1. python -m venv venv
2. source venv/bin/activate
3. pip install -r requirements.txt

## Rodar local (modo rápido)
1. uvicorn app.main:app --reload
2. streamlit run app/ui_streamlit.py

A API estará em http://127.0.0.1:8000
O frontend (Streamlit) estará em http://127.0.0.1:8501

## Rodar com Docker
docker build -t phishdetect-b .
docker run -p 8000:8000 -p 8501:8501 phishdetect-b

## O que entregar
- Relatório (PDF) usando `report_template.md`
- Slides (PDF/PPTX) usando `slides_template.md`
- Repositório com o código
- Evidências: screenshots do dashboard com 3 URLs, CSV exportado do histórico.
