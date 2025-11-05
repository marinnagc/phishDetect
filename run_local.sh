#!/usr/bin/env bash
# ative o venv antes: source venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 &
streamlit run app/ui_streamlit.py --server.port 8501
# chmod +x run_local.sh