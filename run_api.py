"""
Script para iniciar a API (FastAPI) - Rode em um terminal
"""
import subprocess
from pathlib import Path

root = Path(__file__).parent
venv_scripts = root / "venv" / "Scripts"
uvicorn_exe = venv_scripts / "uvicorn.exe"

print("🚀 Iniciando API na porta 8000...")
subprocess.run([str(uvicorn_exe), "app.main:app", "--reload"], cwd=str(root))
