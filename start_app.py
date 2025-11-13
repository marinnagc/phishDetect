"""
Script para iniciar a API (FastAPI) e o Frontend (Streamlit) simultaneamente
"""
import subprocess
import sys
import time
from pathlib import Path

# Caminhos
root = Path(__file__).parent
venv_scripts = root / "venv" / "Scripts"
uvicorn_exe = venv_scripts / "uvicorn.exe"
streamlit_exe = venv_scripts / "streamlit.exe"

print("=" * 60)
print("🚀 INICIANDO PHISHDETECT")
print("=" * 60)

# Inicia a API (FastAPI)
print("\n📡 Iniciando API (FastAPI) na porta 8000...")
api_process = subprocess.Popen(
    [str(uvicorn_exe), "app.main:app", "--reload"],
    cwd=str(root),
    creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
)
print("✅ API iniciada em: http://127.0.0.1:8000")
print("📚 Documentação: http://127.0.0.1:8000/docs")

# Aguarda a API iniciar
time.sleep(3)

# Inicia o Streamlit
print("\n🎨 Iniciando Frontend (Streamlit) na porta 8502...")
streamlit_process = subprocess.Popen(
    [str(streamlit_exe), "run", "app/ui_streamlit.py", "--server.port=8502"],
    cwd=str(root),
    creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
)
print("✅ Frontend iniciado em: http://localhost:8502")

print("\n" + "=" * 60)
print("✅ PHISHDETECT ESTÁ RODANDO!")
print("=" * 60)
print("\n📍 URLs:")
print("   🔧 API: http://127.0.0.1:8000")
print("   📚 Docs: http://127.0.0.1:8000/docs")
print("   🎨 App: http://localhost:8502")
print("\n⚠️  Pressione Ctrl+C para parar os serviços")
print("=" * 60)

try:
    # Mantém o script rodando
    api_process.wait()
    streamlit_process.wait()
except KeyboardInterrupt:
    print("\n\n🛑 Encerrando serviços...")
    api_process.terminate()
    streamlit_process.terminate()
    print("✅ Serviços encerrados!")
