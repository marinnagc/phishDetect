"""
Script para rodar o Streamlit corretamente com as importações do app
"""
import sys
from pathlib import Path

# Adiciona o diretório raiz ao Python path
root_dir = Path(__file__).parent
sys.path.insert(0, str(root_dir))

# Agora importa e roda o streamlit
if __name__ == "__main__":
    import streamlit.web.cli as stcli
    import os
    
    # Define o caminho do app
    app_path = root_dir / "app" / "ui_streamlit.py"
    
    sys.argv = [
        "streamlit",
        "run",
        str(app_path),
        "--server.port=8501",
        "--server.address=localhost"
    ]
    
    sys.exit(stcli.main())
