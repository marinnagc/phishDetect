"""
Script para testar as melhorias na função check_ssl
"""
from app.analysis import check_ssl
import json

print("=" * 60)
print("🔒 TESTANDO FUNÇÃO SSL CORRIGIDA")
print("=" * 60)

# Lista de domínios para testar diferentes cenários
test_cases = [
    ("google.com", 443, "Domínio popular com SSL válido"),
    ("github.com", 443, "Domínio tech com SSL válido"),
    ("expired.badssl.com", 443, "Certificado expirado (teste)"),
    ("wrong.host.badssl.com", 443, "Hostname mismatch (teste)"),
    ("example.com", 443, "Domínio de exemplo"),
]

for hostname, port, description in test_cases:
    print(f"\n{'=' * 60}")
    print(f"🔐 Testando: {hostname}:{port}")
    print(f"   ({description})")
    print(f"{'=' * 60}")
    
    try:
        result = check_ssl(hostname, port)
        
        print("\n📊 Resultado:")
        print(f"   ✓ Válido: {result.get('valid', False)}")
        print(f"   ✓ Issuer: {result.get('issuer', 'N/A')}")
        print(f"   ✓ Expira em: {result.get('notAfter', 'N/A')}")
        print(f"   ✓ Expirado: {result.get('expired', 'N/A')}")
        print(f"   ✓ Hostname match: {result.get('hostname_matches', 'N/A')}")
        
        if result.get('error'):
            print(f"   ⚠️ Erro: {result['error']}")
        else:
            print(f"   ✅ SSL verificado com sucesso!")
            
        # Mostra JSON completo para debug
        print(f"\n   JSON completo:")
        print(f"   {json.dumps(result, indent=6, ensure_ascii=False, default=str)}")
        
    except Exception as e:
        print(f"   ❌ EXCEÇÃO NÃO TRATADA: {e}")
        import traceback
        traceback.print_exc()

print("\n" + "=" * 60)
print("✅ TESTE CONCLUÍDO!")
print("=" * 60)
