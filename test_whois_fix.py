"""
Script para testar as melhorias na função get_whois_info
"""
from app.analysis import get_whois_info
import json

print("=" * 60)
print("🧪 TESTANDO FUNÇÃO WHOIS CORRIGIDA")
print("=" * 60)

# Lista de domínios para testar diferentes cenários
test_domains = [
    ("google.com", "Domínio popular - deve funcionar"),
    ("nubank.com.br", "Domínio brasileiro - deve funcionar"),
    ("example.com", "Domínio de exemplo - deve funcionar"),
    ("github.com", "Domínio tech - deve funcionar"),
    ("thisdoesnotexist12345xyz.com", "Domínio inexistente - deve falhar graciosamente"),
]

for domain, description in test_domains:
    print(f"\n{'=' * 60}")
    print(f"📍 Testando: {domain}")
    print(f"   ({description})")
    print(f"{'=' * 60}")
    
    try:
        result = get_whois_info(domain)
        
        print("\n✅ Resultado:")
        print(f"   Registrar: {result.get('registrar', 'N/A')}")
        print(f"   Data de criação: {result.get('creation_date', 'N/A')}")
        print(f"   Idade (dias): {result.get('age_days', 'N/A')}")
        
        if result.get('error'):
            print(f"   ⚠️ Erro: {result['error']}")
        else:
            print(f"   ✅ Sucesso! WHOIS funcionou")
            
        # Mostra JSON completo para debug
        print(f"\n   JSON completo:")
        print(f"   {json.dumps(result, indent=6, ensure_ascii=False)}")
        
    except Exception as e:
        print(f"   ❌ EXCEÇÃO NÃO TRATADA: {e}")
        import traceback
        traceback.print_exc()

print("\n" + "=" * 60)
print("✅ TESTE CONCLUÍDO!")
print("=" * 60)
