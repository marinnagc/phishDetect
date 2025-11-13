"""
Script de teste completo para PhishDetect
Testa todas as funcionalidades e gera dados para entrega
"""
from app.analysis import analyze_url
import json
import pandas as pd
from datetime import datetime

print("=" * 80)
print("🧪 TESTE COMPLETO - PHISHDETECT - CONCEITO B")
print("=" * 80)

# URLs de teste cobrindo diferentes cenários
test_cases = [
    {
        "url": "https://www.google.com",
        "description": "URL LEGÍTIMA - Domínio confiável e antigo",
        "expected_risk": "BAIXO"
    },
    {
        "url": "https://www.nubank.com.br",
        "description": "URL LEGÍTIMA - Banco brasileiro",
        "expected_risk": "BAIXO"
    },
    {
        "url": "https://github.com",
        "description": "URL LEGÍTIMA - Plataforma conhecida",
        "expected_risk": "BAIXO"
    },
    {
        "url": "http://g00gle-login.com",
        "description": "URL SUSPEITA - Typosquatting + números substituindo letras",
        "expected_risk": "ALTO"
    },
    {
        "url": "http://secure.login.verification.paypal-update.com",
        "description": "URL SUSPEITA - Excesso de subdomínios",
        "expected_risk": "MODERADO/ALTO"
    },
]

results = []

for i, test in enumerate(test_cases, 1):
    print(f"\n{'=' * 80}")
    print(f"📍 TESTE {i}/{len(test_cases)}: {test['description']}")
    print(f"🔗 URL: {test['url']}")
    print(f"📊 Risco esperado: {test['expected_risk']}")
    print("=" * 80)
    
    try:
        result = analyze_url(test['url'])
        
        # Determina nível de risco
        score = result['score']
        if score >= 70:
            risk_level = "ALTO"
        elif score >= 40:
            risk_level = "MODERADO"
        else:
            risk_level = "BAIXO"
        
        print(f"\n✅ ANÁLISE CONCLUÍDA")
        print(f"   Score: {score}/100")
        print(f"   Nível de Risco: {risk_level}")
        print(f"   Domínio: {result['domain']}")
        print(f"   Blacklisted: {result['blacklisted']}")
        
        # WHOIS
        whois_info = result.get('whois', {})
        print(f"\n📝 WHOIS:")
        print(f"   Registrar: {whois_info.get('registrar', 'N/A')}")
        print(f"   Data de criação: {whois_info.get('creation_date', 'N/A')}")
        print(f"   Idade (dias): {whois_info.get('age_days', 'N/A')}")
        
        # SSL
        ssl_info = result.get('ssl', {})
        print(f"\n🔒 SSL:")
        print(f"   Válido: {ssl_info.get('valid', False)}")
        print(f"   Expirado: {ssl_info.get('expired', 'N/A')}")
        print(f"   Hostname match: {ssl_info.get('hostname_matches', 'N/A')}")
        if ssl_info.get('error'):
            print(f"   Erro: {ssl_info['error']}")
        
        # DNS
        dns_info = result.get('dns', {})
        print(f"\n🌐 DNS:")
        print(f"   Registros A: {len(dns_info.get('A', []))} encontrado(s)")
        print(f"   Registros MX: {len(dns_info.get('MX', []))} encontrado(s)")
        
        # Redirecionamentos
        redirects = result.get('redirect_chain', [])
        print(f"\n🔄 Redirecionamentos: {len(redirects) - 1 if redirects else 0}")
        
        # Formulários
        forms = result.get('forms', [])
        print(f"\n📋 Formulários: {len(forms)} encontrado(s)")
        if forms:
            has_password = any(f.get('has_password') for f in forms)
            has_sensitive = any(f.get('sensitive_names') for f in forms)
            print(f"   Com campo password: {has_password}")
            print(f"   Com campos sensíveis: {has_sensitive}")
        
        # Similaridade com marcas
        lev = result.get('levenshtein', [])
        if lev:
            print(f"\n🏷️  Similaridade com marcas:")
            for brand_match in lev[:3]:
                print(f"   {brand_match['brand']}: {brand_match['similarity']*100:.1f}%")
        
        # Flags detectadas
        flags = result.get('flags', [])
        print(f"\n🚩 FLAGS DETECTADAS ({len(flags)}):")
        if flags:
            for flag in flags:
                print(f"   ⚠️  {flag}")
        else:
            print("   ✅ Nenhuma flag suspeita")
        
        # Características básicas
        basic = result.get('basic_patterns', {})
        if basic:
            print(f"\n🔍 Padrões Básicos:")
            print(f"   Subdomínios: {basic.get('num_subdomains', 0)}")
            print(f"   Caracteres leet: {basic.get('num_leet_chars', 0)}")
        
        # Adiciona aos resultados
        results.append({
            'url': test['url'],
            'description': test['description'],
            'score': score,
            'risk_level': risk_level,
            'domain': result['domain'],
            'flags': ', '.join(flags) if flags else 'none',
            'num_flags': len(flags),
            'whois_age_days': whois_info.get('age_days'),
            'ssl_valid': ssl_info.get('valid'),
            'num_forms': len(forms),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        print(f"\n❌ ERRO NA ANÁLISE: {e}")
        import traceback
        traceback.print_exc()
        
        results.append({
            'url': test['url'],
            'description': test['description'],
            'score': 0,
            'risk_level': 'ERRO',
            'domain': 'N/A',
            'flags': f'ERROR: {str(e)}',
            'num_flags': 0,
            'whois_age_days': None,
            'ssl_valid': None,
            'num_forms': 0,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

# Gera relatório consolidado
print("\n" + "=" * 80)
print("📊 RELATÓRIO CONSOLIDADO DOS TESTES")
print("=" * 80)

df = pd.DataFrame(results)
print("\n" + df.to_string(index=False))

# Salva CSV
csv_filename = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
df.to_csv(csv_filename, index=False)
print(f"\n💾 Resultados salvos em: {csv_filename}")

# Estatísticas
print("\n" + "=" * 80)
print("📈 ESTATÍSTICAS")
print("=" * 80)
print(f"Total de testes: {len(results)}")
print(f"Testes bem-sucedidos: {len([r for r in results if r['risk_level'] != 'ERRO'])}")
print(f"URLs de risco ALTO: {len([r for r in results if r['risk_level'] == 'ALTO'])}")
print(f"URLs de risco MODERADO: {len([r for r in results if r['risk_level'] == 'MODERADO'])}")
print(f"URLs de risco BAIXO: {len([r for r in results if r['risk_level'] == 'BAIXO'])}")
print(f"Total de flags detectadas: {sum(r['num_flags'] for r in results)}")

# Verificação de funcionalidades (Conceito B)
print("\n" + "=" * 80)
print("✅ VERIFICAÇÃO DE REQUISITOS - CONCEITO B")
print("=" * 80)

features_tested = {
    "WHOIS (idade do domínio)": any(r['whois_age_days'] is not None for r in results),
    "SSL (certificados)": any(r['ssl_valid'] is not None for r in results),
    "Detecção de flags": sum(r['num_flags'] for r in results) > 0,
    "Análise de formulários": any(r['num_forms'] > 0 for r in results if r['risk_level'] != 'ERRO'),
    "Sistema de scoring": all(r['score'] >= 0 for r in results if r['risk_level'] != 'ERRO'),
}

for feature, status in features_tested.items():
    status_icon = "✅" if status else "⚠️"
    print(f"{status_icon} {feature}: {'FUNCIONANDO' if status else 'NÃO TESTADO'}")

print("\n" + "=" * 80)
print("🎯 TESTE COMPLETO FINALIZADO!")
print("=" * 80)
print("\n📝 PRÓXIMOS PASSOS:")
print("1. Rode a aplicação: streamlit run app/ui_streamlit.py")
print("2. Teste as URLs acima na interface")
print("3. Tire screenshots de 3 análises diferentes")
print("4. Exporte o histórico em CSV")
print("5. Use os dados para o relatório")
print("\n" + "=" * 80)
