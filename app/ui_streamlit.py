# app/ui_streamlit.py
import streamlit as st
import requests
import pandas as pd
import json
import sys
from pathlib import Path

# Adiciona o diretório raiz ao path para importações funcionarem
root_dir = Path(__file__).parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from app.db import read_history, init_db

API_URL = "http://127.0.0.1:8000/analyze"


def build_standard_report(result: dict) -> str:
    """
    Gera um relatório padronizado em texto, em português,
    a partir do dicionário retornado pela API /analyze.
    """
    url = result.get("url", "")
    domain = result.get("domain", "")
    score = result.get("score", 0)
    flags = result.get("flags", [])

    whois = result.get("whois", {}) or {}
    registrar = whois.get("registrar")
    creation_date = whois.get("creation_date")
    age_days = whois.get("age_days")
    whois_error = whois.get("error")  


    ssl_info = result.get("ssl", {}) or {}
    ssl_valid = ssl_info.get("valid", False)
    ssl_issuer = ssl_info.get("issuer")
    ssl_not_after = ssl_info.get("notAfter")
    ssl_expired = ssl_info.get("expired")
    ssl_hostname_matches = ssl_info.get("hostname_matches")
    ssl_error = ssl_info.get("error")  


    dns_info = result.get("dns", {}) or {}
    dns_a = dns_info.get("A", [])
    dns_mx = dns_info.get("MX", [])

    redirect_chain = result.get("redirect_chain", []) or []
    num_redirects = max(len(redirect_chain) - 1, 0)

    forms = result.get("forms", []) or []
    num_forms = len(forms)
    has_password_form = any(f.get("has_password") for f in forms)
    has_sensitive_fields = any(f.get("sensitive_names") for f in forms)

    lev = result.get("levenshtein", []) or []
    top_sim = lev[0] if lev else None

    # Nível de risco textual
    if score >= 70:
        risk_level = "ALTO"
    elif score >= 40:
        risk_level = "MODERADO"
    else:
        risk_level = "BAIXO"

    # Explicações das flags
    flag_explanations = {
        "blacklist": "Domínio presente em listas de domínios maliciosos (blacklist).",
        "young_domain": "Domínio recente (ou sem dados WHOIS confiáveis), o que aumenta o risco.",
        "ssl_invalid": "Problema na verificação do certificado SSL/TLS (inválido, ausente ou erro na conexão).",
        "ssl_expired": "O certificado SSL/TLS está expirado.",
        "ssl_hostname_mismatch": "O certificado SSL/TLS é válido, mas o nome do host acessado não coincide com o nome registrado no certificado (ex.: falta ou sobra 'www').",
        "redirects": "Presença de redirecionamentos, possivelmente para domínios diferentes.",
        "form_with_password": "Página contém formulário com campo de senha (possível página de login).",
        "similar_to_brand": "Domínio com alta similaridade com marca conhecida (possível typosquatting).",
        "many_subdomains": "Uso excessivo de subdomínios, o que pode indicar tentativa de ocultar o domínio real.",
        "special_chars_in_domain": "Domínio contém caracteres especiais incomuns (hífens, punycode, etc.).",
        "numbers_in_place_of_letters": "Uso de números no lugar de letras (leet), típico de domínios falsos.",
        "dynamic_dns": "Domínio aparenta usar serviço de DNS dinâmico (no-ip, dyndns), comum em cenários maliciosos.",
    }

    flags_text_list = []
    for f in flags:
        flags_text_list.append(f"- {f}: {flag_explanations.get(f, 'Flag sem descrição detalhada cadastrada.')}")

    if not flags_text_list:
        flags_text_list.append("- Nenhuma característica suspeita marcada pelas heurísticas.")

    # WHOIS / idade
    if whois_error:
        age_text = (
            "Não foi possível determinar a idade do domínio. "
            f"Erro na consulta WHOIS: {whois_error}"
        )
    elif age_days is None:
        age_text = "Não foi possível determinar a idade do domínio."
    else:
        age_text = f"O domínio possui aproximadamente {age_days} dias de existência."


    # SSL
    if ssl_valid:
        ssl_text = "O certificado SSL/TLS foi validado com sucesso."
    elif ssl_error:
        ssl_text = f"Houve falha na validação do certificado SSL/TLS: {ssl_error}"
    else:
        ssl_text = "Houve falha na validação do certificado SSL/TLS (inválido, ausente ou erro na conexão)."


    # Redirects
    if num_redirects > 0:
        redir_text = f"Foram identificados {num_redirects} redirecionamentos durante o acesso à URL."
    else:
        redir_text = "Nenhum redirecionamento adicional foi identificado."

    # Forms
    if num_forms == 0:
        forms_text = "Não foram encontrados formulários na página analisada."
    else:
        extra = []
        if has_password_form:
            extra.append("há pelo menos um formulário com campo de senha")
        if has_sensitive_fields:
            extra.append("foram identificados campos com nomes potencialmente sensíveis (ex.: password, card, cpf)")
        extra_str = " e ".join(extra) if extra else "não foram observados campos sensíveis específicos"
        forms_text = f"Foram encontrados {num_forms} formulários na página; {extra_str}."

    # Similaridade com marcas
    if top_sim and top_sim.get("similarity", 0) >= 0.8:
        sim_brand = top_sim.get("brand")
        sim_value = top_sim.get("similarity")
        sim_text = (
            f"A análise de similaridade (distância de Levenshtein normalizada) indicou "
            f"alta semelhança ({sim_value:.3f}) com o domínio de marca conhecida '{sim_brand}', "
            "o que pode indicar tentativa de imitação (typosquatting)."
        )
    else:
        sim_text = (
            "Não foram encontradas similaridades significativas com domínios de marcas "
            "conhecidas nas heurísticas aplicadas."
        )

    # DNS
    dns_parts = []
    if dns_a:
        dns_parts.append(f"Registros A: {', '.join(dns_a)}")
    if dns_mx:
        dns_parts.append(f"Registros MX: {', '.join(dns_mx)}")
    if not dns_parts:
        dns_parts.append("Não foi possível obter registros DNS A/MX ou o domínio não possui registros convencionais.")
    dns_text = " | ".join(dns_parts)

    # Recomendações básicas com base no nível de risco
    if risk_level == "ALTO":
        rec_text = (
            "Recomenda-se bloquear o acesso à URL, reforçar a conscientização dos usuários, "
            "investigar possíveis impactos e, se aplicável, incluir o domínio em listas internas de bloqueio."
        )
    elif risk_level == "MODERADO":
        rec_text = (
            "Recomenda-se cautela ao acessar esta URL, validação adicional por equipe de segurança "
            "e monitoramento de novos acessos ou alterações no domínio."
        )
    else:
        rec_text = (
            "A URL apresenta baixo risco segundo as heurísticas aplicadas, mas ainda assim é recomendável "
            "manter atenção a comportamentos suspeitos e validar sempre o contexto de uso."
        )

    report = f"""
============================================================
RELATÓRIO PADRONIZADO DE ANÁLISE DE URL - PHISHDETECT
============================================================

1. DADOS GERAIS
- URL analisada: {url}
- Domínio: {domain}
- Score de risco: {score}/100
- Nível de risco (heurístico): {risk_level}

2. CARACTERÍSTICAS TÉCNICAS DO DOMÍNIO
- Registrar (WHOIS): {registrar}
- Data de criação registrada (WHOIS): {creation_date}
- Idade aproximada do domínio: {age_text}
- Informações de DNS: {dns_text}

3. CERTIFICADO SSL/TLS
- Situação: {ssl_text}
- Emissor do certificado (quando disponível): {ssl_issuer}
- Validade (notAfter, quando disponível): {ssl_not_after}
- Expirado: {ssl_expired}
- Coincidência de hostname no certificado: {ssl_hostname_matches}

4. REDIRECIONAMENTOS
- Cadeia de redirecionamentos (URL final é o último elemento): {redirect_chain}
- Resumo: {redir_text}

5. ANÁLISE DE CONTEÚDO E FORMULÁRIOS
- Quantidade de formulários = {num_forms}
- Detalhes: {forms_text}

6. SIMILARIDADE COM MARCAS CONHECIDAS
- Resultado: {sim_text}

7. CARACTERÍSTICAS SUSPEITAS (FLAGS)
- Flags detectadas:
{chr(10).join(flags_text_list)}

8. AVALIAÇÃO GERAL E RECOMENDAÇÕES
Com base nas heurísticas implementadas (idade do domínio, SSL, redirecionamentos,
presença de formulários sensíveis, similaridade com marcas e listas de reputação),
o score de risco calculado foi de {score}/100, resultando no nível de risco: {risk_level}.

Recomendações:
- {rec_text}

Este relatório foi gerado automaticamente pela ferramenta PhishDetect a partir
dos dados coletados no momento da análise.

============================================================
"""
    return report.strip()


def main():
    st.set_page_config(
        layout="wide", 
        page_title="PhishDetect - Detector de Phishing",
        page_icon="🛡️",
        initial_sidebar_state="collapsed"
    )
    
    # Header estilizado
    st.markdown("""
        <style>
        .main-header {
            font-size: 3rem;
            font-weight: bold;
            color: #1f77b4;
            text-align: center;
            margin-bottom: 0.5rem;
        }
        .sub-header {
            font-size: 1.2rem;
            color: #666;
            text-align: center;
            margin-bottom: 2rem;
        }
        </style>
        <div class="main-header">🛡️ PhishDetect</div>
        <div class="sub-header">Ferramenta Avançada de Detecção de Phishing</div>
    """, unsafe_allow_html=True)

    init_db()
    df = read_history()

    # Abas
    tab1, tab2, tab3 = st.tabs(["🔍 Nova Análise", "📊 Histórico", "📄 Relatórios Detalhados"])

    # ---------------------------------------------------------------------
    # ABA 1: NOVA ANÁLISE
    # ---------------------------------------------------------------------
    with tab1:
        st.markdown("### Insira a URL para análise de phishing")
        st.markdown("Analisamos certificados SSL, WHOIS, DNS, redirecionamentos, formulários e muito mais!")

        with st.form("analyze_form"):
            url = st.text_input(
                "🌐 URL para verificar", 
                value="",
                placeholder="https://exemplo.com.br"
            )
            col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
            with col_btn1:
                submitted = st.form_submit_button("🔍 Analisar", use_container_width=True)
            with col_btn2:
                clear = st.form_submit_button("🗑️ Limpar", use_container_width=True)

        if submitted and url:
            with st.spinner("🔍 Analisando URL... (isso pode levar alguns minutos)"):
                try:
                    r = requests.post(API_URL, json={"url": url}, timeout=120)
                    if r.status_code == 200:
                        res = r.json()
                        
                        # Header com score e nível de risco
                        score = res['score']
                        if score >= 70:
                            st.error(f"⚠️ ALTO RISCO — Score: {score}/100")
                            risk_color = "red"
                            risk_emoji = "🔴"
                        elif score >= 40:
                            st.warning(f"⚡ RISCO MODERADO — Score: {score}/100")
                            risk_color = "orange"
                            risk_emoji = "🟡"
                        else:
                            st.success(f"✅ BAIXO RISCO — Score: {score}/100")
                            risk_color = "green"
                            risk_emoji = "🟢"

                        # Métricas principais
                        st.markdown("---")
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("🎯 Score de Risco", f"{score}/100")
                        with col2:
                            st.metric("🌐 Domínio", res["domain"])
                        with col3:
                            flags_count = len(res.get("flags", []))
                            st.metric("🚩 Flags Detectadas", flags_count)

                        # Blocos de teste estilizados
                        st.markdown("---")
                        st.subheader("📊 Resultados dos Testes")
                        
                        # 1. BLACKLIST
                        with st.expander("🛡️ Verificação em Blacklist", expanded=True):
                            if res.get("blacklisted"):
                                st.error("❌ **FALHOU** — Domínio encontrado em lista de sites maliciosos")
                            else:
                                st.success("✅ **PASSOU** — Domínio não está em listas de phishing conhecidas")
                        
                        # 2. WHOIS / IDADE DO DOMÍNIO
                        with st.expander("📅 Idade do Domínio (WHOIS)", expanded=True):
                            whois = res.get("whois", {})
                            age_days = whois.get("age_days")
                            whois_error = whois.get("error")
                            
                            if whois_error:
                                st.warning(f"⚠️ **AVISO** — Não foi possível verificar: {whois_error}")
                            elif age_days is None:
                                st.warning("⚠️ **AVISO** — Idade do domínio indeterminada")
                            elif age_days < 90:
                                st.error(f"❌ **SUSPEITO** — Domínio muito recente ({age_days} dias)")
                                st.caption(f"📆 Criado em: {whois.get('creation_date', 'N/A')}")
                                st.caption(f"🏢 Registrar: {whois.get('registrar', 'N/A')}")
                            else:
                                st.success(f"✅ **PASSOU** — Domínio estabelecido ({age_days} dias / {age_days//365} anos)")
                                st.caption(f"📆 Criado em: {whois.get('creation_date', 'N/A')}")
                                st.caption(f"🏢 Registrar: {whois.get('registrar', 'N/A')}")
                        
                        # 3. CERTIFICADO SSL
                        with st.expander("🔒 Certificado SSL/TLS", expanded=True):
                            ssl_info = res.get("ssl", {})
                            ssl_valid = ssl_info.get("valid", False)
                            ssl_error = ssl_info.get("error")
                            
                            if ssl_error:
                                # Verifica se é timeout - não é erro grave
                                if "timeout" in ssl_error.lower():
                                    st.warning(f"⚠️ **ATENÇÃO** — {ssl_error}")
                                    st.caption("⏱️ Servidor SSL demorou muito para responder")
                                elif "porta 443 fechada" in ssl_error.lower() or "não possui https" in ssl_error.lower():
                                    st.warning(f"⚠️ **SEM HTTPS** — {ssl_error}")
                                    st.caption("🔓 Site só funciona em HTTP (não criptografado)")
                                else:
                                    st.error(f"❌ **FALHOU** — {ssl_error}")
                            elif not ssl_valid:
                                st.error("❌ **FALHOU** — Certificado SSL inválido ou ausente")
                            else:
                                if ssl_info.get("expired"):
                                    st.error("❌ **FALHOU** — Certificado expirado")
                                elif ssl_info.get("hostname_matches") is False:
                                    st.warning("⚠️ **AVISO** — Hostname não coincide com certificado")
                                else:
                                    st.success("✅ **PASSOU** — Certificado SSL válido")
                                
                                if ssl_info.get("issuer"):
                                    st.caption(f"🏛️ Emissor: {ssl_info.get('issuer')}")
                                if ssl_info.get("notAfter"):
                                    st.caption(f"⏰ Válido até: {ssl_info.get('notAfter')}")
                        
                        # 4. DNS DINÂMICO
                        with st.expander("🌍 DNS Dinâmico", expanded=False):
                            if res.get("dynamic_dns"):
                                st.warning("⚠️ **SUSPEITO** — Usa serviço de DNS dinâmico (no-ip, dyndns)")
                            else:
                                st.success("✅ **PASSOU** — Não usa DNS dinâmico conhecido")
                        
                        # 5. REDIRECIONAMENTOS
                        with st.expander("🔀 Redirecionamentos", expanded=False):
                            redirects = res.get("redirect_chain", [])
                            if len(redirects) > 1:
                                st.warning(f"⚠️ **DETECTADO** — {len(redirects)-1} redirecionamento(s)")
                                for i, redir in enumerate(redirects):
                                    st.caption(f"{i+1}. {redir}")
                            else:
                                st.success("✅ **PASSOU** — Sem redirecionamentos")
                        
                        # 6. SIMILARIDADE COM MARCAS
                        with st.expander("🏷️ Similaridade com Marcas (Typosquatting)", expanded=False):
                            lev = res.get("levenshtein", [])
                            if lev and lev[0]["similarity"] > 0.8 and lev[0]["brand"] not in res["domain"]:
                                st.error(f"❌ **SUSPEITO** — Similar a '{lev[0]['brand']}' ({lev[0]['similarity']*100:.1f}% similar)")
                                for brand_info in lev[:3]:
                                    st.caption(f"• {brand_info['brand']}: {brand_info['similarity']*100:.1f}%")
                            else:
                                st.success("✅ **PASSOU** — Sem similaridade suspeita com marcas")
                                if lev:
                                    st.caption("Top 3 similaridades:")
                                    for brand_info in lev[:3]:
                                        st.caption(f"• {brand_info['brand']}: {brand_info['similarity']*100:.1f}%")
                        
                        # 7. FORMULÁRIOS E CAMPOS SENSÍVEIS
                        with st.expander("📝 Formulários e Dados Sensíveis", expanded=False):
                            forms = res.get("forms", [])
                            if not forms:
                                st.info("ℹ️ **INFO** — Nenhum formulário detectado")
                            else:
                                has_password = any(f.get("has_password") for f in forms)
                                has_sensitive = any(f.get("sensitive_names") for f in forms)
                                
                                if has_password or has_sensitive:
                                    st.warning(f"⚠️ **DETECTADO** — {len(forms)} formulário(s) com campos sensíveis")
                                    for i, form in enumerate(forms):
                                        if form.get("has_password"):
                                            st.caption(f"• Formulário {i+1}: Campo de senha detectado")
                                        if form.get("sensitive_names"):
                                            st.caption(f"• Formulário {i+1}: Campos sensíveis (CPF, cartão, etc)")
                                else:
                                    st.info(f"ℹ️ **INFO** — {len(forms)} formulário(s) sem campos sensíveis")
                        
                        # 8. PADRÕES BÁSICOS SUSPEITOS
                        with st.expander("🔍 Padrões Básicos Suspeitos", expanded=False):
                            basic = res.get("basic_patterns", {})
                            flags = res.get("flags", [])
                            suspicious_flags = [f for f in flags if f in ["many_subdomains", "special_chars_in_domain", "numbers_in_place_of_letters"]]
                            
                            if suspicious_flags:
                                st.warning(f"⚠️ **DETECTADO** — {len(suspicious_flags)} padrão(ões) suspeito(s)")
                                if "many_subdomains" in flags:
                                    st.caption(f"• Excesso de subdomínios ({basic.get('num_subdomains', 0)})")
                                if "special_chars_in_domain" in flags:
                                    st.caption("• Caracteres especiais no domínio")
                                if "numbers_in_place_of_letters" in flags:
                                    st.caption(f"• Números substituindo letras ({basic.get('num_leet_chars', 0)} ocorrências)")
                            else:
                                st.success("✅ **PASSOU** — Sem padrões básicos suspeitos")

                        # Relatório completo com download
                        st.markdown("---")
                        st.subheader("📄 Relatório Detalhado")
                        
                        report_text = build_standard_report(res)
                        
                        # Botões de download lado a lado
                        col_d1, col_d2, col_d3 = st.columns(3)
                        with col_d1:
                            st.download_button(
                                "📥 Baixar Relatório (TXT)",
                                data=report_text.encode("utf-8"),
                                file_name=f"phishdetect_relatorio_{res['domain'].replace('.', '_')}.txt",
                                mime="text/plain",
                                use_container_width=True
                            )
                        with col_d2:
                            st.download_button(
                                "📥 Baixar Dados (JSON)",
                                data=json.dumps(res, indent=2, ensure_ascii=False).encode("utf-8"),
                                file_name=f"phishdetect_dados_{res['domain'].replace('.', '_')}.json",
                                mime="application/json",
                                use_container_width=True
                            )
                        with col_d3:
                            # Botão para expandir relatório
                            if st.button("👁️ Ver Relatório Completo", use_container_width=True):
                                st.text_area("Relatório Completo", report_text, height=400)
                        
                        # JSON expandível
                        with st.expander("🔧 Ver JSON Técnico (Debug)", expanded=False):
                            st.json(res)

                    else:
                        st.error(f"Erro do backend: {r.status_code} {r.text}")
                except Exception as e:
                    st.error(f"Erro: {e}")

    # ---------------------------------------------------------------------
    # ABA 2: HISTÓRICO
    # ---------------------------------------------------------------------
    with tab2:
        st.markdown("### 📊 Histórico de Análises")

        if df.empty:
            st.info("Nenhuma análise registrada ainda. Faça uma análise na aba 'Nova Análise'.")
        else:
            # Estatísticas gerais
            st.markdown("#### 📈 Estatísticas Gerais")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total de Análises", len(df))
            with col2:
                avg_score = df["score"].mean()
                st.metric("Score Médio", f"{avg_score:.1f}/100")
            with col3:
                high_risk = len(df[df["score"] >= 70])
                st.metric("Alto Risco", high_risk)
            with col4:
                low_risk = len(df[df["score"] < 40])
                st.metric("Baixo Risco", low_risk)
            
            st.markdown("---")
            
            # Tabela de todas as análises
            st.markdown("#### 📋 Todas as Análises")
            st.dataframe(
                df[["id", "url", "domain", "score", "ts"]],
                use_container_width=True,
                hide_index=True
            )

            # Exportar CSV completo
            st.markdown("---")
            st.markdown("#### 💾 Exportar Dados")
            csv = df.to_csv(index=False)
            st.download_button(
                "📥 Baixar Histórico Completo (CSV)",
                csv,
                file_name="phishdetect_historico_completo.csv",
                mime="text/csv",
                use_container_width=True
            )

            # Distribuição global de características suspeitas
            st.markdown("---")
            st.markdown("#### 📊 Distribuição Global de Características Suspeitas")
            df_flags = df.copy()
            df_flags["flags"] = df_flags["flags"].apply(
                lambda x: json.loads(x) if isinstance(x, str) and x.strip() else []
            )
            df_exploded = df_flags.explode("flags")
            df_exploded = df_exploded[
                df_exploded["flags"].notna() & (df_exploded["flags"] != "")
            ]

            if not df_exploded.empty:
                counts = (
                    df_exploded["flags"]
                    .value_counts()
                    .rename_axis("flag")
                    .reset_index(name="quantidade")
                )

                col_chart1, col_chart2 = st.columns([2, 1])
                with col_chart1:
                    st.bar_chart(counts.set_index("flag"), height=400)
                with col_chart2:
                    st.dataframe(counts, use_container_width=True, hide_index=True)
            else:
                st.info("Nenhuma característica suspeita detectada no histórico ainda.")

    # ---------------------------------------------------------------------
    # ABA 3: RELATÓRIOS DETALHADOS
    # ---------------------------------------------------------------------
    with tab3:
        st.markdown("### 📄 Relatórios Detalhados por ID")

        if df.empty:
            st.info("Nenhuma análise registrada ainda. Faça uma análise na aba 'Nova Análise'.")
        else:
            # Selecionar ID
            st.markdown("#### 🔎 Selecione uma análise para visualizar o relatório completo")
            
            col_select1, col_select2 = st.columns([3, 1])
            with col_select1:
                id_list = df["id"].tolist()
                selected_id = st.selectbox(
                    "ID da Análise", 
                    id_list,
                    format_func=lambda x: f"ID {x} - {df[df['id']==x]['domain'].values[0]} (Score: {df[df['id']==x]['score'].values[0]})"
                )
            
            with col_select2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🔄 Atualizar Lista", use_container_width=True):
                    st.rerun()

            row = df[df["id"] == selected_id].iloc[0]
            raw = json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"]
            flags_single = (
                json.loads(row["flags"])
                if isinstance(row["flags"], str) and row["flags"].strip()
                else []
            )

            st.markdown("---")
            
            # Resumo em cards
            st.markdown(f"#### 📊 Resumo da Análise #{selected_id}")
            col_a, col_b, col_c, col_d = st.columns(4)
            
            score_val = row['score']
            if score_val >= 70:
                score_color = "🔴"
                risk_text = "Alto Risco"
            elif score_val >= 40:
                score_color = "🟡"
                risk_text = "Risco Moderado"
            else:
                score_color = "🟢"
                risk_text = "Baixo Risco"
            
            with col_a:
                st.metric(f"{score_color} Score", f"{score_val}/100")
            with col_b:
                st.metric("🌐 Domínio", raw.get("domain", row["domain"]))
            with col_c:
                st.metric("🚩 Flags", len(flags_single) if flags_single else 0)
            with col_d:
                st.metric("📅 Data", row["ts"][:10] if len(row["ts"]) >= 10 else row["ts"])

            st.info(f"**Classificação:** {risk_text}")

            # Flags detectadas
            if flags_single:
                st.markdown("---")
                st.markdown("#### 🚩 Características Suspeitas Detectadas")
                
                flag_explanations = {
                    "blacklist": "🛡️ Domínio em lista de sites maliciosos",
                    "young_domain": "📅 Domínio muito recente",
                    "ssl_invalid": "🔒 Problema no certificado SSL",
                    "ssl_expired": "⏰ Certificado SSL expirado",
                    "ssl_hostname_mismatch": "⚠️ Nome do certificado não coincide",
                    "redirects": "🔀 Redirecionamentos detectados",
                    "form_with_password": "🔐 Formulário com senha",
                    "similar_to_brand": "🏷️ Similar a marca conhecida",
                    "many_subdomains": "🌐 Excesso de subdomínios",
                    "special_chars_in_domain": "❓ Caracteres especiais",
                    "numbers_in_place_of_letters": "🔢 Números no lugar de letras",
                    "dynamic_dns": "🌍 DNS dinâmico"
                }
                
                for flag in flags_single:
                    st.warning(f"**{flag}**: {flag_explanations.get(flag, 'Flag detectada')}")
                
                # Gráfico de flags
                df_flags_single = pd.DataFrame(
                    {"flag": flags_single, "valor": [1] * len(flags_single)}
                )
                st.bar_chart(df_flags_single.set_index("flag"), height=300)
            else:
                st.success("✅ Nenhuma característica suspeita detectada")

            # JSON técnico
            st.markdown("---")
            with st.expander("🔧 Ver JSON Técnico Completo"):
                st.json(raw)

            # Relatório padronizado
            st.markdown("---")
            st.markdown(f"#### 📄 Relatório Padronizado")
            report_id_text = build_standard_report(raw)
            
            # Botões de download
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.download_button(
                    "📥 Baixar Relatório (TXT)",
                    data=report_id_text.encode("utf-8"),
                    file_name=f"phishdetect_relatorio_id_{selected_id}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
            with col_d2:
                st.download_button(
                    "📥 Baixar Dados (JSON)",
                    data=json.dumps(raw, indent=2, ensure_ascii=False).encode("utf-8"),
                    file_name=f"phishdetect_dados_id_{selected_id}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            # Preview do relatório
            with st.expander("👁️ Visualizar Relatório Completo"):
                st.text_area("Relatório", report_id_text, height=500)


if __name__ == "__main__":
    main()
