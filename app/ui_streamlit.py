# app/ui_streamlit.py
import streamlit as st
import requests
import pandas as pd
import json

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
    st.set_page_config(layout="wide", page_title="PhishDetect")
    st.title("PhishDetect")

    init_db()
    df = read_history()

    # Abas
    tab1, tab2 = st.tabs(["Nova análise", "Histórico & Relatórios"])

    # ---------------------------------------------------------------------
    # ABA 1: NOVA ANÁLISE
    # ---------------------------------------------------------------------
    with tab1:
        st.subheader("Nova análise de URL")

        with st.form("analyze_form"):
            url = st.text_input("URL para verificar", value="")
            submitted = st.form_submit_button("Analisar")

        if submitted and url:
            st.info("Enviando requisição ao backend...")
            try:
                r = requests.post(API_URL, json={"url": url}, timeout=20)
                if r.status_code == 200:
                    res = r.json()
                    st.success(f"Análise concluída — score {res['score']}/100")

                    # Resumo rápido em métricas
                    st.subheader("Resumo da análise atual")
                    cols = st.columns(3)
                    cols[0].metric("Score", f"{res['score']}/100")
                    cols[1].metric("Domínio", res["domain"])
                    cols[2].metric(
                        "Flags",
                        ", ".join(res["flags"]) if res["flags"] else "Nenhuma flag suspeita",
                    )

                    st.subheader("Detalhes (JSON) da análise atual")
                    st.json(res)

                    st.markdown("**Interpretação rápida:**")
                    if res["score"] >= 70:
                        st.warning("Alto risco — evite acesso e investigue mais.")
                    elif res["score"] >= 40:
                        st.info("Risco moderado — avaliar com cuidado.")
                    else:
                        st.success("Risco baixo nas heurísticas aplicadas.")

                    # Relatório padronizado
                    st.subheader("Relatório (análise atual)")
                    report_text = build_standard_report(res)
                    st.text(report_text)

                    st.download_button(
                        "Baixar relatório desta análise (TXT)",
                        data=report_text.encode("utf-8"),
                        file_name="relatorio_phishdetect_atual.txt",
                        mime="text/plain",
                    )

                else:
                    st.error(f"Erro do backend: {r.status_code} {r.text}")
            except Exception as e:
                st.error(f"Erro: {e}")

    # ---------------------------------------------------------------------
    # ABA 2: HISTÓRICO & RELATÓRIOS
    # ---------------------------------------------------------------------
    with tab2:
        st.subheader("Histórico de análises")

        if df.empty:
            st.info("Nenhuma análise registrada ainda. Faça uma análise na aba 'Nova análise'.")
        else:
            # Tabela geral
            st.dataframe(df[["id", "url", "domain", "score", "ts"]])

            # Selecionar ID
            st.markdown("### Detalhar uma análise específica (por ID)")
            id_list = df["id"].tolist()
            selected_id = st.selectbox("Selecione o ID da análise", id_list)

            row = df[df["id"] == selected_id].iloc[0]
            raw = json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"]
            flags_single = (
                json.loads(row["flags"])
                if isinstance(row["flags"], str) and row["flags"].strip()
                else []
            )

            st.subheader(f"Resumo da análise ID {selected_id}")
            col_a, col_b, col_c = st.columns(3)
            col_a.metric("Score", f"{row['score']}/100")
            col_b.metric("Domínio", raw.get("domain", row["domain"]))
            col_c.metric("Qtd. Flags", len(flags_single) if flags_single else 0)

            st.subheader("JSON completo da análise selecionada")
            st.json(raw)

            # Relatório padronizado do ID
            st.subheader(f"Relatório padronizado (ID {selected_id})")
            report_id_text = build_standard_report(raw)
            st.text(report_id_text)

            st.download_button(
                f"Baixar relatório do ID {selected_id} (TXT)",
                data=report_id_text.encode("utf-8"),
                file_name=f"relatorio_phishdetect_id_{selected_id}.txt",
                mime="text/plain",
            )

            # Gráfico de flags por ID
            st.markdown("### Características suspeitas desta URL (por ID)")
            if flags_single:
                df_flags_single = pd.DataFrame(
                    {"flag": flags_single, "valor": [1] * len(flags_single)}
                )
                df_flags_single = (
                    df_flags_single.groupby("flag")["valor"].sum().reset_index()
                )
                st.dataframe(df_flags_single)
                st.bar_chart(df_flags_single.set_index("flag"))
            else:
                st.info("Nenhuma característica suspeita foi marcada para esta URL (sem flags).")

            # Exportar CSV completo
            st.markdown("### Exportar histórico completo")
            csv = df.to_csv(index=False)
            st.download_button(
                "Baixar CSV do histórico",
                csv,
                file_name="phish_history.csv",
                mime="text/csv",
            )

            # Distribuição global de características suspeitas
            st.markdown("### Distribuição global de características suspeitas")
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

                st.dataframe(counts)
                st.bar_chart(counts.set_index("flag"))
            else:
                st.info(
                    "Ainda não há características suspeitas suficientes no histórico para gerar a distribuição global."
                )


if __name__ == "__main__":
    main()
