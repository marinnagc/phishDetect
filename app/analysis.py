# app/analysis.py
import requests
import socket
import ssl
import whois
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from rapidfuzz.distance import Levenshtein
import datetime
import dns.resolver
import validators
import logging
import re

logging.basicConfig(level=logging.INFO)
BRAND_LIST = [
    "insper.edu.br",
    "nubank.com.br",
    "itau.com.br",
    "bb.com.br",
    "bradesco.com.br",
    "google.com",
]

SHORTENERS = ["bit.ly","tinyurl.com","t.co","u.nu","goo.gl"]
# Domínios de exemplo para simular uma blacklist local (para a prova).
# Em cenário real, integraria com PhishTank / OpenPhish.
KNOWN_BAD_DOMAINS = {
    "phishing-example.com",
    "malicious-login.net",
    "fake-bank-secure.com",
}

# Provedores de DNS dinâmico (exemplos)
DYNAMIC_DNS_PROVIDERS = [
    "no-ip.com",
    "dyndns.org",
    "duckdns.org",
    "hopto.org",
    "zapto.org",
]
def detect_basic_suspicious_patterns(domain: str):
    """
    Detecta características básicas suspeitas:
    - números substituindo letras (leet)
    - uso excessivo de subdomínios
    - caracteres especiais na URL
    Retorna (flags, info_dict)
    """
    flags = []
    info = {}

    host = domain.split("@")[-1]  # remove credenciais se houver
    host = host.lower()

    # 1) Uso excessivo de subdomínios
    labels = host.split(".")
    num_subdomains = max(len(labels) - 2, 0)  # desconsidera TLD + domínio principal
    info["num_subdomains"] = num_subdomains
    if num_subdomains >= 3:  # definir "excessivo" >= 3 subdomínios
        flags.append("many_subdomains")

    # 2) caracteres especiais na URL (hífens, punycode, etc.)
    if "-" in host or "xn--" in host or re.search(r"[^a-z0-9\.\-]", host):
        flags.append("special_chars_in_domain")

    # 3) números substituindo letras (leet)
    # mapeamento simples de alguns padrões comuns, só pra heurística
    leet_map = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"}
    num_leet = sum(ch in leet_map for ch in host)
    info["num_leet_chars"] = num_leet
    if num_leet >= 2:
        flags.append("numbers_in_place_of_letters")

    return flags, info


def is_shortened(netloc):
    return any(s in netloc for s in SHORTENERS)

def expand_url(url, timeout=6):
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        return r.url
    except Exception:
        return url

import whois

def get_whois_info(domain: str):
    import whois
    import datetime
    try:
        w = whois.whois(domain)
        registrar = w.get("registrar")
        creation_date = w.get("creation_date")
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Calcula idade se possível
        age_days = None
        if creation_date:
            if isinstance(creation_date, datetime.datetime):
                creation_date_str = creation_date.strftime("%Y-%m-%d %H:%M:%S")
                creation_date = creation_date_str
            else:
                creation_date_str = str(creation_date)
            try:
                dt = datetime.datetime.strptime(creation_date_str, "%Y-%m-%d %H:%M:%S")
                age_days = (datetime.datetime.utcnow() - dt).days
            except Exception:
                age_days = None
        else:
            creation_date_str = None

        return {
            "registrar": registrar,
            "creation_date": creation_date_str,  # <- sempre string
            "age_days": age_days,
            "error": None,
        }

    except Exception as e:
        return {
            "registrar": None,
            "creation_date": None,
            "age_days": None,
            "error": str(e),
        }



def get_domain_age_days(whois_info):
    try:
        creation = whois_info.get("creation_date")
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        if isinstance(creation, str):
            creation = pd.to_datetime(creation, errors='coerce')
        if hasattr(creation, "to_pydatetime"):
            creation = creation.to_pydatetime()
        delta = datetime.datetime.utcnow() - creation
        return delta.days
    except Exception:
        return None

def check_ssl(hostname, port=443, timeout=5):
    """
    Tenta obter o certificado SSL/TLS, checar expiração e coincidência de hostname.
    """
    result = {
        "valid": False,
        "issuer": None,
        "notAfter": None,
        "expired": None,
        "hostname_matches": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["issuer"] = cert.get("issuer")
                notAfter = cert.get("notAfter")
                result["notAfter"] = notAfter

                # Verificar expiração
                if notAfter:
                    try:
                        exp = datetime.datetime.strptime(
                            notAfter, "%b %d %H:%M:%S %Y %Z"
                        )
                        result["expired"] = exp < datetime.datetime.utcnow()
                    except Exception:
                        result["expired"] = None

                # Verificar se o hostname bate com o certificado
                try:
                    ssl.match_hostname(cert, hostname)
                    result["hostname_matches"] = True
                except Exception:
                    result["hostname_matches"] = False

                # Considera válido se conseguiu pegar o cert e não está claramente expirado
                if result["expired"] is False and result["hostname_matches"] is not False:
                    result["valid"] = True
                elif result["hostname_matches"] is False:
                    # não tratar mismatch simples (www vs sem www) como SSL inválido total
                    result["valid"] = True


    except Exception as e:
        result["error"] = str(e)

    return result


def domain_in_blacklist(domain: str) -> bool:
    """
    Simula verificação em listas como PhishTank/OpenPhish usando KNOWN_BAD_DOMAINS.
    Para a prova, isso demonstra a verificação básica exigida em Conceito C.
    """
    host = domain.lower().split("@")[-1]
    # Checa domínio inteiro e também o "registrable" (últimos 2 labels, ex: exemplo.com)
    labels = host.split(".")
    base = ".".join(labels[-2:]) if len(labels) >= 2 else host
    return host in KNOWN_BAD_DOMAINS or base in KNOWN_BAD_DOMAINS


def is_dynamic_dns(domain: str) -> bool:
    """
    Verifica se o domínio aparenta usar provedores de DNS dinâmico conhecidos.
    Ex.: no-ip, dyndns, etc. (lista simplificada para a prova).
    """
    host = domain.lower().split("@")[-1]
    return any(host.endswith(provider) for provider in DYNAMIC_DNS_PROVIDERS)


def get_redirection_chain(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=6, headers={"User-Agent":"PhishDetect/0.1"})
        chain = [resp.url for resp in r.history] + [r.url]
        return chain
    except Exception:
        return []

def detect_forms(html):
    try:
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        found = []
        for f in forms:
            inputs = f.find_all("input")
            has_password = any((inp.get("type") or "").lower()=="password" for inp in inputs)
            names = [ (inp.get("name") or "").lower() for inp in inputs ]
            sensitive = any(any(k in n for k in ["password","senha","card","cpf","ccnum","credit"]) for n in names)
            found.append({"has_password": has_password, "sensitive_names": sensitive, "num_inputs": len(inputs)})
        return found
    except Exception:
        return []

def dns_checks(domain):
    out = {}
    try:
        answers = dns.resolver.resolve(domain, 'A')
        out['A'] = [r.to_text() for r in answers]
    except Exception:
        out['A'] = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        out['MX'] = [r.to_text() for r in answers]
    except Exception:
        out['MX'] = []
    return out

def levenshtein_to_brands(domain):
    host = domain.lower()
    results = []
    for b in BRAND_LIST:
        # compute normalized similarity (0..1)
        score = Levenshtein.normalized_similarity(host, b)
        results.append({"brand": b, "similarity": round(float(score),3)})
    results_sorted = sorted(results, key=lambda x: x["similarity"], reverse=True)
    return results_sorted[:3]

def analyze_url(url: str):
    # validate
    if not validators.url(url):
        raise ValueError("URL inválida")

    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    # remove credentials if present
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    # expand if shortener
    if is_shortened(netloc):
        url = expand_url(url)
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()

    blacklisted = domain_in_blacklist(netloc)
    redirect_chain = get_redirection_chain(url)
    who = get_whois_info(netloc)
    age_days = get_domain_age_days(who)
    ssl_info = check_ssl(netloc)
    dns_info = dns_checks(netloc)

    # padrões básicos suspeitos (Conceito C)
    basic_flags, basic_info = detect_basic_suspicious_patterns(netloc)

    # DNS dinâmico (Conceito B)
    dynamic_dns = is_dynamic_dns(netloc)

    # fetch content (safe: only GET; limit size)
    content = ""
    try:
        r = requests.get(url, timeout=6, headers={"User-Agent":"PhishDetect/0.1"})
        content = r.text[:200000]
    except Exception:
        content = ""

    forms = detect_forms(content)
    lev = levenshtein_to_brands(netloc)

    # simple scoring (weights explained in report)
    score = 0
    flags = []

    if blacklisted:
        score += 100
        flags.append("blacklist")

    if age_days is None or (age_days is not None and age_days < 90):
        score += 30
        flags.append("young_domain")

    # SSL
    if not ssl_info.get("valid", False):
        score += 25
        flags.append("ssl_invalid")
    else:
        # se válido, mas expired True ou hostname_matches False, marca também
        if ssl_info.get("expired") is True:
            score += 15
            flags.append("ssl_expired")
        if ssl_info.get("hostname_matches") is False:
            score += 15
            flags.append("ssl_hostname_mismatch")

    if len(redirect_chain) > 1:
        score += 10
        flags.append("redirects")

    if any(f.get("has_password") for f in forms):
        score += 15
        flags.append("form_with_password")

    if lev and lev[0]["similarity"] > 0.8 and lev[0]["brand"] not in netloc:
        score += 20
        flags.append("similar_to_brand")

    # aplica flags básicos de Conceito C
    for f in basic_flags:
        if f not in flags:
            flags.append(f)
            score += 5  # peso pequeno para cada heurística básica

    # DNS dinâmico
    if dynamic_dns:
        flags.append("dynamic_dns")
        score += 10

    final_score = min(score, 100)

    return {
        "url": url,
        "domain": netloc,
        "blacklisted": blacklisted,
        "redirect_chain": redirect_chain,
        "whois": {
            "registrar": who.get("registrar") if isinstance(who, dict) else None,
            "creation_date": who.get("creation_date"),
            "age_days": age_days
        },
        "basic_patterns": basic_info,
        "ssl": ssl_info,
        "dns": dns_info,
        "dynamic_dns": dynamic_dns,
        "forms": forms,
        "levenshtein": lev,
        "score": final_score,
        "flags": flags,
        "raw": {
            "whois": who
        }
    }
