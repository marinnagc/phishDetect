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
import time

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

def expand_url(url, timeout=10):
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        return r.url
    except Exception as e:
        logging.warning(f"Erro ao expandir URL {url}: {e}")
        return url


def get_whois_info(domain: str, max_retries=2):
    """
    Obtém informações WHOIS do domínio com retry e melhor tratamento de erros.
    """
    import time
    
    for attempt in range(max_retries):
        try:
            # Define timeout através de socket (whois usa socket internamente)
            import socket
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(10)
            
            try:
                w = whois.whois(domain)
            finally:
                socket.setdefaulttimeout(original_timeout)
            
            # Extrai registrar
            registrar = w.get("registrar")
            if isinstance(registrar, list) and registrar:
                registrar = registrar[0]
            
            # Extrai creation_date
            creation_date = w.get("creation_date")
            if isinstance(creation_date, list) and creation_date:
                creation_date = creation_date[0]
            
            # Calcula idade se possível
            age_days = None
            creation_date_str = None
            
            if creation_date:
                # Converte para datetime se necessário
                if isinstance(creation_date, datetime.datetime):
                    dt = creation_date
                    creation_date_str = creation_date.strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(creation_date, str):
                    creation_date_str = creation_date
                    # Tenta parsear diferentes formatos de data
                    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y/%m/%d"]:
                        try:
                            dt = datetime.datetime.strptime(creation_date_str, fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        # Se nenhum formato funcionou, tenta com pandas
                        try:
                            dt = pd.to_datetime(creation_date_str).to_pydatetime()
                        except Exception:
                            dt = None
                else:
                    dt = None
                
                # Calcula idade em dias
                if dt:
                    # Remove timezone info para evitar erro de offset-naive vs offset-aware
                    if dt.tzinfo is not None:
                        dt = dt.replace(tzinfo=None)
                    age_days = (datetime.datetime.utcnow() - dt).days
            
            return {
                "registrar": registrar,
                "creation_date": creation_date_str,
                "age_days": age_days,
                "error": None,
            }
        
        except socket.timeout:
            if attempt < max_retries - 1:
                time.sleep(1)  # Aguarda antes de tentar novamente
                continue
            return {
                "registrar": None,
                "creation_date": None,
                "age_days": None,
                "error": "WHOIS timeout - servidor não respondeu",
            }
        
        except Exception as e:
            error_msg = str(e).lower()
            # Verifica se é um erro de whois específico (domínio não encontrado, etc)
            if any(x in error_msg for x in ['no match', 'not found', 'no whois', 'no data']):
                return {
                    "registrar": None,
                    "creation_date": None,
                    "age_days": None,
                    "error": f"WHOIS não disponível para este domínio: {str(e)}",
                }
            
            # Para outros erros, tenta novamente se ainda há tentativas
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            
            return {
                "registrar": None,
                "creation_date": None,
                "age_days": None,
                "error": f"Erro ao consultar WHOIS: {str(e)}",
            }
    
    # Se chegou aqui, todas as tentativas falharam
    return {
        "registrar": None,
        "creation_date": None,
        "age_days": None,
        "error": "WHOIS falhou após múltiplas tentativas",
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

def check_ssl(hostname, port=443, timeout=15, max_retries=1):
    """
    Tenta obter o certificado SSL/TLS de forma rápida.
    Se não conseguir em 15s, provavelmente o site não tem HTTPS.
    """
    result = {
        "valid": False,
        "issuer": None,
        "notAfter": None,
        "expired": None,
        "hostname_matches": None,
        "error": None,
    }
    
    # Primeiro tenta verificar se a porta está aberta
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 5s apenas para verificar se porta está aberta
        result_connect = sock.connect_ex((hostname, port))
        sock.close()
        
        if result_connect != 0:
            # Porta não está aberta - site não tem HTTPS
            result["error"] = "Site não possui HTTPS (porta 443 fechada)"
            logging.info(f"SSL port closed para {hostname}")
            return result
    except Exception as e:
        result["error"] = f"Não foi possível verificar HTTPS: {str(e)[:50]}"
        return result
    
    # Se chegou aqui, a porta está aberta - tenta pegar certificado
    for attempt in range(max_retries):
        try:
            # Configuração SSL - precisa de verify para pegar certificado
            ctx = ssl.create_default_context()
            
            # Socket com timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                sock.connect((hostname, port))
                
                # Tenta obter certificado
                cert = None
                try:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                except Exception as e1:
                    # Se falhar com verificação, tenta sem verificar mas ainda pega o cert
                    logging.info(f"Tentativa 1 falhou para {hostname}: {e1}, tentando sem verificação...")
                    ctx2 = ssl.create_default_context()
                    ctx2.check_hostname = False
                    ctx2.verify_mode = ssl.CERT_NONE
                    
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(timeout)
                    try:
                        sock2.connect((hostname, port))
                        with ctx2.wrap_socket(sock2, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert(binary_form=False)
                            if not cert:
                                # Tenta pegar de outra forma
                                cert = ssock.getpeercert()
                    except Exception as e2:
                        logging.warning(f"Erro ao obter certificado SSL de {hostname}: {e2}")
                        result["error"] = f"Erro SSL: {str(e2)[:100]}"
                        return result
                    finally:
                        sock2.close()
                
                if cert:
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
                    if result["expired"] is False:
                        result["valid"] = True
                    elif result["expired"] is None and result["hostname_matches"] is not False:
                        result["valid"] = True
                    
                    # Sucesso! Sai do loop de retry
                    return result
                else:
                    result["error"] = "Certificado SSL vazio ou inválido"
                    return result
            
            finally:
                sock.close()

        except socket.timeout:
            if attempt < max_retries - 1:
                time.sleep(0.5)
                continue
            # Timeout não é erro fatal - apenas aviso
            result["error"] = f"Verificação SSL não concluída (timeout {timeout}s) - não afeta pontuação"
            logging.warning(f"SSL timeout para {hostname}")
            return result
            
        except socket.gaierror as e:
            # Erro de DNS - não vale a pena fazer retry
            result["error"] = f"Erro de DNS: não foi possível resolver o hostname"
            logging.warning(f"DNS error para {hostname}: {e}")
            return result
            
        except ssl.SSLError as e:
            # Erro SSL específico - pode ser certificado auto-assinado, protocolo antigo, etc
            # Não considera erro fatal para análise
            result["error"] = f"Aviso SSL: {str(e)[:100]}"
            result["valid"] = False
            logging.warning(f"SSL error para {hostname}: {e}")
            return result
            
        except ConnectionRefusedError:
            result["error"] = f"Conexão recusada na porta {port} - servidor não aceita HTTPS"
            logging.warning(f"Connection refused para {hostname}:{port}")
            return result
            
        except Exception as e:
            error_msg = str(e).lower()
            # Se for timeout genérico, não tenta novamente (já tentamos)
            if 'timeout' in error_msg or 'timed out' in error_msg:
                result["error"] = f"Timeout ao conectar - servidor muito lento"
                logging.warning(f"Generic timeout para {hostname}")
            else:
                result["error"] = f"Erro ao verificar SSL: {str(e)}"
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue

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
        r = requests.get(url, allow_redirects=True, timeout=10, headers={"User-Agent":"PhishDetect/0.1"})
        chain = [resp.url for resp in r.history] + [r.url]
        return chain
    except Exception as e:
        logging.warning(f"Erro ao verificar redirecionamentos de {url}: {e}")
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
        r = requests.get(url, timeout=10, headers={"User-Agent":"PhishDetect/0.1"})
        content = r.text[:200000]
    except Exception as e:
        logging.warning(f"Erro ao buscar conteúdo de {url}: {e}")
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

    # SSL - penaliza qualquer problema incluindo timeout
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
