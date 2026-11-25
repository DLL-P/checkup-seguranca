"""Como a pessoa comprova que o domínio é dela.

Dois caminhos, do mais fácil para o mais técnico (pensando no dono de PME):

1. E-mail da empresa: se a pessoa entrou com joao@minhaempresa.com.br, o
   domínio minhaempresa.com.br (e os subdomínios dele) já fica comprovado —
   ela recebeu o link de entrada numa caixa de e-mail desse domínio.
   Provedores públicos (gmail.com, hotmail.com...) nunca contam: senão, quem
   tem um Gmail "comprovaria" o gmail.com.
2. Registro no DNS: para quem usa e-mail pessoal, um registro TXT
   `nebula-checkup=<código>` no domínio — o mesmo método do Google Search
   Console. Pode ser feito pelo responsável de TI ou pela hospedagem.
"""

import re
import secrets

from .checks.domain_dns import DnsUnavailable, _txt_records

TXT_PREFIX = "nebula-checkup="

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")

PUBLIC_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.com.br", "outlook.com", "outlook.com.br",
    "live.com", "live.com.br", "msn.com", "yahoo.com", "yahoo.com.br", "ymail.com", "icloud.com", "me.com",
    "mac.com", "uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br", "globo.com", "globomail.com",
    "r7.com", "protonmail.com", "proton.me", "pm.me", "gmx.com", "gmx.net", "aol.com", "zoho.com",
    "yandex.com", "mail.com", "tutanota.com", "tuta.io",
}


def clean_domain(raw: str) -> str | None:
    domain = (raw or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0].rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain if DOMAIN_RE.match(domain) else None


def new_token() -> str:
    return secrets.token_hex(12)


def txt_record_value(token: str) -> str:
    return f"{TXT_PREFIX}{token}"


def email_proves_domain(email: str, domain: str) -> bool:
    email_domain = email.rsplit("@", 1)[-1].lower()
    if email_domain in PUBLIC_EMAIL_DOMAINS:
        return False
    return domain == email_domain or domain.endswith("." + email_domain)


def dns_proves_domain(domain: str, token: str, lookup=_txt_records) -> bool:
    expected = txt_record_value(token)
    try:
        records = lookup(domain)
    except DnsUnavailable:
        return False
    return any(record.strip() == expected for record in records)
