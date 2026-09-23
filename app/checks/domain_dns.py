import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.resolver

from .base import CheckResult, Status

COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "dkim", "mandrill"]


def _txt_records(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        return ["".join(part.decode() if isinstance(part, bytes) else part for part in rec.strings) for rec in answers]
    except Exception:
        return []


def check_spf(domain: str) -> CheckResult:
    records = _txt_records(domain)
    spf = [r for r in records if r.startswith("v=spf1")]
    if not spf:
        return CheckResult(
            check_id="spf",
            title="Proteção contra falsificação de e-mail (SPF)",
            status=Status.CRITICAL,
            message="Seu domínio não tem um registro SPF configurado.",
            recommendation="Sem SPF, qualquer pessoa pode enviar e-mails se passando pelo seu domínio (golpe/phishing em nome da sua empresa). Configure um registro SPF no DNS — seu provedor de e-mail (Google Workspace, Microsoft 365, etc.) tem um guia pronto pra isso.",
        )
    return CheckResult(
        check_id="spf",
        title="Proteção contra falsificação de e-mail (SPF)",
        status=Status.OK,
        message="Registro SPF encontrado.",
        details=spf,
    )


def check_dmarc(domain: str) -> CheckResult:
    records = _txt_records(f"_dmarc.{domain}")
    dmarc = [r for r in records if r.startswith("v=DMARC1")]
    if not dmarc:
        return CheckResult(
            check_id="dmarc",
            title="Política anti-falsificação de e-mail (DMARC)",
            status=Status.CRITICAL,
            message="Seu domínio não tem uma política DMARC configurada.",
            recommendation="DMARC é o que de fato bloqueia e-mails falsos enviados em nome da sua empresa. Configure um registro DMARC no DNS (pode começar em modo 'monitoramento' antes de bloquear).",
        )
    policy = "desconhecida"
    for r in dmarc:
        if "p=reject" in r:
            policy = "reject (bloqueia)"
        elif "p=quarantine" in r:
            policy = "quarantine (quarentena)"
        elif "p=none" in r:
            policy = "none (só monitora, não bloqueia)"
    is_enforced = "reject" in policy or "quarantine" in policy
    status = Status.OK if is_enforced else Status.WARNING
    return CheckResult(
        check_id="dmarc",
        title="Política anti-falsificação de e-mail (DMARC)",
        status=status,
        message=f"DMARC configurado, política atual: {policy}.",
        recommendation="" if is_enforced else "Sua política DMARC está em modo monitoramento e não bloqueia e-mails falsos de fato. Considere evoluir para quarantine ou reject depois de confirmar que não vai barrar e-mails legítimos.",
        details=dmarc,
    )


def _has_active_dkim_key(records: list[str]) -> bool:
    for r in records:
        if "v=DKIM1" not in r:
            continue
        # "p=" vazio significa chave revogada/desativada, não uma chave DKIM válida.
        match = re.search(r"p=([^;]*)", r)
        if match and match.group(1).strip():
            return True
    return False


def check_dkim(domain: str) -> CheckResult:
    def _check_selector(selector: str) -> bool:
        return _has_active_dkim_key(_txt_records(f"{selector}._domainkey.{domain}"))

    with ThreadPoolExecutor(max_workers=len(COMMON_DKIM_SELECTORS)) as executor:
        has_key = executor.map(_check_selector, COMMON_DKIM_SELECTORS)
        found = [s for s, ok in zip(COMMON_DKIM_SELECTORS, has_key) if ok]
    if not found:
        return CheckResult(
            check_id="dkim",
            title="Assinatura de e-mail (DKIM)",
            status=Status.WARNING,
            message="Não encontramos um seletor DKIM comum configurado (o seletor exato é escolhido pelo seu provedor de e-mail, então isso pode ser um falso negativo).",
            recommendation="Confirme com seu provedor de e-mail (Google Workspace, Microsoft 365, etc.) se o DKIM está ativado — é uma das 3 proteções básicas contra falsificação de e-mail, junto com SPF e DMARC.",
        )
    return CheckResult(
        check_id="dkim",
        title="Assinatura de e-mail (DKIM)",
        status=Status.OK,
        message=f"Seletor(es) DKIM encontrado(s): {', '.join(found)}.",
    )


def check_ssl_certificate(domain: str) -> CheckResult:
    try:
        ctx = ssl.create_default_context()
        # Resolve só o primeiro endereço IPv4: socket.create_connection(domain, ...)
        # tenta CADA endereço (IPv4 e IPv6) retornado pelo DNS até um funcionar, e
        # em redes sem saída IPv6 cada tentativa falha só após o timeout inteiro —
        # multiplicando o tempo total por endereço testado.
        ip = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 0:
            status, msg = Status.CRITICAL, "O certificado de segurança (SSL) do seu site já expirou."
        elif days_left < 15:
            status, msg = Status.WARNING, f"O certificado de segurança (SSL) do seu site expira em {days_left} dia(s)."
        else:
            status, msg = Status.OK, f"Certificado de segurança (SSL) válido por mais {days_left} dias."
        return CheckResult(
            check_id="ssl_cert",
            title="Certificado de segurança do site (SSL/HTTPS)",
            status=status,
            message=msg,
            recommendation="" if status == Status.OK else "Renove o certificado SSL o quanto antes — sem ele, visitantes veem um alerta de 'site não seguro' e os dados trocados com seu site ficam vulneráveis a interceptação.",
        )
    except Exception:
        return CheckResult(
            check_id="ssl_cert",
            title="Certificado de segurança do site (SSL/HTTPS)",
            status=Status.UNKNOWN,
            message="Não conseguimos verificar o certificado SSL (o site pode estar fora do ar ou não usar HTTPS na porta padrão).",
            recommendation="Confirme se o seu site está no ar e configurado com HTTPS.",
        )


def run(domain: str) -> list[CheckResult]:
    return [check_spf(domain), check_dmarc(domain), check_dkim(domain), check_ssl_certificate(domain)]
