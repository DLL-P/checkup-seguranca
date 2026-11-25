"""Exposição do servidor na internet, de forma PASSIVA.

Antes, esta checagem abria conexões nas portas do IP informado (varredura
ativa) — e qualquer pessoa podia apontar a ferramenta para o servidor de
terceiros. Agora ela consulta o Shodan InternetDB, que já varre a internet
inteira, e cruza as falhas encontradas com o catálogo KEV da CISA e o EPSS:
nenhum pacote sai daqui para o servidor analisado.
"""

import ipaddress
import socket

from .. import intel
from .base import CheckResult, Status

# Portas que nunca deveriam estar abertas direto na internet: são a porta de
# entrada mais comum de ransomware e vazamento de banco de dados.
CRITICAL_PORTS = {
    23: ("Telnet", "Protocolo antigo e sem criptografia, não deveria estar exposto de jeito nenhum."),
    139: ("Compartilhamento de arquivos (NetBIOS)", "Usado para espalhar ransomware pela rede."),
    445: ("Compartilhamento de arquivos (SMB)", "Porta clássica usada por ransomware para se espalhar pela rede."),
    1433: ("Banco de dados (SQL Server)", "Banco de dados exposto diretamente à internet."),
    3306: ("Banco de dados (MySQL)", "Banco de dados exposto diretamente à internet."),
    3389: ("Área de Trabalho Remota (RDP)", "Uma das portas de entrada mais comuns para ataques de ransomware."),
    5432: ("Banco de dados (PostgreSQL)", "Banco de dados exposto diretamente à internet."),
    5900: ("Acesso remoto de tela (VNC)", "Controle remoto da tela, muito visado por invasores."),
    6379: ("Banco de dados (Redis)", "Banco de dados que costuma ficar sem senha, exposto à internet."),
    9200: ("Banco de dados (Elasticsearch)", "Causa comum de vazamento de dados de clientes."),
    27017: ("Banco de dados (MongoDB)", "Causa comum de vazamento de dados de clientes."),
}

# Portas que podem estar abertas, mas precisam de cuidado.
ATTENTION_PORTS = {
    21: ("FTP", "Transferência de arquivos antiga e insegura, muito visada por invasores."),
    22: ("SSH", "Acesso remoto a servidor Linux — precisa estar bem protegido (chave, nunca senha padrão)."),
}

EPSS_HIGH = 0.10
MAX_LISTED_VULNS = 10


def _resolve(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_global


def _ports_result(ports: list[int]) -> CheckResult:
    critical = [(p, *CRITICAL_PORTS[p]) for p in ports if p in CRITICAL_PORTS]
    attention = [(p, *ATTENTION_PORTS[p]) for p in ports if p in ATTENTION_PORTS]
    details = [f"Porta {port} — {name}: {why}" for port, name, why in critical + attention]
    if critical:
        return CheckResult(
            check_id="exposed_ports",
            title="Portas sensíveis abertas na internet",
            status=Status.CRITICAL,
            message=f"Seu servidor tem {len(critical)} porta(s) perigosa(s) aberta(s) direto na internet, como acesso remoto ou banco de dados.",
            recommendation="Acesso remoto (RDP) e bancos de dados nunca deveriam estar abertos direto na internet. Feche essas portas no firewall ou deixe o acesso só por VPN. Se não sabe como, peça ao seu responsável de TI — é a correção mais importante desta lista.",
            details=details,
        )
    if attention:
        return CheckResult(
            check_id="exposed_ports",
            title="Portas sensíveis abertas na internet",
            status=Status.WARNING,
            message=f"Seu servidor tem {len(attention)} porta(s) de administração aberta(s) na internet (SSH ou FTP).",
            recommendation="Isso pode ser normal, mas só é seguro com senha forte ou chave de acesso, e de preferência liberado só para os IPs de quem administra o servidor.",
            details=details,
        )
    return CheckResult(
        check_id="exposed_ports",
        title="Portas sensíveis abertas na internet",
        status=Status.OK,
        message="Não encontramos portas perigosas abertas no seu servidor.",
        details=[f"Portas abertas conhecidas: {', '.join(map(str, ports))}"] if ports else [],
    )


def _describe(v: intel.VulnInfo) -> str:
    parts = [v.cve]
    if v.ransomware:
        parts.append("usada por grupos de ransomware")
    if v.in_kev:
        parts.append(f"sendo explorada agora (catálogo KEV da CISA desde {v.kev.date_added})")
    if v.epss is not None:
        parts.append(f"chance de ataque nos próximos 30 dias: {v.epss:.0%}")
    return " — ".join(parts)


def _vulns_result(cves: list[str]) -> CheckResult:
    title = "Falhas conhecidas nos programas do seu servidor"
    if not cves:
        return CheckResult(
            check_id="known_vulns",
            title=title,
            status=Status.OK,
            message="Não há falhas conhecidas registradas para as versões dos programas que o seu servidor mostra na internet.",
        )

    infos = intel.enrich(cves)
    ransomware = [v for v in infos if v.ransomware]
    exploited = [v for v in infos if v.in_kev]
    likely = [v for v in infos if not v.in_kev and (v.epss or 0) >= EPSS_HIGH]
    listed = [_describe(v) for v in infos[:MAX_LISTED_VULNS]]
    if len(infos) > MAX_LISTED_VULNS:
        listed.append(f"... e mais {len(infos) - MAX_LISTED_VULNS} falha(s) de menor urgência.")
    caveat = (
        "A versão é deduzida do que o servidor mostra na internet; se o seu fornecedor já aplicou a correção "
        "sem mudar o número da versão, pode ser falso alarme — confirme com quem cuida do servidor."
    )
    update_advice = (
        "Atualize os programas do servidor (ou peça ao seu responsável de TI/hospedagem) começando pelas falhas "
        "marcadas como exploradas agora. Comprove que o domínio é seu para ver a lista e encaminhar."
    )

    if exploited:
        rule = "known_vulns:ransomware" if ransomware else "known_vulns:critical"
        extra = f", {len(ransomware)} delas já usada(s) por grupos de ransomware" if ransomware else ""
        return CheckResult(
            check_id="known_vulns",
            title=title,
            status=Status.CRITICAL,
            message=f"Seu servidor usa programas com {len(exploited)} falha(s) que criminosos estão explorando agora{extra}.",
            recommendation=f"{update_advice} {caveat}",
            details=[f"{len(infos)} falha(s) conhecida(s) no total, {len(exploited)} com exploração ativa confirmada."],
            private_details=listed,
            rule=rule,
        )
    if likely:
        return CheckResult(
            check_id="known_vulns",
            title=title,
            status=Status.WARNING,
            message=f"Seu servidor usa programas com {len(likely)} falha(s) com alta chance de serem exploradas em breve.",
            recommendation=f"{update_advice} {caveat}",
            details=[f"{len(infos)} falha(s) conhecida(s) no total, nenhuma com exploração ativa confirmada ainda."],
            private_details=listed,
        )
    return CheckResult(
        check_id="known_vulns",
        title=title,
        status=Status.WARNING,
        message=f"Seu servidor usa programas com {len(infos)} falha(s) conhecida(s), sem sinal de que estejam sendo exploradas agora.",
        recommendation=f"Não é urgente, mas inclua a atualização do servidor na próxima manutenção. {caveat}",
        private_details=listed,
        rule="known_vulns:low",
    )


def run(domain: str) -> list[CheckResult]:
    ip = _resolve(domain)
    if not ip:
        return [CheckResult(
            check_id="ip_resolution",
            title="Resolução do domínio",
            status=Status.UNKNOWN,
            message="Não conseguimos descobrir o endereço IP desse domínio. Confira se o endereço foi digitado corretamente.",
        )]

    if not _is_public(ip):
        return [CheckResult(
            check_id="ip_resolution",
            title="Endereço IP público",
            status=Status.UNKNOWN,
            message="Esse domínio aponta para um endereço interno/privado — não há o que checar na internet.",
        )]

    results = [CheckResult(
        check_id="ip_resolution",
        title="Endereço IP público",
        status=Status.OK,
        message=f"Seu domínio aponta para o IP {ip}.",
    )]

    try:
        host = intel.host_intel(ip)
    except Exception:
        results.append(CheckResult(
            check_id="exposed_ports",
            title="Portas sensíveis abertas na internet",
            status=Status.UNKNOWN,
            message="Não foi possível consultar a exposição do servidor agora. Tente novamente mais tarde.",
        ))
        return results

    if host is None:
        results.append(CheckResult(
            check_id="exposed_ports",
            title="Portas sensíveis abertas na internet",
            status=Status.OK,
            message="Não há registro de portas abertas para o seu servidor nas varreduras públicas da internet.",
        ))
        return results

    results.append(_ports_result(host.ports))
    results.append(_vulns_result(host.vulns))
    return results
