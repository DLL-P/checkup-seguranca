import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from .base import CheckResult, Status

# Portas mais visadas por ataques automatizados (ransomware, brute force, etc.)
RISKY_PORTS = {
    21: ("FTP", "Transferência de arquivos antiga e insegura, muito visada por invasores."),
    22: ("SSH", "Acesso remoto a servidor Linux — precisa estar bem protegido (chave, nunca senha padrão)."),
    23: ("Telnet", "Protocolo antigo e inseguro, não deveria estar exposto de jeito nenhum."),
    445: ("Compartilhamento de arquivos (SMB)", "Porta clássica usada por ransomware para se espalhar pela rede."),
    1433: ("Banco de dados (SQL Server)", "Banco de dados exposto diretamente à internet."),
    3306: ("Banco de dados (MySQL)", "Banco de dados exposto diretamente à internet."),
    3389: ("Área de Trabalho Remota (RDP)", "Uma das portas de entrada mais comuns para ataques de ransomware."),
    5432: ("Banco de dados (PostgreSQL)", "Banco de dados exposto diretamente à internet."),
}


def _resolve(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _is_scannable(ip: str) -> bool:
    """Recusa varrer endereços internos/privados — evita usar o serviço para
    sondar redes que não são o alvo pretendido (proteção contra SSRF)."""
    addr = ipaddress.ip_address(ip)
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast)


def _port_open(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def run(domain: str) -> list[CheckResult]:
    ip = _resolve(domain)
    if not ip:
        return [CheckResult(
            check_id="ip_resolution",
            title="Resolução do domínio",
            status=Status.UNKNOWN,
            message="Não conseguimos descobrir o endereço IP desse domínio. Confira se o endereço foi digitado corretamente.",
        )]

    if not _is_scannable(ip):
        return [CheckResult(
            check_id="ip_resolution",
            title="Endereço IP público",
            status=Status.UNKNOWN,
            message="Esse domínio aponta para um endereço interno/privado — não realizamos varredura de portas nesse caso.",
        )]

    results = [CheckResult(
        check_id="ip_resolution",
        title="Endereço IP público",
        status=Status.OK,
        message=f"Seu domínio aponta para o IP {ip}.",
    )]

    with ThreadPoolExecutor(max_workers=len(RISKY_PORTS)) as executor:
        is_open = executor.map(lambda item: _port_open(ip, item[0]), RISKY_PORTS.items())
        open_risky = [
            (port, name, why)
            for (port, (name, why)), open_ in zip(RISKY_PORTS.items(), is_open)
            if open_
        ]

    if open_risky:
        details = [f"Porta {port} — {name}: {why}" for port, name, why in open_risky]
        results.append(CheckResult(
            check_id="exposed_ports",
            title="Portas sensíveis expostas na internet",
            status=Status.CRITICAL,
            message=f"Encontramos {len(open_risky)} porta(s) sensível(is) aberta(s) direto na internet.",
            recommendation="Acesso remoto (RDP/SSH) e bancos de dados nunca deveriam estar abertos direto na internet. Restrinja o acesso com VPN ou firewall, permitindo só os IPs que realmente precisam entrar.",
            details=details,
        ))
    else:
        results.append(CheckResult(
            check_id="exposed_ports",
            title="Portas sensíveis expostas na internet",
            status=Status.OK,
            message="Não encontramos portas sensíveis abertas diretamente na internet (verificação básica, nem todas as portas existentes foram testadas).",
        ))
    return results
