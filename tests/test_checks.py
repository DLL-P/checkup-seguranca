import socket

import pytest

from app import intel
from app.checks import breach_check, ip_exposure, leaked_secrets
from app.checks.base import Status


@pytest.fixture
def no_active_scan(monkeypatch):
    """Garante que nenhuma conexão é aberta com o servidor analisado."""
    def boom(*args, **kwargs):
        raise AssertionError("varredura ativa não é permitida")
    monkeypatch.setattr(socket, "create_connection", boom)


@pytest.fixture
def public_ip(monkeypatch):
    monkeypatch.setattr(ip_exposure, "_resolve", lambda d: "8.8.8.8")


def kev(cve, ransomware=False):
    return intel.KevEntry(cve=cve, name="x", vendor="v", product="p", date_added="2026-01-01", ransomware=ransomware)


def test_exposicao_passiva_com_rdp_e_falha_de_ransomware(monkeypatch, no_active_scan, public_ip):
    monkeypatch.setattr(intel, "host_intel", lambda ip: intel.HostIntel(ip=ip, ports=[443, 3389], vulns=["CVE-1", "CVE-2"], cpes=[]))
    monkeypatch.setattr(intel, "load_kev", lambda: {"CVE-2": kev("CVE-2", ransomware=True)})
    monkeypatch.setattr(intel, "epss_scores", lambda cves: {"CVE-1": 0.02, "CVE-2": 0.97})

    results = {r.check_id: r for r in ip_exposure.run("exemplo.com.br")}
    assert results["exposed_ports"].status == Status.CRITICAL
    assert "3389" in results["exposed_ports"].details[0]

    vulns = results["known_vulns"]
    assert vulns.status == Status.CRITICAL
    assert vulns.rule_key == "known_vulns:ransomware"
    assert "ransomware" in vulns.message
    # a lista exata de CVEs é só para o dono; o público vê só a contagem
    assert vulns.private_details[0].startswith("CVE-2")
    assert not any("CVE-" in d for d in vulns.details)


def test_falha_com_epss_alto_sem_kev(monkeypatch, no_active_scan, public_ip):
    monkeypatch.setattr(intel, "host_intel", lambda ip: intel.HostIntel(ip=ip, ports=[443], vulns=["CVE-9"], cpes=[]))
    monkeypatch.setattr(intel, "load_kev", lambda: {})
    monkeypatch.setattr(intel, "epss_scores", lambda cves: {"CVE-9": 0.4})
    results = {r.check_id: r for r in ip_exposure.run("exemplo.com.br")}
    assert results["exposed_ports"].status == Status.OK
    assert results["known_vulns"].status == Status.WARNING
    assert results["known_vulns"].rule_key == "known_vulns:warning"


def test_falhas_sem_sinal_de_exploracao(monkeypatch, no_active_scan, public_ip):
    monkeypatch.setattr(intel, "host_intel", lambda ip: intel.HostIntel(ip=ip, ports=[22], vulns=["CVE-9"], cpes=[]))
    monkeypatch.setattr(intel, "load_kev", lambda: {})
    monkeypatch.setattr(intel, "epss_scores", lambda cves: {"CVE-9": 0.001})
    results = {r.check_id: r for r in ip_exposure.run("exemplo.com.br")}
    assert results["exposed_ports"].status == Status.WARNING  # SSH
    assert results["known_vulns"].rule_key == "known_vulns:low"


def test_ip_sem_registro_no_internetdb(monkeypatch, no_active_scan, public_ip):
    monkeypatch.setattr(intel, "host_intel", lambda ip: None)
    results = {r.check_id: r for r in ip_exposure.run("exemplo.com.br")}
    assert results["exposed_ports"].status == Status.OK
    assert "known_vulns" not in results


def test_internetdb_fora_do_ar(monkeypatch, no_active_scan, public_ip):
    def fail(ip):
        raise ConnectionError("fora do ar")
    monkeypatch.setattr(intel, "host_intel", fail)
    results = {r.check_id: r for r in ip_exposure.run("exemplo.com.br")}
    assert results["exposed_ports"].status == Status.UNKNOWN


def test_ip_privado_nao_e_consultado(monkeypatch, no_active_scan):
    monkeypatch.setattr(ip_exposure, "_resolve", lambda d: "10.0.0.5")
    monkeypatch.setattr(intel, "host_intel", lambda ip: pytest.fail("não deveria consultar IP privado"))
    results = ip_exposure.run("interno.exemplo.com.br")
    assert results[0].status == Status.UNKNOWN


def test_enrich_ordena_pela_urgencia(monkeypatch):
    monkeypatch.setattr(intel, "load_kev", lambda: {"CVE-B": kev("CVE-B"), "CVE-C": kev("CVE-C", ransomware=True)})
    monkeypatch.setattr(intel, "epss_scores", lambda cves: {"CVE-A": 0.99, "CVE-B": 0.1, "CVE-C": 0.05})
    assert [v.cve for v in intel.enrich(["CVE-A", "CVE-B", "CVE-C"])] == ["CVE-C", "CVE-B", "CVE-A"]


def test_parse_kev():
    entries = intel._parse_kev({"vulnerabilities": [
        {"cveID": "CVE-1", "knownRansomwareCampaignUse": "Known", "dateAdded": "2026-01-01"},
        {"cveID": "CVE-2", "knownRansomwareCampaignUse": "Unknown"},
    ]})
    assert entries["CVE-1"].ransomware and not entries["CVE-2"].ransomware


class FakeResp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


def test_vazamentos_lista_so_para_o_dono(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "x")
    monkeypatch.setattr(breach_check.requests, "get", lambda *a, **k: FakeResp(200, {"joao": ["X"], "maria": ["Y"]}))
    [res] = breach_check.run("exemplo.com.br")
    assert res.status == Status.CRITICAL
    assert res.details == []
    assert res.private_details == ["joao@exemplo.com.br", "maria@exemplo.com.br"]
    assert "2 conta(s)" in res.message


def test_vazamentos_dominio_nao_verificado_no_hibp(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "x")
    monkeypatch.setattr(breach_check.requests, "get", lambda *a, **k: FakeResp(403))
    [res] = breach_check.run("exemplo.com.br")
    assert res.status == Status.UNKNOWN


def test_chaves_vazadas_urls_so_para_o_dono(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    payload = {"total_count": 1, "items": [{"html_url": "https://github.com/alguem/repo/blob/main/.env"}]}
    monkeypatch.setattr(leaked_secrets.requests, "get", lambda *a, **k: FakeResp(200, payload))
    [res] = leaked_secrets.run("exemplo.com.br")
    assert res.status == Status.WARNING
    assert res.details == []
    assert res.private_details == ["https://github.com/alguem/repo/blob/main/.env"]


def test_dns_fora_do_ar_nao_vira_alerta_falso(monkeypatch):
    import dns.exception
    import dns.resolver

    from app import verification
    from app.checks import domain_dns

    def timeout(*a, **k):
        raise dns.exception.Timeout()
    monkeypatch.setattr(dns.resolver, "resolve", timeout)
    assert domain_dns.check_spf("e.com.br").status == Status.UNKNOWN
    assert domain_dns.check_dmarc("e.com.br").status == Status.UNKNOWN
    assert domain_dns.check_dkim("e.com.br").status == Status.UNKNOWN
    assert verification.dns_proves_domain("e.com.br", "abc") is False


def test_registro_inexistente_continua_critico(monkeypatch):
    import dns.resolver

    from app.checks import domain_dns

    def nx(*a, **k):
        raise dns.resolver.NXDOMAIN()
    monkeypatch.setattr(dns.resolver, "resolve", nx)
    assert domain_dns.check_spf("e.com.br").status == Status.CRITICAL
    assert domain_dns.check_dmarc("e.com.br").status == Status.CRITICAL
    assert domain_dns.check_dkim("e.com.br").status == Status.WARNING
