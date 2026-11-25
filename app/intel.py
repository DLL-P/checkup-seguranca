"""Inteligência de ameaças de fontes abertas, usada para dizer ao dono do
negócio não só "existe uma falha" mas "essa falha está sendo usada por
criminosos AGORA".

Fontes (todas gratuitas, sem chave):
- CISA KEV (Known Exploited Vulnerabilities), licença CC0 1.0: falhas com
  exploração ativa confirmada, inclusive se já foram usadas em ransomware.
- EPSS (FIRST.org): probabilidade de uma falha ser explorada nos próximos 30
  dias. Uso gratuito, com crédito à FIRST.
- Shodan InternetDB: portas abertas e falhas conhecidas de um IP, a partir da
  varredura que a Shodan já faz da internet inteira. É PASSIVO: o diagnóstico
  não envia nenhum pacote ao servidor analisado. Uso gratuito não comercial.
"""

import json
import os
import threading
import time
from dataclasses import dataclass

import requests

from . import config

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

KEV_TTL_SECONDS = 12 * 3600
EPSS_BATCH = 50
USER_AGENT = "checkup-seguranca (diagnostico gratuito)"

ATTRIBUTION = [
    ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CC0 1.0"),
    ("EPSS (FIRST.org)", "https://www.first.org/epss/", "uso gratuito com crédito à FIRST"),
    ("Shodan InternetDB", "https://internetdb.shodan.io/", "uso gratuito não comercial"),
]


@dataclass
class KevEntry:
    cve: str
    name: str
    vendor: str
    product: str
    date_added: str
    ransomware: bool


@dataclass
class HostIntel:
    ip: str
    ports: list[int]
    vulns: list[str]
    cpes: list[str]


@dataclass
class VulnInfo:
    cve: str
    epss: float | None
    kev: KevEntry | None

    @property
    def in_kev(self) -> bool:
        return self.kev is not None

    @property
    def ransomware(self) -> bool:
        return bool(self.kev and self.kev.ransomware)


_kev_lock = threading.Lock()
_kev_cache: dict[str, KevEntry] | None = None
_kev_loaded_at = 0.0


def _kev_cache_file() -> str:
    return os.path.join(os.path.dirname(config.DATABASE_PATH) or ".", "kev.json")


def _parse_kev(payload: dict) -> dict[str, KevEntry]:
    entries = {}
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cveID")
        if not cve:
            continue
        entries[cve] = KevEntry(
            cve=cve,
            name=item.get("vulnerabilityName", ""),
            vendor=item.get("vendorProject", ""),
            product=item.get("product", ""),
            date_added=item.get("dateAdded", ""),
            ransomware=(item.get("knownRansomwareCampaignUse", "").lower() == "known"),
        )
    return entries


def load_kev(force: bool = False) -> dict[str, KevEntry]:
    """Catálogo KEV em memória, renovado a cada 12 h. Se a CISA estiver fora do
    ar, usa a última cópia gravada em disco; se não houver nenhuma, devolve
    vazio (o relatório continua, só sem o sinal de exploração ativa)."""
    global _kev_cache, _kev_loaded_at
    with _kev_lock:
        fresh = _kev_cache is not None and time.time() - _kev_loaded_at < KEV_TTL_SECONDS
        if fresh and not force:
            return _kev_cache
        try:
            resp = requests.get(KEV_URL, headers={"user-agent": USER_AGENT}, timeout=20)
            resp.raise_for_status()
            payload = resp.json()
            _kev_cache = _parse_kev(payload)
            _kev_loaded_at = time.time()
            try:
                path = _kev_cache_file()
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh)
            except OSError:
                pass
        except Exception:
            if _kev_cache is None:
                try:
                    with open(_kev_cache_file(), encoding="utf-8") as fh:
                        _kev_cache = _parse_kev(json.load(fh))
                except (OSError, ValueError):
                    _kev_cache = {}
                # tenta de novo em 30 min, não a cada requisição
                _kev_loaded_at = time.time() - KEV_TTL_SECONDS + 1800
        return _kev_cache


def epss_scores(cves: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i:i + EPSS_BATCH]
        try:
            resp = requests.get(
                EPSS_URL, params={"cve": ",".join(batch)}, headers={"user-agent": USER_AGENT}, timeout=15
            )
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                try:
                    scores[row["cve"]] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        except Exception:
            continue
    return scores


def host_intel(ip: str) -> HostIntel | None:
    """O que a Shodan já sabe do IP. None = sem informação (IP nunca visto ou
    sem nada exposto). Levanta exceção em falha de rede, para o chamador
    distinguir "nada exposto" de "não deu para verificar"."""
    resp = requests.get(INTERNETDB_URL.format(ip=ip), headers={"user-agent": USER_AGENT}, timeout=10)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()
    return HostIntel(
        ip=ip,
        ports=sorted(int(p) for p in data.get("ports", [])),
        vulns=sorted(set(data.get("vulns", []))),
        cpes=data.get("cpes", []),
    )


def enrich(cves: list[str]) -> list[VulnInfo]:
    """Cruza cada CVE com o KEV e o EPSS e ordena pela urgência real:
    primeiro as usadas em ransomware, depois as exploradas agora, depois a
    maior probabilidade de exploração."""
    if not cves:
        return []
    kev = load_kev()
    scores = epss_scores(cves)
    infos = [VulnInfo(cve=c, epss=scores.get(c), kev=kev.get(c)) for c in cves]
    infos.sort(key=lambda v: (not v.ransomware, not v.in_kev, -(v.epss or 0.0), v.cve))
    return infos
