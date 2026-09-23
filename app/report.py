from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .checks import (
    breach_check,
    cnpj_status,
    domain_dns,
    ip_exposure,
    leaked_secrets,
    phone_breach_check,
    phone_reputation,
    typosquat,
)
from .checks.base import CheckResult, STATUS_WEIGHT

DOMAIN_CHECK_MODULES = [domain_dns, ip_exposure, breach_check, leaked_secrets, typosquat]


@dataclass
class Report:
    domain: str
    score: int
    results: list[CheckResult]


def _score(results: list[CheckResult]) -> int:
    if not results:
        return 10
    penalty = sum(STATUS_WEIGHT[r.status] for r in results)
    max_penalty = len(results) * 3
    score = round(10 * (1 - penalty / max_penalty))
    return max(0, min(10, score))


def run_all_checks(
    domain: str,
    cnpj: str | None = None,
    own_phone: str | None = None,
    suspicious_phone: str | None = None,
) -> Report:
    results: list[CheckResult] = []
    # executor.submit avalia os argumentos na hora da chamada (não preguiçosamente
    # como um lambda capturando a variável do loop), então cada job roda o módulo certo.
    jobs = [(module.run, domain) for module in DOMAIN_CHECK_MODULES]
    jobs.append((cnpj_status.run, cnpj))
    jobs.append((phone_breach_check.run, own_phone))
    jobs.append((phone_reputation.run, suspicious_phone))

    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        futures = [executor.submit(fn, arg) for fn, arg in jobs]
        for future in futures:
            results.extend(future.result())
    # mostra os problemas mais graves primeiro
    results.sort(key=lambda r: -STATUS_WEIGHT[r.status])
    return Report(domain=domain, score=_score(results), results=results)
