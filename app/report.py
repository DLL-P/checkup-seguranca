from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import scoring
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
from .checks.base import CheckResult, Status, STATUS_WEIGHT

DOMAIN_CHECK_MODULES = [domain_dns, ip_exposure, breach_check, leaked_secrets, typosquat]


@dataclass
class Report:
    domain: str
    score: int
    results: list[CheckResult]
    actions: list[CheckResult] = field(default_factory=list)

    def snapshot(self) -> dict:
        """Retrato compacto do domínio, usado pelo monitoramento para saber o
        que mudou entre uma verificação e a próxima."""
        return {
            "score": self.score,
            "findings": {
                r.check_id: {
                    "status": r.status.value,
                    "rule": r.rule_key,
                    "title": r.title,
                    "message": r.message,
                    "points": r.points,
                    "items": sorted(set(r.details) | set(r.private_details)),
                }
                for r in self.results
            },
        }


def run_domain_checks(domain: str) -> Report:
    return run_all_checks(domain)


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

    note = scoring.score(results)
    # mostra primeiro o que mais pesa na nota, depois o resto por gravidade
    results.sort(key=lambda r: (-r.points, -STATUS_WEIGHT[r.status], r.status == Status.UNKNOWN))
    return Report(domain=domain, score=note, results=results, actions=scoring.top_actions(results))
