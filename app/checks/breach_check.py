import os

import requests

from .base import CheckResult, Status


def run(domain: str) -> list[CheckResult]:
    hibp_api_key = os.getenv("HIBP_API_KEY")
    if not hibp_api_key:
        return [CheckResult(
            check_id="breach_check",
            title="E-mails da empresa em vazamentos conhecidos",
            status=Status.UNKNOWN,
            message="Verificação não configurada nesta instância (requer uma chave de API do Have I Been Pwned).",
            recommendation="Configure HIBP_API_KEY no .env para ativar esta checagem.",
        )]
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers={"hibp-api-key": hibp_api_key, "user-agent": "security-checkup"},
            timeout=10,
        )
        if resp.status_code == 404:
            return [CheckResult(
                check_id="breach_check",
                title="E-mails da empresa em vazamentos conhecidos",
                status=Status.OK,
                message="Não encontramos e-mails do seu domínio em vazamentos de dados conhecidos.",
            )]
        resp.raise_for_status()
        data = resp.json()
        accounts = list(data.keys()) if isinstance(data, dict) else []
        return [CheckResult(
            check_id="breach_check",
            title="E-mails da empresa em vazamentos conhecidos",
            status=Status.CRITICAL if accounts else Status.OK,
            message=(
                f"Encontramos {len(accounts)} conta(s) de e-mail do seu domínio envolvidas em vazamentos de dados."
                if accounts else "Nenhum e-mail do seu domínio encontrado em vazamentos conhecidos."
            ),
            recommendation="Troque as senhas dessas contas e ative a autenticação em duas etapas (MFA) imediatamente." if accounts else "",
            details=accounts,
        )]
    except Exception:
        return [CheckResult(
            check_id="breach_check",
            title="E-mails da empresa em vazamentos conhecidos",
            status=Status.UNKNOWN,
            message="Não foi possível completar esta verificação agora. Tente novamente mais tarde.",
        )]
