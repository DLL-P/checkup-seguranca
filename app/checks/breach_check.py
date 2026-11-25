import os

import requests

from .base import CheckResult, Status

TITLE = "E-mails da empresa em vazamentos conhecidos"


def run(domain: str) -> list[CheckResult]:
    hibp_api_key = os.getenv("HIBP_API_KEY")
    if not hibp_api_key:
        return [CheckResult(
            check_id="breach_check",
            title=TITLE,
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
                title=TITLE,
                status=Status.OK,
                message="Não encontramos e-mails do seu domínio em vazamentos de dados conhecidos.",
            )]
        if resp.status_code in (401, 403):
            # A busca por domínio do HIBP só responde para domínios verificados
            # no painel da chave de API — por desenho do próprio HIBP, para que
            # ninguém liste os e-mails vazados de uma empresa alheia.
            return [CheckResult(
                check_id="breach_check",
                title=TITLE,
                status=Status.UNKNOWN,
                message="Esta checagem só está disponível para domínios cadastrados pela Nebula Host junto ao serviço de vazamentos (Have I Been Pwned).",
                recommendation="Se quiser ativar para o seu domínio, fale com a Nebula Host.",
            )]
        resp.raise_for_status()
        data = resp.json()
        accounts = sorted(data.keys()) if isinstance(data, dict) else []
        if not accounts:
            return [CheckResult(
                check_id="breach_check",
                title=TITLE,
                status=Status.OK,
                message="Nenhum e-mail do seu domínio encontrado em vazamentos conhecidos.",
            )]
        return [CheckResult(
            check_id="breach_check",
            title=TITLE,
            status=Status.CRITICAL,
            message=f"Encontramos {len(accounts)} conta(s) de e-mail do seu domínio envolvidas em vazamentos de dados.",
            recommendation="Troque as senhas dessas contas e ative a verificação em duas etapas (MFA) imediatamente. Comprove que o domínio é seu para ver quais contas são.",
            # Quais e-mails vazaram é dado pessoal dos funcionários: só para quem
            # comprovou que o domínio é seu.
            private_details=[f"{alias}@{domain}" for alias in accounts],
        )]
    except Exception:
        return [CheckResult(
            check_id="breach_check",
            title=TITLE,
            status=Status.UNKNOWN,
            message="Não foi possível completar esta verificação agora. Tente novamente mais tarde.",
        )]
