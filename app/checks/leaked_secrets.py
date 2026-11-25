import os

import requests

from .base import CheckResult, Status

# A API de busca de código do GitHub não aceita OR/parênteses na query — cada
# termo sensível precisa ser buscado separadamente (AND implícito com o domínio).
SENSITIVE_TERMS = ["password", "api_key", "secret", "token"]


def run(domain: str) -> list[CheckResult]:
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        return [CheckResult(
            check_id="leaked_secrets",
            title="Chaves/senhas vazadas em repositórios públicos",
            status=Status.UNKNOWN,
            message="Verificação não configurada nesta instância (requer um token do GitHub).",
            recommendation="Configure GITHUB_TOKEN no .env para ativar esta checagem.",
        )]

    headers = {"Authorization": f"token {github_token}", "Accept": "application/vnd.github+json"}
    total = 0
    seen_urls: dict[str, None] = {}
    successful_queries = 0

    for term in SENSITIVE_TERMS:
        try:
            resp = requests.get(
                "https://api.github.com/search/code",
                params={"q": f'"{domain}" {term}'},
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            total += data.get("total_count", 0)
            for item in data.get("items", []):
                seen_urls[item["html_url"]] = None
            successful_queries += 1
        except Exception:
            continue

    if successful_queries == 0:
        return [CheckResult(
            check_id="leaked_secrets",
            title="Chaves/senhas vazadas em repositórios públicos",
            status=Status.UNKNOWN,
            message="Não foi possível completar esta verificação agora. Tente novamente mais tarde.",
        )]

    items = list(seen_urls)[:10]
    status = Status.WARNING if total else Status.OK
    return [CheckResult(
        check_id="leaked_secrets",
        title="Chaves/senhas vazadas em repositórios públicos",
        status=status,
        message=(
            f"Encontramos {total} resultado(s) públicos no GitHub mencionando seu domínio perto de termos sensíveis "
            "(pode incluir falsos positivos, precisa revisão manual)."
            if total else "Nenhum indício encontrado em repositórios públicos do GitHub."
        ),
        recommendation=(
            "Comprove que o domínio é seu para ver onde estão esses resultados e revise um por um — se alguma "
            "chave/senha real estiver exposta, revogue-a imediatamente e gere uma nova."
        ) if total else "",
        # ONDE estão as chaves só aparece para o dono do domínio: para um
        # visitante anônimo, essa lista é exatamente o que um atacante procura.
        private_details=items,
    )]
