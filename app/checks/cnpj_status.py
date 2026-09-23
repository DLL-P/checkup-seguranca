import re

import requests

from .base import CheckResult, Status

# BrasilAPI espelha dados públicos da Receita Federal — CNPJ é registro de
# empresa (dado público), não dado pessoal sensível como CPF.
BRASILAPI_URL = "https://brasilapi.com.br/api/cnpj/v1/{cnpj}"


def _clean_cnpj(raw: str) -> str:
    return re.sub(r"\D", "", raw)


def run(cnpj: str | None) -> list[CheckResult]:
    if not cnpj:
        return []

    clean = _clean_cnpj(cnpj)
    if len(clean) != 14:
        return [CheckResult(
            check_id="cnpj_status",
            title="Situação da empresa (CNPJ)",
            status=Status.UNKNOWN,
            message="O CNPJ informado não parece válido (precisa ter 14 dígitos).",
        )]

    try:
        resp = requests.get(BRASILAPI_URL.format(cnpj=clean), timeout=10)
        if resp.status_code == 400:
            return [CheckResult(
                check_id="cnpj_status",
                title="Situação da empresa (CNPJ)",
                status=Status.UNKNOWN,
                message="O CNPJ informado não é válido (dígito verificador incorreto). Confira se foi digitado certo.",
            )]
        if resp.status_code == 404:
            return [CheckResult(
                check_id="cnpj_status",
                title="Situação da empresa (CNPJ)",
                status=Status.CRITICAL,
                message="Não encontramos esse CNPJ na base da Receita Federal.",
                recommendation="Confira se o número foi digitado corretamente. Se estiver certo e mesmo assim não aparecer, isso é um sinal de alerta sobre a legitimidade da empresa.",
            )]
        resp.raise_for_status()
        data = resp.json()
        situacao = (data.get("descricao_situacao_cadastral") or "").upper()
        razao_social = data.get("razao_social", "a empresa")
        abertura = data.get("data_inicio_atividade", "")

        if situacao == "ATIVA":
            return [CheckResult(
                check_id="cnpj_status",
                title="Situação da empresa (CNPJ)",
                status=Status.OK,
                message=f"{razao_social} está com situação cadastral ATIVA na Receita Federal (aberta em {abertura}).",
            )]
        return [CheckResult(
            check_id="cnpj_status",
            title="Situação da empresa (CNPJ)",
            status=Status.CRITICAL,
            message=f"{razao_social} está com situação cadastral '{situacao or 'desconhecida'}' na Receita Federal — não é uma empresa ativa.",
            recommendation="Empresas baixadas, suspensas ou inaptas não deveriam estar emitindo cobranças nem fechando negócios em nome próprio. Isso pode indicar fraude ou irregularidade fiscal.",
        )]
    except Exception:
        return [CheckResult(
            check_id="cnpj_status",
            title="Situação da empresa (CNPJ)",
            status=Status.UNKNOWN,
            message="Não foi possível consultar o CNPJ agora. Tente novamente mais tarde.",
        )]
