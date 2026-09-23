import os
import re

import requests

from .base import CheckResult, Status

# Twilio Lookup: identifica o tipo de linha (fixa, móvel, VOIP...). Números VOIP
# são baratos e descartáveis de obter, por isso são comumente usados em golpes de
# vishing/spoofing de identidade local — não é prova de golpe por si só, é um sinal.
LOOKUP_URL = "https://lookups.twilio.com/v2/PhoneNumbers/{phone}"


def _clean_phone(raw: str) -> str:
    return re.sub(r"[^\d+]", "", raw)


def run(phone: str | None) -> list[CheckResult]:
    if not phone:
        return []

    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    if not account_sid or not auth_token:
        return [CheckResult(
            check_id="phone_reputation",
            title="Reputação de número de telefone",
            status=Status.UNKNOWN,
            message="Verificação não configurada nesta instância (requer uma conta Twilio Lookup).",
            recommendation="Configure TWILIO_ACCOUNT_SID e TWILIO_AUTH_TOKEN no .env para ativar esta checagem.",
        )]

    clean = _clean_phone(phone)
    try:
        resp = requests.get(
            LOOKUP_URL.format(phone=clean),
            params={"Fields": "line_type_intelligence"},
            auth=(account_sid, auth_token),
            timeout=10,
        )
        if resp.status_code == 404:
            return [CheckResult(
                check_id="phone_reputation",
                title="Reputação de número de telefone",
                status=Status.WARNING,
                message="Esse número não parece ser um número de telefone válido.",
            )]
        resp.raise_for_status()
        data = resp.json()
        intelligence = data.get("line_type_intelligence") or {}
        line_type = intelligence.get("type")
        carrier = intelligence.get("carrier_name")

        if line_type == "voip":
            return [CheckResult(
                check_id="phone_reputation",
                title="Reputação de número de telefone",
                status=Status.WARNING,
                message="Esse número é de uma linha VOIP (voz sobre internet) — um tipo de linha comumente usado em golpes por telefone, por ser fácil de obter e descartar.",
                recommendation="Isso sozinho não prova golpe, mas combine com outros sinais de alerta (urgência, pedido de pagamento ou de dados sensíveis) antes de confiar na ligação.",
            )]
        return [CheckResult(
            check_id="phone_reputation",
            title="Reputação de número de telefone",
            status=Status.OK,
            message=f"Linha do tipo '{line_type or 'desconhecido'}'{f', operadora {carrier}' if carrier else ''} — sem sinal de risco nesta checagem básica.",
        )]
    except Exception:
        return [CheckResult(
            check_id="phone_reputation",
            title="Reputação de número de telefone",
            status=Status.UNKNOWN,
            message="Não foi possível completar esta verificação agora.",
        )]
