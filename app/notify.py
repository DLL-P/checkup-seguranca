"""Envio de e-mail (Resend) e WhatsApp (Cloud API oficial da Meta).

Sem as chaves configuradas, nada é enviado e o motivo vai para o log — o
resto do sistema continua funcionando (mesmo padrão das checagens)."""

import logging
import re

import requests

from . import config

log = logging.getLogger("checkup.notify")

RESEND_URL = "https://api.resend.com/emails"


def send_email(to: str, subject: str, text: str) -> bool:
    if not config.RESEND_API_KEY:
        log.warning("E-mail não enviado (RESEND_API_KEY ausente): para=%s assunto=%s", to, subject)
        return False
    try:
        resp = requests.post(
            RESEND_URL,
            headers={"Authorization": f"Bearer {config.RESEND_API_KEY}"},
            json={"from": config.EMAIL_FROM, "to": [to], "subject": subject, "text": text},
            timeout=15,
        )
        resp.raise_for_status()
        return True
    except Exception:
        log.exception("Falha ao enviar e-mail para %s", to)
        return False


def normalize_phone(raw: str) -> str | None:
    """Telefone no formato que a Cloud API espera (só dígitos, com DDI). Aceita
    o jeito brasileiro de digitar: (81) 99999-9999 vira 5581999999999."""
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) in (10, 11):
        digits = "55" + digits
    return digits if 12 <= len(digits) <= 15 else None


def send_whatsapp_alert(phone: str, domain: str, summary: str, link: str) -> bool:
    """Mensagem iniciada pela empresa precisa de um modelo (template) aprovado
    pela Meta. O modelo esperado tem 3 variáveis no corpo: {{1}} domínio,
    {{2}} resumo do que mudou, {{3}} link do relatório (ver README)."""
    if not config.whatsapp_configured():
        log.warning("WhatsApp não enviado (WHATSAPP_TOKEN/WHATSAPP_PHONE_NUMBER_ID ausentes)")
        return False
    url = (
        f"https://graph.facebook.com/{config.WHATSAPP_API_VERSION}/"
        f"{config.WHATSAPP_PHONE_NUMBER_ID}/messages"
    )
    payload = {
        "messaging_product": "whatsapp",
        "to": phone,
        "type": "template",
        "template": {
            "name": config.WHATSAPP_TEMPLATE,
            "language": {"code": config.WHATSAPP_TEMPLATE_LANG},
            "components": [{
                "type": "body",
                "parameters": [
                    {"type": "text", "text": domain},
                    # a Meta recusa parâmetro com quebra de linha ou muito longo
                    {"type": "text", "text": " ".join(summary.split())[:900]},
                    {"type": "text", "text": link},
                ],
            }],
        },
    }
    try:
        resp = requests.post(
            url, headers={"Authorization": f"Bearer {config.WHATSAPP_TOKEN}"}, json=payload, timeout=15
        )
        resp.raise_for_status()
        return True
    except Exception:
        log.exception("Falha ao enviar WhatsApp")
        return False
