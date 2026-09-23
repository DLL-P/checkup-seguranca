import os

import requests

VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def is_configured() -> bool:
    return bool(os.getenv("TURNSTILE_SITE_KEY") and os.getenv("TURNSTILE_SECRET_KEY"))


def site_key() -> str | None:
    return os.getenv("TURNSTILE_SITE_KEY")


def verify(token: str, remote_ip: str | None) -> bool:
    """Confirma o desafio do Cloudflare Turnstile. Se o captcha não estiver
    configurado nesta instância (sem TURNSTILE_SECRET_KEY), deixa passar —
    mesmo padrão de degradação graciosa dos outros checks opcionais."""
    secret = os.getenv("TURNSTILE_SECRET_KEY")
    if not secret:
        return True
    if not token:
        return False
    try:
        resp = requests.post(
            VERIFY_URL,
            data={"secret": secret, "response": token, "remoteip": remote_ip or ""},
            timeout=10,
        )
        resp.raise_for_status()
        return bool(resp.json().get("success"))
    except Exception:
        # Falha na checagem do captcha não deve derrubar o formulário inteiro
        # por instabilidade do lado do Cloudflare — mas nega o pedido por padrão.
        return False
