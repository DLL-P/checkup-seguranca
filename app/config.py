"""Configuração lida do ambiente (.env). Tudo é opcional para rodar localmente;
em produção, APP_BASE_URL e SECRET_KEY precisam estar definidos."""

import os

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "sim", "yes", "on")


# Endereço público do site. Os links de entrada (link mágico) e os links dos
# alertas são montados a partir DESTE valor, nunca do cabeçalho Host da
# requisição — senão um atacante poderia forjar o Host e fazer o e-mail de
# entrada apontar para um site dele (envenenamento de link de redefinição).
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")

# Segredo usado para gerar o código (hash) dos IPs no limite de uso. Troque em
# produção; se mudar, os contadores de limite simplesmente recomeçam.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-inseguro-troque-em-producao")

DATABASE_PATH = os.getenv("DATABASE_PATH", "data/checkup.db")

# Redis compartilhado para limite de uso e cooldown por domínio. Sem ele, os
# contadores ficam em memória do processo (ok para 1 máquina só).
REDIS_URL = os.getenv("REDIS_URL", "")

COOKIE_SECURE = _bool("COOKIE_SECURE", APP_BASE_URL.startswith("https://"))

SESSION_DAYS = 30
LOGIN_LINK_MINUTES = 15
MONITOR_INTERVAL_DAYS = int(os.getenv("MONITOR_INTERVAL_DAYS", "7"))

# Segredo do gatilho do monitoramento (POST /tarefas/monitor). Sem ele, o
# gatilho HTTP fica desligado (o CLI `python -m app.monitor` continua valendo).
CRON_SECRET = os.getenv("CRON_SECRET", "")

# Quem é o controlador dos dados (LGPD), exibido na página de privacidade.
CONTROLLER_NAME = os.getenv("CONTROLLER_NAME", "Nebula Host")
CONTROLLER_DOCUMENT = os.getenv("CONTROLLER_DOCUMENT", "")
PRIVACY_CONTACT_EMAIL = os.getenv("PRIVACY_CONTACT_EMAIL", "")

# Para onde aponta o "quero ajuda para resolver".
HELP_URL = os.getenv("HELP_URL", "https://nebulahost.com.br")

# E-mail (Resend). Sem chave, o link de entrada só aparece no log do servidor.
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "Diagnóstico Nebula Host <nao-responda@nebulahost.com.br>")
# Só para desenvolvimento local: mostra o link de entrada na própria tela.
DEV_SHOW_LOGIN_LINK = _bool("DEV_SHOW_LOGIN_LINK", False)

# WhatsApp Cloud API (alertas). Mensagem iniciada pela empresa exige modelo
# (template) aprovado pela Meta, na categoria "utilidade".
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_TEMPLATE = os.getenv("WHATSAPP_TEMPLATE", "alerta_seguranca")
WHATSAPP_TEMPLATE_LANG = os.getenv("WHATSAPP_TEMPLATE_LANG", "pt_BR")
WHATSAPP_API_VERSION = os.getenv("WHATSAPP_API_VERSION", "v21.0")


def whatsapp_configured() -> bool:
    return bool(WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID)
