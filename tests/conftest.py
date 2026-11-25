import os
import sys

import pytest

# Configuração de teste antes de importar o app (config lê o ambiente no import).
os.environ.setdefault("APP_BASE_URL", "http://testserver")
os.environ.setdefault("SECRET_KEY", "teste")
os.environ.setdefault("CRON_SECRET", "segredo-do-cron")
for key in ("REDIS_URL", "RESEND_API_KEY", "WHATSAPP_TOKEN", "HIBP_API_KEY", "GITHUB_TOKEN", "TURNSTILE_SECRET_KEY"):
    os.environ[key] = ""

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)  # o app monta app/static e app/templates por caminho relativo

from app import abuse_guard, config  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "teste.db"))
    abuse_guard.reset()
    yield


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app import main

    main.limiter.enabled = False
    with TestClient(main.app) as c:
        yield c
    main.limiter.enabled = True
