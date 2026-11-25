"""Proteções contra abuso do formulário público.

- Cooldown por domínio: o mesmo domínio não pode ser verificado de novo antes
  de 10 minutos, não importa quem peça — impede que a ferramenta seja usada
  para martelar a infraestrutura de um terceiro.
- O IP do visitante nunca é guardado em claro: o limite de uso conta pedidos
  por um código (HMAC) do IP, que não permite recuperar o IP original.

Com REDIS_URL configurado, os contadores ficam no Redis e valem para todas as
máquinas; sem ele, ficam em memória do processo (ok para 1 máquina só).
"""

import hashlib
import hmac
import os
import threading
import time

from fastapi import Request

from . import config

_DOMAIN_COOLDOWN_SECONDS = 600  # 10 minutos
_PREFIX = "checkup:cooldown:"

_last_checked: dict[str, float] = {}
_lock = threading.Lock()
_redis = None

if config.REDIS_URL:
    import redis

    _redis = redis.Redis.from_url(config.REDIS_URL, socket_timeout=3)


def hashed_ip(request: Request) -> str:
    """Chave do limite de uso: HMAC do IP com o SECRET_KEY. No Fly.io o IP real
    do visitante vem no cabeçalho Fly-Client-IP (o proxy do Fly o preenche e
    sobrescreve qualquer valor enviado pelo cliente). Fora do Fly, esse
    cabeçalho é ignorado, porque aí qualquer cliente poderia forjá-lo."""
    ip = request.headers.get("fly-client-ip") if os.getenv("FLY_APP_NAME") else None
    ip = ip or (request.client.host if request.client else "desconhecido")
    return hmac.new(config.SECRET_KEY.encode(), ip.encode(), hashlib.sha256).hexdigest()[:32]


def limiter_storage_uri() -> str:
    return config.REDIS_URL or "memory://"


def seconds_until_domain_available(domain: str) -> int:
    """Retorna quantos segundos faltam até o domínio poder ser verificado de
    novo, ou 0 se já pode."""
    if _redis is not None:
        try:
            ttl = _redis.ttl(_PREFIX + domain)
            return max(0, int(ttl))
        except Exception:
            return 0  # Redis fora do ar não deve derrubar o diagnóstico
    with _lock:
        last = _last_checked.get(domain)
        if last is None:
            return 0
        remaining = _DOMAIN_COOLDOWN_SECONDS - (time.time() - last)
        return max(0, round(remaining))


def mark_domain_checked(domain: str) -> None:
    if _redis is not None:
        try:
            _redis.set(_PREFIX + domain, "1", ex=_DOMAIN_COOLDOWN_SECONDS)
            return
        except Exception:
            pass
    with _lock:
        _last_checked[domain] = time.time()


def reset() -> None:
    """Só para testes."""
    with _lock:
        _last_checked.clear()
