import threading
import time

# Impede que a ferramenta seja usada para martelar repetidamente a infraestrutura
# de um terceiro (ex: alguém automatizando requisições contra o domínio de outra
# pessoa) — independente de quantos IPs diferentes façam o pedido.
#
# É um cache em memória de processo único: reinicia ao reiniciar o servidor e não
# é compartilhado entre múltiplos workers. Para produção com mais de 1 worker,
# trocar por um backend compartilhado (ex: Redis) mantendo a mesma interface.
_DOMAIN_COOLDOWN_SECONDS = 600  # 10 minutos
_last_checked: dict[str, float] = {}
_lock = threading.Lock()


def seconds_until_domain_available(domain: str) -> int:
    """Retorna quantos segundos faltam até o domínio poder ser verificado de
    novo, ou 0 se já pode."""
    with _lock:
        last = _last_checked.get(domain)
        if last is None:
            return 0
        elapsed = time.time() - last
        remaining = _DOMAIN_COOLDOWN_SECONDS - elapsed
        return max(0, round(remaining))


def mark_domain_checked(domain: str) -> None:
    with _lock:
        _last_checked[domain] = time.time()
