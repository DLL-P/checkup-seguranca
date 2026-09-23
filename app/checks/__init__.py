import socket

import urllib3.util.connection as _urllib3_connection

# Em redes sem saída IPv6 (comum em ambientes de contêiner/sandbox e em algumas
# redes domésticas/corporativas), toda chamada via `requests` tenta primeiro os
# endereços IPv6 retornados pelo DNS e só cai para IPv4 depois do timeout inteiro
# de cada tentativa — isso já fez uma chamada simples demorar 60s. Forçar IPv4
# evita essa demora para todas as checagens que usam `requests` (GitHub, HIBP,
# BrasilAPI).
_urllib3_connection.allowed_gai_family = lambda: socket.AF_INET
