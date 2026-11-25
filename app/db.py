"""Banco SQLite (biblioteca padrão). Em produção no Fly.io, o arquivo fica num
volume montado (ver fly.toml); localmente, em data/checkup.db.

Guardamos só o necessário para a conta e o monitoramento: o e-mail, os
domínios vigiados, o último retrato de cada domínio e, se a pessoa pedir, o
telefone para o alerta por WhatsApp. Nenhum IP de visitante é gravado aqui."""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    email_alerts INTEGER NOT NULL DEFAULT 1,
    whatsapp_phone TEXT,
    whatsapp_optin_at TEXT
);
CREATE TABLE IF NOT EXISTS login_tokens (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    verify_token TEXT NOT NULL,
    verified_at TEXT,
    verify_method TEXT,
    created_at TEXT NOT NULL,
    last_checked_at TEXT,
    last_score INTEGER,
    last_snapshot TEXT,
    UNIQUE (user_id, domain)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    sent_at TEXT NOT NULL,
    channels TEXT NOT NULL,
    summary TEXT NOT NULL
);
"""


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _connect(path: str) -> sqlite3.Connection:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


_initialized: set[str] = set()


@contextmanager
def connect():
    path = config.DATABASE_PATH
    conn = _connect(path)
    try:
        if path not in _initialized:
            conn.executescript(SCHEMA)
            _initialized.add(path)
        yield conn
        conn.commit()
    finally:
        conn.close()
