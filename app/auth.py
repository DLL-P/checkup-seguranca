"""Conta sem senha: entrada por link mágico enviado ao e-mail.

- Não existe senha para vazar.
- O link vale 15 minutos e só pode ser usado uma vez.
- No banco só fica o HASH do link e da sessão: quem ler o banco não consegue
  entrar na conta de ninguém.
- O link abre uma página com o botão "Entrar" (POST) em vez de entrar direto no
  GET, porque os antivírus de e-mail (ex.: Links Seguros do Outlook) abrem os
  links sozinhos e queimariam o link de uso único antes da pessoa clicar.
"""

import hashlib
import re
import secrets
from datetime import timedelta

from fastapi import Request

from . import config, db

SESSION_COOKIE = "checkup_sessao"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def normalize_email(raw: str) -> str | None:
    email = (raw or "").strip().lower()
    return email if len(email) <= 254 and EMAIL_RE.match(email) else None


def create_login_token(email: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = db.now() + timedelta(minutes=config.LOGIN_LINK_MINUTES)
    with db.connect() as conn:
        conn.execute("DELETE FROM login_tokens WHERE expires_at < ?", (db.iso(db.now()),))
        conn.execute(
            "INSERT INTO login_tokens (token_hash, email, expires_at) VALUES (?, ?, ?)",
            (_hash(token), email, db.iso(expires)),
        )
    return token


def login_link(token: str) -> str:
    return f"{config.APP_BASE_URL}/entrar/confirmar?token={token}"


def login_token_is_valid(token: str) -> bool:
    with db.connect() as conn:
        row = conn.execute("SELECT expires_at FROM login_tokens WHERE token_hash = ?", (_hash(token),)).fetchone()
    return bool(row and db.parse(row["expires_at"]) > db.now())


def consume_login_token(token: str) -> int | None:
    """Usa o link (uma vez só) e devolve o id do usuário, criando a conta no
    primeiro acesso."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT email, expires_at FROM login_tokens WHERE token_hash = ?", (_hash(token),)
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM login_tokens WHERE token_hash = ?", (_hash(token),))
        if db.parse(row["expires_at"]) < db.now():
            return None
        email = row["email"]
        user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            return user["id"]
        cur = conn.execute("INSERT INTO users (email, created_at) VALUES (?, ?)", (email, db.iso(db.now())))
        return cur.lastrowid


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = db.now() + timedelta(days=config.SESSION_DAYS)
    with db.connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (db.iso(db.now()),))
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (_hash(token), user_id, db.iso(expires)),
        )
    return token


def current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    with db.connect() as conn:
        row = conn.execute(
            "SELECT u.*, s.expires_at AS session_expires FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ?",
            (_hash(token),),
        ).fetchone()
    if not row or db.parse(row["session_expires"]) < db.now():
        return None
    return row


def destroy_session(request: Request) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash(token),))


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=config.SESSION_DAYS * 86400,
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="lax",
    )


def delete_account(user_id: int) -> None:
    """Apaga a conta e tudo ligado a ela (domínios, retratos, alertas,
    sessões) — direito de eliminação da LGPD (art. 18, VI)."""
    with db.connect() as conn:
        email = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        if email:
            conn.execute("DELETE FROM login_tokens WHERE email = ?", (email["email"],))
