import hmac
import logging
import threading
from urllib.parse import urlparse

from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from . import abuse_guard, auth, captcha, config, db, intel, monitor, notify, scoring, verification
from .checks.base import STATUS_ICON
from .report import run_all_checks, run_domain_checks

log = logging.getLogger("checkup")

app = FastAPI(title="Diagnóstico de Segurança - Nebula Host")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
templates.env.globals.update(
    STATUS_ICON=STATUS_ICON,
    HELP_URL=config.HELP_URL,
)

# Protege contra abuso: sem isso, qualquer pessoa anônima poderia estourar o
# custo das chaves de API pagas (HIBP, Twilio) ou usar a ferramenta contra o
# domínio de terceiros em massa. A chave do limite é um código do IP, nunca o
# IP em claro.
limiter = Limiter(key_func=abuse_guard.hashed_ip, storage_uri=abuse_guard.limiter_storage_uri())
app.state.limiter = limiter

MAX_DOMAINS_PER_USER = 10
_STATE_CHANGING_PREFIXES = ("/painel", "/sair", "/entrar/confirmar")


def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    ctx.setdefault("user", auth.current_user(request))
    ctx.setdefault("turnstile_site_key", captcha.site_key())
    ctx.setdefault("error", None)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def message(request: Request, title: str, text: str, status_code: int = 200) -> HTMLResponse:
    return render(request, "mensagem.html", status_code=status_code, title=title, text=text)


@app.middleware("http")
async def same_origin_posts(request: Request, call_next):
    """Defesa extra contra CSRF (além do cookie SameSite=Lax): um POST que muda
    a conta só é aceito se vier do próprio site."""
    if request.method == "POST" and request.url.path.startswith(_STATE_CHANGING_PREFIXES):
        origin = request.headers.get("origin")
        if origin and origin != "null":
            expected = urlparse(config.APP_BASE_URL)
            got = urlparse(origin)
            if (got.scheme, got.netloc) != (expected.scheme, expected.netloc):
                return Response("Origem não permitida.", status_code=403)
    return await call_next(request)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    return message(
        request,
        "Calma, só um pouquinho",
        "Você atingiu o limite de pedidos por enquanto. Espere um pouco e tente de novo.",
        status_code=429,
    )


def _owned_verified_domains(user) -> list[str]:
    if not user:
        return []
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT domain FROM domains WHERE user_id = ? AND verified_at IS NOT NULL", (user["id"],)
        ).fetchall()
    return [r["domain"] for r in rows]


def _can_see_private(user, domain: str) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in _owned_verified_domains(user))


# ---------------------------------------------------------------- diagnóstico


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return render(request, "index.html")


@app.post("/check", response_class=HTMLResponse)
@limiter.limit("5/hour")
def check(
    request: Request,
    domain: str = Form(...),
    cnpj: str = Form(""),
    own_phone: str = Form(""),
    suspicious_phone: str = Form(""),
    cf_turnstile_response: str = Form("", alias="cf-turnstile-response"),
):
    if not captcha.verify(cf_turnstile_response, request.client.host if request.client else None):
        return render(request, "index.html", error="Não conseguimos confirmar que você não é um robô. Tente marcar a verificação de novo.")

    clean = verification.clean_domain(domain)
    if not clean:
        return render(request, "index.html", error="Digite um endereço de site válido, por exemplo: minhaempresa.com.br")

    wait_seconds = abuse_guard.seconds_until_domain_available(clean)
    if wait_seconds:
        wait_minutes = max(1, round(wait_seconds / 60))
        return render(
            request,
            "index.html",
            error=f"Esse domínio já foi verificado há pouco tempo. Tente de novo em cerca de {wait_minutes} minuto(s).",
        )

    report = run_all_checks(
        clean,
        cnpj=cnpj.strip() or None,
        own_phone=own_phone.strip() or None,
        suspicious_phone=suspicious_phone.strip() or None,
    )
    abuse_guard.mark_domain_checked(clean)
    user = auth.current_user(request)
    return render(request, "report.html", user=user, report=report, show_private=_can_see_private(user, clean))


@app.get("/metodologia", response_class=HTMLResponse)
async def metodologia(request: Request):
    return render(request, "metodologia.html", rules=scoring.RULES, sources=intel.ATTRIBUTION)


@app.get("/privacidade", response_class=HTMLResponse)
async def privacidade(request: Request):
    return render(
        request,
        "privacidade.html",
        controller=config.CONTROLLER_NAME,
        controller_document=config.CONTROLLER_DOCUMENT,
        contact=config.PRIVACY_CONTACT_EMAIL,
    )


# ---------------------------------------------------------------- conta


@app.get("/entrar", response_class=HTMLResponse)
async def entrar_form(request: Request):
    if auth.current_user(request):
        return RedirectResponse("/painel", status_code=303)
    return render(request, "entrar.html")


@app.post("/entrar", response_class=HTMLResponse)
@limiter.limit("5/hour")
def entrar(request: Request, email: str = Form(...)):
    clean = auth.normalize_email(email)
    if not clean:
        return render(request, "entrar.html", error="Digite um e-mail válido, por exemplo: voce@minhaempresa.com.br")
    token = auth.create_login_token(clean)
    link = auth.login_link(token)
    sent = notify.send_email(
        clean,
        "Seu link de entrada — Diagnóstico de Segurança",
        "Olá! Use o link abaixo para entrar no Diagnóstico de Segurança da Nebula Host.\n\n"
        f"{link}\n\n"
        f"O link vale por {config.LOGIN_LINK_MINUTES} minutos e só funciona uma vez.\n"
        "Se não foi você que pediu, é só ignorar este e-mail.",
    )
    if not sent and not config.DEV_SHOW_LOGIN_LINK:
        log.warning("Link de entrada não enviado por e-mail (veja RESEND_API_KEY).")
    # A resposta é a mesma exista ou não a conta: não dá para descobrir quem
    # tem cadastro testando e-mails.
    return render(
        request,
        "entrar_enviado.html",
        email=clean,
        dev_link=link if config.DEV_SHOW_LOGIN_LINK else None,
    )


@app.get("/entrar/confirmar", response_class=HTMLResponse)
async def entrar_confirmar_form(request: Request, token: str = ""):
    if not token or not auth.login_token_is_valid(token):
        return message(request, "Link expirado", "Esse link de entrada expirou ou já foi usado. Peça um novo na página de entrada.", 400)
    return render(request, "entrar_confirmar.html", token=token)


@app.post("/entrar/confirmar")
def entrar_confirmar(request: Request, token: str = Form(...)):
    user_id = auth.consume_login_token(token)
    if not user_id:
        return message(request, "Link expirado", "Esse link de entrada expirou ou já foi usado. Peça um novo na página de entrada.", 400)
    response = RedirectResponse("/painel", status_code=303)
    auth.set_session_cookie(response, auth.create_session(user_id))
    return response


@app.post("/sair")
def sair(request: Request):
    auth.destroy_session(request)
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(auth.SESSION_COOKIE)
    return response


# ---------------------------------------------------------------- painel


def _require_user(request: Request):
    return auth.current_user(request)


def _get_domain(user, domain_id: int):
    with db.connect() as conn:
        return conn.execute(
            "SELECT * FROM domains WHERE id = ? AND user_id = ?", (domain_id, user["id"])
        ).fetchone()


def _baseline(domain_id: int, user_id: int) -> None:
    """Primeira verificação logo após comprovar o domínio: vira o retrato de
    referência, para o monitoramento já saber o que é "novo" na próxima."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT d.*, u.email, u.email_alerts, u.whatsapp_phone, u.whatsapp_optin_at "
            "FROM domains d JOIN users u ON u.id = d.user_id WHERE d.id = ? AND d.user_id = ?",
            (domain_id, user_id),
        ).fetchone()
    if row and not row["last_snapshot"]:
        try:
            monitor.check_domain(row, row)
        except Exception:
            log.exception("Falha na verificação inicial de %s", row["domain"])


@app.get("/painel", response_class=HTMLResponse)
async def painel(request: Request):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/entrar", status_code=303)
    with db.connect() as conn:
        domains = conn.execute(
            "SELECT * FROM domains WHERE user_id = ? ORDER BY created_at", (user["id"],)
        ).fetchall()
    return render(
        request,
        "painel.html",
        user=user,
        domains=domains,
        whatsapp_available=config.whatsapp_configured(),
        interval_days=config.MONITOR_INTERVAL_DAYS,
        notice=request.query_params.get("aviso"),
    )


@app.post("/painel/dominios")
def painel_add_domain(request: Request, background: BackgroundTasks, domain: str = Form(...)):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/entrar", status_code=303)
    clean = verification.clean_domain(domain)
    if not clean:
        return RedirectResponse("/painel?aviso=dominio-invalido", status_code=303)
    with db.connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM domains WHERE user_id = ?", (user["id"],)).fetchone()[0]
        if count >= MAX_DOMAINS_PER_USER:
            return RedirectResponse("/painel?aviso=limite", status_code=303)
        exists = conn.execute(
            "SELECT id FROM domains WHERE user_id = ? AND domain = ?", (user["id"], clean)
        ).fetchone()
        if exists:
            return RedirectResponse(f"/painel/dominios/{exists['id']}", status_code=303)
        by_email = verification.email_proves_domain(user["email"], clean)
        cur = conn.execute(
            "INSERT INTO domains (user_id, domain, verify_token, verified_at, verify_method, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                user["id"],
                clean,
                verification.new_token(),
                db.iso(db.now()) if by_email else None,
                "email" if by_email else None,
                db.iso(db.now()),
            ),
        )
        domain_id = cur.lastrowid
    if by_email:
        background.add_task(_baseline, domain_id, user["id"])
    return RedirectResponse(f"/painel/dominios/{domain_id}", status_code=303)


@app.get("/painel/dominios/{domain_id}", response_class=HTMLResponse)
async def painel_domain(request: Request, domain_id: int):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/entrar", status_code=303)
    row = _get_domain(user, domain_id)
    if not row:
        return message(request, "Domínio não encontrado", "Esse domínio não está na sua conta.", 404)
    with db.connect() as conn:
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE domain_id = ? ORDER BY sent_at DESC LIMIT 20", (domain_id,)
        ).fetchall()
    return render(
        request,
        "dominio.html",
        user=user,
        d=row,
        alerts=alerts,
        txt_value=verification.txt_record_value(row["verify_token"]),
        notice=request.query_params.get("aviso"),
    )


@app.post("/painel/dominios/{domain_id}/verificar")
def painel_verify(request: Request, background: BackgroundTasks, domain_id: int):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/entrar", status_code=303)
    row = _get_domain(user, domain_id)
    if not row:
        return message(request, "Domínio não encontrado", "Esse domínio não está na sua conta.", 404)
    if row["verified_at"]:
        return RedirectResponse(f"/painel/dominios/{domain_id}", status_code=303)
    if not verification.dns_proves_domain(row["domain"], row["verify_token"]):
        return RedirectResponse(f"/painel/dominios/{domain_id}?aviso=dns-nao-encontrado", status_code=303)
    with db.connect() as conn:
        conn.execute(
            "UPDATE domains SET verified_at = ?, verify_method = 'dns' WHERE id = ?", (db.iso(db.now()), domain_id)
        )
    background.add_task(_baseline, domain_id, user["id"])
    return RedirectResponse(f"/painel/dominios/{domain_id}?aviso=comprovado", status_code=303)


@app.post("/painel/dominios/{domain_id}/relatorio", response_class=HTMLResponse)
@limiter.limit("10/hour")
def painel_report(request: Request, domain_id: int):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/entrar", status_code=303)
    row = _get_domain(user, domain_id)
    if not row:
        return message(request, "Domínio não encontrado", "Esse domínio não está na sua conta.", 404)
    report = run_domain_checks(row["domain"])
    return render(request, "report.html", user=user, report=report, show_private=bool(row["verified_at"]))


@app.post("/painel/dominios/{domain_id}/remover")
def painel_remove(request: Request, domain_id: int):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/entrar", status_code=303)
    with db.connect() as conn:
        conn.execute("DELETE FROM domains WHERE id = ? AND user_id = ?", (domain_id, user["id"]))
    return RedirectResponse("/painel?aviso=removido", status_code=303)


@app.post("/painel/avisos")
def painel_alerts(
    request: Request,
    email_alerts: str = Form(""),
    whatsapp_phone: str = Form(""),
    whatsapp_consent: str = Form(""),
):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/entrar", status_code=303)
    phone = notify.normalize_phone(whatsapp_phone) if whatsapp_phone.strip() else None
    if whatsapp_phone.strip() and not phone:
        return RedirectResponse("/painel?aviso=telefone-invalido", status_code=303)
    if phone and not whatsapp_consent:
        return RedirectResponse("/painel?aviso=sem-consentimento", status_code=303)
    with db.connect() as conn:
        if phone:
            keep_optin = user["whatsapp_phone"] == phone and user["whatsapp_optin_at"]
            optin = user["whatsapp_optin_at"] if keep_optin else db.iso(db.now())
        else:
            optin = None
        conn.execute(
            "UPDATE users SET email_alerts = ?, whatsapp_phone = ?, whatsapp_optin_at = ? WHERE id = ?",
            (1 if email_alerts else 0, phone, optin, user["id"]),
        )
    return RedirectResponse("/painel?aviso=avisos-salvos", status_code=303)


@app.post("/painel/excluir-conta")
def painel_delete_account(request: Request, confirmar: str = Form("")):
    user = _require_user(request)
    if not user:
        return RedirectResponse("/entrar", status_code=303)
    if confirmar != "EXCLUIR":
        return RedirectResponse("/painel?aviso=confirmacao-exclusao", status_code=303)
    auth.delete_account(user["id"])
    response = message(request, "Conta excluída", "Sua conta, seus domínios e o histórico de avisos foram apagados.")
    response.delete_cookie(auth.SESSION_COOKIE)
    return response


# ---------------------------------------------------------------- tarefas

# Domínios verificados por chamada. Pequeno de propósito: no Fly.io a máquina
# desliga sozinha quando não há requisição aberta, então o trabalho roda DENTRO
# da requisição (e não em segundo plano, onde poderia ser cortado no meio). O
# agendador chama de novo enquanto houver pendentes.
CRON_BATCH = 2
_monitor_running = threading.Lock()


@app.post("/tarefas/monitor")
def tarefas_monitor(request: Request):
    """Gatilho do monitoramento, chamado pelo agendador (GitHub Actions). Sem
    CRON_SECRET configurado, fica desligado."""
    expected = config.CRON_SECRET
    given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not expected or not hmac.compare_digest(given, expected):
        return JSONResponse({"erro": "não autorizado"}, status_code=401)
    if not _monitor_running.acquire(blocking=False):
        return JSONResponse({"status": "já em andamento"}, status_code=409)
    try:
        results = monitor.run_due(limit=CRON_BATCH)
        pending = monitor.count_due()
    finally:
        _monitor_running.release()
    log.info("Monitoramento: %d verificado(s), %d pendente(s)", len(results), pending)
    return JSONResponse({
        "verificados": len(results),
        "avisos": sum(1 for r in results if r["worse"]),
        "pendentes": pending,
    })
