import re

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from . import abuse_guard, captcha
from .checks.base import STATUS_ICON
from .report import run_all_checks

app = FastAPI(title="Security Checkup")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
templates.env.globals["STATUS_ICON"] = STATUS_ICON

# Protege contra abuso: sem isso, qualquer pessoa anônima poderia usar o
# formulário público para varrer portas de terceiros à vontade ou estourar o
# custo das chaves de API pagas (HIBP, Twilio) só martelando o endpoint.
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _clean_domain(raw: str) -> str | None:
    domain = raw.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    return domain if DOMAIN_RE.match(domain) else None


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "error": "Você atingiu o limite de verificações por enquanto. Espere um pouco e tente de novo.",
            "turnstile_site_key": captcha.site_key(),
        },
        status_code=429,
    )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "error": None, "turnstile_site_key": captcha.site_key()}
    )


@app.post("/check", response_class=HTMLResponse)
@limiter.limit("5/hour")
async def check(
    request: Request,
    domain: str = Form(...),
    cnpj: str = Form(""),
    own_phone: str = Form(""),
    suspicious_phone: str = Form(""),
    cf_turnstile_response: str = Form("", alias="cf-turnstile-response"),
):
    if not captcha.verify(cf_turnstile_response, request.client.host if request.client else None):
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": "Não conseguimos confirmar que você não é um robô. Tente marcar a verificação de novo.",
                "turnstile_site_key": captcha.site_key(),
            },
        )

    clean = _clean_domain(domain)
    if not clean:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": "Digite um endereço de site válido, por exemplo: minhaempresa.com.br",
                "turnstile_site_key": captcha.site_key(),
            },
        )

    wait_seconds = abuse_guard.seconds_until_domain_available(clean)
    if wait_seconds:
        wait_minutes = max(1, round(wait_seconds / 60))
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": f"Esse domínio já foi verificado há pouco tempo. Tente de novo em cerca de {wait_minutes} minuto(s).",
                "turnstile_site_key": captcha.site_key(),
            },
        )

    report = run_all_checks(
        clean,
        cnpj=cnpj.strip() or None,
        own_phone=own_phone.strip() or None,
        suspicious_phone=suspicious_phone.strip() or None,
    )
    abuse_guard.mark_domain_checked(clean)
    return templates.TemplateResponse("report.html", {"request": request, "report": report})
