import re

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .checks.base import STATUS_ICON
from .report import run_all_checks

app = FastAPI(title="Security Checkup")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
templates.env.globals["STATUS_ICON"] = STATUS_ICON

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _clean_domain(raw: str) -> str | None:
    domain = raw.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    return domain if DOMAIN_RE.match(domain) else None


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "error": None})


@app.post("/check", response_class=HTMLResponse)
async def check(
    request: Request,
    domain: str = Form(...),
    cnpj: str = Form(""),
    own_phone: str = Form(""),
    suspicious_phone: str = Form(""),
):
    clean = _clean_domain(domain)
    if not clean:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": "Digite um endereço de site válido, por exemplo: minhaempresa.com.br"},
        )
    report = run_all_checks(
        clean,
        cnpj=cnpj.strip() or None,
        own_phone=own_phone.strip() or None,
        suspicious_phone=suspicious_phone.strip() or None,
    )
    return templates.TemplateResponse("report.html", {"request": request, "report": report})
