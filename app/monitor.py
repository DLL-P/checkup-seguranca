"""Monitoramento contínuo dos domínios comprovados.

"A checagem é de uma vez" — com a conta, o diagnóstico roda de novo sozinho
(por padrão, toda semana) e avisa por e-mail e/ou WhatsApp quando algo PIORA:
uma porta perigosa que abriu, uma falha do servidor que entrou em exploração
ativa, o certificado prestes a vencer, um e-mail novo em vazamento.

Como rodar:
- CLI:    python -m app.monitor            (roda os domínios em atraso)
- HTTP:   POST /tarefas/monitor com o cabeçalho Authorization: Bearer <CRON_SECRET>
          (é o que o agendamento do GitHub Actions chama, em lotes; ver README)
"""

import json
import logging
import sys
from datetime import timedelta

from . import config, db, notify
from .checks.base import STATUS_WEIGHT, Status
from .report import run_domain_checks

log = logging.getLogger("checkup.monitor")

_W = {s.value: STATUS_WEIGHT[s] for s in Status}


def diff(old: dict | None, new: dict) -> tuple[list[str], list[str]]:
    """Compara dois retratos. Devolve (o que piorou, o que foi resolvido).
    Sem retrato anterior (primeira verificação), não há o que avisar."""
    if not old:
        return [], []
    old_f, new_f = old.get("findings", {}), new.get("findings", {})
    worse, resolved = [], []
    for check_id, cur in new_f.items():
        if cur["status"] == Status.UNKNOWN.value:
            continue  # falha temporária de consulta não é novidade
        prev = old_f.get(check_id)
        prev_status = prev["status"] if prev else Status.OK.value
        if cur["status"] == Status.OK.value:
            if prev and prev_status in (Status.WARNING.value, Status.CRITICAL.value):
                resolved.append(f"{cur['title']}: {cur['message']}")
            continue
        if not prev or prev_status in (Status.OK.value, Status.UNKNOWN.value):
            worse.append(f"{cur['title']}: {cur['message']}")
        elif _W[cur["status"]] > _W[prev_status] or cur["points"] > prev["points"]:
            worse.append(f"{cur['title']} (piorou): {cur['message']}")
        elif cur["points"] > 0 and set(cur["items"]) - set(prev["items"]):
            worse.append(f"{cur['title']} (novidade): {cur['message']}")
    return worse, resolved


def carry_forward(old: dict | None, new: dict) -> dict:
    """Se uma checagem falhou agora (⚪) mas tinha resultado antes, mantém o
    resultado anterior no retrato — senão a próxima verificação acharia que o
    problema é "novo" e mandaria um alerta repetido."""
    if not old:
        return new
    merged = json.loads(json.dumps(new))
    for check_id, cur in merged["findings"].items():
        prev = old.get("findings", {}).get(check_id)
        if cur["status"] == Status.UNKNOWN.value and prev:
            merged["findings"][check_id] = prev
    return merged


def _alert_text(domain: str, score: int, worse: list[str], resolved: list[str], link: str) -> str:
    lines = [
        f"Olá! O monitoramento do Diagnóstico de Segurança encontrou novidades em {domain}.",
        "",
        "O que mudou e merece atenção:",
        *[f"- {w}" for w in worse],
    ]
    if resolved:
        lines += ["", "O que foi resolvido desde a última verificação:", *[f"- {r}" for r in resolved]]
    lines += [
        "",
        f"Nota de segurança agora: {score}/10.",
        f"Relatório completo, com o que fazer em cada item: {link}",
        "",
        "Precisa de ajuda para resolver? Responda a Nebula Host: " + config.HELP_URL,
        "",
        "Você recebe este aviso porque ativou o monitoramento. Para parar, remova o domínio ou desligue os avisos no painel.",
    ]
    return "\n".join(lines)


def check_domain(row, user) -> dict:
    report = run_domain_checks(row["domain"])
    new = report.snapshot()
    old = json.loads(row["last_snapshot"]) if row["last_snapshot"] else None
    worse, resolved = diff(old, new)
    stored = carry_forward(old, new)
    channels = []
    if worse:
        link = f"{config.APP_BASE_URL}/painel/dominios/{row['id']}"
        summary = "; ".join(worse)
        if user["email_alerts"]:
            text = _alert_text(row["domain"], report.score, worse, resolved, link)
            if notify.send_email(user["email"], f"Alerta de segurança: {row['domain']}", text):
                channels.append("email")
        if user["whatsapp_phone"] and user["whatsapp_optin_at"]:
            if notify.send_whatsapp_alert(user["whatsapp_phone"], row["domain"], summary, link):
                channels.append("whatsapp")
    with db.connect() as conn:
        conn.execute(
            "UPDATE domains SET last_checked_at = ?, last_score = ?, last_snapshot = ? WHERE id = ?",
            (db.iso(db.now()), report.score, json.dumps(stored), row["id"]),
        )
        if worse:
            conn.execute(
                "INSERT INTO alerts (domain_id, sent_at, channels, summary) VALUES (?, ?, ?, ?)",
                (row["id"], db.iso(db.now()), ",".join(channels) or "nenhum", "; ".join(worse)),
            )
    return {"domain": row["domain"], "score": report.score, "worse": worse, "channels": channels}


_DUE = "d.verified_at IS NOT NULL AND (d.last_checked_at IS NULL OR d.last_checked_at < ?)"


def _cutoff() -> str:
    return db.iso(db.now() - timedelta(days=config.MONITOR_INTERVAL_DAYS))


def count_due() -> int:
    with db.connect() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM domains d WHERE {_DUE}", (_cutoff(),)).fetchone()[0]


def run_due(limit: int = 50) -> list[dict]:
    """Verifica os domínios comprovados cuja última verificação passou do
    intervalo (MONITOR_INTERVAL_DAYS)."""
    cutoff = _cutoff()
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT d.*, u.email, u.email_alerts, u.whatsapp_phone, u.whatsapp_optin_at "
            "FROM domains d JOIN users u ON u.id = d.user_id "
            f"WHERE {_DUE} "
            "ORDER BY d.last_checked_at IS NOT NULL, d.last_checked_at LIMIT ?",
            (cutoff, limit),
        ).fetchall()
    out = []
    for row in rows:
        try:
            out.append(check_domain(row, row))
        except Exception:
            log.exception("Falha ao monitorar %s", row["domain"])
    return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_due(limit=10_000)
    for r in results:
        print(f"{r['domain']}: nota {r['score']}/10, {len(r['worse'])} novidade(s), avisos: {r['channels'] or '-'}")
    print(f"{len(results)} domínio(s) verificado(s).")
    sys.exit(0)
