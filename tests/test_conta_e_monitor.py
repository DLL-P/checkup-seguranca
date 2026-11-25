import json

import pytest

from app import auth, db, main, monitor, notify, verification
from app.checks.base import CheckResult, Status
from app.report import Report


def fake_report(domain, *, port_status=Status.OK, extra_private=None):
    results = [
        CheckResult("exposed_ports", "Portas sensíveis abertas na internet", port_status, "portas",
                    recommendation="feche" if port_status != Status.OK else "",
                    details=["Porta 3389 — RDP"] if port_status != Status.OK else []),
        CheckResult("breach_check", "E-mails vazados", Status.CRITICAL, "2 conta(s)", recommendation="troque",
                    private_details=extra_private or ["joao@" + domain]),
    ]
    from app import scoring
    return Report(domain=domain, score=scoring.score(results), results=results, actions=scoring.top_actions(results))


def login(client, email):
    token = auth.create_login_token(email)
    resp = client.get(f"/entrar/confirmar?token={token}")
    assert resp.status_code == 200 and "Entrar" in resp.text
    resp = client.post("/entrar/confirmar", data={"token": token}, follow_redirects=False)
    assert resp.status_code == 303
    return resp


# ------------------------------------------------------------ verificação

@pytest.mark.parametrize("raw,expected", [
    ("https://www.Empresa.com.br/contato", "empresa.com.br"),
    ("loja.empresa.com.br", "loja.empresa.com.br"),
    ("empresa", None),
    ("<script>", None),
])
def test_clean_domain(raw, expected):
    assert verification.clean_domain(raw) == expected


def test_email_da_empresa_comprova_dominio():
    assert verification.email_proves_domain("joao@empresa.com.br", "empresa.com.br")
    assert verification.email_proves_domain("joao@empresa.com.br", "loja.empresa.com.br")
    assert not verification.email_proves_domain("joao@empresa.com.br", "outraempresa.com.br")
    assert not verification.email_proves_domain("joao@empresa.com.br", "xempresa.com.br")
    # provedor público nunca comprova (senão quem tem Gmail "seria dono" do gmail.com)
    assert not verification.email_proves_domain("alguem@gmail.com", "gmail.com")


def test_dns_txt_comprova_dominio():
    assert verification.dns_proves_domain("x.com", "abc", lookup=lambda d: ["v=spf1 -all", "nebula-checkup=abc"])
    assert not verification.dns_proves_domain("x.com", "abc", lookup=lambda d: ["nebula-checkup=outro"])


# ------------------------------------------------------------ relatório público x dono

def test_relatorio_publico_esconde_detalhes(client, monkeypatch):
    monkeypatch.setattr(main, "run_all_checks", lambda d, **k: fake_report(d))
    resp = client.post("/check", data={"domain": "empresa.com.br"})
    assert resp.status_code == 200
    assert "joao@empresa.com.br" not in resp.text
    assert "visível(is) só para o dono" in resp.text
    assert "Comece por aqui" in resp.text


def test_dono_comprovado_ve_detalhes(client, monkeypatch):
    monkeypatch.setattr(main, "run_all_checks", lambda d, **k: fake_report(d))
    monkeypatch.setattr(main, "_baseline", lambda *a: None)
    login(client, "dono@empresa.com.br")
    client.post("/painel/dominios", data={"domain": "empresa.com.br"})
    resp = client.post("/check", data={"domain": "empresa.com.br"})
    assert "joao@empresa.com.br" in resp.text


def test_outro_usuario_nao_ve_detalhes(client, monkeypatch):
    monkeypatch.setattr(main, "run_all_checks", lambda d, **k: fake_report(d))
    login(client, "curioso@gmail.com")
    client.post("/painel/dominios", data={"domain": "empresa.com.br"})  # não comprovado
    resp = client.post("/check", data={"domain": "empresa.com.br"})
    assert "joao@empresa.com.br" not in resp.text


# ------------------------------------------------------------ conta

def test_link_de_entrada_uso_unico(client):
    token = auth.create_login_token("a@empresa.com.br")
    assert client.post("/entrar/confirmar", data={"token": token}, follow_redirects=False).status_code == 303
    assert client.post("/entrar/confirmar", data={"token": token}, follow_redirects=False).status_code == 400


def test_get_do_link_nao_queima_o_token(client):
    """Antivírus de e-mail abrem o link sozinhos: o GET não pode consumir."""
    token = auth.create_login_token("a@empresa.com.br")
    client.get(f"/entrar/confirmar?token={token}")
    client.get(f"/entrar/confirmar?token={token}")
    assert auth.login_token_is_valid(token)


def test_pedido_de_entrada_nao_revela_cadastro(client):
    a = client.post("/entrar", data={"email": "novo@empresa.com.br"})
    login(client, "existe@empresa.com.br")
    client.post("/sair")
    b = client.post("/entrar", data={"email": "existe@empresa.com.br"})
    assert a.status_code == b.status_code == 200
    assert "Confira o seu e-mail" in a.text and "Confira o seu e-mail" in b.text


def test_link_de_entrada_usa_app_base_url_e_nao_o_host(client, monkeypatch):
    sent = {}
    monkeypatch.setattr(notify, "send_email", lambda to, subject, text: sent.setdefault("text", text) or True)
    client.post("/entrar", data={"email": "a@empresa.com.br"}, headers={"host": "site-do-atacante.com"})
    assert "http://testserver/entrar/confirmar?token=" in sent["text"]
    assert "atacante" not in sent["text"]


def test_painel_exige_login(client):
    assert client.get("/painel", follow_redirects=False).headers["location"] == "/entrar"


def test_post_de_outro_site_e_bloqueado(client):
    login(client, "a@empresa.com.br")
    resp = client.post("/painel/dominios", data={"domain": "x.com.br"}, headers={"origin": "https://malicioso.com"})
    assert resp.status_code == 403


def test_dominio_de_outro_usuario_e_404(client, monkeypatch):
    monkeypatch.setattr(main, "_baseline", lambda *a: None)
    login(client, "a@empresa.com.br")
    client.post("/painel/dominios", data={"domain": "empresa.com.br"})
    client.post("/sair")
    login(client, "b@outra.com.br")
    assert client.get("/painel/dominios/1").status_code == 404
    assert client.post("/painel/dominios/1/remover", follow_redirects=False).status_code == 303
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 1


def test_verificacao_por_dns(client, monkeypatch):
    calls = []
    monkeypatch.setattr(main, "_baseline", lambda *a: calls.append(a))
    login(client, "a@gmail.com")
    client.post("/painel/dominios", data={"domain": "empresa.com.br"})
    with db.connect() as conn:
        token = conn.execute("SELECT verify_token FROM domains").fetchone()[0]
    monkeypatch.setattr(verification, "dns_proves_domain", lambda d, t: t == token)
    resp = client.post("/painel/dominios/1/verificar", follow_redirects=False)
    assert "comprovado" in resp.headers["location"]
    with db.connect() as conn:
        assert conn.execute("SELECT verify_method FROM domains").fetchone()[0] == "dns"
    assert calls  # roda a verificação inicial


def test_whatsapp_exige_consentimento(client):
    login(client, "a@empresa.com.br")
    resp = client.post("/painel/avisos", data={"email_alerts": "1", "whatsapp_phone": "(81) 99999-9999"}, follow_redirects=False)
    assert "sem-consentimento" in resp.headers["location"]
    client.post("/painel/avisos", data={"email_alerts": "1", "whatsapp_phone": "(81) 99999-9999", "whatsapp_consent": "1"})
    with db.connect() as conn:
        row = conn.execute("SELECT whatsapp_phone, whatsapp_optin_at FROM users").fetchone()
    assert row["whatsapp_phone"] == "5581999999999" and row["whatsapp_optin_at"]


def test_excluir_conta_apaga_tudo(client, monkeypatch):
    monkeypatch.setattr(main, "_baseline", lambda *a: None)
    login(client, "a@empresa.com.br")
    client.post("/painel/dominios", data={"domain": "empresa.com.br"})
    resp = client.post("/painel/excluir-conta", data={"confirmar": "EXCLUIR"})
    assert "Conta excluída" in resp.text
    with db.connect() as conn:
        for table in ("users", "domains", "sessions"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


# ------------------------------------------------------------ monitoramento

def test_diff_detecta_piora_e_resolucao():
    old = fake_report("e.com.br").snapshot()
    new = fake_report("e.com.br", port_status=Status.CRITICAL).snapshot()
    worse, resolved = monitor.diff(old, new)
    assert len(worse) == 1 and "Portas" in worse[0]
    worse, resolved = monitor.diff(new, old)
    assert not worse and len(resolved) == 1


def test_diff_primeira_verificacao_nao_avisa():
    assert monitor.diff(None, fake_report("e.com.br").snapshot()) == ([], [])


def test_diff_item_novo_no_mesmo_problema():
    old = fake_report("e.com.br").snapshot()
    new = fake_report("e.com.br", extra_private=["joao@e.com.br", "maria@e.com.br"]).snapshot()
    worse, _ = monitor.diff(old, new)
    assert len(worse) == 1 and "novidade" in worse[0]


def test_falha_temporaria_nao_gera_alerta_repetido():
    old = fake_report("e.com.br", port_status=Status.CRITICAL).snapshot()
    flaky = fake_report("e.com.br").snapshot()
    flaky["findings"]["exposed_ports"]["status"] = Status.UNKNOWN.value
    stored = monitor.carry_forward(old, flaky)
    assert stored["findings"]["exposed_ports"]["status"] == Status.CRITICAL.value
    again = fake_report("e.com.br", port_status=Status.CRITICAL).snapshot()
    assert monitor.diff(stored, again) == ([], [])


def test_run_due_avisa_por_email_e_whatsapp(client, monkeypatch):
    monkeypatch.setattr(main, "_baseline", lambda *a: None)
    login(client, "a@empresa.com.br")
    client.post("/painel/dominios", data={"domain": "empresa.com.br"})
    client.post("/painel/avisos", data={"email_alerts": "1", "whatsapp_phone": "81999999999", "whatsapp_consent": "1"})

    reports = iter([fake_report("empresa.com.br"), fake_report("empresa.com.br", port_status=Status.CRITICAL)])
    monkeypatch.setattr(monitor, "run_domain_checks", lambda d: next(reports))
    sent = []
    monkeypatch.setattr(notify, "send_email", lambda to, subject, text: sent.append(("email", to, text)) or True)
    monkeypatch.setattr(notify, "send_whatsapp_alert", lambda phone, d, s, link: sent.append(("wa", phone, s)) or True)

    first = monitor.run_due()          # retrato de referência: nada a avisar
    assert first[0]["worse"] == [] and not sent

    with db.connect() as conn:         # força a próxima verificação
        conn.execute("UPDATE domains SET last_checked_at = '2000-01-01T00:00:00+00:00'")
    second = monitor.run_due()
    assert second[0]["channels"] == ["email", "whatsapp"]
    assert sent[0][0] == "email" and "Portas" in sent[0][2] and "/painel/dominios/1" in sent[0][2]
    assert sent[1][1] == "5581999999999"
    # o e-mail de alerta não leva os detalhes privados (só o resumo)
    assert "joao@" not in sent[0][2]

    assert monitor.run_due() == []     # dentro do intervalo: não verifica de novo
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
        snap = json.loads(conn.execute("SELECT last_snapshot FROM domains").fetchone()[0])
    assert snap["findings"]["exposed_ports"]["status"] == "critical"


def test_dominio_nao_comprovado_nao_e_monitorado(client, monkeypatch):
    login(client, "a@gmail.com")
    client.post("/painel/dominios", data={"domain": "empresa.com.br"})
    monkeypatch.setattr(monitor, "run_domain_checks", lambda d: pytest.fail("não deveria verificar"))
    assert monitor.run_due() == []


def test_gatilho_do_cron_exige_segredo(client):
    assert client.post("/tarefas/monitor").status_code == 401
    assert client.post("/tarefas/monitor", headers={"authorization": "Bearer errado"}).status_code == 401
    resp = client.post("/tarefas/monitor", headers={"authorization": "Bearer segredo-do-cron"})
    assert resp.status_code == 200 and resp.json() == {"verificados": 0, "avisos": 0, "pendentes": 0}


def test_gatilho_do_cron_processa_em_lotes(client, monkeypatch):
    monkeypatch.setattr(main, "_baseline", lambda *a: None)
    monkeypatch.setattr(monitor, "run_domain_checks", lambda d: fake_report(d))
    login(client, "a@empresa.com.br")
    for sub in ("a", "b", "c"):
        client.post("/painel/dominios", data={"domain": f"{sub}.empresa.com.br"})
    auth_header = {"authorization": "Bearer segredo-do-cron"}
    assert client.post("/tarefas/monitor", headers=auth_header).json()["pendentes"] == 1
    assert client.post("/tarefas/monitor", headers=auth_header).json() == {"verificados": 1, "avisos": 0, "pendentes": 0}


def test_paginas_publicas(client):
    for path in ("/", "/metodologia", "/privacidade", "/entrar"):
        assert client.get(path).status_code == 200
    assert "−30" in client.get("/metodologia").text
