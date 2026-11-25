from app import scoring
from app.checks.base import CheckResult, Status


def r(check_id, status, rule="", recommendation="faça algo"):
    return CheckResult(check_id=check_id, title=check_id, status=status, message="", recommendation=recommendation, rule=rule)


def test_sem_problemas_nota_10():
    assert scoring.score([r("spf", Status.OK), r("dmarc", Status.OK)]) == 10


def test_exemplo_da_metodologia():
    # RDP aberto (-30) + sem DMARC (-10) + certificado vencendo (-5) = -45 -> 5,5 -> 6
    results = [r("exposed_ports", Status.CRITICAL), r("dmarc", Status.CRITICAL), r("ssl_cert", Status.WARNING)]
    assert scoring.score(results) == 6
    assert [x.points for x in results] == [30, 10, 5]


def test_arredondamento_comercial():
    # -45 dá 5,5 -> 6 (e não o arredondamento bancário do Python)
    assert scoring.score([r("known_vulns", Status.CRITICAL, "known_vulns:critical"),
                          r("breach_check", Status.CRITICAL)]) == 6
    # -15 dá 8,5 -> 9 (o round() do Python daria 8)
    assert scoring.score([r("breach_check", Status.CRITICAL)]) == 9


def test_desconto_limitado_a_100():
    results = [r("known_vulns", Status.CRITICAL, "known_vulns:ransomware")] * 5
    assert scoring.score(results) == 0


def test_nao_entram_na_nota():
    results = [
        r("cnpj_status", Status.CRITICAL),       # pode ser de fornecedor
        r("phone_reputation", Status.WARNING),   # é sobre quem ligou
        r("breach_check", Status.UNKNOWN),       # não deu para checar
    ]
    assert scoring.score(results) == 10
    assert all(x.points == 0 for x in results)


def test_ransomware_pesa_mais_que_exploracao_comum():
    assert scoring.RULES_BY_KEY["known_vulns:ransomware"].points > scoring.RULES_BY_KEY["known_vulns:critical"].points


def test_top_actions_pela_gravidade():
    results = [r("dkim", Status.WARNING), r("exposed_ports", Status.CRITICAL), r("spf", Status.CRITICAL),
               r("typosquat", Status.WARNING)]
    scoring.score(results)
    top = scoring.top_actions(results)
    assert [x.check_id for x in top] == ["exposed_ports", "spf", "typosquat"]


def test_regras_sem_chave_duplicada():
    keys = [rule.key for rule in scoring.RULES]
    assert len(keys) == len(set(keys))
