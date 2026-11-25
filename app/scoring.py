"""Como a nota de segurança é calculada — a regra é pública.

A mesma tabela abaixo calcula a nota E gera a página /metodologia, então o
que o site explica é exatamente o que o código faz (nunca escrito à mão em
dois lugares).

Princípio: o peso de cada problema segue o risco REAL de virar ataque. Uma
porta de acesso remoto aberta ou uma falha que criminosos já exploram pesa
muito mais do que uma configuração de e-mail incompleta.

A nota começa em 100 pontos; cada problema encontrado desconta os pontos da
sua regra (o total de descontos é limitado a 100). A nota exibida é de 0 a
10: (100 - descontos) / 10, arredondada.

Não entram na nota: checagens que não puderam ser feitas (⚪), o CNPJ (pode
ser de um fornecedor, não da sua empresa) e a checagem de número suspeito
(é sobre quem te ligou, não sobre você).
"""

from dataclasses import dataclass

from .checks.base import CheckResult


@dataclass(frozen=True)
class Rule:
    key: str
    points: int
    label: str
    why: str


RULES: list[Rule] = [
    Rule("known_vulns:ransomware", 35, "Falha no servidor já usada por grupos de ransomware",
         "Está no catálogo KEV da CISA marcada como usada em campanhas de ransomware: é o cenário de maior prejuízo."),
    Rule("known_vulns:critical", 30, "Falha no servidor sendo explorada agora",
         "Está no catálogo KEV da CISA: há exploração confirmada acontecendo no mundo real."),
    Rule("exposed_ports:critical", 30, "Acesso remoto, compartilhamento de arquivos ou banco de dados aberto na internet",
         "RDP, SMB e bancos de dados expostos são a porta de entrada mais comum de ransomware e vazamentos."),
    Rule("ssl_cert:critical", 15, "Certificado do site (HTTPS) vencido",
         "Visitantes veem o alerta de site inseguro e os dados trafegam sem proteção."),
    Rule("breach_check:critical", 15, "E-mails da empresa em vazamentos conhecidos",
         "Senhas vazadas são reaproveitadas para invadir contas (ataque de reutilização de credenciais)."),
    Rule("leaked_secrets:warning", 15, "Possível chave ou senha exposta em código público",
         "Chaves expostas dão acesso direto a sistemas e serviços pagos; exige revisão manual."),
    Rule("known_vulns:warning", 10, "Falha no servidor com alta chance de exploração",
         "EPSS de 10% ou mais: probabilidade alta de ataque nos próximos 30 dias, mesmo sem exploração confirmada ainda."),
    Rule("exposed_ports:warning", 10, "SSH ou FTP aberto na internet",
         "Pode ser legítimo, mas é alvo constante de tentativas de senha."),
    Rule("spf:critical", 10, "Sem proteção SPF no e-mail",
         "Qualquer pessoa consegue mandar e-mail se passando pela empresa."),
    Rule("dmarc:critical", 10, "Sem política DMARC no e-mail",
         "Sem DMARC, os provedores não bloqueiam e-mails falsos em nome da empresa."),
    Rule("ssl_cert:warning", 5, "Certificado do site vence em menos de 15 dias",
         "Se não for renovado, o site passa a mostrar o alerta de inseguro."),
    Rule("typosquat:warning", 5, "Domínios parecidos com o seu registrados por terceiros",
         "Podem ser usados para golpes de phishing que imitam a empresa."),
    Rule("dmarc:warning", 4, "DMARC só em modo de monitoramento",
         "Existe, mas ainda não bloqueia e-mails falsos."),
    Rule("dkim:warning", 4, "Assinatura DKIM não encontrada",
         "Uma das três proteções básicas do e-mail; pode ser falso negativo (o seletor varia por provedor)."),
    Rule("known_vulns:low", 3, "Falhas conhecidas no servidor sem sinal de exploração",
         "Vale atualizar na próxima manutenção, sem urgência."),
]

RULES_BY_KEY = {r.key: r for r in RULES}
MAX_DEDUCTION = 100


def points_for(result: CheckResult) -> int:
    rule = RULES_BY_KEY.get(result.rule_key)
    return rule.points if rule else 0


def score(results: list[CheckResult]) -> int:
    """Preenche result.points e devolve a nota de 0 a 10."""
    total = 0
    for r in results:
        r.points = points_for(r)
        total += r.points
    total = min(total, MAX_DEDUCTION)
    # arredondamento "comercial" (5,5 → 6; 4,5 → 5), como está na metodologia —
    # o round() do Python arredonda 4,5 para 4.
    return (MAX_DEDUCTION - total + 5) // 10


def top_actions(results: list[CheckResult], limit: int = 3) -> list[CheckResult]:
    """Os problemas que mais pesam, para o resumo "comece por aqui"."""
    ranked = sorted((r for r in results if r.points > 0 and r.recommendation), key=lambda r: -r.points)
    return ranked[:limit]
