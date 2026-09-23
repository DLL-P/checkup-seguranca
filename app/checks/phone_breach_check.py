from .base import CheckResult, Status


def run(phone: str | None) -> list[CheckResult]:
    if not phone:
        return []

    # Placeholder intencional: diferente do e-mail (Have I Been Pwned) e do CNPJ
    # (Receita Federal), não existe um provedor de autoatendimento amplamente aceito
    # para checar telefone em vazamentos de dados — os serviços públicos que fazem
    # isso costumam ser corretoras de dados sem procedência clara, e o próprio HIBP
    # restringiu a busca por telefone por risco de abuso (localizar vítimas por
    # número). Preferimos deixar essa checagem inativa a expor um endpoint duvidoso.
    return [CheckResult(
        check_id="phone_breach_check",
        title="Telefone em vazamentos de dados conhecidos",
        status=Status.UNKNOWN,
        message="Essa checagem ainda não está disponível nesta instância.",
        recommendation=(
            "Para ativar, é preciso contratar diretamente um provedor de threat intelligence confiável "
            "(ex: um fornecedor B2B do setor de monitoramento de vazamentos) — não usamos serviços públicos "
            "de busca de telefone por não termos garantia de procedência dos dados."
        ),
    )]
