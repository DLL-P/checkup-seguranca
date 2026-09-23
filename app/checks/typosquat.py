from concurrent.futures import ThreadPoolExecutor

import dns.resolver

from .base import CheckResult, Status

MAX_VARIANTS = 40


def _generate_variants(label: str) -> set[str]:
    variants = set()
    n = len(label)

    # omissão de caractere (ex: "empresa" -> "empesa")
    for i in range(n):
        variants.add(label[:i] + label[i + 1:])

    # duplicação de caractere (ex: "empresa" -> "empresaa")
    for i in range(n):
        variants.add(label[:i] + label[i] + label[i:])

    # troca de caracteres adjacentes (ex: "empresa" -> "emrpesa")
    for i in range(n - 1):
        chars = list(label)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        variants.add("".join(chars))

    variants.discard(label)
    variants.discard("")
    return variants


def _resolves(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "A", lifetime=2)
        return True
    except Exception:
        return False


def run(domain: str) -> list[CheckResult]:
    if "." not in domain:
        return []

    label, _, suffix = domain.partition(".")
    variants = list(_generate_variants(label))[:MAX_VARIANTS]
    candidates = [f"{v}.{suffix}" for v in variants]

    found = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for candidate, ok in zip(candidates, executor.map(_resolves, candidates)):
            if ok:
                found.append(candidate)

    if found:
        return [CheckResult(
            check_id="typosquat",
            title="Domínios parecidos com o seu (possível golpe de digitação)",
            status=Status.WARNING,
            message=f"Encontramos {len(found)} domínio(s) parecido(s) com o seu já registrado(s) — variações de erro de digitação do seu nome.",
            recommendation="Confira se algum desses é seu (registro defensivo). Se não for, pode ser alguém tentando se passar pela sua empresa (phishing) aproveitando erros de digitação — considere registrar as variações mais óbvias também.",
            details=found[:10],
        )]
    return [CheckResult(
        check_id="typosquat",
        title="Domínios parecidos com o seu (possível golpe de digitação)",
        status=Status.OK,
        message="Não encontramos variações óbvias do seu domínio já registradas (checagem básica, cobre os erros de digitação mais comuns).",
    )]
