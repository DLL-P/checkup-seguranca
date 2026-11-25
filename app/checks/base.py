from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


STATUS_ICON = {
    Status.OK: "\U0001F7E2",
    Status.WARNING: "\U0001F7E1",
    Status.CRITICAL: "\U0001F534",
    Status.UNKNOWN: "⚪",
}

# Ordem de gravidade para desempate na lista do relatório. A NOTA não usa
# mais isto: ela vem da tabela pública de app/scoring.py.
STATUS_WEIGHT = {
    Status.OK: 0,
    Status.WARNING: 1,
    Status.CRITICAL: 3,
    Status.UNKNOWN: 0,
}


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: Status
    message: str
    recommendation: str = ""
    # Detalhes que qualquer visitante pode ver (dados já públicos, como os
    # registros de DNS do domínio).
    details: list[str] = field(default_factory=list)
    # Detalhes que só aparecem para quem comprovou que o domínio é seu (ex.:
    # QUAIS e-mails vazaram, ONDE estão as chaves expostas). Para um visitante
    # anônimo, mostrar isso seria entregar o mapa a um atacante.
    private_details: list[str] = field(default_factory=list)
    # Regra da metodologia que define a pontuação (app/scoring.py). Vazio =
    # "<check_id>:<status>".
    rule: str = ""
    # Preenchido pelo cálculo da nota.
    points: int = 0

    @property
    def rule_key(self) -> str:
        return self.rule or f"{self.check_id}:{self.status.value}"
