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

# Usado para calcular a nota geral do relatório.
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
    details: list[str] = field(default_factory=list)
