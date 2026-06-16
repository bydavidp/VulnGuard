from enum import Enum, auto


class Severity(Enum):
    """Nivel de severidad de una vulnerabilidad encontrada."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    OK = "OK"

    def __str__(self) -> str:
        return self.value

    @property
    def score(self) -> int:
        mapping = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 5,
            Severity.LOW: 3,
            Severity.INFO: 1,
            Severity.OK: 0,
        }
        return mapping[self]

    @property
    def color(self) -> str:
        mapping = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan",
            Severity.OK: "green",
        }
        return mapping[self]


class CheckStatus(Enum):
    """Estado de ejecución de un check."""
    PASSED = auto()
    FAILED = auto()
    ERROR = auto()
    SKIPPED = auto()
    WARNING = auto()
    INFO = auto()

    def __str__(self) -> str:
        return self.name


class RiskLevel(Enum):
    """Nivel de riesgo general del dispositivo."""
    CRITICAL = "CRÍTICO"
    HIGH = "ALTO"
    MEDIUM = "MEDIO"
    LOW = "BAJO"
    SAFE = "SEGURO"

    def __str__(self) -> str:
        return self.value

    @property
    def score_range(self) -> tuple:
        mapping = {
            RiskLevel.CRITICAL: (80, 100),
            RiskLevel.HIGH: (60, 79),
            RiskLevel.MEDIUM: (40, 59),
            RiskLevel.LOW: (20, 39),
            RiskLevel.SAFE: (0, 19),
        }
        return mapping[self]
