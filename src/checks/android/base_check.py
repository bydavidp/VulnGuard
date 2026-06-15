"""
Clase base abstracta para todas las verificaciones de seguridad.

Cada check debe:
  - Heredar de SecurityCheck
  - Definir check_id, check_name, description, severity
  - Implementar el método _run() que retorna SecurityCheckResult
"""

from abc import ABC, abstractmethod
from time import perf_counter
from typing import Any, Optional

from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult, Vulnerability
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityCheck(ABC):
    """Clase base para todos los checks de seguridad."""

    # Identificador único del check (snake_case)
    check_id: str = ""
    # Nombre legible del check
    check_name: str = ""
    # Descripción de qué verifica
    description: str = ""
    # Severidad por defecto si se encuentra vulnerable
    severity: Severity = Severity.MEDIUM

    def __init__(self, device_connector: Any = None, options: Optional[dict] = None):
        """
        Args:
            device_connector: Conector del dispositivo (AdbConnector o IOSConnector).
            options: Opciones adicionales para el check.
        """
        self.device = device_connector
        self.options = options or {}

    @abstractmethod
    def _run(self) -> SecurityCheckResult:
        """
        Ejecuta la verificación y retorna el resultado.
        Este método debe ser implementado por cada subclase.
        """
        ...

    def run(self) -> SecurityCheckResult:
        """
        Ejecuta el check con medición de tiempo y manejo de errores.
        Este es el método público que llama el engine.
        """
        start = perf_counter()
        logger.info(f"Ejecutando check: {self.check_id} - {self.check_name}")

        try:
            result = self._run()
        except Exception as e:
            logger.error(f"Error en check {self.check_id}: {e}", exc_info=True)
            result = SecurityCheckResult(
                check_id=self.check_id,
                check_name=self.check_name,
                status=CheckStatus.ERROR,
                severity=self.severity,
                detail=f"Error durante la verificación: {e}",
                error=str(e),
            )

        result.duration_ms = round((perf_counter() - start) * 1000, 2)
        logger.info(f"Check {self.check_id} completado en {result.duration_ms}ms - Estado: {result.status.name}")
        return result

    def _vulnerability(
        self,
        name: str,
        description: str,
        recommendation: str,
        severity: Optional[Severity] = None,
        cvss: Optional[float] = None,
        cwe: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> Vulnerability:
        """Helper para crear una Vulnerability con la severidad del check."""
        return Vulnerability(
            name=name,
            severity=severity or self.severity,
            description=description,
            recommendation=recommendation,
            cvss_score=cvss,
            cwe_id=cwe,
            evidence=evidence,
        )

    def _result(
        self,
        status: CheckStatus,
        detail: str = "",
        recommendation: str = "",
        vulnerabilities: Optional[list[Vulnerability]] = None,
        raw_data: Optional[dict] = None,
        severity: Optional[Severity] = None,
    ) -> SecurityCheckResult:
        """Helper para crear un SecurityCheckResult."""
        return SecurityCheckResult(
            check_id=self.check_id,
            check_name=self.check_name,
            status=status,
            severity=severity or self.severity,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulnerabilities or [],
            raw_data=raw_data or {},
        )

    def __str__(self) -> str:
        return f"[{self.check_id}] {self.check_name}"
