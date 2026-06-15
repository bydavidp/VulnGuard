"""
Modelos de dominio para la auditoría de seguridad Android.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import Severity, CheckStatus, RiskLevel


@dataclass
class Vulnerability:
    """Representa una vulnerabilidad específica encontrada."""
    name: str
    severity: Severity
    description: str
    recommendation: str
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    evidence: Optional[str] = None
    references: list[str] = field(default_factory=list)


@dataclass
class SecurityCheckResult:
    """
    Resultado de una verificación de seguridad individual.
    Cada check produce una instancia de esta clase.
    """
    check_id: str
    check_name: str
    status: CheckStatus
    severity: Severity = Severity.INFO
    detail: str = ""
    recommendation: str = ""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    error: Optional[str] = None

    @property
    def is_vulnerable(self) -> bool:
        return self.status in (CheckStatus.FAILED, CheckStatus.WARNING)

    @property
    def risk_score(self) -> int:
        """Puntaje de riesgo combinado (0-100)."""
        if self.status == CheckStatus.PASSED:
            return 0
        base = self.severity.score * 10
        if self.status == CheckStatus.FAILED:
            return base
        elif self.status == CheckStatus.WARNING:
            return base // 2
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "status": self.status.name,
            "severity": str(self.severity),
            "detail": self.detail,
            "recommendation": self.recommendation,
            "vulnerable": self.is_vulnerable,
            "risk_score": self.risk_score,
            "vulnerabilities": [
                {
                    "name": v.name,
                    "severity": str(v.severity),
                    "description": v.description,
                    "recommendation": v.recommendation,
                    "cvss_score": v.cvss_score,
                    "cwe_id": v.cwe_id,
                }
                for v in self.vulnerabilities
            ],
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


@dataclass
class DeviceInfo:
    """Información del dispositivo auditado."""
    device_id: str = ""
    model: str = ""
    manufacturer: str = ""
    android_version: str = ""
    security_patch: str = ""
    build_fingerprint: str = ""
    sdk_level: int = 0
    architecture: str = ""
    is_emulator: bool = False
    battery_level: int = 0
    custom_rom: str = ""
    kernel_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "model": self.model,
            "manufacturer": self.manufacturer,
            "android_version": self.android_version,
            "security_patch": self.security_patch,
            "build_fingerprint": self.build_fingerprint,
            "sdk_level": self.sdk_level,
            "architecture": self.architecture,
            "is_emulator": self.is_emulator,
            "battery_level": self.battery_level,
            "custom_rom": self.custom_rom,
            "kernel_version": self.kernel_version,
        }


@dataclass
class AuditReport:
    """
    Reporte completo de auditoría.
    Contiene todos los resultados de las verificaciones,
    información del dispositivo, y métricas de riesgo.
    """
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    device_info: DeviceInfo = field(default_factory=DeviceInfo)
    check_results: list[SecurityCheckResult] = field(default_factory=list)
    vulnerabilities_found: int = 0
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    recommendations: list[str] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    tool_version: str = "2.0.0"

    def add_result(self, result: SecurityCheckResult) -> None:
        self.check_results.append(result)
        self.total_checks += 1
        if result.status == CheckStatus.PASSED:
            self.passed_checks += 1
        else:
            self.failed_checks += 1

    def calculate_risk(self) -> None:
        """Calcula puntaje de riesgo y nivel basado en todos los resultados."""
        if not self.check_results:
            self.risk_score = 0
            self.risk_level = RiskLevel.SAFE
            return

        total_score = sum(r.risk_score for r in self.check_results)
        max_possible = len(self.check_results) * 100
        self.risk_score = min(100, int((total_score / max_possible) * 100)) if max_possible > 0 else 0

        # Determinar nivel de riesgo
        if self.risk_score >= 80:
            self.risk_level = RiskLevel.CRITICAL
        elif self.risk_score >= 60:
            self.risk_level = RiskLevel.HIGH
        elif self.risk_score >= 40:
            self.risk_level = RiskLevel.MEDIUM
        elif self.risk_score >= 20:
            self.risk_level = RiskLevel.LOW
        else:
            self.risk_level = RiskLevel.SAFE

        # Compilar recomendaciones generales
        self.recommendations = [
            r.recommendation
            for r in self.check_results
            if r.recommendation and r.is_vulnerable
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tool_version": self.tool_version,
            "device_info": self.device_info.to_dict(),
            "summary": {
                "total_checks": self.total_checks,
                "passed": self.passed_checks,
                "failed": self.failed_checks,
                "vulnerabilities_found": self.vulnerabilities_found,
                "risk_score": self.risk_score,
                "risk_level": str(self.risk_level),
                "scan_duration_ms": self.scan_duration_ms,
            },
            "results": [r.to_dict() for r in self.check_results],
            "recommendations": self.recommendations,
        }
