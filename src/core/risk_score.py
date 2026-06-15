"""
Calculadora de puntaje de riesgo basada en CVSS principles.
"""

from .enums import Severity, RiskLevel
from .models import SecurityCheckResult


class RiskScoreCalculator:
    """
    Calcula métricas de riesgo agregadas para un conjunto de resultados.

    Basado en principios de CVSS 3.1 adaptados para auditoría móvil:
      - Severidad base (Base Score)
      - Impacto (Impact)
      - Explotabilidad (Exploitability) - ponderada por cantidad de hallazgos
    """

    WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 0.5,
        Severity.OK: 0.0,
    }

    @classmethod
    def calculate_base_score(cls, results: list[SecurityCheckResult]) -> float:
        """
        Calcula puntaje base: promedio ponderado de severidades.

        Returns:
            float: Puntaje de 0 a 100.
        """
        if not results:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for r in results:
            if r.is_vulnerable:
                weight = cls.WEIGHTS.get(r.severity, 0.0)
                total_weight += weight
                weighted_sum += weight * cls.WEIGHTS.get(r.severity, 0.0)

        if total_weight == 0:
            return 0.0

        raw_score = (weighted_sum / (total_weight)) * 10
        return min(100.0, raw_score)

    @classmethod
    def calculate_impact_score(cls, results: list[SecurityCheckResult]) -> float:
        """
        Calcula puntaje de impacto basado en cantidad y severidad de hallazgos.

        Fórmula: más hallazgos críticos = mayor impacto.
        """
        critical_count = sum(1 for r in results if r.severity == Severity.CRITICAL and r.is_vulnerable)
        high_count = sum(1 for r in results if r.severity == Severity.HIGH and r.is_vulnerable)
        medium_count = sum(1 for r in results if r.severity == Severity.MEDIUM and r.is_vulnerable)

        score = (critical_count * 30) + (high_count * 15) + (medium_count * 5)
        return min(100.0, score)

    @classmethod
    def get_risk_level(cls, score: float) -> RiskLevel:
        """Convierte un puntaje numérico a nivel de riesgo."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        return RiskLevel.SAFE

    @classmethod
    def calculate_all(cls, results: list[SecurityCheckResult]) -> dict:
        """
        Calcula todas las métricas de riesgo.

        Returns:
            dict con base_score, impact_score, final_score, risk_level
        """
        base = cls.calculate_base_score(results)
        impact = cls.calculate_impact_score(results)
        # Final score: 70% base + 30% impacto
        final = (base * 0.7) + (impact * 0.3)
        final = min(100.0, final)

        return {
            "base_score": round(base, 1),
            "impact_score": round(impact, 1),
            "final_score": round(final, 1),
            "risk_level": cls.get_risk_level(final),
            "risk_level_str": str(cls.get_risk_level(final)),
        }
