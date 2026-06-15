"""
Genera un reporte en formato JSON estructurado.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.models import AuditReport
from src.reporters.base_reporter import BaseReporter
from src.utils.logger import get_logger

logger = get_logger(__name__)


class JsonReporter(BaseReporter):
    """
    Genera un reporte JSON con:
      - Metadatos de la auditoría
      - Información del dispositivo
      - Resultados detallados con severidad y CVSS
      - Recomendaciones
      - Score de riesgo

    El formato es compatible con herramientas de SIEM y dashboards.
    """

    def __init__(self, report: AuditReport, pretty: bool = True):
        super().__init__(report)
        self.pretty = pretty

    def generate(self, output_path: str = "") -> str:
        """Genera el reporte JSON."""
        data = self._build_report_data()

        if self.pretty:
            json_str = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        else:
            json_str = json.dumps(data, ensure_ascii=False, default=str)

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json_str, encoding="utf-8")
            logger.info(f"Reporte JSON guardado: {path}")
        else:
            # Generar nombre automático
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            filename = f"vulnguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = reports_dir / filename
            filepath.write_text(json_str, encoding="utf-8")
            logger.info(f"Reporte JSON guardado: {filepath}")

            # También imprimir resumen en consola
            summary = data["summary"]
            print(f"\n📊 Reporte JSON generado: {filepath}")
            print(f"   Riesgo: {summary['risk_level']} ({summary['risk_score']}/100)")
            print(f"   Checks: {summary['passed']}✅ / {summary['failed']}❌ / {summary['total_checks']} total")

        return json_str

    def _build_report_data(self) -> dict[str, Any]:
        """Construye la estructura completa del reporte."""
        r = self.report

        # Agrupar resultados por severidad
        severity_counts: dict[str, int] = {}
        vulnerability_details: list[dict] = []

        for result in r.check_results:
            sev = result.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            for vuln in result.vulnerabilities:
                vulnerability_details.append({
                    "check_id": result.check_id,
                    "check_name": result.check_name,
                    "vulnerability": vuln.name,
                    "severity": vuln.severity.value,
                    "description": vuln.description,
                    "recommendation": vuln.recommendation,
                    "cvss_score": vuln.cvss_score,
                    "cwe_id": vuln.cwe_id,
                    "evidence": vuln.evidence,
                })

        # Calcular estadísticas por severidad
        severity_stats = {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
            "INFO": severity_counts.get("INFO", 0),
            "OK": severity_counts.get("OK", 0),
            "PASSED": r.passed_checks,
            "FAILED": r.failed_checks,
        }

        data = {
            "metadata": {
                "tool": "VulnGuard",
                "version": r.tool_version,
                "timestamp": r.timestamp,
                "scan_duration_ms": r.scan_duration_ms,
                "generated_by": "VulnGuard Android Security Auditor",
            },
            "device": r.device_info.to_dict(),
            "summary": {
                "total_checks": r.total_checks,
                "passed": r.passed_checks,
                "failed": r.failed_checks,
                "vulnerabilities_found": r.vulnerabilities_found,
                "risk_score": r.risk_score,
                "risk_level": str(r.risk_level),
                "risk_level_numeric": {
                    "SAFE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5,
                }.get(r.risk_level.value.upper(), 0),
                "severity_breakdown": severity_stats,
                "vulnerability_count": len(vulnerability_details),
            },
            "vulnerabilities": vulnerability_details,
            "results": [result.to_dict() for result in r.check_results],
            "recommendations": r.recommendations,
        }

        return data
