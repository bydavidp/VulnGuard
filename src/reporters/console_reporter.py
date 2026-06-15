"""
Genera un reporte formateado para la consola con colores.
"""

from src.core.enums import Severity, CheckStatus, RiskLevel
from src.core.models import AuditReport
from src.reporters.base_reporter import BaseReporter


class ConsoleReporter(BaseReporter):
    """
    Reporter de consola con salida formateada y colores.

    Usa códigos ANSI para colores en terminales que lo soporten.
    """

    # Colores ANSI
    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "orange": "\033[38;5;208m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "magenta": "\033[95m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
        "bg_red": "\033[101m",
        "bg_green": "\033[102m",
        "bg_yellow": "\033[103m",
    }

    # Iconos
    ICONS = {
        Severity.CRITICAL: "🚨",
        Severity.HIGH: "⚠️",
        Severity.MEDIUM: "⚡",
        Severity.LOW: "ℹ️",
        Severity.INFO: "📌",
        Severity.OK: "✅",
        "tip": "💡",
        "shield": "🔒",
        "target": "🎯",
        "report": "📊",
        "file": "💾",
    }

    def __init__(self, report: AuditReport, use_colors: bool = True):
        super().__init__(report)
        self.use_colors = use_colors

    def _c(self, color: str, text: str = "") -> str:
        """Aplica color si está habilitado."""
        if not self.use_colors:
            return text
        color_code = self.COLORS.get(color, "")
        if not text:
            return color_code
        return f"{color_code}{text}{self.COLORS['reset']}"

    def _severity_color(self, severity: Severity) -> str:
        return self._c(severity.color)

    def _status_icon(self, status: CheckStatus) -> str:
        mapping = {
            CheckStatus.PASSED: "✅",
            CheckStatus.FAILED: "❌",
            CheckStatus.ERROR: "❗",
            CheckStatus.SKIPPED: "⏭️",
            CheckStatus.WARNING: "⚠️",
        }
        return mapping.get(status, "❓")

    def generate(self, output_path: str = "") -> str:
        """Genera el reporte de consola completo."""
        lines: list[str] = []
        r = self.report

        # Encabezado
        lines.append("")
        lines.append(self._c("bold") + "=" * 70 + self._c("reset"))
        lines.append(f"{self.ICONS['shield']} {self._c('bold')}VULNGUARD — AUDITORÍA DE SEGURIDAD ANDROID{self._c('reset')}")
        lines.append(f"   {self._c('dim')}Versión: {r.tool_version} | {r.timestamp}{self._c('reset')}")
        lines.append(self._c("bold") + "=" * 70 + self._c("reset"))
        lines.append("")

        # Información del dispositivo
        lines.append(f"{self.ICONS['target']}  {self._c('bold', 'DISPOSITIVO')}")
        lines.append(f"   Modelo:        {r.device_info.model or 'N/A'}")
        lines.append(f"   Fabricante:    {r.device_info.manufacturer or 'N/A'}")
        lines.append(f"   Android:       {r.device_info.android_version or 'N/A'}")
        lines.append(f"   Parche:        {r.device_info.security_patch or 'N/A'}")
        lines.append(f"   SDK:           {r.device_info.sdk_level or 'N/A'}")
        lines.append(f"   Arquitectura:  {r.device_info.architecture or 'N/A'}")
        lines.append(f"   Fingerprint:   {self._c('dim')}{r.device_info.build_fingerprint or 'N/A'}{self._c('reset')}")
        lines.append("")

        # Resumen de riesgo
        risk_color = r.risk_level.color if hasattr(r.risk_level, 'color') else {
            RiskLevel.CRITICAL: "red",
            RiskLevel.HIGH: "orange",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "blue",
            RiskLevel.SAFE: "green",
        }.get(r.risk_level, "reset")

        lines.append(f"{self.ICONS['report']}  {self._c('bold', 'RESUMEN DE RIESGO')}")
        lines.append(f"   Nivel:         {self._c(risk_color, self._c('bold', str(r.risk_level)))}")
        lines.append(f"   Puntaje:       {self._c(risk_color, f'{r.risk_score}/100')}")
        lines.append(f"   Vulnerabil.:   {r.vulnerabilities_found} de {r.total_checks} checks fallaron")
        lines.append(f"   Checks OK:     {r.passed_checks} pasaron")
        lines.append(f"   Duración:      {r.scan_duration_ms}ms")
        lines.append("")

        # Resultados por check
        lines.append(self._c("bold") + "-" * 70 + self._c("reset"))
        lines.append(f"{self._c('bold')}VERIFICACIONES DETALLADAS{self._c('reset')}")
        lines.append(self._c("bold") + "-" * 70 + self._c("reset"))
        lines.append("")

        for result in r.check_results:
            icon = self._status_icon(result.status)
            severity_str = self._severity_color(result.severity) + f"[{result.severity.value}]" + self._c("reset")
            status_str = self._c({
                CheckStatus.PASSED: "green",
                CheckStatus.FAILED: "red",
                CheckStatus.ERROR: "red",
                CheckStatus.WARNING: "yellow",
                CheckStatus.SKIPPED: "dim",
            }.get(result.status, "reset"), result.status.name)

            lines.append(f"  {icon} {self._c('bold', result.check_name)}  {severity_str}  {status_str}")
            lines.append(f"     ID: {self._c('dim')}{result.check_id}{self._c('reset')}")
            lines.append(f"     → {result.detail}")
            lines.append(f"     Duración: {result.duration_ms}ms")

            # Vulnerabilidades
            if result.vulnerabilities:
                for vuln in result.vulnerabilities:
                    vuln_sev = self._severity_color(vuln.severity) + f"[{vuln.severity.value}]" + self._c("reset")
                    lines.append(f"     {self.ICONS.get(Severity.CRITICAL, '⚠️')} {self._c('bold')}{vuln.name}{self._c('reset')} {vuln_sev}")
                    if vuln.cvss_score:
                        lines.append(f"        CVSS: {vuln.cvss_score}")
                    if vuln.cwe_id:
                        lines.append(f"        CWE:  {vuln.cwe_id}")
                    lines.append(f"        {vuln.description}")
            lines.append("")

        # Recomendaciones generales
        if r.recommendations:
            lines.append(self._c("bold") + "=" * 70 + self._c("reset"))
            lines.append(f"{self.ICONS['tip']}  {self._c('bold')}RECOMENDACIONES{self._c('reset')}")
            lines.append(self._c("bold") + "=" * 70 + self._c("reset"))
            for i, rec in enumerate(r.recommendations, 1):
                lines.append(f"  {i}. {rec}")
                lines.append("")

        # Footer
        lines.append(self._c("bold") + "=" * 70 + self._c("reset"))
        lines.append(f"{self.ICONS['file']}  Reporte generado: {r.timestamp}")
        if output_path:
            lines.append(f"   Guardado en: {output_path}")
        lines.append(self._c("bold") + "=" * 70 + self._c("reset"))
        lines.append("")

        output = "\n".join(lines)
        print(output)
        return output
