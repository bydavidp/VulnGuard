"""
Genera un reporte HTML profesional, responsivo y visual.
"""

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.core.enums import Severity, CheckStatus, RiskLevel
from src.core.models import AuditReport
from src.reporters.base_reporter import BaseReporter
from src.utils.logger import get_logger

logger = get_logger(__name__)


class HtmlReporter(BaseReporter):
    """
    Genera un reporte HTML auto-contenido con:
      - Dashboard visual con score de riesgo
      - Tarjetas por cada verificación
      - Código de colores por severidad
      - Detalles expandibles
      - Diseño responsive (mobile-friendly)
      - Sin dependencias externas (CSS/JS inline)
    """

    SEVERITY_COLORS = {
        Severity.CRITICAL: {"bg": "#dc3545", "text": "#fff", "label": "CRÍTICO"},
        Severity.HIGH: {"bg": "#fd7e14", "text": "#fff", "label": "ALTO"},
        Severity.MEDIUM: {"bg": "#ffc107", "text": "#000", "label": "MEDIO"},
        Severity.LOW: {"bg": "#0d6efd", "text": "#fff", "label": "BAJO"},
        Severity.INFO: {"bg": "#0dcaf0", "text": "#000", "label": "INFO"},
        Severity.OK: {"bg": "#198754", "text": "#fff", "label": "OK"},
    }

    STATUS_ICONS = {
        CheckStatus.PASSED: "✅",
        CheckStatus.FAILED: "❌",
        CheckStatus.ERROR: "❗",
        CheckStatus.SKIPPED: "⏭️",
        CheckStatus.WARNING: "⚠️",
    }

    RISK_COLORS = {
        RiskLevel.CRITICAL: "#dc3545",
        RiskLevel.HIGH: "#fd7e14",
        RiskLevel.MEDIUM: "#ffc107",
        RiskLevel.LOW: "#0d6efd",
        RiskLevel.SAFE: "#198754",
    }

    RISK_ICONS = {
        "CRÍTICO": "🚨",
        "ALTO": "⚠️",
        "MEDIO": "⚡",
        "BAJO": "ℹ️",
        "SEGURO": "🛡️",
    }

    def generate(self, output_path: str = "") -> str:
        """Genera el reporte HTML completo."""
        html = self._build_html()

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html, encoding="utf-8")
            logger.info(f"Reporte HTML guardado: {path}")
        else:
            # Generar nombre automático
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            filename = f"vulnguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            filepath = reports_dir / filename
            filepath.write_text(html, encoding="utf-8")
            logger.info(f"Reporte HTML guardado: {filepath}")

        print(f"\n🌐 Reporte HTML generado: {filepath}")
        return html

    def _build_html(self) -> str:
        """Construye el HTML completo."""
        r = self.report

        risk_color = self.RISK_COLORS.get(r.risk_level, "#6c757d")
        risk_icon = self.RISK_ICONS.get(str(r.risk_level), "🔍")
        risk_str = str(r.risk_level)

        checks_html = "\n".join(self._render_check(result) for result in r.check_results)

        vuln_count = r.vulnerabilities_found
        vuln_label = "SIN VULNERABILIDADES" if vuln_count == 0 else f"{vuln_count} VULNERABILIDAD{(chr(83) if vuln_count != 1 else '')} DETECTADA{(chr(83) if vuln_count != 1 else '')}"

        total_checks = r.total_checks
        passed = r.passed_checks
        failed = r.failed_checks
        pass_rate = round((passed / total_checks * 100) if total_checks > 0 else 0, 1)
        fail_rate = round((failed / total_checks * 100) if total_checks > 0 else 0, 1)

        # Severity breakdown
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "OK": 0}
        for result in r.check_results:
            sev = result.severity.value
            if sev in severity_counts:
                severity_counts[sev] += 1

        sev_bars = ""
        for sev_name, color_info in [
            ("CRITICAL", self.SEVERITY_COLORS[Severity.CRITICAL]),
            ("HIGH", self.SEVERITY_COLORS[Severity.HIGH]),
            ("MEDIUM", self.SEVERITY_COLORS[Severity.MEDIUM]),
            ("LOW", self.SEVERITY_COLORS[Severity.LOW]),
            ("INFO", self.SEVERITY_COLORS[Severity.INFO]),
            ("OK", self.SEVERITY_COLORS[Severity.OK]),
        ]:
            count = severity_counts.get(sev_name, 0)
            pct = round((count / total_checks * 100) if total_checks > 0 else 0, 1)
            if count > 0:
                sev_bars += f"""
                <div class="sev-row">
                    <span class="sev-label" style="color:{color_info['bg']};">{color_info['label']}</span>
                    <div class="sev-bar-container">
                        <div class="sev-bar" style="width:{pct}%;background:{color_info['bg']};"></div>
                    </div>
                    <span class="sev-count">{count}</span>
                </div>"""

        # Recomendaciones
        recs_html = ""
        if r.recommendations:
            recs_html = '<div class="section"><h2>📋 Recomendaciones</h2><ul class="recs-list">'
            for i, rec in enumerate(r.recommendations, 1):
                recs_html += f"<li><strong>{i}.</strong> {rec.replace(chr(10), '<br>')}</li>"
            recs_html += "</ul></div>"

        # JSON data para posible exportación
        report_json = json.dumps(r.to_dict(), indent=2, ensure_ascii=False, default=str)

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnGuard — Reporte de Seguridad Android</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
       background: #0f0f1a; color: #e0e0e0; line-height: 1.6; }}
.container {{ max-width: 960px; margin: 0 auto; padding: 20px; }}

.header {{ text-align: center; padding: 40px 0 30px; }}
.header h1 {{ font-size: 2em; color: #fff; margin-bottom: 8px; }}
.header .subtitle {{ color: #888; font-size: 0.9em; }}
.header .timestamp {{ color: #666; font-size: 0.8em; margin-top: 4px; }}

.risk-card {{ border-radius: 16px; padding: 30px; margin: 20px 0; text-align: center;
              background: linear-gradient(135deg, {risk_color}22, {risk_color}11);
              border: 1px solid {risk_color}44; }}
.risk-icon {{ font-size: 48px; }}
.risk-level {{ font-size: 2em; font-weight: 800; color: {risk_color}; margin: 10px 0; }}
.risk-score {{ font-size: 3.5em; font-weight: 900; color: {risk_color}; }}
.risk-label {{ color: #aaa; font-size: 0.9em; }}

.metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px; margin: 20px 0; }}
.metric {{ background: #1a1a2e; border-radius: 12px; padding: 16px; text-align: center;
           border: 1px solid #2a2a3e; }}
.metric .value {{ font-size: 1.8em; font-weight: 700; color: #fff; }}
.metric .label {{ font-size: 0.8em; color: #888; margin-top: 4px; }}

.device-info {{ background: #1a1a2e; border-radius: 12px; padding: 20px; margin: 20px 0;
               border: 1px solid #2a2a3e; }}
.device-info h2 {{ font-size: 1.1em; color: #aaa; margin-bottom: 12px; }}
.device-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
.device-item {{ padding: 4px 0; }}
.device-item .key {{ color: #888; font-size: 0.85em; }}
.device-item .value {{ color: #e0e0e0; }}

.severity-stats {{ margin: 20px 0; }}
.sev-row {{ display: flex; align-items: center; margin: 6px 0; gap: 10px; }}
.sev-label {{ width: 70px; font-size: 0.85em; font-weight: 600; text-align: right; }}
.sev-bar-container {{ flex: 1; height: 20px; background: #1a1a2e; border-radius: 10px; overflow: hidden; }}
.sev-bar {{ height: 100%; border-radius: 10px; transition: width 0.5s; }}
.sev-count {{ width: 30px; text-align: center; color: #aaa; font-size: 0.85em; }}

.checks {{ margin: 20px 0; }}
.check-card {{ background: #1a1a2e; border-radius: 12px; margin: 10px 0; overflow: hidden;
              border: 1px solid #2a2a3e; }}
.check-header {{ display: flex; align-items: center; padding: 16px 20px; cursor: pointer;
                transition: background 0.2s; }}
.check-header:hover {{ background: #222244; }}
.check-status {{ font-size: 1.3em; margin-right: 12px; }}
.check-name {{ flex: 1; font-weight: 600; color: #fff; }}
.check-severity {{ padding: 3px 10px; border-radius: 6px; font-size: 0.75em; font-weight: 700;
                  margin-right: 10px; }}
.check-detail {{ font-size: 0.85em; color: #ccc; margin-right: 10px; max-width: 300px; }}
.check-duration {{ color: #666; font-size: 0.8em; }}
.toggle-icon {{ color: #666; font-size: 0.9em; transition: transform 0.2s; }}
.check-body {{ max-height: 0; overflow: hidden; transition: max-height 0.3s ease; }}
.check-body.open {{ max-height: 2000px; }}
.check-body-inner {{ padding: 0 20px 16px; border-top: 1px solid #2a2a3e; }}

.vuln-item {{ background: #2a1a1a; border-left: 3px solid #dc3545; border-radius: 6px; padding: 12px; margin: 10px 0; }}
.vuln-item.severity-high {{ border-left-color: #fd7e14; background: #2a221a; }}
.vuln-item.severity-medium {{ border-left-color: #ffc107; background: #2a2a1a; }}
.vuln-item.severity-low {{ border-left-color: #0d6efd; background: #1a1a2a; }}
.vuln-item.severity-ok {{ border-left-color: #198754; background: #1a2a1a; }}
.vuln-name {{ font-weight: 700; color: #fff; margin-bottom: 4px; }}
.vuln-meta {{ font-size: 0.8em; color: #888; margin-bottom: 6px; }}
.vuln-desc {{ font-size: 0.9em; color: #ccc; margin-bottom: 6px; }}
.vuln-rec {{ font-size: 0.85em; color: #adf; padding: 8px; background: #00000033; border-radius: 6px; }}

.recs-list {{ list-style: none; padding: 0; }}
.recs-list li {{ padding: 8px 12px; margin: 6px 0; background: #1a1a2e; border-radius: 8px;
                border-left: 3px solid #0d6efd; font-size: 0.9em; }}

.footer {{ text-align: center; padding: 20px; color: #555; font-size: 0.8em; }}

@media (max-width: 600px) {{
    .device-grid {{ grid-template-columns: 1fr; }}
    .check-header {{ flex-wrap: wrap; }}
    .check-detail {{ max-width: 100%; margin-top: 6px; }}
    .risk-score {{ font-size: 2.5em; }}
}}

/* Scrollbar */
::-webkit-scrollbar {{ width: 8px; }}
::-webkit-scrollbar-track {{ background: #0f0f1a; }}
::-webkit-scrollbar-thumb {{ background: #333; border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: #555; }}
</style>
</head>
<body>
<div class="container">

<!-- HEADER -->
<div class="header">
    <h1>🛡️ VulnGuard</h1>
    <div class="subtitle">Auditoría de Seguridad Android</div>
    <div class="timestamp">v{r.tool_version} · {r.timestamp}</div>
</div>

<!-- RISK CARD -->
<div class="risk-card">
    <div class="risk-icon">{risk_icon}</div>
    <div class="risk-level">{risk_str}</div>
    <div class="risk-score">{r.risk_score}</div>
    <div class="risk-label">/ 100 — Puntaje de Riesgo</div>
</div>

<!-- METRICS -->
<div class="metrics">
    <div class="metric">
        <div class="value">{vuln_count}</div>
        <div class="label">{vuln_label}</div>
    </div>
    <div class="metric">
        <div class="value">{total_checks}</div>
        <div class="label">Total Checks</div>
    </div>
    <div class="metric">
        <div class="value" style="color:#198754;">{passed}</div>
        <div class="label">Pasaron ({pass_rate}%)</div>
    </div>
    <div class="metric">
        <div class="value" style="color:#dc3545;">{failed}</div>
        <div class="label">Fallaron ({fail_rate}%)</div>
    </div>
    <div class="metric">
        <div class="value">{r.scan_duration_ms}ms</div>
        <div class="label">Duración</div>
    </div>
</div>

<!-- DEVICE INFO -->
<div class="device-info">
    <h2>📱 Dispositivo</h2>
    <div class="device-grid">
        <div class="device-item"><div class="key">Modelo</div><div class="value">{r.device_info.model or 'N/A'}</div></div>
        <div class="device-item"><div class="key">Fabricante</div><div class="value">{r.device_info.manufacturer or 'N/A'}</div></div>
        <div class="device-item"><div class="key">Android</div><div class="value">{r.device_info.android_version or 'N/A'}</div></div>
        <div class="device-item"><div class="key">SDK</div><div class="value">{r.device_info.sdk_level or 'N/A'}</div></div>
        <div class="device-item"><div class="key">Parche Seg.</div><div class="value">{r.device_info.security_patch or 'N/A'}</div></div>
        <div class="device-item"><div class="key">Arquitectura</div><div class="value">{r.device_info.architecture or 'N/A'}</div></div>
    </div>
</div>

<!-- SEVERITY STATS -->
<div class="severity-stats">
    <h2 style="margin-bottom:10px;color:#aaa;font-size:1.1em;">📊 Distribución por Severidad</h2>
    {sev_bars}
</div>

<!-- CHECKS -->
<div class="checks">
    <h2 style="margin-bottom:12px;color:#aaa;font-size:1.1em;">🔍 Verificaciones Detalladas</h2>
    {checks_html}
</div>

<!-- RECOMMENDATIONS -->
{recs_html}

<!-- FOOTER -->
<div class="footer">
    <p>VulnGuard v{r.tool_version} · Generado el {r.timestamp}</p>
    <p>🔒 Auditoría de Seguridad Android · Solo para uso autorizado</p>
</div>

</div>

<script>
// Toggle check details
document.querySelectorAll('.check-header').forEach(header => {{
    header.addEventListener('click', () => {{
        const body = header.nextElementSibling;
        const icon = header.querySelector('.toggle-icon');
        body.classList.toggle('open');
        icon.textContent = body.classList.contains('open') ? '▼' : '▶';
    }});
}});
</script>
</body>
</html>"""

        return html

    def _render_check(self, result) -> str:
        """Renderiza un check individual en HTML."""
        icon = self.STATUS_ICONS.get(result.status, "❓")
        sev_info = self.SEVERITY_COLORS.get(result.severity, {"bg": "#6c757d", "text": "#fff", "label": "N/A"})

        vulns_html = ""
        for vuln in result.vulnerabilities:
            vsev_info = self.SEVERITY_COLORS.get(vuln.severity, {"bg": "#6c757d", "text": "#fff"})
            sev_class = vuln.severity.value.lower()

            vulns_html += f"""
            <div class="vuln-item severity-{sev_class}">
                <div class="vuln-name">{vuln.name}</div>
                <div class="vuln-meta">
                    Severidad: <span style="color:{vsev_info['bg']};font-weight:700;">{vuln.severity.value}</span>
                    {f' | CVSS: {vuln.cvss_score}' if vuln.cvss_score else ''}
                    {f' | CWE: {vuln.cwe_id}' if vuln.cwe_id else ''}
                </div>
                <div class="vuln-desc">{vuln.description[:300]}{'...' if len(vuln.description or '') > 300 else ''}</div>
                <div class="vuln-rec">{vuln.recommendation.replace(chr(10), '<br>')}</div>
            </div>"""

        severity_badge = f'<span class="check-severity" style="background:{sev_info["bg"]};color:{sev_info["text"]};">{sev_info["label"]}</span>'

        status_class = {
            CheckStatus.PASSED: "✅",
            CheckStatus.FAILED: "❌",
            CheckStatus.ERROR: "❗",
            CheckStatus.WARNING: "⚠️",
        }.get(result.status, "❓")

        return f"""
        <div class="check-card">
            <div class="check-header">
                <span class="check-status">{status_class}</span>
                <span class="check-name">{result.check_name}</span>
                {severity_badge}
                <span class="check-detail">{result.detail[:80]}{'...' if len(result.detail) > 80 else ''}</span>
                <span class="check-duration">{result.duration_ms}ms</span>
                <span class="toggle-icon">▶</span>
            </div>
            <div class="check-body">
                <div class="check-body-inner">
                    <p style="color:#ccc;margin:10px 0;"><strong>ID:</strong> {result.check_id}</p>
                    <p style="color:#ccc;margin:10px 0;"><strong>Detalle:</strong> {result.detail}</p>
                    <p style="color:#ccc;margin:10px 0;"><strong>Recomendación:</strong> {result.recommendation.replace(chr(10), '<br>')}</p>
                    {vulns_html}
                </div>
            </div>
        </div>"""
