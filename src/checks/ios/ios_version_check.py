"""
Verifica la versión de iOS y el estado de actualizaciones.
"""

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class IOSVersionCheck(SecurityCheck):
    """
    Verifica:
      - Versión de iOS instalada
      - Build version
      - Si hay actualizaciones disponibles (aproximación)
      - Modelo del dispositivo
    """

    check_id = "ios_version"
    check_name = "Versión de iOS"
    description = "Verifica que el dispositivo tenga una versión moderna de iOS con soporte de seguridad"
    severity = Severity.HIGH

    # Versiones iOS y su soporte
    IOS_VERSIONS = {
        "18": "iOS 18 (2024) — Actual",
        "17": "iOS 17 (2023) — Actual",
        "16": "iOS 16 (2022) — Soportado",
        "15": "iOS 15 (2021) — Parches limitados",
        "14": "iOS 14 (2020) — Obsoleto",
        "13": "iOS 13 (2019) — Sin soporte",
        "12": "iOS 12 (2018) — Sin soporte",
    }

    def _run(self) -> SecurityCheckResult:
        ios_version = self.adb.get_property("ProductVersion") if hasattr(self.adb, 'get_property') else ""
        build = self.adb.get_property("BuildVersion") if hasattr(self.adb, 'get_property') else ""
        model = self.adb.get_property("ProductType") if hasattr(self.adb, 'get_property') else ""
        device_name = self.adb.get_property("DeviceName") if hasattr(self.adb, 'get_property') else ""

        if not ios_version:
            return self._result(
                status=CheckStatus.ERROR,
                detail="No se pudo determinar la versión de iOS",
                recommendation="Verifica que el dispositivo esté conectado y desbloqueado.",
                severity=Severity.MEDIUM,
            )

        # Extraer versión principal
        major_version = ios_version.split(".")[0] if "." in ios_version else ios_version

        version_info = self.IOS_VERSIONS.get(major_version, f"iOS {ios_version} — Versión desconocida")
        is_obsolete = major_version in ("12", "13", "14")
        is_limited = major_version == "15"

        if is_obsolete:
            status = CheckStatus.FAILED
            severity = Severity.HIGH
            detail = f"iOS {ios_version} — versión obsoleta sin parches de seguridad"
            recommendation = (
                "⚠️  ACTUALIZACIÓN REQUERIDA:\n"
                "   • Ve a Ajustes > General > Actualización de software\n"
                "   • Las versiones antiguas de iOS tienen vulnerabilidades conocidas\n"
                "   • Si tu modelo no soporta iOS 15+, considera reemplazar el dispositivo"
            )
            vulns = [self._vulnerability(
                name=f"iOS {ios_version} sin soporte",
                description=f"El dispositivo ejecuta iOS {ios_version}, una versión que ya no recibe "
                            f"actualizaciones de seguridad de Apple.",
                recommendation=recommendation,
                cvss=8.0,
                cwe="CWE-1104: Use of Unmaintained Third-Party Components",
            )]
        elif is_limited:
            status = CheckStatus.WARNING
            severity = Severity.MEDIUM
            detail = f"iOS {ios_version} — soporte limitado"
            recommendation = "Actualiza a iOS 16+ para mejor seguridad."
            vulns = [self._vulnerability(
                name="iOS con soporte limitado",
                description=f"iOS {ios_version} recibe solo parches críticos.",
                recommendation=recommendation,
                cvss=5.0,
                severity=Severity.MEDIUM,
            )]
        else:
            status = CheckStatus.PASSED
            severity = Severity.OK
            detail = f"iOS {ios_version} ({build}) — {version_info}"
            recommendation = "✓ Versión actualizada."
            vulns = []

        raw_detail = detail
        if model:
            detail += f" | Modelo: {model}"
        if device_name:
            detail += f" | {device_name}"

        return self._result(
            status=status,
            detail=raw_detail,
            recommendation=recommendation,
            vulnerabilities=vulns,
            raw_data={
                "ios_version": ios_version,
                "build": build,
                "model": model,
                "device_name": device_name,
            },
            severity=severity,
        )
