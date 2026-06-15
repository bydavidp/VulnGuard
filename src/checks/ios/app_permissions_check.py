"""
Analiza permisos de aplicaciones en iOS (transparencia de privacidad).
"""

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class IosAppPermissionsCheck(SecurityCheck):
    """
    Verifica el estado de la transparencia de permisos en iOS:
      - App Tracking Transparency (ATT)
      - Permisos de aplicaciones (localización, cámara, micrófono)
      - Reporte de privacidad de apps (iOS 15.2+)
    """

    check_id = "ios_app_permissions"
    check_name = "Privacidad y Permisos iOS"
    description = "Verifica la configuración de privacidad y permisos de aplicaciones en iOS"
    severity = Severity.MEDIUM

    def _run(self) -> SecurityCheckResult:
        device_info = {}
        if hasattr(self.device, 'get_info'):
            device_info = self.device.get_info()

        ios_version = device_info.get("ProductVersion", "")
        diagnostics = {}
        if hasattr(self.device, 'run_diagnostics'):
            diagnostics = self.device.run_diagnostics() or {}

        # Versión de iOS para determinar qué características de privacidad están disponibles
        major_version = int(ios_version.split(".")[0]) if ios_version and ios_version[0].isdigit() else 0

        warnings = []
        vulns = []

        # 1. App Tracking Transparency (disponible desde iOS 14.5)
        if major_version >= 14:
            tracking_status = diagnostics.get("com.apple.tracking", "")
            if tracking_status and "disabled" in tracking_status.lower():
                warnings.append("App Tracking: apps NO pueden rastrear (bueno para privacidad)")
            elif tracking_status and "enabled" in tracking_status.lower():
                vulns.append(self._vulnerability(
                    name="Rastreo de apps permitido",
                    description="Las aplicaciones pueden solicitar rastrear tu actividad "
                                "a través de otras apps y sitios web.",
                    recommendation=(
                        "Ve a Ajustes > Privacidad > Rastreo y desactiva 'Permitir "
                        "que las apps soliciten rastrear'."
                    ),
                    cvss=3.0,
                    severity=Severity.LOW,
                    cwe="CWE-200: Exposure of Sensitive Information",
                ))
                warnings.append("Rastreo de apps: PERMITIDO")
        else:
            warnings.append(f"App Tracking Transparency no disponible en iOS {ios_version}")

        # 2. Reporte de privacidad (iOS 15.2+)
        if major_version >= 15:
            # El reporte está disponible en Ajustes > Privacidad > Reporte de privacidad de apps
            warnings.append("Reporte de privacidad de apps disponible (iOS 15.2+) — revísalo periódicamente")

        # 3. Permisos de localización
        location_status = diagnostics.get("com.apple.location", "")
        if location_status and "services" in location_status.lower():
            warnings.append("Servicios de localización: activos")

        # 4. Cámara y micrófono
        camera_status = diagnostics.get("com.apple.camera", "")
        mic_status = diagnostics.get("com.apple.microphone", "")
        if camera_status:
            warnings.append(f"Acceso a cámara: {camera_status}")
        if mic_status:
            warnings.append(f"Acceso a micrófono: {mic_status}")

        # Determinar resultado
        if any("PERMITIDO" in w for w in warnings):
            status = CheckStatus.WARNING
            severity = Severity.MEDIUM
        elif warnings:
            status = CheckStatus.INFO
            severity = Severity.INFO
        else:
            status = CheckStatus.PASSED
            severity = Severity.OK

        detail = f"iOS {ios_version} — {len(warnings)} aspecto(s) de privacidad revisados"
        recommendation_parts = []
        if vulns:
            for v in vulns:
                recommendation_parts.append(f"• {v.recommendation.split('.')[0]}.")
        recommendation_parts.append(
            "✓ Recomendaciones generales:\n"
            "   • Revisa Ajustes > Privacidad > Reporte de privacidad de apps\n"
            "   • Desactiva rastreo de apps en Ajustes > Privacidad > Rastreo\n"
            "   • Revisa permisos de localización, cámara y micrófono regularmente"
        )

        return self._result(
            status=status,
            detail=detail,
            recommendation="\n".join(recommendation_parts),
            vulnerabilities=vulns,
            raw_data={
                "ios_version": ios_version,
                "major_version": major_version,
                "tracking_status": diagnostics.get("com.apple.tracking", "unknown"),
                "warnings": warnings,
            },
            severity=severity,
        )
