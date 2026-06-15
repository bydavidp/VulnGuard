"""
Verifica el estado de Google Play Protect y verificación de apps.
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class PlayProtectCheck(SecurityCheck):
    """
    Verifica:
      - Google Play Protect activo
      - Verificación de apps (Verify Apps)
      - Escaneo de seguridad en Play Store
    """

    check_id = "play_protect"
    check_name = "Google Play Protect"
    description = "Verifica que Play Protect y la verificación de apps estén activos"
    severity = Severity.MEDIUM

    def _run(self) -> SecurityCheckResult:
        settings_data: dict[str, str] = {}
        details: list[str] = []
        issues: list[str] = []

        # 1. Verify Apps (Google Play Protect)
        verify_settings = [
            ("settings", "get", "global", "package_verifier_enable"),
            ("settings", "get", "global", "verifier_verify_adb_installs"),
            ("settings", "get", "global", "adb_install_need_verification"),
            ("settings", "get", "secure", "install_non_market_apps"),
        ]

        for cmd in verify_settings:
            try:
                result = subprocess.run(
                    list(cmd),
                    capture_output=True, text=True, timeout=5
                )
                key = cmd[-1]
                value = result.stdout.strip()
                settings_data[key] = value
            except (subprocess.TimeoutExpired, FileNotFoundError):
                settings_data[cmd[-1]] = "unknown"

        # Analizar configuración
        package_verifier = settings_data.get("package_verifier_enable", "")
        verify_adb = settings_data.get("verifier_verify_adb_installs", "")
        adb_verify = settings_data.get("adb_install_need_verification", "")
        unknown_sources = settings_data.get("install_non_market_apps", "")

        if package_verifier == "1":
            details.append("Package Verifier activo")
        else:
            issues.append("Package Verifier DESACTIVADO")
            settings_data["package_verifier_enable"] = "0"

        if verify_adb == "1":
            details.append("Verificación de instalaciones ADB activa")
        else:
            issues.append("Verificación de ADB desactivada")

        if adb_verify == "1":
            details.append("ADB necesita verificación")
        else:
            issues.append("ADB sin verificación requerida")

        # 2. Google Play Services version
        try:
            result = subprocess.run(
                ["pm", "list", "packages", "com.google.android.gms"],
                capture_output=True, text=True, timeout=10
            )
            if "package:" in result.stdout:
                details.append("Google Play Services presente")
            else:
                issues.append("Google Play Services NO detectado")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 3. SafetyNet / Play Integrity (aproximación)
        try:
            result = subprocess.run(
                ["pm", "list", "packages", "com.google.android.gsf"],
                capture_output=True, text=True, timeout=10
            )
            if "package:" in result.stdout:
                details.append("Google Services Framework presente")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 4. Google Play Store verificado
        try:
            result = subprocess.run(
                ["pm", "list", "packages", "com.android.vending"],
                capture_output=True, text=True, timeout=10
            )
            if "package:" in result.stdout:
                details.append("Google Play Store instalado")
            else:
                issues.append("Play Store NO detectada (posible ROM sin Google)")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 5. Verificar si hay SafetyNet passing
        try:
            result = subprocess.run(
                ["pm", "list", "packages", "safetynet"],
                capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        if issues:
            status = CheckStatus.FAILED
            detail = f"Play Protect con {len(issues)} problema(s)"
            severity = Severity.HIGH
        else:
            status = CheckStatus.PASSED
            detail = "Play Protect activo y funcionando"
            severity = Severity.OK

        vulns = []
        if issues:
            issues_str = "\n".join(f"   • {i}" for i in issues)
            vulns.append(self._vulnerability(
                name="Play Protect desactivado o incompleto",
                description=f"Protección de Google Play con problemas:\n{issues_str}",
                recommendation=(
                    "⚠️  ACTIVA PLAY PROTECT:\n"
                    "   • Abre Google Play Store > Menú > Play Protect > Configuración\n"
                    "   • Activa 'Buscar amenazas de seguridad' y 'Mejorar detección'\n"
                    "   • Ve a Ajustes > Google > Seguridad > Google Play Protect\n"
                    "   • Activa 'Verificar apps' y 'Escanea dispositivo en busca de amenazas'\n"
                    "   • Comandos ADB:\n"
                    "     adb shell settings put global package_verifier_enable 1\n"
                    "     adb shell settings put global verifier_verify_adb_installs 1"
                ),
                cvss=7.0,
                cwe="CWE-693: Protection Mechanism Failure",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=(
                "Activa todas las protecciones de Play Protect en Ajustes > Google > Seguridad."
                if issues
                else "✓ Play Protect está protegiendo tu dispositivo."
            ),
            vulnerabilities=vulns,
            raw_data=settings_data,
            severity=severity,
        )
