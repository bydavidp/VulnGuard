"""
Detecta aplicaciones sospechosas instaladas por nombre de paquete.
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SuspiciousAppsCheck(SecurityCheck):
    """
    Escanea aplicaciones instaladas buscando patrones sospechosos
    en nombres de paquete, permisos riesgosos, y orígenes desconocidos.
    """

    check_id = "suspicious_apps"
    check_name = "Aplicaciones Sospechosas"
    description = "Detecta aplicaciones instaladas que podrían ser maliciosas por nombre, origen y permisos"
    severity = Severity.HIGH

    # Patrones en nombre de paquete que podrían indicar malware
    SUSPICIOUS_PATTERNS = [
        "malware", "spy", "tracker", "virus", "hack", "trojan", "ransom",
        "keylog", "rootkit", "backdoor", "rat", "crack", "patched",
        "modded", "stub", "inject", "droidjack", "ahmyth", "omnirat",
    ]

    # Paquetes conocidos de malware/espía
    KNOWN_MALWARE_PACKAGES = [
        "com.estrongs.android.pop",      # ES File Explorer (historial de malware)
        "com.cleanmaster.master",
        "com.snapchat.android",          # NO es malware, pero apps clon sí
        "com.zx2.security",
        "com.dw.installer",
        "com.ludashi.dualspace",
        "com.pspace.secure",
    ]

    # Permisos de alto riesgo
    HIGH_RISK_PERMISSIONS = [
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.CAPTURE_AUDIO_OUTPUT",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
    ]

    def _run(self) -> SecurityCheckResult:
        packages_raw = ""
        suspicious: list[dict] = []
        warnings_list: list[str] = []

        # Obtener lista de paquetes
        try:
            result = subprocess.run(
                ["pm", "list", "packages", "-f"],
                capture_output=True, text=True, timeout=30
            )
            packages_raw = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            # Fallback a listado simple
            try:
                result = subprocess.run(
                    ["pm", "list", "packages"],
                    capture_output=True, text=True, timeout=15
                )
                packages_raw = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError) as e2:
                return self._result(
                    status=CheckStatus.ERROR,
                    detail=f"No se pudo listar paquetes: {e2}",
                    recommendation="Verifica permisos ADB o conectividad del dispositivo.",
                    raw_data={"error": str(e2)},
                    severity=Severity.MEDIUM,
                )

        packages = [
            pkg.replace("package:", "").strip()
            for pkg in packages_raw.strip().split("\n")
            if pkg.strip()
        ]

        # Análisis por nombre de paquete
        for pkg in packages:
            pkg_name = pkg.split("/")[-1] if "/" in pkg else pkg
            pkg_lower = pkg_name.lower()

            # Buscar patrones sospechosos
            for pattern in self.SUSPICIOUS_PATTERNS:
                if pattern in pkg_lower:
                    suspicious.append({
                        "package": pkg_name,
                        "reason": f"patrón sospechoso en nombre: '{pattern}'",
                        "severity": "HIGH",
                    })
                    break

            # Buscar paquetes conocidos de malware
            if pkg_name in self.KNOWN_MALWARE_PACKAGES:
                for i, sp in enumerate(suspicious):
                    if sp["package"] == pkg_name:
                        break
                else:
                    suspicious.append({
                        "package": pkg_name,
                        "reason": "paquete conocido de riesgo",
                        "severity": "MEDIUM",
                    })

            # Aplicaciones con permisos de accesibilidad (alto riesgo)
            if ".accessibility" in pkg_lower or ".access" in pkg_lower:
                if pkg_name not in [s["package"] for s in suspicious]:
                    suspicious.append({
                        "package": pkg_name,
                        "reason": "servicio de accesibilidad (posible abuso)",
                        "severity": "MEDIUM",
                    })

            # Apps de fuentes desconocidas o clonación
            if any(x in pkg_lower for x in ["clone", "dual", "parallel", "2accounts"]):
                suspicious.append({
                    "package": pkg_name,
                    "reason": "app de clonación/múltiples cuentas (riesgo de seguridad)",
                    "severity": "LOW",
                })

        # Verificar instalación de orígenes desconocidos
        try:
            result = subprocess.run(
                ["settings", "get", "global", "install_non_market_apps"],
                capture_output=True, text=True, timeout=5
            )
            val = result.stdout.strip()
            if val == "1":
                warnings_list.append("Instalación de orígenes desconocidos HABILITADA")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Verificar número de apps total (demasiadas apps = mayor superficie de ataque)
        total_apps = len(packages)
        if total_apps > 150:
            warnings_list.append(f"Muchas aplicaciones instaladas ({total_apps}) — mayor superficie de ataque")

        is_vulnerable = len(suspicious) > 0 or len(warnings_list) > 0

        if len(suspicious) > 0:
            status = CheckStatus.FAILED
            detail = f"Se detectaron {len(suspicious)} aplicación(es) sospechosa(s)"
            severity = Severity.HIGH
        elif warnings_list:
            status = CheckStatus.WARNING
            detail = f"{len(warnings_list)} advertencia(s) de seguridad encontrada(s)"
            severity = Severity.MEDIUM
        else:
            status = CheckStatus.PASSED
            detail = f"No se detectaron aplicaciones sospechosas ({total_apps} apps revisadas)"
            severity = Severity.OK

        vulnerability_list = []
        if suspicious:
            apps_str = "\n".join(
                f"   • {s['package']} — {s['reason']}" for s in suspicious
            )
            vulnerability_list.append(self._vulnerability(
                name="Aplicaciones sospechosas detectadas",
                description=f"Se encontraron {len(suspicious)} aplicaciones con indicios de "
                            f"ser maliciosas o de riesgo:\n{apps_str}",
                recommendation=(
                    "⚠️  ACCIONES RECOMENDADAS:\n"
                    "   • Revisa cada app sospechosa en Ajustes > Apps\n"
                    "   • Desinstala las que no reconozcas o no uses\n"
                    "   • Escanea el dispositivo con Malwarebytes o Kaspersky\n"
                    "   • Evita instalar apps fuera de Google Play Store"
                ),
                cvss=7.5,
                cwe="CWE-829: Inclusion of Functionality from Untrusted Sources",
            ))

        if warnings_list and not suspicious:
            for w in warnings_list:
                vulnerability_list.append(self._vulnerability(
                    name="Advertencia de seguridad",
                    description=w,
                    recommendation="Revisa la configuración de seguridad del dispositivo.",
                    severity=Severity.MEDIUM,
                ))

        recommendation = (
            "Revisa y elimina las aplicaciones sospechosas listadas arriba."
            if suspicious
            else "✓ No se detectaron aplicaciones de riesgo."
        )

        return self._result(
            status=status,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulnerability_list,
            raw_data={
                "total_apps": total_apps,
                "suspicious_found": len(suspicious),
                "suspicious_list": suspicious,
                "warnings": warnings_list,
                "install_unknown_sources": "enabled" if "HABILITADA" in str(warnings_list) else "disabled",
            },
            severity=severity,
        )
