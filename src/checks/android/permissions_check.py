"""
Analiza permisos otorgados a aplicaciones y detecta sobre-permisos.
"""

import subprocess
import re

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class PermissionsCheck(SecurityCheck):
    """
    Analiza los permisos otorgados a las aplicaciones instaladas,
    detectando aquellas con permisos excesivos o que no corresponden
    a su funcionalidad principal.
    """

    check_id = "permissions_analysis"
    check_name = "Análisis de Permisos"
    description = "Revisa permisos de alto riesgo otorgados a aplicaciones instaladas"
    severity = Severity.MEDIUM

    # Permisos considerados de alto riesgo
    DANGEROUS_PERMISSIONS = {
        "android.permission.CAMERA": "Cámara",
        "android.permission.RECORD_AUDIO": "Micrófono",
        "android.permission.ACCESS_FINE_LOCATION": "Ubicación precisa (GPS)",
        "android.permission.ACCESS_BACKGROUND_LOCATION": "Ubicación en segundo plano",
        "android.permission.READ_SMS": "Leer SMS",
        "android.permission.RECEIVE_SMS": "Recibir SMS",
        "android.permission.SEND_SMS": "Enviar SMS",
        "android.permission.READ_CONTACTS": "Leer contactos",
        "android.permission.READ_CALL_LOG": "Leer registro de llamadas",
        "android.permission.PROCESS_OUTGOING_CALLS": "Interceptar llamadas",
        "android.permission.READ_EXTERNAL_STORAGE": "Leer almacenamiento",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Escribir almacenamiento",
        "android.permission.SYSTEM_ALERT_WINDOW": "Superponer ventanas",
        "android.permission.BIND_ACCESSIBILITY_SERVICE": "Servicio de accesibilidad",
        "android.permission.REQUEST_INSTALL_PACKAGES": "Instalar paquetes",
        "android.permission.QUERY_ALL_PACKAGES": "Listar todas las apps",
        "android.permission.MANAGE_EXTERNAL_STORAGE": "Gestión de almacenamiento",
        "android.permission.INTERNET": "Internet",
        "android.permission.ACCESS_NETWORK_STATE": "Estado de red",
        "android.permission.ACCESS_WIFI_STATE": "Estado WiFi",
        "android.permission.BLUETOOTH": "Bluetooth",
        "android.permission.BLUETOOTH_ADMIN": "Bluetooth (admin)",
        "android.permission.GET_ACCOUNTS": "Obtener cuentas",
    }

    # Apps del sistema que esperamos tengan permisos especiales
    SYSTEM_ALLOWLIST = [
        "com.android.",
        "com.google.",
        "com.samsung.",
        "com.qualcomm.",
        "com.sec.",
        "com.mediatek.",
        "com.xiaomi.",
        "com.oneplus.",
        "com.huawei.",
        "com.oppo.",
        "com.vivo.",
    ]

    def _run(self) -> SecurityCheckResult:
        apps_with_permissions: list[dict] = []
        risk_scores: dict[str, int] = {}

        # Obtener lista de paquetes
        try:
            result = subprocess.run(
                ["pm", "list", "packages"],
                capture_output=True, text=True, timeout=15
            )
            packages = [
                pkg.replace("package:", "").strip()
                for pkg in result.stdout.strip().split("\n")
                if pkg.strip()
            ]
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return self._result(
                status=CheckStatus.ERROR,
                detail=f"No se pudo listar paquetes: {e}",
                recommendation="Verifica conectividad ADB.",
                raw_data={"error": str(e)},
                severity=Severity.MEDIUM,
            )

        for pkg in packages[:100]:  # Limitar a 100 apps para rendimiento
            dangerous_granted = []
            try:
                result = subprocess.run(
                    ["dumpsys", "package", pkg],
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout

                # Buscar permisos otorgados
                granted_match = re.search(
                    r'grantedPermissions:\s*\[(.*?)\]',
                    output,
                    re.DOTALL
                )
                if not granted_match:
                    continue

                granted_str = granted_match.group(1)
                granted_perms = [
                    p.strip() for p in granted_str.split("\n")
                    if p.strip()
                ]

                for perm in granted_perms:
                    if perm in self.DANGEROUS_PERMISSIONS:
                        dangerous_granted.append({
                            "permission": perm,
                            "label": self.DANGEROUS_PERMISSIONS[perm],
                        })

                if dangerous_granted:
                    # Calcular puntaje de riesgo para esta app
                    score = sum(
                        3 if "CAMERA" in d["permission"] or "RECORD_AUDIO" in d["permission"] or
                                "ACCESS_FINE_LOCATION" in d["permission"] or "READ_SMS" in d["permission"]
                        else 2 if "CONTACTS" in d["permission"] or "CALL_LOG" in d["permission"]
                        else 1
                        for d in dangerous_granted
                    )

                    apps_with_permissions.append({
                        "package": pkg,
                        "dangerous_permissions": dangerous_granted,
                        "risk_score": score,
                        "is_system": any(pkg.startswith(allow) for allow in self.SYSTEM_ALLOWLIST),
                    })
                    risk_scores[pkg] = score

            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # Análisis de resultados
        risky_apps = sorted(
            [a for a in apps_with_permissions if a["risk_score"] >= 5],
            key=lambda x: x["risk_score"],
            reverse=True
        )

        total_analyzed = min(len(packages), 100)
        if risky_apps:
            status = CheckStatus.WARNING
            detail = (f"Se encontraron {len(risky_apps)} aplicación(es) con permisos excesivos "
                      f"(de {len(apps_with_permissions)} con permisos peligrosos)")
            severity = Severity.MEDIUM
        elif apps_with_permissions:
            status = CheckStatus.WARNING
            detail = f"{len(apps_with_permissions)} apps tienen permisos peligrosos (riesgo bajo)"
            severity = Severity.LOW
        else:
            status = CheckStatus.PASSED
            detail = f"No se detectaron aplicaciones con permisos excesivos ({total_analyzed} analizadas)"
            severity = Severity.OK

        vulns = []
        if risky_apps:
            top_risky = risky_apps[:5]
            apps_detail = "\n".join(
                f"   • {a['package']} — {a['risk_score']} pts ({', '.join(d['label'] for d in a['dangerous_permissions'][:5])})"
                for a in top_risky
            )
            vulns.append(self._vulnerability(
                name="Permisos excesivos en aplicaciones",
                description=(
                    f"Se detectaron aplicaciones con permisos que exceden lo necesario:\n"
                    f"{apps_detail}\n"
                    f"Total: {len(risky_apps)} apps con riesgo alto, "
                    f"{len(apps_with_permissions)} con algún permiso peligroso"
                ),
                recommendation=(
                    "⚠️  REVISIÓN DE PERMISOS RECOMENDADA:\n"
                    "   • Ve a Ajustes > Apps > [App] > Permisos\n"
                    "   • Revoca permisos que no sean estrictamente necesarios\n"
                    "   • Desinstala apps que pidan muchos permisos sin justificación\n"
                    "   • Usa el administrador de permisos de Android 11+"
                ),
                cvss=6.0,
                cwe="CWE-250: Execution with Unnecessary Privileges",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=(
                "Revisa y revoca permisos innecesarios en las aplicaciones señaladas."
                if risky_apps
                else "✓ Permisos de aplicaciones dentro de lo esperado."
            ),
            vulnerabilities=vulns,
            raw_data={
                "total_analyzed": total_analyzed,
                "apps_with_dangerous_perms": len(apps_with_permissions),
                "high_risk_apps": len(risky_apps),
                "top_risky_apps": [
                    {"package": a["package"], "risk_score": a["risk_score"]}
                    for a in risky_apps[:10]
                ],
            },
            severity=severity,
        )
