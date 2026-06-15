"""
Verifica configuraciones de backup y ADB backup.
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class BackupCheck(SecurityCheck):
    """
    Verifica:
      - ADB Backup habilitado
      - Backup en la nube (Google)
      - Auto-restore
    """

    check_id = "backup_config"
    check_name = "Configuración de Backup"
    description = "Verifica configuraciones de backup que podrían exponer datos"
    severity = Severity.MEDIUM

    def _run(self) -> SecurityCheckResult:
        issues: list[str] = []
        details: list[str] = []

        # 1. ADB Backup
        try:
            result = subprocess.run(
                ["settings", "get", "global", "adb_backup_fullbackup"],
                capture_output=True, text=True, timeout=5
            )
            adb_backup = result.stdout.strip()
            if adb_backup == "1":
                issues.append("ADB Backup habilitado (permite extraer datos completos por USB)")
                details.append("ADB Backup: HABILITADO")
            else:
                details.append("ADB Backup: deshabilitado ✓")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 2. Backup automático (Google)
        try:
            result = subprocess.run(
                ["settings", "get", "secure", "backup_enabled"],
                capture_output=True, text=True, timeout=5
            )
            backup_enabled = result.stdout.strip()
            if backup_enabled == "1":
                details.append("Backup en la nube: activo")
            else:
                issues.append("Backup en la nube DESACTIVADO (riesgo de pérdida de datos)")
                details.append("Backup en la nube: desactivado")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 3. Auto restore
        try:
            result = subprocess.run(
                ["settings", "get", "secure", "backup_auto_restore"],
                capture_output=True, text=True, timeout=5
            )
            auto_restore = result.stdout.strip()
            if auto_restore == "1":
                details.append("Auto-restore: activo ✓")
            else:
                details.append("Auto-restore: desactivado")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 4. Google backup transport
        try:
            result = subprocess.run(
                ["settings", "get", "secure", "backup_transport"],
                capture_output=True, text=True, timeout=5
            )
            transport = result.stdout.strip()
            if "android" in transport or "gms" in transport:
                details.append(f"Transporte de backup: Google ({transport.split('.')[-1]})")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 5. Verificar si hay backup local
        try:
            result = subprocess.run(
                ["settings", "get", "global", "backup_manager_constants"],
                capture_output=True, text=True, timeout=5
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        if any("HABILITADO" in d and "ADB" in d for d in details):
            status = CheckStatus.FAILED
            detail = "ADB Backup habilitado — datos exportables por USB"
            severity = Severity.HIGH
        elif issues:
            status = CheckStatus.WARNING
            detail = "; ".join(issues[:3])
            severity = Severity.MEDIUM
        else:
            status = CheckStatus.PASSED
            detail = "Configuración de backup sin riesgos"
            severity = Severity.OK

        vulns = []
        if any("ADB Backup" in issue for issue in issues):
            vulns.append(self._vulnerability(
                name="ADB Backup habilitado",
                description="ADB Backup permite extraer copias completas del dispositivo "
                            "incluyendo datos de aplicaciones, configuraciones y credenciales.",
                recommendation=(
                    "⚠️  DESACTIVA ADB BACKUP:\n"
                    "   • Ve a Ajustes > Opciones de Desarrollo\n"
                    "   • Busca 'ADB Backup' y desactívalo\n"
                    "   • O ejecuta: adb shell settings put global adb_backup_fullbackup 0"
                ),
                cvss=6.5,
                cwe="CWE-200: Exposure of Sensitive Information",
            ))

        if any("DESACTIVADO" in issue for issue in issues):
            vulns.append(self._vulnerability(
                name="Backup en la nube desactivado",
                description="El backup automático en la nube está desactivado. "
                            "Si el dispositivo se pierde o daña, los datos pueden perderse.",
                recommendation=(
                    "Activa el backup en Ajustes > Google > Backup\n"
                    "Asegura tus datos en caso de pérdida o daño del dispositivo."
                ),
                severity=Severity.LOW,
                cvss=2.5,
                cwe="CWE-312: Cleartext Storage of Sensitive Information",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=(
                "Revisa y corrige las configuraciones de backup señaladas."
                if issues
                else "✓ Backup configurado correctamente."
            ),
            vulnerabilities=vulns,
            raw_data={
                "issues": issues,
                "details": details,
            },
            severity=severity,
        )
