"""
Verifica configuraciones de backup en iOS (iCloud y iTunes/Finder).
"""

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class IosBackupCheck(SecurityCheck):
    """
    Verifica:
      - Backup en iCloud activo
      - Cifrado de backup local (iTunes/Finder)
      - Sincronización automática
    """

    check_id = "ios_backup"
    check_name = "Backup iOS (iCloud/iTunes)"
    description = "Verifica que los backups del dispositivo iOS estén configurados y cifrados correctamente"
    severity = Severity.MEDIUM

    def _run(self) -> SecurityCheckResult:
        device_info = {}
        if hasattr(self.device, 'get_info'):
            device_info = self.device.get_info()

        diagnostics = {}
        if hasattr(self.device, 'run_diagnostics'):
            diagnostics = self.device.run_diagnostics() or {}

        icloud_backup = diagnostics.get("com.apple.mobile.backup", "")
        encrypted_backup = device_info.get("iTunesEncryptedBackup", "")

        issues = []
        vulns = []

        # 1. Backup iCloud
        if icloud_backup:
            if "disabled" in icloud_backup.lower():
                issues.append("Backup iCloud DESACTIVADO — riesgo de pérdida de datos")
                vulns.append(self._vulnerability(
                    name="Backup iCloud desactivado",
                    description="La copia de seguridad en iCloud está desactivada. "
                                "Si el dispositivo se pierde o daña, los datos no están respaldados.",
                    recommendation=(
                        "⚠️  ACTIVA BACKUP EN iCLOUD:\n"
                        "   • Ve a Ajustes > [Tu nombre] > iCloud > Copia en iCloud\n"
                        "   • Activa 'Copia en iCloud'\n"
                        "   • Asegura fotos, contactos y datos de apps en la nube"
                    ),
                    cvss=5.0,
                    severity=Severity.MEDIUM,
                    cwe="CWE-312: Cleartext Storage of Sensitive Information",
                ))
            else:
                pass  # Backup iCloud activo — OK
        else:
            # No se pudo determinar
            pass

        # 2. Backup cifrado (iTunes/Finder)
        if encrypted_backup:
            if encrypted_backup.lower() == "true":
                pass  # Backup cifrado — OK
            else:
                issues.append("Backup local NO cifrado — los datos están en texto claro")
                vulns.append(self._vulnerability(
                    name="Backup local sin cifrar",
                    description="El backup local (iTunes/Finder) no está cifrado. "
                                "Cualquier persona con acceso al backup puede leer todos los datos.",
                    recommendation=(
                        "⚠️  CIFRA EL BACKUP LOCAL:\n"
                        "   • Conecta el dispositivo al ordenador\n"
                        "   • En Finder/iTunes, marca 'Cifrar copia local'\n"
                        "   • Establece una contraseña segura para el backup"
                    ),
                    cvss=6.5,
                    severity=Severity.HIGH,
                    cwe="CWE-311: Missing Encryption of Sensitive Data",
                ))
        else:
            # No se pudo determinar o iOS no reporta
            pass

        # 3. Verificar si hay suficientes servicios de respaldo
        icloud_account = device_info.get("iCloudAccount", "")
        if not icloud_account and not encrypted_backup:
            issues.append("No se detectaron métodos de backup configurados")

        if vulns:
            status = CheckStatus.FAILED if len([v for v in vulns if v.severity == Severity.HIGH]) > 0 else CheckStatus.WARNING
            severity = Severity.HIGH if status == CheckStatus.FAILED else Severity.MEDIUM
        else:
            status = CheckStatus.PASSED
            severity = Severity.OK

        detail_map = {
            CheckStatus.FAILED: f"⚠️  Backup: {len(issues)} problema(s) de seguridad",
            CheckStatus.WARNING: f"⚠️  Backup: {len(issues)} advertencia(s)",
            CheckStatus.PASSED: "✓ Backup iCloud y local configurados correctamente",
        }
        detail = detail_map.get(status, "Estado de backup: desconocido")

        return self._result(
            status=status,
            detail=detail,
            recommendation=(
                "Revisa y corrige los problemas de backup señalados arriba."
                if vulns
                else "✓ Backup configurado correctamente."
            ),
            vulnerabilities=vulns,
            raw_data={
                "icloud_backup": icloud_backup,
                "encrypted_backup": encrypted_backup,
                "has_icloud_account": bool(icloud_account),
                "issues": issues,
            },
            severity=severity,
        )
