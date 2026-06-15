"""
Verifica el estado de iCloud, Find My iPhone y bloqueo de activación.
"""

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class ICloudCheck(SecurityCheck):
    """
    Verifica:
      - Estado de iCloud (Find My iPhone activo)
      - Bloqueo de activación (Activation Lock)
      - Cuenta iCloud vinculada (si es posible)
      - Copia de seguridad en iCloud habilitada
    """

    check_id = "icloud_status"
    check_name = "iCloud y Find My iPhone"
    description = "Verifica que iCloud, Find My iPhone y Activation Lock estén activos"
    severity = Severity.HIGH

    def _run(self) -> SecurityCheckResult:
        device_info = {}
        if hasattr(self.device, 'get_info'):
            device_info = self.device.get_info()

        # Obtener propiedades relevantes
        activation_state = device_info.get("ActivationState", "unknown")
        icloud_account = device_info.get("iCloudAccount", "")
        find_my_iphone = device_info.get("FindMyPhone", "")
        icloud_backup = ""

        # También intentar con idevicediagnostics
        diagnostics = {}
        if hasattr(self.device, 'run_diagnostics'):
            diagnostics = self.device.run_diagnostics() or {}

        find_my_status = diagnostics.get("com.apple.findmymobile", "")
        icloud_backup = diagnostics.get("com.apple.mobile.backup", "")

        is_activated = activation_state.lower() == "activated"
        has_icloud = bool(icloud_account) or find_my_iphone.lower() == "true"
        has_findmy = find_my_iphone.lower() == "true" or "enabled" in find_my_status.lower()

        issues = []
        vulns = []

        # Verificar Activation Lock
        if not is_activated:
            issues.append("Dispositivo NO activado — posible dispositivo robado o en modo recuperación")
        else:
            # Activation Lock
            al_status = device_info.get("ActivationLock", "")
            if al_status.lower() == "true":
                pass  # Esto es bueno, tiene Activation Lock
            elif al_status:
                issues.append("Activation Lock DESACTIVADO — el dispositivo puede ser borrado sin autorización")

        # Verificar Find My iPhone
        if not has_findmy:
            issues.append("Find My iPhone DESACTIVADO — no se puede localizar el dispositivo si se pierde")
            vulns.append(self._vulnerability(
                name="Find My iPhone desactivado",
                description="Find My iPhone está desactivado. Si el dispositivo se pierde o roba, "
                            "no se podrá localizar, bloquear ni borrar remotamente.",
                recommendation=(
                    "⚠️  ACTIVA FIND MY IPHONE:\n"
                    "   • Ve a Ajustes > [Tu nombre] > Buscar > Buscar mi iPhone\n"
                    "   • Activa también 'Buscar red' para localizarlo aunque esté apagado\n"
                    "   • Sin Find My, el dispositivo no tiene protección antirrobo"
                ),
                cvss=8.0,
                cwe="CWE-287: Improper Authentication",
            ))

        # Verificar Bloqueo de Activación
        activation_lock = device_info.get("ActivationLock", "false")
        if activation_lock.lower() == "false" and is_activated:
            issues.append("Bloqueo de Activación DESACTIVADO — cualquiera puede reactivar el dispositivo")
            if not any("Find My" in v.name for v in vulns):
                vulns.append(self._vulnerability(
                    name="Bloqueo de Activación desactivado",
                    description="El Bloqueo de Activación está desactivado. Cualquier persona puede "
                                "borrar y reactivar el dispositivo sin tu cuenta de iCloud.",
                    recommendation=(
                        "Activa Find My iPhone para habilitar el Bloqueo de Activación.\n"
                        "Esto evita que un ladrón use o venda el dispositivo."
                    ),
                    cvss=7.5,
                    severity=Severity.HIGH,
                ))

        # Verificar respaldo iCloud
        if icloud_backup and "disabled" in icloud_backup.lower():
            issues.append("Respaldo iCloud desactivado — riesgo de pérdida de datos")
        elif not icloud_backup:
            pass  # No se pudo determinar

        status = CheckStatus.FAILED if len(issues) > 1 else (
            CheckStatus.WARNING if len(issues) == 1 else CheckStatus.PASSED
        )
        severity = Severity.HIGH if len(issues) > 1 else (
            Severity.MEDIUM if len(issues) == 1 else Severity.OK
        )

        if vulns:
            detail = f"iCloud: {len(issues)} problema(s) de seguridad"
        else:
            detail = "iCloud y Find My iPhone: configuración segura ✓"

        recommendation_parts = []
        if issues:
            for issue in issues:
                recommendation_parts.append(f"  • {issue}")
        if not issues:
            recommendation_parts.append("✓ Configuración de iCloud y seguridad correcta.")

        return self._result(
            status=status,
            detail=detail,
            recommendation="\n".join(recommendation_parts) if recommendation_parts else "Sin recomendaciones.",
            vulnerabilities=vulns,
            raw_data={
                "activation_state": activation_state,
                "find_my_iphone": find_my_iphone,
                "activation_lock": activation_lock,
                "icloud_account": bool(icloud_account),
                "issues_found": len(issues),
                "diagnostics": diagnostics,
                "device_info_keys": list(device_info.keys()),
            },
            severity=severity,
        )
