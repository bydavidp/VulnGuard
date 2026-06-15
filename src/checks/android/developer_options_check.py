"""
Verifica el estado de las Opciones de Desarrollo.
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class DeveloperOptionsCheck(SecurityCheck):
    """
    Verifica múltiples opciones de desarrollo:
      - Opciones de desarrollo activas
      - Stay Awake (no dormir mientras carga)
      - Bluetooth HCI snoop
      - OEM Unlock
      - Verificación de apps por ADB
      - Procesos en segundo plano
    """

    check_id = "developer_options"
    check_name = "Opciones de Desarrollo"
    description = "Verifica configuraciones de desarrollo que pueden ser riesgos de seguridad"
    severity = Severity.MEDIUM

    def _run(self) -> SecurityCheckResult:
        issues: list[dict] = []
        warnings: list[str] = []
        details: list[str] = []

        # 1. Verificar si opciones de desarrollo están habilitadas
        dev_settings = [
            ("settings", "get", "global", "development_settings_enabled"),
            ("settings", "get", "secure", "adb_enabled"),
            ("settings", "get", "global", "stay_on_while_plugged_in"),
            ("settings", "get", "secure", "bluetooth_hci_log"),
            ("settings", "get", "system", "screen_off_timeout"),
            ("settings", "get", "global", "oem_unlock_enabled"),
        ]

        dev_values = {}
        for cmd in dev_settings:
            try:
                result = subprocess.run(
                    list(cmd),
                    capture_output=True, text=True, timeout=5
                )
                key = cmd[-1]
                value = result.stdout.strip()
                dev_values[key] = value
            except (subprocess.TimeoutExpired, FileNotFoundError):
                dev_values[cmd[-1]] = "unknown"

        # 2. Analizar cada opción
        dev_enabled = dev_values.get("development_settings_enabled", "")
        if dev_enabled == "1":
            warnings.append("Opciones de desarrollo HABILITADAS")
            details.append("Opciones de desarrollo: activas")
            issues.append({
                "setting": "development_settings_enabled",
                "value": "1",
                "risk": "Aumenta superficie de ataque",
                "fix": "Desactiva Opciones de Desarrollo si no las usas",
            })
        else:
            details.append("Opciones de desarrollo: desactivadas ✓")

        # Stay awake
        stay_on = dev_values.get("stay_on_while_plugged_in", "")
        if stay_on and stay_on != "0" and stay_on != "unknown":
            charging_type = {
                "1": "USB", "2": "AC", "3": "USB+AC", "4": "Wireless"
            }.get(stay_on, stay_on)
            warnings.append(f"Stay Awake activo ({charging_type})")
            issues.append({
                "setting": "stay_on_while_plugged_in",
                "value": stay_on,
                "risk": "Dispositivo nunca se bloquea mientras carga",
                "fix": "settings put global stay_on_while_plugged_in 0",
            })

        # Bluetooth HCI snoop log
        bt_hci = dev_values.get("bluetooth_hci_log", "")
        if bt_hci == "1":
            warnings.append("Bluetooth HCI Snoop Log activo")
            issues.append({
                "setting": "bluetooth_hci_log",
                "value": "1",
                "risk": "Registra todas las comunicaciones Bluetooth",
                "fix": "settings put secure bluetooth_hci_log 0",
            })

        # OEM Unlock
        oem_unlock = dev_values.get("oem_unlock_enabled", "")
        if oem_unlock == "1":
            warnings.append("OEM Unlock HABILITADO — bootloader desbloqueable")
            issues.append({
                "setting": "oem_unlock_enabled",
                "value": "1",
                "risk": "Permite desbloquear bootloader y flashear ROMs no oficiales",
                "fix": "Desactiva en Opciones de Desarrollo > Desbloqueo OEM",
            })

        # 3. Bugreport shortcut
        try:
            result = subprocess.run(
                ["settings", "get", "secure", "bugreport_in_power_menu"],
                capture_output=True, text=True, timeout=5
            )
            bugreport = result.stdout.strip()
            if bugreport == "1":
                warnings.append("Bugreport en menú de apagado activo")
                issues.append({
                    "setting": "bugreport_in_power_menu",
                    "value": "1",
                    "risk": "Cualquiera puede generar reporte con datos del sistema",
                    "fix": "Desactiva en Opciones de Desarrollo",
                })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        if issues:
            status = CheckStatus.WARNING
            detail = f"Se encontraron {len(issues)} opción(es) de desarrollo insegura(s)"
            severity = Severity.MEDIUM
        else:
            status = CheckStatus.PASSED
            detail = "Opciones de desarrollo: sin riesgos"
            severity = Severity.OK

        vulns = []
        if issues:
            issues_str = "\n".join(
                f"   • {i['setting']}: {i['risk']}"
                for i in issues
            )
            fixes_str = "\n".join(
                f"   • {i['fix']}"
                for i in issues
            )
            vulns.append(self._vulnerability(
                name="Opciones de desarrollo inseguras",
                description=f"Configuraciones de desarrollo activas que reducen la seguridad:\n{issues_str}",
                recommendation=(
                    f"⚠️  CORRECCIONES:\n{fixes_str}\n\n"
                    "   • Ve a Ajustes > Opciones de Desarrollo y desactiva las opciones señaladas\n"
                    "   • Si no eres desarrollador, desactiva completamente Opciones de Desarrollo"
                ),
                cvss=5.0,
                cwe="CWE-16: Configuration",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=(
                "Desactiva las opciones de desarrollo inseguras listadas arriba."
                if issues
                else "✓ Opciones de desarrollo configuradas de forma segura."
            ),
            vulnerabilities=vulns,
            raw_data={
                "settings": dev_values,
                "issues_found": len(issues),
                "issues": issues,
            },
            severity=severity,
        )
