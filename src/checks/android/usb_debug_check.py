"""
Verifica el estado de USB Debugging y ADB sobre red.
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class USBDebugCheck(SecurityCheck):
    """
    Verifica:
      - USB Debugging habilitado/deshabilitado
      - ADB over TCP/IP (puerto 5555)
      - Configuración de desarrollo
    """

    check_id = "usb_debugging"
    check_name = "USB Debugging y ADB"
    description = "Verifica que USB Debugging esté deshabilitado y ADB no esté expuesto en red"
    severity = Severity.HIGH

    def _run(self) -> SecurityCheckResult:
        usb_debug_enabled = False
        adb_over_tcp = False
        adb_port = None
        details = []
        vulns = []

        # Método 1: getprop para depuración
        props_to_check = [
            ("persist.adb.tcp.port", "TCP port"),
            ("service.adb.tcp.port", "TCP port (service)"),
            ("ro.debuggable", "Debuggable build"),
            ("dalvik.vm.debug", "Dalvik debug"),
        ]

        debug_props = {}
        for prop, label in props_to_check:
            try:
                result = subprocess.run(
                    ["getprop", prop],
                    capture_output=True, text=True, timeout=5
                )
                value = result.stdout.strip()
                debug_props[prop] = value
                if value and value not in ("0", ""):
                    details.append(f"{label}: {value}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # Método 2: settings global
        try:
            result = subprocess.run(
                ["settings", "get", "global", "adb_enabled"],
                capture_output=True, text=True, timeout=5
            )
            adb_val = result.stdout.strip()
            debug_props["adb_enabled"] = adb_val
            if adb_val == "1":
                usb_debug_enabled = True
                details.append("USB Debugging: HABILITADO")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Método 3: ADB over TCP - verificar puerto
        try:
            result = subprocess.run(
                ["getprop", "persist.adb.tcp.port"],
                capture_output=True, text=True, timeout=5
            )
            tcp_port = result.stdout.strip()
            if tcp_port and tcp_port != "0":
                adb_over_tcp = True
                adb_port = tcp_port
                details.append(f"ADB over TCP/IP en puerto {tcp_port}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Método 4: netstat para verificar puerto 5555
        try:
            result = subprocess.run(
                ["netstat", "-tlnp"],
                capture_output=True, text=True, timeout=10
            )
            if ":5555" in result.stdout:
                adb_over_tcp = True
                adb_port = "5555"
                details.append("Puerto 5555 (ADB) abierto en red")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Determinar resultado
        is_secure = not usb_debug_enabled and not adb_over_tcp

        if adb_over_tcp:
            status = CheckStatus.FAILED
            severity = Severity.CRITICAL
            detail = "⚠️  ADB EXPUESTO EN RED — RIESGO CRÍTICO"
            recommendation = (
                "🚨  ACCIÓN INMEDIATA REQUERIDA:\n"
                "   • Ejecuta: `adb shell settings put global adb_enabled 0`\n"
                "   • Desactiva 'ADB over network' en opciones de desarrollo\n"
                "   • Puerto 5555 abierto permite acceso remoto sin autenticación\n"
                "   • Reinicia el dispositivo después de desactivar"
            )
            vulns.append(self._vulnerability(
                name="ADB expuesto en red",
                description=f"El puerto ADB (5555) está expuesto en la red local. "
                            f"Cualquier dispositivo en la misma red puede conectarse sin autenticación.",
                recommendation=recommendation,
                cvss=9.5,
                cwe="CWE-306: Missing Authentication for Critical Function",
            ))
        elif usb_debug_enabled:
            status = CheckStatus.FAILED
            severity = Severity.HIGH
            detail = "USB Debugging está HABILITADO"
            recommendation = (
                "⚠️  DESACTIVA USB DEBUGGING:\n"
                "   • Ve a Ajustes > Opciones de Desarrollo > USB Debugging\n"
                "   • Desmarca la opción\n"
                "   • Si no usas desarrollo, debe estar siempre desactivado\n"
                "   • Reduce riesgo de ataques por conexión física (juice jacking)"
            )
            vulns.append(self._vulnerability(
                name="USB Debugging habilitado",
                description="USB Debugging está habilitado. Un atacante con acceso físico "
                            "al dispositivo puede ejecutar comandos ADB sin restricciones.",
                recommendation=recommendation,
                cvss=7.0,
                cwe="CWE-250: Execution with Unnecessary Privileges",
            ))
        else:
            status = CheckStatus.PASSED
            severity = Severity.OK
            detail = "USB Debugging deshabilitado y ADB no expuesto en red"
            recommendation = "✓ Configuración segura de depuración."

        return self._result(
            status=status,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulns,
            raw_data={
                "usb_debug_enabled": usb_debug_enabled,
                "adb_over_tcp": adb_over_tcp,
                "adb_port": adb_port,
                "debug_props": debug_props,
            },
            severity=severity,
        )
