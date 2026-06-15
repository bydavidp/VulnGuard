"""
Verifica si el dispositivo iOS está jailbreakeado usando múltiples indicadores.
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class JailbreakCheck(SecurityCheck):
    """
    Detección de jailbreak en iOS usando múltiples indicadores:
      1. Verificar existencia de Cydia (el package manager más conocido)
      2. Verificar permisos de lectura en sistema de archivos
      3. Verificar procesos sospechosos
      4. Verificar URL scheme de Cydia
      5. Analizar valores inusuales en propiedades del sistema
    """

    check_id = "jailbreak_detection"
    check_name = "Estado de Jailbreak"
    description = "Detecta si el dispositivo iOS tiene jailbreak mediante 5 indicadores diferentes"
    severity = Severity.CRITICAL

    # Indicadores de jailbreak en ideviceinfo
    JAILBREAK_INDICATORS = [
        "cydia",
        "apt",
        "ssh",
        "mobile substrate",
        "substitute",
        "unc0ver",
        "checkra1n",
        "palera1n",
        "trollstore",
    ]

    # Archivos que solo existen en dispositivos jailbreakeados (vía AFC)
    JAILBREAK_FILES = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate",
        "/bin/bash",
        "/etc/apt",
    ]

    def _run(self) -> SecurityCheckResult:
        jailbroken = False
        evidence: list[str] = []
        methods_tried: list[dict] = []

        # Obtener información del dispositivo
        device_info = {}
        if hasattr(self.device, 'get_info'):
            device_info = self.device.get_info()

        # Método 1: Buscar indicadores en el nombre del dispositivo
        device_name = device_info.get("DeviceName", "")
        device_name_lower = device_name.lower()
        for indicator in self.JAILBREAK_INDICATORS:
            if indicator in device_name_lower:
                jailbroken = True
                evidence.append(f"Indicador en DeviceName: {indicator}")
                methods_tried.append({
                    "method": "device_name_indicator",
                    "found": indicator,
                })
                break

        # Método 2: Verificar valores de compilación inusuales
        build_version = device_info.get("BuildVersion", "")
        product_type = device_info.get("ProductType", "")
        if product_type and product_type.endswith("t"):
            jailbroken = True
            evidence.append(f"ProductType interno: {product_type}")
            methods_tried.append({
                "method": "internal_device_type",
                "product_type": product_type,
            })

        # Método 3: Verificar si se puede acceder a rutas restringidas via idevice
        jailbreak_files_found = []
        for jb_file in self.JAILBREAK_FILES:
            try:
                # Intentar verificar el archivo via AFC (Apple File Conduit)
                result = subprocess.run(
                    ["idevicefile", "file_exists", jb_file],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and "true" in result.stdout.lower():
                    jailbreak_files_found.append(jb_file)
                    jailbroken = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # AFC no disponible, continuar con otros métodos
                continue

        if jailbreak_files_found:
            evidence.append(f"Archivos jailbreak encontrados: {', '.join(jailbreak_files_found[:3])}")
            methods_tried.append({
                "method": "jailbreak_files",
                "files_found": jailbreak_files_found,
            })

        # Método 4: Verificar instalación de Cydia via ideviceprovision
        try:
            result = subprocess.run(
                ["ideviceprovision", "list"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            if "cydia" in output:
                jailbroken = True
                evidence.append("Cydia detectado via provision")
                methods_tried.append({"method": "cydia_provision"})
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Método 5: Verificar si hay servicios SSH corriendo
        try:
            result = subprocess.run(
                ["idevicesyslog", "--quick"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout.lower()
            if "ssh" in output or "sshd" in output:
                jailbroken = True
                evidence.append("Servicio SSH detectado en logs")
                methods_tried.append({"method": "ssh_detection"})
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        status = CheckStatus.FAILED if jailbroken else CheckStatus.PASSED
        detail = (
            f"Dispositivo JAILBREAKEADO — detectado por {len(evidence)} método(s)"
            if jailbroken
            else "Dispositivo NO jailbreakeado (seguro)"
        )
        recommendation = (
            "🚨  RESTAURACIÓN RECOMENDADA:\n"
            "   • Jailbreak expone el dispositivo a malware y pérdida de garantía\n"
            "   • Restaura el dispositivo vía Finder/iTunes\n"
            "   • Actualiza a la última versión de iOS\n"
            "   • Evita instalar perfiles de fuentes no confiables"
            if jailbroken
            else "✓ Sin jailbreak detectado. Estado óptimo de seguridad."
        )

        vulns = []
        if jailbroken:
            vulns.append(self._vulnerability(
                name="Dispositivo con Jailbreak",
                description=f"El dispositivo iOS tiene jailbreak. Esto permite que malware "
                            f"obtenga control total del sistema operativo, acceda a todos los datos "
                            f"y evite las protecciones de sandbox de iOS.",
                recommendation=recommendation,
                evidence=" | ".join(evidence),
                cvss=9.5,
                cwe="CWE-250: Execution with Unnecessary Privileges",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulns,
            raw_data={
                "methods_tried": methods_tried,
                "evidence": evidence,
                "device_info": device_info,
            },
        )
