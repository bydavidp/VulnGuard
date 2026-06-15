"""
Verifica el estado de cifrado del dispositivo Android.
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class EncryptionCheck(SecurityCheck):
    """
    Verifica que el almacenamiento del dispositivo esté cifrado:
      - Cifrado de dispositivo (FBE/FDE)
      - Estado del cifrado via `vold` / `cryptfs`
    """

    check_id = "device_encryption"
    check_name = "Cifrado del Dispositivo"
    description = "Verifica que el almacenamiento interno esté cifrado correctamente"
    severity = Severity.HIGH

    def _run(self) -> SecurityCheckResult:
        encryption_status = "unknown"
        is_encrypted = False
        method = None
        details = []

        # Método 1: cryptfs (cifrado completo)
        try:
            result = subprocess.run(
                ["vdc", "cryptfs", "encryptStatus"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip()
            details.append(f"vdc cryptfs: {output}")
            if "encrypted" in output.lower():
                encryption_status = "encrypted"
                is_encrypted = True
                method = "FDE (Full Disk Encryption)"
            elif "unencrypted" in output.lower():
                encryption_status = "unencrypted"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Método 2: getprop para verificar cifrado
        encryption_props = [
            ("ro.crypto.state", "Crypto state"),
            ("ro.crypto.type", "Crypto type"),
            ("ro.crypto.fde", "FDE enabled"),
            ("ro.crypto.fbe", "FBE enabled"),
        ]

        crypto_info = {}
        for prop, label in encryption_props:
            try:
                result = subprocess.run(
                    ["getprop", prop],
                    capture_output=True, text=True, timeout=5
                )
                value = result.stdout.strip()
                crypto_info[prop] = value
                if value:
                    details.append(f"{label}: {value}")
                    if prop == "ro.crypto.state" and value == "encrypted":
                        is_encrypted = True
                        encryption_status = "encrypted"
                    elif prop == "ro.crypto.type":
                        method = {
                            "block": "FBE (File-Based Encryption)",
                            "file": "FBE (File-Based Encryption)",
                            "default": "FDE (Full Disk Encryption)",
                        }.get(value, f"Tipo: {value}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # Método 3: settings global
        try:
            result = subprocess.run(
                ["settings", "get", "global", "wifi_on"],
                capture_output=True, text=True, timeout=5
            )
            # Si settings funciona, el dispositivo responde bien
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        if is_encrypted:
            status = CheckStatus.PASSED
            detail = f"Almacenamiento cifrado ({method or 'método no determinado'})"
            recommendation = "✓ Cifrado activo. Los datos están protegidos."
        elif encryption_status == "unknown":
            status = CheckStatus.WARNING
            detail = "No se pudo determinar el estado del cifrado"
            recommendation = "Verifica manualmente en Ajustes > Seguridad > Cifrado."
            severity = Severity.MEDIUM
        else:
            status = CheckStatus.FAILED
            detail = "ALMACENAMIENTO NO CIFRADO — datos accesibles sin autenticación"
            recommendation = (
                "🚨  CIFRADO DEL DISPOSITIVO REQUERIDO:\n"
                "   • Ve a Ajustes > Seguridad > Cifrar dispositivo\n"
                "   • Si no aparece, el dispositivo puede no soportarlo\n"
                "   • Sin cifrado, cualquier persona con acceso físico puede leer todos los datos\n"
                "   • En Android 10+, el cifrado debería estar activado por defecto"
            )

        vulns = []
        if not is_encrypted and encryption_status != "unknown":
            vulns.append(self._vulnerability(
                name="Dispositivo sin cifrar",
                description="El almacenamiento interno no está cifrado. Esto significa que "
                            "cualquier persona con acceso físico al dispositivo puede leer "
                            "todos los datos, incluyendo fotos, mensajes y credenciales.",
                recommendation=recommendation,
                cvss=8.5,
                cwe="CWE-311: Missing Encryption of Sensitive Data",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulns,
            raw_data={
                "encryption_status": encryption_status,
                "is_encrypted": is_encrypted,
                "method": method,
                "crypto_properties": crypto_info,
                "details": details,
            },
            severity=severity,
        )
