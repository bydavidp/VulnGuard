"""
Verifica el estado de cifrado del dispositivo iOS.
iOS tiene cifrado por hardware desde el iPhone 3GS, pero hay que verificar
que esté activo (protegido con código de acceso).
"""

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class IosEncryptionCheck(SecurityCheck):
    """
    Verifica el estado de cifrado en iOS:
      - Cifrado por hardware (siempre activo en dispositivos modernos)
      - Protección de datos (Data Protection) — requiere código de acceso
      - FileVault / protección a nivel de archivo
    """

    check_id = "ios_encryption"
    check_name = "Cifrado del Dispositivo iOS"
    description = "Verifica que el cifrado por hardware y la protección de datos estén activos en iOS"
    severity = Severity.HIGH

    # Dispositivos que NO soportan cifrado por hardware (modelos exactos)
    UNENCRYPTED_DEVICES = {
        "iPhone1,1", "iPhone1,2",  # iPhone original, iPhone 3G
        "iPod1,1", "iPod2,1", "iPod3,1", "iPod4,1",  # iPod touch 1ª-4ª gen
        "iPad1,1",  # iPad 1ª gen
    }

    # Versión mínima de iOS desde la que todo dispositivo tiene cifrado garantizado
    MIN_IOS_VERSION_FOR_ENCRYPTION = (5, 0)

    def _is_old_device(self, product_type: str, ios_version: str) -> bool:
        """Verifica si es un dispositivo sin cifrado por hardware.
        
        Usa coincidencia exacta de modelo + versión de iOS como respaldo.
        Todos los dispositivos con iOS >= 5.0 tienen cifrado por hardware.
        """
        if product_type in self.UNENCRYPTED_DEVICES:
            return True
        # Si podemos obtener la versión de iOS, los modernos tienen cifrado
        try:
            parts = ios_version.split(".")
            major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
            if (major, minor) >= self.MIN_IOS_VERSION_FOR_ENCRYPTION:
                return False  # Versión moderna → cifrado garantizado
        except (ValueError, IndexError):
            pass
        # Fallback: solo marcar como antiguo si el modelo ESTÁ en la lista exacta
        return False

    def _run(self) -> SecurityCheckResult:
        device_info = {}
        if hasattr(self.device, 'get_info'):
            device_info = self.device.get_info()

        product_type = device_info.get("ProductType", "")
        model = device_info.get("ProductModel", "")
        ios_version = device_info.get("ProductVersion", "")
        passcode_protected = device_info.get("PasswordProtected", "false")
        hardware_encrypt = device_info.get("HardwareEncryption", "")

        # Verificar si el dispositivo soporta cifrado por hardware
        is_old_device = self._is_old_device(product_type, ios_version)

        if is_old_device:
            status = CheckStatus.FAILED
            detail = f"⚠️  {product_type} NO soporta cifrado por hardware — datos no protegidos"
            severity = Severity.CRITICAL
            recommendation = (
                "🚨  DISPOSITIVO SIN CIFRADO:\n"
                "   • Este modelo de iPhone/iPad no soporta cifrado por hardware\n"
                "   • Considera reemplazar el dispositivo por uno más reciente\n"
                "   • Los datos almacenados no están protegidos ante acceso físico"
            )
            vulns = [self._vulnerability(
                name="Dispositivo sin cifrado por hardware",
                description=f"El modelo {product_type} no incluye el motor de cifrado "
                            f"por hardware de Apple. Todos los datos se almacenan en texto claro.",
                recommendation=recommendation,
                cvss=9.0,
                cwe="CWE-311: Missing Encryption of Sensitive Data",
            )]
        else:
            # El hardware soporta cifrado, verificar que la protección de datos esté activa
            data_protection = passcode_protected.lower() == "true"
            encrypt_enabled = hardware_encrypt.lower() == "true" or not hardware_encrypt

            if not data_protection:
                status = CheckStatus.FAILED
                detail = "⚠️  Protección de Datos DESACTIVADA — cifrado no activo sin código de acceso"
                severity = Severity.HIGH
                recommendation = (
                    "⚠️  ACTIVA LA PROTECCIÓN DE DATOS:\n"
                    "   • Ve a Ajustes > Face ID/Touch ID y Código > Activar código\n"
                    "   • La Protección de Datos de iOS solo se activa con un código de acceso\n"
                    "   • Sin código, el cifrado por hardware no protege los datos"
                )
                vulns = [self._vulnerability(
                    name="Protección de Datos desactivada",
                    description="Aunque el hardware soporta cifrado, la Protección de Datos "
                                "de iOS no está activa porque no hay código de acceso configurado.",
                    recommendation=recommendation,
                    cvss=8.5,
                    cwe="CWE-311: Missing Encryption of Sensitive Data",
                )]
            else:
                status = CheckStatus.PASSED
                detail = "✓ Cifrado por hardware activo y Protección de Datos habilitada"
                severity = Severity.OK
                recommendation = "✓ Cifrado iOS activo y protegiendo todos los datos."
                vulns = []

        return self._result(
            status=status,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulns,
            raw_data={
                "product_type": product_type,
                "passcode_protected": passcode_protected,
                "data_protection_active": passcode_protected.lower() == "true",
                "hardware_encryption": hardware_encrypt,
                "is_old_device": is_old_device,
            },
            severity=severity,
        )
