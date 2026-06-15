"""
Verifica el tipo y estado del bloqueo de pantalla.
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class ScreenLockCheck(SecurityCheck):
    """
    Verifica:
      - Tipo de bloqueo de pantalla (PIN, patrón, contraseña, ninguno)
      - Tiempo de bloqueo automático
      - Opción "Bloquear con botón de encendido"
    """

    check_id = "screen_lock"
    check_name = "Bloqueo de Pantalla"
    description = "Verifica que el dispositivo tenga un bloqueo de pantalla seguro activado"
    severity = Severity.HIGH

    LOCK_TYPES = {
        "0": "NINGUNO — Sin bloqueo",
        "1": "Patrón",
        "2": "PIN",
        "3": "Contraseña",
        "4": "Deslizamiento (inseguro)",
    }

    LOCK_SCORES = {
        "0": 0,
        "1": 4,
        "2": 6,
        "3": 8,
        "4": 2,
    }

    def _run(self) -> SecurityCheckResult:
        lock_type = "unknown"
        lock_type_label = "Desconocido"
        lock_timeout = 0
        power_button_lock = False
        details = []

        # Método 1: obtener tipo de bloqueo
        try:
            result = subprocess.run(
                ["settings", "get", "system", "screen_lock_type"],
                capture_output=True, text=True, timeout=5
            )
            val = result.stdout.strip()
            if val:
                lock_type = val
                lock_type_label = self.LOCK_TYPES.get(val, f"Tipo {val}")
                details.append(f"Tipo de bloqueo: {lock_type_label}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Método 2: obtener tipo de bloqueo (lockscreen)
        try:
            result = subprocess.run(
                ["locksettings", "get-pattern"],
                capture_output=True, text=True, timeout=5
            )
            if "has pattern" in result.stdout.lower():
                lock_type = "1"
                lock_type_label = "Patrón"
                details.append("Bloqueo por patrón detectado")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        try:
            result = subprocess.run(
                ["locksettings", "get-pin"],
                capture_output=True, text=True, timeout=5
            )
            if "has pin" in result.stdout.lower():
                lock_type = "2"
                lock_type_label = "PIN"
                details.append("Bloqueo por PIN detectado")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        try:
            result = subprocess.run(
                ["locksettings", "get-password"],
                capture_output=True, text=True, timeout=5
            )
            if "has password" in result.stdout.lower():
                lock_type = "3"
                lock_type_label = "Contraseña"
                details.append("Bloqueo por contraseña detectado")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Método 3: tiempo de bloqueo automático
        try:
            result = subprocess.run(
                ["settings", "get", "system", "screen_off_timeout"],
                capture_output=True, text=True, timeout=5
            )
            timeout_str = result.stdout.strip()
            if timeout_str.isdigit():
                lock_timeout = int(timeout_str) // 1000  # ms -> segundos
                details.append(f"Tiempo de bloqueo: {lock_timeout}s")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Método 4: bloqueo con botón de encendido
        try:
            result = subprocess.run(
                ["settings", "get", "secure", "lock_screen_lock_after_timeout"],
                capture_output=True, text=True, timeout=5
            )
            after_timeout = result.stdout.strip()
            if after_timeout:
                details.append(f"Bloqueo tras apagado: {after_timeout}ms")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Determinar resultado
        lock_score = self.LOCK_SCORES.get(lock_type, 0)

        if lock_type in ("0", "4") or lock_score == 0:
            status = CheckStatus.FAILED
            detail = f"⚠️  SIN BLOQUEO DE PANTALLA SEGURO ({lock_type_label})"
            recommendation = (
                "🚨  ACCIÓN INMEDIATA:\n"
                "   • Ve a Ajustes > Seguridad > Bloqueo de pantalla\n"
                "   • Configura PIN o CONTRASEÑA (no patrón)\n"
                "   • Sin bloqueo, cualquiera puede acceder al dispositivo"
            )
            severity = Severity.CRITICAL
            vulns = [self._vulnerability(
                name="Sin bloqueo de pantalla",
                description=f"El dispositivo no tiene bloqueo de pantalla seguro ({lock_type_label}). "
                            f"Cualquier persona con acceso físico puede desbloquearlo.",
                recommendation=recommendation,
                cvss=9.0,
                cwe="CWE-522: Insufficiently Protected Credentials",
            )]
        elif lock_type == "1":
            status = CheckStatus.WARNING
            detail = f"Bloqueo por patrón — seguridad básica"
            recommendation = (
                "⚠️  MEJORA RECOMENDADA:\n"
                "   • Cambia a PIN o contraseña para mayor seguridad\n"
                "   • Los patrones son más fáciles de adivinar por marcas de dedo"
            )
            severity = Severity.MEDIUM
            vulns = [self._vulnerability(
                name="Bloqueo por patrón (débil)",
                description="El bloqueo por patrón es el método menos seguro después de no tener bloqueo. "
                            "Las huellas de dedo pueden revelar el patrón.",
                recommendation=recommendation,
                cvss=5.0,
                cwe="CWE-522: Insufficiently Protected Credentials",
            )]
        else:
            status = CheckStatus.PASSED
            detail = f"✓ Bloqueo de pantalla seguro ({lock_type_label})"
            recommendation = "✓ Método de bloqueo seguro."
            severity = Severity.OK
            vulns = []

        # Advertencia por timeout largo
        if lock_timeout > 300:  # más de 5 minutos
            if not vulns:
                vulns = []
            vulns.append(self._vulnerability(
                name="Tiempo de bloqueo excesivo",
                description=f"El dispositivo tarda {lock_timeout} segundos en bloquearse automáticamente. "
                            f"Esto deja el dispositivo expuesto si se deja desatendido.",
                recommendation="Reduce el tiempo a 30 segundos o menos en Ajustes > Pantalla > Tiempo de espera.",
                cvss=3.5,
                severity=Severity.LOW,
                cwe="CWE-522: Insufficiently Protected Credentials",
            ))
            if status == CheckStatus.PASSED:
                status = CheckStatus.WARNING

        return self._result(
            status=status,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulns,
            raw_data={
                "lock_type": lock_type,
                "lock_type_label": lock_type_label,
                "lock_timeout_seconds": lock_timeout,
                "lock_score": lock_score,
            },
            severity=severity,
        )
