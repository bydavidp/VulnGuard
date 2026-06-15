"""
Verifica el estado de SELinux (Enforcing / Permissive / Disabled).
"""

import subprocess

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SELinuxCheck(SecurityCheck):
    """
    Verifica el modo actual de SELinux:
      - Enforcing: seguro
      - Permissive: solo log, no bloquea
      - Disabled: sin protección
    """

    check_id = "selinux_status"
    check_name = "Estado de SELinux"
    description = "Verifica que SELinux esté en modo Enforcing (seguro)"
    severity = Severity.HIGH

    def _run(self) -> SecurityCheckResult:
        mode = "unknown"
        is_secure = False
        error_msg = None

        # Método 1: getenforce
        try:
            result = subprocess.run(
                ["getenforce"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                mode = result.stdout.strip()
                is_secure = mode == "Enforcing"
            else:
                error_msg = result.stderr.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"getenforce falló, intentando getprop: {e}")
            # Método 2: fallback a getprop
            try:
                result = subprocess.run(
                    ["getprop", "ro.build.selinux"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    prop_val = result.stdout.strip()
                    mode = "Enforcing" if prop_val == "1" else "Permissive"
                    is_secure = prop_val == "1"
                else:
                    # Método 3: leer /sys/fs/selinux/enforce
                    result = subprocess.run(
                        ["cat", "/sys/fs/selinux/enforce"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        val = result.stdout.strip()
                        mode = "Enforcing" if val == "1" else "Permissive"
                        is_secure = val == "1"
                    else:
                        error_msg = "No se pudo determinar el modo SELinux"
            except (subprocess.TimeoutExpired, FileNotFoundError) as e2:
                error_msg = str(e2)

        if mode == "Disabled":
            vulnerable = True
            severity = Severity.CRITICAL
        elif mode == "Permissive":
            vulnerable = True
            severity = Severity.HIGH
        elif mode == "Enforcing":
            vulnerable = False
            severity = Severity.OK
        else:
            vulnerable = True
            severity = Severity.MEDIUM

        status = CheckStatus.FAILED if vulnerable else CheckStatus.PASSED

        detail_map = {
            "Enforcing": "SELinux en modo Enforcing — política de seguridad activa ✅",
            "Permissive": "SELinux en modo Permissive — solo registra, NO bloquea ⚠️",
            "Disabled": "SELinux DESHABILITADO — sin protección de control de acceso ⛔",
        }
        detail = detail_map.get(mode, f"SELinux: {mode} — no se pudo determinar el estado ❓")

        recommendations = {
            "Enforcing": "✓ SELinux protegido correctamente.",
            "Permissive": (
                "⚠️  SELinux en modo Permissive:\n"
                "   • Ejecuta: `adb shell setenforce 1` para cambiarlo a Enforcing\n"
                "   • O modifica /system/etc/selinux/config\n"
                "   • Si persiste al reinicio, revisa el kernel o recovery"
            ),
            "Disabled": (
                "⛔  SELinux DESHABILITADO — RIESGO CRÍTICO:\n"
                "   • Reactívalo en el kernel o compilando un boot.img con SELinux activado\n"
                "   • Sin SELinux, cualquier app puede acceder a recursos sin restricciones"
            ),
        }
        recommendation = recommendations.get(mode, f"Error: {error_msg}" if error_msg else "No determinable.")

        vulns = []
        if vulnerable:
            cvss_map = {"Permissive": 7.5, "Disabled": 9.5}
            vulns.append(self._vulnerability(
                name=f"SELinux en modo {mode}",
                description=f"SELinux está en modo {mode}. {detail_map.get(mode, '')}",
                recommendation=recommendation,
                cvss=cvss_map.get(mode, 5.0),
                cwe="CWE-276: Incorrect Default Permissions",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulns,
            raw_data={"selinux_mode": mode, "is_secure": is_secure},
            severity=severity,
        )
