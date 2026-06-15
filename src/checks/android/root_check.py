"""
Verifica si el dispositivo Android está rooteado usando múltiples métodos.
"""

import subprocess
from typing import Optional

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class RootCheck(SecurityCheck):
    """
    Detección de root usando múltiples técnicas:
      1. `which su` — buscar binario su
      2. `test -f /system/bin/su` — ruta común
      3. `test -f /system/xbin/su` — ruta alternativa
      4. `test -f /sbin/su` — otra ruta
      5. `id` — verificar si el UID es 0
    """

    check_id = "root_detection"
    check_name = "Estado de Root"
    description = "Verifica si el dispositivo Android tiene acceso root mediante 5 métodos diferentes"
    severity = Severity.CRITICAL

    # Rutas comunes del binario su
    SU_PATHS = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/sd/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/bin/failsafe/su",
        "/su/bin/su",
    ]

    def _run(self) -> SecurityCheckResult:
        methods_tried: list[dict] = []
        rooted = False
        evidence: list[str] = []

        # Método 1: which su
        try:
            result = subprocess.run(
                ["which", "su"],
                capture_output=True, text=True, timeout=10
            )
            method1_rooted = result.returncode == 0 and result.stdout.strip()
            methods_tried.append({
                "method": "which su",
                "found": method1_rooted,
                "output": result.stdout.strip() if method1_rooted else "not found",
            })
            if method1_rooted:
                rooted = True
                evidence.append(f"which su: {result.stdout.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            methods_tried.append({"method": "which su", "error": str(e)})

        # Método 2: Buscar binarios su en rutas conocidas
        found_paths = []
        for path in self.SU_PATHS:
            try:
                result = subprocess.run(
                    ["test", "-f", path],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    found_paths.append(path)
                    rooted = True
                    evidence.append(f"su found at: {path}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        methods_tried.append({
            "method": "su binary paths",
            "found_paths": found_paths,
        })

        # Método 3: Verificar UID actual
        try:
            result = subprocess.run(
                ["id"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip()
            is_root_uid = "uid=0" in output
            methods_tried.append({
                "method": "id (UID check)",
                "uid_is_root": is_root_uid,
                "output": output,
            })
            if is_root_uid:
                rooted = True
                evidence.append(f"UID is root: {output}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            methods_tried.append({"method": "id", "error": str(e)})

        # Método 4: Build Tags
        try:
            result = subprocess.run(
                ["getprop", "ro.build.tags"],
                capture_output=True, text=True, timeout=5
            )
            tags = result.stdout.strip()
            is_test_keys = "test-keys" in tags
            methods_tried.append({
                "method": "build tags",
                "test_keys": is_test_keys,
                "tags": tags,
            })
            if is_test_keys:
                evidence.append(f"Build tags: {tags} (test-keys)")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            methods_tried.append({"method": "build tags", "error": str(e)})

        # Método 5: Buscar app Superuser o Magisk
        try:
            result = subprocess.run(
                ["pm", "list", "packages"],
                capture_output=True, text=True, timeout=15
            )
            packages = result.stdout.lower()
            root_apps = []
            for pattern in ["superuser", "magisk", "supersu", "kingroot", "kingoroot"]:
                if pattern in packages:
                    root_apps.append(pattern)

            if root_apps:
                rooted = True
                evidence.append(f"Root management apps: {', '.join(root_apps)}")
            methods_tried.append({
                "method": "root apps detection",
                "found_root_apps": root_apps,
            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            methods_tried.append({"method": "root apps", "error": str(e)})

        status = CheckStatus.FAILED if rooted else CheckStatus.PASSED
        detail = (
            f"Dispositivo ROOTEADO — detectado por {len(evidence)} método(s)"
            if rooted
            else "Dispositivo NO rooteado (seguro)"
        )
        recommendation = (
            "⚠️  RESTAURACIÓN URGENTE RECOMENDADA:\n"
            "   • El root expone el dispositivo a malware y pérdida de garantía\n"
            "   • Considera restaurar firmware oficial vía Odin/SP Flash\n"
            "   • Algunas apps bancarias/no-funcionarán en dispositivos rooteados\n"
            "   • Ejecuta: `adb shell` y revisa los procesos con `ps -A | grep su`"
            if rooted
            else "✓ Sin root detectado. Estado óptimo de seguridad."
        )

        vulns = []
        if rooted:
            vulns.append(self._vulnerability(
                name="Dispositivo con Root",
                description=f"El dispositivo tiene acceso root. Esto permite que malware "
                            f"obtenga control total del sistema operativo.",
                recommendation=recommendation,
                evidence=" | ".join(evidence),
                cvss=9.0,
                cwe="CWE-250: Execution with Unnecessary Privileges",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=recommendation,
            vulnerabilities=vulns,
            raw_data={"methods_tried": methods_tried, "evidence": evidence},
        )
