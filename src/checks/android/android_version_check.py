"""
Verifica la versión de Android y el nivel del parche de seguridad.
"""

import subprocess
import re

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class AndroidVersionCheck(SecurityCheck):
    """
    Verifica:
      - Versión de Android (release)
      - API level (SDK)
      - Security patch level
      - Build fingerprint
    """

    check_id = "android_version"
    check_name = "Versión de Android y Parche de Seguridad"
    description = "Verifica que el dispositivo tenga una versión moderna de Android y parche de seguridad reciente"
    severity = Severity.HIGH

    # Versiones mínimas recomendadas por seguridad
    MIN_ANDROID_VERSION = 11   # Android 11 como mínimo recomendado
    MIN_SECURITY_2023 = "2023"  # Parche mínimo: 2023
    SECURE_VERSIONS = {
        "15": "Android 15 (2024) — Mayor seguridad",
        "14": "Android 14 (2023) — Seguro",
        "13": "Android 13 (2022) — Seguro",
        "12": "Android 12 (2021) — Seguro",
        "11": "Android 11 (2020) — Mínimo recomendado",
        "10": "Android 10 (2019) — Obsoleto, sin parches oficiales",
        "9":  "Android 9 Pie (2018) — Sin soporte",
        "8":  "Android 8 Oreo (2017) — Sin soporte",
        "7":  "Android 7 Nougat (2016) — Sin soporte",
        "6":  "Android 6 Marshmallow (2015) — Sin soporte",
        "5":  "Android 5 Lollipop (2014) — Sin soporte",
    }

    def _run(self) -> SecurityCheckResult:
        android_version = ""
        sdk_level = 0
        security_patch = ""
        build_fingerprint = ""

        # Obtener versión de Android
        try:
            result = subprocess.run(
                ["getprop", "ro.build.version.release"],
                capture_output=True, text=True, timeout=5
            )
            android_version = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Obtener SDK level
        try:
            result = subprocess.run(
                ["getprop", "ro.build.version.sdk"],
                capture_output=True, text=True, timeout=5
            )
            sdk_str = result.stdout.strip()
            sdk_level = int(sdk_str) if sdk_str.isdigit() else 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Obtener security patch
        try:
            result = subprocess.run(
                ["getprop", "ro.build.version.security_patch"],
                capture_output=True, text=True, timeout=5
            )
            security_patch = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Obtener fingerprint
        try:
            result = subprocess.run(
                ["getprop", "ro.build.fingerprint"],
                capture_output=True, text=True, timeout=5
            )
            build_fingerprint = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Análisis
        vulns = []
        warnings = []

        # 1. Versión de Android
        version_num = 0
        try:
            version_num = float(android_version.split(".")[0])
        except (ValueError, IndexError):
            pass

        version_outdated = version_num > 0 and version_num < self.MIN_ANDROID_VERSION
        version_unknown = not android_version

        if version_unknown:
            detail = "No se pudo determinar la versión de Android"
            status = CheckStatus.WARNING
            severity = Severity.MEDIUM
        elif version_outdated:
            detail = f"Android {android_version} — versión obsoleta y sin soporte de seguridad"
            status = CheckStatus.FAILED
            severity = Severity.HIGH
            vulns.append(self._vulnerability(
                name=f"Android {android_version} sin soporte",
                description=f"El dispositivo ejecuta Android {android_version}, una versión que ya no recibe "
                            f"parches de seguridad oficiales de Google.",
                recommendation=(
                    "Actualiza a Android 11+ lo antes posible.\n"
                    "Si no hay actualización oficial, considera usar una Custom ROM "
                    "como LineageOS que extiende el soporte."
                ),
                cvss=8.0,
                cwe="CWE-1104: Use of Unmaintained Third-Party Components",
            ))
        else:
            version_info = self.SECURE_VERSIONS.get(str(int(version_num)), "Versión moderna")
            detail = f"Android {android_version} (SDK {sdk_level}) — {version_info}"
            status = CheckStatus.PASSED
            severity = Severity.OK

        # 2. Security patch check
        if security_patch:
            try:
                patch_year = security_patch.split("-")[0]
                if patch_year < self.MIN_SECURITY_2023:
                    warnings.append(
                        f"Parche de seguridad desactualizado: {security_patch}"
                    )
            except (IndexError, ValueError):
                pass

        recommendation_parts = []
        if version_outdated:
            recommendation_parts.append("⚠️  ACTUALIZACIÓN DE ANDROID NECESARIA")
        if warnings:
            recommendation_parts.append(f"⚠️  {'; '.join(warnings)}")
        if not version_outdated and not warnings:
            recommendation_parts.append("✓ Versión y parches actualizados.")

        # Si hay parche viejo pero versión moderna, agregar warning
        if warnings and not version_outdated:
            status = CheckStatus.WARNING
            severity = Severity.MEDIUM
            for w in warnings:
                vulns.append(self._vulnerability(
                    name="Parche de seguridad desactualizado",
                    description=w,
                    recommendation="Instala la actualización de seguridad disponible en Ajustes > Sistema > Actualización.",
                    cvss=6.5,
                    cwe="CWE-1104: Use of Unmaintained Third-Party Components",
                ))

        return self._result(
            status=status,
            detail=detail,
            recommendation="\n".join(recommendation_parts),
            vulnerabilities=vulns,
            raw_data={
                "android_version": android_version,
                "sdk_level": sdk_level,
                "security_patch": security_patch,
                "build_fingerprint": build_fingerprint,
            },
            severity=severity,
        )
