"""
Módulo de checks de seguridad.

Provee acceso a los checks según la plataforma detectada.
"""

from src.checks.android import ANDROID_CHECKS
from src.checks.ios import IOS_CHECKS
from src.checks.android.base_check import SecurityCheck

# Mapa de plataforma a lista de checks
PLATFORM_CHECKS = {
    "android": ANDROID_CHECKS,
    "ios": IOS_CHECKS,
}


def get_checks_for_platform(platform: str) -> list:
    """
    Obtiene la lista de checks apropiada para la plataforma.

    Args:
        platform: "android" o "ios"

    Returns:
        Lista de clases de checks para esa plataforma.
    """
    return PLATFORM_CHECKS.get(platform, ANDROID_CHECKS)


def list_all_checks() -> list:
    """Retorna todos los checks de todas las plataformas."""
    return ANDROID_CHECKS + IOS_CHECKS


__all__ = [
    "SecurityCheck",
    "get_checks_for_platform",
    "list_all_checks",
    "ANDROID_CHECKS",
    "IOS_CHECKS",
    "PLATFORM_CHECKS",
]
