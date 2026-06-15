"""
Funciones auxiliares para VulnGuard.
"""

import re
import socket
from datetime import datetime
from typing import Any, Optional


def validate_ip(ip: str) -> bool:
    """Valida si una cadena es una dirección IP válida."""
    pattern = r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    return bool(re.match(pattern, ip))


def validate_port(port: int) -> bool:
    """Valida si un puerto está en rango válido (1-65535)."""
    return 1 <= port <= 65535


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Verifica si un puerto TCP está abierto."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """Limpia un nombre de archivo eliminando caracteres no seguros."""
    return re.sub(r'[<>:"/\\|?*]', "_", filename)


def format_duration(ms: float) -> str:
    """Formatea milisegundos a cadena legible."""
    if ms < 1000:
        return f"{ms:.0f}ms"
    elif ms < 60000:
        return f"{ms / 1000:.1f}s"
    else:
        return f"{ms / 60000:.1f}min"


def truncate(text: str, max_length: int = 100) -> str:
    """Trunca texto a una longitud máxima."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def build_banner() -> str:
    """Genera el banner ASCII de VulnGuard."""
    return r"""
+------------------------------------------------------------------+
|                    VULNGUARD                                      |
|            Android Security Auditor v2.0                          |
|                                                                   |
|   Audita la seguridad de tu dispositivo Android                   |
|   Reportes: JSON / HTML / Consola                                 |
+------------------------------------------------------------------+
"""
