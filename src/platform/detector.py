"""
Detector de plataforma móvil — identifica si el dispositivo conectado es Android o iOS.
"""

import os
import subprocess
from enum import Enum
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PlatformType(Enum):
    """Tipos de plataforma móvil soportados."""
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


class PlatformDetector:
    """
    Detecta automáticamente la plataforma del dispositivo conectado.

    Estrategia de detección:
      1. Ejecuta `adb devices` — si hay dispositivo, es Android
      2. Ejecuta `ideviceinfo` — si hay dispositivo, es iOS
      3. Si ambos fallan, plataforma = UNKNOWN
    """

    @staticmethod
    def detect(adb_path: str = "adb", idevice_path: str = "ideviceinfo") -> PlatformType:
        """
        Detecta la plataforma del dispositivo conectado.

        Returns:
            PlatformType.ANDROID, PlatformType.IOS, o PlatformType.UNKNOWN
        """
        # 1. Intentar detectar Android via ADB
        if PlatformDetector._check_adb(adb_path):
            logger.info("Plataforma detectada: ANDROID")
            return PlatformType.ANDROID

        # 2. Intentar detectar iOS via libimobiledevice
        if PlatformDetector._check_idevice(idevice_path):
            logger.info("Plataforma detectada: iOS")
            return PlatformType.IOS

        # 3. No se detectó nada
        logger.warning("No se pudo detectar la plataforma (ni Android ni iOS)")
        return PlatformType.UNKNOWN

    @staticmethod
    def detect_from_serial(serial: str) -> PlatformType:
        """
        Detecta plataforma basado en formato del serial/identificador.

        Args:
            serial: Serial del dispositivo o identificador.

        Returns:
            PlatformType estimado.
        """
        serial_lower = serial.lower()
        # Los UDID de iOS son más largos y tienen formato específico
        if len(serial) > 20 and not serial_lower.startswith("emulator"):
            return PlatformType.IOS
        # Android suele tener seriales más cortos
        return PlatformType.ANDROID

    @staticmethod
    def _check_adb(adb_path: str) -> bool:
        """Verifica si hay un dispositivo Android conectado via ADB."""
        try:
            result = subprocess.run(
                [adb_path, "devices"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return False

            lines = result.stdout.strip().split("\n")[1:]  # Saltar header
            for line in lines:
                if line.strip() and "device" in line and "offline" not in line:
                    return True
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("ADB no disponible o timeout")
            return False

    @staticmethod
    def _check_idevice(idevice_path: str) -> bool:
        """Verifica si hay un dispositivo iOS conectado via libimobiledevice."""
        # Intentar con la ruta dada
        resolved = PlatformDetector._resolve_tool_path(idevice_path)
        if resolved is None:
            logger.debug("ideviceinfo no disponible (libimobiledevice no instalado)")
            return False

        try:
            result = subprocess.run(
                [resolved],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0 and len(result.stdout.strip()) > 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def get_available_tools() -> dict[str, bool]:
        """Verifica qué herramientas de detección están disponibles."""
        tools = {
            "adb": False,
            "ideviceinfo": False,
            "libimobiledevice": False,
            "idevice_id": False,
        }

        # ADB
        if PlatformDetector._check_tool("adb"):
            tools["adb"] = True

        # libimobiledevice
        if PlatformDetector._check_tool("ideviceinfo"):
            tools["ideviceinfo"] = True
            tools["libimobiledevice"] = True
        if PlatformDetector._check_tool("idevice_id"):
            tools["idevice_id"] = True
            tools["libimobiledevice"] = True
            tools["ideviceinfo"] = True  # Si idevice_id funciona, el resto también

        return tools

    @staticmethod
    def _check_tool(tool_name: str) -> bool:
        """Verifica si una herramienta está disponible (PATH + rutas comunes)."""
        resolved = PlatformDetector._resolve_tool_path(tool_name)
        if resolved is None:
            return False
        try:
            result = subprocess.run(
                [resolved, "--version"] if tool_name in ("adb",) else [resolved],
                capture_output=True, timeout=5
            )
            return result.returncode in (0, 255)  # 255 = no device pero tool existe
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _resolve_tool_path(tool_name: str) -> Optional[str]:
        """
        Busca una herramienta en PATH y rutas comunes.
        Si se encuentra, retorna la ruta completa. Si no, retorna None.
        """
        import shutil

        # 1. Buscar en PATH
        path_in_path = shutil.which(tool_name)
        if path_in_path:
            return path_in_path

        # 2. Buscar en rutas comunes de instalación
        user_home = os.path.expanduser("~")
        common_paths = [
            # libimobiledevice
            os.path.join(user_home, "libimobiledevice_bin"),
            os.path.join(user_home, "libimobiledevice", "bin"),
            r"C:\Program Files\libimobiledevice\bin",
            r"C:\Program Files (x86)\libimobiledevice\bin",
            # ADB (Android)
            os.path.join(user_home, "AppData", "Local", "Android", "Sdk", "platform-tools"),
            os.path.join(user_home, "Android", "Sdk", "platform-tools"),
            r"C:\Android\sdk\platform-tools",
            r"C:\Program Files\Android\Android Studio\platform-tools",
        ]

        for base_path in common_paths:
            expanded = os.path.expandvars(base_path)
            if os.path.isdir(expanded):
                exe_path = os.path.join(expanded, f"{tool_name}.exe")
                if os.path.isfile(exe_path):
                    logger.debug(f"Tool encontrada en ruta común: {exe_path}")
                    return exe_path

        # 3. Buscar en el directorio actual y subdirectorios
        for root, dirs, files in os.walk("."):
            for f in files:
                if f.lower() == f"{tool_name}.exe" or f == tool_name:
                    full_path = os.path.join(root, f)
                    logger.debug(f"Tool encontrada en directorio local: {full_path}")
                    return full_path

        return None
