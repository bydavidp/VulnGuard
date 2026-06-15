"""
Conector iOS — maneja la comunicación con dispositivos iOS vía libimobiledevice.

Requiere: libimobiledevice instalado en el sistema.
  - Windows: https://github.com/libimobiledevice-win32/libimobiledevice
  - macOS: brew install libimobiledevice
  - Linux: apt install libimobiledevice-utils
"""

import os
import shutil
import subprocess
import time
from typing import Any, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class IOSConnector:
    """
    Maneja la conexión con dispositivos iOS a través de libimobiledevice.

    Herramientas utilizadas:
      - ideviceinfo: Información general del dispositivo
      - idevicediagnostics: Diagnósticos y estado
      - idevicesyslog: Logs del sistema
      - ideviceprovision: Perfiles de provisioning
      - idevicecrashreport: Reportes de crash
      - idevice_id: Listar dispositivos
    """

    # Rutas comunes donde buscar herramientas libimobiledevice
    COMMON_TOOL_PATHS = [
        os.path.join(os.path.expanduser("~"), "libimobiledevice_bin"),
        os.path.join(os.path.expanduser("~"), "libimobiledevice", "bin"),
        r"C:\Program Files\libimobiledevice\bin",
        r"C:\Program Files (x86)\libimobiledevice\bin",
    ]

    def __init__(
        self,
        udid: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.udid = udid
        self.timeout = timeout
        self.max_retries = max_retries
        self._connected = False
        self._device_info: dict[str, str] = {}
        self._tool_cache: dict[str, Optional[str]] = {}

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def device_udid(self) -> Optional[str]:
        return self.udid

    def connect(self) -> bool:
        """
        Establece conexión con el dispositivo iOS.

        Returns:
            True si la conexión fue exitosa.
        """
        if self._connected:
            return True

        try:
            # Verificar que libimobiledevice está instalado
            info = self._run_idevicecmd("ideviceinfo", [])
            if info is None:
                return False

            self._device_info = self._parse_idevice_output(info)
            self._connected = True
            self.udid = self._device_info.get("UniqueDeviceID", self.udid)
            logger.info(f"iOS conectado: {self._device_info.get('DeviceName', 'unknown')}")
            return True

        except Exception as e:
            logger.error(f"Error conectando iOS: {e}")
            return False

    def disconnect(self) -> None:
        """Cierra la conexión (no aplica para USB, es solo cleanup)."""
        self._connected = False
        logger.info("iOS desconectado")

    def get_info(self) -> dict[str, str]:
        """Obtiene información completa del dispositivo iOS."""
        if not self._connected:
            self.connect()
        return self._device_info.copy()

    def get_property(self, key: str) -> str:
        """
        Obtiene una propiedad específica del dispositivo iOS.
        Args:
            key: Nombre de la propiedad (ej: "ProductVersion", "DeviceName")
        """
        if not self._connected:
            self.connect()
        return self._device_info.get(key, "")

    def run_diagnostics(self) -> Optional[dict[str, str]]:
        """Ejecuta diagnósticos en el dispositivo iOS."""
        output = self._run_idevicecmd("idevicediagnostics", ["diagnostics", "All"])
        if output:
            return self._parse_idevice_output(output)
        return None

    def get_syslog(self, lines: int = 50) -> list[str]:
        """Obtiene las últimas líneas del syslog iOS."""
        output = self._run_idevicecmd(
            "idevicesyslog",
            ["--quick"] if lines <= 50 else []
        )
        if output:
            return output.strip().split("\n")[-lines:]
        return []

    def device_info_dict(self) -> dict[str, Any]:
        """Obtiene información del dispositivo en formato dict estándar."""
        info = self.get_info()
        return {
            "device_id": info.get("UniqueDeviceID", ""),
            "model": info.get("ProductType", ""),
            "manufacturer": "Apple",
            "ios_version": info.get("ProductVersion", ""),
            "build_version": info.get("BuildVersion", ""),
            "device_name": info.get("DeviceName", ""),
            "serial": info.get("SerialNumber", ""),
            "is_jailbroken": self._check_jailbreak_indicators(info),
        }

    def _check_jailbreak_indicators(self, info: dict[str, str]) -> bool:
        """Verifica indicadores de jailbreak en la información del dispositivo."""
        indicators = []

        # Si tiene paquete de desarrollo instalado (Cydia)
        try:
            result = subprocess.run(
                ["ideviceprovision", "list"],
                capture_output=True, text=True, timeout=10
            )
            if "cydia" in result.stdout.lower():
                indicators.append("cydia_detected")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Verificar si el dispositivo reporta valores inusuales
        model = info.get("ProductType", "")
        if model and "t" in model:  # Internal devices
            indicators.append("internal_device")

        return len(indicators) > 0

    def _resolve_tool_path(self, tool_name: str) -> Optional[str]:
        """
        Busca una herramienta de libimobiledevice en PATH y rutas comunes.

        Args:
            tool_name: Nombre del ejecutable (ej: "ideviceinfo")

        Returns:
            Ruta completa al ejecutable o None si no se encuentra.
        """
        # Cache
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]

        # 1. Buscar en PATH
        path_in_path = shutil.which(tool_name)
        if path_in_path:
            self._tool_cache[tool_name] = path_in_path
            return path_in_path

        # 2. Buscar en rutas comunes
        for tool_dir in self.COMMON_TOOL_PATHS:
            candidate = os.path.join(tool_dir, f"{tool_name}.exe")
            if os.path.isfile(candidate):
                logger.debug(f"Tool iOS encontrada en: {candidate}")
                self._tool_cache[tool_name] = candidate
                return candidate

        self._tool_cache[tool_name] = None
        return None

    def _run_idevicecmd(self, cmd: str, args: list[str]) -> Optional[str]:
        """
        Ejecuta un comando de libimobiledevice.

        Args:
            cmd: Nombre del comando (ideviceinfo, idevicediagnostics, etc.)
            args: Argumentos adicionales

        Returns:
            stdout del comando o None si falló
        """
        # Resolver ruta del comando
        cmd_path = self._resolve_tool_path(cmd)
        if not cmd_path:
            logger.error(f"{cmd} no encontrado. Verifica la instalación de libimobiledevice.")
            return None

        full_cmd = [cmd_path]
        if self.udid:
            full_cmd.extend(["-u", self.udid])
        full_cmd.extend(args)

        logger.debug(f"iOS cmd: {' '.join(full_cmd)}")

        for attempt in range(self.max_retries):
            try:
                result = subprocess.run(
                    full_cmd,
                    capture_output=True, text=True,
                    timeout=self.timeout
                )
                if result.returncode == 0:
                    return result.stdout
                elif result.returncode == 255:
                    # Error de conexión
                    logger.warning(f"Error de conexión iOS (intento {attempt + 1}): {result.stderr}")
                    if attempt < self.max_retries - 1:
                        time.sleep(1)
                    else:
                        return None
                else:
                    logger.error(f"Error {cmd}: {result.stderr}")
                    return None

            except FileNotFoundError:
                logger.error(f"{cmd} no encontrado. Instala libimobiledevice.")
                return None
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout {cmd} (intento {attempt + 1})")
                if attempt < self.max_retries - 1:
                    time.sleep(1)
                else:
                    return None
            except Exception as e:
                logger.error(f"Error en {cmd}: {e}")
                return None

        return None

    @staticmethod
    def _parse_idevice_output(output: str) -> dict[str, str]:
        """
        Parsea la salida de ideviceinfo (formato clave: valor).

        Ejemplo:
            ActivationState: Activated
            BasebandVersion: 2.05.01
            BuildVersion: 21A329
            DeviceName: iPhone de Juan
        """
        result = {}
        for line in output.strip().split("\n"):
            if ":" in line:
                key, _, value = line.partition(":")
                result[key.strip()] = value.strip()
        return result

    @staticmethod
    def is_libimobiledevice_installed() -> bool:
        """Verifica si libimobiledevice está instalado en el sistema."""
        try:
            subprocess.run(
                ["ideviceinfo", "--help"],
                capture_output=True, timeout=5
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # También verificar idevice_id
            try:
                subprocess.run(
                    ["idevice_id", "--help"] if False else ["idevice_id"],
                    capture_output=True, timeout=5
                )
                return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False
