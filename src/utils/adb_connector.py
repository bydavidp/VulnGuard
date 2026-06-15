"""
Conector ADB — maneja la comunicación con dispositivos Android vía ADB.
"""

import os
import shutil
import subprocess
import time
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AdbConnector:
    """
    Maneja la conexión con dispositivos Android a través de ADB.

    Características:
      - Detección automática de dispositivos
      - Búsqueda de ADB en PATH y rutas comunes
      - Conexión TCP/IP o USB
      - Timeout configurable
      - Reintentos automáticos
      - Soporte para múltiples dispositivos
    """

    # Rutas comunes donde buscar adb.exe
    COMMON_ADB_PATHS = [
        lambda: os.path.join(os.path.expanduser("~"), "AppData", "Local", "Android", "Sdk", "platform-tools"),
        lambda: os.path.join(os.path.expanduser("~"), "Android", "Sdk", "platform-tools"),
        lambda: r"C:\Android\sdk\platform-tools",
        lambda: r"C:\Program Files\Android\Android Studio\platform-tools",
    ]

    def __init__(
        self,
        serial: Optional[str] = None,
        host: Optional[str] = None,
        port: int = 5555,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.serial = serial
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self._connected = False
        self._device_id: Optional[str] = None
        self._adb_path: Optional[str] = None

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def device_id(self) -> Optional[str]:
        return self._device_id

    def _resolve_adb_path(self) -> Optional[str]:
        """Busca adb.exe en PATH y rutas comunes."""
        # 1. Buscar en PATH
        path_in_path = shutil.which("adb")
        if path_in_path:
            return path_in_path

        # 2. Buscar en rutas comunes
        for path_fn in self.COMMON_ADB_PATHS:
            try:
                adb_dir = path_fn()
                candidate = os.path.join(adb_dir, "adb.exe")
                if os.path.isfile(candidate):
                    logger.debug(f"ADB encontrado en: {candidate}")
                    return candidate
            except Exception:
                continue

        return None

    def connect(self) -> bool:
        """
        Establece conexión con el dispositivo.

        Returns:
            True si la conexión fue exitosa.
        """
        if self._connected:
            return True

        # Resolver ruta de ADB
        self._adb_path = self._resolve_adb_path()
        if not self._adb_path:
            logger.error("ADB no encontrado. Descarga Platform Tools:")
            logger.error("  https://developer.android.com/studio/releases/platform-tools")
            return False

        # Si hay host, conectar TCP/IP
        if self.host:
            return self._connect_tcp()

        # Si hay serial, conectar por USB con ese serial
        if self.serial:
            return self._connect_usb(self.serial)

        # Detectar y conectar automáticamente
        return self._connect_auto()

    def disconnect(self) -> None:
        """Cierra la conexión ADB."""
        if self._connected:
            try:
                if self.host:
                    subprocess.run(
                        [self._adb_path or "adb", "disconnect", f"{self.host}:{self.port}"],
                        capture_output=True, timeout=10
                    )
                self._connected = False
                self._device_id = None
                logger.info("ADB desconectado")
            except Exception as e:
                logger.warning(f"Error al desconectar ADB: {e}")

    def run_command(self, command: list[str]) -> subprocess.CompletedProcess:
        """
        Ejecuta un comando ADB en el dispositivo.

        Args:
            command: Lista de argumentos del comando.

        Returns:
            CompletedProcess con stdout, stderr y returncode.
        """
        if not self._connected:
            self.connect()

        adb_cmd = [self._adb_path or "adb"]
        if self._device_id:
            adb_cmd.extend(["-s", self._device_id])
        adb_cmd.extend(command)

        logger.debug(f"ADB: {' '.join(adb_cmd)}")

        for attempt in range(self.max_retries):
            try:
                result = subprocess.run(
                    adb_cmd,
                    capture_output=True, text=True,
                    timeout=self.timeout
                )
                return result
            except subprocess.TimeoutExpired:
                logger.warning(f"Comando ADB timeout (intento {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(1)
                else:
                    raise
            except FileNotFoundError:
                logger.error("ADB no encontrado. Instala Android SDK Platform Tools.")
                raise

        raise RuntimeError("No se pudo ejecutar el comando ADB")

    def get_device_prop(self, prop: str) -> str:
        """Obtiene una propiedad del dispositivo vía getprop."""
        result = self.run_command(["shell", "getprop", prop])
        return result.stdout.strip()

    def device_info(self) -> dict[str, str]:
        """Obtiene información básica del dispositivo."""
        props = {
            "model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
            "android_version": "ro.build.version.release",
            "sdk_level": "ro.build.version.sdk",
            "security_patch": "ro.build.version.security_patch",
            "serial": "ro.serialno",
        }

        info = {}
        for key, prop in props.items():
            try:
                info[key] = self.get_device_prop(prop)
            except Exception:
                info[key] = "unknown"

        return info

    def _connect_tcp(self) -> bool:
        """Conecta vía TCP/IP."""
        target = f"{self.host}:{self.port}"
        try:
            result = subprocess.run(
                [self._adb_path or "adb", "connect", target],
                capture_output=True, text=True, timeout=15
            )
            if "connected" in result.stdout.lower():
                self._connected = True
                self._device_id = target
                logger.info(f"Conectado a {target}")
                return True
            else:
                logger.error(f"No se pudo conectar a {target}: {result.stdout}")
                return False
        except Exception as e:
            logger.error(f"Error conectando a {target}: {e}")
            return False

    def _connect_usb(self, serial: str) -> bool:
        """Conecta por USB con un serial específico."""
        try:
            result = subprocess.run(
                [self._adb_path or "adb", "-s", serial, "get-state"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self._connected = True
                self._device_id = serial
                logger.info(f"Conectado a dispositivo USB: {serial}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error conectando a dispositivo {serial}: {e}")
            return False

    def _connect_auto(self) -> bool:
        """Detecta y conecta automáticamente al primer dispositivo disponible."""
        try:
            # Listar dispositivos
            result = subprocess.run(
                [self._adb_path or "adb", "devices"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split("\n")[1:]  # saltar header
            devices = [
                line.split("\t")[0]
                for line in lines
                if line.strip() and "device" in line
            ]

            if not devices:
                logger.error("No se detectaron dispositivos Android conectados")
                logger.info("Asegúrate de que:")
                logger.info("  1. El dispositivo esté conectado por USB")
                logger.info("  2. USB Debugging esté habilitado")
                logger.info("  3. Hayas aceptado la clave RSA en el dispositivo")
                logger.info("  4. Los drivers ADB estén instalados")
                return False

            # Usar el primer dispositivo
            self._device_id = devices[0]
            self._connected = True
            logger.info(f"Dispositivo detectado: {self._device_id}")
            return True

        except FileNotFoundError:
            logger.error("ADB no encontrado. Descarga Platform Tools:")
            logger.error("  https://developer.android.com/studio/releases/platform-tools")
            return False
        except Exception as e:
            logger.error(f"Error detectando dispositivos: {e}")
            return False
