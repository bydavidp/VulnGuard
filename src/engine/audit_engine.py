"""
Motor de auditoría multi-plataforma — orquesta la ejecución de checks
para Android o iOS según la plataforma detectada.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from time import perf_counter
from typing import Optional

from src.checks import get_checks_for_platform, list_all_checks
from src.checks.android.base_check import SecurityCheck
from src.connectors.ios_connector import IOSConnector
from src.core.enums import CheckStatus, RiskLevel
from src.core.models import DeviceInfo, AuditReport, SecurityCheckResult
from src.core.risk_score import RiskScoreCalculator
from src.platform.detector import PlatformDetector, PlatformType
from src.utils.adb_connector import AdbConnector
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AuditEngine:
    """
    Orquestador multi-plataforma que:
      - Detecta automáticamente la plataforma (Android/iOS)
      - Conecta al dispositivo (ADB o libimobiledevice)
      - Carga y ejecuta los checks apropiados para la plataforma
      - Recopila resultados y calcula riesgo
      - Genera el reporte final
    """

    def __init__(
        self,
        platform: Optional[str] = None,
        serial: Optional[str] = None,
        host: Optional[str] = None,
        port: int = 5555,
        timeout: int = 30,
        max_workers: int = 4,
        enable_parallel: bool = True,
    ):
        self.platform_override = platform
        self.serial = serial
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_workers = max_workers
        self.enable_parallel = enable_parallel

        self.device_connector = None
        self.platform = PlatformType.UNKNOWN
        self.checks: list[SecurityCheck] = []
        self.report = AuditReport()

    def connect(self) -> bool:
        """
        Detecta la plataforma y conecta al dispositivo.

        Returns:
            True si la conexión fue exitosa.
        """
        logger.info("Detectando plataforma del dispositivo...")

        # 1. Si el usuario especificó la plataforma, usarla
        if self.platform_override:
            self.platform = PlatformType(self.platform_override.lower())
            logger.info(f"Plataforma forzada por usuario: {self.platform}")
        else:
            # 2. Detectar automáticamente
            self.platform = PlatformDetector.detect()
            if self.platform == PlatformType.UNKNOWN:
                # 3. Último recurso: ver herramientas disponibles
                tools = PlatformDetector.get_available_tools()
                if tools.get("adb"):
                    self.platform = PlatformType.ANDROID
                    logger.info("Fallback a Android (ADB disponible)")
                elif tools.get("libimobiledevice"):
                    self.platform = PlatformType.IOS
                    logger.info("Fallback a iOS (libimobiledevice disponible)")

        # 4. Conectar según plataforma
        if self.platform == PlatformType.ANDROID:
            return self._connect_android()
        elif self.platform == PlatformType.IOS:
            return self._connect_ios()
        else:
            logger.error("No se pudo detectar la plataforma del dispositivo")
            return False

    def _connect_android(self) -> bool:
        """Conecta al dispositivo Android via ADB."""
        self.device_connector = AdbConnector(
            serial=self.serial,
            host=self.host,
            port=self.port,
            timeout=self.timeout,
        )
        connected = self.device_connector.connect()
        if connected:
            logger.info(f"Android conectado: {self.device_connector.device_id}")
        return connected

    def _connect_ios(self) -> bool:
        """Conecta al dispositivo iOS via libimobiledevice."""
        self.device_connector = IOSConnector(
            udid=self.serial,
            timeout=self.timeout,
        )
        connected = self.device_connector.connect()
        if connected:
            logger.info(f"iOS conectado: {self.device_connector.device_udid}")
        return connected

    def discover_checks(self, check_ids: Optional[list[str]] = None) -> None:
        """
        Descubre y registra los checks apropiados para la plataforma detectada.
        """
        check_classes = get_checks_for_platform(self.platform.value)

        if check_ids:
            check_ids_set = set(check_ids)
            self.checks = [
                check_class(self.device_connector)
                for check_class in check_classes
                if check_class.check_id in check_ids_set
            ]
        else:
            self.checks = [
                check_class(self.device_connector)
                for check_class in check_classes
            ]

        logger.info(f"Checks cargados: {len(self.checks)} para plataforma {self.platform}")

    def run_checks(self) -> list[SecurityCheckResult]:
        """Ejecuta todos los checks registrados (paralelo o secuencial)."""
        if not self.checks:
            self.discover_checks()

        results: list[SecurityCheckResult] = []
        logger.info(f"Iniciando ejecución de {len(self.checks)} checks...")

        if self.enable_parallel and len(self.checks) > 1:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_check = {
                    executor.submit(check.run): check
                    for check in self.checks
                }

                for future in as_completed(future_to_check):
                    check = future_to_check[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Error check {check.check_id}: {e}")
                        results.append(SecurityCheckResult(
                            check_id=check.check_id,
                            check_name=check.check_name,
                            status=CheckStatus.ERROR,
                            detail=f"Error: {e}",
                            error=str(e),
                        ))
        else:
            for check in self.checks:
                result = check.run()
                results.append(result)

        # Ordenar por severidad (más crítico primero)
        severity_order = {
            "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5
        }
        results.sort(key=lambda r: severity_order.get(r.severity.value, 99))

        return results

    def run(self, check_ids: Optional[list[str]] = None) -> AuditReport:
        """
        Ejecuta la auditoría completa.

        Args:
            check_ids: IDs específicos de checks a ejecutar.

        Returns:
            AuditReport con todos los resultados.
        """
        start_time = perf_counter()
        logger.info("=" * 60)
        logger.info(f"VULNGUARD — AUDITORÍA {self.platform.value.upper()}")
        logger.info("=" * 60)

        # 1. Conectar al dispositivo
        if not self.connect():
            logger.error("No se pudo conectar al dispositivo")
            self.report.device_info = DeviceInfo()
            self.report.risk_score = 100
            self.report.risk_level = RiskLevel.CRITICAL
            return self.report

        # 2. Obtener información del dispositivo
        logger.info("Obteniendo información del dispositivo...")
        self.report.device_info = self._collect_device_info()
        logger.info(f"Dispositivo: {self.report.device_info.model or 'N/A'} | "
                    f"Plataforma: {self.platform}")

        # 3. Descubrir y ejecutar checks
        self.discover_checks(check_ids)
        results = self.run_checks()

        # 4. Procesar resultados
        for result in results:
            self.report.add_result(result)
        self.report.vulnerabilities_found = sum(1 for r in results if r.is_vulnerable)

        # 5. Calcular riesgo
        risk_metrics = RiskScoreCalculator.calculate_all(results)
        self.report.risk_score = risk_metrics["final_score"]
        self.report.risk_level = risk_metrics["risk_level"]
        self.report.calculate_risk()

        # 6. Registrar duración
        self.report.scan_duration_ms = round((perf_counter() - start_time) * 1000, 2)

        logger.info("=" * 60)
        logger.info(f"AUDITORÍA COMPLETADA en {self.report.scan_duration_ms}ms")
        logger.info(f"Riesgo: {self.report.risk_level} ({self.report.risk_score}/100)")
        logger.info(f"Vulnerabilidades: {self.report.vulnerabilities_found}/{self.report.total_checks}")
        logger.info("=" * 60)

        return self.report

    def _collect_device_info(self) -> DeviceInfo:
        """Recopila información del dispositivo según la plataforma."""
        info = DeviceInfo()

        if self.platform == PlatformType.ANDROID:
            return self._collect_android_info(info)
        elif self.platform == PlatformType.IOS:
            return self._collect_ios_info(info)

        return info

    def _collect_android_info(self, info: DeviceInfo) -> DeviceInfo:
        """Recopila información de un dispositivo Android."""
        import subprocess

        prop_commands = {
            "device_id": ["getprop", "ro.serialno"],
            "model": ["getprop", "ro.product.model"],
            "manufacturer": ["getprop", "ro.product.manufacturer"],
            "android_version": ["getprop", "ro.build.version.release"],
            "security_patch": ["getprop", "ro.build.version.security_patch"],
            "build_fingerprint": ["getprop", "ro.build.fingerprint"],
            "sdk_level": ["getprop", "ro.build.version.sdk"],
            "architecture": ["getprop", "ro.product.cpu.abi"],
        }

        for attr, cmd in prop_commands.items():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                value = result.stdout.strip()
                if attr == "sdk_level" and value.isdigit():
                    setattr(info, attr, int(value))
                elif value:
                    setattr(info, attr, value)
            except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
                pass

        return info

    def _collect_ios_info(self, info: DeviceInfo) -> DeviceInfo:
        """Recopila información de un dispositivo iOS."""
        ios_info = self.device_connector.get_info() if hasattr(self.device_connector, 'get_info') else {}

        info.device_id = ios_info.get("UniqueDeviceID", "")
        info.model = ios_info.get("ProductType", "")
        info.manufacturer = "Apple"
        info.android_version = ios_info.get("ProductVersion", "")  # Re-use field for iOS version
        info.security_patch = ios_info.get("BuildVersion", "")
        info.build_fingerprint = ios_info.get("BuildVersion", "")
        info.architecture = "ARM64"

        # Intentar obtener más info
        model_name = ios_info.get("DeviceName", "")
        if model_name:
            info.model = f"{model_name} ({info.model})"

        return info
