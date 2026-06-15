"""
Interfaz de línea de comandos profesional para VulnGuard multi-plataforma.

Soporta Android (via ADB) e iOS (via libimobiledevice).
"""

import io
import sys
from pathlib import Path
from typing import Optional

import click

from src import __version__
from src.checks import get_checks_for_platform, list_all_checks
from src.core.models import AuditReport
from src.engine.audit_engine import AuditEngine
from src.platform.detector import PlatformDetector
from src.reporters.console_reporter import ConsoleReporter
from src.reporters.html_reporter import HtmlReporter
from src.reporters.json_reporter import JsonReporter
from src.utils.helpers import build_banner
from src.utils.logger import setup_logging, get_logger

logger = get_logger(__name__)

# Forzar UTF-8 en stdout para emojis y caracteres especiales en Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


def get_available_checks(platform: Optional[str] = None) -> list[str]:
    """Retorna lista de IDs de checks disponibles para una plataforma."""
    if platform:
        return [c.check_id for c in get_checks_for_platform(platform)]
    return [c.check_id for c in list_all_checks()]


# Opciones comunes como decorador
_common_options = [
    click.option("--verbose", "-v", is_flag=True, help="Modo verbose (logs detallados)"),
    click.option("--log-file", type=click.Path(path_type=str), help="Archivo de log"),
    click.option("--platform", "-p", type=click.Choice(["android", "ios"]),
                 help="Forzar plataforma (auto-detectada si no se especifica)"),
    click.option("--serial", "-s", help="Serial/UDID del dispositivo"),
    click.option("--host", help="IP del dispositivo (solo Android TCP/IP)"),
    click.option("--port", default=5555, type=int, help="Puerto ADB (default: 5555)"),
    click.option("--timeout", default=30, type=int, help="Timeout de conexión en segundos"),
]


def common_options(func):
    """Aplica opciones comunes a un comando."""
    for option in reversed(_common_options):
        func = option(func)
    return func


@click.group()
@click.version_option(version=__version__, prog_name="VulnGuard")
@click.option("--verbose", "-v", is_flag=True, help="Modo verbose")
@click.option("--log-file", type=click.Path(path_type=str), help="Archivo de log")
def cli(verbose: bool, log_file: Optional[str]):
    """
    🛡️  VulnGuard — Auditoría de Seguridad Móvil Multi-Plataforma

    Herramienta profesional de auditoría de seguridad para dispositivos
    Android e iOS. Ejecuta múltiples verificaciones y genera reportes detallados.

    Ejemplos:

        \b
        # Android: auditoría completa con reporte HTML
        vulnguard audit --html

        # iOS: forzar plataforma
        vulnguard audit --platform ios --html

        # Solo checks específicos en Android
        vulnguard audit --checks root_detection,selinux_status

        # Conexión TCP/IP Android
        vulnguard audit --host 192.168.1.100

        # Todos los formatos
        vulnguard audit --html --json --output-dir ./reportes
    """
    setup_logging(verbose=verbose, log_file=log_file)


@cli.command()
@common_options
@click.option("--checks", "-c", help="Checks específicos (separados por coma)")
@click.option("--json", "json_flag", is_flag=True, help="Generar reporte JSON")
@click.option("--html", "html_flag", is_flag=True, help="Generar reporte HTML")
@click.option("--output-dir", "-o", type=click.Path(path_type=str), default="reports",
              help="Directorio de salida para reportes")
@click.option("--console/--no-console", default=True, help="Mostrar reporte en consola")
@click.option("--parallel/--sequential", default=True, help="Ejecución paralela de checks")
@click.option("--workers", default=4, type=int, help="Número de workers paralelos")
@click.option("--list-checks", is_flag=True, help="Listar checks disponibles y salir")
def audit(
    verbose: bool,
    log_file: Optional[str],
    platform: Optional[str],
    serial: Optional[str],
    host: Optional[str],
    port: int,
    timeout: int,
    checks: Optional[str],
    json_flag: bool,
    html_flag: bool,
    output_dir: str,
    console: bool,
    parallel: bool,
    workers: int,
    list_checks: bool,
):
    """
    Ejecuta la auditoría de seguridad en el dispositivo móvil conectado.

    Detecta automáticamente Android (via ADB) o iOS (via libimobiledevice).
    Usa --platform para forzar una plataforma específica.
    """

    # Banner
    click.echo(build_banner())

    # Listar checks si se solicita
    if list_checks:
        click.echo(f"\n🔍  CHECKS DISPONIBLES:")
        click.echo("-" * 60)

        all_checks = get_checks_for_platform(platform) if platform else list_all_checks()

        for i, check_class in enumerate(all_checks, 1):
            sev_icon = {
                "CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡",
                "LOW": "ℹ️", "INFO": "📌", "OK": "✅",
            }.get(check_class.severity.value, "❓")
            click.echo(f"  {i:2d}. {sev_icon} [{check_class.severity.value:8s}] "
                       f"{click.style(check_class.check_id, bold=True)}")
            click.echo(f"      {check_class.check_name}")
            click.echo(f"      {click.style(check_class.description, dim=True)}")
        click.echo("-" * 60)
        plat = platform or "auto-detectada"
        click.echo(f"  Total: {len(all_checks)} checks para {plat}\n")
        return

    # Validar checks
    check_ids = None
    if checks:
        check_ids = [c.strip() for c in checks.split(",")]
        available = get_available_checks(platform)
        invalid = [c for c in check_ids if c not in available]
        if invalid:
            click.echo(f"❌  Checks inválidos: {', '.join(invalid)}", err=True)
            click.echo(f"    Disponibles: {', '.join(available)}")
            sys.exit(1)

    # Crear engine
    engine = AuditEngine(
        platform=platform,
        serial=serial,
        host=host,
        port=port,
        timeout=timeout,
        max_workers=workers,
        enable_parallel=parallel,
    )

    # Verificar herramientas disponibles
    tools = PlatformDetector.get_available_tools()
    if not platform:
        if tools.get("adb"):
            click.echo("📱  ADB disponible para Android")
        if tools.get("libimobiledevice"):
            click.echo("🍎  libimobiledevice disponible para iOS")
        if not any(tools.values()):
            click.echo("\n⚠️  No se detectaron herramientas de conexión")
            click.echo("   • Android: instala ADB (Platform Tools)")
            click.echo("   • iOS: instala libimobiledevice")
            if not click.confirm("   ¿Continuar de todas formas?"):
                return

    # Ejecutar auditoría
    click.echo(f"\n{'='*50}")
    plat = platform or "auto-detectada"
    click.echo(f"🔍  EJECUTANDO AUDITORÍA ({plat.upper()})")
    click.echo(f"{'='*50}\n")

    try:
        report = engine.run(check_ids=check_ids)
    except FileNotFoundError as e:
        click.echo(f"\n❌  ERROR: {e}")
        click.echo("   Asegúrate de tener las herramientas necesarias instaladas.")
        sys.exit(1)

    # Generar reporte de consola
    if console:
        console_reporter = ConsoleReporter(report)
        console_reporter.generate()

    # Generar JSON
    if json_flag or not (html_flag or console):
        output_path = str(Path(output_dir) / f"vulnguard_report.json")
        json_reporter = JsonReporter(report)
        json_reporter.generate(output_path)

    # Generar HTML
    if html_flag:
        output_path = str(Path(output_dir) / f"vulnguard_report.html")
        html_reporter = HtmlReporter(report)
        html_reporter.generate(output_path)

    # Mostrar resumen final
    click.echo("\n" + "=" * 50)
    click.echo(f"📊  AUDITORÍA COMPLETADA")

    risk_colors = {"CRÍTICO": "red", "ALTO": "yellow", "MEDIO": "yellow", "BAJO": "blue", "SEGURO": "green"}
    rc = risk_colors.get(str(report.risk_level), "white")
    click.echo(f"   Plataforma: {click.style(plat.upper(), bold=True)}")
    click.echo(f"   Riesgo: {click.style(str(report.risk_level) + f' ({report.risk_score}/100)', fg=rc, bold=True)}")
    click.echo(f"   Vulnerabilidades: {report.vulnerabilities_found}/{report.total_checks}")
    click.echo(f"   Duración: {report.scan_duration_ms}ms")
    click.echo("=" * 50)


@cli.command()
@common_options
def info(
    verbose: bool,
    log_file: Optional[str],
    platform: Optional[str],
    serial: Optional[str],
    host: Optional[str],
    port: int,
    timeout: int,
):
    """Muestra información detallada del dispositivo conectado."""
    click.echo(build_banner())
    click.echo(f"\n📱  INFORMACIÓN DEL DISPOSITIVO\n")

    engine = AuditEngine(
        platform=platform,
        serial=serial,
        host=host,
        port=port,
        timeout=timeout,
    )

    if not engine.connect():
        click.echo("❌  No se pudo conectar al dispositivo")
        return

    info = engine._collect_device_info()
    click.echo(f"   Plataforma:      {engine.platform.value}")
    click.echo(f"   Modelo:          {info.model}")
    click.echo(f"   Fabricante:      {info.manufacturer}")
    click.echo(f"   Versión OS:      {info.android_version}")
    click.echo(f"   Parche/Build:    {info.security_patch}")
    click.echo(f"   Serial/UDID:     {info.device_id}")
    click.echo(f"   Arquitectura:    {info.architecture}")

    if engine.platform.value == "android" and hasattr(engine.device_connector, 'device_id'):
        click.echo(f"   Dispositivo ADB: {engine.device_connector.device_id}")


@cli.command()
@click.option("--json", "json_flag", is_flag=True, help="Salida en JSON")
@click.option("--platform", "-p", type=click.Choice(["android", "ios"]),
              help="Filtrar por plataforma")
def checks(json_flag: bool, platform: Optional[str]):
    """Lista todos los checks de seguridad disponibles por plataforma."""
    check_list = get_checks_for_platform(platform) if platform else list_all_checks()
    plat_label = platform or "TODAS"

    if json_flag:
        import json as json_lib
        data = [
            {
                "id": c.check_id,
                "name": c.check_name,
                "description": c.description,
                "severity": c.severity.value,
            }
            for c in check_list
        ]
        click.echo(json_lib.dumps(data, indent=2, ensure_ascii=False))
        return

    click.echo(f"\n🔍  CHECKS DISPONIBLES ({plat_label}): {len(check_list)}\n")
    for i, check_class in enumerate(check_list, 1):
        sev_icon = {
            "CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡",
            "LOW": "ℹ️", "INFO": "📌", "OK": "✅",
        }.get(check_class.severity.value, "❓")
        click.echo(f"  {i:2d}. {sev_icon} [{check_class.severity.value:8s}] "
                   f"{click.style(check_class.check_id, bold=True)}")
        click.echo(f"      {click.style(check_class.check_name, fg='cyan')}")
        click.echo(f"      {check_class.description}")


@cli.command()
def version():
    """Muestra la versión de VulnGuard."""
    click.echo(f"VulnGuard v{__version__}")
    click.echo("Auditoría de Seguridad Móvil Multi-Plataforma")


@cli.command()
@click.option("--json", "json_flag", is_flag=True, help="Salida en JSON")
def tools(json_flag: bool):
    """Muestra las herramientas de conexión disponibles en el sistema."""
    tools_available = PlatformDetector.get_available_tools()

    if json_flag:
        import json as json_lib
        click.echo(json_lib.dumps(tools_available, indent=2))
        return

    click.echo("\n🔧  HERRAMIENTAS DISPONIBLES\n")
    click.echo(f"   {'ADB (Android)':25s}: {'✅ Disponible' if tools_available.get('adb') else '❌ No encontrado'}")
    click.echo(f"   {'libimobiledevice (iOS)':25s}: {'✅ Disponible' if tools_available.get('libimobiledevice') else '❌ No encontrado'}")
    click.echo("")

    if not tools_available.get("adb"):
        click.echo("   📥 Para Android: https://developer.android.com/studio/releases/platform-tools")
    if not tools_available.get("libimobiledevice"):
        click.echo("   📥 Para iOS: https://github.com/libimobiledevice-win32/libimobiledevice")
        click.echo("      macOS: brew install libimobiledevice")
        click.echo("      Linux: apt install libimobiledevice-utils")


if __name__ == "__main__":
    cli()
