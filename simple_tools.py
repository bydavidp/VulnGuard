#!/usr/bin/env python3
"""
Versión simple para verificar herramientas sin usar Click (evita problemas de console)
"""

import sys
import io

# Forzar UTF-8 en stdout para caracteres especiales en Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from src.platform.detector import PlatformDetector
from src.utils.logger import setup_logging, get_logger

# Configurar logging básico
setup_logging(verbose=False, log_file=None)
logger = get_logger(__name__)

def main():
    print("HERRAMIENTAS DE CONEXION DISPONIBLES")
    print("=" * 40)

    # Obtener herramientas disponibles
    tools = PlatformDetector.get_available_tools()

    # Mostrar estado de cada herramienta
    adb_status = "[OK] Disponible" if tools.get("adb") else "[FALLO] No encontrado"
    idevice_status = "[OK] Disponible" if tools.get("libimobiledevice") else "[FALLO] No encontrado"

    print(f"   {'ADB (Android)':25s}: {adb_status}")
    print(f"   {'libimobiledevice (iOS)':25s}: {idevice_status}")
    print("")

    # Información adicional
    if not tools.get("adb"):
        print("   📥 Para Android: https://developer.android.com/studio/releases/platform-tools")
    if not tools.get("libimobiledevice"):
        print("   📥 Para iOS: https://github.com/libimobiledevice-win32/libimobiledevice")
        print("      macOS: brew install libimobiledevice")
        print("      Linux: apt install libimobiledevice-utils")

    # Mostrar también detección actual
    print("\nDETECCION DE PLATAFORMA:")
    print("-" * 25)
    platform = PlatformDetector.detect()
    print(f"   Plataforma detectada: {platform}")

    # Comparar con UNKNOWN (asumiendo que el valor es "unknown" o similar)
    if str(platform).lower() != "unknown":
        print("   [OK] Dispositivo detectado correctamente")
    else:
        print("   [AVISO] No se detectó ningún dispositivo")
        print("      Verifique la conexión y que el dispositivo esté confiado")

if __name__ == "__main__":
    main()