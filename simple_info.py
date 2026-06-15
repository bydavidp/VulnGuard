#!/usr/bin/env python3
"""
Versión simple para obtener información del dispositivo sin usar Click
"""

import sys
import io

# Forzar UTF-8 en stdout para caracteres especiales en Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from src.platform.detector import PlatformDetector, PlatformType
from src.engine.audit_engine import AuditEngine
from src.utils.logger import setup_logging, get_logger

# Configurar logging básico
setup_logging(verbose=False, log_file=None)
logger = get_logger(__name__)

def main():
    print("INFORMACION DEL DISPOSITIVO CONECTADO")
    print("=" * 40)

    # 1. Detectar plataforma
    print("\n1. Detectando plataforma...")
    platform = PlatformDetector.detect()
    print(f"   Plataforma detectada: {platform}")

    if platform == PlatformType.UNKNOWN:
        print("   [ERROR] No se pudo detectar ningún dispositivo")
        print("   Verifique que:")
        print("   - Su iPhone/Android esté conectado por USB")
        print("   - Para iOS: haya confiado en esta computadora")
        print("   - Para Android: haya depuración USB activada")
        return 1

    # 2. Crear motor de auditoría
    print(f"\n2. Inicializando motor para {platform.value}...")
    engine = AuditEngine(
        platform=platform.value,
        timeout=15
    )

    # 3. Conectar al dispositivo
    print("\n3. Conectando al dispositivo...")
    if not engine.connect():
        print("   [ERROR] No se pudo conectar al dispositivo")
        return 1

    print(f"   [OK] Conectado como {engine.platform.value}")

    # 4. Obtener información del dispositivo
    print("\n4. Obteniendo informacion del dispositivo...")
    try:
        device_info = engine._collect_device_info()

        print(f"   Modelo:           {device_info.model or 'N/A'}")
        print(f"   Fabricante:       {device_info.manufacturer or 'N/A'}")
        print(f"   Sistema Operativo: {device_info.android_version or 'N/A'}")
        print(f"   Parche de Seguridad: {device_info.security_patch or 'N/A'}")
        print(f"   Arquitectura:     {device_info.architecture or 'N/A'}")
        print(f"   Serial/UDID:      {device_info.device_id or 'N/A'}")

        # Información adicional específica por plataforma
        if engine.platform == PlatformType.ANDROID:
            print(f"   Nivel SDK:        {device_info.sdk_level}")
            print(f"   Es emulador:      {'Si' if device_info.is_emulator else 'No'}")
        elif engine.platform == PlatformType.IOS:
            print(f"   Build Fingerprint: {device_info.build_fingerprint or 'N/A'}")

    except Exception as e:
        print(f"   [ADVERTENCIA] Error obteniendo info: {e}")

    print("\n[OK] Informacion obtenida correctamente")
    return 0

if __name__ == "__main__":
    sys.exit(main())