#!/usr/bin/env python3
"""
Script temporal para demostrar cómo funciona VulnGuard internamente
sin pasar por el CLI (para evitar problemas de stdout en este entorno).
"""

import sys
import io
from src.platform.detector import PlatformDetector, PlatformType
from src.engine.audit_engine import AuditEngine
from src.utils.logger import setup_logging, get_logger

# Configurar logging para que no falle
setup_logging(verbose=False, log_file=None)
logger = get_logger(__name__)

def main():
    print("VULNGUARD - DEMOSTRACION INTERNA")
    print("=" * 50)

    # 1. Detectar plataforma
    print("\n1. Detectando plataforma...")
    platform = PlatformDetector.detect()
    print(f"   Plataforma detectada: {platform}")

    if platform == PlatformType.UNKNOWN:
        print("   ERROR: No se pudo detectar ningún dispositivo")
        print("   Asegúrate de tener conectado un iPhone y confiar en la computadora")
        return 1

    # 2. Crear motor de auditoría
    print("\n2. Creando motor de auditoría...")
    engine = AuditEngine(
        platform=platform.value,
        timeout=15  # Timeout reducido para demo
    )

    # 3. Intentar conectar
    print("\n3. Conectando al dispositivo...")
    if not engine.connect():
        print("   ERROR: No se pudo conectar al dispositivo")
        print("   Verifica que:")
        print("   - El iPhone esté conectado vía USB")
        print("   - Hayas confiado en esta computadora en el iPhone")
        print("   - Tengas libimobiledevice instalado y funcionando")
        return 1

    print(f"   OK: Conectado exitosamente como {engine.platform.value}")

    # 4. Obtener información del dispositivo
    print("\n4. Obteniendo información del dispositivo...")
    try:
        device_info = engine._collect_device_info()
        print(f"   Modelo:      {device_info.model or 'N/A'}")
        print(f"   Fabricante:  {device_info.manufacturer or 'N/A'}")
        print(f"   Versión OS:  {device_info.android_version or 'N/A'}")  # Campo reutilizado para iOS
        print(f"   Parche/Build:{device_info.security_patch or 'N/A'}")
        print(f"   Arquitectura:{device_info.architecture or 'N/A'}")
        print(f"   Serial/UDID: {device_info.device_id or 'N/A'}")
    except Exception as e:
        print(f"   ADVERTENCIA: Error obteniendo info: {e}")
        device_info = None

    # 5. Descubrir y ejecutar algunos checks representativos
    print("\n5. Cargando checks de seguridad...")
    engine.discover_checks()
    print(f"   Checks disponibles: {len(engine.checks)}")

    # Ejecutar solo unos pocos checks para la demo (los primeros 3)
    checks_to_run = engine.checks[:3] if len(engine.checks) >= 3 else engine.checks
    print(f"\n6. Ejecutando {len(checks_to_run)} checks de muestra...")

    results = []
    for check in checks_to_run:
        print(f"   Ejecutando: {check.check_id} - {check.check_name}")
        try:
            result = check.run()
            results.append(result)
            if result.status.name == "PASSED":
                status_icon = "OK"
            elif result.status.name == "FAILED":
                status_icon = "ERROR"
            else:
                status_icon = "WARNING"
            print(f"     {status_icon} {result.status.name} ({result.detail[:50]}{'...' if len(result.detail) > 50 else ''})")
        except Exception as e:
            print(f"     ERROR: {e}")

    # 6. Mostrar resumen
    print("\n" + "=" * 50)
    print("RESUMEN DE LA DEMOSTRACION")
    print("=" * 50)
    passed = sum(1 for r in results if r.status.name == "PASSED")
    failed = sum(1 for r in results if r.status.name == "FAILED")
    print(f"   Checks ejecutados: {len(results)}")
    print(f"   Pasaron: {passed}")
    print(f"   Fallaron: {failed}")
    print(f"   Informacion del dispositivo: {'OK Obtenida' if device_info else 'ERROR No disponible'}")

    if failed > 0:
        print("\n   ADVERTENCIA: Algunos checks fallaron - esto podría indicar problemas de seguridad")
    else:
        print("\n   OK: Todos los checks de muestra pasaron")

    print("\nINFO: Para ejecutar una auditoria completa, usa:")
    print("      vulnguard audit --html")
    print("      o")
    print("      python -m src.main audit --html")

    return 0

if __name__ == "__main__":
    sys.exit(main())