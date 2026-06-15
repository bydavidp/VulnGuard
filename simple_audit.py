#!/usr/bin/env python3
"""
Versión simple para ejecutar una auditoría de seguridad básica sin usar Click
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

# Configurar logging
setup_logging(verbose=True, log_file=None)
logger = get_logger(__name__)

def main():
    print("AUDITORIA DE SEGURIDAD BASICA")
    print("=" * 40)

    # 1. Detectar plataforma
    print("\n1. Detectando plataforma...")
    platform = PlatformDetector.detect()
    print(f"   Plataforma detectada: {platform}")

    if platform == PlatformType.UNKNOWN:
        print("   [ERROR] No se pudo detectar ningún dispositivo")
        return 1

    # 2. Crear motor de auditoría
    print(f"\n2. Inicializando motor para {platform.value}...")
    engine = AuditEngine(
        platform=platform.value,
        timeout=20,
        max_workers=2,  # Reducir workers para evitar sobrecarga
        enable_parallel=True
    )

    # 3. Conectar al dispositivo
    print("\n3. Conectando al dispositivo...")
    if not engine.connect():
        print("   [ERROR] No se pudo conectar al dispositivo")
        return 1

    print(f"   [OK] Conectado como {engine.platform.value}")

    # 4. Descubrir checks disponibles
    print(f"\n4. Descubriendo checks para {platform.value}...")
    engine.discover_checks()
    total_checks = len(engine.checks)
    print(f"   Checks disponibles: {total_checks}")

    if total_checks == 0:
        print("   [ERROR] No se encontraron checks para esta plataforma")
        return 1

    # 5. Filtrar checks problemáticos (los que sabemos tienen bugs en iOS)
    # Para iOS, evitamos los checks que tienen problemas conocidos
    safe_check_ids = []
    if platform == PlatformType.IOS:
        # Estos checks iOS tienen bugs conocidos en el código actual
        problematic_checks = ['ios_version', 'ios_app_permissions']
        safe_check_ids = [check.check_id for check in engine.checks
                         if check.check_id not in problematic_checks]
        print(f"   Evitando checks problemáticos: {problematic_checks}")
    else:
        # Para Android, usamos todos los checks
        safe_check_ids = [check.check_id for check in engine.checks]

    print(f"   Checks a ejecutar: {len(safe_check_ids)}")
    if len(safe_check_ids) < total_checks:
        print(f"   (Saltando {total_checks - len(safe_check_ids)} checks con problemas conocidos)")

    # 6. Ejecutar los checks seguros
    print(f"\n5. Ejecutando {len(safe_check_ids)} checks de seguridad...")
    print("   Esto puede tomar un momento...")

    try:
        report = engine.run(check_ids=safe_check_ids if safe_check_ids else None)
    except Exception as e:
        print(f"   [ERROR] Durante la ejecucion de checks: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # 7. Mostrar resultados
    print("\n" + "=" * 40)
    print("RESULTADOS DE LA AUDITORIA")
    print("=" * 40)

    print(f"\nRESUMEN:")
    print(f"   Plataforma:           {engine.platform.value.upper()}")
    print(f"   Tiempo de escaneo:    {report.scan_duration_ms}ms")
    print(f"   Total checks:         {report.total_checks}")
    print(f"   Checks passed:        {report.passed_checks}")
    print(f"   Checks failed:        {report.failed_checks}")
    print(f"   Vulnerabilidades:     {report.vulnerabilities_found}")
    print(f"   Puntaje de riesgo:    {report.risk_score}/100")

    # Determinar nivel de riesgo
    if report.risk_score >= 80:
        risk_level = "CRITICO"
        risk_desc = "Se requiere accion inmediata"
    elif report.risk_score >= 60:
        risk_level = "ALTO"
        risk_desc = "Se necesita atencion pronto"
    elif report.risk_score >= 40:
        risk_level = "MEDIO"
        risk_desc = "Se recomienda revision"
    elif report.risk_score >= 20:
        risk_level = "BAJO"
        risk_desc = "Riesgo bajo detectado"
    else:
        risk_level = "SEGURO"
        risk_desc = "Buena postura de seguridad"

    print(f"   Nivel de riesgo:      {risk_level} - {risk_desc}")

    # Mostrar detalles de checks fallados (si los hay)
    if report.failed_checks > 0:
        print(f"\nDETALLE DE CHECKS FALLADOS ({report.failed_checks}):")
        failed_results = [r for r in report.check_results if r.status.name == "FAILED"]

        # Ordenar por severidad (critico primero)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}
        failed_results.sort(key=lambda r: severity_order.get(r.severity.value, 99))

        for i, result in enumerate(failed_results[:5], 1):  # Mostrar máximo 5
            print(f"\n   {i}. [{result.severity.value}] {result.check_id}")
            print(f"      Nombre: {result.check_name}")
            print(f"      Estado: {result.status.name}")
            print(f"      Detalle: {result.detail[:100]}{'...' if len(result.detail) > 100 else ''}")
            if result.vulnerabilities:
                print(f"      Vulnerabilidades: {len(result.vulnerabilities)}")
                for vuln in result.vulnerabilities[:2]:  # Máximo 2 vulns por check
                    print(f"        - {vuln.name}")
        if len(failed_results) > 5:
            print(f"\n   ... y {len(failed_results) - 5} checks fallados más")

    # Mostrar resumen de checks passed
    if report.passed_checks > 0:
        print(f"\nRESUMEN DE CHECKS EXITOSOS ({report.passed_checks}):")
        passed_results = [r for r in report.check_results if r.status.name == "PASSED"]

        # Agrupar por severidad
        critical_passed = [r for r in passed_results if r.severity.value == "CRITICAL"]
        high_passed = [r for r in passed_results if r.severity.value == "HIGH"]
        medium_passed = [r for r in passed_results if r.severity.value == "MEDIUM"]
        low_passed = [r for r in passed_results if r.severity.value in ["LOW", "INFO"]]

        if critical_passed:
            print(f"   - Checks CRITICOS passed: {len(critical_passed)} (protecciones fuertes)")
        if high_passed:
            print(f"   - Checks ALTO passed: {len(high_passed)}")
        if medium_passed:
            print(f"   - Checks MEDIO passed: {len(medium_passed)}")
        if low_passed:
            print(f"   - Checks BAJO/INFO passed: {len(low_passed)}")

    print("\n" + "=" * 40)
    print("AUDITORIA COMPLETADA")
    print("=" * 40)

    if report.risk_score >= 60:
        print("   [RECOMENDACION] Revise los resultados y considere tomar medidas de seguridad")
    else:
        print("   [RECOMENDACION] Su dispositivo muestra una buena postura de seguridad básica")

    return 0

if __name__ == "__main__":
    sys.exit(main())