#!/usr/bin/env python3
"""
Script para ejecutar una auditoría completa de VulnGuard en el dispositivo conectado
evitando los problemas de Click/console en este entorno.
"""

import sys
import json
import os
from datetime import datetime
from src.platform.detector import PlatformDetector, PlatformType
from src.engine.audit_engine import AuditEngine
from src.utils.logger import setup_logging, get_logger
from src.reporters.json_reporter import JsonReporter
from src.reporters.html_reporter import HtmlReporter
from src.core.models import AuditReport

# Configurar logging
setup_logging(verbose=True, log_file=None)
logger = get_logger(__name__)

def main():
    print("VULNGUARD - AUDITORIA COMPLETA DE SEGURIDAD MOVIL")
    print("=" * 60)

    # 1. Detectar plataforma
    print("\n1. Detectando plataforma del dispositivo...")
    platform = PlatformDetector.detect()
    print(f"   Plataforma detectada: {platform}")

    if platform == PlatformType.UNKNOWN:
        print("   ERROR: No se pudo detectar ningún dispositivo conectado")
        print("   Verifique que:")
        print("   - Su iPhone/Android esté conectado por USB")
        print("   - Para iOS: haya confiado en esta computadora")
        print("   - Para Android: haya depuración USB activada")
        print("   - Tenga instaladas las herramientas necesarias (ADB o libimobiledevice)")
        return 1

    # 2. Crear motor de auditoría
    print(f"\n2. Inicializando motor de auditoría para {platform.value}...")
    engine = AuditEngine(
        platform=platform.value,
        timeout=20,
        max_workers=4,
        enable_parallel=True
    )

    # 3. Conectar al dispositivo
    print("\n3. Conectando al dispositivo...")
    if not engine.connect():
        print("   ERROR: No se pudo establecer conexión con el dispositivo")
        print("   Pasos de troubleshooting:")
        if platform == PlatformType.IOS:
            print("   - Asegúrese de haber confiado en esta computadora en el iPhone")
            print("   - Verifique que libimobiledevice esté instalado correctamente")
            print("   - Intente desconectar y reconectar el dispositivo")
        else:  # ANDROID
            print("   - Active la depuración USB en Opciones de desarrollador")
            print("   - Verifique que ADB esté instalado y en el PATH")
            print("   - Intente ejecutar 'adb devices' para ver si el dispositivo aparece")
        return 1

    print(f"   OK: Conectado como {engine.platform.value}")
    print(f"   Identificador del dispositivo: {getattr(engine.device_connector, 'device_id', getattr(engine.device_connector, 'device_udid', 'N/A'))}")

    # 4. Obtener información detallada del dispositivo
    print("\n4. Recopilando información del dispositivo...")
    try:
        device_info = engine._collect_device_info()
        print(f"   Modelo:           {device_info.model or 'N/A'}")
        print(f"   Fabricante:       {device_info.manufacturer or 'N/A'}")
        print(f"   Sistema Operativo: {device_info.android_version or 'N/A'}")
        print(f"   Parche de Seguridad: {device_info.security_patch or 'N/A'}")
        print(f"   Arquitectura:     {device_info.architecture or 'N/A'}")
        print(f"   Serial/UDID:      {device_info.device_id or 'N/A'}")
    except Exception as e:
        print(f"   ADVERTENCIA: No se pudo obtener información completa del dispositivo: {e}")
        device_info = None

    # 5. Descubrir todos los checks disponibles
    print(f"\n5. Descubriendo checks de seguridad para {platform.value}...")
    engine.discover_checks()
    total_checks = len(engine.checks)
    print(f"   Checks disponibles: {total_checks}")

    if total_checks == 0:
        print("   ERROR: No se encontraron checks para esta plataforma")
        return 1

    # 6. Ejecutar todos los checks
    print(f"\n6. Ejecutando {total_checks} checks de seguridad...")
    print("   Esto puede tomar varios minutos dependiendo del dispositivo y la conexión...")

    start_time = datetime.now()

    try:
        report = engine.run()  # Ejecuta todos los checks
    except Exception as e:
        print(f"   ERROR durante la ejecución de los checks: {e}")
        import traceback
        traceback.print_exc()
        return 1

    end_time = datetime.now()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)
    report.scan_duration_ms = duration_ms

    # 7. Mostrar resultados
    print("\n" + "=" * 60)
    print("RESULTADOS DE LA AUDITORIA DE SEGURIDAD")
    print("=" * 60)

    # Resumen ejecutivo
    print(f"\nRESUMEN EJECUTIVO:")
    print(f"   Plataforma auditada:     {engine.platform.value.upper()}")
    print(f"   Tiempo total de escaneo: {report.scan_duration_ms}ms ({report.scan_duration_ms/1000:.2f}s)")
    print(f"   Total de checks ejecutados: {report.total_checks}")
    print(f"   Checks passed:           {report.passed_checks}")
    print(f"   Checks failed:           {report.failed_checks}")
    print(f"   Vulnerabilidades encontradas: {report.vulnerabilities_found}")
    print(f"   Puntaje de riesgo:       {report.risk_score}/100")

    # Nivel de riesgo con descripción
    risk_level_desc = {
        "SAFE": "Bajo riesgo - El dispositivo cumple con los estándares de seguridad básicos",
        "LOW": "Riesgo bajo - Se encontraron algunas questões menores de seguridad",
        "MEDIUM": "Riesgo medio - Se encontraron vulnérabilidades que requieren atención",
        "HIGH": "Riesgo alto - Se encontraron múltiples vulnerabilidades de seguridad significativas",
        "CRITICAL": "Riesgo crítico - Se encontraron vulnerabilidades graves que requieren acción inmediata"
    }

    risk_level_str = str(report.risk_level)
    desc = risk_level_desc.get(risk_level_str, "Nivel de riesgo desconocido")
    print(f"   Nivel de riesgo:         {risk_level_str} - {desc}")

    # Detalle de checks fallados
    if report.failed_checks > 0:
        print(f"\nDETALLE DE CHECKS FALLADOS ({report.failed_checks} de {report.total_checks}):")
        failed_results = [r for r in report.check_results if r.status.name == "FAILED"]
        # Ordenar por severidad (crítico primero)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}
        failed_results.sort(key=lambda r: severity_order.get(r.severity.value, 99))

        for i, result in enumerate(failed_results, 1):
            print(f"\n   {i}. [{result.severity.value}] {result.check_id}")
            print(f"      Nombre: {result.check_name}")
            print(f"      Estado: {result.status.name}")
            print(f"      Detalle: {result.detail}")
            if result.vulnerabilities:
                print(f"      Vulnerabilidades identificadas: {len(result.vulnerabilities)}")
                for vuln in result.vulnerabilities[:2]:  # Mostrar máximo 2 vulns por check
                    print(f"        - {vuln.name} (CVSS: {vuln.cvss_score or 'N/A'})")
                if len(result.vulnerabilities) > 2:
                    print(f"        ... y {len(result.vulnerabilities) - 2} más")
            print(f"      Duración: {result.duration_ms}ms")

    # Detalle de checks passed (resumen)
    if report.passed_checks > 0:
        print(f"\nRESUMEN DE CHECKS EXITOSOS ({report.passed_checks} de {report.total_checks}):")
        passed_results = [r for r in report.check_results if r.status.name == "PASSED"]
        # Agrupar por severidad para mostrar los más importantes primero
        critical_passed = [r for r in passed_results if r.severity.value == "CRITICAL"]
        high_passed = [r for r in passed_results if r.severity.value == "HIGH"]
        medium_passed = [r for r in passed_results if r.severity.value == "MEDIUM"]
        low_passed = [r for r in passed_results if r.severity.value in ["LOW", "INFO"]]

        if critical_passed:
            print(f"   - Checks CRÍTICOS passed: {len(critical_passed)} (protecciones fuertes activas)")
        if high_passed:
            print(f"   - Checks ALTO passed: {len(high_passed)}")
        if medium_passed:
            print(f"   - Checks MEDIO passed: {len(medium_passed)}")
        if low_passed:
            print(f"   - Checks BAJO/INFO passed: {len(low_passed)}")

    # Recomendaciones principales
    if report.recommendations:
        print(f"\nRECOMENDACIONES PRINCIPALES:")
        # Mostrar las primeras 5 recomendaciones únicas
        unique_recs = list(dict.fromkeys(report.recommendations))[:5]
        for i, rec in enumerate(unique_recs, 1):
            print(f"   {i}. {rec}")
        if len(report.recommendations) > 5:
            print(f"   ... y {len(report.recommendations) - 5} recomendaciones adicionales disponibles en el reporte completo")

    # 8. Generar reportes de archivo
    print(f"\n7. Generando reportes de archivo...")
    output_dir = "audit_results"
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Reporte JSON
    json_filename = f"vulnguard_audit_{engine.platform.value}_{timestamp}.json"
    json_path = os.path.join(output_dir, json_filename)
    try:
        json_reporter = JsonReporter(report)
        json_reporter.generate(json_path)
        print(f"   OK: Reporte JSON guardado en: {json_path}")
    except Exception as e:
        print(f"   ERROR al generar reporte JSON: {e}")

    # Reporte HTML
    html_filename = f"vulnguard_audit_{engine.platform.value}_{timestamp}.html"
    html_path = os.path.join(output_dir, html_filename)
    try:
        html_reporter = HtmlReporter(report)
        html_reporter.generate(html_path)
        print(f"   OK: Reporte HTML guardado en: {html_path}")
        print(f"      Puede abrir este archivo en su navegador para una vista detallada")
    except Exception as e:
        print(f"   ERROR al generar reporte HTML: {e}")

    # 9. Conclusión
    print("\n" + "=" * 60)
    print("AUDITORIA COMPLETADA")
    print("=" * 60)

    if report.risk_score >= 80:
        print("   ACCION URGENTE REQUIERIDA: Su dispositivo presenta riesgos críticos de seguridad.")
        print("   Se recomienda tomar medidas inmediatas para mitigar las vulnerabilidades encontradas.")
    elif report.risk_score >= 60:
        print("   ATENCIÓN REQUIERIDA: Se encontraron vulnerabilidades de seguridad significativas.")
        print("   Se recomienda revisar y abordar los problemas identificados a la brevedad posible.")
    elif report.risk_score >= 40:
        print("   SE RECOMIENDA REVISIÓN: Se detectaron algunas cuestiones de seguridad que merecen atención.")
        print("   Considere mejorar la configuración de seguridad de su dispositivo.")
    elif report.risk_score >= 20:
        print("   SEGURIDAD ACEPTABLE: Riesgo bajo detectado.")
        print("   Mantenga las buenas prácticas de seguridad y realice auditorías periódicas.")
    else:
        print("   EXCELENTE SEGURIDAD: Su dispositivo muestra una buena postura de seguridad.")
        print("   Continúe manteniendo sus prácticas de seguridad actuales.")

    print(f"\n   Los reportes detallados están disponibles en el directorio: {os.path.abspath(output_dir)}")
    print(f"   - JSON: {json_filename}")
    print(f"   - HTML: {html_filename}")

    print("\n   ¡Gracias por usar VulnGuard para auditar la seguridad de su dispositivo móvil!")

    return 0

if __name__ == "__main__":
    sys.exit(main())