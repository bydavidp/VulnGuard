"""
Verifica conexiones de red activas y posibles riesgos de red.
"""

import subprocess
import re

from src.checks.android.base_check import SecurityCheck
from src.core.enums import Severity, CheckStatus
from src.core.models import SecurityCheckResult


class NetworkCheck(SecurityCheck):
    """
    Verifica:
      - Tipo de conexión activa (WiFi, móvil, VPN)
      - Conexiones establecidas sospechosas
      - DNS configurado (posible hijacking)
      - Proxy configurado
      - VPN activa
    """

    check_id = "network_security"
    check_name = "Seguridad de Red"
    description = "Analiza conexiones de red activas, VPN, proxy y posibles riesgos"
    severity = Severity.MEDIUM

    # Puertos sospechosos para conexiones salientes
    SUSPICIOUS_PORTS = {
        "4444": "Metasploit reverse shell",
        "1337": "Theef RAT / elite",
        "6666": "DarkComet RAT",
        "6667": "IRC (malware C2)",
        "7777": "Orwell RAT",
        "8080": "Proxy/C2 común",
        "8443": "C2 alternativa",
        "9001": "Tor obfs4 / C2",
    }

    # IPs/dominios de servicios de C2 conocidos (ejemplos educativos)
    SUSPICIOUS_DOMAINS_PATTERNS = [
        r"\.ru$", r"\.cn$", r"\.su$", r"\.kp$",
        r"\.top$", r"\.xyz$", r"\.pw$", r"\.tk$",
    ]

    DNS_SERVERS_KNOWN = {
        "8.8.8.8": "Google DNS",
        "8.8.4.4": "Google DNS",
        "1.1.1.1": "Cloudflare DNS",
        "9.9.9.9": "Quad9 DNS",
        "208.67.222.222": "OpenDNS",
        "208.67.220.220": "OpenDNS",
    }

    def _run(self) -> SecurityCheckResult:
        findings: list[dict] = []
        warnings: list[str] = []
        details: list[str] = []

        # 1. Verificar tipo de conexión activa
        try:
            result = subprocess.run(
                ["dumpsys", "connectivity"],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout

            # WiFi
            wifi_match = re.search(r'SSID:\s*"([^"]+)"', output)
            if wifi_match:
                details.append(f"WiFi conectado a: {wifi_match.group(1)}")

            # Móvil
            if "MOBILE" in output and "CONNECTED" in output:
                details.append("Red móvil (datos) conectada")

            # VPN
            vpn_match = re.search(r'\[vpn\].*?connected', output, re.IGNORECASE)
            if vpn_match:
                details.append("VPN activa")
            else:
                warnings.append("No se detectó VPN activa")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 2. Verificar conexiones establecidas
        try:
            result = subprocess.run(
                ["netstat", "-tn"],
                capture_output=True, text=True, timeout=10
            )
            connections = result.stdout.strip().split("\n")
            established = [
                conn.strip() for conn in connections
                if "ESTABLISHED" in conn or "ESTAB" in conn or "tcp" in conn
            ]

            suspicious_conns = []
            for conn in established:
                # Buscar puertos sospechosos
                for port, desc in self.SUSPICIOUS_PORTS.items():
                    if f":{port}" in conn:
                        suspicious_conns.append({
                            "connection": conn,
                            "suspicious_port": port,
                            "description": desc,
                        })

            if suspicious_conns:
                findings.extend(suspicious_conns)
                warnings.append(f"Conexiones a puertos sospechosos: {len(suspicious_conns)}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 3. Verificar DNS
        try:
            result = subprocess.run(
                ["getprop", "net.dns1"],
                capture_output=True, text=True, timeout=5
            )
            dns1 = result.stdout.strip()
            if dns1:
                dns_label = self.DNS_SERVERS_KNOWN.get(dns1, "DNS no reconocido")
                details.append(f"DNS: {dns1} ({dns_label})")
                if dns_label == "DNS no reconocido":
                    warnings.append(f"Servidor DNS no estándar: {dns1}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 4. Verificar proxy
        try:
            result = subprocess.run(
                ["settings", "get", "global", "http_proxy"],
                capture_output=True, text=True, timeout=5
            )
            proxy = result.stdout.strip()
            if proxy and proxy != ":0" and proxy != "null":
                findings.append({
                    "type": "proxy_configured",
                    "proxy": proxy,
                })
                warnings.append(f"Proxy HTTP configurado: {proxy}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 5. Verificar modo avión
        try:
            result = subprocess.run(
                ["settings", "get", "global", "airplane_mode_on"],
                capture_output=True, text=True, timeout=5
            )
            airplane = result.stdout.strip()
            if airplane == "1":
                details.append("Modo avión activo")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 6. Verificar estado WiFi (seguridad)
        try:
            result = subprocess.run(
                ["dumpsys", "wifi"],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout

            # Buscar redes guardadas inseguras
            if "WPA" not in output and "WPA2" not in output:
                if "open" in output.lower() or "none" in output.lower():
                    warnings.append("Posible red WiFi insegura detectada")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Determinar resultado
        has_findings = len(findings) > 0
        has_warnings = len(warnings) > 0

        if has_findings:
            status = CheckStatus.WARNING
            detail = f"Se encontraron {len(findings)} hallazgo(s) de red y {len(warnings)} advertencia(s)"
            severity = Severity.MEDIUM
        elif has_warnings:
            status = CheckStatus.WARNING
            detail = f"{len(warnings)} advertencia(s) de red"
            severity = Severity.LOW
        else:
            status = CheckStatus.PASSED
            detail = "Red: configuración sin riesgos detectados"
            severity = Severity.OK

        vulns = []
        if findings:
            find_str = "\n".join(
                f"   • {f.get('description', f.get('proxy', str(f)))}"
                for f in findings[:5]
            )
            vulns.append(self._vulnerability(
                name="Riesgos de red detectados",
                description=f"Hallazgos de red:\n{find_str}\nAdvertencias: {len(warnings)}",
                recommendation=(
                    "⚠️  REVISIÓN DE RED RECOMENDADA:\n"
                    "   • Conéctate solo a redes WiFi seguras (WPA2/WPA3)\n"
                    "   • Usa una VPN de confianza en redes públicas\n"
                    "   • Verifica que no haya proxies no autorizados\n"
                    "   • Revisa conexiones salientes sospechosas"
                ),
                cvss=5.5,
                cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            ))

        return self._result(
            status=status,
            detail=detail,
            recommendation=(
                "Revisa las conexiones de red y configuración de VPN/proxy."
                if has_findings
                else "✓ Configuración de red sin anomalías."
            ),
            vulnerabilities=vulns,
            raw_data={
                "findings": findings,
                "warnings": warnings,
                "details": details,
            },
            severity=severity,
        )
