# 🛡️ VulnGuard — Android Security Auditor

Herramienta profesional de **auditoría de seguridad para dispositivos Android**.  
Ejecuta múltiples verificaciones de seguridad y genera reportes detallados en consola, JSON y HTML.

> ⚠️ **Solo para usar en tus propios dispositivos o con autorización explícita del propietario.**

---

## 🚀 Características

| Característica | Descripción |
|---|---|
| ✅ **12+ verificaciones** | Root, SELinux, versión Android, USB Debugging, apps sospechosas, permisos, cifrado, bloqueo de pantalla, red, Play Protect, opciones de desarrollo, backup |
| 📊 **Reportes múltiples** | Consola con colores, JSON estructurado, HTML interactivo |
| 🎯 **Puntaje de riesgo** | Basado en principios CVSS 3.1 con severidad ponderada |
| 🔌 **Conexión flexible** | USB, TCP/IP, detección automática de dispositivos |
| ⚡ **Ejecución paralela** | Checks ejecutados en paralelo para máximo rendimiento |
| 🔍 **Checks individuales** | Ejecuta checks específicos con `--checks` |
| 📱 **Info del dispositivo** | Modelo, fabricante, versión Android, parche de seguridad, SDK |

---

## 📋 Verificaciones Incluidas

| ID | Nombre | Severidad |
|---|---|---|
| `root_detection` | Estado de Root | 🔴 CRÍTICO |
| `selinux_status` | Estado de SELinux | 🟠 ALTO |
| `android_version` | Versión de Android y Parche | 🟠 ALTO |
| `usb_debugging` | USB Debugging y ADB | 🟠 ALTO |
| `suspicious_apps` | Aplicaciones Sospechosas | 🟠 ALTO |
| `permissions_analysis` | Análisis de Permisos | 🟡 MEDIO |
| `device_encryption` | Cifrado del Dispositivo | 🟠 ALTO |
| `screen_lock` | Bloqueo de Pantalla | 🟠 ALTO |
| `network_security` | Seguridad de Red | 🟡 MEDIO |
| `play_protect` | Google Play Protect | 🟡 MEDIO |
| `developer_options` | Opciones de Desarrollo | 🟡 MEDIO |
| `backup_config` | Configuración de Backup | 🟡 MEDIO |

---

## 🔧 Instalación

### Requisitos

- Python 3.9 o superior
- ADB (Android Debug Bridge) en el PATH
- Dispositivo Android con USB Debugging habilitado

### Instalación rápida

```bash
# Clonar o copiar el proyecto
cd VulnGuard

# Instalar dependencias
pip install -r requirements.txt

# (Opcional) Instalar como paquete
pip install -e .
```

---

## 📖 Uso

### Auditoría completa

```bash
python -m src.main audit
```

### Auditoría con reporte HTML

```bash
python -m src.main audit --html
```

### Todos los formatos de reporte

```bash
python -m src.main audit --json --html --output-dir ./mis_reportes
```

### Solo checks específicos

```bash
python -m src.main audit --checks root_detection,selinux_status,usb_debugging
```

### Conexión TCP/IP

```bash
python -m src.main audit --host 192.168.1.100 --port 5555
```

### Listar checks disponibles

```bash
python -m src.main audit --list-checks

# O también
python -m src.main checks
```

### Información del dispositivo

```bash
python -m src.main info
```

### Modo verbose (más detalles)

```bash
python -m src.main audit --verbose
```

### Usando el comando instalado

```bash
vulnguard audit --html
vulnguard checks
vulnguard info
```

---

## 📊 Ejemplo de Salida (Consola)

```
🔒 VULNGUARD — AUDITORÍA DE SEGURIDAD ANDROID

🎯  DISPOSITIVO
   Modelo:        Pixel 7
   Fabricante:    Google
   Android:       14
   Parche:        2024-01-01

📊  RESUMEN DE RIESGO
   Nivel:         SEGURO (0/100)
   Vulnerabil.:   0 de 12 checks fallaron

VERIFICACIONES DETALLADAS
  ✅ Estado de Root        [OK]       PASSED
  ✅ Estado de SELinux     [OK]       PASSED
  ...
```

## 📁 Estructura del Proyecto

```
VulnGuard/
├── src/
│   ├── core/           # Modelos de dominio
│   │   ├── models.py   # Dataclasses: DeviceInfo, AuditReport, Vulnerability
│   │   ├── enums.py    # Severity, CheckStatus, RiskLevel
│   │   └── risk_score.py  # Cálculo de riesgo (CVSS-based)
│   ├── checks/         # Módulos de verificación (plugins)
│   │   ├── base_check.py   # Clase base abstracta
│   │   ├── root_check.py
│   │   ├── selinux_check.py
│   │   └── ... (12 checks)
│   ├── engine/         # Motor de auditoría
│   ├── reporters/      # Generadores de reportes
│   │   ├── console_reporter.py
│   │   ├── json_reporter.py
│   │   └── html_reporter.py
│   ├── utils/          # Utilidades
│   │   ├── adb_connector.py  # Conexión ADB
│   │   ├── logger.py
│   │   └── helpers.py
│   └── cli/            # Interfaz de línea de comandos
├── tests/              # Tests unitarios
├── reports/            # Reportes generados
└── pyproject.toml      # Configuración del proyecto
```

---

## 🧪 Tests

```bash
# Ejecutar todos los tests
pytest

# Con cobertura
pytest --cov=src --cov-report=html

# Tests específicos
pytest tests/test_core_models.py -v
```

---

## 🏗️ Arquitectura

El proyecto sigue una **arquitectura modular por capas**:

```
CLI → AuditEngine → SecurityCheck (x12) → AuditReport → Reporters
  │         │              │                    │
  │    AdbConnector   subprocess.run       Console/JSON/HTML
  │         │
  │    Dispositivo Android
```

- **Core**: Modelos puros de dominio sin dependencias externas
- **Checks**: Cada verificación es una clase independiente y extensible
- **Engine**: Orquestador que gestiona la ejecución (paralela/secuencial)
- **Reporters**: Múltiples formatos de salida (console, JSON, HTML)
- **Utils**: Conector ADB, logging, funciones auxiliares

---

## ⚙️ Requisitos del Dispositivo

1. **USB Debugging activado**: Ajustes > Opciones de Desarrollo > USB Debugging
2. **Conexión USB**: Cable conectado al ordenador
3. **Confianza RSA**: Aceptar la clave RSA en el dispositivo cuando aparezca
4. **ADB en PATH**: `adb` debe estar accesible desde la terminal

### Verificar conexión

```bash
adb devices
# Debería mostrar: <serial>    device
```

---

## 🔒 Consideraciones Éticas

VulnGuard es una herramienta de **seguridad defensiva**. Está diseñada para:

- Auditar tus **propios dispositivos**
- Realizar pruebas de seguridad con **autorización explícita**
- Identificar vulnerabilidades para **corregirlas**

**No uses esta herramienta en dispositivos que no te pertenezcan o sin autorización.**

---

## 📄 Licencia

MIT License — Ver [LICENSE](LICENSE) para más detalles.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Haz fork del proyecto
2. Crea una rama para tu feature (`git checkout -b feature/amazing-feature`)
3. Commit tus cambios (`git commit -m 'feat: add amazing feature'`)
4. Push a la rama (`git push origin feature/amazing-feature`)
5. Abre un Pull Request
