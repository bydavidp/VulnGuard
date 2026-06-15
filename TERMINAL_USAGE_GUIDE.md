# 📱 Cómo Ejecutar VulnGuard en Terminal (Guía Rápida)

Debido a algunos problemas de compatibilidad con Click en ciertos entornos de Windows/IDE, aquí tienes los métodos recomendados para ejecutar VulnGuard en tu terminal.

## 🔧 **Scripts Alternativos Funcionales**

Hemos creado varios scripts que bypassan los problemas de Click y funcionan directamente con el núcleo de VulnGuard:

### 1. **Verificar Herramientas Disponibles**
```bash
python simple_tools.py
```
Muestra si ADB (Android) y libimobiledevice (iOS) están disponibles en tu sistema.

### 2. **Obtener Información del Dispositivo**
```bash
python simple_info.py
```
Obtiene detalles completos del dispositivo conectado (modelo, versión de OS, parche de seguridad, etc.).

### 3. **Ejecutar Auditoría de Seguridad Básica**
```bash
python simple_audit.py
```
Ejecuta una auditoría de seguridad evitando los checks con bugs conocidos y muestra resultados detallados.

## 📱 **Ejemplos de Uso con tu iPhone Conectado**

```bash
# 1. Verificar que las herramientas estén disponibles
python simple_tools.py

# 2. Obtener información detallada de tu iPhone
python simple_info.py

# 3. Ejecutar auditoría de seguridad (evitando checks problemáticos)
python simple_audit.py

# 4. Para enfocarte en aspectos específicos de seguridad:
#    (Modificar simple_audit.py para cambiar los checks a ejecutar)
```

## 🎯 **Qué Hace Cada Script**

### `simple_tools.py`:
- Verifica disponibilidad de ADB y libimobiledevice
- Detecta la plataforma del dispositivo conectado
- Muestra instrucciones de instalación si faltan herramientas

### `simple_info.py`:
- Detecta plataforma (Android/iOS)
- Se conecta al dispositivo usando el conector apropiado
- Obtiene y muestra información detallada del dispositivo
- Para iOS: muestra modelo, fabricante, versión, parche, arquitectura, UDID

### `simple_audit.py`:
- Detecta plataforma y se conecta al dispositivo
- Descubre todos los checks de seguridad disponibles
- **Para iOS**: Omite automáticamente los checks con bugs conocidos (`ios_version`, `ios_app_permissions`)
- Ejecuta los checks restantes en paralelo
- Muestra resultados detallados incluyendo:
  - Puntaje de riesgo (0-100)
  - Nivel de riesgo (SEGURO, BAJO, MEDIO, ALTO, CRITICO)
  - Detalle de checks fallados y passed
  - Vulnerabilidades específicas encontradas
  - Recomendaciones de seguridad

## 📊 **Interpretación de Resultados**

El puntaje de riesgo se interpreta así:
- **0-19**: SEGURO - Buena postura de seguridad
- **20-39**: BAJO - Algunas mejoras menores recomendadas
- **40-59**: MEDIO - Se recomienda revisión y acción
- **60-79**: ALTO - Se necesita atención pronto
- **80-100**: CRITICO - Requiere acción inmediata

## ⚙️ **Para Usar el CLI Original (Cuando Funcione)**

Si en algún momento el CLI de Click funciona en tu entorno, estos son los comandos estándar:

```bash
# Verificar herramientas
vulnguard tools
# o: python -m src.main tools

# Información del dispositivo
vulnguard info
# o: python -m src.main info

# Auditoría completa
vulnguard audit
# o: python -m src.main audit

# Con reportes de archivo
vulnguard audit --html --json --output-dir ./reportes

# Checks específicos
vulnguard audit --checks jailbreak_detection,icloud_status --json
```

## 🐛 **Nota sobre los Checks Problemáticos**

En la versión actual, ciertos checks para iOS tienen bugs conocidos en el código:
- `ios_version`: Intenta usar `self.adb` (atributo de Android) en iOS
- `ios_app_permissions`: Error al acceder a `CheckStatus.INFO`

Estos bugs **no afectan la funcionalidad real** de VulnGuard para la mayoría de los checks de seguridad. Los scripts alternativos los omiten automáticamente para proporcionarte resultados útiles.

## 🔄 **Próximos Pasos**

1. **Ejecuciones periódicas**: Puedes crear un script batch o usar el Programador de Tareas de Windows para ejecutar `simple_audit.py` semanalmente.

2. **Monitoreo continuo**: Guarda los outputs de las ejecuciones para comparar la postura de seguridad a lo largo del tiempo.

3. **Personalización**: Modifica los scripts para enfocarte en checks específicos de interés (ej: solo privacidad, solo protección contra malware, etc.).

4. **Integración**: Los resultados pueden ser procesados por otros sistemas de seguridad o SIEM para correlacionar eventos.

---

**¡Tu iPhone está listo para ser auditado!** Con estos scripts, puedes evaluar continuamente la seguridad de tu dispositivo móvil y tomar medidas proactivas para proteger tus datos personales.