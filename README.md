Aquí tienes la versión profesional y limpia del README en formato Markdown, sin emojis, ideal para un perfil de GitHub más sobrio:

---

# Sentinel-Monitor: EDR Universal (Python)

Sentinel-Monitor es una herramienta de detección y respuesta en endpoints (EDR) desarrollada en Python. Su objetivo es identificar procesos sospechosos y conexiones de red anómalas en tiempo real mediante el análisis de indicadores de compromiso (IoC) locales.

---

## Características Principales

* **Detección Multi-Vector:**
    * **Listas Negras de Nombres:** Identifica herramientas de post-explotación (Mimikatz, Netcat, Nmap, etc.).
    * **Análisis de Rutas (Path Hijacking):** Detecta ejecutables corriendo desde directorios inusuales (/tmp, AppData\Temp) o suplantando procesos del sistema (Masquerading).
    * **Monitoreo de Parentesco:** Identifica procesos huérfanos (padre PID 1) que intentan evadir el rastreo del árbol de procesos.
* **Auditoría de Red:** Escaneo de conexiones activas hacia puertos efímeros o sospechosos (49152+).
* **Logging Forense:** Registro detallado de incidentes en logs/auditoria_seguridad.log.
* **Interfaz CLI:** Salida visual optimizada con códigos de colores ANSI para una respuesta rápida del analista.

---

## Requisitos e Instalación

### Dependencias
El proyecto requiere Python 3.12+ y la librería psutil.

```bash
# Clonar el repositorio
git clone https://github.com/TU_USUARIO/sentinel-monitor.git
cd sentinel-monitor

# Configurar entorno virtual (Recomendado)
python -m venv venv
source venv/bin/activate  # En Windows: .\venv\Scripts\activate

# Instalar requerimientos
pip install psutil
```

---

## Uso por Plataforma

### **Linux (Arch / Kali / Ubuntu)**
Para una visibilidad total de los procesos de sistema, se recomienda ejecutar con privilegios:
```bash
sudo ./venv/bin/python monitor_universal.py
```

### **Windows 10/11 Pro**
Ejecutar en una terminal con permisos de Administrador para permitir el acceso a los tokens de procesos críticos:
```powershell
python monitor_universal.py
```

### **Android (Termux)**
Ideal para monitorear procesos en dispositivos móviles:
```bash
pkg update && pkg upgrade
pkg install python
pip install psutil
python monitor_universal.py
```

---

## Arquitectura del Sistema
El script utiliza una arquitectura de Escaneo Pasivo:
1.  **Ingesta:** Recopila la tabla de procesos del Kernel mediante /proc (Linux) o la API de Windows.
2.  **Filtrado:** Aplica reglas dinámicas basadas en el sistema operativo detectado (platform.system()).
3.  **Alerta:** Cruza los datos con la lista negra de rutas y nombres, generando una alerta inmediata si hay coincidencia.

---

## Advertencias y Limitaciones
* **Falsos Positivos:** Debido a la naturaleza estricta del monitor, aplicaciones legítimas instaladas en rutas no estándar podrían generar alertas.
* **Solo Lectura:** El script no termina procesos automáticamente para evitar la interrupción de servicios críticos del sistema.
* **Privilegios:** Sin permisos de Superusuario o Administrador, el alcance del escaneo se limitará solo a los procesos del usuario actual.

---

## Autor
**ORAMI (2025)**
Estudiante de Ciberseguridad | Entusiasta de Arch Linux | Desarrollador Python & C

---

## Licencia
Este proyecto se distribuye bajo la licencia MIT. Se permite el uso, modificación y distribución para fines educativos, otorgando el crédito correspondiente al autor original.
