Sistema de Monitoreo de Procesos - ORAMI
Una herramienta de monitoreo desarrollada en Python que detecta procesos y conexiones de red sospechosas en tiempo real. Ideal para análisis forense, pentesting defensivo y uso educativo en sistemas Linux, Android (Termux) o Windows (con modificaciones).
________________________________________
Características
•	Escanea todos los procesos activos del sistema.
•	Detecta procesos por:
o	Nombres sospechosos comunes (ej. mimikatz, netcat, etc.)
o	Ubicación de ejecución fuera de rutas confiables.
o	Procesos huérfanos (sin padre legítimo).
•	Revisa conexiones de red activas por cada proceso.
o	Destaca conexiones salientes a puertos efímeros (49152+).
•	Guarda un log de alertas en logs/procesos_sospechosos.log.
•	Incluye interfaz colorida en CLI con colores ANSI.
________________________________________
Requisitos
•	Python 3.12.10
•	Módulo psutil (multiplataforma)
Instalar dependencias:
  pip install psutil

Uso
Windows:
  PS C:\Users\ruta\del\archivo> python .\sys_monitor.py

Linux / Termux:
  sudo python3 sys_monitor.py
El resultado se mostrará en pantalla y se guardará un log en:
  logs/procesos_sospechosos.log
________________________________________
Estructura del proyecto
sys_monitor/
 ┣ sys_monitor.py          → Script principal
 ┗ logs/
    ┗ procesos_sospechosos.log   → Archivo de registro de alertas
________________________________________
Advertencias
•	En Termux o Android, es posible que algunos procesos estén protegidos. Ejecutar con permisos adecuados si es necesario.
•	El script no mata procesos ni bloquea conexiones, solo detecta y registra alertas.
________________________________________
Soporte para Android (Termux)
1.	Instala Termux desde F-Droid.
2.	Actualiza paquetes:
  pkg update && pkg upgrade
  pkg install python
  pip install psutil
4.	Ejecuta el script como en Linux:
  python sys_monitor.py
________________________________________
Autor
ORAMI (2025)
Seguridad Informática | Hacking Ético | Linux | Automatización
Proyecto educativo
________________________________________
Licencia

Este proyecto es de uso libre con fines educativos.
Distribuye, modifica o mejora con créditos al autor original.


