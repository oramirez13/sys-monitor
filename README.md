# Sys Monitor

Sys Monitor es un script de consola que revisa procesos activos y marca algunos casos básicos que podrían requerir una revisión manual.

## Screenshots

![Sys Monitor](Screenshot%202025-05-26%20072739.png)
![Sys Monitor](Screenshot%202025-05-26%20072826.png)
![Sys Monitor](Screenshot%202025-05-26%20073855.png)
![Sys Monitor](Screenshot%202025-05-26%20074119.png)
![Sys Monitor Windows](win_sys_monitor.png)

## Funciones

- Recorre procesos del sistema con `psutil`.
- Busca nombres sensibles definidos en una lista simple.
- Marca rutas de ejecución poco comunes fuera de directorios confiables.
- Señala algunos procesos huérfanos fuera de rutas normales del sistema.

## Requisitos

- Python 3.11 o superior

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Ejecución

```bash
python sys_monitor.py
```

## Estructura

- `sys_monitor.py`: archivo principal del proyecto.
- `requirements.txt`: dependencia de Python usada por el script.

## Nota

Las alertas de este proyecto son heurísticas básicas y deben interpretarse como apoyo, no como una confirmación automática de amenaza.
