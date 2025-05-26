import psutil
import os
import platform
import logging
from datetime import datetime

# === Colores ANSI para terminal ===
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# === Banner de bienvenida ===
def mostrar_banner():
    banner = f"""{BOLD}{CYAN}
  ╔══════════════════════════════════════╗
  ║   Sistema de Monitoreo de Procesos   ║
  ║              orami - 2025            ║
  ╚══════════════════════════════════════╝
{RESET}"""
    print(banner)

# === Configuración del log ===
directorio_logs = "logs"
os.makedirs(directorio_logs, exist_ok=True)
archivo_log = os.path.join(directorio_logs, "procesos_sospechosos.log")

logging.basicConfig(
    filename=archivo_log,
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# === Parámetros de configuración ===
nombres_sospechosos = {
    "mimikatz.exe", "powershell.exe", "powershell",
    "cmd.exe", "nc.exe", "netcat", "nmap", "python.exe"
}

ubicaciones_confiables = {
    "windows": ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"],
    "linux": ["/usr/bin", "/bin", "/usr/sbin", "/sbin"],
    "darwin": ["/Applications", "/usr/bin", "/System"]
}

rango_puertos_sospechosos = (49152, 65535)

tipo_sistema = platform.system().lower()
rutas_confiables = ubicaciones_confiables.get(tipo_sistema, [])

# === Verificación de proceso sospechoso ===
def es_proceso_sospechoso(proceso):
    try:
        nombre = proceso.name().lower()
        ejecutable = proceso.exe()
        padre = proceso.parent()
        directorio = proceso.cwd()

        if nombre in nombres_sospechosos:
            return True, f"Nombre sospechoso: {nombre}"

        if not any(ejecutable.startswith(ruta) for ruta in rutas_confiables):
            return True, f"Ubicación no confiable: {ejecutable}"

        if padre and padre.pid == 1:
            return True, f"Proceso huérfano: PID del padre = 1"

    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        pass

    return False, ""

# === Conexiones de red sospechosas ===
def detectar_conexiones_sospechosas(proceso):
    alertas = []
    try:
        conexiones = proceso.connections(kind='inet')
        for conexion in conexiones:
            direccion_remota = conexion.raddr
            if direccion_remota:
                ip = direccion_remota.ip
                puerto = direccion_remota.port

                if puerto >= rango_puertos_sospechosos[0]:
                    mensaje = f"[!] Conexión sospechosa: PID {proceso.pid} ({proceso.name()}) -> {ip}:{puerto}"
                    alertas.append(mensaje)
                    logging.warning(mensaje)

    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    return alertas

# === Escanear procesos activos ===
def escanear_procesos():
    alertas_totales = []
    for proceso in psutil.process_iter(['pid', 'name']):
        es_sospechoso, razon = es_proceso_sospechoso(proceso)
        if es_sospechoso:
            mensaje = f"[!] PID {proceso.pid} ({proceso.name()}) - {razon}"
            logging.warning(mensaje)
            alertas_totales.append(mensaje)

        alertas_red = detectar_conexiones_sospechosas(proceso)
        alertas_totales.extend(alertas_red)

    return alertas_totales

# === Mostrar resultados en pantalla ===
def mostrar_resultados(alertas):
    if not alertas:
        print(f"{GREEN}[OK] No se encontraron procesos o conexiones sospechosas.{RESET}")
    else:
        print(f"\n{YELLOW}[Resumen de alertas detectadas]{RESET}")
        for alerta in alertas:
            print(f"{RED}{alerta}{RESET}")

# === MAIN ===
if __name__ == "__main__":
    mostrar_banner()
    resultados = escanear_procesos()
    mostrar_resultados(resultados)
