import os

import psutil

# Estas constantes guardan colores ANSI simples para la salida en terminal.
CYAN = "\033[96m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Esta lista define rutas del sistema que suelen ser normales.
TRUSTED_PATHS = [
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/lib",
]

# Este conjunto guarda algunos nombres que pueden ser delicados en un analisis.
SUSPICIOUS_NAMES = {"mimikatz", "metasploit", "nc", "netcat", "socat", "nmap"}


def mostrar_banner():
    # Esta linea imprime un titulo corto al iniciar el programa.
    print(f"{CYAN}Monitor simple de procesos sospechosos{RESET}")


def ruta_es_confiable(executable_path):
    # Este ciclo revisa si la ruta empieza por una ubicacion confiable.
    for trusted_path in TRUSTED_PATHS:
        if executable_path.startswith(trusted_path):
            return True

    # Si no coincide con ninguna ruta confiable, devolvemos False.
    return False


def es_proceso_sospechoso(process):
    try:
        # Si el proceso es el mismo script, no lo marcamos.
        if process.pid == os.getpid():
            return False, ""

        # Esta linea obtiene el nombre del proceso en minusculas.
        name = process.name().lower()

        # Esta linea obtiene la ruta del ejecutable.
        executable_path = process.exe()

        # Si el nombre coincide exactamente con una herramienta sensible, se marca.
        if name in SUSPICIOUS_NAMES:
            return True, f"Nombre sensible detectado: {name}"

        # Si la ruta no es confiable, revisamos si esta dentro del home del usuario.
        if not ruta_es_confiable(executable_path):
            user_home = os.path.expanduser("~")
            if not executable_path.startswith(user_home):
                return True, f"Ruta poco comun: {executable_path}"

        # Si el padre es 1 y no viene de rutas de sistema conocidas, se marca.
        if process.ppid() == 1:
            if not executable_path.startswith(
                "/usr/lib"
            ) and not executable_path.startswith("/usr/bin"):
                return True, "Proceso huerfano fuera de rutas del sistema"

    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        # Si no se puede leer el proceso, lo ignoramos sin detener el programa.
        return False, ""

    # Si no se encontro nada raro, devolvemos False.
    return False, ""


def escanear():
    # Esta linea muestra el banner del proyecto.
    mostrar_banner()

    # Esta lista guardara las alertas encontradas.
    alerts = []

    # Este ciclo revisa los procesos activos del sistema.
    for process in psutil.process_iter(["pid", "name"]):
        suspicious, reason = es_proceso_sospechoso(process)

        # Si el proceso parece sospechoso, se guarda un mensaje claro.
        if suspicious:
            alerts.append(f"[!] PID {process.pid} ({process.name()}) - {reason}")

    # Si no hubo alertas, se informa con un mensaje simple.
    if len(alerts) == 0:
        print(
            f"{GREEN}[+] No se detectaron procesos sospechosos con las reglas basicas.{RESET}"
        )
        return

    # Si hubo alertas, se muestran una por una.
    print(f"{YELLOW}[!] Posibles hallazgos detectados:{RESET}")
    for alert in alerts:
        print(f"{RED}{alert}{RESET}")


if __name__ == "__main__":
    # Esta condicion ejecuta el escaneo solo si el archivo se corre directamente.
    escanear()
