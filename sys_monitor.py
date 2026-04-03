import psutil
import os
import platform
import logging

# === Colores y Banner ===
CYAN, RED, GREEN, YELLOW, RESET = (
    "\033[96m",
    "\033[91m",
    "\033[92m",
    "\033[93m",
    "\033[0m",
)


def mostrar_banner():
    print(
        f"{CYAN}Iniciando Escaneo de Seguridad Optimizado (Arch Linux Edition){RESET}"
    )


# === Configuración ===
# Añadimos /usr/lib porque en Arch muchos binarios viven ahí
ubicaciones_confiables = [
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/lib",
]
nombres_peligrosos = {"mimikatz", "metasploit", "nc", "netcat", "socat", "nmap"}


def es_proceso_sospechoso(proceso):
    try:
        # 1. Ignorar el propio script y procesos de root básicos si no eres root
        if proceso.pid == os.getpid():
            return False, ""

        nombre = proceso.name().lower()
        # Usamos .exe() para obtener la ruta real del archivo
        ruta_exe = proceso.exe()

        # 2. Refinar búsqueda de nombres (evitar falsos positivos con 'service' o 'launch')
        if any(peligro == nombre for peligro in nombres_peligrosos):
            return True, f"Herramienta de hacking detectada por nombre exacto: {nombre}"

        # 3. Validar rutas (Arch Linux usa /usr/lib)
        if not any(ruta_exe.startswith(ruta) for ruta in ubicaciones_confiables):
            # Permitir aplicaciones instaladas en el HOME del usuario
            if not ruta_exe.startswith(os.path.expanduser("~")):
                return True, f"Ruta inusual: {ruta_exe}"

        # 4. Los huerfanos son normales si estan en /usr/lib o /usr/bin (systemd)
        if proceso.ppid() == 1:
            if not (ruta_exe.startswith("/usr/lib") or ruta_exe.startswith("/usr/bin")):
                return True, "Proceso huérfano fuera de rutas del sistema"

    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return False, ""


def escanear():
    mostrar_banner()
    alertas = []
    # Usamos net_connections() en lugar de proceso.connections() para evitar el DeprecationWarning
    for proc in psutil.process_iter(["pid", "name"]):
        sospecha, motivo = es_proceso_sospechoso(proc)
        if sospecha:
            alertas.append(f"[!] {proc.pid} ({proc.name()}) - {motivo}")

    if not alertas:
        print(f"{GREEN}[✔] Sistema optimizado y limpio.{RESET}")
    else:
        print(f"{YELLOW}Amenazas reales detectadas:{RESET}")
        for a in alertas:
            print(f"{RED}{a}{RESET}")


if __name__ == "__main__":
    escanear()
