import psutil
import os
import platform
import logging

# === Configuración de Rutas y Nombres (Específico Windows) ===
# Directorios donde NO es común que un usuario ejecute programas manualmente
rutas_criticas_windows = [
    "C:\\Windows\\System32", 
    "C:\\Windows\\SysWOW64",
    "C:\\Program Files",
    "C:\\Program Files (x86)"
]

# Procesos que el malware suele intentar suplantar o inyectar
procesos_criticos = {
    "lsass.exe", "svchost.exe", "wininit.exe", 
    "services.exe", "csrss.exe", "explorer.exe"
}

# Herramientas de hacking comunes en entornos Windows
black_list_windows = {
    "mimikatz.exe", "powershell.exe", "cmd.exe", 
    "psexec.exe", "nc.exe", "procdump.exe"
}

def es_proceso_sospechoso_windows(proceso):
    try:
        nombre = proceso.name().lower()
        ruta_exe = proceso.exe()
        
        # 1. Detección por nombre de herramienta conocida
        if nombre in black_list_windows:
            return True, f"Herramienta de administración/hacking activa: {nombre}"

        # 2. Análisis de "Masquerading" (Suplantación)
        # Si un proceso se llama 'lsass.exe' pero NO está en System32, es 100% malware
        if nombre in procesos_criticos:
            if "C:\\Windows\\System32" not in ruta_exe:
                return True, f"Proceso crítico ejecutándose desde ruta falsa: {ruta_exe}"

        # 3. Ejecución desde carpetas temporales (Táctica común de Phishing/Ransomware)
        # Malware suele correr desde AppData\Local\Temp o Descargas
        if "AppData\\Local\\Temp" in ruta_exe or "Downloads" in ruta_exe:
            return True, f"Ejecutable detectado en carpeta temporal/descargas: {ruta_exe}"

        # 4. Procesos sin descripción o fabricante (Opcional, requiere más permisos)
        # Muchos malwares no firman sus ejecutables.

    except (psutil.AccessDenied, psutil.NoSuchProcess):
        # En Windows, muchos procesos del sistema deniegan el acceso si no eres Admin
        pass
    return False, ""

def escanear_windows():
    print("--- Iniciando Escaneo de Seguridad en Windows ---")
    alertas = []
    
    for proc in psutil.process_iter(['pid', 'name']):
        sospecha, motivo = es_proceso_sospechoso_windows(proc)
        if sospecha:
            alertas.append(f"[!] ALERTA: PID {proc.pid} ({proc.name()}) - {motivo}")
            
    if not alertas:
        print("Sistema Windows aparentemente seguro.")
    else:
        for a in alertas:
            print(a)

if __name__ == "__main__":
    if platform.system().lower() == "windows":
        escanear_windows()
    else:
        print("Este perfil es exclusivo para Windows.")
