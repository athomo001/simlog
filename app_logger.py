# app_logger.py

"""
Módulo de logging para registrar la actividad y errores del simulador de logs.
"""

import logging
import os
from datetime import datetime

# --- Configuración del Logger ---

LOG_FILENAME = 'logs_simlog/simlog.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Crear el logger principal para esta aplicación
logger = logging.getLogger('SimLogAppLogger')
logger.setLevel(logging.DEBUG) # Capturar todos los niveles de mensajes

# Crear un manejador de archivo (FileHandler)
try:
    # Usar 'a' para modo append (agregar al archivo existente)
    file_handler = logging.FileHandler(LOG_FILENAME, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO) # Escribir mensajes INFO y superiores en el archivo
except IOError as e:
     print(f"[ERROR CRÍTICO] No se pudo abrir o crear el archivo de log '{LOG_FILENAME}': {e}")
     # Usar un handler nulo para evitar errores posteriores si falla la creación del archivo.
     file_handler = logging.NullHandler()

# Crear un formateador
formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
file_handler.setFormatter(formatter)

# Añadir el manejador al logger
# Evitar añadir handlers duplicados si este módulo se recarga
if not logger.hasHandlers():
    logger.addHandler(file_handler)

    # Opcional: Añadir un manejador de consola (StreamHandler) para ver logs en pantalla también
    # console_handler = logging.StreamHandler()
    # console_handler.setLevel(logging.WARNING) # Mostrar WARNING y superiores en consola
    # console_handler.setFormatter(formatter)
    # logger.addHandler(console_handler)


# --- Funciones de Logging Específicas ---

def log_simulation_start(technologies, target_ip, target_port, protocol, total_logs, interval):
    """Registra el inicio de una simulación con información clave."""
    tech_str = ", ".join(technologies) if technologies else "Ninguna"
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    msg = (f"[INICIO] Simulación iniciada a las {start_time}. "
           f"Tecnologías: [{tech_str}], Destino: {target_ip}:{target_port} ({protocol}), "
           f"Total Logs: {total_logs}, Intervalo: {interval}s")
    logger.info(msg)
    return start_time  # Devolver la hora de inicio para calcular la duración

def log_simulation_end(logs_attempted, logs_sent_ok):
    log_info(f"Simulación terminada. Logs intentados: {logs_attempted}, Logs enviados: {logs_sent_ok}")

def log_info(message):
    """Registra un mensaje informativo general."""
    logger.info(message)

def log_warning(message):
    """Registra un mensaje de advertencia general."""
    logger.warning(message)

def log_error(message):
    """Registra un mensaje de error general."""
    logger.error(message)

def log_critical(message):
    """Registra un mensaje crítico general."""
    logger.critical(message)

def log_debug(message):
     """Registra un mensaje de depuración (puede que no vaya al archivo por defecto)."""
     logger.debug(message)

def log_generation_error(template, keys, error_msg):
    log_error(f"Error generando log. Plantilla: {template[:100]}..., Claves disponibles: {list(keys)}, Error: {error_msg}")

# --- Configuración adicional para placeholders no encontrados ---
PLACEHOLDERS_LOG_FILENAME = 'logs_simlog/placeholders_not_found.log'

def log_placeholder_not_found(placeholder):
    """
    Registra un placeholder no encontrado en el archivo 'placeholders_not_found.log'.
    Cada placeholder se guarda en una línea sin formato adicional.
    """
    try:
        with open(PLACEHOLDERS_LOG_FILENAME, 'a', encoding='utf-8') as f:
            f.write(f"{placeholder}\n")
    except IOError as e:
        logger.error(f"[ERROR] No se pudo escribir en el archivo '{PLACEHOLDERS_LOG_FILENAME}': {e}")

# Ejemplo de uso de log_critical con exc_info
try:
    # Simulación de un error crítico
    raise ValueError("Simulación de un error crítico")
except Exception as e:
    log_critical(f"Error crítico durante el bucle de envío: {e}")