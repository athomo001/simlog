# app_logger.py

"""
Módulo de logging para registrar la actividad y errores del simulador de logs.
"""

import logging
import os
from datetime import datetime

# --- Configuración del Logger ---

LOG_FILENAME = 'simulator_activity.log'
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
    """Registra el inicio de una simulación."""
    tech_str = ", ".join(technologies) if technologies else "Ninguna"
    msg = (f"Inicio de simulación: Tecnologías=[{tech_str}], Destino={target_ip}:{target_port} ({protocol}), "
           f"Total Logs={total_logs}, Intervalo={interval}s")
    logger.info(msg)

def log_template_load_warning(technology, filename, reason):
    """Registra una advertencia durante la carga de plantillas."""
    msg = f"Advertencia carga plantillas: Tecnología='{technology}', Archivo='{filename}', Razón='{reason}'"
    logger.warning(msg)

def log_template_load_error(technology, filename, error):
    """Registra un error durante la carga de plantillas."""
    msg = f"Error carga plantillas: Tecnología='{technology}', Archivo='{filename}', Error='{error}'"
    logger.error(msg)

def log_generation_error(template, data_keys, error):
    """Registra un error al formatear una plantilla de log."""
    template_preview = template[:100] + '...' if len(template) > 100 else template
    msg = (f"Error generación log: Error='{error}', Plantilla='{template_preview}', "
           f"Claves de datos disponibles={list(data_keys)}")
    logger.error(msg)

def log_send_error(target_info, error):
    """Registra un error durante el envío de un log Syslog."""
    msg = f"Error envío Syslog: Destino='{target_info}', Error='{error}'"
    logger.error(msg)

def log_connection_error(target_info, error):
    """Registra un error al establecer la conexión inicial (ej. TCP)."""
    msg = f"Error conexión Syslog: Destino='{target_info}', Error='{error}'"
    logger.critical(msg) # Error crítico si no se puede conectar al inicio

def log_simulation_end(logs_attempted, logs_sent_ok):
    """Registra el final de una simulación."""
    msg = (f"Fin de simulación: Logs intentados={logs_attempted}, "
           f"Logs enviados OK (aprox.)={logs_sent_ok}")
    logger.info(msg)

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

# --- Configuración adicional para placeholders no encontrados ---
PLACEHOLDERS_LOG_FILENAME = 'placeholders_not_found.log'

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