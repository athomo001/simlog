def mostrar_progreso(actual, total):
    porcentaje = (actual / total) * 100
    print(f"\rProgreso: {actual}/{total} ({porcentaje:.2f}%)", end="")
import os

def cargar_plantillas(tecnologia):
    """
    Carga plantillas de log desde un archivo asociado a una tecnología.

    Args:
        tecnologia (str): Nombre de la tecnología.

    Returns:
        list: Lista de plantillas cargadas desde el archivo.
    """
    from config import LOG_FILES  # Importar el diccionario LOG_FILES desde config
    archivo = LOG_FILES.get(tecnologia)
    plantillas = []
    if archivo and os.path.exists(archivo):
        try:
            with open(archivo, 'r', encoding='utf-8') as f:
                plantillas = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not plantillas:
                print(f"[ADVERTENCIA] El archivo de logs para '{tecnologia}' ({archivo}) está vacío o solo contiene comentarios.")
        except Exception as e:
            print(f"[ERROR] No se pudo leer el archivo {archivo} para '{tecnologia}': {e}")
    elif not archivo:
        print(f"[ERROR] No se encontró una ruta de archivo definida para la tecnología: '{tecnologia}' en LOG_FILES.")
    else:
        print(f"[ERROR] El archivo de logs '{archivo}' para la tecnología '{tecnologia}' no existe.")
    return plantillas