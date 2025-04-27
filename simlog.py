# main.py

"""
Punto de entrada principal para el Simulador de Logs Syslog.

Coordina la selección de tecnología, carga de plantillas, generación de datos,
envío de logs y registro de actividad de la aplicación.
"""

import random
import time
import os
import math
from datetime import datetime

# Importar los módulos propios
import config
import data_generators
import syslog_sender
import utils
import app_logger

# --- Interfaz de Usuario ---

def mostrar_nuevo_menu_seleccion():
    """
    Muestra el menú de selección de tecnologías y procesa la entrada del usuario.

    Utiliza config.LOG_FILES para obtener las tecnologías disponibles.

    Returns:
        list: Lista con los nombres de las tecnologías seleccionadas,
              o lista vacía si el usuario no selecciona nada válido.
    """
    tecnologias = list(config.LOG_FILES.keys())
    num_tecnologias = len(tecnologias)
    if num_tecnologias == 0:
        print("[ERROR] No hay tecnologías definidas en config.LOG_FILES.")
        app_logger.log_error("El diccionario config.LOG_FILES está vacío.")
        return []

    opcion_todos = num_tecnologias + 1
    # Calcular columnas dinámicamente (aproximado)
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = 80 # Valor por defecto si no se puede obtener
    ancho_columna_deseado = 30 # Ancho deseado para cada opción
    columnas = max(1, terminal_width // ancho_columna_deseado)
    ancho_columna_real = terminal_width // columnas # Distribuir espacio

    print("\nSelecciona las marcas de logs que deseas utilizar:")
    print("Ingresa los números separados por comas (ej: 1,3,5) o el número para 'Todos'.")
    print("-" * (ancho_columna_real * columnas))

    for i in range(0, num_tecnologias, columnas):
        linea = ""
        for j in range(columnas):
            idx = i + j
            if idx < num_tecnologias:
                opcion_str = f"{(idx+1):<3d} {tecnologias[idx]}" # Alineación simple
                linea += opcion_str.ljust(ancho_columna_real)
            else:
                linea += " " * ancho_columna_real
        print(linea.rstrip()) # Eliminar espacios extra al final

    # Añadir opción "Todos"
    print(f"{opcion_todos:<3d} {'Todos'.ljust(ancho_columna_real-4)}")
    print("-" * (ancho_columna_real * columnas))

    seleccionadas = []
    while True: # Bucle hasta obtener entrada válida o salir
        entrada = input("Ingrese opción/opciones y después ENTER (o 'q' para salir): ").strip()

        if entrada.lower() == 'q':
            print("Saliendo...")
            app_logger.log_info("Usuario eligió salir desde el menú de selección.")
            return [] # Retorna lista vacía para indicar salida

        try:
            numeros_str = [n.strip() for n in entrada.split(',') if n.strip()]
            if not numeros_str:
                 print("[ERROR] Entrada vacía. Por favor, ingresa números o 'q'.")
                 continue

            numeros_int = [int(n) for n in numeros_str]

            if opcion_todos in numeros_int:
                if len(numeros_int) > 1:
                    print(f"[ADVERTENCIA] Seleccionaste '{opcion_todos} Todos' junto con otras opciones. Se seleccionarán todas las tecnologías.")
                    app_logger.log_warning("Usuario seleccionó 'Todos' junto con otras opciones. Se usarán todas.")
                print("Seleccionando todas las tecnologías.")
                return tecnologias # Devuelve la lista completa

            opciones_validas = True
            temp_seleccionadas = []
            numeros_invalidos = []
            for num in numeros_int:
                if 1 <= num <= num_tecnologias:
                    temp_seleccionadas.append(tecnologias[num-1])
                else:
                    numeros_invalidos.append(str(num))
                    opciones_validas = False

            if not opciones_validas:
                print(f"[ERROR] Números fuera de rango: {', '.join(numeros_invalidos)}. Las opciones válidas son de 1 a {opcion_todos}.")
                app_logger.log_warning(f"Usuario ingresó números inválidos: {', '.join(numeros_invalidos)}")
                continue # Vuelve a pedir entrada

            # Eliminar duplicados manteniendo el orden y verificar si hay algo
            seleccionadas = list(dict.fromkeys(temp_seleccionadas))
            if seleccionadas:
               print(f"Seleccionaste: {', '.join(seleccionadas)}")
               return seleccionadas
            else:
                # Esto no debería ocurrir si la validación anterior funciona, pero por si acaso
                print("[ERROR] No se pudo procesar la selección. Intenta de nuevo.")
                app_logger.log_error("Fallo inesperado al procesar selección de tecnologías.")

        except ValueError:
            print("[ERROR] Entrada inválida. Asegúrate de ingresar solo números separados por comas o 'q'.")
            app_logger.log_warning(f"Entrada inválida del usuario en menú: '{entrada}'")
        except Exception as e:
            print(f"[ERROR] Ocurrió un error inesperado procesando la entrada: {e}")
            app_logger.log_error(f"Error inesperado en menú: {e}", exc_info=True) # Log con traceback

# --- Generación de Datos Específica ---

def generar_datos_para_log():
    """
    Genera un diccionario de datos aleatorios para rellenar una plantilla de log.
    Utiliza las funciones del módulo data_generators.

    Returns:
        dict: Diccionario con claves y valores aleatorios (todos como strings).
    """
    # Reutiliza la función original, pero ahora llama a data_generators.*
    data = {
        # Timestamps y básicos
        'date': datetime.now().strftime('%Y-%m-%d'),
        'time': datetime.now().strftime('%H:%M:%S'),
        'timestamp_bsd': data_generators.random_bsd_timestamp(),
        'timestamp_unix': data_generators.random_unix_timestamp(),
        'timestamp_iso': data_generators.random_iso_timestamp(),
        'timestamp_sql': data_generators.random_sql_timestamp(),
        'w3c_date': data_generators.random_w3c_datetime()[0],
        'w3c_time': data_generators.random_w3c_datetime()[1],
        'hostname': data_generators.random_hostname(),
        'severity': data_generators.random_severity(),
        'logid': data_generators.random_logid(),
        'pid': data_generators.random_process_id(),
        'message': random.choice(['Operation successful', 'Access denied', 'Configuration updated', 'Connection established', 'File downloaded', 'Scan complete', 'User logged out', 'Service started', 'Service stopped']),

        # Red
        'src_ip': data_generators.random_ip(random.choice(['internal', 'external', 'any'])),
        'dst_ip': data_generators.random_ip(random.choice(['internal', 'external', 'any'])),
        'src': data_generators.random_ip(random.choice(['internal', 'external', 'any'])), # Alias
        'dst': data_generators.random_ip(random.choice(['internal', 'external', 'any'])), # Alias
        'src_port': data_generators.random_port(random.choice(['ephemeral', 'well-known', 'any'])),
        'dst_port': data_generators.random_port(random.choice(['ephemeral', 'well-known', 'any'])),
        'sport': data_generators.random_port(random.choice(['ephemeral', 'well-known', 'any'])), # Alias
        'dport': data_generators.random_port(random.choice(['ephemeral', 'well-known', 'any'])), # Alias
        'port': data_generators.random_port(random.choice(['ephemeral', 'well-known', 'any'])), # General
        'protocol': data_generators.random_protocol(),
        'interface': data_generators.random_interface(),
        'iface': data_generators.random_iface(), # Alias
        'src_mac': data_generators.random_mac_address(),
        'dst_mac': data_generators.random_dst_mac(), # Usar la que puede ser broadcast/multicast
        'mac_address': data_generators.random_mac_address(), # General
        'bytes': data_generators.random_bytes(),
        'pkt_length': data_generators.random_pkt_length(),
        'tcp_flags': data_generators.random_tcp_flags(),
        'icmp_type': data_generators.random_icmp_type(),
        'icmp_code': data_generators.random_icmp_code(),
        'icmp_id': data_generators.random_icmp_id(),
        'vlan_id': data_generators.random_vlan_id(),
        'tunnel': data_generators.random_tunnel(),
        'gateway': data_generators.random_gateway(),
        'dns_servers': data_generators.random_dns_servers(),
        'session': data_generators.random_session(),
        'connection_id': data_generators.random_connection_id(),

        # Sistema/Host
        'user': data_generators.random_user(),
        'admin': data_generators.random_admin(),
        'process': data_generators.random_process(),
        'process_id': data_generators.random_process_id(), # Alias
        'command': data_generators.random_command(),
        'file_path': data_generators.random_file_path(),
        'file_name': data_generators.random_file_name(),
        'filename': data_generators.random_filename(), # Alias
        'file_hash': data_generators.random_file_hash(),
        'file_type': data_generators.random_file_type(),
        'device': data_generators.random_device(),
        'disk': data_generators.random_disk(),
        'mount_point': data_generators.random_mount_point(),
        'filesystem': data_generators.random_filesystem(),
        'free_space': data_generators.random_free_space(),
        'cpu_usage': data_generators.random_cpu_usage(),
        'memory_usage': data_generators.random_memory_usage(),
        'used': data_generators.random_used(),
        'load': data_generators.random_load(),
        'temp': data_generators.random_temp(),
        'script_path': data_generators.random_script_path(),
        'dir_path': data_generators.random_dir_path(),
        'service': data_generators.random_service(),
        'service_name': data_generators.random_service_name_os(),
        'package_name': data_generators.random_package_name(),
        'version': data_generators.random_version(),
        'update': data_generators.random_update(),
        'start_type': data_generators.random_start_type(),
        'state': data_generators.random_state(),
        'timezone': data_generators.random_timezone(),
        'event': data_generators.random_event(),
        'job_name': data_generators.random_job_name(),

        # Seguridad
        'action': data_generators.random_action_taken(),
        'policy': data_generators.random_policy_name_generic(),
        'policy_id': data_generators.random_numeric_id(4),
        'rule': data_generators.random_rule_name(),
        'rule_name': data_generators.random_rule_name(), # Alias
        'rule_id': data_generators.random_numeric_id(5),
        'acl': data_generators.random_acl(),
        'access_group': data_generators.random_access_group(),
        'object': data_generators.random_object_name(),
        'object_name': data_generators.random_object_name(), # Alias
        'threat_name': data_generators.random_threat_name_generic(),
        'attack_name': data_generators.random_attack_name_generic(),
        'cve_id': data_generators.random_cve_id(),
        'signature_id': data_generators.random_signature_id(),
        'sigid': data_generators.random_sigid(), # Alias
        'sig_id': data_generators.random_sig_id(), # Alias
        'subsig_id': data_generators.random_subsig_id(),
        'category': data_generators.random_category(),
        'verdict': data_generators.random_verdict(),
        'feature': data_generators.random_feature(),
        'module': data_generators.random_module(),
        'description': data_generators.random_description(),
        'details': data_generators.random_details(),
        'severity_level': random.randint(1, 7), # Nivel numérico simple

        # Autenticación/Identidad
        'auth_result': data_generators.random_auth_result_detail(),
        'mfa_factor': data_generators.random_mfa_factor(),
        'sid': data_generators.random_sid(),
        'guid': data_generators.random_guid(),
        'realm': data_generators.random_realm(),
        'dn': data_generators.random_dn(),
        'group': data_generators.random_group(),
        'auth_server_group': data_generators.random_auth_server_group(),
        'attempts': data_generators.random_attempts(),
        'duration': data_generators.random_duration(),
        'method': data_generators.random_method(),

        # Web/HTTP
        'url': data_generators.random_url(),
        'domain': data_generators.random_domain(),
        'http_method': data_generators.random_http_method(),
        'status_code': data_generators.random_http_status_code(),
        'status': data_generators.random_status(), # Alias (ej. "200 OK")
        'user_agent': data_generators.random_user_agent_string(),

        # Windows Específico
        'registry_path': data_generators.random_registry_path(),
        'share_name': data_generators.random_share_name(),

        # Cisco Específico
        'vty': data_generators.random_vty(),
        'pc': data_generators.random_pc(),
        'call_stack': data_generators.random_call_stack(),
        'drop_rate': data_generators.random_drop_rate(),
        'burst_rate': data_generators.random_burst_rate(),
        'max_burst_rate': data_generators.random_max_burst_rate(),
        'avg_rate': data_generators.random_avg_rate(),
        'max_avg_rate': data_generators.random_max_avg_rate(),
        'total_count': data_generators.random_total_count(),
        'group_id': data_generators.random_group_id(),

        # Otros/Genéricos
        'limit': data_generators.random_limit(),
        'trap': data_generators.random_trap(),
        'mapping_name': data_generators.random_mapping_name(),
        'tool_name': data_generators.random_tool_name(),
        'fragment_count': data_generators.random_fragment_count(),
        'fragment_id': data_generators.random_fragment_id(),
        'fragment_offset': data_generators.random_fragment_offset(),
        'fragment_size': data_generators.random_fragment_size(),
        'hdr_length': data_generators.random_hdr_length(),
        'arp_type': data_generators.random_arp_type(),
        'devname': data_generators.random_devname(),

        # Placeholders Genéricos (si alguna plantilla usa algo no listado arriba)
        'value': data_generators.random_value(),
        'application': random.choice(['Web', 'Email', 'Database', 'CustomApp', 'NetworkShare', 'SystemProcess']),
        'setting': data_generators.random_setting(),
        'code': data_generators.random_code(), # Renombrar a random_generic_status_code?
        'type': data_generators.random_type(), # Renombrar a random_generic_type_code?
        'numeric_id': data_generators.random_numeric_id(),
        'placeholder': data_generators.random_placeholder()
    }
    # Asegurarse de que todos los valores sean strings para .format
    return {k: str(v) for k, v in data.items()}


# --- Lógica Principal ---

def main():
    """Función principal que ejecuta el simulador."""
    app_logger.log_info("Simulador de logs iniciado.")

    # 1. Mostrar menú y obtener selección
    tecnologias_seleccionadas = mostrar_nuevo_menu_seleccion()

    if not tecnologias_seleccionadas:
        app_logger.log_info("No se seleccionaron tecnologías o el usuario salió. Terminando.")
        print("\nNo se seleccionaron tecnologías. Saliendo...")
        return

    # 2. Cargar plantillas
    plantillas_totales = []
    app_logger.log_info(f"Intentando cargar plantillas para: {', '.join(tecnologias_seleccionadas)}")
    for tech in tecnologias_seleccionadas:
        # Usar utils.cargar_plantillas y registrar problemas con app_logger
        plantillas_tech = utils.cargar_plantillas(tech)
        if not plantillas_tech:
            # El error/advertencia ya se imprimió y registró dentro de cargar_plantillas/utils
            pass # Continuar con la siguiente tecnología
        plantillas_totales.extend(plantillas_tech)

    if not plantillas_totales:
        print("\n[ERROR] No se pudieron cargar plantillas válidas para las tecnologías seleccionadas.")
        print("Asegúrate de que los archivos existen en el directorio 'logs', no están vacíos y tienen el formato correcto.")
        app_logger.log_error("No se cargaron plantillas válidas. Terminando simulación.")
        return

    print(f"\nTotal de plantillas cargadas y listas para usar: {len(plantillas_totales)}")
    app_logger.log_info(f"Total de plantillas cargadas: {len(plantillas_totales)}")

    # 3. Configurar parámetros de envío
    while True:
        server_ip = input("Introduce la IP del servidor Syslog (ej: 127.0.0.1): ").strip()
        if server_ip: break
        print("[ERROR] La IP del servidor no puede estar vacía.")

    while True:
        server_port_str = input("Introduce el puerto del servidor Syslog (ej: 514): ").strip()
        try:
            server_port = int(server_port_str)
            if 1 <= server_port <= 65535:
                break
            else:
                print("[ERROR] Puerto fuera de rango (1-65535).")
        except ValueError:
            print(f"[ERROR] Puerto inválido: '{server_port_str}'. Debe ser un número.")

    while True:
        protocolo = input("Introduce el protocolo (UDP/TCP, defecto UDP): ").strip().upper() or 'UDP'
        if protocolo in ['UDP', 'TCP']:
            break
        else:
            print(f"[ERROR] Protocolo '{protocolo}' inválido. Usa UDP o TCP.")

    while True:
        total_logs_str = input(f"¿Cuántos logs deseas enviar? (entero > 0, defecto 100): ").strip() or "100"
        try:
            total_logs = int(total_logs_str)
            if total_logs > 0:
                break
            else:
                 print("[ERROR] El número de logs debe ser mayor que cero.")
        except ValueError:
            print(f"[ERROR] Número de logs inválido: '{total_logs_str}'.")

    while True:
        intervalo_str = input("Intervalo entre logs (segundos >= 0, ej: 0.5, defecto 1.0): ").strip() or "1.0"
        try:
            intervalo = float(intervalo_str)
            if intervalo >= 0:
                break
            else:
                print("[ERROR] El intervalo no puede ser negativo.")
        except ValueError:
            print(f"[ERROR] Intervalo inválido: '{intervalo_str}'.")

    # Log de inicio de simulación
    app_logger.log_simulation_start(
        tecnologias_seleccionadas, server_ip, server_port, protocolo, total_logs, intervalo
    )

    # 4. Inicializar Syslog Sender
    sender = None
    try:
        sender = syslog_sender.SyslogSender(server_ip, server_port, protocolo)
        print(f"\nIniciando simulación: Enviando {total_logs} logs a {server_ip}:{server_port} vía {protocolo}, intervalo {intervalo}s")
        print("Presiona Ctrl+C para detener.")
        app_logger.log_info("SyslogSender inicializado correctamente.")
    except ConnectionError as e:
        # El error ya fue registrado por SyslogSender.__init__
        print(f"\n[ERROR FATAL] No se pudo establecer la conexión inicial con el servidor: {e}")
        print("Verifica la IP, puerto y que el servidor Syslog esté escuchando.")
        # No es necesario loguear de nuevo aquí, ya lo hizo el constructor
        return # Salir si no se puede conectar al inicio
    except ValueError as e: # Protocolo inválido
         print(f"\n[ERROR FATAL] Configuración inválida: {e}")
         app_logger.log_critical(f"Error al inicializar SyslogSender: {e}")
         return
    except Exception as e:
        print(f"\n[ERROR FATAL] Error inesperado al inicializar el sender: {e}")
        app_logger.log_critical(f"Error inesperado inicializando SyslogSender: {e}", exc_info=True)
        return

    # 5. Bucle de envío de logs
    logs_enviados_ok = 0
    logs_fallidos_formato = 0
    logs_fallidos_envio = 0
    target_info_str = f"{server_ip}:{server_port} ({protocolo})" # Para logging de errores de envío

    try:
        for i in range(total_logs):
            # Seleccionar plantilla y generar datos
            template = random.choice(plantillas_totales)
            data = generar_datos_para_log()

            # Formatear log (manejar errores de formato)
            log_message = None
            try:
                # Opcional: Validar antes de formatear (puede ser redundante si se captura KeyError)
                # if not utils.validar_plantilla(template, data):
                #    logs_fallidos_formato += 1
                #    # El error ya se imprimió/registró en validar_plantilla
                #    continue # Saltar al siguiente log

                log_message = template.format(**data)

            except KeyError as e:
                logs_fallidos_formato += 1
                error_msg = f"Falta marcador '{e}'"
                # Registrar error de generación
                app_logger.log_generation_error(template, data.keys(), error_msg)
                # Imprimir solo una vez por error de formato para no llenar consola
                if logs_fallidos_formato == 1:
                     print(f"\n[ERROR DE FORMATO] {error_msg} en plantilla: '{template[:100]}...'. Verifica tus plantillas.")
                continue # Saltar al siguiente log
            except Exception as e:
                logs_fallidos_formato += 1
                error_msg = f"Error inesperado formateando: {e}"
                app_logger.log_generation_error(template, data.keys(), error_msg)
                if logs_fallidos_formato == 1:
                     print(f"\n[ERROR DE FORMATO] {error_msg} en plantilla: '{template[:100]}...'.")
                continue

            # Enviar log
            if sender.send(log_message):
                logs_enviados_ok += 1
            else:
                logs_fallidos_envio += 1
                # Registrar error de envío usando el logger (el error se almacena en sender.last_error)
                send_error = getattr(sender, 'last_error', 'Error desconocido de envío')
                app_logger.log_send_error(target_info_str, send_error)
                # Imprimir solo el primer error de envío para no saturar
                if logs_fallidos_envio == 1:
                    print(f"\n[ERROR DE ENVÍO] Fallo al enviar log a {target_info_str}. Verifica conexión/servidor. Error: {send_error}")

            # Mostrar progreso y esperar
            utils.mostrar_progreso(i + 1, total_logs) # Mostrar progreso basado en intentos
            if intervalo > 0:
                time.sleep(intervalo)

    except KeyboardInterrupt:
        print("\n\nSimulación interrumpida por el usuario (Ctrl+C).")
        app_logger.log_warning("Simulación interrumpida por el usuario.")
    except Exception as e:
        print(f"\n\n[ERROR INESPERADO] Ocurrió un error durante el bucle de envío: {e}")
        app_logger.log_critical(f"Error crítico durante el bucle de envío: {e}", exc_info=True)
    finally:
        # Asegurarse de cerrar el socket y registrar el final
        if sender:
            sender.close() # El cierre ahora también loguea

        # Imprimir resumen final
        print("\n" + "="*30 + " Resumen Final " + "="*30)
        print(f"Logs totales a enviar: {total_logs}")
        print(f"Logs procesados (intentos): {logs_enviados_ok + logs_fallidos_envio + logs_fallidos_formato}")
        print(f"Logs enviados correctamente (aprox.): {logs_enviados_ok}")
        print(f"Errores de formato de plantilla: {logs_fallidos_formato}")
        print(f"Errores de envío (socket): {logs_fallidos_envio}")
        print(f"Puedes revisar el archivo '{app_logger.LOG_FILENAME}' para más detalles.")
        print("="*75)

        # Registrar final
        app_logger.log_simulation_end(
            logs_attempted=(logs_enviados_ok + logs_fallidos_envio + logs_fallidos_formato),
            logs_sent_ok=logs_enviados_ok
        )
        app_logger.log_info("Simulador de logs terminado.")

# --- Punto de Entrada ---

if __name__ == "__main__":
    # Crear directorio 'logs' si no existe (necesario para cargar_plantillas)
    logs_dir = 'logs'
    if not os.path.exists(logs_dir):
        print(f"Directorio '{logs_dir}' no encontrado. Intentando crear...")
        try:
            os.makedirs(logs_dir)
            print(f"Directorio '{logs_dir}' creado exitosamente.")
            app_logger.log_info(f"Directorio de plantillas '{logs_dir}' creado.")
            # Aquí podrías añadir la creación de archivos de ejemplo si lo necesitas,
            # pero es mejor que el usuario los cree manualmente.
            # print("Recuerda colocar tus archivos de plantillas (ej: cisco_logs.txt) dentro de la carpeta 'logs'.")
        except OSError as e:
            print(f"[ERROR CRÍTICO] No se pudo crear el directorio '{logs_dir}': {e}")
            print("Por favor, crea la carpeta 'logs' manualmente en el mismo directorio que main.py.")
            app_logger.log_critical(f"No se pudo crear el directorio '{logs_dir}': {e}. Las plantillas no se cargarán.")
            exit(1) # Salir si no se puede crear el directorio esencial
        except Exception as e:
             print(f"[ERROR] Ocurrió un error inesperado creando el directorio '{logs_dir}': {e}")
             app_logger.log_error(f"Error inesperado creando el directorio '{logs_dir}': {e}", exc_info=True)
             # Podríamos decidir salir o continuar dependiendo de la severidad
             # exit(1)

    # Llamar a la función principal que contiene toda la lógica
    main()