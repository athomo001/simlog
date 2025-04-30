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
import ipaddress  # Importar el módulo para validar IPs

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
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'timestamp_bsd': data_generators.random_bsd_timestamp(),
        'timestamp_unix': data_generators.random_unix_timestamp(),
        'timestamp_iso': data_generators.random_iso_timestamp(),
        'timestamp_sql': data_generators.random_sql_timestamp(),
        'timestamp_cs': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'timestamp_w3c_date': datetime.now().strftime('%Y-%m-%d'),
        'timestamp_w3c_time': datetime.now().strftime('%H:%M:%S'),
        'timestamp_xr': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'timestamp_cef': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
        'mde_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        's1_timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
        'cb_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'sysmon_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
        'huawei_timestamp': datetime.now().strftime('%Y/%m/%d %H:%M:%S'),
        'auth_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'audit_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'w3c_date': data_generators.random_w3c_datetime()[0],
        'w3c_time': data_generators.random_w3c_datetime()[1],
        'hostname': data_generators.random_hostname(),
        'severity': data_generators.random_severity(),
        'logid': data_generators.random_logid(),
        'pid': data_generators.random_process_id(),
        'message': random.choice(['Operation successful', 'Access denied', 'Configuration updated', 'Connection established', 'File downloaded', 'Scan complete', 'User logged out', 'Service started', 'Service stopped']),


        # Información del dispositivo
        'device_name': 'Device-' + str(random.randint(1, 100)),
        'device_name_huawei': 'Huawei-' + str(random.randint(1, 100)),
        'serial_number': 'SN-' + str(random.randint(100000, 999999)),
        'device_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'client_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'client_ip_auth': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'neighbor_ip': f"10.1.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'radius_server_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'firewall_ip': f"172.16.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'device_class': random.choice(['Router', 'Switch', 'Firewall']),
        'client_mac': ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6)),
        'slot_num': str(random.randint(1, 10)),
        'port_num': str(random.randint(1024, 65535)),
        'ntp_server': f"ntp{random.randint(1, 5)}.example.com",
        'panos_version': '10.' + str(random.randint(0, 5)),
        'firmware_version': 'v' + str(random.randint(1, 10)) + '.' + str(random.randint(0, 99)),
        'vlan_id': str(random.randint(1, 4096)),

        # Información de red
        'source': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'source_ip_sophos': f"172.16.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'syslog_server': f"syslog{random.randint(1, 5)}.example.com",
        'peer_type': random.choice(['Internal', 'External']),
        'peer_ip': f"10.2.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'as_num': str(random.randint(1, 65535)),
        'interface': random.choice(['eth0', 'eth1', 'wlan0']),
        'arp_type': random.choice(['Request', 'Reply']),
        'icmp_code': str(random.randint(0, 15)),
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

        # Información de logs y eventos
        'message_type': random.choice(['INFO', 'WARN', 'ERROR']),
        'event_id': str(random.randint(1000, 9999)),
        'line': str(random.randint(1, 100)),
        'hit_count': str(random.randint(1, 100)),
        'teardown_reason': random.choice(['Session timeout', 'User logout']),
        'reload_reason': random.choice(['Configuration change', 'System update']),
        'audit_name': 'Audit-' + str(random.randint(1, 100)),
        'audit_event_id': str(random.randint(1000, 9999)),
        'audit_spec_name': 'Spec-' + str(random.randint(1, 50)),
        'max_connections': str(random.randint(1, 1000)),
        'task_duration': str(random.randint(1, 3600)) + 's',

        # Seguridad
        'reason': random.choice(['Policy violation', 'Unauthorized access']),
        'threat_name_sophos': random.choice(['Trojan.Generic', 'Ransom.Cryptolocker', 'Exploit.Kit']),
        'severity_sophos': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'severity_num': str(random.randint(1, 10)),
        'category_sophos': random.choice(['Malware', 'Phishing', 'Ransomware']),
        'threat_category': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'detection_name': random.choice(['Malware detected', 'Suspicious activity']),
        'auth_method': random.choice(['Password', 'Token', 'Biometric']),
        'ips_policy_name': 'IPS-Policy-' + str(random.randint(1, 50)),
        'script_content_snippet': 'print("Hello World")',
        'acl_name': 'ACL-' + str(random.randint(1, 100)),
        'alert_id': str(random.randint(10000, 99999)),
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

        # Placeholders Genéricos (si alguna plantilla usa algo no listado arriba)
        'value': data_generators.random_value(),
        'application': random.choice(['Web', 'Email', 'Database', 'CustomApp', 'NetworkShare', 'SystemProcess']),
        'setting': data_generators.random_setting(),
        'code': data_generators.random_code(), # Renombrar a random_generic_status_code?
        'type': data_generators.random_type(), # Renombrar a random_generic_type_code?
        'numeric_id': data_generators.random_numeric_id(),
        'placeholder': data_generators.random_placeholder(),

        # Otros
        'admin_login': random.choice(['admin', 'root', 'user']),
        'login_name': random.choice(['user1', 'user2', 'admin']),
        'file_path_sophos': f"/var/log/file{random.randint(1, 100)}.log",
        'spi': str(random.randint(1000, 9999)),
        'database_name': random.choice(['db1', 'db2', 'db3']),
        'group_policy': random.choice(['Policy1', 'Policy2', 'Policy3']),
        'url_sophos': f"https://example{random.randint(1, 100)}.com",
        'for object of type': random.choice(['TypeA', 'TypeB', 'TypeC']),
        'hostname': random.choice(['host1', 'host2', 'host3']),
        'hostname_cs': random.choice(['host-cs1', 'host-cs2']),
        'hostname_xr': random.choice(['host-xr1', 'host-xr2']),
        'process': random.choice(['proc1', 'proc2']),
        'process_path_sophos': f"/usr/bin/process{random.randint(1, 100)}",
        'pid': str(random.randint(1000, 9999)),
        'method': random.choice(['GET', 'POST', 'PUT']),
        'permission': random.choice(['Read', 'Write', 'Execute']),
        'memory_usage': f"{random.randint(1, 100)}%",
        'limit': str(random.randint(1, 100)),
        'action': random.choice(['Allow', 'Deny']),
        'action_sophos': random.choice(['Block', 'Allow']), 
        'action_s1': random.choice(['Block', 'Allow']),
        'action_cb': random.choice(['Block', 'Allow']),
        'action_sysmon': random.choice(['Create', 'Delete']),  
        'action_huawei': random.choice(['Permit', 'Deny']),
        'action_auth': random.choice(['Login', 'Logout']), 
        'action_audit': random.choice(['Create', 'Delete']),
        'action_arp': random.choice(['Request', 'Reply']),
        'action_traffic': random.choice(['Allow', 'Deny']),
        'action_traffic_sophos': random.choice(['Allow', 'Deny']),
        'action_traffic_s1': random.choice(['Allow', 'Deny']),
        'action_traffic_cb': random.choice(['Allow', 'Deny']),  
        'action_traffic_sysmon': random.choice(['Allow', 'Deny']),
        'trap': data_generators.random_trap(),
        'mapping_name': data_generators.random_mapping_name(),
        'tool_name': data_generators.random_tool_name(),
        'fragment_count': data_generators.random_fragment_count(),
        'fragment_id': data_generators.random_fragment_id(),
        'fragment_offset': data_generators.random_fragment_offset(),
        'fragment_size': data_generators.random_fragment_size(),
        'hdr_length': data_generators.random_hdr_length(),
        'arp_type': data_generators.random_arp_type(),
                'uid': str(random.randint(1000, 9999)),
        'agent_id': f"agent-{random.randint(1, 100)}",
        'dc_hostname': f"dc-{random.randint(1, 100)}",
        'bsd_timestamp': datetime.now().strftime('%b %d %H:%M:%S'),
        'agent_id_s1': f"agent-s1-{random.randint(1, 100)}",
        'process_guid_sysmon': f"guid-{random.randint(1000, 9999)}",
        'timestamp_win': datetime.now().strftime('%m/%d/%Y %I:%M:%S %p'),
        'spy_sig_id': f"spy-{random.randint(1000, 9999)}",
        'ips_sig_id': f"ips-{random.randint(1000, 9999)}",
        'file_name_huawei': f"file-{random.randint(1, 100)}.log",
        'firewall_hostname': f"fw-{random.randint(1, 100)}",
        'hostname_pa': f"pa-{random.randint(1, 100)}",
        'mapped_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'customer_id': f"cust-{random.randint(1, 1000)}",
        'device_id': f"dev-{random.randint(1, 1000)}",
        'hostname_cb': f"cb-{random.randint(1, 100)}",
        'event_name': random.choice(['Login', 'Logout', 'File Upload', 'File Download']),
        'bytes_written': str(random.randint(1000, 1000000)),
        'DeviceId': f"Device-{random.randint(1, 1000)}",
        'dhcp_message_type': random.choice(['Discover', 'Offer', 'Request', 'Ack']),
        'devname': f"devname-{random.randint(1, 100)}",
        'process_pid_linux': str(random.randint(1000, 9999)),
        'target_server_ad': f"server-{random.randint(1, 100)}",
        's_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'admin_user_pa': f"admin-{random.randint(1, 100)}",
        'socket_fd': str(random.randint(1, 1000)),
        'permission_bitmask': f"{random.randint(0, 255):08b}",
        'statistics': f"stat-{random.randint(1, 100)}",
        'actor_id': f"actor-{random.randint(1, 100)}",
        'target_login': f"user-{random.randint(1, 100)}",
        'slot_id': str(random.randint(1, 10)),
        'category_name': random.choice(['Network', 'System', 'Application']),
        'error_code': f"ERR-{random.randint(100, 999)}",
        'process_id_ospf': str(random.randint(1000, 9999)),
        'cfs_category_code': f"CFS-{random.randint(1, 100)}",
        'user_huawei': f"user-{random.randint(1, 100)}",
        'group_name': f"group-{random.randint(1, 100)}",
        'parent_pid_linux': str(random.randint(1000, 9999)),
        'integration_name': f"int-{random.randint(1, 100)}",
        'policy_name_huawei': f"policy-{random.randint(1, 100)}",
        'user_pa': f"user-{random.randint(1, 100)}",
        'process_name': f"proc-{random.randint(1, 100)}",
        'packet_count': str(random.randint(1, 1000)),
        'interface_linux': random.choice(['eth0', 'eth1', 'wlan0']),
        'target_count': str(random.randint(1, 100)),
        'signature_name': f"sig-{random.randint(1, 100)}",
        'stratum': str(random.randint(1, 16)),
        'violation_count': str(random.randint(1, 100)),
        'assigned_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'app_name_sophos': f"app-{random.randint(1, 100)}",
        'state_code': random.choice(['OK', 'ERROR', 'WARN']),
        'service_name_linux': f"service-{random.randint(1, 100)}",
        'argc': str(random.randint(1, 10)),
        'vty_xr': f"vty-{random.randint(1, 100)}",
        'dns_query_pa': f"query-{random.randint(1, 100)}",
        'gav_sig_id': f"gav-{random.randint(1, 100)}",
        'scanner_app_name': f"scanner-{random.randint(1, 100)}",
        'time_login': datetime.now().strftime('%H:%M:%S'),
        'flood_rate': f"{random.randint(1, 100)}%",
        'threat_type': random.choice(['Malware', 'Phishing', 'Ransomware']),
        'error_message': f"Error-{random.randint(1, 100)}",
        'interface_xr': random.choice(['eth0', 'eth1', 'wlan0']),
        'username_duo': f"user-{random.randint(1, 100)}",
        'target_user_id': f"user-{random.randint(1, 100)}",
        'fd': str(random.randint(1, 1000)),
        'app_name': f"app-{random.randint(1, 100)}",
        'botnet_name': f"botnet-{random.randint(1, 100)}",
        'task_name': f"task-{random.randint(1, 100)}",
        'fan_tray_num': str(random.randint(1, 10)),
        'interface_huawei': random.choice(['eth0', 'eth1', 'wlan0']),
        'application_name': f"app-{random.randint(1, 100)}",
        'ip_proto_num': str(random.randint(1, 255)),
        'device_path': f"/dev/device-{random.randint(1, 100)}",
        'cfs_category_name': f"cfs-{random.randint(1, 100)}",
        'column_name': f"col-{random.randint(1, 100)}",
        'admin_user': f"admin-{random.randint(1, 100)}",
        'admin_user_duo': f"admin-{random.randint(1, 100)}",
        'old_state': random.choice(['Active', 'Inactive']),
        'attack_type': random.choice(['DDoS', 'SQL Injection', 'XSS']),
        'admin_actor_id': f"actor-{random.randint(1, 100)}",
        'rbl_service': f"rbl-{random.randint(1, 100)}",
        'opid': str(random.randint(1, 1000)),
        'new_owner': f"owner-{random.randint(1, 100)}",
        'reason_huawei': random.choice(['Policy Violation', 'Unauthorized Access']),
        'acl_name_xr': f"acl-{random.randint(1, 100)}",
        'schema_name': f"schema-{random.randint(1, 100)}",
        'proc_name': f"proc-{random.randint(1, 100)}",
        'registry_key_sophos': f"key-{random.randint(1, 100)}",
        'rollback_point': f"rollback-{random.randint(1, 100)}",
        'ips_rule_name': f"rule-{random.randint(1, 100)}",
        'kernel_extension_path': f"/lib/modules/{random.randint(1, 100)}",
        'radius_port': str(random.randint(1024, 65535)),
        'log_full_reason': f"reason-{random.randint(1, 100)}",
        'scan_type': random.choice(['Full', 'Quick']),
        'tacacs_server_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'country_code': random.choice(['US', 'MX', 'CA']),
        'system_critical_file': f"/etc/critical-{random.randint(1, 100)}",
        'pool_name': f"pool-{random.randint(1, 100)}",
        'error_list': f"error-{random.randint(1, 100)}",
        'fan_id': str(random.randint(1, 100)),
        'fault_reason': f"fault-{random.randint(1, 100)}",
        'auth_server_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'power_id': str(random.randint(1, 100)),
        'table_name': f"table-{random.randint(1, 100)}",
        'ids_engine': f"engine-{random.randint(1, 100)}",
        'remote_ip_sophos': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'backup_path': f"/backup/{random.randint(1, 100)}",
        'pool_name_huawei': f"pool-{random.randint(1, 100)}",
        'auid': str(random.randint(1, 1000)),
        'spid': str(random.randint(1, 1000)),
        'failover_reason': random.choice(['Hardware Failure', 'Network Issue']),
        'tty_xr': f"tty-{random.randint(1, 100)}",
        'target_process': f"proc-{random.randint(1, 100)}",
        'notify_message': f"notify-{random.randint(1, 100)}",
        'sensor_id': f"sensor-{random.randint(1, 100)}",
        'threshold': str(random.randint(1, 100)),
        'mem_usage': f"{random.randint(1, 100)}%",
        'src_country_name': random.choice(['USA', 'Canada', 'Mexico']),
        'config_file': f"/etc/config-{random.randint(1, 100)}",
        'socket_addr_hex': f"0x{random.randint(1, 100):x}",
        'syslog_port': str(random.randint(1024, 65535)),
        'ios_version': f"ios-{random.randint(1, 100)}",
        'bytes_xmt': str(random.randint(1, 1000000)),
        'file_id': f"file-{random.randint(1, 100)}",
        'flow_type': random.choice(['TCP', 'UDP']),
        'virtual_server_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'endpoint_id': f"endpoint-{random.randint(1, 1000)}",
        'hostname_linux': f"linux-host-{random.randint(1, 100)}",
        'session_id_pa': f"session-{random.randint(1, 1000)}",
        'attack_id': f"attack-{random.randint(1, 1000)}",
        'param_value': f"value-{random.randint(1, 100)}",
        'message_id': f"msg-{random.randint(1, 1000)}",
        'hostname_win': f"win-host-{random.randint(1, 100)}",
        'session_duration': f"{random.randint(1, 3600)}s",
        'computer_name_s1': f"comp-s1-{random.randint(1, 100)}",
        'client_type_pa': random.choice(['Internal', 'External']),
        'account_name': f"account-{random.randint(1, 100)}",
        'process_id_sysmon': str(random.randint(1000, 9999)),
        'virtual_server_name': f"vs-{random.randint(1, 100)}",
        'filesystem_type': random.choice(['ext4', 'ntfs', 'fat32']),
        'actor_user': f"user-{random.randint(1, 100)}",
        'trojan_id': f"trojan-{random.randint(1, 100)}",
        'in_interface': random.choice(['eth0', 'eth1', 'wlan0']),
        'session_id': f"session-{random.randint(1, 1000)}",
        's_port': str(random.randint(1024, 65535)),
        'vpn_instance': f"vpn-{random.randint(1, 100)}",
        'log_id': f"log-{random.randint(1, 1000)}",
        'process_id_cs': str(random.randint(1000, 9999)),
        'threat_id_cb': f"threat-{random.randint(1, 100)}",
        'vsys': f"vsys-{random.randint(1, 100)}",
        'disabled_user': f"user-{random.randint(1, 100)}",
        'ssl_profile_name': f"ssl-profile-{random.randint(1, 100)}",
        'session_id_linux': f"session-{random.randint(1, 1000)}",
        'user_sid': f"sid-{random.randint(1, 1000)}",
        'count': str(random.randint(1, 100)),
        'error_text': f"error-{random.randint(1, 100)}",
        'euid': str(random.randint(1000, 9999)),
        'node_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'process_guid_cb': f"guid-{random.randint(1000, 9999)}",
        'DeviceName': f"device-{random.randint(1, 100)}",
        'hostname_ipa': f"ipa-host-{random.randint(1, 100)}",
        'uid_linux': str(random.randint(1000, 9999)),
        'arp_inspect_reason': random.choice(['ARP Spoofing', 'Invalid MAC']),
        'policy_name': f"policy-{random.randint(1, 100)}",
        'ransomware_variant': f"ransom-{random.randint(1, 100)}",
        'severity_cs': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'address_list_name': f"address-list-{random.randint(1, 100)}",
        'remote_port_sophos': str(random.randint(1024, 65535)),
        'admin_user_ad': f"admin-{random.randint(1, 100)}",
        'banker_variant': f"banker-{random.randint(1, 100)}",
        'threat_id': f"threat-{random.randint(1, 100)}",
        'login_method_huawei': random.choice(['Password', 'Token', 'Biometric']),
        'rate_huawei': f"{random.randint(1, 100)}%",
        'signature_file_path': f"/path/to/signature-{random.randint(1, 100)}.sig",
        'hostname_duo': f"duo-host-{random.randint(1, 100)}",
        'feature_name': f"feature-{random.randint(1, 100)}",
        'rule_num': str(random.randint(1, 100)),
        'temperature': f"{random.randint(20, 100)}C",
        'dst_country_name': random.choice(['USA', 'Canada', 'Mexico']),
        'severity_huawei': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'rogue_dhcp_server_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'ioctl_flags': f"flags-{random.randint(1, 100)}",
        'dhcp_server_name': f"dhcp-{random.randint(1, 100)}",
        'packet_rate': f"{random.randint(1, 1000)} packets/s",
        'fail_reason': random.choice(['Timeout', 'Connection Refused']),
        'profile_name': f"profile-{random.randint(1, 100)}",
        'conflicting_mac': ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6)),
        'pid_xr': str(random.randint(1000, 9999)),
        'id': str(random.randint(1, 1000)),
        'protocol_num': str(random.randint(1, 255)),
        'login_method': random.choice(['Password', 'Token', 'Biometric']),
        'threat_level': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'parent_guid_cb': f"guid-{random.randint(1000, 9999)}",
        'priority': random.choice(['High', 'Medium', 'Low']),
        'role_name': f"role-{random.randint(1, 100)}",
        'script_name': f"script-{random.randint(1, 100)}",
        'bytes_rcv': str(random.randint(1, 1000000)),
        'url_huawei': f"https://huawei-{random.randint(1, 100)}.com",
        'device_id_cb': f"device-{random.randint(1, 100)}",
        'failsafe_action': random.choice(['Reboot', 'Shutdown']),
        'traffic_group': f"group-{random.randint(1, 100)}",
        'ip_address': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'reason_auth': random.choice(['Policy Violation', 'Unauthorized Access']),
        'deleted_user': f"user-{random.randint(1, 100)}",
        'backdoor_name': f"backdoor-{random.randint(1, 100)}",
        'config_destination': f"/path/to/config-{random.randint(1, 100)}",
        'country_name': random.choice(['USA', 'Canada', 'Mexico']),
        'scan_tool': f"tool-{random.randint(1, 100)}",
        'reset_cause': random.choice(['Power Failure', 'Manual Reset']),
        'rule_id_huawei': f"rule-{random.randint(1, 100)}",
        'old_level': random.choice(['Low', 'Medium', 'High']),
        'proxy_target_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'flap_count': str(random.randint(1, 100)),
        'mapped_port': str(random.randint(1024, 65535)),
        'scanned_ports_range': f"{random.randint(1, 1024)}-{random.randint(1025, 65535)}",
        'login_fail_reason': random.choice(['Invalid Password', 'Account Locked']),
        'enumerating_user': f"user-{random.randint(1, 100)}",
        'malware_svc_exe': f"malware-{random.randint(1, 100)}.exe",
        'session_count': str(random.randint(1, 1000)),
        'component': f"component-{random.randint(1, 100)}",
        'new_state': random.choice(['Active', 'Inactive']),
        'ssh_fail_reason': random.choice(['Key Mismatch', 'Timeout']),
        'ssh_key_type': random.choice(['RSA', 'DSA', 'ECDSA']),
        'dos_attack_type': random.choice(['SYN Flood', 'UDP Flood']),
        'dos_score': str(random.randint(1, 100)),
        'loop_count': str(random.randint(1, 100)),
        'asm_policy_name': f"asm-policy-{random.randint(1, 100)}",
        'condition': f"condition-{random.randint(1, 100)}",
        'reboot_reason': random.choice(['Power Failure', 'Manual Reboot']),
        'enrollment_type': random.choice(['Manual', 'Automatic']),
        'command_executed': f"command-{random.randint(1, 100)}",
        'kernel_error_message': f"kernel-error-{random.randint(1, 100)}",
        'clearpass_policy': f"policy-{random.randint(1, 100)}",
        'client_pid': str(random.randint(1000, 9999)),
        'action_description': f"action-{random.randint(1, 100)}",
        'user_name_cs': f"user-{random.randint(1, 100)}",
        'commit_error': f"commit-error-{random.randint(1, 100)}",
        'activation_key': f"key-{random.randint(1, 100)}",
        'tunnel_id': f"tunnel-{random.randint(1, 100)}",
        'cnc_host': f"cnc-{random.randint(1, 100)}",
        'remport': str(random.randint(1024, 65535)),
        'session_type': random.choice(['TCP', 'UDP']),
        'bytes_huawei': str(random.randint(1, 1000000)),
        'action_id': f"action-{random.randint(1, 100)}",
        'comment': f"comment-{random.randint(1, 100)}",
        'stealer_variant': f"stealer-{random.randint(1, 100)}",
        'service_account_name': f"service-{random.randint(1, 100)}",
        'client_type': random.choice(['Internal', 'External']),
        'malware_plist': f"malware-{random.randint(1, 100)}.plist",
        'instance_id': f"instance-{random.randint(1, 100)}",
        'irule_name': f"irule-{random.randint(1, 100)}",
        'partition': f"partition-{random.randint(1, 100)}",
        'config_path': f"/path/to/config-{random.randint(1, 100)}",
        'neighbor_hostname': f"neighbor-{random.randint(1, 100)}",
        'app_category': random.choice(['Web', 'Email', 'Database']),
        'miner_name': f"miner-{random.randint(1, 100)}",
        'target_user_auth': f"user-{random.randint(1, 100)}",
        'policy_name_duo': f"policy-{random.randint(1, 100)}",
        'flood_threshold': f"{random.randint(1, 100)}%",
        'rate': f"{random.randint(1, 100)}%",
        'listener_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'vpn_tunnel': f"vpn-{random.randint(1, 100)}",
        'oauid': str(random.randint(1, 1000)),
        'param_name': f"param-{random.randint(1, 100)}",
        'keylog_variant': f"keylog-{random.randint(1, 100)}",
        'cve_year': str(random.randint(2000, 2025)),
        'privilege_level': random.choice(['Admin', 'User', 'Guest']),
        'malicious_ldap_server': f"ldap-{random.randint(1, 100)}",
        'virus_name_huawei': f"virus-{random.randint(1, 100)}",
        'address': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'api_token_id': f"token-{random.randint(1, 100)}",
        'new_user': f"user-{random.randint(1, 100)}",
        'executable_path_linux': f"/usr/bin/executable-{random.randint(1, 100)}",
        'phishingsite': f"https://phishing-{random.randint(1, 100)}.com",
        'port_count': str(random.randint(1, 100)),
        'interface_name': random.choice(['eth0', 'eth1', 'wlan0']),
        'image_name': f"image-{random.randint(1, 100)}",
        'locked_account_name': f"account-{random.randint(1, 100)}",
        'sig_rev': f"rev-{random.randint(1, 100)}",
        'adware_variant': f"adware-{random.randint(1, 100)}",
        'command_payload': f"payload-{random.randint(1, 100)}",
        'target_user': f"user-{random.randint(1, 100)}",
        'sql_payload': f"sql-{random.randint(1, 100)}",
        'dhcp_snoop_reason': random.choice(['Invalid Lease', 'Spoofing Detected']),
        'pua_name': f"pua-{random.randint(1, 100)}",
        'release_reason': random.choice(['End of Lease', 'Manual Release']),
        'worm_name': f"worm-{random.randint(1, 100)}",
        'drop_reason': random.choice(['Timeout', 'Connection Reset']),
        'tty': f"tty-{random.randint(1, 100)}",
        'phish_id': f"phish-{random.randint(1, 100)}",
        'tacacs_error': f"error-{random.randint(1, 100)}",
        'vs_path': f"/path/to/vs-{random.randint(1, 100)}",
        'hacktool_name': f"hacktool-{random.randint(1, 100)}",
        'process_name_linux': f"process-{random.randint(1, 100)}",
        'acl_type': random.choice(['Standard', 'Extended']),
        'command_injection_payload': f"payload-{random.randint(1, 100)}",
        'RegistryKey_UACDisable': f"key-{random.randint(1, 100)}",
        'InitiatingProcessFileName': f"process-{random.randint(1, 100)}.exe",
        'process_pid_cb': str(random.randint(1000, 9999)),
        'user_sophos': f"user-{random.randint(1, 100)}",
        'firewall_rule_id': f"rule-{random.randint(1, 100)}",
        'image_file_name': f"image-{random.randint(1, 100)}.png",
        'location_city': random.choice(['New York', 'London', 'Tokyo']),
        'src_country_code': random.choice(['US', 'MX', 'CA']),
        'parent_process_id_cs': str(random.randint(1000, 9999)),
        'out_interface': random.choice(['eth0', 'eth1', 'wlan0']),
        'support_id': f"support-{random.randint(1, 100)}",
        'oses': random.choice(['Windows', 'Linux', 'macOS']),
        'line_num': str(random.randint(1, 100)),
        'os_type': random.choice(['Server', 'Desktop']),
        'cwd': f"/home/user{random.randint(1, 100)}",
        'sid_admin': f"sid-{random.randint(1, 1000)}",
        'image_path_sysmon': f"/path/to/image-{random.randint(1, 100)}.png",
        'FileName': f"file-{random.randint(1, 100)}.txt",
        'file_size': f"{random.randint(1, 1000)}KB",
        'c_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'command_huawei': f"command-{random.randint(1, 100)}",
        'length': str(random.randint(1, 100)),
        'user_name': f"user-{random.randint(1, 100)}",
        'pid_linux': str(random.randint(1000, 9999)),
        'known_bot_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'parent_pid_cb': str(random.randint(1000, 9999)),
        'ssh_key_fp': f"key-{random.randint(1, 100)}",
        'ips_sensor': f"sensor-{random.randint(1, 100)}",
        'sid_enumerator': f"sid-{random.randint(1, 1000)}",
        'attribute_count': str(random.randint(1, 100)),
        'sid_null': f"sid-{random.randint(1, 1000)}",
        'compliance_failure': random.choice(['Policy Violation', 'Unauthorized Access']),
        'existing_mac_address': ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6)),
        'sid_user': f"sid-{random.randint(1, 1000)}",
        'malware_path': f"/path/to/malware-{random.randint(1, 100)}.exe",
        'failed_statement': f"statement-{random.randint(1, 100)}",
        'mount_flags': f"flags-{random.randint(1, 100)}",
        'origin_gw': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'adware_family': f"adware-{random.randint(1, 100)}",
        'failed_user': f"user-{random.randint(1, 100)}",
        'user_sysmon': f"user-{random.randint(1, 100)}",
        'user_home': f"/home/user{random.randint(1, 100)}",
        'app_id': f"app-{random.randint(1, 100)}",
        'dll_path_sysmon': f"/path/to/dll-{random.randint(1, 100)}.dll",
        'total_rate': f"{random.randint(1, 100)}%",
        'gid_linux': str(random.randint(1000, 9999)),
        'service_name_kdc': f"service-{random.randint(1, 100)}",
        'identity': f"identity-{random.randint(1, 100)}",
        'requesting_user': f"user-{random.randint(1, 100)}",
        'cred_id': f"cred-{random.randint(1, 100)}",
        'pid_ipa': str(random.randint(1000, 9999)),
        'audit_key': f"key-{random.randint(1, 100)}",
        'quarantine_db_path': f"/path/to/quarantine-{random.randint(1, 100)}.db",
        'campaign_name': f"campaign-{random.randint(1, 100)}",
        'kernel_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'RegistryKey_Security': f"key-{random.randint(1, 100)}",
        'system_config_file': f"/path/to/config-{random.randint(1, 100)}.conf",
        'process_id_win': str(random.randint(1000, 9999)),
        'arg1': f"arg-{random.randint(1, 100)}",
        'threshold_huawei': f"{random.randint(1, 100)}%",
        'user_linux': f"user-{random.randint(1, 100)}",
        'RemoteUrl_C2': f"https://c2-{random.randint(1, 100)}.com",
        'RegistryKey_SafeBoot': f"key-{random.randint(1, 100)}",
        'category_huawei': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'job_name_sysmon': f"job-{random.randint(1, 100)}",
        'SHA1': f"{random.randint(1, 1000):x}",
        'source_workstation': f"workstation-{random.randint(1, 100)}",
        'setting_details': f"details-{random.randint(1, 100)}",
        'parameter_name': f"param-{random.randint(1, 100)}",
        'bytes_pa': str(random.randint(1, 1000000)),
        'threat_score': str(random.randint(1, 100)),
        'mac_address1': ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6)),
        'RemoteUrl_Phishing': f"https://phishing-{random.randint(1, 100)}.com",
        'header_name': f"header-{random.randint(1, 100)}",
        'quarantine_vlan': f"vlan-{random.randint(1, 100)}",
        'service_sid': f"sid-{random.randint(1, 1000)}",
        'new_uid': str(random.randint(1000, 9999)),
        'location_country': random.choice(['USA', 'Canada', 'Mexico']),
        'RegistryKey_Run': f"key-{random.randint(1, 100)}",
        'threat_cause': random.choice(['Malware', 'Phishing', 'Ransomware']),
        'level': random.choice(['Low', 'Medium', 'High']),
        'AlertId': f"alert-{random.randint(1, 100)}",
        'listener_port': str(random.randint(1024, 65535)),
        'added_user': f"user-{random.randint(1, 100)}",
        'ProcessId': str(random.randint(1000, 9999)),
        'user_agent_auth': f"agent-{random.randint(1, 100)}",
        'script_path_sysmon': f"/path/to/script-{random.randint(1, 100)}.py",
        'RemoteIP': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'kerberos_status_code': f"code-{random.randint(1, 100)}",
        'FolderPath': f"/path/to/folder-{random.randint(1, 100)}",
        'agent_name': f"agent-{random.randint(1, 100)}",
        'file_extension': random.choice(['.txt', '.exe', '.log']),
        'policy_name_cb': f"policy-{random.randint(1, 100)}",
        'service_name_win': f"service-{random.randint(1, 100)}",
        'proxy_profile': f"profile-{random.randint(1, 100)}",
        'target_process_id': str(random.randint(1000, 9999)),
        'LogonType': random.choice(['Interactive', 'Network']),
        'corr_id': f"corr-{random.randint(1, 100)}",
        'new_group_name': f"group-{random.randint(1, 100)}",
        'error_description': f"error-{random.randint(1, 100)}",
        'capture_size': f"{random.randint(1, 1000)}KB",
        'src_ip_sysmon': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'RegistryKey_Persistence': f"key-{random.randint(1, 100)}",
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'violation_details': f"details-{random.randint(1, 100)}",
        'lsass_pid': str(random.randint(1000, 9999)),
        'domain_dns_name': f"domain-{random.randint(1, 100)}.com",
        'expiry_date': datetime.now().strftime('%Y-%m-%d'),
        'virus_id': f"virus-{random.randint(1, 100)}",
        'process_path': f"/path/to/process-{random.randint(1, 100)}.exe",
        'LogonType_RDP': random.choice(['Interactive', 'Remote']),
        'flap_duration': f"{random.randint(1, 100)}s",
        'node_port': str(random.randint(1024, 65535)),
        'new_level': random.choice(['Low', 'Medium', 'High']),
        'process_pid_s1': str(random.randint(1000, 9999)),
        'original_file': f"file-{random.randint(1, 100)}.txt",
        'host_count': str(random.randint(1, 100)),
        'LogonType_Service': random.choice(['Interactive', 'Network']),
        'proxy_target_port': str(random.randint(1024, 65535)),
        'locport': str(random.randint(1024, 65535)),
        'RegistryKey_DefenderDisable': f"key-{random.randint(1, 100)}",
        'autorun_inf': f"autorun-{random.randint(1, 100)}.inf",
        'cookie_name': f"cookie-{random.randint(1, 100)}",
        'process_path_cb': f"/path/to/process-{random.randint(1, 100)}.exe",
        'RemoteIP_TOR': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'user_win': f"user-{random.randint(1, 100)}",
        'log_file_path': f"/path/to/log-{random.randint(1, 100)}.log",
        'command_view': f"command-{random.randint(1, 100)}",
        'listen_port': str(random.randint(1024, 65535)),
        'known_c2_domain': f"domain-{random.randint(1, 100)}.com",
        'subject_name': f"subject-{random.randint(1, 100)}",
        'logon_type': random.choice(['Interactive', 'Network']),
        'sid_locked_user': f"sid-{random.randint(1, 1000)}",
        'bytes_sent': str(random.randint(1, 1000000)),
        'failure_reason': random.choice(['Timeout', 'Connection Refused']),
        'LogonType_Network': random.choice(['Interactive', 'Remote']),
        'bytes_rcvd': str(random.randint(1, 1000000)),
        'malware_file': f"malware-{random.randint(1, 100)}.exe",
        'api_token_name': f"token-{random.randint(1, 100)}",
        'anomaly_description': f"anomaly-{random.randint(1, 100)}",
        'dll_path': f"/path/to/dll-{random.randint(1, 100)}.dll",
        'attacker_uid': str(random.randint(1000, 9999)),
        'dos_profile_name': f"profile-{random.randint(1, 100)}",
        'config_command': f"command-{random.randint(1, 100)}",
        'ha_group_id': f"group-{random.randint(1, 100)}",
        'network_remote_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'encoding_type': random.choice(['Base64', 'Hex']),
        'error_details': f"details-{random.randint(1, 100)}",
        'severity_cb': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'cve_num': f"CVE-{random.randint(2000, 2025)}-{random.randint(1000, 9999)}",
        'seq_num_xr': str(random.randint(1, 1000)),
        'server_cn': f"server-{random.randint(1, 100)}",
        'new_user_linux': f"user-{random.randint(1, 100)}",
        'tgt_options': f"options-{random.randint(1, 100)}",
        'sid_system': f"sid-{random.randint(1, 1000)}",
        'malware_url_sysmon': f"https://malware-{random.randint(1, 100)}.com",
        'hidden_file_name': f"file-{random.randint(1, 100)}.txt",
        'schema_violation': f"violation-{random.randint(1, 100)}",
        'remote_hostname_sysmon': f"host-{random.randint(1, 100)}",
        'admin_user_cb': f"admin-{random.randint(1, 100)}",
        'sender_email': f"email-{random.randint(1, 100)}@example.com",
        'subcategory_guid': f"guid-{random.randint(1000, 9999)}",
        'pattern_name': f"pattern-{random.randint(1, 100)}",
        'ransom_variant': f"ransom-{random.randint(1, 100)}",
        'child_pid': str(random.randint(1000, 9999)),
        'auth_method_huawei': random.choice(['Password', 'Token', 'Biometric']),
        'pua_file_name': f"pua-{random.randint(1, 100)}.exe",
        'file_path_linux': f"/path/to/file-{random.randint(1, 100)}.txt",
        'roles': f"role-{random.randint(1, 100)}",
        'score': str(random.randint(1, 100)),
        'auth_method_pa': random.choice(['Password', 'Token', 'Biometric']),
        'os_file_path': f"/path/to/os-{random.randint(1, 100)}.conf",
        'task_name_sysmon': f"task-{random.randint(1, 100)}",
        'logname': f"log-{random.randint(1, 100)}",
        'sinkhole_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'sid_new_user': f"sid-{random.randint(1, 1000)}",
        'acct_method_huawei': random.choice(['Password', 'Token', 'Biometric']),
        'ransomware_file_name': f"ransom-{random.randint(1, 100)}.exe",
        'port_state': random.choice(['Open', 'Closed']),
        'access_mask_sam': f"mask-{random.randint(1, 100)}",
        'new_user_sysmon': f"user-{random.randint(1, 100)}",
        'datasource_type': random.choice(['Database', 'API']),
        'update_fail_reason': random.choice(['Timeout', 'Connection Refused']),
        'script_file_name': f"script-{random.randint(1, 100)}.py",
        'Severity_mde': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'seq_num': str(random.randint(1, 1000)),
        'admin_user_win': f"admin-{random.randint(1, 100)}",
        'domain_name': f"domain-{random.randint(1, 100)}.com",
        'src_ip_linux': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'threat_id_sophos': f"threat-{random.randint(1, 100)}",
        'registry_key_security_sysmon': f"key-{random.randint(1, 100)}",
        'dynamic_dns_domain': f"dynamic-{random.randint(1, 100)}.com",
        'conn_id': f"conn-{random.randint(1, 1000)}",
        'username_cb': f"user-{random.randint(1, 100)}",
        'domain_win': f"domain-{random.randint(1, 100)}.com",
        'referer_host': f"referer-{random.randint(1, 100)}.com",
        'sha256_sophos': f"{random.randint(1, 1000):064x}",
        'malware_url': f"https://malware-{random.randint(1, 100)}.com",
        'process_path_s1': f"/path/to/process-{random.randint(1, 100)}.exe",
        'source_process_guid_sysmon': f"guid-{random.randint(1000, 9999)}",
        'disk_used_percent': f"{random.randint(1, 100)}%",
        'parent_path_cb': f"/path/to/parent-{random.randint(1, 100)}",
        'tty_linux': f"tty-{random.randint(1, 100)}",
        'aes256': f"{random.randint(1, 1000):064x}",
        'aes128': f"{random.randint(1, 1000):032x}",
        'storyline_id': f"story-{random.randint(1, 1000)}",
        'ParentProcessId': str(random.randint(1000, 9999)),
        'target_filename_ransom': f"ransom-{random.randint(1, 100)}.exe",
        'ips_policy_id': f"policy-{random.randint(1, 100)}",
        'user_agent_scanner': f"scanner-{random.randint(1, 100)}",
        'sophos_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip_win': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'target_process_guid_sysmon': f"guid-{random.randint(1000, 9999)}",
        'new_uid_linux': str(random.randint(1000, 9999)),
        'pipe_name_sysmon': f"pipe-{random.randint(1, 100)}",
        'user_name_s1': f"user-{random.randint(1, 100)}",
        'parent_process_guid_sysmon': f"guid-{random.randint(1000, 9999)}",
        'sc_bytes': str(random.randint(1, 1000000)),
        'web_category': random.choice(['Social Media', 'News', 'Shopping']),
        'error_code_kerberos': f"ERR-{random.randint(100, 999)}",
        'ha_reason': random.choice(['Failover', 'Maintenance']),
        'error_desc': f"error-{random.randint(1, 100)}",
        'velocity_score': str(random.randint(1, 100)),
        'link_name': f"link-{random.randint(1, 100)}",
        'col_num': str(random.randint(1, 100)),
        'password': f"pass-{random.randint(1, 100)}",
        'js_script_file': f"script-{random.randint(1, 100)}.js",
        'locked_user': f"user-{random.randint(1, 100)}",
        'confidence_cb': random.choice(['High', 'Medium', 'Low']),
        'file_hash_sha256': f"{random.randint(1, 1000):064x}",
        'group_linux': f"group-{random.randint(1, 100)}",
        'recipient_email': f"email-{random.randint(1, 100)}@example.com",
        'process_cmd_ps_encoded': f"cmd-{random.randint(1, 100)}",
        'blocked_app_path': f"/path/to/app-{random.randint(1, 100)}.exe",
        'src_port_sysmon': str(random.randint(1024, 65535)),
        'user_count': str(random.randint(1, 100)),
        'script_hash': f"{random.randint(1, 1000):064x}",
        'in_interface_linux': random.choice(['eth0', 'eth1', 'wlan0']),
        'dst_country_code': random.choice(['US', 'MX', 'CA']),
        'object_dn': f"dn-{random.randint(1, 100)}",
        'child_guid_cb': f"guid-{random.randint(1000, 9999)}",
        'RemotePort': str(random.randint(1024, 65535)),
        'AccountName': f"account-{random.randint(1, 100)}",
        'loaded_dll_path': f"/path/to/dll-{random.randint(1, 100)}.dll",
        'large_sc_bytes': str(random.randint(1000000, 10000000)),
        'data_pattern': f"pattern-{random.randint(1, 100)}",
        'proctitle_hex': f"{random.randint(1, 1000):x}",
        'registry_path_cs': f"/path/to/registry-{random.randint(1, 100)}",
        'target_ip_range': f"192.168.{random.randint(0, 255)}.0/24",
        'http_status_code': str(random.randint(200, 599)),
        'invalid_user': f"user-{random.randint(1, 100)}",
        'ProcessFileName': f"process-{random.randint(1, 100)}.exe",
        'url_with_traversal': f"https://example.com/../../{random.randint(1, 100)}",
        'parent_image_file_name': f"image-{random.randint(1, 100)}.png",
        'SHA256': f"{random.randint(1, 1000):064x}",
        'deleted_group': f"group-{random.randint(1, 100)}",
        'src_ip_s1': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'target_file_name': f"file-{random.randint(1, 100)}.txt",
        'ReportId': f"report-{random.randint(1, 1000)}",
        'device_id_string': f"device-{random.randint(1, 1000)}",
        'enumerator_user': f"user-{random.randint(1, 100)}",
        'dump_file_path': f"/path/to/dump-{random.randint(1, 100)}.dmp",
        'tty_ipa': f"tty-{random.randint(1, 100)}",
        'tkt_options': f"options-{random.randint(1, 100)}",
        'ProcessCommandLine': f"cmd-{random.randint(1, 100)}",
        'local_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'threat_name_s1': random.choice(['Malware', 'Phishing', 'Ransomware']),
        'macf_reason': random.choice(['Policy Violation', 'Unauthorized Access']),
        'file_mode': random.choice(['Read', 'Write', 'Execute']),
        'new_user_win': f"user-{random.randint(1, 100)}",
        'LocalPort': str(random.randint(1024, 65535)),
        'user_agent_hacker_tool': f"hacker-tool-{random.randint(1, 100)}",
        'firewall_rule_name': f"rule-{random.randint(1, 100)}",
        'device_linux': f"device-{random.randint(1, 100)}",
        'packets_pa': str(random.randint(1, 1000)),
        'FileOriginUrl': f"https://origin-{random.randint(1, 100)}.com",
        'appfilter_policy_id': f"policy-{random.randint(1, 100)}",
        'command_line_cs': f"cmd-{random.randint(1, 100)}",
        'euid_linux': str(random.randint(1000, 9999)),
        'dga_domain_name': f"dga-{random.randint(1, 100)}.com",
        'file_creation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target_filename_sysmon': f"file-{random.randint(1, 100)}.txt",
        'command_linux': f"command-{random.randint(1, 100)}",
        'service_name_sysmon': f"service-{random.randint(1, 100)}",
        'system_folder_path': f"/path/to/system-{random.randint(1, 100)}",
        'u2f_key_name': f"u2f-{random.randint(1, 100)}",
        'policy_name_s1': f"policy-{random.randint(1, 100)}",
        'bypass_reason': random.choice(['Timeout', 'Connection Refused']),
        'new_gid': str(random.randint(1000, 9999)),
        'new_admin_user': f"admin-{random.randint(1, 100)}",
        'bot_name': f"bot-{random.randint(1, 100)}",
        'detection_id': f"detection-{random.randint(1, 1000)}",
        'known_bad_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'dns_request': f"request-{random.randint(1, 100)}",
        'malware_family': f"family-{random.randint(1, 100)}",
        'filter_id': f"filter-{random.randint(1, 100)}",
        'arg2': f"arg-{random.randint(1, 100)}",
        'hostname_sysmon': f"sysmon-host-{random.randint(1, 100)}",
        'cmdline': f"cmd-{random.randint(1, 100)}",
        'local_ip_s1': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'modified_cookie_value': f"cookie-{random.randint(1, 100)}",
        'attacker_gid': str(random.randint(1000, 9999)),
        'device_trusted_duo': f"trusted-{random.randint(1, 100)}",
        'js_code': f"code-{random.randint(1, 100)}",
        'connection_count': str(random.randint(1, 100)),
        'InitiatingProcessAccountName': f"account-{random.randint(1, 100)}",
        'file_path_cb': f"/path/to/file-{random.randint(1, 100)}.txt",
        'config_path_pa': f"/path/to/config-{random.randint(1, 100)}",
        'spyware_name': f"spyware-{random.randint(1, 100)}",
        'RemoteDeviceName': f"device-{random.randint(1, 100)}",
        'user_agent_bot': f"bot-{random.randint(1, 100)}",
        'base64_encoded_command': f"base64-{random.randint(1, 100)}",
        'network_remote_port': str(random.randint(1024, 65535)),
        'phishing_domain': f"phishing-{random.randint(1, 100)}.com",
        'user_group': f"group-{random.randint(1, 100)}",
        'device_instance_id': f"instance-{random.randint(1, 100)}",
        'parent_pid_s1': str(random.randint(1000, 9999)),
        'malware_startup_path': f"/path/to/startup-{random.randint(1, 100)}",
        'rule_name_s1': f"rule-{random.randint(1, 100)}",
        'miner_family': f"miner-{random.randint(1, 100)}",
        'RegistryValueName': f"value-{random.randint(1, 100)}",
        'dns_query': f"query-{random.randint(1, 100)}",
        'hidden_script_path': f"/path/to/hidden-{random.randint(1, 100)}.js",
        'context_process_id': str(random.randint(1000, 9999)),
        'payload_url': f"https://payload-{random.randint(1, 100)}.com",
        'command_sysmon': f"command-{random.randint(1, 100)}",
        'workstation_win': f"workstation-{random.randint(1, 100)}",
        'mac_address2': ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6)),
        'dga_domain_sysmon': f"dga-{random.randint(1, 100)}.com",
        'dst_port_linux': str(random.randint(1024, 65535)),
        'admin_user_ipa': f"admin-{random.randint(1, 100)}",
        'old_start_type': random.choice(['Manual', 'Automatic']),
        'internal_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'target_filename_ads': f"ads-{random.randint(1, 100)}.txt",
        'file_version': f"v{random.randint(1, 10)}.{random.randint(0, 99)}",
        'value1': f"value-{random.randint(1, 100)}",
        'sha256_sysmon': f"{random.randint(1, 1000):064x}",
        'malware_reg_name': f"reg-{random.randint(1, 100)}",
        'daemon_name': f"daemon-{random.randint(1, 100)}",
        'martian_src_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'device_sysmon': f"sysmon-{random.randint(1, 100)}",
        'failure_count': str(random.randint(1, 100)),
        'download_path_sysmon': f"/path/to/download-{random.randint(1, 100)}",
        'new_group_linux': f"group-{random.randint(1, 100)}",
        'sha256_hash_cb': f"{random.randint(1, 1000):064x}",
        'target_process_path_s1': f"/path/to/process-{random.randint(1, 100)}.exe",
        'session_duration_s': f"{random.randint(1, 3600)}s",
        'service_path_win': f"C:\\path\\to\\service-{random.randint(1, 100)}.exe",
        'application_auth': f"app-{random.randint(1, 100)}",
        'encoded_payload': f"payload-{random.randint(1, 100)}",
        'ransom_ext': f".ransom-{random.randint(1, 100)}",
        'legit_process_name_sysmon': f"process-{random.randint(1, 100)}.exe",
        'policy_name_auth': f"policy-{random.randint(1, 100)}",
        'network_dest_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'master_ipa_hostname': f"ipa-master-{random.randint(1, 100)}",
        'vbs_script_file': f"script-{random.randint(1, 100)}.vbs",
        'command_to_run': f"command-{random.randint(1, 100)}",
        'ThreatFamilyName': f"family-{random.randint(1, 100)}",
        'peer_id': f"peer-{random.randint(1, 100)}",
        'command_line_args': f"args-{random.randint(1, 100)}",
        'malicious_domain': f"malicious-{random.randint(1, 100)}.com",
        'stage': random.choice(['Initial', 'Execution', 'Cleanup']),
        'dns_query_sysmon': f"query-{random.randint(1, 100)}",
        'netconn_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'pua_family': f"pua-{random.randint(1, 100)}",
        'log_file_path_sysmon': f"/path/to/log-{random.randint(1, 100)}.log",
        'json_parse_error': f"error-{random.randint(1, 100)}",
        'registry_key_run': f"key-{random.randint(1, 100)}",
        'xss_payload': f"payload-{random.randint(1, 100)}",
        'target_filename_obfuscated': f"file-{random.randint(1, 100)}.txt",
        'monitor_name': f"monitor-{random.randint(1, 100)}",
        'sync_error': f"error-{random.randint(1, 100)}",
        'network_share_path': f"\\\\server\\share\\path-{random.randint(1, 100)}",
        'md5_hash': f"{random.randint(1, 1000):032x}",
        'registry_key_path': f"HKLM\\Software\\Key-{random.randint(1, 100)}",
        'before_value': f"value-{random.randint(1, 100)}",
        'downloaded_exe': f"download-{random.randint(1, 100)}.exe",
        'cs_bytes': str(random.randint(1, 1000000)),
        'rule_uid': f"rule-{random.randint(1, 1000)}",
        'user_dn': f"CN=User-{random.randint(1, 100)},OU=Users,DC=example,DC=com",
        'value_name': f"value-{random.randint(1, 100)}",
        'file_path_s1': f"/path/to/file-{random.randint(1, 100)}.txt",
        'pwd_linux': f"password-{random.randint(1, 100)}",
        'protection_name': f"protection-{random.randint(1, 100)}",
        'malware_path_sysmon': f"/path/to/malware-{random.randint(1, 100)}.exe",
        'logon_id_admin': f"logon-{random.randint(1, 100)}",
        'src_port_linux': str(random.randint(1024, 65535)),
        'policy_name_sophos': f"policy-{random.randint(1, 100)}",
        'logon_id': f"logon-{random.randint(1, 100)}",
        'powershell_suspicious_cmd': f"cmd-{random.randint(1, 100)}",
        'process_cmd': f"process-{random.randint(1, 100)}",
        'protection_id': f"protection-{random.randint(1, 100)}",
        'context_thread_id': f"thread-{random.randint(1, 1000)}",
        'ParentProcessFileName': f"parent-{random.randint(1, 100)}.exe",
        'vendor_id': f"vendor-{random.randint(1, 100)}",
        'pattern_id': f"pattern-{random.randint(1, 100)}",
        'detection_engine': f"engine-{random.randint(1, 100)}",
        'target_guid_cb': f"guid-{random.randint(1000, 9999)}",
        'download_path': f"/path/to/download-{random.randint(1, 100)}",
        'email_subject': f"subject-{random.randint(1, 100)}",
        'parent_process_id_sysmon': str(random.randint(1000, 9999)),
        'monitor_failure_reason': random.choice(['Timeout', 'Connection Refused']),
        'bind_dn': f"CN=Bind-{random.randint(1, 100)},OU=Users,DC=example,DC=com",
        'remote_hostname': f"remote-{random.randint(1, 100)}.example.com",
        'category_id': f"category-{random.randint(1, 100)}",
        'mac_address_linux': ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6)),
        'process_cmd_sophos': f"cmd-{random.randint(1, 100)}",
        'source_process_id_sysmon': str(random.randint(1000, 9999)),
        'duration_pa': f"{random.randint(1, 3600)}s",
        'confidence': random.choice(['High', 'Medium', 'Low']),
        'ads_content_example': f"content-{random.randint(1, 100)}",
        'script_path_cb': f"/path/to/script-{random.randint(1, 100)}.py",
        'dst_ip_linux': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'Category_mde': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'suid_linux': str(random.randint(1000, 9999)),
        'ioc_term': f"ioc-{random.randint(1, 100)}",
        'new_start_type': random.choice(['Manual', 'Automatic']),
        'src_port_win': str(random.randint(1024, 65535)),
        'parent_process_path_s1': f"/path/to/parent-{random.randint(1, 100)}",
        'packets': str(random.randint(1, 1000)),
        'dns_response_sysmon': f"response-{random.randint(1, 100)}",
        'domain_cb': f"domain-{random.randint(1, 100)}.com",
        'uac_value': f"value-{random.randint(1, 100)}",
        'malware_family_cb': f"family-{random.randint(1, 100)}",
        'vbscript_code': f"code-{random.randint(1, 100)}",
        'dst_ip_sysmon': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'tor_node_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'dynamic_dns_domain_s1': f"dynamic-{random.randint(1, 100)}.com",
        'query_length': str(random.randint(1, 100)),
        'child_pid_cb': str(random.randint(1000, 9999)),
        'ransomware_family': f"ransom-{random.randint(1, 100)}",
        'mount_options': f"options-{random.randint(1, 100)}",
        'ProcessTokenElevation': random.choice(['True', 'False']),
        'disk_threshold': f"{random.randint(1, 100)}%",
        'device_vendor': f"vendor-{random.randint(1, 100)}",
        'service_account': f"account-{random.randint(1, 100)}",
        'inode': str(random.randint(1, 100000)),
        'sha1_sysmon': f"{random.randint(1, 1000):x}",
        'new_gid_linux': str(random.randint(1000, 9999)),
        'new_file_name_ransom': f"ransom-{random.randint(1, 100)}.exe",
        'command_persistence': f"command-{random.randint(1, 100)}",
        'user_list': f"user-{random.randint(1, 100)}",
        'access_device_os': f"device-{random.randint(1, 100)}",
        'source_image_path_sysmon': f"/path/to/image-{random.randint(1, 100)}.png",
        'FileOriginReferrerUrl': f"https://referrer-{random.randint(1, 100)}.com",
        'lsass_pid_sysmon': str(random.randint(1000, 9999)),
        'url_path': f"/path/to/url-{random.randint(1, 100)}",
        'remote_ip_s1': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'dns_tunnel_query': f"query-{random.randint(1, 100)}",
        'pwd_ipa': f"password-{random.randint(1, 100)}",
        'aes256': f"{random.randint(1, 1000):064x}",
        'aes256': 'Encrypted with AES256',
        'aes128': 'Encrypted with AES128',
        'AccountDomain': f"domain-{random.randint(1, 100)}.com",
        'legit_process_name': f"process-{random.randint(1, 100)}.exe",
        'target_process_id_sysmon': str(random.randint(1000, 9999)),
        'reg_path_cb': f"HKLM\\Software\\Key-{random.randint(1, 100)}",
        'InitialDetectionTime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'layer_id': f"layer-{random.randint(1, 100)}",
        'blocked_port': str(random.randint(1024, 65535)),
        'dga_domain_s1': f"dga-{random.randint(1, 100)}.com",
        'dns_query_s1': f"query-{random.randint(1, 100)}",
        'logon_id_enum': f"logon-{random.randint(1, 100)}",
        'network_dest_port': str(random.randint(1024, 65535)),
        'target_path_cb': f"/path/to/target-{random.randint(1, 100)}",
        'netconn_port': str(random.randint(1024, 65535)),
        'irc_port': str(random.randint(1024, 65535)),
        'classification': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'system_log_path': f"/var/log/system-{random.randint(1, 100)}.log",
        'large_cs_bytes': str(random.randint(1000000, 10000000)),
        'target_computer_name': f"computer-{random.randint(1, 100)}",
        'webfilter_id': f"filter-{random.randint(1, 100)}",
        'report_name': f"report-{random.randint(1, 100)}",
        'deleted_user_dn': f"CN=User-{random.randint(1, 100)},OU=Deleted,DC=example,DC=com",
        'mitigation_action': random.choice(['Quarantine', 'Block']),
        'new_user_dn': f"CN=User-{random.randint(1, 100)},OU=New,DC=example,DC=com",
        'registry_key_path_security': f"HKLM\\Security\\Key-{random.randint(1, 100)}",
        'target_process_pid': str(random.randint(1000, 9999)),
        'value_name_sysmon': f"value-{random.randint(1, 100)}",
        'system_binary_path': f"/bin/system-{random.randint(1, 100)}",
        'dns_query_cb': f"query-{random.randint(1, 100)}",
        'dst_ip_sysmon_c2': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'listen_port_s1': str(random.randint(1024, 65535)),
        'ldap_err_code': f"ERR-{random.randint(100, 999)}",
        'phishing_domain_s1': f"phishing-{random.randint(1, 100)}.com",
        'asr_rule_name': f"rule-{random.randint(1, 100)}",
        'value2': f"value-{random.randint(1, 100)}",
        'system_file_path': f"/path/to/system-{random.randint(1, 100)}.conf",
        'vpn_peer': f"vpn-{random.randint(1, 100)}",
        'IncidentId': f"incident-{random.randint(1, 1000)}",
        'mining_pool_address': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'remote_ip_logon': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'registry_value_name': f"value-{random.randint(1, 100)}",
        'file_description': f"description-{random.randint(1, 100)}",
        'new_user_display_name': f"user-{random.randint(1, 100)}",
        'reverse_dns': f"reverse-{random.randint(1, 100)}.com",
        'after_value': f"value-{random.randint(1, 100)}",
        'domain_sophos': f"domain-{random.randint(1, 100)}.com",
        'device_model': f"model-{random.randint(1, 100)}",
        'exploit_name': f"exploit-{random.randint(1, 100)}",
        'web_policy_id': f"policy-{random.randint(1, 100)}",
        'response_time_ms': str(random.randint(1, 1000)),
        'perf_impact': random.choice(['Low', 'Medium', 'High']),
        'malware_sig': f"sig-{random.randint(1, 100)}",
        'encryption_suite': random.choice(['AES', 'RSA', 'SHA']),
        'vpn_community': f"community-{random.randint(1, 100)}",
        'emulation_result': random.choice(['Success', 'Failure']),
        'target_pid_cb': str(random.randint(1000, 9999)),
        'device_product': f"product-{random.randint(1, 100)}",
        'original_path_cb': f"/path/to/original-{random.randint(1, 100)}",
        'original_hash': f"{random.randint(1, 1000):064x}",
        'suspicious_exe': f"suspicious-{random.randint(1, 100)}.exe",
        'reg_value_cb': f"value-{random.randint(1, 100)}",
        'powershell_encoded': f"encoded-{random.randint(1, 100)}",
        'malware_debugger_path': f"/path/to/debugger-{random.randint(1, 100)}",
        'tactic_cb': random.choice(['Execution', 'Persistence']),
        'source_process_path': f"/path/to/source-{random.randint(1, 100)}",
        'file_hash_sha1': f"{random.randint(1, 1000):x}",
        'failed_count': str(random.randint(1, 100)),
        'confidence_level_s1': random.choice(['High', 'Medium', 'Low']),
        'dns_response_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'value_data': f"value-{random.randint(1, 100)}",
        'product_id': f"product-{random.randint(1, 100)}",
        'script_path_s1': f"/path/to/script-{random.randint(1, 100)}.py",
        'malware_cmd': f"cmd-{random.randint(1, 100)}",
        'cve_id_s1': f"CVE-{random.randint(2000, 2025)}-{random.randint(1000, 9999)}",
        'remote_port_s1': str(random.randint(1024, 65535)),
        'action_taken_cs': random.choice(['Blocked', 'Allowed']),
        'registry_value_data': f"value-{random.randint(1, 100)}",
        'tactic': random.choice(['Discovery', 'Privilege Escalation']),
        'packet_len': str(random.randint(1, 1500)),
        'fsuid_linux': str(random.randint(1000, 9999)),
        'scontext': f"context-{random.randint(1, 100)}",
        'key_type': random.choice(['RSA', 'DSA', 'ECDSA']),
        'disconnect_code': f"code-{random.randint(1, 100)}",
        'homedir': f"/home/user{random.randint(1, 100)}",
        'audit_action': random.choice(['Create', 'Delete']),
        'env_vars': f"env-{random.randint(1, 100)}",
        'parent_image_path_sysmon': f"/path/to/parent-{random.randint(1, 100)}.png",
        'command_scheduled': f"command-{random.randint(1, 100)}",
        'target_user_enum': f"user-{random.randint(1, 100)}",
        'handle_id': f"handle-{random.randint(1, 100)}",
        'target_image_path_sysmon': f"/path/to/target-{random.randint(1, 100)}.png",
        'process_name_win': f"process-{random.randint(1, 100)}.exe",
        'signed': random.choice(['True', 'False']),
        'parent_process_id_win': str(random.randint(1000, 9999)),
        'timestamp_never': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'dst_ip_win': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'call_trace': f"trace-{random.randint(1, 100)}",
        'malware_exe': f"malware-{random.randint(1, 100)}.exe",
        'share_path': f"\\\\server\\share\\path-{random.randint(1, 100)}",
        'c2_domain': f"c2-{random.randint(1, 100)}.com",
        'user_sid_added': f"sid-{random.randint(1, 1000)}",
        'user_sid_removed': f"sid-{random.randint(1, 1000)}",
        'new_thread_id': f"thread-{random.randint(1, 1000)}",
        'sid_backup_group': f"sid-{random.randint(1, 1000)}",
        'product_name': f"product-{random.randint(1, 100)}",
        'sid_schema_admin_group': f"sid-{random.randint(1, 1000)}",
        'sensitive_file_path': f"/path/to/sensitive-{random.randint(1, 100)}",
        'time_taken_ms': str(random.randint(1, 1000)),
        'InitiatingProcessAccountDomain': f"domain-{random.randint(1, 100)}.com",
        'LastDetectionTime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'FailureReason': random.choice(['Timeout', 'Connection Refused']),
        'MitigationAction': random.choice(['Quarantine', 'Block']),
        'Title': f"title-{random.randint(1, 100)}",
        'asr_action': random.choice(['Blocked', 'Allowed']),
        'command_ipa': f"command-{random.randint(1, 100)}",
        'access_device_browser': f"browser-{random.randint(1, 100)}",
        'aes256': f"{random.randint(1, 1000):064x}",
        'new_group_dn': f"CN=Group-{random.randint(1, 100)},OU=Groups,DC=example,DC=com",
        'auth_method_ldap': random.choice(['Password', 'Token', 'Biometric']),
        'sni_hostname': f"sni-{random.randint(1, 100)}.example.com",
        'client_src_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'egid_linux': str(random.randint(1000, 9999)),
        'technique': f"technique-{random.randint(1, 100)}",
        'file_hash_sha256_s1': f"{random.randint(1, 1000):064x}",
        'start_address': f"0x{random.randint(1, 1000):x}",
        'dst_port_sysmon': str(random.randint(1024, 65535)),
        'attack_info': f"attack-{random.randint(1, 100)}",
        'company_name': f"Company-{random.randint(1, 100)}",
        'aes256': f"{random.randint(1, 1000):064x}",
        'exception_id': f"exception-{random.randint(1, 100)}",
        'ioc_value': f"ioc-{random.randint(1, 100)}",
        'parent_process_name_win': f"process-{random.randint(1, 100)}.exe",
        'local_share_path': f"\\\\server\\share\\path-{random.randint(1, 100)}",
        'rollback_duration': f"{random.randint(1, 3600)}s",
        'technique_cb': f"technique-{random.randint(1, 100)}",
        'key_fingerprint': f"fingerprint-{random.randint(1, 100)}",
        'ttl': str(random.randint(1, 255)),
        'tcontext': f"context-{random.randint(1, 100)}",
        'sid_target_user': f"sid-{random.randint(1, 1000)}",
        'source_thread_id': f"thread-{random.randint(1, 1000)}",
        'signature': f"signature-{random.randint(1, 100)}",
        'sid_removed_user': f"sid-{random.randint(1, 1000)}",
        'sid_added_user': f"sid-{random.randint(1, 1000)}",
        'engine': f"engine-{random.randint(1, 100)}",
        'MitreTechniques': f"T{random.randint(1000, 1999)}",
        'malware_type': random.choice(['Trojan', 'Ransomware', 'Spyware']),
        'deleted_file_path': f"/path/to/deleted-{random.randint(1, 100)}.txt",
        'Description': f"description-{random.randint(1, 100)}",
        'sni_hostname': f"sni-{random.randint(1, 100)}.example.com",
        'client_src_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'egid_linux': str(random.randint(1000, 9999)),
        'technique': f"technique-{random.randint(1, 100)}",
        'file_hash_sha256_s1': f"{random.randint(1, 1000):064x}",
        'start_address': f"0x{random.randint(1, 1000):x}",
        'dst_port_sysmon': str(random.randint(1024, 65535)),
        'attack_info': f"attack-{random.randint(1, 100)}",
        'company_name': f"Company-{random.randint(1, 100)}",
        'aes256': f"{random.randint(1, 1000):064x}",
        'exception_id': f"exception-{random.randint(1, 100)}",
        'ioc_value': f"ioc-{random.randint(1, 100)}",
        'parent_process_name_win': f"process-{random.randint(1, 100)}.exe",
        'local_share_path': f"\\\\server\\share\\path-{random.randint(1, 100)}",
        'rollback_duration': f"{random.randint(1, 3600)}s",
        'technique_cb': f"technique-{random.randint(1, 100)}",
        'key_fingerprint': f"fingerprint-{random.randint(1, 100)}",
        'ttl': str(random.randint(1, 255)),
        'tcontext': f"context-{random.randint(1, 100)}",
        'sid_target_user': f"sid-{random.randint(1, 1000)}",
        'source_thread_id': f"thread-{random.randint(1, 1000)}",
        'signature': f"signature-{random.randint(1, 100)}",
        'sid_removed_user': f"sid-{random.randint(1, 1000)}",
        'sid_added_user': f"sid-{random.randint(1, 1000)}",
        'engine': f"engine-{random.randint(1, 100)}",
        'MitreTechniques': f"T{random.randint(1000, 1999)}",
        'malware_type': random.choice(['Trojan', 'Ransomware', 'Spyware']),
        'deleted_file_path': f"/path/to/deleted-{random.randint(1, 100)}.txt",
        'Description': f"description-{random.randint(1, 100)}",
        'bytes_transferred': str(random.randint(1000, 1000000)),
        'mitigation_status': random.choice(['Success', 'Failure']),
        'ioc_type': random.choice(['Indicator', 'Behavior']),
        'sid_rdp_group': f"sid-{random.randint(1, 1000)}",
        'sgid_linux': str(random.randint(1000, 9999)),
        'tclass': f"class-{random.randint(1, 100)}",
        'signature_status': random.choice(['Valid', 'Invalid']),
        'DetectionSource': random.choice(['Endpoint', 'Network', 'Cloud']),
        'start_module': f"module-{random.randint(1, 100)}",
        'relative_file_path': f"./path/to/file-{random.randint(1, 100)}.txt",
        'ip_id': f"ip-{random.randint(1, 1000)}",
        'mitre_tactic_s1': f"Tactic-{random.randint(1, 100)}",
        'original_file_name': f"file-{random.randint(1, 100)}.txt",
        'large_bytes_transferred': str(random.randint(1000000, 10000000)),
        'very_large_bytes_transferred': str(random.randint(10000000, 100000000)),
        'sid_admin_group': f"sid-{random.randint(1, 1000)}",
        'url_with_sqli_pattern': f"https://example.com?id={random.randint(1, 100)}' OR '1'='1",
        'content_type': random.choice(['application/json', 'text/html', 'application/xml']),
        'url_c2_beacon': f"https://c2-beacon-{random.randint(1, 100)}.com",
        'non_std_http_method': random.choice(['PROPFIND', 'TRACE', 'CONNECT']),
        'url_large_file': f"https://example.com/largefile-{random.randint(1, 100)}.zip",
        'reputation_level': random.choice(['High', 'Medium', 'Low']),
        'fsgid_linux': str(random.randint(1000, 9999)),
        'url_vulnerable_app': f"https://vulnerable-app-{random.randint(1, 100)}.com",
        'acl_blocked_telnet': f"telnet-{random.randint(1, 100)}",
        'url_with_traversal_pattern': f"https://example.com/../../{random.randint(1, 100)}",
        'url_needs_auth': f"https://auth-required-{random.randint(1, 100)}.com",
        'acl_time_restriction': f"time-{random.randint(1, 100)}",
        'tor_exit_node_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'url_adware_site': f"https://adware-{random.randint(1, 100)}.com",
        'non_ssl_port': str(random.randint(1024, 65535)),
        'rdp_server_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'mitre_technique_s1': f"T{random.randint(1000, 1999)}",
        'url_ransomware_payment': f"https://ransomware-payment-{random.randint(1, 100)}.com",
        'url_malware_hash_check': f"https://malware-hash-check-{random.randint(1, 100)}.com",
        'url_geoblocked_resource': f"https://geoblocked-{random.randint(1, 100)}.com",
        'malicious_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'url_file_put': f"https://example.com/upload-{random.randint(1, 100)}",
        'url_phishing': f"https://phishing-{random.randint(1, 100)}.com",
        'acl_blocked_user_agent': f"user-agent-{random.randint(1, 100)}",
        'url_internal_resource': f"https://internal-{random.randint(1, 100)}.example.com",
        'ssh_server_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'url_c2': f"https://c2-{random.randint(1, 100)}.com",
        'url_coinminer': f"https://coinminer-{random.randint(1, 100)}.com",
        'url_forbidden': f"https://forbidden-{random.randint(1, 100)}.com",
        'url_hacking_forum': f"https://hacking-forum-{random.randint(1, 100)}.com",
        'url_exploit_kit_landing': f"https://exploit-kit-{random.randint(1, 100)}.com",
        'url_upload': f"https://upload-{random.randint(1, 100)}.example.com",
        'url_suspicious_tld': f"https://example.{random.choice(['xyz', 'top', 'info'])}",
        'url_with_exe': f"https://example.com/file-{random.randint(1, 100)}.exe",
        'start_function': f"function-{random.randint(1, 100)}",
        'url_anon_proxy': f"https://anon-proxy-{random.randint(1, 100)}.com",
        'udp_len': str(random.randint(1, 65535)),
        'command_line_sysmon': f"cmd-{random.randint(1, 100)}",
        'protocol_linux': random.choice(['TCP', 'UDP', 'ICMP']),

        # ...Rapid SCADA...
        'scada_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'component_name': f"component-{random.randint(1, 100)}",
        'severity_scada': random.choice(['Critical', 'High', 'Medium', 'Low']),
        'message': f"message-{random.randint(1, 100)}",
        'user_scada': f"user-{random.randint(1, 100)}",
        'src_ip_scada': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'attempts': str(random.randint(1, 10)),
        'admin_user_scada': f"admin-{random.randint(1, 100)}",
        'target_user_scada': f"user-{random.randint(1, 100)}",
        'command_scada': f"command-{random.randint(1, 100)}",
        'cnl_num': str(random.randint(1, 100)),
        'obj_num': str(random.randint(1, 100)),
        'command_value': f"value-{random.randint(1, 100)}",
        'config_file_scada': f"/path/to/config-{random.randint(1, 100)}.conf",
        'error_reason_scada': f"reason-{random.randint(1, 100)}",
        'line_num_scada': str(random.randint(1, 100)),
        'device_id_scada': f"device-{random.randint(1, 100)}",
        'device_ip_scada': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'invalid_data_hex': f"0x{random.randint(1, 100):x}",
        'session_id_scada': f"session-{random.randint(1, 1000)}",
        'location_scada': f"location-{random.randint(1, 100)}",
        'usual_ip_scada': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'property_name': f"property-{random.randint(1, 100)}",
        'old_value': f"value-{random.randint(1, 100)}",
        'new_value': f"value-{random.randint(1, 100)}",
        'event_id_scada': f"event-{random.randint(1, 1000)}",
        'service_stop_reason': random.choice(['Maintenance', 'Failure']),
        'scada_version': f"v{random.randint(1, 10)}.{random.randint(0, 99)}",
        'exception_code': f"code-{random.randint(1, 100)}",
        'function_code': f"func-{random.randint(1, 100)}",
        'new_user_scada': f"user-{random.randint(1, 100)}",
        'role_scada': f"role-{random.randint(1, 100)}",
        'deleted_user_scada': f"user-{random.randint(1, 100)}",
        'license_error': f"error-{random.randint(1, 100)}",
        'comm_port': str(random.randint(1, 65535)),
        'session_duration_scada': f"{random.randint(1, 3600)}s",
        'old_role_id': f"role-{random.randint(1, 100)}",
        'new_role_id': f"role-{random.randint(1, 100)}",
        'db_connection_string': f"db-{random.randint(1, 100)}",
        'db_error': f"error-{random.randint(1, 100)}",
        'error_count': str(random.randint(1, 100)),
        'time_window': f"{random.randint(1, 60)}m",
        'invalid_session_id': f"session-{random.randint(1, 1000)}",
        'backup_path_scada': f"/path/to/backup-{random.randint(1, 100)}",
        'backup_error': f"error-{random.randint(1, 100)}",
        'disk_free_percent': f"{random.randint(1, 100)}%",
        'expected_protocol': random.choice(['Modbus', 'DNP3', 'OPC']),
        'received_protocol': random.choice(['Modbus', 'DNP3', 'OPC']),
        'allowed_ips': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        'last_comm_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'channel_num': str(random.randint(1, 100)),
        'ntp_server_scada': f"ntp-{random.randint(1, 5)}.example.com",
        'time_offset': f"{random.randint(-100, 100)}ms",
        'archive_file_path': f"/path/to/archive-{random.randint(1, 100)}.zip",
        'archive_error': f"error-{random.randint(1, 100)}",
        'serial_error': f"error-{random.randint(1, 100)}",
        'param_name': f"param-{random.randint(1, 100)}",
        'xss_value': f"xss-{random.randint(1, 100)}",
        'permission_scada': random.choice(['Read', 'Write', 'Execute']),
        'cpu_util_percent': f"{random.randint(1, 100)}%",
        'expected_len': str(random.randint(1, 1000)),
        'received_len': str(random.randint(1, 1000)),
        'field_name': f"field-{random.randint(1, 100)}",
        'sqli_value': f"sqli-{random.randint(1, 100)}",
        'restore_file_path': f"/path/to/restore-{random.randint(1, 100)}.bak",
        'failover_reason': random.choice(['Hardware Failure', 'Network Issue']),
                'acl_detect_beacon': 'Detected beacon activity',
        'blocked_user_agent': 'Blocked suspicious user agent',
        'acl_warn_executable': 'Warning: Executable detected',
        'mark': 'Important log marker',
        'acl_warn_connect_port': 'Warning: Connection to restricted port',
        'current_directory': '/home/user/current',
        'acl_blocked_ip': '192.168.1.100',
        'aes256': 'Encrypted with AES256',
        'aes128': 'Encrypted with AES128',
        'acl_monitor_403': 'Monitoring HTTP 403 responses',
        'acl_monitor_ssh_tunnel': 'Monitoring SSH tunnel activity',
        'acl_blocked_phishing': 'Blocked phishing attempt',
        'window_size': '1024x768',
        'acl_blocked_category': 'Blocked category: Social Media',
        'incident_status': 'Resolved',
        'acl_monitor_large_upload': 'Monitoring large file upload',
        'acl_blocked_ransom_pay': 'Blocked ransomware payment',
        'acl_blocked_hacking': 'Blocked hacking attempt',
        'acl_blocked_c2': 'Blocked Command and Control server',
        'acl_blocked_tor': 'Blocked TOR exit node',
        'acl_detect_miner': 'Detected cryptocurrency miner',
        'acl_blocked_proxy': 'Blocked proxy usage',
        'acl_monitor_rdp_tunnel': 'Monitoring RDP tunnel activity',
        'acl_detect_sqli': 'Detected SQL injection attempt',
        'acl_detect_exploit_kit': 'Detected exploit kit activity',
        'acl_internal_policy': 'Internal policy violation',
        'acl_alert_large_download': 'Alert: Large file download detected',
        'owner_uid': '1001',
        'acl_detect_adware': 'Detected adware activity',
        'acl_monitor_put': 'Monitoring HTTP PUT requests',
        'acl_warn_suspicious_tld': 'Warning: Suspicious TLD detected',
        'acl_blocked_malware_check': 'Blocked malware hash check',
        'beacon_interval': f"{random.randint(1, 60)}s",  # Intervalo de beacon en segundos
        'owner_gid': str(random.randint(1000, 9999)),    # ID de grupo del propietario
        'logon_guid': f"guid-{random.randint(1000, 9999)}",  # GUID de inicio de sesión
        'aes256,aes128': f"{random.randint(1, 1000):032x}",
        'aes256,aes128,': f"{random.randint(1, 1000):032x}",
        ',aes256,aes128,': f"{random.randint(1, 1000):032x}",  # Valor hexadecimal aleatorio  # Valor hexadecimal aleatorio
        'logon_id_sysmon': f"logon-{random.randint(1000, 9999)}",  # ID de inicio de sesión para Sysmon


    }

    # Asegurarse de que todos los valores sean strings para .format
    return {k: str(v) for k, v in data.items()}


# --- Lógica Principal ---

def main():
    """Función principal que ejecuta el simulador."""
    app_logger.log_info("Simulador de logs iniciado.")

    # 1. Mostrar menú y obtener selección
    tecnologias_seleccionadas = mostrar_nuevo_menu_seleccion()
    server_port_str = 514 # Puerto por defecto para Syslog
    server_port = server_port_str # Puerto por defecto para Syslog

    protocolo =  'UDP' # Protocolo por defecto para Syslog

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
        try:
            # Validar si la IP es válida
            ipaddress.ip_address(server_ip)
            break  # Salir del bucle si la IP es válida
        except ValueError:
            print(f"[ERROR] '{server_ip}' no es una dirección IP válida. Intenta de nuevo.")

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
                missing_placeholder = str(e).strip("'")  # Extraer el nombre del placeholder que falta
                error_msg = f"Falta marcador '{missing_placeholder}'"
                
                # Registrar el placeholder faltante
                app_logger.log_generation_error(template, data.keys(), error_msg)
                app_logger.log_placeholder_not_found(missing_placeholder)  # Enviar solo el placeholder faltante
                
                # Imprimir solo una vez por error de formato para no llenar consola
                if logs_fallidos_formato == 1:
                    print(f"\n[ERROR DE FORMATO] {error_msg} en plantilla: '{template[:100]}...'. Verifica tus plantillas.")
                continue  # Saltar al siguiente log
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