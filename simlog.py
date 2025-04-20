import socket
import time
import random
from datetime import datetime

# Solicitar IP del colector de logs
SYSLOG_SERVER = input("Introduce la IP del servidor Syslog (Wazuh, QRadar, etc.): ").strip()
SYSLOG_PORT = 514  # Puerto por defecto (UDP)
PROTOCOL = 'UDP'  # 'UDP' o 'TCP'

# Plantillas de logs por marca (con placeholders)
LOG_TEMPLATES = {
    'Fortinet': [
        "<134>date={date} time={time} devname=FGT01 msg='Denied by policy {policy}' src={src} dst={dst} service={service}",
        "<134>date={date} time={time} devname=FGT01 msg='Allowed by policy {policy}' src={src} dst={dst} service={service}",
        "<134>date={date} time={time} devname=FGT01 msg='User {user} login success' src={src} dst={dst}",
        "<134>date={date} time={time} devname=FGT01 msg='User {user} login failure' src={src} dst={dst}",
        "<134>date={date} time={time} devname=FGT01 msg='System event: {event}'",
        "<134>date={date} time={time} devname=FGT01 logid=\"{logid}\" severity={severity} src={src}",
        "<134>date={date} time={time} devname=FGT01 kernel: Interface {iface} down",
        "<134>date={date} time={time} devname=FGT01 kernel: Interface {iface} up",
        "<134>date={date} time={time} devname=FGT01 msg='VPN tunnel {tunnel} established' src={src} dst={dst}",
        "<134>date={date} time={time} devname=FGT01 msg='VPN tunnel {tunnel} disconnected' src={src} dst={dst}",
        "<134>date={date} time={time} devname=FGT01 msg='Antivirus update: version {version}'",
        "<134>date={date} time={time} devname=FGT01 msg='Disk usage: {percent}% full on {disk}'",
        "<134>date={date} time={time} devname=FGT01 msg='CPU load average: {load}'",
        "<134>date={date} time={time} devname=FGT01 msg='Memory usage: {used}/{total} MB'",
        "<134>date={date} time={time} devname=FGT01 msg='Configuration change by {user}'",
        "<134>date={date} time={time} devname=FGT01 msg='Firmware upgrade started version={version}'",
        "<134>date={date} time={time} devname=FGT01 msg='Firmware upgrade completed version={version}'",
        "<134>date={date} time={time} devname=FGT01 msg='High temperature alert: {temp}°C'",
        "<134>date={date} time={time} devname=FGT01 msg='Session timeout for user {user}'",
        "<134>date={date} time={time} devname=FGT01 msg='Threat detected: {threat}' src={src} dst={dst}",
        "<134>date={date} time={time} devname=FGT01 msg='IPS signature {sigid} triggered'",
        "<134>date={date} time={time} devname=FGT01 msg='Web filter: URL blocked {url}'",
        "<134>date={date} time={time} devname=FGT01 msg='SSL inspection {action} for session {session}'",
        "<134>date={date} time={time} devname=FGT01 msg='User {user} changed password'",
        "<134>date={date} time={time} devname=FGT01 msg='Admin {user} logged out'",
        "<134>date={date} time={time} devname=FGT01 msg='Configuration backup created: {filename}'",
        "<134>date={date} time={time} devname=FGT01 msg='Configuration restore started'",
        "<134>date={date} time={time} devname=FGT01 msg='Configuration restore completed'",
        "<134>date={date} time={time} devname=FGT01 logid=\"{logid}\" msg='License expired'",
        "<134>date={date} time={time} devname=FGT01 logid=\"{logid}\" msg='License renewed'"
    ],
    'Cisco ASA': [
        "<189>{date} {time} %ASA-6-302013: Built outbound TCP connection for outside:{src}/{sport}",
        "<189>{date} {time} %ASA-4-313005: No matching connection for ICMP error message from {src}",
        "<189>{date} {time} %ASA-5-111008: User '{user}' executed 'show running-config'",
        "<189>{date} {time} %ASA-6-302015: Built inbound UDP connection for inside:{src}/{sport} to {dst}/{dport}",
        "<189>{date} {time} %ASA-6-302014: Teardown TCP connection for outside:{src}/{sport}",
        "<189>{date} {time} %ASA-6-302016: Teardown UDP connection for inside:{src}/{sport}",
        "<189>{date} {time} %ASA-5-713172: HTTP request from {src} to {dst}",
        "<189>{date} {time} %ASA-4-313001: Denied ICMP type={type} from {src}",
        "<189>{date} {time} %ASA-6-302020: Built outbound IPSEC SA for {tunnel}",
        "<189>{date} {time} %ASA-6-302021: Teardown IPSEC SA for {tunnel}",
        "<189>{date} {time} %ASA-4-305011: Incomplete header received",
        "<189>{date} {time} %ASA-6-725001: SNMP trap: {trap}",
        "<189>{date} {time} %ASA-5-713158: HTTP status {status} from {dst}",
        "<189>{date} {time} %ASA-5-713165: FTP login success for {user}",
        "<189>{date} {time} %ASA-4-713166: FTP login failure for {user}",
        "<189>{date} {time} %ASA-6-605007: AAA user authentication success for {user}",
        "<189>{date} {time} %ASA-4-605008: AAA user authentication failure for {user}",
        "<189>{date} {time} %ASA-6-113019: DHCP lease allocated to {src}",
        "<189>{date} {time} %ASA-4-113020: DHCP lease release from {src}",
        "<189>{date} {time} %ASA-6-305015: Fragment received from {src}",
        "<189>{date} {time} %ASA-7-713142: HTTP URL filter log: {url}",
        "<189>{date} {time} %ASA-6-106100: Access-list {acl} permitted {protocol} from {src}/{sport} to {dst}/{dport}",
        "<189>{date} {time} %ASA-4-106001: Access-list {acl} denied {protocol} from {src}/{sport} to {dst}/{dport}",
        "<189>{date} {time} %ASA-3-710002: PIX operating correctly",
        "<189>{date} {time} %ASA-6-713162: HTTP redirect to {url}",
        "<189>{date} {time} %ASA-5-622001: Syslog logging enabled",
        "<189>{date} {time} %ASA-5-622002: Syslog logging disabled",
        "<189>{date} {time} %ASA-6-113010: DHCP request from {src}",
        "<189>{date} {time} %ASA-6-408100: ASA platform event: {event}",
        "<189>{date} {time} %ASA-6-305004: ICMP type={type} code={code} from {src}"
    ],
    'Windows': [
        "<134>EventID=4624; Inicio de sesión exitoso de {user} desde {src_ip}",
        "<134>EventID=4625; Intento de inicio de sesión fallido para {user} desde {src_ip}",
        "<134>EventID=4634; Cierre de sesión de {user} desde {src_ip}",
        "<134>EventID=4647; Cierre de sesión iniciado por el usuario {user}",
        "<134>EventID=4648; Inicio de sesión con credenciales explícitas por {user}",
        "<134>EventID=4672; Privilegios especiales asignados a {user}",
        "<134>EventID=4688; Se ha creado un nuevo proceso: {process_name}",
        "<134>EventID=4689; El proceso {process_name} ha salido",
        "<134>EventID=4720; Se ha creado una cuenta de usuario: {user}",
        "<134>EventID=4722; Se ha habilitado la cuenta de usuario: {user}",
        "<134>EventID=4723; Intento de restablecer la contraseña de {user}",
        "<134>EventID=4724; Se ha restablecido la contraseña de {user}",
        "<134>EventID=4725; Se ha deshabilitado la cuenta de usuario: {user}",
        "<134>EventID=4726; Se ha eliminado la cuenta de usuario: {user}",
        "<134>EventID=4732; Se ha añadido un miembro a un grupo global: {group}",
        "<134>EventID=4733; Se ha eliminado un miembro de un grupo global: {group}",
        "<134>EventID=4740; Se ha bloqueado la cuenta de usuario: {user}",
        "<134>EventID=4767; Se ha desbloqueado la cuenta de usuario: {user}",
        "<134>EventID=4776; Intento de validación de credenciales para {user}",
        "<134>EventID=4798; Se ha enumerado la membresía de grupo local de {user}",
        "<134>EventID=4799; Se ha enumerado la membresía de grupo local habilitado para seguridad de {user}",
        "<134>EventID=5140; Acceso a recurso compartido de red: {share_name}",
        "<134>EventID=5142; Se ha añadido un recurso compartido de red: {share_name}",
        "<134>EventID=5143; Se ha modificado un recurso compartido de red: {share_name}",
        "<134>EventID=5144; Se ha eliminado un recurso compartido de red: {share_name}",
        "<134>EventID=5145; Se ha comprobado el acceso a recurso compartido de red: {share_name}",
        "<134>EventID=7034; El servicio {service_name} se ha detenido inesperadamente",
        "<134>EventID=7036; El servicio {service_name} ha cambiado de estado a {state}",
        "<134>EventID=7040; Se ha cambiado el tipo de inicio del servicio {service_name} a {start_type}",
        "<134>EventID=7045; Se ha instalado un nuevo servicio: {service_name}",
        "<134>EventID=1102; Se ha borrado el registro de seguridad",
        "<134>EventID=1104; El registro de seguridad está lleno",
        "<134>EventID=1105; Copia de seguridad automática del registro de eventos",
    ],
    'Palo Alto': [ "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|TRAFFIC|Allow traffic|1|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={protocol} act=allow",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|TRAFFIC|Deny traffic|1|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={protocol} act=deny",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|Virus detected|5|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={protocol} fileHash={file_hash} fileName={file_name} threatName={threat_name} act=alert",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|Spyware detected|5|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={protocol} threatName={threat_name} act=alert",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|Vulnerability exploit|5|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={protocol} threatName={threat_name} act=alert",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|URL filtering|5|src={src_ip} dst={dst_ip} url={url} category={category} act=block",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|Data filtering|5|src={src_ip} dst={dst_ip} fileName={file_name} fileType={file_type} act=alert",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|File blocking|5|src={src_ip} dst={dst_ip} fileName={file_name} fileType={file_type} act=block",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|WildFire verdict|5|src={src_ip} dst={dst_ip} fileName={file_name} verdict={verdict} act=alert",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|DNS sinkhole|5|src={src_ip} dst={dst_ip} domain={domain} act=alert",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|System reboot|3|msg=System reboot initiated by {user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|Configuration change|3|msg=Configuration changed by {user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|HA failover|3|msg=HA failover occurred",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|License expired|3|msg=License for {feature} expired",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|Software update|3|msg=Software updated to version {version}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|Commit successful|3|msg=Configuration committed by {user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|Commit failed|3|msg=Configuration commit failed by {user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|Interface up|3|msg=Interface {interface} is up",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|SYSTEM|Interface down|3|msg=Interface {interface} is down",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|AUTH|User login successful|1|src={src_ip} user={user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|AUTH|User login failed|1|src={src_ip} user={user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|AUTH|Admin login successful|1|src={src_ip} admin={user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|AUTH|Admin login failed|1|src={src_ip} admin={user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|AUTH|User logout|1|src={src_ip} user={user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|AUTH|Admin logout|1|src={src_ip} admin={user}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Rule added|2|admin={user} rule={rule_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Rule modified|2|admin={user} rule={rule_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Rule deleted|2|admin={user} rule={rule_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Address object added|2|admin={user} object={object_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Address object modified|2|admin={user} object={object_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Address object deleted|2|admin={user} object={object_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Service object added|2|admin={user} object={object_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Service object modified|2|admin={user} object={object_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|Service object deleted|2|admin={user} object={object_name}",
        "<134>CEF:0|Palo Alto Networks|PAN-OS|10.2|CONFIG|User-ID mapping added|2|admin={user} mapping={mapping_name}", ],

    'Linux': [  # Autenticación
        "<134>EventID=1000; Usuario inició sesión exitosamente: {user} desde {src_ip}",
        "<134>EventID=1001; Fallo en intento de inicio de sesión: {user} desde {src_ip}",
        "<134>EventID=1002; Usuario cerró sesión: {user}",
        "<134>EventID=1003; Usuario cambió su contraseña: {user}",
        "<134>EventID=1004; Usuario creado: {user} por {admin}",
        "<134>EventID=1005; Usuario eliminado: {user} por {admin}",
        "<134>EventID=1006; Usuario añadido al grupo: {user} al grupo {group}",
        "<134>EventID=1007; Usuario eliminado del grupo: {user} del grupo {group}",
        "<134>EventID=1008; Usuario bloqueado: {user}",
        "<134>EventID=1009; Usuario desbloqueado: {user}",

        # Procesos
        "<134>EventID=2000; Proceso iniciado: {process} por {user}",
        "<134>EventID=2001; Proceso terminado: {process} por {user}",
        "<134>EventID=2002; Proceso suspendido: {process} por {user}",
        "<134>EventID=2003; Proceso reanudado: {process} por {user}",
        "<134>EventID=2004; Proceso ejecutado con privilegios elevados: {process} por {user}",
        "<134>EventID=2005; Proceso matado: {process} por {user}",
        "<134>EventID=2006; Proceso zombie detectado: {process}",
        "<134>EventID=2007; Proceso en espera: {process}",
        "<134>EventID=2008; Proceso en ejecución: {process}",
        "<134>EventID=2009; Proceso detenido: {process}",

        # Red
        "<134>EventID=3000; Conexión entrante establecida desde {src_ip} a {dst_ip}:{dst_port}",
        "<134>EventID=3001; Conexión saliente establecida desde {src_ip} a {dst_ip}:{dst_port}",
        "<134>EventID=3002; Conexión cerrada entre {src_ip} y {dst_ip}:{dst_port}",
        "<134>EventID=3003; Intento de conexión fallido desde {src_ip} a {dst_ip}:{dst_port}",
        "<134>EventID=3004; Interfaz de red {interface} activada",
        "<134>EventID=3005; Interfaz de red {interface} desactivada",
        "<134>EventID=3006; Dirección IP asignada a {interface}: {ip_address}",
        "<134>EventID=3007; Dirección IP eliminada de {interface}: {ip_address}",
        "<134>EventID=3008; Cambio en la configuración de DNS: {dns_servers}",
        "<134>EventID=3009; Cambio en la configuración de la puerta de enlace: {gateway}",

        # Sistema
        "<134>EventID=4000; Sistema iniciado",
        "<134>EventID=4001; Sistema apagado",
        "<134>EventID=4002; Sistema reiniciado",
        "<134>EventID=4003; Cambio en la configuración del sistema por {user}",
        "<134>EventID=4004; Actualización del sistema instalada: {update}",
        "<134>EventID=4005; Error en la actualización del sistema: {update}",
        "<134>EventID=4006; Espacio en disco bajo en {filesystem}: {free_space} MB disponibles",
        "<134>EventID=4007; Uso de CPU alto detectado: {cpu_usage}%",
        "<134>EventID=4008; Uso de memoria alto detectado: {memory_usage}%",
        "<134>EventID=4009; Cambio en la zona horaria: {timezone}",

        # Auditoría
        "<134>EventID=5000; Archivo accedido: {file_path} por {user}",
        "<134>EventID=5001; Archivo modificado: {file_path} por {user}",
        "<134>EventID=5002; Archivo eliminado: {file_path} por {user}",
        "<134>EventID=5003; Archivo creado: {file_path} por {user}",
        "<134>EventID=5004; Permisos cambiados en {file_path} por {user}",
        "<134>EventID=5005; Propietario cambiado en {file_path} por {user}",
        "<134>EventID=5006; Intento de acceso no autorizado a {file_path} por {user}",
        "<134>EventID=5007; Montaje de dispositivo: {device} en {mount_point} por {user}",
        "<134>EventID=5008; Desmontaje de dispositivo: {device} de {mount_point} por {user}",
        "<134>EventID=5009; Cambio en la configuración de auditoría por {user}",

        # Servicios
        "<134>EventID=6000; Servicio iniciado: {service} por {user}",
        "<134>EventID=6001; Servicio detenido: {service} por {user}",
        "<134>EventID=6002; Servicio reiniciado: {service} por {user}",
        "<134>EventID=6003; Servicio falló: {service}",
        "<134>EventID=6004; Servicio habilitado: {service} por {user}",
        "<134>EventID=6005; Servicio deshabilitado: {service} por {user}",
        "<134>EventID=6006; Cambio en la configuración del servicio: {service} por {user}",
        "<134>EventID=6007; Servicio actualizado: {service} a la versión {version}",
        "<134>EventID=6008; Servicio degradado: {service}",
        "<134>EventID=6009; Servicio restaurado: {service}",

        # Seguridad
       "<134>EventID=7000; Intento de acceso remoto desde {src_ip} a {dst_ip}:{dst_port}",
        "<134>EventID=7001; Escaneo de puertos detectado desde {src_ip}",
        "<134>EventID=7002; Ataque de fuerza bruta detectado en {service} desde {src_ip}",
        "<134>EventID=7003; Malware detectado en {file_path}",
        "<134>EventID=7004; Fuga de datos potencial detectada: {details}",
        "<134>EventID=7005; Archivo sospechoso detectado: {file_path}",
        "<134>EventID=7006; Intento de escalada de privilegios detectado por {user}",
        "<134>EventID=7007; Acceso no autorizado a {file_path} por {user}",
        "<134>EventID=7008; Modificación de archivo crítico: {file_path} por {user}",
        "<134>EventID=7009; Eliminación de archivo sospechoso: {file_path} por {user}",
        "<134>EventID=7010; Configuración de firewall modificada por {user}",
        "<134>EventID=7011; Reglas de iptables cambiadas por {user}",
        "<134>EventID=7012; Servicio SSH reiniciado por {user}",
        "<134>EventID=7013; Servicio SSH detenido por {user}",
        "<134>EventID=7014; Servicio SSH iniciado por {user}",
        "<134>EventID=7015; Intento de conexión SSH fallido desde {src_ip}",
        "<134>EventID=7016; Acceso a directorio protegido: {dir_path} por {user}",
        "<134>EventID=7017; Intento de ejecución de script no autorizado: {script_path} por {user}",
        "<134>EventID=7018; Uso de sudo detectado por {user}",
        "<134>EventID=7019; Comando sospechoso ejecutado: {command} por {user}",
        "<134>EventID=7020; Acceso a puerto no autorizado: {port} por {user}",
        "<134>EventID=7021; Conexión VPN establecida por {user}",
        "<134>EventID=7022; Conexión VPN terminada por {user}",
        "<134>EventID=7023; Modificación de archivo de configuración: {file_path} por {user}",
        "<134>EventID=7024; Intento de desactivación de antivirus detectado por {user}",
        "<134>EventID=7025; Instalación de paquete sospechoso: {package_name} por {user}",
        "<134>EventID=7026; Eliminación de paquete sospechoso: {package_name} por {user}",
        "<134>EventID=7027; Actividad inusual en {service} detectada",
        "<134>EventID=7028; Conexión a red desconocida detectada por {user}",
        "<134>EventID=7029; Uso de herramienta de hacking detectado: {tool_name} por {user}",
        "<134>EventID=7030; Modificación de cron job: {job_name} por {user}",
        ]
}

# Funciones auxiliares para datos aleatorios
def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
def random_port():
    return random.randint(1024,65535)
def random_user():
    return random.choice(['admin','user','guest','root','sysadmin','john.doe'])
def random_service():
    return random.choice(['HTTP','HTTPS','SSH','DNS','ICMP','FTP'])
def random_event():
    return random.choice(['reboot','config-change','interface-down','session-timeout'])
def random_process():
    return random.choice(['cmd.exe','powershell.exe','notepad.exe','svchost.exe'])
def random_command():
    return random.choice(['apt update','rm -rf /tmp/*','systemctl restart sshd','chmod 700 /etc'])

def random_setting(): return random.choice(['ssh-port','hostname','timezone'])
def random_value(): return random.choice(['22','server1','UTC','PDT','EST'])
def random_load(): return round(random.uniform(0.1,5.0),2)
# Más funciones (etc.)

# Mapping placeholders a funciones
# ... Puede extender según plantillas

class SyslogSender:
    def __init__(self, server, port, protocol='UDP'):
        self.server = server
        self.port = port
        if protocol.upper() == 'TCP':
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((server, port))
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    def send(self, message):
        if self.sock.type == socket.SOCK_STREAM:
            self.sock.sendall((message + '\n').encode())
        else:
            self.sock.sendto(message.encode(), (self.server, self.port))

def mostrar_progreso(actual, total):
    pct = (actual / total) * 100
    print(f"Progreso: {actual}/{total} logs enviados ({pct:.2f}%)", end="\r")

if __name__ == '__main__':
    # Selección de marcas
    marcas = list(LOG_TEMPLATES.keys())
    print("Marcas disponibles:")
    for i, m in enumerate(marcas, 1): print(f"  {i}. {m}")
    sel = input("Selecciona marcas (ej: 1,3 o 'all'): ").strip()
    elegidas = marcas if sel.lower()=='all' else [marcas[int(i)-1] for i in sel.split(',') if i.isdigit()]

    # Cantidad de logs como float
    try: total = float(input("¿Cuántos logs deseas enviar? (puede ser decimal): "))
    except: total = 100.0
    total_int = int(total)
    # Intervalo como float
    try: intervalo = float(input("Intervalo entre logs (segundos, defecto 1): ") or 1.0)
    except: intervalo = 1.0

    sender = SyslogSender(SYSLOG_SERVER, SYSLOG_PORT, PROTOCOL)
    print(f"Iniciando simulación: {total_int} logs de {elegidas}, intervalo {intervalo}s")

    for i in range(total_int):
        marca = random.choice(elegidas)
        template = random.choice(LOG_TEMPLATES[marca])
        now = datetime.now()
        data = {
            'date': now.strftime('%Y-%m-%d'),  # Fecha actual
            'time': now.strftime('%H:%M:%S'),  # Hora actual
            'src': random_ip(),                # Dirección IP de origen (campo general)
            'src_ip': random_ip(),             # Dirección IP de origen (campo específico)
            'dst': random_ip(),                # Dirección IP de destino
            'sport': random_port(),            # Puerto de origen
            'dport': random_port(),            # Puerto de destino
            'pid': random.randint(100, 9999),  # ID de proceso aleatorio
            'user': random_user(),             # Usuario aleatorio
            'policy': random.randint(1, 100),  # Política aleatoria
            'service': random_service(),       # Servicio aleatorio
            'event': random_event(),           # Evento aleatorio
            'process': random_process(),       # Proceso aleatorio
            'command': random_command(),       # Comando aleatorio
            'setting': random_setting(),       # Configuración aleatoria
            'value': random_value(),           # Valor aleatorio
            'action': random.choice(['login', 'logout', 'config-change']),  # Acción aleatoria
            'load': random_load(),             # Carga promedio aleatoria
            # Extender según placeholders...
        }
        log = template.format(**data)  # Formatear el log con los datos generados
        sender.send(log)               # Enviar el log al servidor Syslog
        mostrar_progreso(i + 1, total_int)  # Mostrar progreso
        time.sleep(intervalo)          # Esperar el intervalo configurado

    print("\nSimulación completada.")
