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
        "<134>date={date} time={time} devname=FGT01 logid=\"{policy}\" severity={policy} src={src}",
        "<134>date={date} time={time} devname=FGT01 kernel: Interface {process} down",
        "<134>date={date} time={time} devname=FGT01 kernel: Interface {process} up",
        "<134>date={date} time={time} devname=FGT01 msg='VPN tunnel {process} established' src={src} dst={dst}",
        "<134>date={date} time={time} devname=FGT01 msg='VPN tunnel {process} disconnected' src={src} dst={dst}",
        "<134>date={date} time={time} devname=FGT01 msg='Antivirus update: version {value}'",
        "<134>date={date} time={time} devname=FGT01 msg='Disk usage: {load}% full on {process}'",
        "<134>date={date} time={time} devname=FGT01 msg='CPU load average: {load}'",
        "<134>date={date} time={time} devname=FGT01 msg='Memory usage: {load}/{policy} MB'",
        "<134>date={date} time={time} devname=FGT01 msg='Configuration change by {user}'",
        "<134>date={date} time={time} devname=FGT01 msg='Firmware upgrade started version={value}'",
        "<134>date={date} time={time} devname=FGT01 msg='Firmware upgrade completed version={value}'",
        "<134>date={date} time={time} devname=FGT01 msg='High temperature alert: {load}°C'",
        "<134>date={date} time={time} devname=FGT01 msg='Session timeout for user {user}'",
        "<134>date={date} time={time} devname=FGT01 msg='Threat detected: {threat_name}' src={src} dst={dst}",
        "<134>date={date} time={time} devname=FGT01 msg='IPS signature {rule_name} triggered'",
        "<134>date={date} time={time} devname=FGT01 msg='Web filter: URL blocked {url}'",
        "<134>date={date} time={time} devname=FGT01 msg='SSL inspection {action} for session {process}'",
        "<134>date={date} time={time} devname=FGT01 msg='User {user} changed password'",
        "<134>date={date} time={time} devname=FGT01 msg='Admin {user} logged out'",
        "<134>date={date} time={time} devname=FGT01 msg='Configuration backup created: {file_name}'",
        "<134>date={date} time={time} devname=FGT01 msg='Configuration restore started'",
        "<134>date={date} time={time} devname=FGT01 msg='Configuration restore completed'",
        "<134>date={date} time={time} devname=FGT01 logid=\"{policy}\" msg='License expired'",
        "<134>date={date} time={time} devname=FGT01 logid=\"{policy}\" msg='License renewed'"
    ],
    'Cisco ASA': [
        "<189>{date} {time} %ASA-6-302013: Built outbound TCP connection for outside:{src}/{sport}",
        "<189>{date} {time} %ASA-4-313005: No matching connection for ICMP error message from {src}",
        "<189>{date} {time} %ASA-5-111008: User '{user}' executed 'show running-config'",
        "<189>{date} {time} %ASA-6-302015: Built inbound UDP connection for inside:{src}/{sport} to {dst}/{dport}",
        "<189>{date} {time} %ASA-6-302014: Teardown TCP connection for outside:{src}/{sport}",
        "<189>{date} {time} %ASA-6-302016: Teardown UDP connection for inside:{src}/{sport}",
        "<189>{date} {time} %ASA-5-713172: HTTP request from {src} to {dst}",
        "<189>{date} {time} %ASA-4-313001: Denied ICMP type={policy} from {src}",
        "<189>{date} {time} %ASA-6-302020: Built outbound IPSEC SA for {process}",
        "<189>{date} {time} %ASA-6-302021: Teardown IPSEC SA for {process}",
        "<189>{date} {time} %ASA-4-305011: Incomplete header received",
        "<189>{date} {time} %ASA-6-725001: SNMP trap: {process}",
        "<189>{date} {time} %ASA-5-713158: HTTP status {policy} from {dst}",
        "<189>{date} {time} %ASA-5-713165: FTP login success for {user}",
        "<189>{date} {time} %ASA-4-713166: FTP login failure for {user}",
        "<189>{date} {time} %ASA-6-605007: AAA user authentication success for {user}",
        "<189>{date} {time} %ASA-4-605008: AAA user authentication failure for {user}",
        "<189>{date} {time} %ASA-6-113019: DHCP lease allocated to {src}",
        "<189>{date} {time} %ASA-4-113020: DHCP lease release from {src}",
        "<189>{date} {time} %ASA-6-305015: Fragment received from {src}",
        "<189>{date} {time} %ASA-7-713142: HTTP URL filter log: {url}",
        "<189>{date} {time} %ASA-6-106100: Access-list {rule_name} permitted {service} from {src}/{sport} to {dst}/{dport}",
        "<189>{date} {time} %ASA-4-106001: Access-list {rule_name} denied {service} from {src}/{sport} to {dst}/{dport}",
        "<189>{date} {time} %ASA-3-710002: PIX operating correctly",
        "<189>{date} {time} %ASA-6-713162: HTTP redirect to {url}",
        "<189>{date} {time} %ASA-5-622001: Syslog logging enabled",
        "<189>{date} {time} %ASA-5-622002: Syslog logging disabled",
        "<189>{date} {time} %ASA-6-113010: DHCP request from {src}",
        "<189>{date} {time} %ASA-6-408100: ASA platform event: {event}",
        "<189>{date} {time} %ASA-6-305004: ICMP type={policy} code={policy} from {src}"
    ],
    # Continúa con las demás plantillas...
}

# Funciones auxiliares para datos aleatorios
def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_port():
    return random.randint(1024, 65535)

def random_user():
    return random.choice(['admin', 'user', 'guest', 'root', 'sysadmin', 'john.doe'])

def random_service():
    return random.choice(['HTTP', 'HTTPS', 'SSH', 'DNS', 'ICMP', 'FTP'])

def random_event():
    return random.choice(['reboot', 'config-change', 'interface-down', 'session-timeout'])

def random_process():
    return random.choice(['cmd.exe', 'powershell.exe', 'notepad.exe', 'svchost.exe'])

def random_command():
    return random.choice(['apt update', 'rm -rf /tmp/*', 'systemctl restart sshd', 'chmod 700 /etc'])

def random_setting():
    return random.choice(['ssh-port', 'hostname', 'timezone'])

def random_value():
    return random.choice(['22', 'server1', 'UTC', 'PDT', 'EST'])

def random_load():
    return round(random.uniform(0.1, 5.0), 2)

def random_object_name():
    return random.choice(['Object1', 'Object2', 'Object3'])

def random_rule_name():
    return random.choice(['Rule1', 'Rule2', 'Rule3'])

def random_file_hash():
    return random.choice(['abc123', 'def456', 'ghi789'])

def random_file_name():
    return random.choice(['file1.txt', 'file2.exe', 'file3.doc'])

def random_threat_name():
    return random.choice(['Trojan', 'Ransomware', 'Spyware'])

def random_domain():
    return random.choice(['example.com', 'malicious.net', 'phishing.org'])

def random_url():
    return random.choice(['http://example.com', 'https://malicious.net', 'http://phishing.org'])

def random_category():
    return random.choice(['Malware', 'Phishing', 'Spam'])

def random_mapping_name():
    return random.choice(['Mapping1', 'Mapping2', 'Mapping3'])

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
    # Selección de marcas
    marcas = list(LOG_TEMPLATES.keys())
    print("Marcas disponibles:")
    for i, m in enumerate(marcas, 1):
        print(f"  {i}. {m}")
    sel = input("Selecciona marcas (ej: 1,3 o 'all'): ").strip()
    elegidas = marcas if sel.lower() == 'all' else [marcas[int(i)-1] for i in sel.split(',') if i.isdigit()]

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
    print(f"Iniciando simulación: {total_int} logs de {elegidas}, intervalo {intervalo}s")

    for i in range(total_int):
        marca = random.choice(elegidas)
        template = random.choice(LOG_TEMPLATES[marca])
        now = datetime.now()
        data = {
            'date': now.strftime('%Y-%m-%d'),
            'time': now.strftime('%H:%M:%S'),
            'src': random_ip(),
            'src_ip': random_ip(),
            'dst': random_ip(),
            'sport': random_port(),
            'dport': random_port(),
            'pid': random.randint(100, 9999),
            'user': random_user(),
            'policy': random.randint(1, 100),
            'service': random_service(),
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
        }
        if validar_plantilla(template, data):
            log = template.format(**data)
            print(log)
            sender.send(log)
            mostrar_progreso(i + 1, total_int)
        time.sleep(intervalo)

    print("\nSimulación completada.")