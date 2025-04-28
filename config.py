# config.py

"""
Módulo de configuración para el simulador de logs.
Contiene constantes globales como las rutas de los archivos de log.
"""

# Diccionario que mapea las tecnologías con sus archivos de logs
LOG_FILES = {
    "Cisco": "logs/cisco_logs.txt",
    "Fortinet": "logs/fortinet_logs.txt",
    "Huawei": "logs/huawei_logs.txt",
    "Mikrotik": "logs/mikrotik_logs.txt",
    "Palo Alto": "logs/paloalto_logs.txt",
    "WatchGuard": "logs/watchguard_logs.txt",
    "SonicWall": "logs/sonicwall_logs.txt",
    "Sophos (X/Central)": "logs/sophosintercepx_logs.txt",
    "Sophos (XG Fw/UTM)": "logs/sophos_logs.txt",
    "Squid Proxy": "logs/squidproxy_logs.txt",
    "F5 (BIG-IP LTM/ASM)": "logs/f5_logs.txt",
    "Aruba/HPE": "logs/aruba_logs.txt",
    "Check Point": "logs/checkpoint_logs.txt",
    "Carbon Black": "logs/carbonblack_logs.txt",
    "SentinelOne": "logs/sentinelone_logs.txt",
    "CrowdStrike Falcon": "logs/crowdstrike_logs.txt",
    "macOS": "logs/macos_logs.txt",
    "Linux": "logs/linux_logs.txt",
    "Windows": "logs/windows_logs.txt",
    "Microsoft IIS": "logs/microsoftiss_logs.txt",
    "Microsoft SQL Server": "logs/microsoftsql_logs.txt",
    "Microsoft Defender": "logs/microsoftdefender_logs.txt",
    "Rapid SCADA": "logs/rapidscada_logs.txt",
    "Auth Varios": "logs/authvarioswindows_logs.txt",
}