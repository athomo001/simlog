# 🪵 SimLog: Generador de Logs Syslog Simulados

![Alpha](https://img.shields.io/badge/status-Alpha-orange)
![GitHub repo size](https://img.shields.io/github/repo-size/athomo001/simlog)
![GitHub last commit](https://img.shields.io/github/last-commit/athomo001/simlog)
![GitHub issues](https://img.shields.io/github/issues/athomo001/simlog)
![GitHub](https://img.shields.io/github/license/athomo001/simlog)
![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![Python](https://img.shields.io/badge/python-3.x-blue)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Tools-yellow)
![SIEM](https://img.shields.io/badge/SIEM-Logs-green)
![Simulator](https://img.shields.io/badge/Simulator-Logs-red)
![Wazuh](https://img.shields.io/badge/Wazuh-Integration-blue)
![Splunk](https://img.shields.io/badge/Splunk-Integration-orange)
![Log Collection](https://img.shields.io/badge/Log%20Collection-Enabled-blue)
![QRadar](https://img.shields.io/badge/QRadar-Integration-blue)


---

## 📚 Tabla de Contenidos

- [¿Por qué usar SimLog?](#-por-qué-usar-simlog)
- [Características principales](#-características-principales)
- [Estado actual](#-estado-actual)
- [Requisitos](#-requisitos)
- [Instalación y uso](#-instalación-y-uso)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Tipos de logs soportados](#-tipos-de-logs-soportados-plantillas-disponibles)
- [Manejo de errores](#-manejo-de-errores)
- [Próximas mejoras](#-próximas-mejoras)
- [Licencia](#-licencia)

---

## 🤔 ¿Por qué usar SimLog?

- **Pruebas de carga:** Mide cuántos EPS soporta tu infraestructura de logs antes de entrar en producción o tras cambios importantes.
- **Entornos de laboratorio:** Evita montar costosa infraestructura (firewalls, servidores, routers) solo para generar tráfico de logs.
- **Formación y pruebas:** Perfecto para practicar análisis de logs, desarrollar reglas de correlación, dashboards o realizar demostraciones de SIEM.

---

## ✨ Características principales

- Generación de logs para múltiples tecnologías y fabricantes.
- Envío de logs vía Syslog (UDP) a un destino configurable (IP o hostname).
- Selección personalizada de tipos de logs a enviar.
- Configuración de cantidad de logs e intervalo de envío (permite tasas menores a un segundo).
- Interfaz interactiva desde línea de comandos.
- Código limpio, modular y fácil de extender.

---

## ⚠️ Estado actual

> **Alpha** – Proyecto en fase temprana, puede contener errores o comportamientos inesperados. Uso bajo tu propia responsabilidad.

---

## 📋 Requisitos

- Python 3.x
- Conectividad de red hacia el servidor Syslog destino (puerto UDP 514 por defecto).

---

## 🚀 Instalación y uso

1. Clona el repositorio:

```bash
git clone https://github.com/athomo001/simlog.git
cd simlog


2. Ejecuta el script principal:

```bash
python ./simlog.py
```

Opcionalmente, puedes darle permisos de ejecución:

```bash
chmod +x simlog.py
./simlog.py


3. Sigue las instrucciones interactivas en pantalla:

```plaintext
Selecciona las marcas de logs que deseas utilizar:
Ingresa los números separados por comas (ej: 1,3,5) o el número para 'Todos'.
------------------------------------------------------------------------------------------------------------------------
1   Cisco               2   Fortinet            3   Huawei            4   Mikrotik
5   Palo Alto           6   WatchGuard          7   SonicWall         8   Sophos (X/Central)
9   Sophos (XG Fw/UTM) 10   Squid Proxy        11   F5 (BIG-IP)       12   Aruba/HPE
13  Check Point        14   Carbon Black       15   SentinelOne      16   CrowdStrike
17  macOS              18   Linux              19  Windows           20   Microsoft IIS
21  SQL Server         22   Defender           23  Rapid SCADA       24  Auth Varios
25  Todos
------------------------------------------------------------------------------------------------------------------------
Ingrese opción/opciones y después ENTER (o 'q' para salir): 25
Seleccionando todas las tecnologías.

Total de plantillas cargadas y listas para usar: 1402
Introduce la IP del servidor Syslog (ej: 127.0.0.1): 192.168.88.128
¿Cuántos logs deseas enviar? (ej: 1000): 1000
Intervalo entre logs (segundos, ej: 0.001): 0.001
```

Puedes detener el envío en cualquier momento con `Ctrl+C`.

---

## 🛠️ Estructura del proyecto

- `config.py`: Contiene los nombres de los archivos de logs (`LOG_FILES`).
- `data_generators.py`: Funciones de generación aleatoria de datos (`random_*`).
- `syslog_sender.py`: Clase `SyslogSender` para envío de mensajes.
- `utils.py`: Funciones de utilidad (`mostrar_progreso`, `validar_plantilla`, `cargar_plantillas`).
- `app_logger.py`: Sistema interno de logging de SimLog.
- `main.py`: Punto de entrada principal.

**Importante:**  
- Crea una carpeta `logs/` y coloca ahí los archivos de plantillas correspondientes (por ejemplo: `cisco_logs.txt`, `fortinet_logs.txt`, etc.).
- Los nombres de los archivos deben coincidir con las claves en `LOG_FILES` de `config.py`.

---

## 📝 Tipos de logs soportados (plantillas disponibles)

- Cisco
- Fortinet
- Huawei
- Mikrotik
- Palo Alto
- WatchGuard
- SonicWall
- Sophos (X/Central y XG Fw/UTM)
- Squid Proxy
- F5 (BIG-IP LTM/ASM)
- Aruba/HPE
- Check Point
- Carbon Black
- SentinelOne
- CrowdStrike Falcon
- macOS
- Linux
- Windows
- Microsoft IIS
- Microsoft SQL Server
- Microsoft Defender
- Rapid SCADA
- Auth Varios
- **Todos**

---

## 🛡️ Manejo de errores

- SimLog posee un archivo interno de log (`simulator_activity.log`) que registra la actividad y los errores que puedan surgir durante la ejecución.

---

## 📈 Próximas mejoras

- Implementación de envío multihilo.
- Incorporación de logo al inicio del programa.
- Creación de un archivo de configuración para automatizar envíos.
- Mejoras en el manejo y reporte de errores.

---

## 📄 Licencia

🚲 Este proyecto actualmente con una licencia no oficial de "El ciclista sin licencia".

---

_**README generado el domingo, 28 de abril de 2025.**_
```