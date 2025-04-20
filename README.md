¡Claro! Aquí tienes una propuesta de README para tu proyecto `SimLog`, usando Markdown para que se vea bien en GitHub. He intentado mantener un tono descriptivo y útil, incorporando la información que me diste.

```markdown
# 🪵 SimLog: Generador de Logs Syslog Simulados

Una herramienta simple en Python para generar y enviar logs simulados vía Syslog. Ideal para realizar pruebas de carga (EPS - Eventos Por Segundo) en sistemas de recolección de logs como Wazuh, QRadar, Splunk, ELK Stack, etc., o simplemente para poblar tu SIEM de laboratorio con datos de ejemplo.

## 🤔 ¿Por qué SimLog?

* **Pruebas de Carga:** ¿Necesitas saber cuántos EPS realmente soporta tu infraestructura de logs antes de ponerla en producción o tras un cambio? SimLog te permite enviar un volumen controlado de eventos.
* **Entornos de Laboratorio:** Montar infraestructura real (Firewalls, Servidores Windows/Linux, Routers) solo para generar logs puede ser costoso y complejo. SimLog te permite tener datos de diversas fuentes para:
    * Practicar la visualización y análisis de logs.
    * Desarrollar y probar reglas de correlación, dashboards y alertas en tu SIEM.
    * Realizar demostraciones o formaciones.

## ✨ Características

* Genera logs simulados para múltiples tecnologías (ver lista abajo).
* Envía logs vía Syslog (UDP) a un destino configurable (IP/Hostname).
* Permite seleccionar qué tipo(s) de logs enviar o enviarlos todos.
* Número de logs a enviar configurable.
* Intervalo de envío entre logs configurable (soporta valores decimales para tasas < 1 segundo).
* Fácil de usar a través de una interfaz interactiva en línea de comandos.
* Escrito en Python, fácil de modificar y extender.

## ⚠️ Estado Actual: Alpha

Este proyecto se encuentra en fase **Alpha**. Las plantillas de logs incluidas son **básicas** y buscan simular la apariencia general de los eventos, pero pueden no representar todos los tipos de logs o formatos específicos de cada vendor/OS. ¡El objetivo principal ahora es generar volumen y variedad básica!

Se aceptan y agradecen sugerencias, mejoras en las plantillas y contribuciones en general.

## 📋 Requisitos

* Python 3.x
* Conectividad de red desde donde ejecutes el script hacia el servidor Syslog destino (normalmente sobre el puerto UDP 514).

## 🚀 Instalación

No requiere instalación compleja. Simplemente clona el repositorio:

```bash
[git clone](https://github.com/athomo001/simlog/blob/main/simlog.py)  # 
cd TU_REPOSITORIO
```

## ⚙️ Uso

Ejecuta el script directamente con Python:

```bash
python ./simlog.py
```

O dale permisos de ejecución:

```bash
chmod +x simlog.py
./simlog.py
```

El script te guiará interactivamente para configurar el envío:

```
Introduce la IP del servidor Syslog (Wazuh, QRadar, etc.): 192.168.1.100  # IP de tu recolector
Selecciona qué plantillas de logs deseas utilizar:
1. Fortinet
2. Cisco
3. Windows
4. Palo Alto
5. Linux
6. MikroTik
7. Huawei
8. Todas las anteriores
Introduce el número de tu elección: 8  # Elige una o todas
¿Cuántos logs deseas enviar?: 10000  # Cantidad total de logs
Intervalo entre logs (segundos, defecto 1): 0.1  # Tiempo entre cada log (0.1 = 10 EPS aprox.)
```

El script comenzará a enviar los logs seleccionados al destino indicado. Puedes detenerlo con `Ctrl+C`.

## 📜 Tipos de Logs Soportados (Plantillas Alpha)

* Fortinet (Eventos básicos de Firewall/Tráfico)
* Cisco (Eventos básicos de IOS/ASA - logins, config)
* Windows (Eventos básicos de Seguridad Simulados - login success/failure)
* Palo Alto (Eventos básicos de Firewall/Tráfico)
* Linux (Eventos básicos de Syslog - auth, cron, genéricos)
* MikroTik (Eventos básicos de RouterOS - login, system)
* Huawei (Eventos básicos de dispositivos de Red - VRP)

*(Recuerda: Las plantillas son simplificadas en esta fase)*

## 🤝 Contribuciones

¡Las contribuciones son muy bienvenidas! Si deseas:

* Mejorar las plantillas de logs existentes para hacerlas más realistas o variadas.
* Añadir soporte para nuevas tecnologías o vendors.
* Corregir bugs o mejorar la eficiencia del código.

Por favor, siéntete libre de abrir un *Issue* para discutir cambios o un *Pull Request* con tus mejoras.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Puedes ver los detalles en el archivo `LICENSE` (***Nota:** Asegúrate de añadir un archivo LICENSE a tu repositorio, por ejemplo, [eligiendo la licencia MIT al crearlo o añadiéndolo manualmente](https://choosealicense.com/licenses/mit/)*).

---
*README generado el domingo, 20 de abril de 2025.*
```
