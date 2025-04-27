# syslog_sender.py (CORREGIDO)

"""
Módulo que define la clase SyslogSender para enviar mensajes Syslog
a un servidor remoto vía UDP o TCP.
"""

import socket
import app_logger # Importar para registrar errores de conexión

class SyslogSender:
    """
    Clase para enviar mensajes Syslog a un servidor.
    Soporta protocolos UDP y TCP.
    """
    def __init__(self, server, port, protocol='UDP'):
        """
        Inicializa el sender.
        [...]
        """
        self.server = server
        self.port = port
        self.protocol = protocol.upper()
        self.sock = None
        target_info = f"{server}:{port} ({self.protocol})" # Para logging

        if self.protocol == 'TCP':
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.sock.connect((server, port))
            except socket.error as e:
                # Registrar el error de conexión usando app_logger
                app_logger.log_connection_error(target_info, e)
                # Propaga el error para que sea manejado en el punto de llamada (main.py)
                raise ConnectionError(f"Fallo al conectar a {target_info}") from e
        elif self.protocol == 'UDP':
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
             raise ValueError(f"Protocolo no soportado: {protocol}. Usar 'UDP' o 'TCP'.")

    def send(self, message):
        """
        Envía un mensaje al servidor Syslog.

        Args:
            message (str): El mensaje de log a enviar.

        Returns:
            bool: True si el envío se realizó sin errores de socket inmediatos, False en caso contrario.
                  Nota: UDP no garantiza entrega, así que True solo significa que sendto() no lanzó excepción.
        """
        if not self.sock:
             # Registrar este error interno
             app_logger.log_error("Intento de enviar con socket no inicializado o cerrado.")
             return False

        try:
            encoded_message = message.encode('utf-8', errors='replace')

            if self.protocol == 'TCP':
                self.sock.sendall(encoded_message + b'\n')
            else: # UDP
                self.sock.sendto(encoded_message, (self.server, self.port))
            return True # Envío realizado sin error de socket

        except socket.error as e:
            # Ya no imprimimos aquí, solo devolvemos False para que main.py lo registre.
            # Guardamos el error para posible inspección si fuera necesario.
            self.last_error = e
            return False
        except Exception as e:
            # Captura otros errores inesperados durante el envío
            app_logger.log_error(f"Error inesperado durante SyslogSender.send: {e}")
            self.last_error = e
            return False

    def close(self):
        """
        Cierra el socket de conexión.
        """
        if self.sock:
            target_info = f"{self.server}:{self.port} ({self.protocol})"
            try:
                self.sock.close()
                # Registrar cierre exitoso (opcional, nivel INFO o DEBUG)
                app_logger.log_info(f"Socket a {target_info} cerrado.")
            except socket.error as e:
                 # Registrar error al cerrar
                 app_logger.log_error(f"Error al cerrar socket a {target_info}: {e}")
            finally:
                 self.sock = None
        # else:
             # Podríamos registrar un intento de cerrar un socket ya cerrado si fuera útil (nivel DEBUG)
             # app_logger.log_debug("Intento de cerrar un socket que ya estaba cerrado o no inicializado.")