import unittest
from unittest.mock import patch, MagicMock
import scapy.all as scapy
from scapy.layers import http

# Importar las funciones del archivo monitor.py
from monitor import capture_traffic, process_packet, log_event, send_alert, take_photo

class TestTrafficCapture(unittest.TestCase):

    @patch('monitor.log_event')
    @patch('monitor.send_alert')
    @patch('monitor.take_photo')
    def test_process_packet(self, mock_take_photo, mock_send_alert, mock_log_event):
        # Crear un paquete HTTP de prueba
        packet = MagicMock()
        packet.haslayer.return_value = True
        packet[http.HTTPRequest].Host.decode.return_value = "example.com"
        packet[http.HTTPRequest].Path.decode.return_value = "/test"

        # Llamar a la función process_packet con el paquete de prueba
        process_packet(packet)

        # Verificar que las funciones se llamaron correctamente
        mock_log_event.assert_called_once_with("example.com/test")
        mock_send_alert.assert_called_once_with("example.com/test")
        mock_take_photo.assert_called_once()

    @patch('scapy.all.sniff')
    def test_capture_traffic(self, mock_sniff):
        # Llamar a la función capture_traffic
        capture_traffic()

        # Verificar que scapy.sniff se llamó con los argumentos correctos
        mock_sniff.assert_called_once_with(iface="en0", prn=process_packet, store=False)

if __name__ == '__main__':
    unittest.main()

    