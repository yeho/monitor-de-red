import scapy.all as scapy
import cv2
import smtplib
from email.mime.text import MIMEText
from scapy.layers import http
import time
from dotenv import load_dotenv
import os

# Lista de sitios no autorizados
load_dotenv()

unauthorized_sites = os.getenv("UNAUTHORIZED_SITES").split(",")

def capture_traffic():
    scapy.sniff(iface="en0", prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("HTTP request detected")
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"URL: {url}")
        if any(site in url for site in unauthorized_sites):
            log_event("Unauthorized access detected", url)
          #  send_alert(url)
            take_photo()
    # Inspección de contenido
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
      #  url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
       # print(f"2URL: {url}")
        analyze_payload(payload)
    

def log_event(event, details):
    with open("log.txt", "a") as log_file:
        log_file.write("\n\n")
        print(f"jeje {event}")
        log_file.write(f"{event}: {details}\n")

def send_alert(url):
    msg = MIMEText(f"Unauthorized access detected: {url}")
    msg['Subject'] = os.getenv("EMAIL_SUBJECT")
    msg['From'] = os.getenv("EMAIL_FROM")
    msg['To'] = os.getenv("EMAIL_TO")
    print("Sending email alert...")

    with smtplib.SMTP('smtp.example.com') as server:
        server.login(os.getenv("EMAIL_FROM"), os.getenv("EMAIL_PASSWORD"))
        server.sendmail(os.getenv("EMAIL_FROM"), os.getenv("EMAIL_TO"), msg.as_string())

def take_photo():
    cap = cv2.VideoCapture(0)
    
    # Dar tiempo a la cámara para ajustarse
    time.sleep(2)
    
    # Intentar capturar varias veces para asegurar el enfoque
    for _ in range(5):
        ret, frame = cap.read()
        if ret:
            timestamp = int(time.time())
            photo_filename = f"alert_photo_{timestamp}.jpg"
            cv2.imwrite(photo_filename, frame)
            print(f"Photo taken: {photo_filename}")
        else:
            print("Error: Could not capture image.")
        time.sleep(0.5)  # Esperar un poco entre capturas
    
    cap.release()
    cv2.destroyAllWindows()

def check_camera():
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Error: Could not open video device.")
        return False
    
    ret, frame = cap.read()
    cap.release()
    cv2.destroyAllWindows()
    
    if ret:
        print("Camera is working.")
        return True
    else:
        print("Error: Could not capture image.")
        return False

def analyze_payload(payload):
    # Detectar archivos .exe en el payload
    if payload[:2] == b"MZ":
        print("Executable file detected in payload")
        log_event("Executable file detected", payload)
    
    # Detectar imágenes en el payload
    if payload[:2] == b'\xFF\xD8' and payload[-2:] == b'\xFF\xD9':
        print("JPEG image detected in payload")
        log_event("JPEG image detected", payload)
    elif payload[:8] == b'\x89PNG\r\n\x1A\n':
        print("PNG image detected in payload")
        log_event("PNG image detected", payload)
    elif payload[:6] == b'GIF89a' or payload[:6] == b'GIF87a':
        print("GIF image detected in payload")
        log_event("GIF image detected", payload)
     # Detectar patrones maliciosos conocidos
    malicious_patterns = [b"malicious_pattern1", b"malicious_pattern2"]
    for pattern in malicious_patterns:
        if pattern in payload:
            print(f"Malicious pattern detected: {pattern}")
            log_event(f"Malicious pattern detected: {pattern}", payload)
    
    # Análisis de contenido sensible
    sensitive_keywords = [b"password", b"credit card"]
    for keyword in sensitive_keywords:
        if keyword in payload:
            print(f"Sensitive content detected: {keyword}")
            log_event(f"Sensitive content detected: {keyword}", payload)
    
    # Desempaquetado y decodificación (ejemplo simple)
    try:
        decompressed_payload = zlib.decompress(payload)
        print("Decompressed payload detected")
        log_event("Decompressed payload detected", decompressed_payload)
    except:
        pass  # No se pudo descomprimir el payload

    # Análisis de protocolos (ejemplo simple)
    if b"HTTP" in payload[:4]:
        print("HTTP protocol detected in payload")
        log_event("HTTP protocol detected", payload)
    elif b"FTP" in payload[:3]:
        print("FTP protocol detected in payload")
        log_event("FTP protocol detected", payload)

if __name__ == "__main__":
    if check_camera():
        capture_traffic()
    else:
        print("Exiting due to camera error.")