# Descripción del Proyecto

Este proyecto es una herramienta de monitoreo de red y seguridad que captura y analiza el tráfico de red en tiempo real. Utiliza `scapy` para la captura de paquetes y `OpenCV` para tomar fotos con la cámara del dispositivo en caso de detectar actividad sospechosa. Además, envía alertas por correo electrónico cuando se detecta acceso no autorizado a sitios web específicos.

## Características

- **Captura de Tráfico de Red**: Utiliza `scapy` para capturar y analizar paquetes de red.
- **Detección de Actividad Sospechosa**: Identifica accesos no autorizados a sitios web y analiza el contenido de los paquetes.
- **Alertas por Correo Electrónico**: Envía alertas por correo electrónico cuando se detecta actividad sospechosa.
- **Captura de Imágenes**: Utiliza `OpenCV` para tomar fotos con la cámara del dispositivo en caso de detectar actividad sospechosa.
- **Configuración Flexible**: Permite configurar los parámetros de correo electrónico y los sitios web no autorizados a través de variables de entorno.

## Requisitos

- Python 3.x
- scapy
- OpenCV
- smtplib

## Instalación

1. Clona el repositorio:
   ```sh
   git clone https://github.com/tu_usuario/tu_repositorio.git
   cd tu_repositorio
   ``` 

   Instala las dependencias:
```sh
pip install -r requirements.txt
```


Configura las variables de entorno para el correo electrónico:
export EMAIL_FROM="tu_email@example.com"
export EMAIL_PASSWORD="tu_contraseña"
export EMAIL_TO="destinatario@example.com"

Uso
Ejecuta el script principal:
```sh
python monitor.py
```

El script comenzará a capturar el tráfico de red y a monitorear la actividad sospechosa. Si se detecta actividad sospechosa, se enviará una alerta por correo electrónico y se tomará una foto con la cámara del dispositivo.

Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un issue o envía un pull request para discutir cualquier cambio que te gustaría realizar.
