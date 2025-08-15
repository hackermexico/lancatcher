⚡ Lancatcher ⚡

Descripción:
Lancatcher es una herramienta de hacking ético en Go diseñada para explorar redes locales y remotas. Permite descubrir dispositivos activos, escanear puertos abiertos y analizar servicios corriendo en hosts objetivo, todo desde una interfaz de terminal sencilla pero poderosa. Ideal para pentesters, hackers éticos y entusiastas de la seguridad.

🛠 Características principales

Detección de dispositivos en red local
Encuentra hosts activos y obtiene sus direcciones MAC, identificando puertos abiertos.

Escaneo de puertos TCP
Escanea un puerto específico o rangos completos con resultados rápidos.

Análisis de servicios
Identifica servicios comunes como FTP, SSH, HTTP, HTTPS, SMB, MySQL, SMTP, POP3, IMAP y más.

Interfaz tipo menú
Navegación simple con opciones:

Escanear dispositivos

Escanear puertos

Analizar servicios

Salir

Compatibilidad multi-sistema
Funciona en Linux, macOS y Windows, adaptando comandos de pantalla y ping.

Paralelización inteligente
Escanea múltiples hosts y puertos simultáneamente usando goroutines para máxima velocidad.

⚡ Uso

Compilar Lancatcher

go build -o lancatcherlite lancatcherlite.go


Ejecutar

./lancatcherlite


Seleccionar opción en el menú

Escaneo de dispositivos: descubre todos los dispositivos activos en tu red local.

Escaneo de puertos: escanea un puerto específico o un rango en un host.

Análisis de servicios: detecta qué servicios corren en los puertos abiertos de un host.

🌐 Ejemplos

Escanear red local:
Detecta todos los dispositivos conectados mostrando IP, MAC y puertos abiertos.

Escanear puertos específicos:

IP: 192.168.1.50
Puertos: 22-80


Analizar servicios:
Muestra servicios corriendo en los puertos abiertos y genera un resumen rápido.

🚨 Requisitos

Go 1.18+

Permisos de administrador para escaneos avanzados

Conexión a la red local

💡 Notas de seguridad

Herramienta solo para pruebas en entornos controlados.

Nunca usar Lancatcher para atacar redes sin autorización.

La detección de MAC puede variar según permisos y configuración de red.
