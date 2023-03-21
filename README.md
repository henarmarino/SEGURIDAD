# SEGURIDAD
En esta práctica se desarrolla una sencilla aplicación segura en red sobre protocolo SSL/TLS. La
aplicación se desarrolla usando el paquete Java JSSE para el protocolo SSL y las APIs criptográficas,
JCA y JCE. La práctica permitirá:
.Introducirse al uso de una librería criptográfica moderna (Java JCA/JCE).
.Profundizar en la funcionalidad, prestaciones, utilización y problemática del protocolo TLS y
en su implementación en el paquete Java JSSE.
.Adquirir familiaridad con una herramienta de gestión de claves y certificados (KeyExplorer ).
.Aprender a manejar certificados usando una clase Java.
.Utilización del paquete OpenSSL para crear autoridades de certificación y gestionar la revocación de certificados OCSP.
.Formarse en el desarrollo de productos de ingeniería.

Se desarrolló una aplicación cliente-servidor para registrar documentos de forma segura. En ella, el cliente puede registrar y revocar documentos. Se ha usado la tecnica OCSP, en el proceso del Handshake TLS, para verificar que el certificado del servidor no está revocado. Se implementaron las dos tecnicas OCSP:
1. La opcion de verificación por el cliente, denominada usualmente Client-driven OCSP
2. La opcion de verificación por el servidor, tambien llamada OCSP Stapling.
