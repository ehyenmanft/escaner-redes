# Escáner de redes

App de escritorio para Windows que detecta los dispositivos conectados a tu red local (cable y Wi-Fi).
Python 3 + tkinter, sin dependencias.

## Uso

Doble clic en `Escaner.bat`, o:

```
python escaner_red.py          # abre la app
python escaner_red.py --scan   # escaneo por consola
python escaner_red.py --test   # pruebas rápidas
```

## Funciones

- **Panel**: conexiones, alertas, tráfico en vivo, IP pública (api.ipify.org), firewall, Wi-Fi y acceso a la LAN.
- **Dispositivos LAN**: escaneo por ping (API de Windows, dos pasadas) + tabla ARP, que encuentra también equipos que
  bloquean el ping. Empieza solo al abrir la app; `F5` repite. En redes mayores que /22 recorre el bloque de tu IP.
  Marca **NUEVOS** y desconectados, con alias (doble clic), fabricante (api.macvendors.com), puertos, CSV y vigilancia
  cada 5 minutos. Avisa si una VPN o un cortafuegos bloquea la red local.
- **Conexiones**: TCP/UDP con proceso, firma digital, host y servicio, clasificadas como Segura, Revisar, Peligrosa o
  Desconocida con su motivo. Permite cortar la conexión, terminar el proceso, bloquear la IP o el programa y marcarlos
  como de confianza o peligrosos.
- **Adaptadores**: habilitar, deshabilitar, DNS (Cloudflare, Google, Quad9, AdGuard o automático), IP automática o fija.
- **Wi-Fi**: redes con su seguridad, conectar, desconectar y olvidar perfiles.
- **Firewall**: activar perfiles, protección rápida (entradas a SMB, RDP, NetBIOS, Telnet y VNC) y reglas creadas aquí.
- **Pruebas de red**: diagnóstico, velocidad (speed.cloudflare.com), ping, traceroute, comparar DNS y probar puertos.
- **Métricas**: ancho de banda por interfaz, picos, datos de la sesión e historial de conexiones.
- **Herramientas**: vaciar DNS, renovar IP, restablecer proxy, Winsock y TCP/IP, desactivar SMBv1, listas y bloqueo automático.
- **Registro**: historial de acciones en `registro.log`.

## Bandeja y widget

Al cerrar la ventana sigue en la bandeja del sistema, junto al reloj: clic en el icono para abrirla, clic derecho para
escanear, mostrar u ocultar el widget y salir. Solo puede haber una abierta a la vez. Necesita Tk 9 (incluido en
Python 3.14); con versiones anteriores funciona sin bandeja. Los dispositivos nuevos y otros avisos llegan como
notificación de Windows.

El widget flotante muestra bajada, subida, conexiones y alertas siempre encima de las ventanas. Se arrastra para moverlo
y recuerda su posición.

Cambiar la configuración del sistema necesita permisos: pulsa «elevar» abajo a la izquierda. La clasificación de riesgo
es una ayuda heurística y no sustituye a un antivirus. Solo se pueden cortar conexiones TCP IPv4.
Interfaz glass, igual que Antimalware y Optimizador PC.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
