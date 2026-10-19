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

- Escaneo por ping + tabla ARP (encuentra también equipos que bloquean el ping)
- Tipo probable: router, este PC, inalámbrico (MAC aleatoria)
- Historial en `dispositivos.json`: marca dispositivos **NUEVOS** y desconectados
- Alias por dispositivo, fabricante por MAC (api.macvendors.com), puertos comunes
- Abrir la web del dispositivo, exportar a CSV, vigilancia cada 5 minutos con aviso
