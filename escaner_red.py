"""Escáner y control de red para Windows (Python + tkinter, sin dependencias).

Dispositivos de la LAN, conexiones con nivel de riesgo, adaptadores, Wi-Fi, firewall, pruebas de red,
métricas y herramientas. Cambiar la configuración del sistema requiere abrirla como administrador.

Uso:
  python escaner_red.py          abre la app
  python escaner_red.py --scan   escanea y muestra el resultado en consola
  python escaner_red.py --test   pruebas rápidas
"""
import csv
import ctypes
import ipaddress
import itertools
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW: que powershell/arp no abran consolas
DB_FILE = Path(__file__).with_name("dispositivos.json")
CONFIG_FILE = Path(__file__).with_name("red.json")  # listas de confianza y bloqueo
LOG_FILE = Path(__file__).with_name("registro.log")
RULE_GROUP = "EscanerRed"  # todas las reglas de firewall creadas aquí, para poder listarlas y quitarlas
MAC_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", re.I)
PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 139: "NetBIOS",
         443: "HTTPS", 445: "SMB", 554: "RTSP (cámara)", 1883: "MQTT", 3389: "Escritorio remoto",
         5000: "UPnP/NAS", 8008: "Chromecast", 8080: "HTTP alt", 8443: "HTTPS alt", 9100: "Impresora",
         62078: "iPhone/iPad"}
MIN_PREFIX = 22  # como mucho se recorren 1022 equipos alrededor de esta IP
IP_GENERAL_FAILURE = 11050  # Windows rechaza el ping sin enviarlo: lo hace una VPN o un cortafuegos
IFACES_PS = ("Get-NetRoute -DestinationPrefix 0.0.0.0/0 | ? NextHop -ne '0.0.0.0' | % { "
             "$a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex; "
             "$i = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 | ? AddressState -eq 'Preferred' | select -First 1; "
             "[pscustomobject]@{alias=$a.Name; ip=$i.IPAddress; prefix=$i.PrefixLength; gw=$_.NextHop; "
             "mac=$a.MacAddress; medio=$a.PhysicalMediaType} } | ConvertTo-Json")

iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
iphlpapi.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint16, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]


def execute(cmd, timeout=30, **env):
    env = {**os.environ, **env}
    env.pop("PSMODULEPATH", None)  # si se abrió desde PowerShell 7, sus módulos rompen los del powershell.exe clásico
    return subprocess.run(cmd, capture_output=True, text=True, encoding="oem", errors="replace", creationflags=NO_WINDOW,
                          timeout=timeout, env=env)


def run(cmd, timeout=30):
    try:
        return execute(cmd, timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


def run_ps(script, **env):
    """Salida de una consulta de PowerShell. Los datos variables van por entorno, nunca dentro del script."""
    try:
        return execute(["powershell", "-NoProfile", "-Command", script], **env).stdout
    except subprocess.TimeoutExpired:
        return ""


def ps_json(script, **env):
    try:
        data = json.loads(run_ps(script + " | ConvertTo-Json -Compress", **env) or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else [data]


def change(cmd, timeout=60, **env):
    """Ejecuta un cambio del sistema; si falla lanza el mensaje de Windows."""
    r = execute(cmd, timeout, **env)
    if r.returncode:
        raise RuntimeError((r.stderr or r.stdout).strip()[:300] or f"código {r.returncode}")
    return r.stdout.strip()


def change_ps(script, **env):
    return change(["powershell", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; " + script], **env)


def is_admin():
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def interfaces():
    """Interfaces con puerta de enlace: alias, ip, prefijo, gateway, mac y tipo (Wi-Fi/Ethernet)."""
    try:
        data = json.loads(run(["powershell", "-NoProfile", "-Command", IFACES_PS]) or "[]")
    except ValueError:
        return []
    data = data if isinstance(data, list) else [data]
    # sin IP o de una sola dirección no son una LAN que escanear; una interfaz puede tener varias rutas
    return list({d["ip"]: d for d in data if d["ip"] and d["prefix"] < 32}.values())


def iface_label(i):
    return f"{i['alias']} – {i['ip']}/{i['prefix']}"


def local_ips():
    try:
        return socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        return []


def icmp(ip, timeout=600):
    """Resultado de un ping por la API de Windows: 0 si responde, si no el código de error.
    Sin lanzar ping.exe un barrido entero cuesta lo que tarda el timeout."""
    handle = iphlpapi.IcmpCreateFile()
    reply = ctypes.create_string_buffer(128)
    try:
        if iphlpapi.IcmpSendEcho(handle, int.from_bytes(socket.inet_aton(ip), "little"), b"x", 1, None, reply, 128, timeout):
            return int.from_bytes(reply.raw[4:8], "little")  # ICMP_ECHO_REPLY.Status
        return ctypes.get_last_error()
    finally:
        iphlpapi.IcmpCloseHandle(handle)


def ping(ip):
    return icmp(ip) == 0


def lan_blocked(iface):
    return icmp(iface["gw"]) == IP_GENERAL_FAILURE


def parse_arp(text, net):
    """Devuelve {ip: mac} de la salida de `arp -a`, solo de la red dada y sin broadcast/multicast."""
    found = {}
    for ip, mac in MAC_RE.findall(text):
        mac = mac.upper()
        if ipaddress.ip_address(ip) in net and ip != str(net.broadcast_address) \
                and mac not in ("FF-FF-FF-FF-FF-FF", "00-00-00-00-00-00") and not mac.startswith("01-00-5E"):
            found[ip] = mac
    return found


def is_random_mac(mac):
    # bit "administrado localmente": lo usan iPhone/Android/Windows al conectarse por Wi-Fi
    return bool(mac) and mac[1].upper() in "26AE"


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def hostnames(ips, timeout=3):
    """{ip: nombre} de lo que resuelva a tiempo: gethostbyaddr no admite timeout y con una VPN tarda 15 s."""
    names, deadline = {}, time.time() + timeout
    threads = [threading.Thread(target=lambda ip=ip: names.update({ip: hostname(ip)}), daemon=True) for ip in ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(0, deadline - time.time()))
    return dict(names)


def guess_type(ip, mac, iface):
    if ip == iface["gw"]:
        return "Router"
    if ip == iface["ip"]:
        medio = "Wi-Fi" if "802.11" in (iface["medio"] or "") else "cable" if iface["medio"] == "802.3" else iface["alias"]
        return f"Este PC ({medio})"
    if is_random_mac(mac):
        return "Inalámbrico (probable: móvil/tablet)"
    return "Desconocido"


def scan_net(iface):
    """Red a recorrer. En redes mayores que /22 solo el bloque de esta IP."""
    return ipaddress.ip_network(f"{iface['ip']}/{max(iface['prefix'], MIN_PREFIX)}", strict=False)


def scan(iface, progress=lambda done, total: None):
    net = scan_net(iface)
    hosts = [str(h) for h in net.hosts()]
    alive = set()
    with ThreadPoolExecutor(256) as pool:
        for _ in range(2):  # la segunda pasada recoge móviles dormidos, que tardan en contestar
            todo = [h for h in hosts if h not in alive]
            for done, (ip, ok) in enumerate(zip(todo, pool.map(ping, todo)), 1):
                if ok:
                    alive.add(ip)
                if done % 16 == 0:
                    progress(done, len(todo))
    # shortcut: un equipo recién desconectado puede seguir en la caché ARP unos segundos; sale en el siguiente escaneo
    arp = parse_arp(run(["arp", "-a"]), net)  # dispositivos que bloquean ping pero sí responden ARP
    arp[iface["ip"]] = (iface["mac"] or "").upper()
    ips = sorted(alive | set(arp), key=ipaddress.ip_address)
    names = hostnames(ips)
    return [{"ip": ip, "mac": arp.get(ip, ""), "ping": ip in alive, "nombre": names.get(ip, ""),
             "tipo": guess_type(ip, arp.get(ip, ""), iface)} for ip in ips]


def merge(db, res, net, now):
    """Une un escaneo con el historial. Devuelve los conectados y los conocidos de esa red que ya no responden."""
    rows, seen = [], set()
    for r in res:
        key = r["mac"] or r["ip"]
        seen.add(key)
        nuevo = key not in db
        d = db.setdefault(key, {"alias": "", "fabricante": "", "visto": now})
        d.update(ultimo=now, ip=r["ip"], nombre=r["nombre"] or d.get("nombre", ""))
        rows.append({**r, **d, "key": key, "online": True, "nuevo": nuevo})
    for key, d in db.items():
        if key not in seen and d.get("ip") and ipaddress.ip_address(d["ip"]) in net:
            rows.append({"nombre": "", **d, "key": key, "mac": key if "-" in key else "", "ping": False,
                         "tipo": "Desconectado", "online": False, "nuevo": False})
    return rows


def scan_ports(ip):
    def check(port):
        with socket.socket() as s:
            s.settimeout(0.6)
            return port if s.connect_ex((ip, port)) == 0 else None
    with ThreadPoolExecutor(len(PORTS)) as pool:
        return [p for p in pool.map(check, PORTS) if p]


def port_text(ports):
    return ", ".join(f"{p} {PORTS.get(p, '')}".strip() for p in ports or [])


def web_url(ip, ports):
    for port, url in ((80, f"http://{ip}"), (443, f"https://{ip}"), (8080, f"http://{ip}:8080"), (8443, f"https://{ip}:8443")):
        if port in (ports or []):
            return url
    return f"http://{ip}"


def vendor(mac):
    """Fabricante por MAC (envía solo los 3 primeros bytes a api.macvendors.com). "?" si no existe, "" si falló la consulta."""
    try:
        with urllib.request.urlopen(f"https://api.macvendors.com/{mac[:8]}", timeout=5) as r:
            return r.read().decode("utf-8", "replace")[:80]
    except urllib.error.HTTPError as e:
        return "?" if e.code == 404 else ""
    except OSError:
        return ""


def csv_safe(value):
    # los nombres llegan de la red: que Excel no ejecute uno que empiece como fórmula
    return "'" + value if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return {}
    except ValueError:  # dañado: se aparta para no sobrescribir el historial
        path.replace(path.with_suffix(".dañado.json"))
        return {}


def save_json(path, data):
    tmp = path.with_suffix(".tmp")  # un corte a medio guardar no debe perder el historial
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def load_db():
    return load_json(DB_FILE)


def save_db(db):
    save_json(DB_FILE, db)


def log_line(text):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {text}\n")


# ---------------------------------------------------------------- conexiones y riesgo
NETSTAT_RE = re.compile(r"^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(?:([A-Z_0-9]+)\s+)?(\d+)\s*$", re.M)
MALWARE_PORTS = {1337, 4444, 5555, 6666, 6667, 9001, 9030, 9050, 12345, 27374, 31337}
PLAIN_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP"}
EXPOSED_PORTS = {135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC"}
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "spoolsv.exe"}
SERVICES = {**PORTS, 25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
            123: "NTP", 3306: "MySQL", 5353: "mDNS", 5900: "VNC", 51820: "WireGuard"}


def split_addr(addr):
    """("1.2.3.4", 80) de "1.2.3.4:80" o "[::1]:80"; ("", 0) si es *:*."""
    host, _, port = addr.rpartition(":")
    return host.strip("[]").split("%")[0].replace("*", ""), int(port) if port.isdigit() else 0


def parse_netstat(text):
    rows = []
    for proto, local, remote, state, pid in NETSTAT_RE.findall(text):
        lip, lport = split_addr(local)
        rip, rport = split_addr(remote)
        rows.append({"proto": proto, "lip": lip, "lport": lport, "rip": rip if rport else "", "rport": rport,
                     "estado": state, "pid": int(pid)})
    return rows


def processes():
    """{pid: ruta del ejecutable} de los procesos que este usuario puede consultar."""
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    pids, needed = (ctypes.c_ulong * 8192)(), ctypes.c_ulong()
    ctypes.windll.psapi.EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(needed))
    out = {}
    for pid in pids[:needed.value // 4]:
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            continue
        buf, size = ctypes.create_unicode_buffer(1024), ctypes.c_ulong(1024)
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            out[pid] = buf.value
        k32.CloseHandle(h)
    return out


def connections():
    procs = processes()
    rows = parse_netstat(run(["netstat", "-ano"]))
    for c in rows:
        c["ruta"] = procs.get(c["pid"], "")
        c["proceso"] = Path(c["ruta"]).name if c["ruta"] else "System" if c["pid"] == 4 else f"PID {c['pid']}"
        c["id"] = f"{c['proto']}|{c['lip']}:{c['lport']}|{c['rip']}:{c['rport']}|{c['pid']}"
        c["servicio"] = SERVICES.get(c["rport"] or c["lport"], "")
    return list({c["id"]: c for c in rows}.values())  # netstat repite algunos puertos UDP


def signatures(paths):
    """{ruta: estado de la firma digital}: Valid, NotSigned, HashMismatch…"""
    if not paths:
        return {}
    script = ("$env:AM_RUTAS -split '\\|' | % { try { $s = Get-AuthenticodeSignature -LiteralPath $_; "
              "\"$($s.Status)|$_\" } catch { } }")
    return {r: st for st, _, r in (line.partition("|") for line in run_ps(script, AM_RUTAS="|".join(paths)).splitlines()) if r}


def classify(c, sig, lists):
    """(Segura | Revisar | Peligrosa | Desconocida, motivo). Tus listas mandan sobre los indicadores."""
    keys = {c["rip"], c["ruta"].lower(), c["proceso"].lower()} - {""}
    if keys & set(lists.get("bloqueo", [])):
        return "Peligrosa", "Está en tu lista de bloqueo"
    if keys & set(lists.get("confianza", [])):
        return "Segura", "Está en tu lista de confianza"
    score, why = 0, []
    ruta = c["ruta"].lower()
    system = os.environ.get("SYSTEMROOT", r"C:\Windows").lower()
    if sig == "NotSigned":
        score, why = score + 1, why + ["sin firma digital"]
    elif sig and sig != "Valid":
        score, why = score + 3, why + [f"firma no válida ({sig})"]
    if any(d in ruta for d in ("\\temp\\", "\\downloads\\")):
        score, why = score + 2, why + ["ejecutado desde Temp o Descargas"]
    if c["proceso"].lower() in SYSTEM_NAMES and ruta and not ruta.startswith(system):
        score, why = score + 3, why + ["nombre del sistema fuera de Windows (suplantación)"]
    remote_lan = c["rip"] and ipaddress.ip_address(c["rip"]).is_loopback
    if c["rport"] in MALWARE_PORTS and not remote_lan:
        score, why = score + 3, why + [f"puerto {c['rport']} típico de malware o Tor"]
    if c["rport"] in PLAIN_PORTS and not remote_lan:
        score, why = score + 1, why + [f"{PLAIN_PORTS[c['rport']]} sin cifrar"]
    if not c["rip"] and c["lport"] in EXPOSED_PORTS and c["lip"] in ("0.0.0.0", "::"):
        score, why = score + 1, why + [f"{EXPOSED_PORTS[c['lport']]} expuesto a la red"]
    if score:
        return ("Peligrosa" if score >= 3 else "Revisar"), "; ".join(why)
    if sig == "Valid":
        return "Segura", "Firmado y sin indicadores"
    return "Desconocida", "No se pudo comprobar la firma" if ruta else "Proceso protegido: se lee abriendo la app como administrador"


def cut_tcp(c):
    """Corta una conexión TCP IPv4 (Windows no permite cortar IPv6 ni UDP)."""
    class Row(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint32) for n in ("state", "laddr", "lport", "raddr", "rport")]
    if c["proto"] != "TCP" or ":" in c["lip"] or not c["rip"]:
        raise RuntimeError("Solo se pueden cortar conexiones TCP IPv4 establecidas: usa bloquear o terminar el proceso.")
    addr = lambda ip: int.from_bytes(socket.inet_aton(ip), "little")
    row = Row(12, addr(c["lip"]), socket.htons(c["lport"]), addr(c["rip"]), socket.htons(c["rport"]))  # 12 = DELETE_TCB
    code = ctypes.windll.iphlpapi.SetTcpEntry(ctypes.byref(row))
    if code:
        raise RuntimeError(f"Windows no permitió cortar la conexión (código {code}).")
    return f"Conexión con {c['rip']} cortada."


def kill_process(pid):
    return change(["taskkill", "/PID", str(pid), "/F"]) or f"Proceso {pid} terminado."


def block_ip(ip):
    ipaddress.ip_address(ip)
    for way in ("Outbound", "Inbound"):
        change_ps(f"New-NetFirewallRule -DisplayName \"EscanerRed bloquea $env:AM_IP\" -Group {RULE_GROUP} -Direction {way} "
                  "-Action Block -RemoteAddress $env:AM_IP | Out-Null", AM_IP=ip)
    return f"{ip} bloqueada en el firewall."


def block_program(path):
    change_ps(f"New-NetFirewallRule -DisplayName \"EscanerRed bloquea $env:AM_RUTA\" -Group {RULE_GROUP} -Direction Outbound "
              "-Action Block -Program $env:AM_RUTA | Out-Null", AM_RUTA=path)
    return f"{Path(path).name} ya no puede salir a la red."


# ---------------------------------------------------------------- adaptadores y Wi-Fi
DNS_PRESETS = {"Cloudflare": ("1.1.1.1", "1.0.0.1"), "Google": ("8.8.8.8", "8.8.4.4"), "Quad9": ("9.9.9.9", "149.112.112.112"),
               "AdGuard": ("94.140.14.14", "94.140.15.15")}
ADAPTERS_PS = ("Get-NetAdapter | % { $i = Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
               "$a = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | select -First 1; "
               "$d = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
               "[pscustomobject]@{nombre=$_.Name; estado=\"$($_.Status)\"; descripcion=$_.InterfaceDescription; velocidad=\"$($_.LinkSpeed)\"; "
               "mac=$_.MacAddress; ip=$a.IPAddress; prefijo=$a.PrefixLength; dhcp=\"$($i.Dhcp)\"; dns=($d.ServerAddresses -join ', ')} }")


def adapters():
    return ps_json(ADAPTERS_PS)


def set_adapter(name, on):
    change_ps(("Enable" if on else "Disable") + "-NetAdapter -Name $env:AM_NOMBRE -Confirm:$false", AM_NOMBRE=name)
    return f"{name} {'habilitado' if on else 'deshabilitado'}."


def set_dns(name, servers):
    if not servers:
        change_ps("Set-DnsClientServerAddress -InterfaceAlias $env:AM_NOMBRE -ResetServerAddresses", AM_NOMBRE=name)
        return f"DNS de {name}: automático."
    for ip in servers:
        ipaddress.ip_address(ip)
    change_ps("Set-DnsClientServerAddress -InterfaceAlias $env:AM_NOMBRE -ServerAddresses ($env:AM_DNS -split ',')",
              AM_NOMBRE=name, AM_DNS=",".join(servers))
    return f"DNS de {name}: {', '.join(servers)}."


def set_dhcp(name):
    change_ps("Set-NetIPInterface -InterfaceAlias $env:AM_NOMBRE -Dhcp Enabled; "
              "Remove-NetRoute -InterfaceAlias $env:AM_NOMBRE -DestinationPrefix 0.0.0.0/0 -Confirm:$false -ErrorAction SilentlyContinue; "
              "Set-DnsClientServerAddress -InterfaceAlias $env:AM_NOMBRE -ResetServerAddresses", AM_NOMBRE=name)
    return f"{name}: IP automática (DHCP)."


def parse_static(text):
    """(ip, prefijo, puerta de enlace) de "192.168.1.50/24 192.168.1.1"; ValueError si no es válido."""
    addr, gw = text.split()
    iface = ipaddress.ip_interface(addr)
    gateway = ipaddress.ip_address(gw)
    if iface.version != 4 or "/" not in addr or gateway not in iface.network or gateway == iface.ip:
        raise ValueError("La puerta de enlace debe estar en la misma red y ser distinta de la IP.")
    return str(iface.ip), iface.network.prefixlen, str(gateway)


def set_static(name, ip, prefix, gw):
    change_ps("Set-NetIPInterface -InterfaceAlias $env:AM_NOMBRE -Dhcp Disabled; "
              "Remove-NetIPAddress -InterfaceAlias $env:AM_NOMBRE -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue; "
              "Remove-NetRoute -InterfaceAlias $env:AM_NOMBRE -DestinationPrefix 0.0.0.0/0 -Confirm:$false -ErrorAction SilentlyContinue; "
              "New-NetIPAddress -InterfaceAlias $env:AM_NOMBRE -IPAddress $env:AM_IP -PrefixLength $env:AM_PREFIJO "
              "-DefaultGateway $env:AM_GW | Out-Null", AM_NOMBRE=name, AM_IP=ip, AM_PREFIJO=str(prefix), AM_GW=gw)
    return f"{name}: IP fija {ip}/{prefix}."


def parse_wifi(text):
    """[{ssid, seguridad, señal}] de `netsh wlan show networks mode=bssid`, en inglés o español."""
    nets = []
    for line in text.splitlines():
        if m := re.match(r"\s*SSID \d+\s*:\s*(.*)", line):
            nets.append({"ssid": m[1].strip() or "(oculta)", "seguridad": "", "señal": 0})
        elif nets and (m := re.match(r"\s*(?:Authentication|Autenticaci.n)\s*:\s*(.*)", line)):
            nets[-1]["seguridad"] = m[1].strip()
        elif nets and (m := re.search(r"(\d+)\s*%", line)):
            nets[-1]["señal"] = max(nets[-1]["señal"], int(m[1]))
    return sorted(nets, key=lambda n: -n["señal"])


def parse_profiles(text):
    return [m.strip() for m in re.findall(r"(?:All User Profile|Perfil de todos los usuarios)\s*:\s*(.*)", text)]


def wifi_risk(security):
    s = security.upper()
    return "bad" if "WEP" in s or "OPEN" in s or "ABIERT" in s else "ok" if "WPA2" in s or "WPA3" in s else "warn"


# ---------------------------------------------------------------- firewall y herramientas
QUICK_PORTS = "135,139,445,3389,23,5900"  # SMB, RDP, NetBIOS, Telnet, VNC
TOOLS = {  # nombre: (comando, necesita administrador, aviso antes de ejecutarlo)
    "Vaciar caché DNS": (["ipconfig", "/flushdns"], False, ""),
    "Renovar IP": (["ipconfig", "/renew"], True, "Se cortará la red unos segundos."),
    "Restablecer proxy": (["netsh", "winhttp", "reset", "proxy"], True, "Se quitará el proxy del sistema."),
    "Restablecer Winsock": (["netsh", "winsock", "reset"], True, "Hay que reiniciar Windows y puede afectar a VPN y antivirus."),
    "Restablecer TCP/IP": (["netsh", "int", "ip", "reset"], True, "Hay que reiniciar Windows y se pierde la configuración de IP fija."),
    "Desactivar SMBv1": (["powershell", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; "
                          "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"], True,
                         "Los equipos muy antiguos dejarán de ver tus carpetas compartidas."),
}


def firewall_profiles():
    return ps_json("Get-NetFirewallProfile | select Name, @{n='on';e={[bool][int]$_.Enabled}}")


def firewall_rules():
    return ps_json(f"Get-NetFirewallRule -Group {RULE_GROUP} -ErrorAction SilentlyContinue | "
                   "select Name, DisplayName, @{n='dir';e={\"$($_.Direction)\"}}, @{n='on';e={\"$($_.Enabled)\"}}")


def firewall_on():
    change_ps("Set-NetFirewallProfile -All -Enabled True")
    return "Firewall activado en todos los perfiles."


def quick_protect():
    change_ps(f"New-NetFirewallRule -DisplayName 'EscanerRed protección rápida' -Group {RULE_GROUP} -Direction Inbound "
              f"-Action Block -Protocol TCP -LocalPort {QUICK_PORTS} | Out-Null")
    return "Entradas bloqueadas: SMB, RDP, NetBIOS, Telnet y VNC."


def remove_rule(name):
    change_ps("Remove-NetFirewallRule -Name $env:AM_REGLA", AM_REGLA=name)
    return "Regla eliminada."


# ---------------------------------------------------------------- pruebas de red
def valid_host(host):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host):
        raise ValueError("Escribe un nombre de equipo o una IP.")
    return host


def dns_query(server, name="example.com", timeout=2):
    """Milisegundos que tarda un servidor DNS en responder a una consulta A; None si no contesta."""
    packet = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        start = time.perf_counter()
        try:
            s.sendto(packet, (server, 53))
            return (time.perf_counter() - start) * 1000 if s.recv(512)[:2] == packet[:2] else None
        except OSError:
            return None


def ping_lines(host, count=4):
    ip = socket.gethostbyname(valid_host(host))
    for _ in range(count):
        start = time.perf_counter()
        code = icmp(ip, 1000)
        yield f"{ip}: {(time.perf_counter() - start) * 1000:.0f} ms" if code == 0 else f"{ip}: sin respuesta (código {code})"


def diagnose(iface):
    """Comprobaciones de la conexión, de la más cercana a la más lejana."""
    yield f"IP de este PC: {iface['ip']}/{iface['prefix']} en {iface['alias']}" if iface else "Sin red con puerta de enlace."
    if iface:
        code = icmp(iface["gw"])
        yield f"Router {iface['gw']}: " + ("responde" if code == 0 else "bloqueado por una VPN o cortafuegos"
                                           if code == IP_GENERAL_FAILURE else "no responde al ping")
    try:
        yield f"DNS: example.com → {socket.gethostbyname('example.com')}"
    except OSError:
        yield "DNS: no resuelve nombres"
    with socket.socket() as s:
        s.settimeout(3)
        yield "Internet: " + ("conectado" if s.connect_ex(("1.1.1.1", 443)) == 0 else "sin salida a 1.1.1.1:443")


def speed_test(progress, size=25_000_000):
    """Mbps de bajada descargando de speed.cloudflare.com."""
    req = urllib.request.Request(f"https://speed.cloudflare.com/__down?bytes={size}", headers={"User-Agent": "escaner-red/1.0"})
    start, got = time.perf_counter(), 0
    with urllib.request.urlopen(req, timeout=20) as r:
        while chunk := r.read(1 << 18):
            got += len(chunk)
            progress(got * 8 / 1e6 / max(time.perf_counter() - start, .001))
    return got * 8 / 1e6 / (time.perf_counter() - start)


def public_ip():
    """IP pública según api.ipify.org (es lo único que ese servicio recibe)."""
    with urllib.request.urlopen("https://api.ipify.org", timeout=6) as r:
        return r.read().decode("ascii", "replace")[:45]


def if_counters():
    """{nombre: (bytes recibidos, bytes enviados)} de GetIfTable: sin lanzar procesos, se puede leer cada segundo."""
    size = ctypes.c_ulong(0)
    ctypes.windll.iphlpapi.GetIfTable(None, ctypes.byref(size), False)
    buf = ctypes.create_string_buffer(size.value)
    if ctypes.windll.iphlpapi.GetIfTable(buf, ctypes.byref(size), False):
        return {}
    out = {}
    for n in range(int.from_bytes(buf.raw[:4], "little")):
        row = buf.raw[4 + n * 860:4 + (n + 1) * 860]  # MIB_IFROW
        field = lambda off: int.from_bytes(row[off:off + 4], "little")
        name = row[604:604 + field(600)].rstrip(b"\0").decode("oem", "replace")
        # 544 = estado, 516 = tipo (24 = loopback); "-0000" y Miniport son capas internas que repiten cada adaptador
        if field(544) == 5 and field(516) != 24 and "-00" not in name and "Miniport" not in name:
            out[name] = field(552), field(576)
    return out


def human_rate(n):
    return f"{n / 1e6:.1f} MB/s" if n >= 1e6 else f"{n / 1e3:.0f} KB/s"


def human_size(n):
    return f"{n / 1e9:.2f} GB" if n >= 1e9 else f"{n / 1e6:.1f} MB"


# ---------------------------------------------------------------- interfaz
FONT = "Segoe UI"
BG, SIDE, CARD, CARD2, LINE = "#07090d", "#090c11", "#131923", "#1e2532", "#3c4554"
TEXT, MUTED, ACCENT, ACCENT_HOVER = "#ffffff", "#b6c0cc", "#76b900", "#8acc14"
HOVER, SELECTED, NAV_ON = "#2b3342", "#2b3d14", "#1e2a12"
GLASS_ALPHA = 0.97  # opacidad de la ventana
# Windows suma el fondo a los colores oscuros: sin esta capa (0xAABBGGRR) un fondo claro se come el texto
GLASS_TINT = 0xF0100B08
TONES = {"ok": ("#22c55e", "#0f2a1c"), "warn": ("#fbbf24", "#33240c"), "bad": ("#f87171", "#3a1620")}
BLOCKED_TEXT = ("Una VPN o un cortafuegos está bloqueando la red local: solo se ven este PC y el router. "
                "Desactívala o permite el acceso a la LAN y vuelve a escanear.")


PAGES = {"panel": ("Panel", "▦"), "dispositivos": ("Dispositivos LAN", "◉"), "conexiones": ("Conexiones", "⇄"),
         "adaptadores": ("Adaptadores", "▤"), "wifi": ("Wi-Fi", "◔"), "firewall": ("Firewall", "▣"),
         "pruebas": ("Pruebas de red", "⌕"), "metricas": ("Métricas", "▥"), "herramientas": ("Herramientas", "⚙"),
         "registro": ("Registro", "☰")}
LEVEL_TONE = {"Peligrosa": "bad", "Revisar": "warn"}
ADMIN_TEXT = "Esta acción necesita permisos de administrador: pulsa «elevar» abajo a la izquierda."


class App:
    COLS = ("estado", "ip", "mac", "alias", "nombre", "fabricante", "tipo", "ping", "puertos", "visto")
    HEAD = ("", "IP", "MAC", "Alias", "Nombre de red", "Fabricante", "Tipo", "Ping", "Puertos", "Primera vez")
    WIDTH = (50, 95, 120, 75, 95, 95, 125, 40, 90, 115)

    def __init__(self, root, mutex=None):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk, self.root, self.mutex = tk, ttk, root, mutex
        self.db, self.rows, self.ifaces, self.q, self.busy = load_db(), [], [], queue.Queue(), False
        self.corner_cache, self.sort_by, self.watch_job = {}, ("estado", False), None
        self.lists = {"confianza": [], "bloqueo": [], "auto": False, "widget": True, **load_json(CONFIG_FILE)}
        self.conns, self.sigs, self.host_cache, self.seen_conns = {}, {}, {}, set()
        self.page, self.loaded, self.polling, self.blocked_ips = None, set(), False, set()
        self.counters, self.rates, self.traffic, self.totals, self.peak = {}, {}, [(0, 0)] * 60, [0, 0], 0
        root.title("Escáner de red")
        root.geometry(f"1240x760+{max(0, (root.winfo_screenwidth() - 1240) // 2)}+{max(0, (root.winfo_screenheight() - 760) // 2)}")
        root.minsize(1060, 640)
        root.configure(bg=BG, highlightthickness=1, highlightbackground=LINE)
        root.iconbitmap(Path(__file__).with_name("escaner.ico"))
        self.glass()
        self.styles()
        self.title_bar()

        status = tk.Frame(root, bg=SIDE)
        status.pack(side="bottom", fill="x")
        tk.Frame(root, bg=LINE, height=1).pack(side="bottom", fill="x")
        grip = tk.Label(status, text="◢", font=(FONT, 9), fg=MUTED, bg=SIDE, cursor="size_nw_se")
        grip.pack(side="right", anchor="se")
        grip.bind("<B1-Motion>", self.resize)
        self.bar = ttk.Progressbar(status, mode="indeterminate", length=180)  # visible solo con una tarea en curso
        self.status = tk.StringVar(value="Listo.")
        tk.Label(status, textvariable=self.status, font=(FONT, 9), fg=MUTED, bg=SIDE, anchor="w").pack(
            side="left", fill="x", expand=True, padx=16, pady=8)

        side = tk.Frame(root, bg=SIDE, width=214)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(root, bg=LINE, width=1).pack(side="left", fill="y")
        tk.Frame(side, bg=SIDE, height=8).pack()
        self.nav = {}
        for key, (title, icon) in PAGES.items():
            b = tk.Button(side, text=f"  {icon}   {title}", anchor="w", font=(FONT, 10), relief="flat", bd=0, bg=SIDE,
                          padx=10, pady=6, cursor="hand2", command=lambda k=key: self.show(k))
            b.pack(fill="x", padx=10, pady=1)
            b.bar = tk.Frame(b, bg=ACCENT, width=3)
            b.bind("<Enter>", lambda e, k=key: self.paint_nav(k, True))
            b.bind("<Leave>", lambda e, k=key: self.paint_nav(k))
            self.nav[key] = b
        foot = tk.Frame(side, bg=SIDE)
        foot.pack(side="bottom", fill="x", padx=14, pady=12)
        if is_admin():
            tk.Label(foot, text="● Administrador", font=(FONT, 8, "bold"), fg=TONES["ok"][0], bg=SIDE).pack(anchor="w")
        else:
            self.button(foot, "● Usuario estándar · elevar", self.elevate).pack(fill="x")

        self.body = tk.Frame(root, bg=BG)
        self.body.pack(side="left", fill="both", expand=True, padx=22, pady=(10, 16))
        self.pages = {k: tk.Frame(self.body, bg=BG) for k in PAGES}
        for key, page in self.pages.items():
            getattr(self, f"build_{key}")(page)
        root.bind("<F5>", lambda e: self.start_scan())

        self.refresh()
        self.show("panel")
        self.build_tray()
        self.build_widget()
        self.poll()
        self.find_networks()
        self.tick_traffic()
        self.tick_connections()

    def show(self, key):
        for page in self.pages.values():
            page.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        self.page = key
        for k in self.nav:
            self.paint_nav(k)
        if key == "conexiones":
            self.paint_connections()
        if key not in self.loaded:  # cada página pide sus datos la primera vez que se abre
            self.loaded.add(key)
            load = getattr(self, f"load_{key}", None)
            if load:
                load()

    def paint_nav(self, key, hover=False):
        b, on = self.nav[key], key == self.page
        fill = NAV_ON if on else HOVER if hover else SIDE
        b.configure(bg=fill, fg=TEXT if on else "#c9d1db", activebackground=fill, activeforeground=TEXT)
        self.rounded(b, fill, SIDE, 9)
        b.bar.place(x=0, rely=.2, relheight=.6) if on else b.bar.place_forget()

    def elevate(self):
        here = Path(__file__).resolve()
        if self.mutex:  # la copia elevada no debe encontrar esta abierta
            ctypes.windll.kernel32.CloseHandle(self.mutex)
            self.mutex = None
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{here}"', str(here.parent), 1) > 32:
            self.quit()

    # ---- bandeja del sistema (Tk 9: tk systray / tk sysnotify)
    def build_tray(self):
        tk = self.tk
        self.logo = tk.PhotoImage(file=Path(__file__).with_name("escaner.png"))
        self.tray_menu = tk.Menu(self.root, tearoff=0, bg=CARD, fg=TEXT, activebackground=SELECTED,
                                 activeforeground="#ffffff", bd=0, font=(FONT, 9))
        for label, cmd in (("Abrir Escáner de red", self.show_window), ("Escanear ahora", self.start_scan),
                           ("Ocultar widget", lambda: self.set_widget(not self.lists["widget"])), (None, None), ("Salir", self.quit)):
            if label:
                self.tray_menu.add_command(label=label, command=cmd)
            else:
                self.tray_menu.add_separator()
        try:
            self.root.tk.call("tk", "systray", "create", "-image", self.logo, "-text", "Escáner de red",
                              "-button1", self.root.register(self.show_window),
                              "-button3", self.root.register(self.tray_popup))
            self.tray = True
        except tk.TclError:  # Tk 8.6 o anterior: sin bandeja, cerrar sale de la app
            self.tray = False
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.told_tray = False

    def tray_popup(self):
        self.tray_menu.tk_popup(*self.root.winfo_pointerxy())

    def show_window(self):
        self.root.deiconify()
        ctypes.windll.user32.ShowWindow(self.hwnd, 9)  # SW_RESTORE: por si se minimizó
        self.root.lift()
        self.root.focus_force()

    def close(self):
        if not self.tray:
            self.quit()
            return
        self.root.withdraw()
        if not self.told_tray:  # avisar solo la primera vez
            self.told_tray = True
            self.notify("Escáner de red sigue activo", "Está en la bandeja, junto al reloj. Clic derecho en el icono para salir.")

    def quit(self):
        if self.tray:
            self.root.tk.call("tk", "systray", "destroy")
        self.root.destroy()

    def notify(self, title, msg):
        try:
            self.root.tk.call("tk", "sysnotify", title, msg[:250])
        except self.tk.TclError:
            pass  # sin bandeja no hay notificaciones; el aviso queda en el registro

    # ---- widget flotante
    def build_widget(self):
        tk = self.tk
        w = self.widget = tk.Toplevel(self.root, bg=BG, highlightthickness=1, highlightbackground=LINE)
        w.withdraw()
        w.title("Widget Escáner de red")
        self.widget_hwnd = self.blur(w)
        w.attributes("-topmost", True)
        head = tk.Frame(w, bg=BG)
        head.pack(fill="x", padx=(12, 4), pady=(6, 2))
        name = tk.Label(head, text="Escáner de red", font=(FONT, 9, "bold"), fg=TEXT, bg=BG)
        name.pack(side="left")
        for glyph, cmd, label in (("\ue8bb", lambda: self.set_widget(False), "Ocultar widget"), ("\ue8a7", self.show_window, "Abrir la app")):
            tk.Button(head, text=glyph, command=cmd, font=("Segoe MDL2 Assets", 8), bg=BG, fg=MUTED, relief="flat", bd=0, padx=7, pady=3,
                      activebackground=HOVER, activeforeground=TEXT, cursor="hand2", takefocus=True).pack(side="right")
        grid = tk.Frame(w, bg=BG)
        grid.pack(fill="x", padx=12, pady=(0, 9))
        grid.columnconfigure((0, 1), weight=1, uniform="w")
        self.w_vals, labels = {}, [w, head, name, grid]
        for n, (key, caption) in enumerate((("down", "Bajada"), ("up", "Subida"), ("conn", "Conexiones"), ("alert", "Alertas"))):
            cell = tk.Frame(grid, bg=BG)
            cell.grid(row=n // 2, column=n % 2, sticky="w", pady=1)
            cap = tk.Label(cell, text=caption, font=(FONT, 8), fg=MUTED, bg=BG)
            cap.pack(anchor="w")
            self.w_vals[key] = tk.Label(cell, text="–", font=(FONT, 11, "bold"), fg=TEXT, bg=BG)
            self.w_vals[key].pack(anchor="w")
            labels += [cell, cap, self.w_vals[key]]
        for item in labels:
            item.bind("<Button-1>", self.drag_widget)
        w.update_idletasks()
        w.geometry(f"{max(w.winfo_reqwidth(), 210)}x{w.winfo_reqheight()}+{self.widget_x()}+{self.widget_y()}")
        self.set_widget(self.lists["widget"])

    def work_area(self):
        rect = (ctypes.c_long * 4)()
        ctypes.windll.user32.SystemParametersInfoW(48, 0, rect, 0)  # SPI_GETWORKAREA: sin la barra de tareas
        return list(rect)

    def widget_x(self):
        left, _, right, _ = self.work_area()
        x = self.lists.get("widget_pos", [None])[0]
        return x if x is not None and left <= x < right - 40 else right - max(self.widget.winfo_reqwidth(), 210) - 12

    def widget_y(self):
        _, top, _, bottom = self.work_area()
        pos = self.lists.get("widget_pos", [None, None])
        return pos[1] if pos[1] is not None and top <= pos[1] < bottom - 40 else bottom - self.widget.winfo_reqheight() - 12

    def drag_widget(self, event):
        self.drag(event, self.widget_hwnd)  # vuelve al soltar el ratón
        self.lists["widget_pos"] = [self.widget.winfo_rootx(), self.widget.winfo_rooty()]
        self.save_lists()

    def set_widget(self, on):
        self.widget.deiconify() if on else self.widget.withdraw()
        self.lists["widget"] = on
        self.save_lists()
        self.tray_menu.entryconfigure(2, label="Ocultar widget" if on else "Mostrar widget")

    def paint_status(self, down, up):
        """Widget y texto del icono de la bandeja."""
        alerts = sum(c["nivel"] == "Peligrosa" for c in self.conns.values())
        live = sum(bool(c["rip"]) for c in self.conns.values())
        self.w_vals["down"].configure(text=human_rate(down))
        self.w_vals["up"].configure(text=human_rate(up))
        self.w_vals["conn"].configure(text=str(live))
        self.w_vals["alert"].configure(text=str(alerts), fg=TONES["bad" if alerts else "ok"][0])
        if self.tray:
            self.root.tk.call("tk", "systray", "configure", "-text",
                              f"Escáner de red · {live} conexiones" + (f" · {alerts} alertas" if alerts else ""))

    # ---- páginas
    def build_panel(self, page):
        tk = self.tk
        cards = tk.Frame(page, bg=BG)
        cards.pack(fill="x", pady=(0, 12))
        for c in range(4):
            cards.columnconfigure(c, weight=1, uniform="c")
        self.p_conn, self.p_alert, self.p_down, self.p_up = (
            self.stat(cards, c, cap) for c, cap in enumerate(("Conexiones", "Alertas", "Bajada", "Subida")))
        outer, body = self.card(page, "Tráfico en vivo (último minuto)")
        outer.pack(fill="x", pady=(0, 12))
        self.chart = tk.Canvas(body, height=110, bg=CARD, highlightthickness=0)
        self.chart.pack(fill="x")
        outer, body = self.card(page, "Estado")
        outer.pack(fill="both", expand=True)
        self.kv = {}
        for key, label in (("ip", "IP pública"), ("red", "Red local"), ("firewall", "Firewall"), ("wifi", "Wi-Fi"), ("lan", "Acceso a la LAN")):
            row = tk.Frame(body, bg=CARD)
            row.pack(fill="x", pady=5)
            tk.Label(row, text=label, font=(FONT, 9), fg=MUTED, bg=CARD).pack(side="left")
            self.kv[key] = tk.Label(row, text="…", font=(FONT, 9), fg=TEXT, bg=CARD)
            self.kv[key].pack(side="right")

    def load_panel(self):
        def work():
            try:
                ip = public_ip()
            except OSError:
                ip = "sin conexión"
            profiles = firewall_profiles()
            wifi = re.search(r"\bSSID\s*:\s*(.+)", run(["netsh", "wlan", "show", "interfaces"]))
            on = sum(p["on"] for p in profiles)

            def apply():
                self.kv["ip"].configure(text=ip)
                self.kv["firewall"].configure(text=f"Activo en {on} de {len(profiles)} perfiles",
                                              fg=TONES["ok" if profiles and on == len(profiles) else "warn"][0])
                self.kv["wifi"].configure(text=wifi[1].strip() if wifi else "Sin conexión Wi-Fi")
            self.q.put(apply)
        threading.Thread(target=work, daemon=True).start()

    def build_dispositivos(self, page):
        tk, ttk = self.tk, self.ttk
        cards = tk.Frame(page, bg=BG)
        cards.pack(fill="x", pady=(0, 12))
        for c in range(4):
            cards.columnconfigure(c, weight=1, uniform="c")
        self.s_on, self.s_new, self.s_off, self.s_net = (
            self.stat(cards, c, cap) for c, cap in enumerate(("Conectados", "Nuevos", "Desconectados", "Red")))

        outer, tools = self.card(page)
        outer.pack(fill="x", pady=(0, 12))
        self.iface_var = tk.StringVar()
        self.combo = ttk.Combobox(tools, textvariable=self.iface_var, state="readonly", width=26, font=(FONT, 9))
        self.combo.pack(side="left", padx=(0, 8), ipady=4)
        self.combo.bind("<<ComboboxSelected>>", lambda e: self.start_scan())
        self.button(tools, "Escanear", self.start_scan, primary=True).pack(side="left", padx=(0, 6))
        for text, cmd in (("Fabricantes", self.lookup_vendors), ("Puertos", self.ports), ("Abrir web", self.open_web),
                          ("Renombrar", self.rename), ("CSV", self.export)):
            self.button(tools, text, cmd).pack(side="left", padx=(0, 6))
        self.watch_btn = self.button(tools, "Vigilar: no", self.toggle_watch)
        self.watch_btn.pack(side="right")

        self.banner = tk.Label(page, text=BLOCKED_TEXT, font=(FONT, 9, "bold"), fg=TONES["warn"][0], bg=TONES["warn"][1],
                               anchor="w", justify="left", padx=16, pady=10, wraplength=900)
        self.rounded(self.banner, TONES["warn"][1], BG, 10)

        self.table, table = self.card(page, "Dispositivos")
        self.table.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table, columns=self.COLS, show="headings")
        for c, h, w in zip(self.COLS, self.HEAD, self.WIDTH):
            self.tree.heading(c, text=h, anchor="w", command=lambda c=c: self.sort(c))
            self.tree.column(c, width=w)
        self.tree.tag_configure("nuevo", foreground=TONES["warn"][0])
        self.tree.tag_configure("off", foreground="#7d8796")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda e: self.rename() if self.tree.identify_region(e.x, e.y) == "cell" else None)

    def build_conexiones(self, page):
        self.c_tree = self.table_page(
            page, "Conexiones activas",
            (("nivel", "Riesgo", 80), ("proceso", "Proceso", 110), ("proto", "Proto", 45), ("local", "Local", 125),
             ("remoto", "Remoto", 130), ("host", "Host", 115), ("servicio", "Servicio", 60), ("estado", "Estado", 85),
             ("motivo", "Motivo", 170)),
            (("Cortar", self.cut_selected, True), ("Terminar proceso", self.kill_selected, False),
             ("Bloquear IP", self.block_ip_selected, False), ("Bloquear programa", self.block_program_selected, False),
             ("Es de confianza", lambda: self.list_selected("confianza"), False),
             ("Es peligroso", lambda: self.list_selected("bloqueo"), False)))
        for level, tone in LEVEL_TONE.items():
            self.c_tree.tag_configure(level, foreground=TONES[tone][0])
        self.c_tree.tag_configure("Desconocida", foreground=MUTED)
        self.c_tree.bind("<<TreeviewSelect>>", lambda e: self.show_reason())

    def build_adaptadores(self, page):
        tools = self.toolbar(page)
        self.button(tools, "Actualizar", self.load_adaptadores).pack(side="left", padx=(0, 6))
        self.button(tools, "Habilitar", lambda: self.adapter_power(True)).pack(side="left", padx=(0, 6))
        self.button(tools, "Deshabilitar", lambda: self.adapter_power(False)).pack(side="left", padx=(0, 6))
        self.button(tools, "IP automática", self.adapter_dhcp).pack(side="left", padx=(0, 6))
        self.button(tools, "IP fija…", self.adapter_static).pack(side="left", padx=(0, 6))
        self.dns_var = self.tk.StringVar(value="Automático")
        self.ttk.Combobox(tools, textvariable=self.dns_var, state="readonly", width=12, font=(FONT, 9),
                          values=["Automático", *DNS_PRESETS]).pack(side="left", padx=(10, 6), ipady=4)
        self.button(tools, "Aplicar DNS", self.adapter_dns).pack(side="left")
        self.a_tree = self.table_page(
            page, "Adaptadores de red",
            (("nombre", "Nombre", 130), ("estado", "Estado", 80), ("ip", "IP", 130), ("dhcp", "DHCP", 70), ("dns", "DNS", 210),
             ("velocidad", "Velocidad", 90), ("mac", "MAC", 140), ("descripcion", "Descripción", 240)), ())

    def build_wifi(self, page):
        tools = self.toolbar(page)
        for text, cmd in (("Actualizar", self.load_wifi), ("Conectar", self.wifi_connect), ("Desconectar", self.wifi_disconnect),
                          ("Olvidar perfil", self.wifi_forget)):
            self.button(tools, text, cmd).pack(side="left", padx=(0, 6))
        self.w_note = self.tk.Label(tools, font=(FONT, 9), fg=MUTED, bg=CARD)
        self.w_note.pack(side="left", padx=8)
        self.w_tree = self.table_page(page, "Redes disponibles y perfiles guardados",
                                      (("ssid", "Red", 320), ("señal", "Señal", 90), ("seguridad", "Seguridad", 220), ("perfil", "Perfil", 100)), ())
        for tone in TONES:
            self.w_tree.tag_configure(tone, foreground=TONES[tone][0])

    def build_firewall(self, page):
        tools = self.toolbar(page)
        for text, cmd in (("Actualizar", self.load_firewall), ("Activar todos los perfiles", self.fw_enable),
                          ("Protección rápida", self.fw_quick), ("Eliminar regla", self.fw_remove)):
            self.button(tools, text, cmd).pack(side="left", padx=(0, 6))
        self.f_note = self.tk.Label(tools, font=(FONT, 9), fg=MUTED, bg=CARD)
        self.f_note.pack(side="right")
        self.f_tree = self.table_page(page, "Reglas creadas por esta app",
                                      (("nombre", "Regla", 620), ("dir", "Dirección", 110), ("on", "Activa", 90)), ())

    def build_pruebas(self, page):
        tk = self.tk
        tools = self.toolbar(page)
        self.host_var = tk.StringVar(value="1.1.1.1")
        tk.Entry(tools, textvariable=self.host_var, width=18, font=(FONT, 10), bg=CARD2, fg=TEXT, insertbackground=TEXT,
                 relief="flat", highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT).pack(side="left", padx=(0, 8), ipady=6)
        for text, cmd in (("Diagnóstico", self.test_diagnose), ("Velocidad", self.test_speed), ("Ping", self.test_ping),
                          ("Traceroute", self.test_trace), ("Comparar DNS", self.test_dns), ("Probar puerto…", self.test_port)):
            self.button(tools, text, cmd).pack(side="left", padx=(0, 6))
        outer, body = self.card(page, "Resultado")
        outer.pack(fill="both", expand=True)
        self.output = tk.Text(body, bg=CARD, fg=TEXT, bd=0, font=("Consolas", 10), wrap="word", state="disabled", highlightthickness=0)
        self.output.pack(fill="both", expand=True)

    def build_metricas(self, page):
        tk = self.tk
        cards = tk.Frame(page, bg=BG)
        cards.pack(fill="x", pady=(0, 12))
        for c in range(3):
            cards.columnconfigure(c, weight=1, uniform="c")
        self.m_down, self.m_up, self.m_peak = (self.stat(cards, c, cap, last=2)
                                               for c, cap in enumerate(("Bajado en la sesión", "Subido en la sesión", "Pico de bajada")))
        self.m_tree = self.table_page(page, "Por interfaz", (("nombre", "Interfaz", 420), ("down", "Bajada", 120), ("up", "Subida", 120)), (), expand=False)
        self.m_tree.configure(height=4)
        self.h_tree = self.table_page(page, "Historial de conexiones de la sesión",
                                      (("hora", "Hora", 80), ("proceso", "Proceso", 170), ("remoto", "Remoto", 190),
                                       ("host", "Host", 240), ("nivel", "Riesgo", 90)), ())
        self.h_tree.master.master.pack_configure(pady=(12, 0))

    def build_herramientas(self, page):
        tools = self.toolbar(page, "Reparar la red")
        for name in TOOLS:
            self.button(tools, name, lambda n=name: self.run_tool(n)).pack(side="left", padx=(0, 6))
        tools = self.toolbar(page, "Bloqueo automático")
        self.auto_btn = self.button(tools, "", self.toggle_auto)
        self.auto_btn.pack(side="left")
        self.tk.Label(tools, text="Bloquea en el firewall las IP remotas peligrosas o de tu lista de bloqueo en cuanto aparecen.",
                      font=(FONT, 9), fg=MUTED, bg=CARD).pack(side="left", padx=12)
        self.l_tree = self.table_page(page, "Listas de confianza y bloqueo", (("lista", "Lista", 130), ("valor", "IP o programa", 720)),
                                      (("Quitar de la lista", self.list_remove, False),))
        self.paint_lists()

    def build_registro(self, page):
        self.r_tree = self.table_page(page, "Historial de acciones", (("hora", "Hora", 160), ("detalle", "Detalle", 780)), ())
        try:
            lines = LOG_FILE.read_text(encoding="utf-8").splitlines()[-300:]
        except OSError:
            lines = []
        for line in lines:
            self.r_tree.insert("", 0, values=(line[:19], line[21:]))

    def toolbar(self, page, title=None):
        outer, body = self.card(page, title)
        outer.pack(fill="x", pady=(0, 12))
        return body

    def table_page(self, page, title, cols, actions, expand=True):
        outer, body = self.card(page, title)
        outer.pack(fill="both" if expand else "x", expand=expand)
        if actions:
            row = self.tk.Frame(body, bg=CARD)
            row.pack(side="bottom", fill="x", pady=(10, 0))
            for text, cmd, primary in actions:
                self.button(row, text, cmd, primary).pack(side="left", padx=(0, 6))
        tree = self.ttk.Treeview(body, columns=[c[0] for c in cols], show="headings")
        for c, h, w in cols:
            tree.heading(c, text=h, anchor="w")
            tree.column(c, width=w)
        scroll = self.ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    def fill(self, tree, rows):
        """Sustituye las filas [(iid, valores, etiqueta)] conservando la selección."""
        selected, top = tree.selection(), tree.yview()[0]
        tree.delete(*tree.get_children())
        for iid, values, tag in rows:
            tree.insert("", "end", iid=iid, values=values, tags=(tag,))
        tree.selection_set([k for k in selected if tree.exists(k)])
        tree.yview_moveto(top)

    # ---- ventana glass (la misma que Antimalware)
    def blur(self, window):
        """Fondo desenfocado de una ventana sin marco, como el optimizador (ACCENT_ENABLE_BLURBEHIND). Devuelve su HWND."""
        class Accent(ctypes.Structure):
            _fields_ = [("state", ctypes.c_int), ("flags", ctypes.c_int), ("color", ctypes.c_uint), ("anim", ctypes.c_int)]

        class Data(ctypes.Structure):
            _fields_ = [("attr", ctypes.c_int), ("data", ctypes.c_void_p), ("size", ctypes.c_size_t)]
        window.overrideredirect(True)
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        try:
            accent = Accent(3, 2, GLASS_TINT, 0)  # 3 = desenfoque, 2 = usar el color
            data = Data(19, ctypes.cast(ctypes.byref(accent), ctypes.c_void_p), ctypes.sizeof(accent))  # 19 = WCA_ACCENT_POLICY
            ctypes.windll.user32.SetWindowCompositionAttribute(hwnd, ctypes.byref(data))
            window.attributes("-alpha", GLASS_ALPHA)
        except Exception:
            pass  # Windows antiguo: ventana opaca
        return hwnd

    def glass(self):
        u32 = ctypes.windll.user32
        self.hwnd = self.blur(self.root)
        # sin marco Tk la saca de la barra de tareas: APPWINDOW la devuelve y MINIMIZEBOX deja minimizarla desde ahí.
        # Va después de -alpha, que reescribe estos estilos; ocultar y mostrar hace que la barra de tareas la vea
        u32.SetWindowLongW(self.hwnd, -20, u32.GetWindowLongW(self.hwnd, -20) & ~0x80 | 0x40000)
        u32.SetWindowLongW(self.hwnd, -16, u32.GetWindowLongW(self.hwnd, -16) | 0x20000 | 0x80000)
        self.root.withdraw()
        self.root.deiconify()

    def title_bar(self):
        """Barra de título propia: forma parte del cristal, como en el optimizador."""
        tk = self.tk
        bar = tk.Frame(self.root, bg=SIDE)
        bar.pack(side="top", fill="x")
        logo = tk.Label(bar, text="", font=("Segoe MDL2 Assets", 12), fg="#000000", bg=ACCENT, padx=7, pady=6)
        logo.pack(side="left", padx=(16, 10), pady=7)
        self.rounded(logo, ACCENT, SIDE, 10)
        name = tk.Label(bar, text="Escáner de red", font=(FONT, 11, "bold"), fg=TEXT, bg=SIDE)
        name.pack(side="left")
        tagline = tk.Label(bar, text="Dispositivos de tu red local", font=(FONT, 8), fg=MUTED, bg=SIDE)
        tagline.pack(side="left", padx=10)
        for glyph, cmd, hover in (("", self.close, "#c42b1c"), ("", self.minimize, HOVER)):
            b = tk.Button(bar, text=glyph, command=cmd, font=("Segoe MDL2 Assets", 9), bg=SIDE, fg=TEXT, relief="flat", bd=0,
                          activebackground=hover, activeforeground=TEXT, padx=18, pady=10, cursor="hand2")
            b.pack(side="right", fill="y")
            b.bind("<Enter>", lambda e, b=b, c=hover: b.configure(bg=c))
            b.bind("<Leave>", lambda e, b=b: b.configure(bg=SIDE))
        for w in (bar, logo, name, tagline):
            w.bind("<Button-1>", self.drag)

    def drag(self, event, hwnd=None):
        ctypes.windll.user32.ReleaseCapture()
        ctypes.windll.user32.SendMessageW(hwnd or self.hwnd, 0xA1, 2, 0)  # WM_NCLBUTTONDOWN + HTCAPTION: Windows mueve la ventana

    def resize(self, event):
        w, h = self.root.minsize()
        self.root.geometry(f"{max(w, event.x_root - self.root.winfo_rootx())}x{max(h, event.y_root - self.root.winfo_rooty())}")

    def minimize(self):
        ctypes.windll.user32.ShowWindow(self.hwnd, 6)  # SW_MINIMIZE: Tk no iconifica ventanas sin marco

    def corner(self, q, fill, bg, r, line):
        """Esquina q (nw, ne, sw, se) suavizada, con 4×4 muestras por píxel: tk no dibuja con antialias."""
        key = q, fill, bg, r, line
        if key not in self.corner_cache:
            rgb = lambda c: [int(c[i:i + 2], 16) for i in (1, 3, 5)]
            cx, cy = (0 if "e" in q else r), (0 if "s" in q else r)
            rows = []
            for y in range(r):
                row = []
                for x in range(r):
                    acc = [0, 0, 0]
                    for sx, sy in itertools.product((.125, .375, .625, .875), repeat=2):
                        d = ((x + sx - cx) ** 2 + (y + sy - cy) ** 2) ** .5
                        c = rgb(bg if d > r else line if line and d > r - 1 else fill)
                        acc = [a + b for a, b in zip(acc, c)]
                    row.append("#%02x%02x%02x" % tuple(a // 16 for a in acc))
                rows.append("{" + " ".join(row) + "}")
            img = self.tk.PhotoImage(width=r, height=r)
            img.put(" ".join(rows))
            self.corner_cache[key] = img
        return self.corner_cache[key]

    def rounded(self, w, fill, bg, r=8, line=None):
        """Redondea w tapando sus cuatro esquinas; se vuelve a llamar si cambia de color."""
        if not hasattr(w, "corners"):
            u32, hwnd = ctypes.windll.user32, w.winfo_id()
            u32.SetWindowLongW(hwnd, -16, u32.GetWindowLongW(hwnd, -16) | 0x02000000)  # WS_CLIPCHILDREN: un Button pinta sobre sus hijos
            w.corners = {q: self.tk.Label(w, bd=0, padx=0, pady=0, highlightthickness=0) for q in ("nw", "ne", "sw", "se")}
            for q, label in w.corners.items():
                label.place(relx=int("e" in q), rely=int("s" in q), anchor=q, bordermode="outside")
        for q, label in w.corners.items():
            label.configure(image=self.corner(q, fill, bg, r, line))

    # ---- estilo y piezas reutilizables
    def styles(self):
        s = self.ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT, rowheight=30, borderwidth=0, font=(FONT, 9))
        s.configure("Treeview.Heading", background=CARD2, foreground=MUTED, borderwidth=0, relief="flat",
                    font=(FONT, 9, "bold"), padding=(8, 6))
        s.map("Treeview", background=[("selected", SELECTED)], foreground=[("selected", "#ffffff")])
        s.map("Treeview.Heading", background=[("active", HOVER)])
        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("TScrollbar", background=CARD2, troughcolor=CARD, bordercolor=CARD, arrowcolor=MUTED,
                    lightcolor=CARD2, darkcolor=CARD2, gripcount=0)
        s.map("TScrollbar", background=[("active", HOVER), ("disabled", CARD)], arrowcolor=[("disabled", CARD2)])
        s.configure("TProgressbar", troughcolor=CARD2, background=ACCENT, bordercolor=SIDE, lightcolor=ACCENT, darkcolor=ACCENT)
        s.configure("TCombobox", fieldbackground=CARD2, background=CARD2, foreground=TEXT, arrowcolor=TEXT,
                    bordercolor=LINE, lightcolor=CARD2, darkcolor=CARD2, padding=4)
        s.map("TCombobox", fieldbackground=[("readonly", CARD2)], foreground=[("readonly", TEXT)],
              selectbackground=[("readonly", CARD2)], selectforeground=[("readonly", TEXT)])
        for option, value in (("background", CARD2), ("foreground", TEXT), ("selectBackground", SELECTED), ("selectForeground", TEXT)):
            self.root.option_add(f"*TCombobox*Listbox.{option}", value)

    def card(self, parent, title=None):
        tk = self.tk
        outer = tk.Frame(parent, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        if title:
            tk.Label(outer, text=title, font=(FONT, 10, "bold"), fg=TEXT, bg=CARD).pack(anchor="w", padx=18, pady=(14, 0))
        body = tk.Frame(outer, bg=CARD)
        body.pack(fill="both", expand=True, padx=18, pady=(10 if title else 14, 16))
        self.rounded(outer, CARD, parent["bg"], 14, LINE)
        return outer, body

    def button(self, parent, text, cmd, primary=False):
        bg, hover = (ACCENT, ACCENT_HOVER) if primary else (CARD2, HOVER)
        fg, line = ("#000000", None) if primary else (TEXT, LINE)
        b = self.tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
                           relief="flat", bd=0, cursor="hand2", highlightthickness=0 if primary else 1,
                           highlightbackground=LINE, font=(FONT, 9, "bold" if primary else "normal"), padx=14, pady=8)

        def paint(color):
            b.configure(bg=color)
            self.rounded(b, color, parent["bg"], 9, line)
        b.bind("<Enter>", lambda e: paint(hover))
        b.bind("<Leave>", lambda e: paint(bg))
        paint(bg)
        return b

    def stat(self, parent, col, caption, last=3):
        tk = self.tk
        outer, body = self.card(parent)
        outer.grid(row=0, column=col, sticky="nsew", padx=(0, 0 if col == last else 12))
        tk.Label(body, text=caption.upper(), font=(FONT, 8), fg=MUTED, bg=CARD).pack(anchor="w")
        value = tk.Label(body, text="–", font=(FONT, 18, "bold"), fg=TEXT, bg=CARD)
        value.pack(anchor="w", pady=(2, 0))
        sub = tk.Label(body, font=(FONT, 8), fg=MUTED, bg=CARD)
        sub.pack(anchor="w")
        return value, sub

    # ---- tareas en segundo plano
    # tkinter no es seguro entre hilos: los hilos encolan funciones y el hilo de la UI las ejecuta
    def poll(self):
        try:
            while not self.q.empty():
                self.q.get()()
        finally:  # un error en una tarea no debe congelar la app
            self.root.after(100, self.poll)

    def say(self, msg):
        self.q.put(lambda: self.status.set(msg))

    def job(self, msg, work):
        """Ejecuta work() en segundo plano, de una en una. Lo que devuelve (una función) se ejecuta en el hilo de la UI."""
        if self.busy:
            self.status.set("Espera a que termine la tarea actual.")
            return
        self.busy = True
        self.status.set(msg)
        self.bar.pack(side="right", padx=16, pady=10)
        self.bar.start(12)

        def run_it():
            try:
                done = work()
            except Exception as e:
                done = lambda e=e: self.status.set(f"Error: {e}")
            self.q.put(lambda: self.finish(done))
        threading.Thread(target=run_it, daemon=True).start()

    def finish(self, done):
        self.bar.stop()
        self.bar.pack_forget()
        self.busy = False
        try:
            done()
        except Exception as e:
            self.status.set(f"Error: {e}")

    # ---- redes y escaneo
    def find_networks(self):
        self.job("Buscando redes…", self.load_networks)

    def load_networks(self):
        ifaces = interfaces()

        def done():
            self.ifaces = ifaces
            names = [iface_label(i) for i in ifaces]
            self.combo.configure(values=names)
            if not names:
                self.iface_var.set("")
                self.status.set("No se encontró ninguna red con puerta de enlace. Comprueba la conexión y pulsa Escanear.")
                return
            if self.iface_var.get() not in names:
                self.iface_var.set(names[0])
            self.start_scan()
        return done

    def start_scan(self, alert=False):
        if not self.ifaces:
            self.find_networks()
            return
        iface = next(i for i in self.ifaces if iface_label(i) == self.iface_var.get())

        def work():
            ips = local_ips()
            if ips and iface["ip"] not in ips:  # cambió la IP o el cable: la lista de redes ya no vale
                return self.load_networks()
            res = scan(iface, lambda d, t: self.say(f"Escaneando… {d}/{t}"))
            blocked = lan_blocked(iface)
            return lambda: self.show_scan(res, blocked, iface, alert)
        self.job("Escaneando…", work)

    def show_scan(self, res, blocked, iface, alert):
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.rows = merge(self.db, res, scan_net(iface), now)
        save_db(self.db)
        self.s_net[0].configure(text=str(scan_net(iface)))
        self.s_net[1].configure(text=f"{iface['alias']} · puerta de enlace {iface['gw']}")
        self.banner.pack(fill="x", pady=(0, 12), before=self.table) if blocked else self.banner.pack_forget()
        self.kv["red"].configure(text=f"{iface['alias']} · {iface['ip']}")
        self.kv["lan"].configure(text="Bloqueado por una VPN o cortafuegos" if blocked else "Correcto",
                                 fg=TONES["warn" if blocked else "ok"][0])
        self.refresh()
        new = [r for r in self.rows if r["nuevo"]]
        self.status.set(f"{sum(r['online'] for r in self.rows)} dispositivos conectados, {len(new)} nuevos. Último escaneo {now}.")
        if alert and new:
            text = ", ".join(f"{r['ip']} {r['mac']}" for r in new)
            self.log(f"Dispositivo nuevo: {text}")
            self.notify("Dispositivo nuevo en la red", text)

    def toggle_watch(self):
        if self.watch_job:
            self.root.after_cancel(self.watch_job)
            self.watch_job = None
        else:
            self.watch_tick()
        self.watch_btn.configure(text=f"Vigilar: {'sí' if self.watch_job else 'no'}")

    def watch_tick(self):
        self.watch_job = self.root.after(5 * 60 * 1000, self.watch_tick)
        self.start_scan(alert=True)

    # ---- tabla
    def sort_key(self, r):
        col = self.sort_by[0]
        if col == "ip":
            return ipaddress.ip_address(r["ip"])
        if col == "estado":
            return not r["online"], not r["nuevo"], ipaddress.ip_address(r["ip"])
        return str(r.get(col, "")).casefold()

    def refresh(self):
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for r in sorted(self.rows, key=self.sort_key, reverse=self.sort_by[1]):
            tag = "nuevo" if r["nuevo"] else ("" if r["online"] else "off")
            self.tree.insert("", "end", iid=r["key"], tags=(tag,), values=(
                "NUEVO" if r["nuevo"] else ("●" if r["online"] else "○"), r["ip"], r["mac"], r.get("alias", ""),
                r["nombre"], r.get("fabricante", ""), r["tipo"], "sí" if r["ping"] else "no",
                port_text(r.get("puertos")), r.get("visto", "")))
        self.tree.selection_set([k for k in selected if self.tree.exists(k)])
        on = sum(r["online"] for r in self.rows)
        new = sum(r["nuevo"] for r in self.rows)
        self.s_on[0].configure(text=str(on), fg=TONES["ok"][0] if on else TEXT)
        self.s_on[1].configure(text=f"al ping responden: {sum(r['ping'] for r in self.rows)}")
        self.s_new[0].configure(text=str(new), fg=TONES["warn"][0] if new else TEXT)
        self.s_new[1].configure(text="en el último escaneo")
        self.s_off[0].configure(text=str(len(self.rows) - on))
        self.s_off[1].configure(text="conocidos de esta red")

    def sort(self, col):
        self.sort_by = col, self.sort_by == (col, False)
        for c, h in zip(self.COLS, self.HEAD):
            self.tree.heading(c, text=h + (" ▼" if self.sort_by[1] else " ▲") * (c == col))
        self.refresh()

    def selected(self):
        sel = self.tree.selection()
        if not sel:
            self.status.set("Selecciona un dispositivo de la lista.")
            return None
        return next(r for r in self.rows if r["key"] == sel[0])

    # ---- acciones de sistema: confirmación, permisos y registro en un solo sitio
    def log(self, text):
        log_line(text)
        self.r_tree.insert("", 0, values=(f"{datetime.now():%Y-%m-%d %H:%M:%S}", text))

    def action(self, msg, fn, confirm="", admin=True, then=None):
        from tkinter import messagebox
        if admin and not is_admin():
            self.status.set(ADMIN_TEXT)
            return
        if confirm and not messagebox.askyesno("Confirmar", confirm, parent=self.root):
            return

        def work():
            try:
                text = fn()
            except Exception as e:
                text = f"Error: {e}"

            def done():
                self.log(f"{msg} → {text}")
                self.status.set(text.splitlines()[0][:200] if text else "Hecho.")
                if then:
                    then()
            return done
        self.job(msg, work)

    def load(self, fn, apply):
        """Lee datos del sistema en segundo plano y los entrega a apply en el hilo de la UI."""
        def work():
            data = fn()
            self.q.put(lambda: apply(data))
        threading.Thread(target=work, daemon=True).start()

    def pick(self, tree, rows):
        sel = tree.selection()
        if not sel:
            self.status.set("Selecciona una fila de la lista.")
            return None
        return rows.get(sel[0])

    # ---- conexiones
    def tick_connections(self):
        self.root.after(5000, self.tick_connections)
        if self.polling:
            return
        self.polling = True

        def work():
            try:
                rows = connections()

                def publish():
                    ready = [{**c, "host": self.host_cache.get(c["rip"], "")} for c in rows]
                    for c in ready:
                        c["nivel"], c["motivo"] = classify(c, self.sigs.get(c["ruta"], ""), self.lists)
                    self.q.put(lambda: self.show_connections(ready))
                paths = {c["ruta"] for c in rows if c["ruta"]} - self.sigs.keys()
                ips = {c["rip"] for c in rows if c["rip"] and not ipaddress.ip_address(c["rip"]).is_private} - self.host_cache.keys()
                if paths or ips:  # las firmas tardan varios segundos: primero se enseña lo que ya se sabe
                    publish()
                    self.sigs.update({p: "" for p in paths} | signatures(sorted(paths)))
                    self.host_cache.update({ip: "" for ip in ips} | hostnames(ips, 1.5))
                publish()
            finally:
                self.polling = False
        threading.Thread(target=work, daemon=True).start()

    def show_connections(self, rows):
        self.conns = {c["id"]: c for c in rows}
        if self.page == "conexiones":
            self.paint_connections()
        alerts = [c for c in rows if c["nivel"] == "Peligrosa"]
        live = [c for c in rows if c["rip"]]
        self.p_conn[0].configure(text=str(len(live)))
        self.p_conn[1].configure(text=f"{len(rows) - len(live)} a la escucha")
        self.p_alert[0].configure(text=str(len(alerts)), fg=TONES["bad" if alerts else "ok"][0])
        self.p_alert[1].configure(text=f"{sum(c['nivel'] == 'Revisar' for c in rows)} para revisar")
        now = datetime.now().strftime("%H:%M:%S")
        for c in live:
            key = c["proceso"], c["rip"], c["rport"]
            if key not in self.seen_conns:
                self.seen_conns.add(key)
                self.h_tree.insert("", 0, values=(now, c["proceso"], f"{c['rip']}:{c['rport']}", c["host"], c["nivel"]))
        self.h_tree.delete(*self.h_tree.get_children()[500:])
        if self.lists["auto"] and is_admin():
            for c in alerts:
                if c["rip"] and c["rip"] not in self.blocked_ips and not ipaddress.ip_address(c["rip"]).is_private:
                    self.blocked_ips.add(c["rip"])
                    self.load(lambda ip=c["rip"]: self.auto_block(ip), self.log)

    def paint_connections(self):
        order = {"Peligrosa": 0, "Revisar": 1, "Desconocida": 2, "Segura": 3}
        self.fill(self.c_tree, [(c["id"], (c["nivel"], c["proceso"], c["proto"], f"{c['lip']}:{c['lport']}",
                                           f"{c['rip']}:{c['rport']}" if c["rip"] else "", c["host"], c["servicio"],
                                           c["estado"], c["motivo"]), c["nivel"])
                                for c in sorted(self.conns.values(), key=lambda c: (order[c["nivel"]], c["proceso"].lower()))])

    @staticmethod
    def auto_block(ip):
        try:
            return "Bloqueo automático: " + block_ip(ip)
        except Exception as e:
            return f"Bloqueo automático de {ip} falló: {e}"

    def show_reason(self):
        c = self.conns.get(next(iter(self.c_tree.selection()), None))
        if c:
            self.status.set(f"{c['proceso']}: {c['motivo']}" + (f" · {c['ruta']}" if c["ruta"] else ""))

    def conn_selected(self):
        return self.pick(self.c_tree, self.conns)

    def cut_selected(self):
        c = self.conn_selected()
        if c:
            self.action(f"Cortar {c['proceso']} → {c['rip']}", lambda: cut_tcp(c))

    def kill_selected(self):
        c = self.conn_selected()
        if c:
            self.action(f"Terminar {c['proceso']}", lambda: kill_process(c["pid"]), f"¿Terminar {c['proceso']} (PID {c['pid']})? "
                        "Se perderá lo que no esté guardado.", admin=False)

    def block_ip_selected(self):
        c = self.conn_selected()
        if c and not c["rip"]:
            self.status.set("Esta fila no tiene IP remota.")
        elif c:
            self.action(f"Bloquear {c['rip']}", lambda: block_ip(c["rip"]), then=self.load_firewall)

    def block_program_selected(self):
        c = self.conn_selected()
        if c and not c["ruta"]:
            self.status.set("No se puede leer la ruta de este programa: abre la app como administrador.")
        elif c:
            self.action(f"Bloquear {c['proceso']}", lambda: block_program(c["ruta"]),
                        f"¿Impedir que {c['proceso']} salga a la red?", then=self.load_firewall)

    def list_selected(self, name):
        c = self.conn_selected()
        if not c:
            return
        value = (c["ruta"] or c["proceso"]).lower() if name == "confianza" or not c["rip"] else c["rip"]
        other = "bloqueo" if name == "confianza" else "confianza"
        if value in self.lists[other]:
            self.lists[other].remove(value)
        if value not in self.lists[name]:
            self.lists[name].append(value)
        self.save_lists()
        self.status.set(f"{value} añadido a la lista de {name}.")

    def save_lists(self):
        save_json(CONFIG_FILE, self.lists)
        self.paint_lists()

    def paint_lists(self):
        self.fill(self.l_tree, [(f"{n}|{v}", (n, v), "") for n in ("confianza", "bloqueo") for v in self.lists[n]])
        self.auto_btn.configure(text=f"Bloqueo automático: {'sí' if self.lists['auto'] else 'no'}")

    def list_remove(self):
        sel = self.l_tree.selection()
        if not sel:
            self.status.set("Selecciona una fila de la lista.")
            return
        name, value = sel[0].split("|", 1)
        self.lists[name].remove(value)
        self.save_lists()

    def toggle_auto(self):
        if not self.lists["auto"] and not is_admin():
            self.status.set(ADMIN_TEXT)
            return
        self.lists["auto"] = not self.lists["auto"]
        self.save_lists()

    # ---- adaptadores
    def load_adaptadores(self):
        def apply(rows):
            self.adapters = {a["nombre"]: a for a in rows}
            self.fill(self.a_tree, [(a["nombre"], (a["nombre"], a["estado"], f"{a['ip']}/{a['prefijo']}" if a["ip"] else "",
                                                   a["dhcp"], a["dns"], a["velocidad"], a["mac"], a["descripcion"]), "") for a in rows])
        self.load(adapters, apply)

    def adapter_selected(self):
        return self.pick(self.a_tree, getattr(self, "adapters", {}))

    def adapter_power(self, on):
        a = self.adapter_selected()
        if a:
            self.action(f"{'Habilitar' if on else 'Deshabilitar'} {a['nombre']}", lambda: set_adapter(a["nombre"], on),
                        "" if on else f"¿Deshabilitar {a['nombre']}? Si es tu conexión, te quedarás sin red.", then=self.load_adaptadores)

    def adapter_dns(self):
        a = self.adapter_selected()
        if a:
            name = self.dns_var.get()
            self.action(f"DNS {name} en {a['nombre']}", lambda: set_dns(a["nombre"], DNS_PRESETS.get(name)), then=self.load_adaptadores)

    def adapter_dhcp(self):
        a = self.adapter_selected()
        if a:
            self.action(f"DHCP en {a['nombre']}", lambda: set_dhcp(a["nombre"]), f"¿Pasar {a['nombre']} a IP automática?",
                        then=self.load_adaptadores)

    def adapter_static(self):
        from tkinter import simpledialog
        a = self.adapter_selected()
        if not a:
            return
        if not is_admin():
            self.status.set(ADMIN_TEXT)
            return
        text = simpledialog.askstring("IP fija", "IP/prefijo y puerta de enlace, por ejemplo:\n192.168.1.50/24 192.168.1.1", parent=self.root)
        if not text:
            return
        try:
            ip, prefix, gw = parse_static(text)
        except ValueError as e:
            self.status.set(f"Datos no válidos: {e}")
            return
        self.action(f"IP fija en {a['nombre']}", lambda: set_static(a["nombre"], ip, prefix, gw),
                    f"¿Poner {ip}/{prefix} en {a['nombre']}? Si los datos no son correctos te quedarás sin red.", then=self.load_adaptadores)

    # ---- Wi-Fi
    def load_wifi(self):
        def read():
            text = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
            return text, parse_wifi(text), parse_profiles(run(["netsh", "wlan", "show", "profiles"]))

        def apply(data):
            text, nets, profiles = data
            self.w_note.configure(text="" if nets or profiles else (text.strip().splitlines() or ["Sin datos."])[0][:90])
            names = {n["ssid"] for n in nets}
            self.fill(self.w_tree, [(n["ssid"], (n["ssid"], f"{n['señal']}%", n["seguridad"], "guardado" if n["ssid"] in profiles else ""),
                                     wifi_risk(n["seguridad"])) for n in nets]
                      + [(p, (p, "fuera de alcance", "", "guardado"), "") for p in profiles if p not in names])
        self.load(read, apply)

    def wifi_selected(self):
        sel = self.w_tree.selection()
        if not sel:
            self.status.set("Selecciona una red de la lista.")
        return sel[0] if sel else None

    def wifi_connect(self):
        name = self.wifi_selected()
        if name:
            self.action(f"Conectar a {name}", lambda: change(["netsh", "wlan", "connect", f"name={name}"]), admin=False, then=self.load_wifi)

    def wifi_disconnect(self):
        self.action("Desconectar Wi-Fi", lambda: change(["netsh", "wlan", "disconnect"]), admin=False, then=self.load_wifi)

    def wifi_forget(self):
        name = self.wifi_selected()
        if name:
            self.action(f"Olvidar {name}", lambda: change(["netsh", "wlan", "delete", "profile", f"name={name}"]),
                        f"¿Olvidar la red {name}? Tendrás que volver a poner la contraseña.", then=self.load_wifi)

    # ---- firewall
    def load_firewall(self):
        def apply(data):
            profiles, rules = data
            self.f_note.configure(text=" · ".join(f"{p['Name']}: {'sí' if p['on'] else 'no'}" for p in profiles))
            self.fill(self.f_tree, [(r["Name"], (r["DisplayName"], r["dir"], r["on"]), "") for r in rules])
        self.load(lambda: (firewall_profiles(), firewall_rules()), apply)

    def fw_enable(self):
        self.action("Activar firewall", firewall_on, then=self.load_firewall)

    def fw_quick(self):
        self.action("Protección rápida", quick_protect, "Bloquea las entradas a SMB, RDP, NetBIOS, Telnet y VNC: otros equipos dejarán de "
                    "ver tus carpetas compartidas y de conectarse por escritorio remoto. ¿Continuar?", then=self.load_firewall)

    def fw_remove(self):
        sel = self.f_tree.selection()
        if not sel:
            self.status.set("Selecciona una regla de la lista.")
            return
        self.action("Eliminar regla", lambda: remove_rule(sel[0]), then=self.load_firewall)

    # ---- pruebas
    def write(self, line):
        def add():
            self.output.configure(state="normal")
            self.output.insert("end", line + "\n")
            self.output.see("end")
            self.output.configure(state="disabled")
        self.q.put(add)

    def test(self, title, fn):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.write(f"== {title}")

        def work():
            for line in fn():
                self.write(line)
            return lambda: self.status.set(f"{title}: terminado.")
        self.job(f"{title}…", work)

    def host(self):
        try:
            return valid_host(self.host_var.get().strip())
        except ValueError as e:
            self.status.set(str(e))
            return None

    def test_diagnose(self):
        iface = next((i for i in self.ifaces if iface_label(i) == self.iface_var.get()), None)
        self.test("Diagnóstico", lambda: diagnose(iface))

    def test_speed(self):
        def lines():
            yield f"Bajada: {speed_test(lambda m: self.say(f'Velocidad… {m:.0f} Mbps')):.1f} Mbps (speed.cloudflare.com)"
        self.test("Velocidad", lines)

    def test_ping(self):
        host = self.host()
        if host:
            self.test(f"Ping a {host}", lambda: ping_lines(host))

    def test_trace(self):
        host = self.host()
        if host:
            self.test(f"Traceroute a {host}", lambda: run(["tracert", "-d", "-h", "20", "-w", "500", host], 90).splitlines())

    def test_dns(self):
        def lines():
            for name, servers in DNS_PRESETS.items():
                ms = dns_query(servers[0])
                yield f"{name:12}{servers[0]:18}" + (f"{ms:.0f} ms" if ms is not None else "sin respuesta")
        self.test("Comparar DNS", lines)

    def test_port(self):
        from tkinter import simpledialog
        host = self.host()
        port = host and simpledialog.askinteger("Probar puerto", f"Puerto de {host}:", minvalue=1, maxvalue=65535, parent=self.root)
        if not port:
            return

        def lines():
            with socket.socket() as s:
                s.settimeout(3)
                yield f"{host}:{port} " + ("abierto" if s.connect_ex((host, port)) == 0 else "cerrado o filtrado")
        self.test("Probar puerto", lines)

    # ---- métricas
    def tick_traffic(self):
        self.root.after(1000, self.tick_traffic)
        now = if_counters()
        wrap = lambda new, old: (new - old) % (1 << 32)  # los contadores son de 32 bits
        self.rates = {n: (wrap(v[0], self.counters[n][0]), wrap(v[1], self.counters[n][1])) for n, v in now.items() if n in self.counters}
        self.counters = now
        # shortcut: una VPN pasa el mismo tráfico por dos interfaces, así que el total lo cuenta dos veces
        down, up = sum(r[0] for r in self.rates.values()), sum(r[1] for r in self.rates.values())
        self.traffic = [*self.traffic[1:], (down, up)]
        self.totals = [self.totals[0] + down, self.totals[1] + up]
        self.peak = max(self.peak, down)
        self.p_down[0].configure(text=human_rate(down))
        self.p_up[0].configure(text=human_rate(up))
        self.p_down[1].configure(text=f"pico {human_rate(self.peak)}")
        self.p_up[1].configure(text=f"{human_size(self.totals[1])} en la sesión")
        self.m_down[0].configure(text=human_size(self.totals[0]))
        self.m_up[0].configure(text=human_size(self.totals[1]))
        self.m_peak[0].configure(text=human_rate(self.peak))
        self.paint_status(down, up)
        if self.root.state() == "withdrawn":
            return
        if self.page == "metricas":
            self.fill(self.m_tree, [(n, (n, human_rate(r[0]), human_rate(r[1])), "") for n, r in self.rates.items()])
        if self.page == "panel":
            self.draw_chart()

    def draw_chart(self):
        c, w, h = self.chart, self.chart.winfo_width(), 110
        c.delete("all")
        top = max(max(max(p) for p in self.traffic), 1)
        for n, color in ((0, ACCENT), (1, "#38bdf8")):
            points = [v for i, p in enumerate(self.traffic) for v in (i * w / 59, h - 6 - p[n] / top * (h - 16))]
            c.create_line(*points, fill=color, width=2, smooth=True)
        c.create_text(4, 8, anchor="w", text=f"máx. {human_rate(top)} · bajada verde, subida azul", fill=MUTED, font=(FONT, 8))

    # ---- acciones de dispositivos
    def lookup_vendors(self):
        todo = [r for r in self.rows if r["mac"] and not r.get("fabricante") and not is_random_mac(r["mac"])]
        if not todo:
            self.status.set("No hay fabricantes pendientes (las MAC aleatorias no tienen fabricante).")
            return

        def work():
            found = {}
            for n, oui in enumerate(ouis := {r["mac"][:8] for r in todo}, 1):
                found[oui] = vendor(oui)
                self.say(f"Fabricantes {n}/{len(ouis)}…")
                time.sleep(1.1)  # la API gratuita admite 1 consulta por segundo

            def done():
                for r in todo:
                    if found[r["mac"][:8]]:
                        self.db[r["key"]]["fabricante"] = r["fabricante"] = found[r["mac"][:8]]
                save_db(self.db)
                self.refresh()
                failed = sum(not v for v in found.values())
                self.status.set(f"Fabricantes actualizados. {failed} consulta(s) fallaron: inténtalo más tarde." if failed
                                else "Fabricantes actualizados.")
            return done
        self.job("Consultando fabricantes…", work)

    def ports(self):
        r = self.selected()
        if not r:
            return
        if not r["online"]:
            self.status.set(f"{r['ip']} está desconectado: esa IP podría ser ahora de otro equipo.")
            return

        def work():
            found = scan_ports(r["ip"])

            def done():
                self.db[r["key"]]["puertos"] = r["puertos"] = found
                save_db(self.db)
                self.refresh()
                self.status.set(f"Puertos abiertos en {r['ip']}: {port_text(found) or 'ninguno de los comunes'}")
            return done
        self.job(f"Buscando puertos abiertos en {r['ip']}…", work)

    def open_web(self):
        r = self.selected()
        if r:
            webbrowser.open(web_url(r["ip"], r.get("puertos")))

    def rename(self):
        from tkinter import simpledialog
        r = self.selected()
        if not r:
            return
        name = simpledialog.askstring("Renombrar", f"Alias para {r['ip']}:", initialvalue=r.get("alias", ""), parent=self.root)
        if name is not None:
            self.db[r["key"]]["alias"] = r["alias"] = name.strip()
            save_db(self.db)
            self.refresh()

    def run_tool(self, name):
        cmd, admin, warning = TOOLS[name]
        self.action(name, lambda: change(cmd), f"{warning} ¿Continuar?" if warning else "", admin=admin)

    def export(self):
        from tkinter import filedialog
        if not self.rows:
            self.status.set("Todavía no hay dispositivos que exportar.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], parent=self.root)
        if not path:
            return
        fields = ["ip", "mac", "alias", "nombre", "fabricante", "tipo", "ping", "online", "puertos", "visto", "ultimo"]
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fields, extrasaction="ignore", delimiter=";")
                w.writeheader()
                w.writerows({k: csv_safe(port_text(v) if k == "puertos" else v) for k, v in r.items()} for r in self.rows)
            self.status.set(f"Exportado a {path}")
        except OSError as e:  # lo más habitual: el archivo está abierto en Excel
            self.status.set(f"No se pudo exportar: {e}")


def self_test():
    global DB_FILE
    import tempfile
    net = ipaddress.ip_network("192.168.0.0/24")
    sample = """
  192.168.0.1           00-11-22-33-44-55     dinámico
  192.168.0.104         fe-12-34-56-78-9a     dinámico
  192.168.0.105         00-00-00-00-00-00     no válido
  192.168.0.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  10.0.0.5              aa-bb-cc-dd-ee-ff     dinámico
"""
    assert parse_arp(sample, net) == {"192.168.0.1": "00-11-22-33-44-55", "192.168.0.104": "FE-12-34-56-78-9A"}
    assert is_random_mac("FE-12-34-56-78-9A") and not is_random_mac("00-AA-BB-CC-DD-EE")
    iface = {"ip": "192.168.0.102", "gw": "192.168.0.1", "medio": "802.3", "alias": "Ethernet", "prefix": 24}
    assert guess_type("192.168.0.1", "", iface) == "Router"
    assert guess_type("192.168.0.104", "FE-12-34-56-78-9A", iface).startswith("Inalámbrico")
    assert ping("127.0.0.1") and icmp("127.0.0.1") == 0
    assert str(scan_net(iface)) == "192.168.0.0/24"
    assert str(scan_net({"ip": "10.5.200.7", "prefix": 8})) == "10.5.200.0/22"  # el bloque de esta IP, no el principio de la red

    # historial: una IP nueva por DHCP se actualiza, y los de otra red no aparecen
    mac, row = "00-11-22-33-44-55", lambda ip, mac: {"ip": ip, "mac": mac, "ping": True, "nombre": "", "tipo": "x"}
    db = {mac: {"alias": "tele", "fabricante": "", "visto": "a", "ip": "192.168.0.50", "nombre": "tv.lan"},
          "AA-AA-AA-AA-AA-AA": {"alias": "", "fabricante": "", "visto": "a", "ip": "192.168.0.9"},
          "BB-BB-BB-BB-BB-BB": {"alias": "", "fabricante": "", "visto": "a", "ip": "10.0.0.9"}}
    rows = merge(db, [row("192.168.0.60", mac), row("192.168.0.9", "CC-CC-CC-CC-CC-CC")], net, "b")
    tv = next(r for r in rows if r["key"] == mac)
    assert tv["ip"] == db[mac]["ip"] == "192.168.0.60" and tv["alias"] == "tele" and tv["nombre"] == "tv.lan" and not tv["nuevo"]
    assert {r["key"]: (r["online"], r["nuevo"]) for r in rows} == {
        mac: (True, False), "CC-CC-CC-CC-CC-CC": (True, True), "AA-AA-AA-AA-AA-AA": (False, False)}  # misma IP, dos filas

    assert web_url("1.1.1.1", [443, 8080]) == "https://1.1.1.1" and web_url("1.1.1.1", None) == "http://1.1.1.1"
    assert port_text([80, 9100]) == "80 HTTP, 9100 Impresora" and port_text(None) == ""
    assert csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)" and csv_safe("nas") == "nas" and csv_safe(True) is True

    # conexiones y riesgo
    table = """
  TCP    192.168.1.5:50000      142.250.1.1:443        ESTABLISHED     1234
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    [::1]:5000             [::1]:5001             ESTABLISHED     7
  UDP    0.0.0.0:500            *:*                                    1080
"""
    a, b, c, d = parse_netstat(table)
    assert (a["rip"], a["rport"], a["estado"], a["pid"]) == ("142.250.1.1", 443, "ESTABLISHED", 1234)
    assert (b["rip"], b["lport"]) == ("", 445) and c["lip"] == "::1" and (d["proto"], d["estado"], d["rip"]) == ("UDP", "", "")
    conn = lambda **k: {"rip": "8.8.8.8", "rport": 443, "lip": "192.168.1.5", "lport": 5000, "proceso": "a.exe", "ruta": r"C:\Apps\a.exe", **k}
    assert classify(conn(), "Valid", {})[0] == "Segura"
    assert classify(conn(), "", {})[0] == "Desconocida"
    assert classify(conn(), "NotSigned", {})[0] == "Revisar"
    assert classify(conn(), "HashMismatch", {})[0] == "Peligrosa"
    assert classify(conn(rport=4444), "Valid", {})[0] == "Peligrosa"
    assert classify(conn(rport=80), "Valid", {})[0] == "Revisar"
    assert classify(conn(ruta=r"C:\Users\x\Downloads\a.exe"), "NotSigned", {})[0] == "Peligrosa"
    assert classify(conn(proceso="svchost.exe", ruta=r"C:\Users\x\svchost.exe"), "Valid", {})[0] == "Peligrosa"
    assert classify(conn(proceso="svchost.exe", ruta=r"C:\Windows\System32\svchost.exe"), "Valid", {})[0] == "Segura"
    assert classify(conn(rip="", rport=0, lip="0.0.0.0", lport=3389), "Valid", {})[0] == "Revisar"
    assert classify(conn(rport=4444, rip="127.0.0.1"), "Valid", {})[0] == "Segura"
    assert classify(conn(rport=4444), "Valid", {"confianza": ["8.8.8.8"]})[0] == "Segura"  # tus listas mandan
    assert classify(conn(), "Valid", {"bloqueo": ["8.8.8.8"]})[0] == "Peligrosa"
    try:
        cut_tcp({"proto": "UDP", "lip": "1.1.1.1", "rip": "", "lport": 1, "rport": 0})
        raise AssertionError
    except RuntimeError:
        pass

    # Wi-Fi, en los dos idiomas de netsh
    wifi = """
SSID 1 : Casa
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Señal              : 40%
    BSSID 2                 : aa:bb:cc:dd:ee:00
         Señal              : 81%
SSID 2 : Libre
    Authentication          : Open
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 90%
"""
    assert parse_wifi(wifi) == [{"ssid": "Libre", "seguridad": "Open", "señal": 90},
                                {"ssid": "Casa", "seguridad": "WPA2-Personal", "señal": 81}]
    assert parse_profiles("    Perfil de todos los usuarios : Casa 5G\n    All User Profile     : Otra") == ["Casa 5G", "Otra"]
    assert (wifi_risk("WPA2-Personal"), wifi_risk("Open"), wifi_risk("WEP"), wifi_risk("WPA-Personal")) == ("ok", "bad", "bad", "warn")

    # entradas que acaban en órdenes del sistema
    assert parse_static("192.168.1.50/24 192.168.1.1") == ("192.168.1.50", 24, "192.168.1.1")
    for bad in ("192.168.1.50 192.168.1.1", "192.168.1.50/24 10.0.0.1", "192.168.1.1/24 192.168.1.1", "x y", "uno"):
        try:
            parse_static(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    assert valid_host("router.lan") == "router.lan"
    for bad in ("-n 5", "a b", "a&calc", ""):
        try:
            valid_host(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    assert isinstance(if_counters(), dict) and human_rate(1500) == "2 KB/s" and human_size(2_500_000_000) == "2.50 GB"
    assert signatures([sys.executable])[sys.executable] == "Valid"
    rows = connections()
    assert all(c["id"] and c["proceso"] for c in rows) and len({c["id"] for c in rows}) == len(rows)

    # guardar es atómico y un archivo dañado no se pierde
    DB_FILE = Path(tempfile.mkdtemp(), "dispositivos.json")
    save_db({"a": 1})
    assert load_db() == {"a": 1}
    DB_FILE.write_text("{roto", encoding="utf-8")
    assert load_db() == {} and DB_FILE.with_suffix(".dañado.json").exists()
    print("ok")


if __name__ == "__main__":
    if "--test" in sys.argv:
        self_test()
    elif "--scan" in sys.argv:
        for i in interfaces():
            print(f"== {i['alias']} {i['ip']}/{i['prefix']}")
            for r in scan(i):
                print(f"{r['ip']:16}{r['mac']:20}{'ping' if r['ping'] else '    '}  {r['tipo']:40}{r['nombre']}")
            if lan_blocked(i):
                print(BLOCKED_TEXT)
    else:
        import tkinter as tk
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        mutex = k32.CreateMutexW(None, False, "Local\\EscanerDeRed")  # vive hasta que el proceso termina
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS: ya hay una abierta (quizá en la bandeja)
            from tkinter import messagebox
            tk.Tk().withdraw()
            messagebox.showinfo("Escáner de red", "Ya está abierto: búscalo en la bandeja del sistema, junto al reloj.")
            sys.exit()
        root = tk.Tk()
        App(root, mutex)
        root.mainloop()
