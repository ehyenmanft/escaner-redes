"""Escáner de red local para Windows (Python + tkinter, sin dependencias).

Uso:
  python escaner_red.py          abre la app
  python escaner_red.py --scan   escanea y muestra el resultado en consola
  python escaner_red.py --test   pruebas rápidas
"""
import csv
import ipaddress
import json
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW: que ping/arp no abran consolas
DB_FILE = Path(__file__).with_name("dispositivos.json")
MAC_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", re.I)
PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 139: "NetBIOS",
         443: "HTTPS", 445: "SMB", 554: "RTSP (cámara)", 1883: "MQTT", 3389: "Escritorio remoto",
         5000: "UPnP/NAS", 8008: "Chromecast", 8080: "HTTP alt", 8443: "HTTPS alt", 9100: "Impresora",
         62078: "iPhone/iPad"}


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                          creationflags=NO_WINDOW).stdout


def interfaces():
    """Interfaces con puerta de enlace: alias, ip, prefijo, gateway, mac y tipo (Wi-Fi/Ethernet)."""
    ps = ("Get-NetIPConfiguration | ? IPv4DefaultGateway | % { $a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex; "
          "[pscustomobject]@{alias=$_.InterfaceAlias; ip=$_.IPv4Address[0].IPAddress; prefix=$_.IPv4Address[0].PrefixLength; "
          "gw=$_.IPv4DefaultGateway[0].NextHop; mac=$a.MacAddress; medio=$a.PhysicalMediaType} } | ConvertTo-Json")
    out = run(["powershell", "-NoProfile", "-Command", ps]).strip()
    if not out:
        return []
    data = json.loads(out)
    data = data if isinstance(data, list) else [data]
    # VPNs con gateway 0.0.0.0 no son una LAN que escanear
    return [d for d in data if d["gw"] != "0.0.0.0" and d["prefix"] < 32]


def ping(ip):
    return "TTL=" in run(["ping", "-n", "1", "-w", "600", ip]).upper()


def parse_arp(text, net):
    """Devuelve {ip: mac} de la salida de `arp -a`, solo de la red dada y sin broadcast/multicast."""
    found = {}
    for ip, mac in MAC_RE.findall(text):
        mac = mac.upper()
        if ipaddress.ip_address(ip) in net and ip != str(net.broadcast_address) \
                and mac != "FF-FF-FF-FF-FF-FF" and not mac.startswith("01-00-5E"):
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


def guess_type(ip, mac, iface):
    if ip == iface["gw"]:
        return "Router"
    if ip == iface["ip"]:
        medio = "Wi-Fi" if "802.11" in (iface["medio"] or "") else "cable" if iface["medio"] == "802.3" else iface["alias"]
        return f"Este PC ({medio})"
    if is_random_mac(mac):
        return "Inalámbrico (probable: móvil/tablet)"
    return "Desconocido"


def scan(iface, progress=lambda done, total: None):
    net = ipaddress.ip_network(f"{iface['ip']}/{iface['prefix']}", strict=False)
    # shortcut: tope de 1022 hosts (/22); redes mayores necesitarían un escaneo por bloques
    hosts = [str(h) for h in net.hosts()][:1022]
    alive, done = set(), 0
    with ThreadPoolExecutor(64) as pool:
        for ip, ok in zip(hosts, pool.map(ping, hosts)):
            done += 1
            if ok:
                alive.add(ip)
            if done % 16 == 0:
                progress(done, len(hosts))
    arp = parse_arp(run(["arp", "-a"]), net)  # dispositivos que bloquean ping pero sí responden ARP
    arp[iface["ip"]] = iface["mac"].upper()
    ips = sorted(alive | set(arp), key=ipaddress.ip_address)
    with ThreadPoolExecutor(32) as pool:
        names = list(pool.map(hostname, ips))
    return [{"ip": ip, "mac": arp.get(ip, ""), "ping": ip in alive, "nombre": n,
             "tipo": guess_type(ip, arp.get(ip, ""), iface)} for ip, n in zip(ips, names)]


def scan_ports(ip):
    def check(port):
        with socket.socket() as s:
            s.settimeout(0.6)
            return port if s.connect_ex((ip, port)) == 0 else None
    with ThreadPoolExecutor(len(PORTS)) as pool:
        return [p for p in pool.map(check, PORTS) if p]


def vendor(mac):
    """Fabricante por MAC (envía solo los 3 primeros bytes a api.macvendors.com)."""
    try:
        with urllib.request.urlopen(f"https://api.macvendors.com/{mac[:8]}", timeout=5) as r:
            return r.read().decode()
    except Exception:
        return ""


def load_db():
    try:
        return json.loads(DB_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_db(db):
    DB_FILE.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------- interfaz
class App:
    COLS = ("estado", "ip", "mac", "alias", "nombre", "fabricante", "tipo", "ping", "visto")
    HEAD = ("", "IP", "MAC", "Alias", "Nombre de red", "Fabricante", "Tipo", "Ping", "Primera vez")

    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk, self.root = tk, ttk, root
        self.db, self.rows, self.q, self.busy = load_db(), [], queue.Queue(), False
        root.title("Escáner de red")
        root.geometry("1150x560")

        bar = ttk.Frame(root, padding=6)
        bar.pack(fill="x")
        self.ifaces = interfaces()
        self.iface_var = tk.StringVar()
        names = [f"{i['alias']} – {i['ip']}/{i['prefix']}" for i in self.ifaces]
        ttk.Combobox(bar, textvariable=self.iface_var, values=names, state="readonly", width=34).pack(side="left")
        if names:
            self.iface_var.set(names[0])
        for text, cmd in (("Escanear", self.start_scan), ("Fabricantes", self.lookup_vendors),
                          ("Puertos", self.ports), ("Abrir web", self.open_web),
                          ("Renombrar", self.rename), ("Exportar CSV", self.export)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=3)
        self.watch = tk.BooleanVar()
        ttk.Checkbutton(bar, text="Vigilar cada 5 min", variable=self.watch,
                        command=self.watch_tick).pack(side="left", padx=8)

        self.tree = ttk.Treeview(root, columns=self.COLS, show="headings")
        for c, h in zip(self.COLS, self.HEAD):
            self.tree.heading(c, text=h, command=lambda c=c: self.sort(c))
            self.tree.column(c, width=60 if c in ("estado", "ping") else 130)
        self.tree.tag_configure("nuevo", background="#fff3c4")
        self.tree.tag_configure("off", foreground="#999")
        self.tree.pack(fill="both", expand=True, padx=6)
        self.tree.bind("<Double-1>", lambda e: self.rename())

        self.status = tk.StringVar(value="Listo." if names else "No se encontró ninguna red con puerta de enlace.")
        ttk.Label(root, textvariable=self.status, padding=6).pack(fill="x")
        self.poll()

    # tkinter no es seguro entre hilos: los hilos encolan funciones y el hilo de la UI las ejecuta
    def poll(self):
        while not self.q.empty():
            self.q.get()()
        self.root.after(100, self.poll)

    def ui(self, fn):
        self.q.put(fn)

    def background(self, fn):
        threading.Thread(target=fn, daemon=True).start()

    def selected(self):
        sel = self.tree.selection()
        if not sel:
            self.status.set("Selecciona un dispositivo de la lista.")
            return None
        return next(r for r in self.rows if r["ip"] == sel[0])

    def start_scan(self, alert=False):
        if self.busy or not self.ifaces:
            return
        self.busy = True
        iface = self.ifaces[[f"{i['alias']} – {i['ip']}/{i['prefix']}" for i in self.ifaces].index(self.iface_var.get())]

        def work():
            res = scan(iface, lambda d, t: self.ui(lambda: self.status.set(f"Escaneando… {d}/{t}")))
            self.ui(lambda: self.show(res, alert))
        self.background(work)

    def show(self, res, alert):
        now, new = datetime.now().strftime("%Y-%m-%d %H:%M"), []
        seen = set()
        for r in res:
            key = r["mac"] or r["ip"]
            seen.add(key)
            if key not in self.db:
                self.db[key] = {"alias": "", "fabricante": "", "visto": now}
                new.append(r)
            r.update(self.db[key], online=True, nuevo=r in new)
            self.db[key].update(ultimo=now, ip=r["ip"])
        # dispositivos conocidos que ya no responden, en gris
        for key, d in self.db.items():
            if key not in seen and d.get("ip"):
                res.append({"ip": d["ip"], "mac": key if "-" in key else "", "ping": False, "nombre": "",
                            "tipo": "Desconectado", "online": False, "nuevo": False, **d})
        save_db(self.db)
        self.rows = res
        self.refresh()
        online = sum(r["online"] for r in res)
        self.status.set(f"{online} dispositivos conectados, {len(new)} nuevos. Último escaneo {now}.")
        self.busy = False
        if alert and new:
            from tkinter import messagebox
            messagebox.showwarning("Dispositivo nuevo", "\n".join(f"{r['ip']}  {r['mac']}" for r in new))

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for r in self.rows:
            if self.tree.exists(r["ip"]):
                continue  # un desconectado con la IP que ahora tiene otro equipo
            tag = "nuevo" if r["nuevo"] else ("" if r["online"] else "off")
            self.tree.insert("", "end", iid=r["ip"], tags=(tag,), values=(
                "NUEVO" if r["nuevo"] else ("●" if r["online"] else "○"), r["ip"], r["mac"], r.get("alias", ""),
                r["nombre"], r.get("fabricante", ""), r["tipo"], "sí" if r["ping"] else "no", r.get("visto", "")))

    def sort(self, col):
        key = (lambda r: ipaddress.ip_address(r["ip"])) if col == "ip" else (lambda r: str(r.get(col, "")))
        self.rows.sort(key=key)
        self.refresh()

    def lookup_vendors(self):
        todo = [r for r in self.rows if r["mac"] and not r.get("fabricante") and not is_random_mac(r["mac"])]
        if not todo:
            self.status.set("No hay fabricantes pendientes (las MAC aleatorias no tienen fabricante).")
            return

        def work():
            for i, r in enumerate(todo):
                v = vendor(r["mac"]) or "?"
                self.db[r["mac"]]["fabricante"] = r["fabricante"] = v
                self.ui(lambda i=i: self.status.set(f"Fabricantes {i + 1}/{len(todo)}…"))
                time.sleep(1.1)  # la API gratuita admite 1 consulta por segundo
            save_db(self.db)
            self.ui(lambda: (self.refresh(), self.status.set("Fabricantes actualizados.")))
        self.background(work)

    def ports(self):
        r = self.selected()
        if not r:
            return
        self.status.set(f"Buscando puertos abiertos en {r['ip']}…")

        def work():
            found = scan_ports(r["ip"])
            txt = ", ".join(f"{p} ({PORTS[p]})" for p in found) or "ninguno de los comunes"
            self.ui(lambda: self.status.set(f"Puertos abiertos en {r['ip']}: {txt}"))
        self.background(work)

    def open_web(self):
        r = self.selected()
        if r:
            webbrowser.open(f"http://{r['ip']}")

    def rename(self):
        from tkinter import simpledialog
        r = self.selected()
        if not r:
            return
        key = r["mac"] or r["ip"]
        name = simpledialog.askstring("Renombrar", f"Alias para {r['ip']}:", initialvalue=r.get("alias", ""))
        if name is not None and key in self.db:
            self.db[key]["alias"] = r["alias"] = name.strip()
            save_db(self.db)
            self.refresh()

    def export(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        fields = ["ip", "mac", "alias", "nombre", "fabricante", "tipo", "ping", "online", "visto", "ultimo"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fields, extrasaction="ignore", delimiter=";")
            w.writeheader()
            w.writerows(self.rows)
        self.status.set(f"Exportado a {path}")

    def watch_tick(self):
        if self.watch.get():
            self.start_scan(alert=True)
            self.root.after(5 * 60 * 1000, self.watch_tick)


def self_test():
    net = ipaddress.ip_network("192.168.0.0/24")
    sample = """
  192.168.0.1           00-11-22-33-44-55     dinámico
  192.168.0.104         fe-12-34-56-78-9a     dinámico
  192.168.0.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  10.0.0.5              aa-bb-cc-dd-ee-ff     dinámico
"""
    assert parse_arp(sample, net) == {"192.168.0.1": "00-11-22-33-44-55", "192.168.0.104": "FE-12-34-56-78-9A"}
    assert is_random_mac("FE-12-34-56-78-9A") and not is_random_mac("00-AA-BB-CC-DD-EE")
    iface = {"ip": "192.168.0.102", "gw": "192.168.0.1", "medio": "802.3", "alias": "Ethernet"}
    assert guess_type("192.168.0.1", "", iface) == "Router"
    assert guess_type("192.168.0.104", "FE-12-34-56-78-9A", iface).startswith("Inalámbrico")
    print("ok")


if __name__ == "__main__":
    if "--test" in sys.argv:
        self_test()
    elif "--scan" in sys.argv:
        for i in interfaces():
            print(f"== {i['alias']} {i['ip']}/{i['prefix']}")
            for r in scan(i):
                print(f"{r['ip']:16}{r['mac']:20}{'ping' if r['ping'] else '    '}  {r['tipo']:40}{r['nombre']}")
    else:
        import tkinter as tk
        root = tk.Tk()
        App(root)
        root.mainloop()
