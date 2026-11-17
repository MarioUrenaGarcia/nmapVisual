"""Gestor de escaneos nmap con salida progresiva, parseo incremental de XML y diagnostico."""

import json
import os
import queue
import re
import shlex
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import nmap_utils

# Expresiones para leer en vivo la salida detallada de nmap.
RE_DISCOVERED = re.compile(r"Discovered open port (\d+)/(\w+) on ([0-9a-fA-F:.]+)")
RE_PROGRESS = re.compile(r"About ([\d.]+)% done")
RE_REMAINING = re.compile(r"\(([\d:]+) remaining\)")
RE_TASK = re.compile(r"^(.+?) Timing:")
RE_REPORT = re.compile(r"Nmap scan report for (.+)")
RE_MAC = re.compile(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\(([^)]*)\))?")
RE_HOST_UP = re.compile(r"Host is up")
RE_HOST_BLOCK = re.compile(r"<host\b.*?</host>", re.DOTALL)


def _now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# Flags de los argumentos del usuario que tambien tienen sentido en la fase de
# descubrimiento del modo secuencial (resolucion DNS, sondas de ping, velocidad...).
_DISC_PREFIXES = ("-PS", "-PA", "-PU", "-PO", "-PY", "-PE", "-PP", "-PM", "-PR", "-Pn")
_DISC_SINGLE = {"-n", "-R", "-6", "--system-dns", "--disable-arp-ping"}
_DISC_PAIR = {
    "--dns-servers", "--max-retries", "--host-timeout", "--min-rate", "--max-rate",
    "-e", "-S", "-g", "--source-port", "--scan-delay", "--max-rtt-timeout",
}
_RE_TIMING = re.compile(r"^-T[0-5]$")


def _discovery_args(tokens):
    """Extrae de los argumentos del usuario los flags utiles para el descubrimiento."""
    out = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in _DISC_SINGLE or _RE_TIMING.match(t) or any(t.startswith(p) for p in _DISC_PREFIXES):
            out.append(t)
        elif t in _DISC_PAIR:
            out.append(t)
            if i + 1 < len(tokens):
                out.append(tokens[i + 1])
                i += 1
        i += 1
    return out


class Scan:
    def __init__(self, scan_id, target, args, command, output_base, project="General"):
        self.id = scan_id
        self.target = target
        self.args = args
        self.command = command
        self.output_base = output_base
        self.project = project or "General"
        self.sequential = False
        self.status = "queued"  # queued | running | done | failed | cancelled
        self.start_time = None
        self.end_time = None
        self.returncode = None
        self.summary = ""

        self.process = None
        self.hosts = {}  # ip -> dict
        self.log = []  # lista de {seq, line}
        self.diagnostics = []  # lista de dicts de diagnostico
        self.progress = {"percent": 0.0, "task": "", "remaining": ""}

        self._seq = 0
        self._subscribers = []
        self._lock = threading.Lock()
        self._diag_seen = set()
        self._last_report_ip = None
        self._seq_mode = False

    # ---------- publicacion de eventos ----------

    def add_subscriber(self):
        q = queue.Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def remove_subscriber(self, q):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _emit(self, event):
        with self._lock:
            self._seq += 1
            event["seq"] = self._seq
            subs = list(self._subscribers)
        for q in subs:
            q.put(event)

    def _add_log(self, line):
        entry = {"line": line}
        with self._lock:
            self._seq += 1
            entry["seq"] = self._seq
            self.log.append(entry)
            if len(self.log) > 5000:
                self.log = self.log[-5000:]
            subs = list(self._subscribers)
        event = {"type": "log", "seq": entry["seq"], "line": line}
        for q in subs:
            q.put(event)

    def snapshot(self):
        with self._lock:
            return {
                "type": "snapshot",
                "seq": self._seq,
                "id": self.id,
                "status": self.status,
                "target": self.target,
                "args": self.args,
                "command": self.command,
                "startTime": self.start_time,
                "endTime": self.end_time,
                "summary": self.summary,
                "progress": dict(self.progress),
                "hosts": list(self.hosts.values()),
                "log": [dict(x) for x in self.log],
                "diagnostics": list(self.diagnostics),
            }

    def meta(self):
        with self._lock:
            up = sum(1 for h in self.hosts.values() if h.get("status") == "up")
            open_ports = sum(
                1
                for h in self.hosts.values()
                for p in h.get("ports", [])
                if p.get("state") == "open"
            )
            return {
                "id": self.id,
                "target": self.target,
                "args": self.args,
                "command": self.command,
                "project": self.project,
                "status": self.status,
                "startTime": self.start_time,
                "endTime": self.end_time,
                "summary": self.summary,
                "hostsUp": up,
                "hostCount": len(self.hosts),
                "openPorts": open_ports,
            }

    # ---------- diagnostico ----------

    def _check_diag(self, line):
        diag = nmap_utils.diagnose_line(line)
        if not diag:
            return
        key = (diag["title"], diag["source"])
        with self._lock:
            if key in self._diag_seen:
                return
            self._diag_seen.add(key)
            self.diagnostics.append(diag)
        self._emit({"type": "diagnostic", **diag})

    # ---------- parseo de salida en vivo ----------

    def _handle_line(self, line):
        self._add_log(line)
        self._check_diag(line)

        m = RE_DISCOVERED.search(line)
        if m:
            port, proto, ip = m.group(1), m.group(2), m.group(3)
            self._upsert_port(ip, port, proto, "open")

        m = RE_PROGRESS.search(line)
        if m and not self._seq_mode:
            percent = float(m.group(1))
            task = ""
            tmatch = RE_TASK.search(line)
            if tmatch:
                task = tmatch.group(1).strip()
            remaining = ""
            rmatch = RE_REMAINING.search(line)
            if rmatch:
                remaining = rmatch.group(1)
            with self._lock:
                self.progress = {"percent": percent, "task": task, "remaining": remaining}
            self._emit({"type": "progress", "percent": percent, "task": task, "remaining": remaining})

        m = RE_REPORT.search(line)
        if m:
            label = m.group(1).strip()
            ip = self._ip_from_label(label)
            if ip:
                self._last_report_ip = ip
                # No creamos tarjeta para equipos que nmap marca como apagados.
                if "down" not in line.lower():
                    self._ensure_host(ip, label)

        if RE_HOST_UP.search(line) and self._last_report_ip:
            self._mark_up(self._last_report_ip)

        m = RE_MAC.search(line)
        if m and self._last_report_ip:
            self._set_mac(self._last_report_ip, m.group(1), (m.group(2) or "").strip())

    def _ip_from_label(self, label):
        # Formatos tipico: "scanme.nmap.org (45.33.32.156)" o "192.168.1.1"
        m = re.search(r"\(([0-9a-fA-F:.]+)\)", label)
        if m:
            return m.group(1)
        token = label.split()[0] if label.split() else ""
        if re.match(r"^[0-9a-fA-F:.]+$", token):
            return token
        return token or None

    def _ensure_host(self, ip, label=None):
        with self._lock:
            host = self.hosts.get(ip)
            if host is None:
                host = {
                    "ip": ip,
                    "hostname": "",
                    "status": "unknown",
                    "ports": [],
                    "os": "",
                    "mac": "",
                    "vendor": "",
                }
                self.hosts[ip] = host
                new = True
            else:
                new = False
            if label and "(" in label:
                name = label.split("(")[0].strip()
                if name and not host["hostname"]:
                    host["hostname"] = name
            snap = dict(host)
            snap["ports"] = list(host["ports"])
        if new:
            self._emit({"type": "host", "host": snap})
        return snap

    def _mark_up(self, ip):
        self._ensure_host(ip)
        with self._lock:
            host = self.hosts[ip]
            if host["status"] == "up":
                return
            host["status"] = "up"
            snap = dict(host)
            snap["ports"] = [dict(p) for p in host["ports"]]
        self._emit({"type": "host", "host": snap})

    def _set_mac(self, ip, mac, vendor):
        self._ensure_host(ip)
        with self._lock:
            host = self.hosts[ip]
            host["mac"] = mac
            if vendor:
                host["vendor"] = vendor
            if host["status"] == "unknown":
                host["status"] = "up"
            snap = dict(host)
            snap["ports"] = [dict(p) for p in host["ports"]]
        self._emit({"type": "host", "host": snap})

    def _upsert_port(self, ip, port, proto, state, service=None):
        self._ensure_host(ip)
        with self._lock:
            host = self.hosts[ip]
            if host["status"] == "unknown":
                host["status"] = "up"
            existing = None
            for p in host["ports"]:
                if p["port"] == str(port) and p["proto"] == proto:
                    existing = p
                    break
            if existing is None:
                existing = {"port": str(port), "proto": proto, "state": state, "service": service or "", "product": "", "version": ""}
                host["ports"].append(existing)
                host["ports"].sort(key=lambda x: (x["proto"], int(x["port"])))
            else:
                existing["state"] = state
                if service:
                    existing["service"] = service
            snap = dict(host)
            snap["ports"] = [dict(p) for p in host["ports"]]
        self._emit({"type": "host", "host": snap})

    # ---------- parseo incremental de XML ----------

    def parse_xml_hosts(self, path=None):
        """Lee el XML parcial y actualiza los hosts con datos estructurados completos."""
        path = path or (self.output_base + ".xml")
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return

        for block in RE_HOST_BLOCK.findall(content):
            try:
                el = ET.fromstring(block)
            except ET.ParseError:
                continue
            self._merge_host_element(el)

    def _merge_host_element(self, el):
        ip = ""
        mac = ""
        vendor = ""
        hostname = ""
        for addr in el.findall("address"):
            atype = addr.get("addrtype")
            if atype in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
            elif atype == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        if not ip:
            for addr in el.findall("address"):
                ip = addr.get("addr", "")
                break
        if not ip:
            return

        hn = el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        status_el = el.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        # Los equipos apagados no aportan nada y, en una red grande, llenan la vista
        # de tarjetas vacias. Solo nos quedamos con los que estan activos.
        if status == "down":
            with self._lock:
                self.hosts.pop(ip, None)
            return

        ports = []
        for p in el.findall("ports/port"):
            state_el = p.find("state")
            svc_el = p.find("service")
            port_scripts = []
            for scr in p.findall("script"):
                port_scripts.append({"id": scr.get("id", ""), "output": scr.get("output", "")})
            cpe = ""
            if svc_el is not None:
                cpe = ", ".join(c.text for c in svc_el.findall("cpe") if c.text)
            ports.append(
                {
                    "port": p.get("portid", ""),
                    "proto": p.get("protocol", ""),
                    "state": state_el.get("state") if state_el is not None else "",
                    "reason": state_el.get("reason", "") if state_el is not None else "",
                    "service": svc_el.get("name", "") if svc_el is not None else "",
                    "product": svc_el.get("product", "") if svc_el is not None else "",
                    "version": svc_el.get("version", "") if svc_el is not None else "",
                    "extrainfo": svc_el.get("extrainfo", "") if svc_el is not None else "",
                    "cpe": cpe,
                    "scripts": port_scripts,
                }
            )
        ports.sort(key=lambda x: (x["proto"], int(x["port"]) if x["port"].isdigit() else 0))

        os_name = ""
        osmatch = el.find("os/osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name", "")
            acc = osmatch.get("accuracy", "")
            if acc:
                os_name = f"{os_name} ({acc}%)"

        scripts = []
        for scr in el.findall("hostscript/script"):
            scripts.append({"id": scr.get("id", ""), "output": scr.get("output", "")})

        with self._lock:
            prev = self.hosts.get(ip, {})
            host = {
                "ip": ip,
                "hostname": hostname or prev.get("hostname", ""),
                "status": status,
                "ports": ports if ports else prev.get("ports", []),
                "os": os_name or prev.get("os", ""),
                "mac": mac or prev.get("mac", ""),
                "vendor": vendor or prev.get("vendor", ""),
                "scripts": scripts or prev.get("scripts", []),
            }
            # El sondeo del XML corre cada 2s sobre todos los hosts. Si este host no
            # cambio desde la ultima vez, no reemitimos nada: asi evitamos inundar
            # el stream y que la interfaz se sature con una red grande.
            if prev == host:
                return
            self.hosts[ip] = host
            snap = dict(host)
            snap["ports"] = [dict(p) for p in host["ports"]]
        self._emit({"type": "host", "host": snap})


class ScanManager:
    def __init__(self, nmap_path, scans_dir):
        self.nmap_path = nmap_path
        self.scans_dir = scans_dir
        self.scans = {}
        self._lock = threading.Lock()
        os.makedirs(scans_dir, exist_ok=True)
        self._load_history()

    # ---------- historial ----------

    def _load_history(self):
        for name in os.listdir(self.scans_dir):
            if not name.endswith(".meta.json"):
                continue
            path = os.path.join(self.scans_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            scan_id = meta.get("id")
            if not scan_id:
                continue
            target = meta.get("target", "")
            args = meta.get("args", "")
            command = meta.get("command", "")
            clean = nmap_utils.strip_nmap_prefix(args)
            if clean != args:
                # Metadatos con restos de la ruta de nmap: se corrigen en memoria
                # para mostrar y copiar un comando valido, sin reescribir el archivo.
                args = clean
                command = " ".join(x for x in ("nmap", args, target) if x)
            scan = Scan(
                scan_id,
                target,
                args,
                command,
                os.path.join(self.scans_dir, scan_id),
            )
            scan.project = meta.get("project", "General")
            scan.status = meta.get("status", "done")
            if scan.status in ("running", "queued"):
                scan.status = "done"
            scan.start_time = meta.get("startTime")
            scan.end_time = meta.get("endTime")
            scan.summary = meta.get("summary", "")
            # Preferimos los equipos guardados en vivo (incluye los de escaneos
            # detenidos); si no existen, reconstruimos desde el XML.
            hosts_path = os.path.join(self.scans_dir, scan_id + ".hosts.json")
            loaded = False
            if os.path.isfile(hosts_path):
                try:
                    with open(hosts_path, "r", encoding="utf-8") as f:
                        saved = json.load(f)
                    scan.hosts = {h["ip"]: h for h in saved if isinstance(h, dict) and h.get("ip")}
                    loaded = True
                except (OSError, json.JSONDecodeError):
                    loaded = False
            if not loaded:
                try:
                    scan.parse_xml_hosts()
                except Exception:
                    pass
            self.scans[scan_id] = scan

    def _write_meta(self, scan):
        path = os.path.join(self.scans_dir, scan.id + ".meta.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(scan.meta(), f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ---------- ciclo de vida ----------

    def clear_history(self):
        """Borra los escaneos guardados y sus archivos, salvo los que esten en curso."""
        with self._lock:
            ids = list(self.scans.keys())
        removed = 0
        for sid in ids:
            scan = self.scans.get(sid)
            if scan and scan.status == "running":
                continue
            for ext in (".xml", ".nmap", ".gnmap", ".meta.json", ".hosts.json"):
                try:
                    os.remove(os.path.join(self.scans_dir, sid + ext))
                except OSError:
                    pass
            with self._lock:
                self.scans.pop(sid, None)
            removed += 1
        return removed

    def list_scans(self):
        with self._lock:
            scans = list(self.scans.values())
        metas = [s.meta() for s in scans]
        metas.sort(key=lambda m: m.get("startTime") or "", reverse=True)
        return metas

    def get(self, scan_id):
        return self.scans.get(scan_id)

    def set_project(self, scan_id, project):
        """Reasigna un escaneo a otro proyecto y persiste el cambio."""
        scan = self.scans.get(scan_id)
        if not scan:
            return False
        scan.project = (project or "General").strip() or "General"
        self._write_meta(scan)
        return True

    def build_command(self, target, args):
        try:
            arg_tokens = shlex.split(args, posix=False) if args else []
        except ValueError:
            arg_tokens = args.split()
        target_tokens = target.split()
        scan_id = uuid.uuid4().hex[:12]
        output_base = os.path.join(self.scans_dir, scan_id)
        cmd = [self.nmap_path] + arg_tokens
        cmd += ["-v", "--stats-every", "2s", "-oA", output_base]
        cmd += target_tokens
        return scan_id, output_base, cmd

    def start(self, target, args, project="General", sequential=False):
        target = (target or "").strip()
        if not target:
            raise ValueError("Debes indicar al menos un objetivo.")
        args = nmap_utils.strip_nmap_prefix(args)
        scan_id, output_base, cmd = self.build_command(target, args)
        display = " ".join(["nmap"] + ([args.strip()] if args.strip() else []) + [target])
        scan = Scan(scan_id, target, args, display, output_base, project)
        scan.sequential = bool(sequential)
        with self._lock:
            self.scans[scan_id] = scan
        if scan.sequential:
            thread = threading.Thread(target=self._run_sequential, args=(scan,), daemon=True)
        else:
            thread = threading.Thread(target=self._run, args=(scan, cmd), daemon=True)
        thread.start()
        return scan

    def _run(self, scan, cmd):
        scan.status = "running"
        scan.start_time = _now_iso()
        scan._emit({"type": "status", "status": "running", "startTime": scan.start_time})
        self._write_meta(scan)

        try:
            scan.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=nmap_utils._no_window_flag(),
            )
        except FileNotFoundError:
            scan.status = "failed"
            scan.summary = "No se encontro el ejecutable de nmap."
            scan.end_time = _now_iso()
            scan._emit({"type": "done", "status": "failed", "summary": scan.summary})
            self._write_meta(scan)
            return
        except Exception as exc:
            scan.status = "failed"
            scan.summary = f"No se pudo iniciar nmap: {exc}"
            scan.end_time = _now_iso()
            scan._emit({"type": "done", "status": "failed", "summary": scan.summary})
            self._write_meta(scan)
            return

        stop_poll = threading.Event()
        poller = threading.Thread(target=self._poll_xml, args=(scan, stop_poll), daemon=True)
        poller.start()
        watchdog = threading.Thread(target=self._speed_watchdog, args=(scan, stop_poll), daemon=True)
        watchdog.start()

        try:
            for line in scan.process.stdout:
                scan._handle_line(line.rstrip("\n"))
        except Exception:
            pass

        scan.returncode = scan.process.wait()
        stop_poll.set()
        poller.join(timeout=5)

        # Parseo final completo para asegurar que no falte nada.
        try:
            scan.parse_xml_hosts()
        except Exception:
            pass

        scan.end_time = _now_iso()
        if scan.status == "cancelled":
            up = sum(1 for h in scan.hosts.values() if h.get("status") == "up")
            openp = sum(1 for h in scan.hosts.values() for p in h.get("ports", []) if p.get("state") == "open")
            scan.summary = f"Detenido. Se conservan los {up} equipo(s) y {openp} puerto(s) abiertos encontrados hasta aqui."
        elif scan.returncode == 0:
            scan.status = "done"
            up = sum(1 for h in scan.hosts.values() if h.get("status") == "up")
            scan.summary = f"Completado. {up} host(s) activos de {len(scan.hosts)} analizados."
            self._final_advice(scan)
        else:
            scan.status = "failed"
            up = sum(1 for h in scan.hosts.values() if h.get("status") == "up")
            scan.summary = f"nmap termino con codigo {scan.returncode}. Se muestran los {up} equipo(s) encontrados."

        # Guarda en disco los equipos encontrados (en vivo + XML) para que, aunque
        # se haya detenido y el XML quedara incompleto, se vean igual al recargar.
        self._persist_hosts(scan)
        scan._emit({
            "type": "done",
            "status": scan.status,
            "summary": scan.summary,
            "endTime": scan.end_time,
        })
        self._write_meta(scan)

    def _persist_hosts(self, scan):
        path = os.path.join(self.scans_dir, scan.id + ".hosts.json")
        try:
            with scan._lock:
                hosts = []
                for h in scan.hosts.values():
                    hc = dict(h)
                    hc["ports"] = [dict(p) for p in h.get("ports", [])]
                    hosts.append(hc)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(hosts, f, ensure_ascii=False)
        except OSError:
            pass

    def _poll_xml(self, scan, stop_event):
        while not stop_event.is_set():
            time.sleep(2)
            try:
                scan.parse_xml_hosts()
            except Exception:
                pass

    # ---------- modo secuencial (un nmap por equipo) ----------

    def _run_capture(self, scan, cmd):
        """Lanza un nmap, vuelca su salida al parseo en vivo y espera a que acabe."""
        try:
            scan.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, creationflags=nmap_utils._no_window_flag(),
            )
        except Exception as exc:
            scan._add_log(f"No se pudo lanzar nmap: {exc}")
            return 1
        try:
            for line in scan.process.stdout:
                scan._handle_line(line.rstrip("\n"))
        except Exception:
            pass
        return scan.process.wait()

    def _emit_progress(self, scan, percent, task, remaining):
        with scan._lock:
            scan.progress = {"percent": percent, "task": task, "remaining": remaining}
        scan._emit({"type": "progress", "percent": percent, "task": task, "remaining": remaining})

    def _run_sequential(self, scan):
        scan._seq_mode = True
        scan.status = "running"
        scan.start_time = _now_iso()
        scan._emit({"type": "status", "status": "running", "startTime": scan.start_time})
        self._write_meta(scan)
        nmap = self.nmap_path

        try:
            arg_tokens = shlex.split(scan.args, posix=False) if scan.args.strip() else ["-T4", "-F"]
        except ValueError:
            arg_tokens = scan.args.split() or ["-T4", "-F"]

        # Fase 1: descubrir que equipos estan activos (rapido). El descubrimiento
        # hereda los flags relevantes de tus argumentos (-n, -Pn, -PR, -T4, etc.).
        self._emit_progress(scan, 0.0, "Descubriendo equipos", "")
        scan._add_log("Fase 1: descubriendo equipos activos en la red...")
        disc_base = scan.output_base + "_disc"
        disc_cmd = [nmap, "-sn"] + _discovery_args(arg_tokens) + ["-v", "-oX", disc_base + ".xml"] + scan.target.split()
        self._run_capture(scan, disc_cmd)
        try:
            scan.parse_xml_hosts(disc_base + ".xml")
        except Exception:
            pass
        try:
            os.remove(disc_base + ".xml")
        except OSError:
            pass

        with scan._lock:
            up_ips = [ip for ip, h in scan.hosts.items() if h.get("status") == "up"]
        total = len(up_ips)

        if total == 0 and scan.status != "cancelled":
            diag = {
                "level": "info",
                "title": "Ningun equipo respondio al descubrimiento",
                "message": "No se encontraron equipos activos para escanear uno por uno.",
                "suggestion": "Prueba un rango con equipos activos, ejecuta como administrador, o usa el modo normal con -Pn.",
                "fix_args": None,
                "source": "secuencial",
            }
            with scan._lock:
                scan.diagnostics.append(diag)
            scan._emit({"type": "diagnostic", **diag})

        # Fase 2: un escaneo de nmap por cada equipo, acumulando resultados.
        done = 0
        sub_bases = []
        for ip in up_ips:
            if scan.status == "cancelled":
                break
            done += 1
            self._emit_progress(scan, (done - 1) / total * 100, f"Escaneando {ip}", f"{done} de {total}")
            scan._add_log(f"[{done}/{total}] Escaneando {ip}...")
            base = f"{scan.output_base}_{done}"
            sub_bases.append(base)
            self._run_capture(scan, [nmap] + arg_tokens + ["-v", "-oA", base, ip])
            try:
                scan.parse_xml_hosts(base + ".xml")
            except Exception:
                pass
            self._emit_progress(scan, done / total * 100, f"Escaneando {ip}", f"{done} de {total}")

        self._combine_outputs(scan, sub_bases)

        scan.end_time = _now_iso()
        open_ports = sum(1 for h in scan.hosts.values() for p in h.get("ports", []) if p.get("state") == "open")
        if scan.status == "cancelled":
            scan.summary = f"Detenido. {done} de {total} equipos escaneados, {open_ports} puerto(s) abiertos encontrados."
        else:
            scan.status = "done"
            scan.summary = f"Completado equipo por equipo. {total} equipos, {open_ports} puerto(s) abiertos."
        self._persist_hosts(scan)
        scan._emit({"type": "done", "status": scan.status, "summary": scan.summary, "endTime": scan.end_time})
        self._write_meta(scan)

    def _combine_outputs(self, scan, bases):
        """Junta las salidas de los escaneos por equipo en los archivos descargables."""
        nmap_parts, gnmap_parts, xml_blocks = [], [], []
        for base in bases:
            for ext, store in ((".nmap", nmap_parts), (".gnmap", gnmap_parts)):
                try:
                    with open(base + ext, "r", encoding="utf-8", errors="replace") as f:
                        store.append(f.read())
                except OSError:
                    pass
            try:
                with open(base + ".xml", "r", encoding="utf-8", errors="replace") as f:
                    xml_blocks += RE_HOST_BLOCK.findall(f.read())
            except OSError:
                pass
        try:
            with open(scan.output_base + ".nmap", "w", encoding="utf-8") as f:
                f.write("\n".join(nmap_parts))
            with open(scan.output_base + ".gnmap", "w", encoding="utf-8") as f:
                f.write("\n".join(gnmap_parts))
            with open(scan.output_base + ".xml", "w", encoding="utf-8") as f:
                f.write('<?xml version="1.0"?>\n<nmaprun>\n' + "\n".join(xml_blocks) + "\n</nmaprun>\n")
        except OSError:
            pass
        for base in bases:
            for ext in (".nmap", ".gnmap", ".xml"):
                try:
                    os.remove(base + ext)
                except OSError:
                    pass

    def _speed_watchdog(self, scan, stop_event):
        """Si el escaneo se alarga, avisa de por que y como acelerarlo."""
        for threshold in (25, 75):
            waited = 0
            while waited < threshold and not stop_event.is_set():
                time.sleep(1)
                waited += 1
            if stop_event.is_set() or scan.status != "running":
                return
            self._emit_speed_notice(scan, threshold)

    def _emit_speed_notice(self, scan, elapsed):
        items = nmap_utils.analyze_speed(scan.args, scan.target)
        remaining = scan.progress.get("remaining") if scan.progress else ""
        if items:
            reasons = " ".join(it["reason"] for it in items)
            tips = " ".join(it["tip"] for it in items)
            fix = next((it["fix_args"] for it in items if it.get("fix_args")), None)
        else:
            reasons = "Puede deberse al tamano del rango, a equipos que no responden o a la latencia de la red."
            tips = "Puedes reducir el rango, usar -F para menos puertos o -Pn si los equipos estan activos."
            fix = None
        eta = f" nmap estima unos {remaining} restantes." if remaining else ""
        diag = {
            "level": "info",
            "title": "El escaneo esta tardando",
            "message": f"Lleva mas de {elapsed} segundos y sigue en curso.{eta} {reasons}",
            "suggestion": tips,
            "fix_args": fix,
            "source": f"velocidad-{elapsed}",
        }
        with scan._lock:
            scan.diagnostics.append(diag)
        scan._emit({"type": "diagnostic", **diag})

    def _final_advice(self, scan):
        """Sugerencias de mejora cuando el escaneo termina sin hallazgos utiles."""
        up = sum(1 for h in scan.hosts.values() if h.get("status") == "up")
        open_ports = sum(
            1 for h in scan.hosts.values() for p in h.get("ports", []) if p.get("state") == "open"
        )
        if up == 0 and "-Pn" not in scan.args:
            diag = {
                "level": "info",
                "title": "Ningun host respondio al descubrimiento",
                "message": "No se detectaron equipos activos. Puede que bloqueen el ping.",
                "suggestion": "Reintenta anadiendo -Pn para escanear sin descubrimiento previo.",
                "fix_args": (scan.args + " -Pn").strip(),
                "source": "resumen final",
            }
            scan.diagnostics.append(diag)
            scan._emit({"type": "diagnostic", **diag})
        elif up > 0 and open_ports == 0 and "-p" not in scan.args and "-F" in scan.args:
            diag = {
                "level": "info",
                "title": "Hosts activos pero sin puertos abiertos",
                "message": "El escaneo rapido no hallo puertos abiertos. Quiza esten en rangos menos comunes.",
                "suggestion": "Prueba un rango mayor, por ejemplo -p 1-65535, o la plantilla intensa.",
                "fix_args": scan.args.replace("-F", "-p 1-65535").strip(),
                "source": "resumen final",
            }
            scan.diagnostics.append(diag)
            scan._emit({"type": "diagnostic", **diag})

    def stop(self, scan_id):
        scan = self.scans.get(scan_id)
        if not scan or not scan.process:
            return False
        if scan.status != "running":
            return False
        scan.status = "cancelled"
        try:
            scan.process.terminate()
        except Exception:
            pass
        return True
