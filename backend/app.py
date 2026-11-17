"""Servidor local para la interfaz visual de nmap. Usa solo la libreria estandar."""

import json
import os
import platform
import re
import subprocess
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import nmap_utils
from scanner import ScanManager

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Carpeta de datos alternativa: permite levantar una instancia de pruebas con
# su propio historial, plantillas y proyectos sin leer ni escribir los reales.
DATA_DIR = os.path.abspath(os.environ.get("NMAPVISUAL_DATA_DIR") or BASE_DIR)
SCANS_DIR = os.path.join(DATA_DIR, "scans")
CUSTOM_PROFILES_FILE = os.path.join(DATA_DIR, "custom_profiles.json")
PROJECTS_FILE = os.path.join(DATA_DIR, "projects.json")

# En modo prueba no se lanza nmap ni se detecta la red real: la interfaz se
# puede revisar entera con datos simulados sin enviar un solo paquete.
TEST_MODE = os.environ.get("NMAPVISUAL_TEST_MODE") == "1"
TEST_NETWORKS = [{"cidr": "192.168.56.0/24", "ip": "192.168.56.10"}]

NMAP_PATH = "" if TEST_MODE else nmap_utils.find_nmap()
manager = ScanManager(NMAP_PATH, SCANS_DIR) if (NMAP_PATH or TEST_MODE) else None

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}

RE_SCAN = re.compile(r"^/api/scan/([0-9a-zA-Z_]+)$")
RE_STREAM = re.compile(r"^/api/scan/([0-9a-zA-Z_]+)/stream$")
RE_STOP = re.compile(r"^/api/scan/([0-9a-zA-Z_]+)/stop$")
RE_FILE = re.compile(r"^/api/scan/([0-9a-zA-Z_]+)/file/(xml|nmap|gnmap)$")
RE_PROJECT = re.compile(r"^/api/scan/([0-9a-zA-Z_]+)/project$")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # evita ruido en consola

    # ---------- helpers ----------

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body, content_type, status=200, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    # ---------- GET ----------

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/environment":
            return self._environment()
        if path == "/api/flags":
            return self._send_json(nmap_utils.FLAGS)
        if path == "/api/scans":
            return self._send_json(manager.list_scans() if manager else [])

        m = RE_STREAM.match(path)
        if m:
            return self._stream(m.group(1))
        m = RE_FILE.match(path)
        if m:
            return self._download(m.group(1), m.group(2))
        m = RE_SCAN.match(path)
        if m:
            return self._get_scan(m.group(1))

        return self._serve_static(path)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/scan":
            return self._start_scan()
        if path == "/api/quit":
            self._send_json({"stopping": True})
            threading.Thread(target=_delayed_exit, daemon=True).start()
            return
        if path == "/api/scans/clear":
            if not manager:
                return self._send_json({"error": "nmap no disponible"}, 400)
            removed = manager.clear_history()
            return self._send_json({"removed": removed})
        if path == "/api/profiles/custom":
            data = self._read_json()
            try:
                profile = nmap_utils.add_custom_profile(
                    CUSTOM_PROFILES_FILE, data.get("name", ""), data.get("args", "")
                )
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, 400)
            return self._send_json(profile)
        if path == "/api/profiles/custom/delete":
            data = self._read_json()
            removed = nmap_utils.delete_custom_profile(CUSTOM_PROFILES_FILE, data.get("id", ""))
            return self._send_json({"removed": removed})
        if path == "/api/projects":
            data = self._read_json()
            try:
                projects = nmap_utils.add_project(PROJECTS_FILE, data.get("name", ""))
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, 400)
            return self._send_json({"projects": projects})
        if path == "/api/projects/delete":
            data = self._read_json()
            projects = nmap_utils.delete_project(PROJECTS_FILE, data.get("name", ""))
            return self._send_json({"projects": projects})
        m = RE_PROJECT.match(path)
        if m:
            if not manager:
                return self._send_json({"error": "nmap no disponible"}, 400)
            data = self._read_json()
            ok = manager.set_project(m.group(1), data.get("project", "General"))
            if not ok:
                return self._send_json({"error": "Escaneo no encontrado"}, 404)
            return self._send_json({"moved": True, "project": data.get("project", "General")})
        m = RE_STOP.match(path)
        if m:
            if not manager:
                return self._send_json({"error": "nmap no disponible"}, 400)
            ok = manager.stop(m.group(1))
            return self._send_json({"stopped": ok})
        return self._send_json({"error": "no encontrado"}, 404)

    # ---------- rutas ----------

    def _environment(self):
        if TEST_MODE:
            return self._send_json({
                "nmapFound": True,
                "nmapPath": "",
                "nmapVersion": "Modo prueba: escaneos desactivados, datos simulados",
                "isAdmin": False,
                "hasNpcap": True,
                "testMode": True,
                "profiles": nmap_utils.PROFILES,
                "customProfiles": nmap_utils.load_custom_profiles(CUSTOM_PROFILES_FILE),
                "projects": nmap_utils.load_projects(PROJECTS_FILE),
                "networks": TEST_NETWORKS,
            })
        if not NMAP_PATH:
            return self._send_json({
                "nmapFound": False,
                "nmapPath": "",
                "nmapVersion": "",
                "isAdmin": nmap_utils.is_admin(),
                "hasNpcap": nmap_utils.has_npcap(),
                "profiles": nmap_utils.PROFILES,
                "customProfiles": nmap_utils.load_custom_profiles(CUSTOM_PROFILES_FILE),
                "projects": nmap_utils.load_projects(PROJECTS_FILE),
                "networks": nmap_utils.local_networks(),
            })
        return self._send_json({
            "nmapFound": True,
            "nmapPath": NMAP_PATH,
            "nmapVersion": nmap_utils.nmap_version(NMAP_PATH),
            "isAdmin": nmap_utils.is_admin(),
            "hasNpcap": nmap_utils.has_npcap(),
            "profiles": nmap_utils.PROFILES,
            "customProfiles": nmap_utils.load_custom_profiles(CUSTOM_PROFILES_FILE),
            "projects": nmap_utils.load_projects(PROJECTS_FILE),
            "networks": nmap_utils.local_networks(),
        })

    def _start_scan(self):
        if TEST_MODE:
            return self._send_json({"error": "Modo prueba: los escaneos estan desactivados."}, 403)
        if not manager:
            return self._send_json({"error": "nmap no esta disponible en este equipo."}, 400)
        data = self._read_json()
        try:
            scan = manager.start(
                data.get("target", ""), data.get("args", ""),
                data.get("project", "General"), data.get("sequential", False),
            )
        except ValueError as exc:
            return self._send_json({"error": str(exc)}, 400)
        return self._send_json(scan.meta())

    def _get_scan(self, scan_id):
        if not manager:
            return self._send_json({"error": "nmap no disponible"}, 400)
        scan = manager.get(scan_id)
        if not scan:
            return self._send_json({"error": "Escaneo no encontrado"}, 404)
        return self._send_json(scan.snapshot())

    def _download(self, scan_id, kind):
        if not manager:
            return self._send_json({"error": "nmap no disponible"}, 400)
        scan = manager.get(scan_id)
        if not scan:
            return self._send_json({"error": "Escaneo no encontrado"}, 404)
        ext = {"xml": ".xml", "nmap": ".nmap", "gnmap": ".gnmap"}[kind]
        fpath = scan.output_base + ext
        if not os.path.isfile(fpath):
            return self._send_json({"error": "Archivo no disponible todavia"}, 404)
        with open(fpath, "rb") as f:
            body = f.read()
        self._send_bytes(
            body,
            "application/octet-stream",
            extra={"Content-Disposition": f'attachment; filename="{scan_id}{ext}"'},
        )

    def _serve_static(self, path):
        if path == "/" or path == "":
            path = "/index.html"
        rel = path.lstrip("/")
        full = os.path.normpath(os.path.join(FRONTEND_DIR, rel))
        if not full.startswith(FRONTEND_DIR) or not os.path.isfile(full):
            return self._send_json({"error": "no encontrado"}, 404)
        ext = os.path.splitext(full)[1].lower()
        ctype = CONTENT_TYPES.get(ext, "application/octet-stream")
        with open(full, "rb") as f:
            body = f.read()
        self._send_bytes(body, ctype, extra={"Cache-Control": "no-cache, no-store, must-revalidate"})

    def _stream(self, scan_id):
        if not manager:
            return self._send_json({"error": "nmap no disponible"}, 400)
        scan = manager.get(scan_id)
        if not scan:
            return self._send_json({"error": "Escaneo no encontrado"}, 404)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()

        q = scan.add_subscriber()
        try:
            self._write_sse(scan.snapshot())
            if scan.status in ("done", "failed", "cancelled"):
                self._write_sse({
                    "type": "done",
                    "status": scan.status,
                    "summary": scan.summary,
                    "endTime": scan.end_time,
                })
            last_ping = time.time()
            while True:
                try:
                    event = q.get(timeout=5)
                    self._write_sse(event)
                    if event.get("type") == "done":
                        break
                except Exception:
                    if not self._write_raw(b": keep-alive\n\n"):
                        break
                    last_ping = time.time()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            scan.remove_subscriber(q)

    def _write_sse(self, obj):
        payload = "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"
        return self._write_raw(payload.encode("utf-8"))

    def _write_raw(self, data):
        try:
            self.wfile.write(data)
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ValueError):
            return False


def _delayed_exit():
    time.sleep(0.3)
    os._exit(0)


def _port_owner_pids(port):
    """PIDs que escuchan en el puerto indicado (solo Windows)."""
    if platform.system() != "Windows":
        return []
    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True, text=True, timeout=10,
            creationflags=nmap_utils._no_window_flag(),
        ).stdout
    except Exception:
        return []
    pids = set()
    needle = f":{port} "
    for line in out.splitlines():
        if "LISTENING" in line and needle in line:
            parts = line.split()
            pid = parts[-1]
            if pid.isdigit() and int(pid) != os.getpid():
                pids.add(pid)
    return list(pids)


def _replace_previous_instance(port):
    """Cierra una instancia previa que ocupe el puerto, para que al abrir la app
    siempre arranque la version mas reciente en lugar de chocar con la vieja."""
    pids = _port_owner_pids(port)
    for pid in pids:
        try:
            subprocess.run(
                ["taskkill", "/F", "/PID", pid],
                capture_output=True, timeout=10,
                creationflags=nmap_utils._no_window_flag(),
            )
        except Exception:
            pass
    if pids:
        time.sleep(1.0)


def main():
    host = os.environ.get("NMAPVISUAL_HOST", "127.0.0.1")
    port = int(os.environ.get("NMAPVISUAL_PORT", "5000"))
    url = f"http://{host}:{port}/"

    if TEST_MODE:
        print(f"Modo prueba: datos en {DATA_DIR}, escaneos desactivados.")
    elif not NMAP_PATH:
        print("AVISO: no se encontro nmap. Instalalo o define NMAP_PATH antes de escanear.")
    else:
        print(f"nmap detectado en: {NMAP_PATH}")
    print(f"Interfaz disponible en {url}")

    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError:
        if TEST_MODE:
            # Una instancia de pruebas nunca cierra procesos ajenos: el puerto
            # podria pertenecer a la instancia real con escaneos en curso.
            print(f"El puerto {port} esta ocupado. La instancia de pruebas no arranca.")
            return
        # El puerto esta ocupado por una instancia anterior: la cerramos y lo
        # reintentamos para servir siempre el codigo mas reciente.
        _replace_previous_instance(port)
        try:
            server = ThreadingHTTPServer((host, port), Handler)
        except OSError:
            # No se pudo liberar (por ejemplo, otra instancia con permisos
            # distintos). Abrimos una pestana en la que ya esta corriendo.
            try:
                webbrowser.open(url)
            except Exception:
                pass
            return
    server.daemon_threads = True

    if os.environ.get("NMAPVISUAL_NO_BROWSER") != "1":
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
        server.shutdown()


if __name__ == "__main__":
    main()
