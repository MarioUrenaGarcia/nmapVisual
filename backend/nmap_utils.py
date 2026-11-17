"""Deteccion de nmap, privilegios, plantillas de escaneo y diagnostico de errores."""

import ctypes
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import uuid


def find_nmap():
    """Devuelve la ruta al ejecutable de nmap o None si no se encuentra."""
    env_path = os.environ.get("NMAP_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    found = shutil.which("nmap")
    if found:
        return found

    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def strip_nmap_prefix(args):
    """Quita de los argumentos la invocacion del ejecutable si se coló en ellos.

    Ocurre al pegar un comando completo o al reconstruir argumentos desde una
    linea de nmap cuya ruta tiene espacios ("C:\\Program Files (x86)\\Nmap\\nmap.exe"):
    cortar en el primer espacio deja restos de la ruta delante de los flags.
    """
    args = (args or "").strip()
    m = re.search(r'nmap\.exe"?(?=\s|$)', args, re.I)
    if m:
        return args[m.end():].strip()
    parts = args.split(None, 1)
    if parts and parts[0].strip('"').lower() == "nmap":
        return parts[1].strip() if len(parts) > 1 else ""
    return args


def nmap_version(nmap_path):
    """Devuelve la primera linea de version de nmap o cadena vacia."""
    try:
        out = subprocess.run(
            [nmap_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_no_window_flag(),
        )
        first = (out.stdout or out.stderr or "").strip().splitlines()
        return first[0] if first else ""
    except Exception:
        return ""


def is_admin():
    """True si el proceso tiene privilegios de administrador o root."""
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def has_npcap():
    """Comprueba de forma aproximada si Npcap o WinPcap estan instalados (Windows)."""
    if platform.system() != "Windows":
        return True
    paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Windows\System32\wpcap.dll",
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Program Files\Npcap",
    ]
    return any(os.path.exists(p) for p in paths)


def _no_window_flag():
    """Evita que aparezca una ventana de consola al lanzar nmap en Windows."""
    if platform.system() == "Windows":
        return 0x08000000  # CREATE_NO_WINDOW
    return 0


def local_networks():
    """Devuelve las redes locales detectadas como lista de {cidr, ip}.

    Util para ofrecer en la interfaz un objetivo listo para el descubrimiento
    de red sin que el usuario tenga que averiguar su propia subred.
    """
    results = {}

    # IP principal mediante un socket UDP que no envia datos.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(primary + "/24", strict=False)
        results[str(net)] = primary
    except Exception:
        primary = None

    # Empareja IP y mascara segun el sistema para obtener la subred real.
    for ip, mask in _ip_mask_pairs():
        try:
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        if net.is_loopback or net.is_link_local:
            continue
        if net.num_addresses > 1:
            results[str(net)] = ip

    return [{"cidr": cidr, "ip": ip} for cidr, ip in results.items()]


def _ip_mask_pairs():
    """Extrae pares (ip, mascara) de la configuracion de red del sistema."""
    pairs = []
    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=10,
                creationflags=_no_window_flag(),
            ).stdout
            current_ip = None
            for line in out.splitlines():
                m = re.search(r"IPv4.*?:\s*([\d.]+)", line)
                if m:
                    current_ip = m.group(1)
                m = re.search(r"(Subnet Mask|Mascara de subred).*?:\s*([\d.]+)", line)
                if m and current_ip:
                    pairs.append((current_ip, m.group(2)))
                    current_ip = None
        else:
            out = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True, text=True, timeout=10,
            ).stdout
            for line in out.splitlines():
                m = re.search(r"inet ([\d.]+)/(\d+)", line)
                if m:
                    pairs.append((m.group(1), m.group(2)))
    except Exception:
        pass
    return pairs


# Plantillas inspiradas en los perfiles clasicos, adaptadas para uso visual.
# requires_admin marca las que usan tecnicas que en Windows necesitan Npcap y
# privilegios elevados (SYN scan, deteccion de SO, escaneo UDP crudo).
PROFILES = [
    {
        "id": "netmap",
        "name": "Red: dispositivos y puertos abiertos",
        "args": "-T4 -F",
        "requires_admin": False,
        "description": "Descubre los equipos de la red y muestra los puertos abiertos de cada uno. Funciona sin privilegios de administrador.",
    },
    {
        "id": "netmap_services",
        "name": "Red: puertos y servicios",
        "args": "-T4 -F -sV",
        "requires_admin": False,
        "description": "Ademas del puerto, identifica el servicio y la version que corre en cada dispositivo.",
    },
    {
        "id": "netmap_full",
        "name": "Red: 1000 puertos principales",
        "args": "-T4",
        "requires_admin": False,
        "description": "Escanea los 1000 puertos mas usados en cada dispositivo de la red. Mas completo, algo mas lento que la opcion de 100.",
    },
    {
        "id": "netmap_discover",
        "name": "Red: solo descubrir dispositivos (rapido)",
        "args": "-sn",
        "requires_admin": False,
        "description": "Lista rapida de los equipos activos, sin escanear puertos.",
    },
    {
        "id": "netmap_arp",
        "name": "Red: descubrir ocultos con MAC y fabricante",
        "args": "-sn -PR -PE -PP -PM",
        "requires_admin": True,
        "description": "Usa ARP para ver todos los equipos aunque ignoren el ping, con su MAC y fabricante. Da mejores resultados como administrador.",
    },
    {
        "id": "quick",
        "name": "Escaneo rapido",
        "args": "-T4 -F",
        "requires_admin": False,
        "description": "Revisa los 100 puertos mas comunes. Rapido y silencioso.",
    },
    {
        "id": "quick_version",
        "name": "Rapido con servicios",
        "args": "-T4 -F -sV --version-light",
        "requires_admin": False,
        "description": "Puertos comunes mas deteccion ligera de servicios y versiones.",
    },
    {
        "id": "intense",
        "name": "Escaneo intenso",
        "args": "-T4 -A -v",
        "requires_admin": True,
        "description": "Servicios, versiones, SO y scripts por defecto en los 1000 puertos top.",
    },
    {
        "id": "intense_no_ping",
        "name": "Intenso sin ping",
        "args": "-T4 -A -v -Pn",
        "requires_admin": True,
        "description": "Como el intenso pero asume que el host esta activo. Util tras firewalls.",
    },
    {
        "id": "intense_all_tcp",
        "name": "Intenso todos los puertos TCP",
        "args": "-p 1-65535 -T4 -A -v",
        "requires_admin": True,
        "description": "Barre los 65535 puertos TCP. Mucho mas lento pero completo.",
    },
    {
        "id": "ping_sweep",
        "name": "Descubrir hosts (ping sweep)",
        "args": "-sn",
        "requires_admin": False,
        "description": "Lista que equipos estan activos en la red, sin escanear puertos.",
    },
    {
        "id": "tcp_connect",
        "name": "Conexion TCP (sin admin)",
        "args": "-sT -T4 -F -sV",
        "requires_admin": False,
        "description": "Usa conexion TCP completa. Funciona sin privilegios de administrador.",
    },
    {
        "id": "regular",
        "name": "Escaneo normal",
        "args": "",
        "requires_admin": False,
        "description": "Comportamiento por defecto de nmap sobre los 1000 puertos top.",
    },
    {
        "id": "udp_common",
        "name": "UDP comunes",
        "args": "-sU -T4 --top-ports 50",
        "requires_admin": True,
        "description": "Revisa los 50 puertos UDP mas habituales. Lento por naturaleza.",
    },
    {
        "id": "vuln_safe",
        "name": "Deteccion con scripts seguros",
        "args": "-T4 -sV --script \"default or (discovery and safe)\"",
        "requires_admin": False,
        "description": "Servicios mas scripts de categoria segura y de descubrimiento.",
    },
]


def profile_by_id(profile_id):
    for p in PROFILES:
        if p["id"] == profile_id:
            return p
    return None


# ---------- plantillas personalizadas (guardadas por el usuario) ----------

def load_custom_profiles(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [p for p in data if isinstance(p, dict) and p.get("id")]
    except (OSError, json.JSONDecodeError):
        pass
    return []


def save_custom_profiles(path, profiles):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profiles, f, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


def add_custom_profile(path, name, args):
    name = (name or "").strip()
    args = (args or "").strip()
    if not name:
        raise ValueError("La plantilla necesita un nombre.")
    profiles = load_custom_profiles(path)
    profile = {
        "id": "custom_" + uuid.uuid4().hex[:8],
        "name": name,
        "args": args,
        "description": "Plantilla guardada por ti.",
        "requires_admin": False,
        "custom": True,
    }
    profiles.append(profile)
    save_custom_profiles(path, profiles)
    return profile


def delete_custom_profile(path, profile_id):
    profiles = load_custom_profiles(path)
    remaining = [p for p in profiles if p.get("id") != profile_id]
    if len(remaining) == len(profiles):
        return False
    save_custom_profiles(path, remaining)
    return True


# ---------- proyectos (para organizar los escaneos) ----------

def load_projects(path):
    names = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            names = [str(x) for x in data if str(x).strip()]
    except (OSError, json.JSONDecodeError):
        names = []
    if "General" not in names:
        names = ["General"] + names
    return names


def save_projects(path, names):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(names, f, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


def add_project(path, name):
    name = (name or "").strip()
    if not name:
        raise ValueError("El proyecto necesita un nombre.")
    names = load_projects(path)
    if name not in names:
        names.append(name)
        save_projects(path, names)
    return names


def delete_project(path, name):
    names = [n for n in load_projects(path) if n != name]
    if "General" not in names:
        names = ["General"] + names
    save_projects(path, names)
    return names


# Referencia de banderas agrupadas, al estilo de la ayuda de nmap pero explicada.
# admin indica que la opcion necesita privilegios elevados (y Npcap en Windows).
FLAGS = [
    {
        "category": "Descubrimiento de hosts",
        "items": [
            {"flag": "-sn", "desc": "Solo descubre que hosts estan activos, sin escanear puertos."},
            {"flag": "-Pn", "desc": "Asume que todos los hosts estan activos y omite el descubrimiento. Util cuando bloquean el ping."},
            {"flag": "-PR", "desc": "Descubrimiento por ARP. En la red local detecta todos los equipos aunque ignoren el ping.", "admin": True},
            {"flag": "-PE", "desc": "Ping ICMP echo (el ping clasico)."},
            {"flag": "-PP", "desc": "Ping ICMP timestamp. Alternativa cuando el echo esta bloqueado."},
            {"flag": "-PM", "desc": "Ping ICMP netmask."},
            {"flag": "-PS", "desc": "Ping TCP SYN a los puertos indicados, por ejemplo -PS80,443."},
            {"flag": "-PA", "desc": "Ping TCP ACK a los puertos indicados."},
            {"flag": "-PU", "desc": "Ping UDP a los puertos indicados."},
            {"flag": "-n", "desc": "No resuelve nombres DNS. Hace el escaneo mas rapido."},
            {"flag": "-R", "desc": "Fuerza la resolucion DNS incluso de hosts que parecen caidos."},
            {"flag": "--system-dns", "desc": "Usa el resolvedor DNS del sistema en lugar del propio de nmap. Util si la resolucion interna falla o da problemas."},
            {"flag": "--dns-servers", "desc": "Usa servidores DNS concretos para resolver, por ejemplo --dns-servers 8.8.8.8,1.1.1.1."},
        ],
    },
    {
        "category": "Tecnicas de escaneo",
        "items": [
            {"flag": "-sS", "desc": "SYN scan: rapido y discreto, no completa la conexion.", "admin": True},
            {"flag": "-sT", "desc": "Connect scan: conexion TCP completa. Funciona sin privilegios."},
            {"flag": "-sU", "desc": "Escaneo de puertos UDP. Mas lento por naturaleza.", "admin": True},
            {"flag": "-sA", "desc": "ACK scan: ayuda a mapear reglas de firewall.", "admin": True},
            {"flag": "-sW", "desc": "Window scan: variante del ACK que a veces distingue puertos abiertos.", "admin": True},
            {"flag": "-sN", "desc": "Null scan: sin banderas TCP. Tecnica de evasion.", "admin": True},
            {"flag": "-sF", "desc": "FIN scan: solo la bandera FIN. Tecnica de evasion.", "admin": True},
            {"flag": "-sX", "desc": "Xmas scan: banderas FIN, PSH y URG. Tecnica de evasion.", "admin": True},
        ],
    },
    {
        "category": "Puertos",
        "items": [
            {"flag": "-p", "desc": "Puertos a escanear. Ejemplos: -p 80,443  o  -p 1-65535  o  -p-  (todos)."},
            {"flag": "-F", "desc": "Escaneo rapido: solo los 100 puertos mas comunes."},
            {"flag": "--top-ports", "desc": "Escanea los N puertos mas frecuentes, por ejemplo --top-ports 50."},
            {"flag": "-r", "desc": "Escanea los puertos en orden secuencial en lugar de aleatorio."},
            {"flag": "--exclude-ports", "desc": "Excluye los puertos indicados del escaneo."},
        ],
    },
    {
        "category": "Servicios y sistema operativo",
        "items": [
            {"flag": "-sV", "desc": "Detecta el servicio y la version que corre en cada puerto abierto."},
            {"flag": "--version-light", "desc": "Deteccion de version ligera y rapida."},
            {"flag": "--version-all", "desc": "Deteccion de version con intensidad maxima."},
            {"flag": "-O", "desc": "Intenta identificar el sistema operativo del host.", "admin": True},
            {"flag": "-A", "desc": "Agresivo: version, sistema operativo, scripts por defecto y traceroute.", "admin": True},
        ],
    },
    {
        "category": "Scripts (NSE)",
        "items": [
            {"flag": "-sC", "desc": "Ejecuta los scripts por defecto de nmap (informacion basica de cada servicio)."},
            {"flag": "--script", "desc": "Ejecuta scripts concretos o categorias, por ejemplo --script vuln  o  --script default,discovery."},
            {"flag": "--script-args", "desc": "Pasa argumentos a los scripts, por ejemplo --script-args user=admin."},
            {"flag": "--script vuln", "desc": "Busca vulnerabilidades conocidas en los servicios encontrados. Mas lento."},
            {"flag": "--script default", "desc": "Equivale a -sC: los scripts por defecto, seguros y utiles."},
            {"flag": "--script discovery", "desc": "Scripts que recogen mas informacion de la red y los equipos."},
            {"flag": "--script safe", "desc": "Solo scripts considerados seguros, que no alteran el objetivo."},
            {"flag": "--script http-enum", "desc": "Descubre rutas y aplicaciones comunes en servidores web."},
            {"flag": "--script http-title", "desc": "Muestra el titulo de las paginas web encontradas."},
            {"flag": "--script ssl-cert", "desc": "Muestra los datos del certificado SSL/TLS de cada servicio seguro."},
            {"flag": "--script smb-os-discovery", "desc": "Identifica el sistema operativo y el nombre via SMB (equipos Windows)."},
            {"flag": "--script banner", "desc": "Captura el banner (texto de bienvenida) de cada servicio."},
        ],
    },
    {
        "category": "Velocidad y rendimiento",
        "items": [
            {"flag": "-T4", "desc": "Plantilla de velocidad rapida. Buen equilibrio para redes modernas."},
            {"flag": "-T5", "desc": "Muy agresiva y rapida. Puede perder resultados en redes lentas."},
            {"flag": "-T2", "desc": "Mas lenta y discreta, menos carga en la red."},
            {"flag": "--min-rate", "desc": "Minimo de paquetes por segundo, por ejemplo --min-rate 1000."},
            {"flag": "--max-rate", "desc": "Maximo de paquetes por segundo para no saturar la red."},
            {"flag": "--host-timeout", "desc": "Abandona un host si tarda demasiado, por ejemplo --host-timeout 30m."},
        ],
    },
    {
        "category": "Evasion y opciones avanzadas",
        "items": [
            {"flag": "-f", "desc": "Fragmenta los paquetes para dificultar la deteccion.", "admin": True},
            {"flag": "-D", "desc": "Usa senuelos para ocultar el origen real, por ejemplo -D RND:5.", "admin": True},
            {"flag": "-g", "desc": "Fija el puerto de origen, por ejemplo -g 53."},
            {"flag": "--spoof-mac", "desc": "Falsea la direccion MAC de origen.", "admin": True},
            {"flag": "-6", "desc": "Activa el escaneo sobre IPv6."},
        ],
    },
    {
        "category": "Archivos de entrada y salida",
        "items": [
            {"flag": "-iL", "desc": "Lee los objetivos desde un archivo de texto, una IP o rango por linea. Ejemplo: -iL objetivos.txt."},
            {"flag": "-iR", "desc": "Elige objetivos al azar en internet (indicas cuantos). Uso avanzado."},
            {"flag": "--exclude", "desc": "Excluye las IPs o rangos indicados, separados por comas."},
            {"flag": "--excludefile", "desc": "Excluye los objetivos listados en un archivo."},
            {"flag": "-oN", "desc": "Guarda el resultado en texto normal en el archivo indicado. Ejemplo: -oN salida.txt."},
            {"flag": "-oX", "desc": "Guarda el resultado en XML (estructurado, para otras herramientas)."},
            {"flag": "-oG", "desc": "Guarda en formato grepable: una linea por equipo, facil de filtrar."},
            {"flag": "-oA", "desc": "Guarda los tres formatos a la vez con un nombre base. La app ya lo hace por dentro."},
            {"flag": "--append-output", "desc": "Anade al archivo de salida en lugar de sobrescribirlo."},
            {"flag": "--resume", "desc": "Reanuda un escaneo interrumpido desde su archivo de salida."},
            {"flag": "-sL", "desc": "List scan: solo lista los objetivos que escanearia, sin enviar paquetes."},
        ],
    },
    {
        "category": "Salida e informacion",
        "items": [
            {"flag": "-v", "desc": "Modo verboso: muestra mas detalle durante el escaneo."},
            {"flag": "-vv", "desc": "Aun mas detalle."},
            {"flag": "--reason", "desc": "Explica por que nmap considera cada puerto en su estado."},
            {"flag": "--traceroute", "desc": "Traza la ruta de red hasta cada host."},
            {"flag": "--open", "desc": "Muestra solo los puertos abiertos."},
        ],
    },
]


# Reglas de diagnostico. Cada regla casa una expresion con la salida de nmap y
# propone una explicacion y, cuando aplica, un ajuste de argumentos sugerido.
_RULES = [
    {
        "pattern": re.compile(r"requires (root|administrator) privileges", re.I),
        "level": "error",
        "title": "Se necesitan privilegios de administrador",
        "message": "Esta tecnica de escaneo (SYN, deteccion de SO o UDP crudo) necesita ejecutar la app como administrador y tener Npcap instalado en Windows.",
        "suggestion": "Cierra la app y vuelve a abrirla como administrador, o usa una plantilla que no requiera admin.",
        "fix_args": "-sT -T4 -F -sV",
    },
    {
        "pattern": re.compile(r"(npcap|winpcap|pcap_open|Failed to open device|dnet:)", re.I),
        "level": "error",
        "title": "Problema con el driver de captura (Npcap)",
        "message": "nmap no pudo acceder a la interfaz de red. En Windows el escaneo crudo depende de Npcap.",
        "suggestion": "Instala Npcap desde npcap.com y ejecuta la app como administrador. Mientras tanto puedes usar la plantilla de conexion TCP.",
        "fix_args": "-sT -T4 -F -sV",
    },
    {
        "pattern": re.compile(r"Failed to resolve", re.I),
        "level": "error",
        "title": "No se pudo resolver el objetivo",
        "message": "El nombre de host indicado no se pudo traducir a una direccion IP.",
        "suggestion": "Revisa que el objetivo este bien escrito o usa directamente una direccion IP.",
        "fix_args": None,
    },
    {
        "pattern": re.compile(r"(Note: Host seems down|0 hosts up|host.*appears to be down)", re.I),
        "level": "warning",
        "title": "El host parece estar caido",
        "message": "nmap no recibio respuesta al descubrimiento. Puede que el equipo bloquee el ping aunque este activo.",
        "suggestion": "Reintenta anadiendo -Pn para omitir el descubrimiento y escanear igualmente.",
        "fix_args": "-Pn",
    },
    {
        "pattern": re.compile(r"QUITTING", re.I),
        "level": "error",
        "title": "nmap se detuvo",
        "message": "nmap aborto el escaneo por un error. Revisa el detalle en el registro.",
        "suggestion": "Corrige los argumentos o el objetivo segun el mensaje mostrado.",
        "fix_args": None,
    },
    {
        "pattern": re.compile(r"WARNING: Duplicate port number", re.I),
        "level": "warning",
        "title": "Puertos duplicados en los argumentos",
        "message": "Se indico un numero de puerto repetido en -p.",
        "suggestion": "Revisa la lista de puertos para quitar duplicados.",
        "fix_args": None,
    },
    {
        "pattern": re.compile(r"Unable to find.*interface|no available / configured interface", re.I),
        "level": "error",
        "title": "No hay interfaz de red disponible",
        "message": "nmap no encontro una interfaz de red utilizable.",
        "suggestion": "Comprueba tu conexion de red y que Npcap este instalado.",
        "fix_args": None,
    },
]


def analyze_speed(args, target):
    """Explica por que un escaneo puede estar tardando y como acelerarlo.

    Devuelve una lista de dicts {reason, tip, fix_args}. No ejecuta nada:
    solo razona sobre los argumentos y el objetivo.
    """
    tokens = (args or "").split()
    low = [t.lower() for t in tokens]
    joined = " ".join(low)
    target = target or ""
    items = []

    if "-su" in low:
        items.append({
            "reason": "El escaneo UDP (-sU) es lento por naturaleza: UDP no confirma la recepcion y nmap espera un tiempo por cada puerto.",
            "tip": "Limita los puertos con --top-ports 50, o quita -sU si solo te interesan los TCP.",
            "fix_args": None,
        })
    if "-p-" in low or "1-65535" in joined:
        items.append({
            "reason": "Escanear los 65535 puertos tarda mucho, sobre todo en varios equipos a la vez.",
            "tip": "Usa -F (100 puertos comunes) o --top-ports 1000 si no necesitas todos.",
            "fix_args": _replace_token(tokens, ["-p-", "-p", "1-65535"], "-F"),
        })
    if "-sv" in low or "--version-all" in low or "-a" in low:
        items.append({
            "reason": "La deteccion de version y servicios (-sV o -A) sondea cada puerto abierto varias veces.",
            "tip": "Anade --version-light para que sea mas rapida, o quita -sV si no necesitas versiones.",
            "fix_args": (args + " --version-light").strip() if "--version-light" not in low else None,
        })
    if any(t in low for t in ("-t0", "-t1", "-t2")):
        items.append({
            "reason": "La plantilla de velocidad elegida es lenta (-T0/-T1/-T2).",
            "tip": "En una red local puedes subir a -T4 sin problema.",
            "fix_args": None,
        })
    if "-pn" not in low and ("/" in target or "-" in target or "," in target):
        items.append({
            "reason": "nmap intenta descubrir cada equipo del rango y espera a los que no responden; en un rango grande con muchos apagados, eso suma mucho tiempo.",
            "tip": "Si sabes que los equipos estan activos, anade -Pn para saltar el descubrimiento. Tambien ayuda reducir el rango.",
            "fix_args": (args + " -Pn").strip(),
        })
    return items


def _replace_token(tokens, targets, replacement):
    out = []
    replaced = False
    for t in tokens:
        if t.lower() in targets:
            if not replaced:
                out.append(replacement)
                replaced = True
        else:
            out.append(t)
    if not replaced:
        return None
    return " ".join(out)


def diagnose_line(line):
    """Analiza una linea de salida de nmap y devuelve un diagnostico o None."""
    for rule in _RULES:
        if rule["pattern"].search(line):
            return {
                "level": rule["level"],
                "title": rule["title"],
                "message": rule["message"],
                "suggestion": rule["suggestion"],
                "fix_args": rule["fix_args"],
                "source": line.strip(),
            }
    return None
