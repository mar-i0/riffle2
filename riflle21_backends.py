"""riflle21_backends — adaptadores de protocolo de túnel.

Cada backend traduce un fichero de config (.ovpn / .vless) en:
  - la línea de comando que hay que lanzar dentro del netns,
  - el marker stdout que indica "túnel arriba",
  - los markers de fallo conocidos,
  - una IP/MTU del lado interno del tun (usada por openvpn implícitamente;
    para xray la inyectamos en el JSON generado).

Mantiene la simetría con OpenVPN: ambos backends terminan creando un
dispositivo `tun0` dentro del netns por el que salen todas las rutas, así el
resto de la fontanería (geo, MASQUERADE per-child, SHELL+TOR, MTU para
chained) sigue funcionando sin cambios.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# Reutilizamos parseo + comprobación del proyecto vless/
_VLESS_DIR = Path("/home/iam/PROYECTOS/vless")
if str(_VLESS_DIR) not in sys.path and _VLESS_DIR.exists():
    sys.path.insert(0, str(_VLESS_DIR))
try:
    import vless_check  # type: ignore
except ImportError:
    vless_check = None  # type: ignore

# riflle2.py y riflle21_net.py viven al lado de este módulo.
import riflle2          # type: ignore
import riflle21_net as net   # type: ignore
import riflle21_uri as proxyuri   # type: ignore

XRAY_BIN = "/usr/local/bin/xray"
SINGBOX_BIN = "/usr/bin/sing-box"

# IP del tun de xray dentro del netns. Subnet propia distinta de la del veth
# (10.201.x.x). Usamos 198.18.x.x — RFC 2544 para benchmarks, así no choca con
# nada interno del proveedor VLESS. /30 basta: tun0=.1, peer no asignado.
XRAY_TUN_ADDR = "198.18.{slot}.1/30"

VLESS_OK_MARKER = "[Info] transport/internet: listening TUN"
# Fallback: si la cadena cambia entre versiones, también aceptamos el marcador
# genérico de "core: server started". Lo evaluamos como "or" en wait_marker.
VLESS_OK_ALT = "core: server started"
VLESS_DEAD_MARKERS = (
    "Failed to start",
    "failed to create server",
    "infra/conf: unable to parse",
    "failed to load config",
)

# sing-box (sólo lo usamos para hysteria2). Markers heredados de la
# verificación con `sing-box check`: si la config se valida y arranca, el
# log emite "started" en INFO; los fallos llegan como "FATAL" o "ERROR".
SINGBOX_DEAD_MARKERS = (
    "FATAL",
    "decode config:",
    "parse config:",
    "start service:",
)


@dataclass
class BackendSpec:
    """Descripción de qué lanzar para un room concreto."""
    kind: str                                  # "ovpn" | "vless"
    cmd: list[str]                             # argv completo (con ip netns exec delante)
    ok_marker: str = ""                        # cadena en stdout = túnel listo (sólo OVPN)
    ok_marker_alt: str = ""                    # marcador alternativo (or)
    dead_markers: tuple[str, ...] = ()
    cleanup_paths: list[Path] = field(default_factory=list)
    settle_seconds: float = 2.0                # espera tras handshake antes del geo
    # VLESS: host del servidor (de la URI) — necesario para instalar la /32 que
    # preserva la ruta del propio túnel (xray hablando con el VLESS server).
    vless_server_host: str = ""


# ---------------------------------------------------------------------------
# Detección de tipo
# ---------------------------------------------------------------------------

def detect_kind(path: Path) -> str:
    """Devuelve uno de: ovpn | vless | vmess | trojan | hy2.

    Los cuatro últimos los persiste el panel "Pegar URIs" en proxies_ok/
    con una extensión específica por protocolo (no hay detección por
    contenido — la extensión es autoritativa)."""
    suf = path.suffix.lower()
    if suf == ".ovpn":
        return "ovpn"
    k = proxyuri.EXT_TO_KIND.get(suf)
    if k is not None:
        return k
    raise ValueError(f"extensión no soportada: {path.name}")


# ---------------------------------------------------------------------------
# OpenVPN
# ---------------------------------------------------------------------------

def build_openvpn(netns: str, ovpn_path: Path, chained: bool) -> BackendSpec:
    """Genera el spec OpenVPN preservando el comportamiento previo de
    riflle21_ui.py (markers, redirect-gateway, MTU para chained)."""
    text = ovpn_path.read_text(errors="replace")
    force_rg = not (riflle2.has_redirect_gateway(text)
                    or riflle2.PATCH_MARKER in text)
    cmd: list[str] = [
        "ip", "netns", "exec", netns,
        riflle2.OPENVPN_BIN,
        "--config", str(ovpn_path),
        "--dev", "tun0",
        "--connect-timeout", "10",
        "--connect-retry", "0",
        "--resolv-retry", "0",
        "--pull-filter", "ignore", "block-outside-dns",
        "--verb", "3",
    ]
    if force_rg:
        cmd += ["--redirect-gateway", "def1"]
    if chained:
        cmd += [
            "--tun-mtu", "1280",
            "--mssfix", "1200",
            "--pull-filter", "ignore", "tun-mtu",
            "--pull-filter", "ignore", "mssfix",
            "--pull-filter", "ignore", "link-mtu",
        ]
    return BackendSpec(
        kind="ovpn",
        cmd=cmd,
        ok_marker=riflle2.OK_MARKER,
        dead_markers=riflle2.DEAD_MARKERS,
        settle_seconds=2.0,
    )


# ---------------------------------------------------------------------------
# VLESS via xray-core (TUN inbound + VLESS outbound)
# ---------------------------------------------------------------------------

def _xray_tun_slot(netns: str) -> int:
    """Mapea el nombre del netns a un slot 0-255 para la IP del tun, evitando
    colisiones entre rooms (cada netns es aislado pero esto da consistencia)."""
    h = 0
    for ch in netns:
        h = (h * 131 + ord(ch)) & 0xFF
    return h


def _write_tmp_json(payload: dict, prefix: str) -> Path:
    fd = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix=prefix,
        delete=False, encoding="utf-8",
    )
    json.dump(payload, fd, ensure_ascii=False)
    fd.write("\n")
    fd.close()
    return Path(fd.name)


def _build_xray_proxy(netns: str, p: "proxyuri.ProxyURI",
                       chained: bool) -> BackendSpec:
    """Genera spec xray-core (TUN inbound + outbound del protocolo) para
    vless/vmess/trojan. xray ignora silenciosamente campos tipo
    auto_route/strict_route, así que las rutas las instalamos nosotros desde
    el host vía install_vless_routes para tener control explícito del
    split-default y de la /32 al server."""
    outbound = proxyuri.to_xray_outbound(p)
    mtu = 1280 if chained else 1500
    slot = _xray_tun_slot(netns)
    tun_addr = XRAY_TUN_ADDR.format(slot=slot)
    config = {
        "log": {"loglevel": "info"},
        "inbounds": [{
            "tag": "tun-in",
            "protocol": "tun",
            "port": 0,
            "settings": {"name": "tun0", "mtu": mtu, "address": [tun_addr]},
            "sniffing": {"enabled": True,
                          "destOverride": ["http", "tls", "quic"]},
        }],
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": ["tun-in"],
                        "outboundTag": "proxy"}],
        },
    }
    cfg_path = _write_tmp_json(
        config, prefix=f"riffle21-{p.kind}-{netns}-",
    )
    cmd = ["ip", "netns", "exec", netns,
            XRAY_BIN, "run", "-c", str(cfg_path)]
    return BackendSpec(
        kind=p.kind, cmd=cmd,
        ok_marker="", ok_marker_alt="",
        dead_markers=VLESS_DEAD_MARKERS,
        cleanup_paths=[cfg_path],
        settle_seconds=4.0 if chained else 2.0,
        vless_server_host=p.host,
    )


def _build_singbox_proxy(netns: str, p: "proxyuri.ProxyURI",
                          chained: bool) -> BackendSpec:
    """Genera spec sing-box. Sólo lo usamos para hysteria2 (xray no lo
    soporta). El TUN se llama "tun0" y se direcciona como el de xray para
    que install_vless_routes funcione sin cambios."""
    mtu = 1280 if chained else 1500
    slot = _xray_tun_slot(netns)
    tun_addr = XRAY_TUN_ADDR.format(slot=slot)
    config = proxyuri.singbox_config(p, "tun0", tun_addr, mtu=mtu)
    cfg_path = _write_tmp_json(
        config, prefix=f"riffle21-singbox-{netns}-",
    )
    cmd = ["ip", "netns", "exec", netns,
            SINGBOX_BIN, "run", "-c", str(cfg_path)]
    return BackendSpec(
        kind=p.kind, cmd=cmd,
        ok_marker="", ok_marker_alt="",
        dead_markers=SINGBOX_DEAD_MARKERS,
        cleanup_paths=[cfg_path],
        # hysteria2 tarda un pelín más en QUIC handshake; subimos settle.
        settle_seconds=5.0 if chained else 3.0,
        vless_server_host=p.host,
    )


def build_proxy(netns: str, uri_path: Path, chained: bool) -> BackendSpec:
    """Builder único para vless/vmess/trojan/hysteria2: lee la URI del
    fichero, parsea y delega en xray o sing-box según el protocolo."""
    uri_str = proxyuri.read_uri_from_file(uri_path)
    p = proxyuri.parse(uri_str)
    if p.kind in ("vless", "vmess", "trojan"):
        if vless_check is None and p.kind == "vless":
            raise RuntimeError(
                "vless_check no disponible (revisa /home/iam/PROYECTOS/vless)"
            )
        return _build_xray_proxy(netns, p, chained)
    if p.kind == "hy2":
        return _build_singbox_proxy(netns, p, chained)
    raise ValueError(f"build_proxy: kind no soportado: {p.kind}")


# ---------------------------------------------------------------------------
# VLESS: espera de tun0 + instalación de rutas (split-default + /32 al server)
# ---------------------------------------------------------------------------

def tun_exists_in_ns(netns: str, ifname: str = "tun0") -> bool:
    """True si <ifname> existe dentro de <netns>."""
    r = subprocess.run(
        ["ip", "netns", "exec", netns, "ip", "-br", "link", "show", ifname],
        capture_output=True, text=True, timeout=4,
    )
    return r.returncode == 0


def wait_for_tun_in_ns(netns: str, timeout: float = 30.0,
                       proc: Optional[subprocess.Popen] = None,
                       ifname: str = "tun0") -> tuple[bool, str]:
    """Polls hasta que <ifname> aparece en <netns>. Si <proc> muere antes,
    devuelve fail inmediato. Devuelve (ok, reason)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return False, f"xray salió con rc={proc.returncode} antes de crear {ifname}"
        if tun_exists_in_ns(netns, ifname):
            # Asegurar que está UP (xray puede crearlo down brevemente)
            subprocess.run(
                ["ip", "netns", "exec", netns, "ip", "link", "set", ifname, "up"],
                capture_output=True, text=True, timeout=3,
            )
            return True, ""
        time.sleep(0.4)
    return False, f"timeout {timeout}s esperando {ifname} en {netns}"


def _resolve_host_in_ns(netns: str, host: str, timeout: float = 6.0) -> str:
    """Resuelve <host> a IPv4. Si ya es IP, devuelve la misma. Usa getent
    dentro del netns para que la respuesta venga vía el resolv.conf del netns
    (1.1.1.1 / 8.8.8.8) y no del host."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        r = subprocess.run(
            ["ip", "netns", "exec", netns, "getent", "ahosts", host],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "STREAM":
            # Sólo aceptar IPv4 (xray-core hace IPv4 por defecto en su outbound)
            try:
                ip_obj = ipaddress.ip_address(parts[0])
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    return parts[0]
            except ValueError:
                continue
    return ""


def install_vless_routes(netns: str, gateway_ip: str,
                         server_host: str) -> tuple[bool, str]:
    """Configura el routing del netns para que el tráfico salga por tun0
    excepto el del propio xray hacia el VLESS server:

      1. <server_ip>/32 via <gateway_ip>  — preserva la ruta que usa xray
         para llegar al servidor VLESS (si no, se enrutaría al propio tun0
         y haríamos loop infinito).
      2. 0.0.0.0/1   dev tun0             — mitad inferior del espacio v4
      3. 128.0.0.0/1 dev tun0             — mitad superior

    Las rutas /1 son más específicas que la default (/0), así que ganan
    sin tener que tocar la default original (que sigue apuntando al veth,
    cosa que xray necesita para hablar con el server).
    """
    server_ip = _resolve_host_in_ns(netns, server_host)
    if not server_ip:
        return False, f"no se pudo resolver {server_host} dentro del netns"

    def _run(cmd: list[str], best_effort_dup: bool = False) -> tuple[bool, str]:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
        if r.returncode == 0:
            return True, ""
        err = (r.stderr or r.stdout or "").strip()
        # "File exists" es idempotente (ruta ya estaba) — sólo lo aceptamos
        # para el add de la /32, no para los /1 (donde forzamos replace).
        if best_effort_dup and "File exists" in err:
            return True, ""
        return False, err

    ok, err = _run(
        ["ip", "netns", "exec", netns, "ip", "route", "add",
         f"{server_ip}/32", "via", gateway_ip],
        best_effort_dup=True,
    )
    if not ok:
        return False, f"route add {server_ip}/32 via {gateway_ip}: {err}"

    for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
        ok, err = _run(
            ["ip", "netns", "exec", netns, "ip", "route", "replace",
             prefix, "dev", "tun0"],
        )
        if not ok:
            return False, f"route replace {prefix} dev tun0: {err}"
    return True, f"server={server_ip}/32 via {gateway_ip}; default→tun0 (split /1)"


# ---------------------------------------------------------------------------
# Deep smoke test: levanta cada URI como una sala real (netns + TUN + rutas +
# geo + estabilidad) antes de aceptarla. Es ~50 s/URI pero garantiza que lo
# que pasa el chequeo conecta de verdad al crear el room.
# ---------------------------------------------------------------------------

# Bandwidth: mismo proveedor que riflle2.py para OpenVPN — Cloudflare speed test.
# (Las constantes de geo viven en riflle21_net.GEO_*; no las duplicamos aquí.)
BW_HOST = "speed.cloudflare.com"
BW_PATH = "/__down?bytes=10000000"        # 10 MB
BW_FALLBACK_IPS = ("104.16.0.1", "104.16.1.1", "104.16.2.1", "172.66.0.218")
BW_TIMEOUT = 8

# Pausa entre el primer y el segundo curl de geo. Filtra servidores que cierran
# la sesión casi al instante (los que pasan smoke pero no aguantan la sala).
STABILITY_WAIT_S = 15.0


def _measure_bandwidth_in_ns(netns: str, timeout: int = BW_TIMEOUT) -> float:
    """Descarga un blob de Cloudflare desde dentro del netns y devuelve Mbps.
    0.0 si todas las IPs fallback fallan. Replica la lógica del speed test
    OpenVPN para que el dato sea comparable entre backends."""
    for resolved_ip in BW_FALLBACK_IPS:
        try:
            r = subprocess.run(
                [
                    "ip", "netns", "exec", netns,
                    "curl", "-s", "-o", "/dev/null",
                    "--max-time", str(timeout),
                    "--resolve", f"{BW_HOST}:443:{resolved_ip}",
                    "-w", "%{speed_download}",
                    f"https://{BW_HOST}{BW_PATH}",
                ],
                capture_output=True, text=True,
                timeout=timeout + 3,
            )
            out = (r.stdout or "").strip()
            if not out:
                continue
            bytes_per_sec = float(out)
            if bytes_per_sec <= 0:
                continue
            return bytes_per_sec * 8 / 1_000_000   # bytes/s → Mbps
        except (subprocess.SubprocessError, ValueError, OSError):
            continue
    return 0.0


def _smoke_name(uri: str) -> str:
    """Nombre corto y único para el netns/veth efímero del smoke. Las
    interfaces de Linux están limitadas a 15 chars; veth_names añade
    'rfl-' (4) y '-h'/'-n' (2), así que el nombre debe ser <=9. Usamos
    1 char prefijo + 3 hex de sha1(uri) + 4 hex aleatorios = 8 chars."""
    digest = hashlib.sha1(uri.encode("utf-8")).hexdigest()[:3]
    return "s" + digest + os.urandom(2).hex()


def deep_smoke_test_uri(uri: str, timeout: float = 8.0,
                         taken_subnets: Iterable[str] = (),
                         baseline_ip: str = "",
                         ) -> tuple[bool, str, str, str, str, float]:
    """Reproduce el flujo exacto de RoomManager._setup_and_connect para
    cualquier URI soportada (vless/vmess/trojan/hysteria2): crea un netns
    efímero con su veth/NAT/DNS, lanza xray o sing-box con TUN inbound,
    instala las rutas split, mide geo dentro del netns, espera 15 s y
    vuelve a medir (descarta servidores con idle disconnect), mide
    bandwidth y limpia todo.

    Si la prueba pasa, lo que se persista en proxies_ok/ va a conectar
    igual al crear la sala. Si falla, el reason lleva la fase y la última
    línea relevante del log del binario para diagnosticar.

    Devuelve (ok, reason, kind, public_ip, country_code, bandwidth_mbps).
    `kind` se devuelve siempre que el parseo tenga éxito, aunque la prueba
    falle, para que la UI sepa qué extensión asignarle si quiere guardarla.
    Requiere root (igual que las salas)."""
    try:
        p = proxyuri.parse(uri)
    except ValueError as exc:
        return False, f"parse: {exc}", "", "", "", 0.0
    except RuntimeError as exc:
        return False, f"parse: {exc}", "", "", "", 0.0
    kind = p.kind

    name = _smoke_name(uri)
    netns = net.netns_name(name)
    veth_host, veth_ns = net.veth_names(name)
    try:
        subnet, host_ip, ns_ip = net.alloc_subnet(name, taken=taken_subnets)
    except net.NetworkError as exc:
        return False, f"alloc_subnet: {exc}", kind, "", "", 0.0

    # Fichero temporal con la extensión del protocolo — build_proxy() detecta
    # el kind por extensión cuando lo lee.
    ext = proxyuri.KIND_TO_EXT[kind]
    fd = tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, prefix="riffle21-deepsmoke-",
        delete=False, encoding="utf-8",
    )
    fd.write(uri + "\n")
    fd.close()
    tmp_uri_path = Path(fd.name)

    netns_created = False
    proc: Optional[subprocess.Popen] = None
    cfg_paths: list[Path] = []

    # Log del binario drenado en background; cola corta para el reason.
    log_tail: list[str] = []
    log_lock = threading.Lock()

    def _drain_log(pr: subprocess.Popen) -> None:
        if pr.stdout is None:
            return
        try:
            for line in pr.stdout:
                s = line.rstrip()
                if not s:
                    continue
                with log_lock:
                    log_tail.append(s)
                    if len(log_tail) > 30:
                        log_tail.pop(0)
        except (OSError, ValueError):
            pass

    def _tail() -> str:
        with log_lock:
            last = log_tail[-3:]
        return " | ".join(last) if last else "sin output"

    try:
        # 1) red: netns + veth + NAT + DNS (mismo create_room_netns que las salas).
        try:
            net.create_room_netns(netns, subnet, host_ip, ns_ip,
                                  veth_host, veth_ns)
            netns_created = True
        except net.NetworkError as exc:
            return False, f"create_room_netns: {exc}", kind, "", "", 0.0

        # 2) spec del backend + spawn dentro del netns.
        try:
            spec = build_proxy(netns, tmp_uri_path, chained=False)
        except (OSError, ValueError, RuntimeError) as exc:
            return False, f"build: {exc}", kind, "", "", 0.0
        cfg_paths = list(spec.cleanup_paths)

        try:
            proc = subprocess.Popen(
                spec.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd="/tmp",
                preexec_fn=os.setsid,
            )
        except OSError as exc:
            return False, f"spawn: {exc}", kind, "", "", 0.0
        threading.Thread(target=_drain_log, args=(proc,), daemon=True).start()

        # 3) esperar tun0 dentro del netns.
        tun_timeout = max(timeout * 2, 15.0)
        tun_ok, tun_err = wait_for_tun_in_ns(netns, timeout=tun_timeout, proc=proc)
        if not tun_ok:
            return False, f"wait_tun: {tun_err} ({_tail()})", kind, "", "", 0.0

        # 4) instalar rutas split + /32 al server.
        routes_ok, routes_info = install_vless_routes(
            netns, host_ip, spec.vless_server_host,
        )
        if not routes_ok:
            return False, f"routes: {routes_info}", kind, "", "", 0.0

        # 5) settle — deja que las rutas se asienten.
        time.sleep(spec.settle_seconds)

        # 6) geo #1 desde dentro del netns.
        per_curl = max(3, int(timeout))
        ip1, code, _country = net.query_geo_in_ns(netns, timeout=per_curl)
        if not ip1:
            return False, f"geo1: ip-api no responde ({_tail()})", kind, "", "", 0.0
        if baseline_ip and ip1 == baseline_ip:
            return False, f"geo1: VPN no enruta (IP=baseline {ip1})", kind, "", "", 0.0

        # 7) estabilidad: pausa y re-medir. Descarta servidores con idle disconnect.
        time.sleep(STABILITY_WAIT_S)
        ip2, _code2, _country2 = net.query_geo_in_ns(netns, timeout=per_curl)
        if not ip2:
            return False, f"stability: sesión cayó tras {int(STABILITY_WAIT_S)}s", kind, "", "", 0.0
        # ip2 puede diferir de ip1 si el provider rota — no es fail; nos
        # quedamos con la primera lectura como representativa.

        # 8) bandwidth (informativo; no bloquea OK).
        bw_mbps = _measure_bandwidth_in_ns(netns)
        return True, "", kind, ip1, code, bw_mbps
    finally:
        # Cleanup garantizado — kill proc, destroy netns, borrar tmps.
        if proc is not None:
            try:
                riflle2.kill_proc_group(proc)
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if netns_created:
            try:
                net.destroy_room_netns(netns, subnet, veth_host)
            except Exception:
                pass
        for cp in cfg_paths:
            try:
                cp.unlink()
            except OSError:
                pass
        try:
            tmp_uri_path.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_backend(netns: str, tunnel_path: Path, chained: bool) -> BackendSpec:
    kind = detect_kind(tunnel_path)
    if kind == "ovpn":
        return build_openvpn(netns, tunnel_path, chained)
    if kind in proxyuri.SUPPORTED_KINDS:
        return build_proxy(netns, tunnel_path, chained)
    raise ValueError(f"backend desconocido para {tunnel_path.name}")
