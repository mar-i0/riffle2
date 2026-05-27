#!/usr/bin/env python3
"""riflle21_ui — riffle2.1: multi-VPN simultáneo con shells por país.

Cada conexión OpenVPN vive en su propio network namespace (rfl-<name>). La
shell asociada se lanza con `ip netns exec rfl-<name> bash`, así su tráfico
sale por la VPN sin pelearse con las otras ni con el host.

Lanzar como root:
    sudo python3 riflle21_ui.py
Cleanup de huérfanos tras un kill -9:
    sudo python3 riflle21_ui.py --cleanup-orphans

UI por defecto en http://0.0.0.0:8061/
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import json
import os
import pty
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import (FastAPI, HTTPException, UploadFile, File,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Reutilizamos lógica de la v1 (sin tocar riflle2.py / riflle2_ui.py)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import riflle2          # type: ignore
import riflle21_net as net   # type: ignore
import riflle21_backends as backends  # type: ignore
import riflle21_uri as proxyuri   # type: ignore

ROOT = Path(__file__).resolve().parent
OK_DIR = ROOT / "ok"
INBOX = ROOT / "inbox"
# Carpeta donde se persisten las URIs validadas (vless/vmess/trojan/hy2).
# Antes se llamaba "vless_ok" — migración automática en _migrate_legacy_dirs().
PROXIES_OK_DIR = ROOT / "proxies_ok"
PROXIES_TRASH = ROOT / "proxies_trash"
VLESS_INBOX = ROOT / "vless_inbox"
CACHE_FILE = ROOT / ".riflle2_cache.json"


def _migrate_legacy_dirs() -> None:
    """Renombra carpetas de versiones anteriores (sólo gestionaban .vless).
    Idempotente: no hace nada si la destino ya existe o la origen no."""
    legacy_ok = ROOT / "vless_ok"
    if legacy_ok.exists() and not PROXIES_OK_DIR.exists():
        legacy_ok.rename(PROXIES_OK_DIR)
    legacy_trash = ROOT / "vless_trash"
    if legacy_trash.exists() and not PROXIES_TRASH.exists():
        legacy_trash.rename(PROXIES_TRASH)


_migrate_legacy_dirs()
HOST = os.environ.get("RIFLLE21_HOST", "0.0.0.0")
PORT = int(os.environ.get("RIFLLE21_PORT", "8061"))

CONNECT_TIMEOUT_S = 50

CHECK_LOG = ROOT / ".last_check.log"

# Borra ANSI color codes (riflle2.py imprime \033[32mOK\033[0m etc.) para que
# el log se vea limpio en la UI web.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------

@dataclass
class Room:
    name: str
    netns: str
    ovpn_path: str                            # path del .ovpn O .vless (nombre legacy)
    subnet: str
    host_ip: str
    ns_ip: str
    veth_host: str
    veth_ns: str
    kind: str = "ovpn"                         # "ovpn" | "vless"
    state: str = "creating"   # creating | connecting | connected | error | disconnecting
    ip: str = ""
    country_code: str = ""
    country: str = ""
    started_at: float = 0.0
    error: str = ""
    log_tail: list[str] = field(default_factory=list)
    proc: Optional[subprocess.Popen] = field(default=None, repr=False)
    net_torn_down: bool = False   # True una vez se limpió netns/veth/iptables
    # Ficheros temporales generados por el backend (p. ej. .json de xray);
    # se borran al destruir el room.
    tmp_paths: list[str] = field(default_factory=list)
    # Encadenamiento VPN-sobre-VPN
    parent: Optional[str] = None              # nombre del room padre (no netns)
    children: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        # NO usar dataclasses.asdict: hace deepcopy y subprocess.Popen contiene
        # un _thread.lock que no es picklable → revienta el endpoint /api/rooms
        # y la UI se queda en CREATING para siempre.
        return {
            "name": self.name,
            "netns": self.netns,
            "ovpn_path": self.ovpn_path,
            "kind": self.kind,
            "subnet": self.subnet,
            "host_ip": self.host_ip,
            "ns_ip": self.ns_ip,
            "veth_host": self.veth_host,
            "veth_ns": self.veth_ns,
            "state": self.state,
            "ip": self.ip,
            "country_code": self.country_code,
            "country": self.country,
            "started_at": self.started_at,
            "error": self.error,
            "log_tail": list(self.log_tail),
            "uptime_s": int(time.time() - self.started_at) if self.started_at else 0,
            "parent": self.parent,
            "children": list(self.children),
        }


# ---------------------------------------------------------------------------
# RoomManager
# ---------------------------------------------------------------------------

class RoomManager:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.rooms: dict[str, Room] = {}
        self.baseline_ip = ""
        self._orig_ip_forward = "0"

    # -- bootstrap / shutdown --------------------------------------------

    def bootstrap(self) -> None:
        """Llamar al arrancar el servidor. Idempotente."""
        if os.geteuid() != 0:
            print("AVISO: no estás como root. ip netns / iptables fallarán.",
                  file=sys.stderr)
            return
        self._orig_ip_forward = net.ensure_ip_forward()
        net.ensure_iptables_chains()
        print(f"[riflle21] ip_forward previo={self._orig_ip_forward} → ahora=1")
        print(f"[riflle21] cadenas iptables {net.RIFFLE21_NAT}/{net.RIFFLE21_FWD} OK")
        ip, code, country = riflle2.baseline_geo()
        self.baseline_ip = ip
        print(f"[riflle21] baseline host: {ip} [{code}] {country}")

    def shutdown(self) -> None:
        """Limpia todos los rooms y revierte iptables/ip_forward."""
        with self.lock:
            names = list(self.rooms.keys())
        if names:
            print(f"[riflle21] saliendo: limpiando {len(names)} room(s)")
        for n in names:
            try:
                self.destroy_room(n)
            except Exception as exc:
                print(f"[riflle21] error destruyendo {n}: {exc}", file=sys.stderr)
        tor_mgr.shutdown_all()
        if os.geteuid() == 0:
            net.teardown_iptables_chains()
            # restaurar ip_forward original sólo si lo modificamos
            try:
                net.write_ip_forward(self._orig_ip_forward)
            except net.NetworkError:
                pass

    # -- API pública ------------------------------------------------------

    def snapshot(self) -> list[dict]:
        with self.lock:
            return [r.to_dict() for r in self.rooms.values()]

    def get_room(self, name: str) -> Optional[Room]:
        with self.lock:
            return self.rooms.get(name)

    def create_room(self, name: str, ovpn_path: Path,
                    parent: Optional[str] = None) -> Room:
        net.validate_name(name)
        try:
            kind = backends.detect_kind(ovpn_path)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        with self.lock:
            if name in self.rooms:
                raise HTTPException(409, f"room '{name}' ya existe")
            if parent:
                p = self.rooms.get(parent)
                if p is None:
                    raise HTTPException(404, f"parent '{parent}' no existe")
                if p.state != "connected":
                    raise HTTPException(409,
                        f"parent '{parent}' está en estado '{p.state}', "
                        "solo puedes encadenar sobre rooms conectadas")
            taken = {r.subnet for r in self.rooms.values()}
            subnet, host_ip, ns_ip = net.alloc_subnet(name, taken)
            netns = net.netns_name(name)
            veth_host, veth_ns = net.veth_names(name)
            room = Room(name=name, netns=netns, ovpn_path=str(ovpn_path),
                        kind=kind,
                        subnet=subnet, host_ip=host_ip, ns_ip=ns_ip,
                        veth_host=veth_host, veth_ns=veth_ns,
                        state="creating", started_at=time.time(),
                        parent=parent)
            self.rooms[name] = room
            if parent:
                self.rooms[parent].children.append(name)

        # Setup de red + arranque openvpn se hace fuera del lock en un hilo.
        threading.Thread(target=self._setup_and_connect, args=(room,),
                         daemon=True).start()
        return room

    def destroy_room(self, name: str) -> None:
        with self.lock:
            room = self.rooms.get(name)
            if not room:
                return
            room.state = "disconnecting"
            proc = room.proc
            already_clean = room.net_torn_down
            # Marcamos AHORA, dentro del lock — si _cleanup_failed corre en
            # paralelo (timeout openvpn justo cuando el usuario pulsa X), ve
            # el flag y se salta su teardown. Antes ambos hilos veían False
            # y borraban los mismos recursos, generando "Bad rule" warns.
            room.net_torn_down = True
            children_snapshot = list(room.children)
            parent_name = room.parent
            # Derivamos el netns del nombre (determinista) en vez de leerlo del
            # dict: así no importa si el parent ya fue destruido en cascada o
            # por error — el cleanup queda best-effort en ambos casos.
            parent_netns = net.netns_name(parent_name) if parent_name else None

        # -1. cascada: destruir hijos primero (recursivo, profundidad-primero)
        for child in children_snapshot:
            try:
                self.destroy_room(child)
            except Exception as exc:
                print(f"[riflle21] error destruyendo hijo {child} de {name}: {exc}",
                      file=sys.stderr)

        # 0. matar el tor del room (si lo hay) — antes del netns porque vive
        # dentro de él
        tor_mgr.force_release(f"room:{name}")

        # 1. matar openvpn (si está vivo)
        if proc is not None:
            try:
                riflle2.kill_proc_group(proc)
            except Exception:
                pass

        # 2. teardown net (best-effort) — sólo si no se limpió ya
        if not already_clean:
            errors = net.destroy_room_netns(
                room.netns, room.subnet, room.veth_host,
                parent_netns=parent_netns,
                child_name=name if parent_netns else None,
            )
            for e in errors:
                print(f"[riflle21] cleanup warn ({name}): {e}", file=sys.stderr)

        # 3. borrar ficheros temporales del backend (p. ej. .json de xray)
        for tp in list(room.tmp_paths):
            try:
                os.unlink(tp)
            except OSError:
                pass

        with self.lock:
            self.rooms.pop(name, None)
            # quitar este room de la lista de hijos del parent
            if parent_name:
                p = self.rooms.get(parent_name)
                if p is not None:
                    try:
                        p.children.remove(name)
                    except ValueError:
                        pass

    def _cascade_kill_children(self, room: Room) -> None:
        """Llamado cuando un parent cae a error: marca los hijos en error y
        los destruye."""
        with self.lock:
            children_snapshot = list(room.children)
        for child_name in children_snapshot:
            child = self.get_room(child_name)
            if child is None:
                continue
            with self.lock:
                if child.state in ("error", "disconnecting"):
                    continue
                child.state = "error"
                child.error = f"parent '{room.name}' caída"
            try:
                self.destroy_room(child_name)
            except Exception as exc:
                print(f"[riflle21] cascade-kill {child_name}: {exc}",
                      file=sys.stderr)

    # -- internals --------------------------------------------------------

    def _push_log(self, room: Room, line: str) -> None:
        with self.lock:
            room.log_tail.append(line.rstrip())
            room.log_tail = room.log_tail[-30:]

    def _setup_and_connect(self, room: Room) -> None:
        # Derivado por nombre — robusto frente a races con destroy del parent.
        parent_netns: Optional[str] = (
            net.netns_name(room.parent) if room.parent else None
        )

        # 1. crear netns + veth + NAT
        try:
            net.create_room_netns(room.netns, room.subnet,
                                  room.host_ip, room.ns_ip,
                                  room.veth_host, room.veth_ns,
                                  parent_netns=parent_netns,
                                  child_name=room.name if parent_netns else None)
        except net.NetworkError as exc:
            with self.lock:
                room.state = "error"
                room.error = f"setup red: {exc}"
            return

        with self.lock:
            room.state = "connecting"

        # 2. construir el comando del backend (openvpn o xray)
        try:
            spec = backends.build_backend(
                room.netns, Path(room.ovpn_path), chained=bool(parent_netns),
            )
        except (OSError, ValueError, RuntimeError) as exc:
            with self.lock:
                room.state = "error"
                room.error = f"backend {room.kind}: {exc}"
            self._cleanup_failed(room)
            return

        with self.lock:
            room.tmp_paths = [str(p) for p in spec.cleanup_paths]

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
            with self.lock:
                room.state = "error"
                room.error = f"{spec.kind} spawn: {exc}"
            self._cleanup_failed(room)
            return

        with self.lock:
            room.proc = proc

        # 3. esperar handshake — la estrategia depende del backend
        ok = False
        dead_reason = ""

        vless_drain_started = False
        if spec.kind == "vless":
            # xray no expone un marker estable. Estrategia: spawnear el drain
            # "definitivo" ya (_drain_log captura log_tail + reacciona si el
            # proceso muere); el main thread polleará tun0 dentro del netns.
            # Importante: un único lector de stdout (si hubiera dos, se
            # repartirían las líneas y se vería log corrupto).
            threading.Thread(target=self._drain_log, args=(room, proc),
                             daemon=True).start()
            vless_drain_started = True

            tun_ok, tun_err = backends.wait_for_tun_in_ns(
                room.netns, timeout=CONNECT_TIMEOUT_S, proc=proc,
            )
            if not tun_ok:
                dead_reason = tun_err
            else:
                routes_ok, routes_info = backends.install_vless_routes(
                    room.netns, room.host_ip, spec.vless_server_host,
                )
                self._push_log(room, f"[routes] {routes_info}")
                if not routes_ok:
                    dead_reason = f"install_vless_routes: {routes_info}"
                else:
                    ok = True
        else:
            # OpenVPN: leer stdout esperando OK_MARKER o un DEAD_MARKER.
            start = time.monotonic()
            while time.monotonic() - start < CONNECT_TIMEOUT_S:
                assert proc.stdout is not None
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                self._push_log(room, line)
                if spec.ok_marker and spec.ok_marker in line:
                    ok = True
                    break
                if spec.ok_marker_alt and spec.ok_marker_alt in line:
                    ok = True
                    break
                for m in spec.dead_markers:
                    if m in line:
                        dead_reason = m
                        break
                if dead_reason:
                    break

        if not ok:
            try:
                riflle2.kill_proc_group(proc)
            except Exception:
                pass
            with self.lock:
                room.state = "error"
                room.error = dead_reason or "timeout esperando handshake"
                room.proc = None
            self._cleanup_failed(room)
            return

        # 4. dejar que se asienten rutas (xray instala tun0+ruta default al
        # arrancar; openvpn igual). Doblamos espera en chained.
        time.sleep(spec.settle_seconds + (3.0 if parent_netns else 0.0))
        ip, code, country = net.query_geo_in_ns(
            room.netns, timeout=15 if parent_netns else 8
        )
        if not ip:
            # Diagnóstico: si chained, los counters de la cadena del child en
            # el parent dicen si el MASQUERADE se está disparando o no — sin
            # esto, el usuario solo ve "geo no responde" y no sabe si es MTU,
            # routing o NAT.
            if parent_netns:
                try:
                    diag = subprocess.run(
                        ["ip", "netns", "exec", parent_netns, "iptables",
                         "-t", "nat", "-nvL", net._child_chain(room.name)],
                        capture_output=True, text=True, timeout=4,
                    )
                    self._push_log(room,
                        "[diag] iptables -nvL en parent:\n"
                        + (diag.stdout or diag.stderr or "<sin salida>"))
                except (subprocess.SubprocessError, OSError) as exc:
                    self._push_log(room, f"[diag] iptables fallo: {exc}")
            # Diagnóstico VLESS: rutas + estado del tun + ping al server.
            # El log_tail del room ya tiene la salida de xray (lo más útil
            # para saber si la negociación VLESS está fallando), pero
            # añadimos lo de red para que esté todo junto.
            if spec.kind == "vless":
                for cmd, tag in [
                    (["ip", "netns", "exec", room.netns, "ip", "route"], "ip route"),
                    (["ip", "netns", "exec", room.netns, "ip", "-br", "addr"], "ip addr"),
                    (["ip", "netns", "exec", room.netns, "ss", "-tn", "state", "established"], "ss"),
                ]:
                    try:
                        d = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
                        self._push_log(room, f"[diag] {tag}:\n"
                                       + (d.stdout or d.stderr or "<vacío>"))
                    except (subprocess.SubprocessError, OSError) as exc:
                        self._push_log(room, f"[diag] {tag} fallo: {exc}")
            try:
                riflle2.kill_proc_group(proc)
            except Exception:
                pass
            with self.lock:
                room.state = "error"
                room.error = "túnel arriba pero geo no responde en netns"
                room.proc = None
            self._cleanup_failed(room)
            return

        if self.baseline_ip and ip == self.baseline_ip:
            try:
                riflle2.kill_proc_group(proc)
            except Exception:
                pass
            with self.lock:
                room.state = "error"
                room.error = f"VPN no enruta (IP en netns = baseline {ip})"
                room.proc = None
            self._cleanup_failed(room)
            return

        # 5. todo OK; drenar log en background (para VLESS ya está corriendo
        # desde el paso 3 — evitamos duplicar el reader sobre el mismo stdout)
        if not vless_drain_started:
            threading.Thread(target=self._drain_log, args=(room, proc),
                             daemon=True).start()

        with self.lock:
            room.state = "connected"
            room.ip = ip
            room.country_code = code
            room.country = country

    def _drain_log(self, room: Room, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            self._push_log(room, line)
            if proc.poll() is not None:
                break
        # Si el proceso muere por su cuenta, marcamos error y limpiamos red
        with self.lock:
            if room.proc is proc and room.state == "connected":
                room.state = "error"
                room.error = "el proceso del túnel salió inesperadamente"
                room.proc = None
        # cascada: si esta room tenía hijos encadenados, mueren con ella
        self._cascade_kill_children(room)
        self._cleanup_failed(room)

    def _cleanup_failed(self, room: Room) -> None:
        """Best-effort de teardown si el room queda en error a medio camino.
        El room sigue en self.rooms para que el usuario vea el error en la UI;
        el DELETE explícito posterior será silencioso porque net_torn_down=True."""
        with self.lock:
            if room.net_torn_down:
                return
            # Claim inmediato bajo lock para evitar race con destroy_room
            # (ver comentario en destroy_room).
            room.net_torn_down = True
            parent_netns = net.netns_name(room.parent) if room.parent else None
        errors = net.destroy_room_netns(
            room.netns, room.subnet, room.veth_host,
            parent_netns=parent_netns,
            child_name=room.name if parent_netns else None,
        )
        for e in errors:
            print(f"[riflle21] cleanup-failed warn ({room.name}): {e}",
                  file=sys.stderr)
        # ficheros tmp del backend (config xray, etc.)
        for tp in list(room.tmp_paths):
            try:
                os.unlink(tp)
            except OSError:
                pass


manager = RoomManager()

# Estado global del proceso de validación lanzado por /api/check-inbox.
# Sólo permitimos una validación a la vez (riflle2.py es secuencial igualmente).
_check_proc: Optional[subprocess.Popen] = None
_check_log_fh = None   # fd abierto a CHECK_LOG mientras la validación corre
_check_lock = threading.Lock()


def _check_running() -> bool:
    with _check_lock:
        return _check_proc is not None and _check_proc.poll() is None


# ---------------------------------------------------------------------------
# Carga de VPNs disponibles (reutilizamos cache de v1)
# ---------------------------------------------------------------------------

def list_vpns() -> list[dict]:
    """Lista túneles disponibles: .ovpn de ok/ y .vless/.vmess/.trojan/.hy2
    de proxies_ok/. Sólo los validados aparecen — el dropdown no debe ofrecer
    rotos."""
    cache: dict = {}
    if CACHE_FILE.exists():
        try:
            cache = json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            cache = {}
    entries: list[dict] = []
    if OK_DIR.exists():
        for p in sorted(OK_DIR.iterdir()):
            if p.is_file() and p.suffix == ".ovpn":
                digest = riflle2.sha1_of(p)
                c = cache.get(digest, {})
                entries.append({
                    "kind": "ovpn",
                    "name": p.name,
                    "path": str(p),
                    "source": "ok",
                    "country_code": (c.get("country_code") or "").lower(),
                    "country": c.get("country") or "",
                    "bandwidth_mbps": float(c.get("bandwidth_mbps") or 0.0),
                    "validated": c.get("status") == "ok",
                })
    if PROXIES_OK_DIR.exists():
        for p in sorted(PROXIES_OK_DIR.iterdir()):
            if not p.is_file():
                continue
            kind = proxyuri.kind_from_path(p)
            if kind is None:
                continue
            digest = riflle2.sha1_of(p)
            c = cache.get(digest, {})
            entries.append({
                "kind": kind,
                "name": p.name,
                "path": str(p),
                "source": "proxies_ok",
                "country_code": (c.get("country_code") or "").lower(),
                "country": c.get("country") or "",
                "bandwidth_mbps": float(c.get("bandwidth_mbps") or 0.0),
                # Si no hay cache, asumimos validado por estar en proxies_ok/.
                "validated": c.get("status", "ok") == "ok",
            })
    return entries


SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._一-鿿-]+")


def safe_filename(name: str, default_ext: str = ".ovpn") -> str:
    base = Path(name).name
    base = SAFE_NAME_RE.sub("_", base)
    lower = base.lower()
    if not (lower.endswith(".ovpn") or lower.endswith(".vless")):
        base += default_ext
    return base[:200]


# ---------------------------------------------------------------------------
# Tor (procesos por room, con refcount)
# ---------------------------------------------------------------------------

TOR_RUN_DIR = Path("/run/riffle2-tor")


def _detect_tor_user() -> Optional[str]:
    """tor se niega a correr como root sin User directive. Buscamos un
    usuario tor del sistema y le pasamos la DataDirectory en propiedad."""
    if os.geteuid() != 0:
        return None
    import pwd
    for cand in ("debian-tor", "_tor", "tor"):
        try:
            pwd.getpwnam(cand)
            return cand
        except KeyError:
            continue
    return None


_TOR_USER = _detect_tor_user()


class TorProcess:
    """Una instancia de `tor` viva: proceso, refcount, log de bootstrap."""

    def __init__(self, key: str, netns: Optional[str]) -> None:
        self.key = key
        self.netns = netns
        self.proc: Optional[subprocess.Popen] = None
        self.refcount = 0
        self.bootstrap_lines: list[str] = []
        self.bootstrap_done = threading.Event()
        self.dead = threading.Event()
        self._listeners: list[asyncio.Queue] = []
        self._lock = threading.Lock()
        # SocksPort 9050 sirve para todos los room (cada netns tiene su propio
        # loopback). Para el global usamos 9051 por si el host ya tiene un tor
        # en 9050 (no chocará en términos de bind: es un netns distinto, pero
        # así también el cliente sabe dónde apuntar si se reusa host tor).
        self.socks_port = 9050

    def data_dir(self) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", self.key)
        return TOR_RUN_DIR / safe

    def _write_torrc(self) -> Path:
        ddir = self.data_dir()
        ddir.mkdir(parents=True, exist_ok=True)
        # tor exige permisos restrictivos en DataDirectory
        os.chmod(ddir, 0o700)
        # Si corremos como root, tor se negará a continuar a menos que le
        # demos un User al que bajar privilegios — y ese user tiene que ser
        # dueño de la DataDirectory.
        user_line = ""
        if _TOR_USER:
            import pwd
            pw = pwd.getpwnam(_TOR_USER)
            try:
                os.chown(ddir, pw.pw_uid, pw.pw_gid)
            except OSError:
                pass
            user_line = f"User {_TOR_USER}\n"
        torrc = ddir / "torrc"
        torrc.write_text(
            f"SocksPort {self.socks_port}\n"
            f"DataDirectory {ddir}\n"
            "Log notice stdout\n"
            "RunAsDaemon 0\n"
            "ClientOnly 1\n"
            "AvoidDiskWrites 1\n"
            + user_line
        )
        return torrc

    def start(self) -> None:
        torrc = self._write_torrc()
        argv: list[str]
        if self.netns:
            argv = ["ip", "netns", "exec", self.netns, "tor", "-f", str(torrc)]
        else:
            argv = ["tor", "-f", str(torrc)]
        self.proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            start_new_session=True,
        )
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for raw in self.proc.stdout:
            line = raw.rstrip("\n")
            with self._lock:
                self.bootstrap_lines.append(line)
                if len(self.bootstrap_lines) > 200:
                    self.bootstrap_lines = self.bootstrap_lines[-200:]
                listeners = list(self._listeners)
            for q in listeners:
                try:
                    q.put_nowait(line)
                except Exception:
                    pass
            if "Bootstrapped 100%" in line:
                self.bootstrap_done.set()
        self.dead.set()
        self.bootstrap_done.set()   # desbloquear esperas si tor murió
        with self._lock:
            listeners = list(self._listeners)
        for q in listeners:
            try:
                q.put_nowait(None)   # sentinela de fin
            except Exception:
                pass

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        with self._lock:
            # entregar histórico al nuevo subscriptor para que vea lo ya emitido
            for line in self.bootstrap_lines:
                q.put_nowait(line)
            self._listeners.append(q)
        if self.bootstrap_done.is_set():
            q.put_nowait("__BOOTSTRAPPED__")
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            try:
                self._listeners.remove(q)
            except ValueError:
                pass

    def stop(self) -> None:
        if self.proc is None:
            return
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        except Exception:
            pass
        self.proc = None
        self.dead.set()
        # limpiar DataDirectory (es ephemeral en /run)
        try:
            shutil.rmtree(self.data_dir(), ignore_errors=True)
        except Exception:
            pass


class TorManager:
    """Pool de procesos tor con refcount por clave."""

    def __init__(self) -> None:
        self._tors: dict[str, TorProcess] = {}
        self._lock = threading.Lock()

    def acquire(self, key: str, netns: Optional[str]) -> TorProcess:
        with self._lock:
            tp = self._tors.get(key)
            if tp is None or tp.dead.is_set():
                tp = TorProcess(key, netns)
                tp.start()
                self._tors[key] = tp
            tp.refcount += 1
            return tp

    def release(self, key: str) -> None:
        with self._lock:
            tp = self._tors.get(key)
            if tp is None:
                return
            tp.refcount -= 1
            if tp.refcount > 0:
                return
            self._tors.pop(key, None)
        tp.stop()

    def force_release(self, key: str) -> None:
        """Mata el tor de `key` aunque queden refs (usado al borrar un room)."""
        with self._lock:
            tp = self._tors.pop(key, None)
        if tp is not None:
            tp.stop()

    def shutdown_all(self) -> None:
        with self._lock:
            tors = list(self._tors.values())
            self._tors.clear()
        for tp in tors:
            tp.stop()


tor_mgr = TorManager()


# ---------------------------------------------------------------------------
# PTY (con soporte de netns)
# ---------------------------------------------------------------------------

class PTYSession:
    def __init__(self) -> None:
        self.pid: int = -1
        self.fd: int = -1

    def start(self, cwd: str = "/root", netns: Optional[str] = None,
              tor: bool = False) -> None:
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.environ.setdefault("HOME", cwd)
            try:
                os.chdir(cwd)
            except OSError:
                os.chdir("/")
            inner = ["torsocks", "bash", "--login"] if tor else ["bash", "--login"]
            if netns:
                os.execvp("ip", ["ip", "netns", "exec", netns] + inner)
            else:
                os.execvp(inner[0], inner)
        self.pid = pid
        self.fd = fd
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def resize(self, rows: int, cols: int) -> None:
        if self.fd < 0:
            return
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass

    def read_blocking(self, maxbytes: int = 8192, poll_timeout: float = 0.05) -> bytes:
        if self.fd < 0:
            return b""
        try:
            r, _, _ = select.select([self.fd], [], [], poll_timeout)
            if not r:
                return b""
            return os.read(self.fd, maxbytes)
        except OSError:
            return b""

    def write(self, data: bytes) -> None:
        if self.fd < 0:
            return
        try:
            os.write(self.fd, data)
        except OSError:
            pass

    def close(self) -> None:
        if self.pid > 0:
            try:
                os.kill(self.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                pass
        if self.fd > 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
        self.pid = -1
        self.fd = -1


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="riffle2.1 — multi-VPN")


class RoomBody(BaseModel):
    name: str
    path: str
    parent: Optional[str] = None   # nombre de un room ya `connected` para encadenar


NOCACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML, headers=NOCACHE_HEADERS)


@app.get("/shell", response_class=HTMLResponse)
def shell_page() -> HTMLResponse:
    return HTMLResponse(SHELL_HTML, headers=NOCACHE_HEADERS)


@app.get("/api/vpns")
def api_vpns() -> JSONResponse:
    return JSONResponse(list_vpns())


@app.delete("/api/tunnels")
def api_tunnels_delete(path: str) -> JSONResponse:
    """Mueve un túnel (.ovpn de ok/ o cualquier .vless/.vmess/.trojan/.hy2 de
    proxies_ok/) a su papelera correspondiente (`trash/` u `proxies_trash/`).
    No borra destructivamente — por si te arrepientes."""
    p = Path(path)
    try:
        resolved = p.resolve()
    except OSError as exc:
        raise HTTPException(400, f"path inválido: {exc}")
    root_resolved = ROOT.resolve()
    if not str(resolved).startswith(str(root_resolved)):
        raise HTTPException(403, "path fuera del proyecto")
    if not p.exists() or not p.is_file():
        raise HTTPException(404, "fichero no encontrado")
    suf = p.suffix.lower()
    if suf == ".ovpn":
        dest_dir = ROOT / "trash"
        cache_kind = "ovpn"
    elif proxyuri.kind_from_path(p) is not None:
        dest_dir = PROXIES_TRASH
        cache_kind = proxyuri.kind_from_path(p)
    else:
        raise HTTPException(400,
            "extensiones soportadas: .ovpn / .vless / .vmess / .trojan / .hy2")
    dest_dir.mkdir(exist_ok=True)
    target = dest_dir / p.name
    n = 1
    while target.exists():
        target = dest_dir / f"{p.stem}.dup{n}{suf}"
        n += 1
    # Invalida la entrada del cache (si la había) — el digest cambia con la
    # ubicación pero el contenido es igual; mejor: borramos por sha1 actual.
    try:
        digest = riflle2.sha1_of(p)
    except OSError:
        digest = ""
    p.rename(target)
    if digest:
        try:
            with _CACHE_LOCK:
                cache = riflle2.load_cache()
                if digest in cache:
                    cache.pop(digest, None)
                    riflle2.save_cache(cache)
        except (OSError, ValueError):
            pass
    return JSONResponse({"ok": True, "moved_to": str(target),
                          "kind": cache_kind})


@app.get("/api/rooms")
def api_rooms_list() -> JSONResponse:
    return JSONResponse(manager.snapshot())


@app.post("/api/rooms", status_code=202)
def api_rooms_create(body: RoomBody) -> JSONResponse:
    if os.geteuid() != 0:
        raise HTTPException(503, "el servidor no está como root; ip netns falla")
    p = Path(body.path)
    valid_ext = (p.suffix.lower() == ".ovpn"
                 or proxyuri.kind_from_path(p) is not None)
    if not p.exists() or not valid_ext:
        raise HTTPException(400,
            "fichero no encontrado o extensión no soportada "
            "(.ovpn / .vless / .vmess / .trojan / .hy2)")
    if not str(p.resolve()).startswith(str(ROOT.resolve())):
        raise HTTPException(403, "path fuera del proyecto")
    try:
        room = manager.create_room(body.name, p, parent=body.parent or None)
    except net.NetworkError as exc:
        raise HTTPException(400, str(exc))
    return JSONResponse(room.to_dict())


@app.delete("/api/rooms/{name}")
def api_rooms_delete(name: str) -> JSONResponse:
    room = manager.get_room(name)
    if not room:
        raise HTTPException(404, f"no existe room '{name}'")
    manager.destroy_room(name)
    return JSONResponse({"ok": True, "name": name})


# Cache per-room para realip (evita martillear ip-api.com)
_REALIP_CACHE: dict[str, dict] = {}
_REALIP_LOCK = threading.Lock()
_REALIP_TTL = 4.0


@app.get("/api/rooms/{name}/realip")
def api_room_realip(name: str, force: bool = False) -> JSONResponse:
    room = manager.get_room(name)
    if not room:
        raise HTTPException(404, f"no existe room '{name}'")

    now = time.time()
    with _REALIP_LOCK:
        c = _REALIP_CACHE.get(name, {"ip": "", "country_code": "", "country": "", "ts": 0.0})
        age = now - c["ts"] if c["ts"] else None
        if (not force and c["ip"] and age is not None and age < _REALIP_TTL):
            return JSONResponse({**c, "age_s": round(age, 1),
                                  "cached": True, "live": True})

    ip, code, country = net.query_geo_in_ns(room.netns, timeout=6)
    with _REALIP_LOCK:
        if ip:
            _REALIP_CACHE[name] = {"ip": ip, "country_code": code,
                                    "country": country, "ts": time.time()}
        c = _REALIP_CACHE.get(name, {"ip": "", "country_code": "", "country": "", "ts": 0.0})
        age2 = time.time() - c["ts"] if c["ts"] else None
        return JSONResponse({
            "ip": c["ip"], "country_code": c["country_code"],
            "country": c["country"],
            "age_s": round(age2, 1) if age2 else None,
            "cached": False, "live": bool(ip),
        })


# Cache para realip del HOST (sin netns)
_HOST_REALIP = {"ip": "", "country_code": "", "country": "", "ts": 0.0}


@app.get("/api/realip")
def api_realip_host(force: bool = False) -> JSONResponse:
    now = time.time()
    with _REALIP_LOCK:
        age = now - _HOST_REALIP["ts"] if _HOST_REALIP["ts"] else None
        if not force and _HOST_REALIP["ip"] and age is not None and age < _REALIP_TTL:
            return JSONResponse({**_HOST_REALIP, "age_s": round(age, 1),
                                  "cached": True, "live": True})
    ip, code, country = riflle2.query_geo(timeout=6)
    with _REALIP_LOCK:
        if ip:
            _HOST_REALIP.update({"ip": ip, "country_code": code,
                                  "country": country, "ts": time.time()})
        age2 = time.time() - _HOST_REALIP["ts"] if _HOST_REALIP["ts"] else None
        return JSONResponse({
            "ip": _HOST_REALIP["ip"], "country_code": _HOST_REALIP["country_code"],
            "country": _HOST_REALIP["country"],
            "age_s": round(age2, 1) if age2 else None,
            "cached": False, "live": bool(ip),
        })


# ---------------------------------------------------------------------------
# Upload de .ovpn + lanzar validación en background
# ---------------------------------------------------------------------------

@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)) -> JSONResponse:
    fname = (file.filename or "").lower()
    if fname.endswith(".ovpn"):
        kind, dest_dir, ext = "ovpn", INBOX, ".ovpn"
    elif fname.endswith(".vless"):
        kind, dest_dir, ext = "vless", VLESS_INBOX, ".vless"
    else:
        raise HTTPException(400, "extensión soportada: .ovpn o .vless")
    dest_dir.mkdir(exist_ok=True)
    safe = safe_filename(file.filename, default_ext=ext)
    target = dest_dir / safe
    n = 1
    while target.exists():
        stem = safe[:-len(ext)]
        target = dest_dir / f"{stem}.dup{n}{ext}"
        n += 1
    data = await file.read()
    if len(data) > 2_000_000:
        raise HTTPException(413, "fichero demasiado grande (>2MB)")
    target.write_bytes(data)
    return JSONResponse({"ok": True, "saved": target.name, "size": len(data),
                         "kind": kind})


@app.post("/api/check-inbox")
def api_check_inbox(bandwidth: bool = True, timeout: int = 10) -> JSONResponse:
    """Lanza riflle2.py check en background contra ./inbox/.
    Rechaza si ya hay una validación corriendo (sólo una a la vez).

    Query params:
      bandwidth (default true)  → mide Mbps de cada VPN que conecta.
      timeout   (default 10s)   → segundos por intento de handshake openvpn;
                                   pasado ese tiempo descarta y va a la siguiente.

    Siempre pasa --inbox-only: la UI no quiere re-procesar todos los ok/ cuando
    el usuario sube 4 ficheros nuevos. Para re-medir toda ok/, usar la CLI.
    """
    global _check_proc, _check_log_fh
    if os.geteuid() != 0:
        raise HTTPException(503, "necesita ejecutarse como root")
    # Clamp seguro: 3..120s
    timeout = max(3, min(int(timeout), 120))
    with _check_lock:
        if _check_proc is not None and _check_proc.poll() is None:
            raise HTTPException(
                409, f"ya hay una validación corriendo (PID {_check_proc.pid})"
            )
        # Cerrar fd del run anterior si quedó abierto
        if _check_log_fh is not None:
            try:
                _check_log_fh.close()
            except OSError:
                pass
            _check_log_fh = None

        script = ROOT / "riflle2.py"
        # -u → unbuffered: si no, las prints() del subprocess se quedan en su
        # buffer de stdout hasta que se llena (~8KB) o termine. La UI hace
        # poll del fichero y se vería "siempre validando".
        cmd = ["python3", "-u", str(script),
               "--timeout", str(timeout), "--inbox-only"]
        if bandwidth:
            cmd.append("--bandwidth")
        cmd.append("check")
        # 'w' trunca el fichero — empezamos limpios cada run.
        _check_log_fh = open(CHECK_LOG, "w")
        _check_proc = subprocess.Popen(
            cmd,
            stdout=_check_log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(ROOT),
            start_new_session=True,
        )
        pid = _check_proc.pid
    return JSONResponse({"ok": True, "pid": pid, "log": str(CHECK_LOG),
                          "cmd": " ".join(cmd)})


class ProxyUrisBody(BaseModel):
    uris: list[str]
    # Timeout aplica POR curl interno (geo / bandwidth). El total de cada URI
    # es del orden de 50-60s: wait_tun (~15) + settle + geo1 + estabilidad
    # (15) + geo2 + bw + teardown.
    timeout: float = 12.0


@app.post("/api/check-proxy-uris")
def api_check_proxy_uris(body: ProxyUrisBody) -> JSONResponse:
    """Valida una lista de URIs (vless/vmess/trojan/hysteria2) pegadas en la
    UI. Para cada una se reproduce el flujo exacto de una sala (netns efímero
    + TUN + rutas split + geo + estabilidad 15s) — si la prueba pasa, la URI
    conecta de verdad al crear el room. Las que pasan se guardan en
    proxies_ok/ con la extensión propia del protocolo (.vless/.vmess/.trojan/
    .hy2) y aparecen en el desplegable.

    Es lento (~50 s por URI con 4 workers concurrentes) pero garantiza que lo
    añadido funciona. Cap de 50 URIs por request."""
    uris = [u.strip() for u in body.uris
            if u.strip() and not u.strip().startswith("#")]
    if not uris:
        raise HTTPException(400, "lista vacía")
    if len(uris) > 50:
        raise HTTPException(400,
            f"máximo 50 URIs por request, recibidas {len(uris)}")
    # timeout aplica por curl (geo/bw). Total por URI ≈ 50-60 s.
    timeout = max(4.0, min(float(body.timeout), 20.0))

    PROXIES_OK_DIR.mkdir(exist_ok=True)
    existing = _existing_proxy_uris()
    existing_lock = threading.Lock()

    # Snapshot de subnets ya ocupadas por rooms vivos + lock para reservar
    # subnets entre workers concurrentes del propio deep test. Sin esto, dos
    # smokes pueden chocar al pedir la misma /30 a alloc_subnet.
    with manager.lock:
        in_use_subnets: set[str] = {r.subnet for r in manager.rooms.values()}
    subnets_lock = threading.Lock()
    baseline_ip = manager.baseline_ip

    def _check_one(uri: str) -> dict:
        entry: dict = {"uri": uri, "status": "malformed", "reason": "",
                       "saved_as": None, "target": "", "tag": "",
                       "kind": "",
                       "ip": "", "country_code": "", "bandwidth_mbps": 0.0}
        with existing_lock:
            if uri in existing:
                entry["status"] = "duplicated"
                entry["reason"] = "ya estaba en proxies_ok/"
                return entry
        # Pre-parseo para clasificar malformadas sin reservar netns.
        try:
            p = proxyuri.parse(uri)
        except (ValueError, RuntimeError) as exc:
            entry["status"] = "malformed"
            entry["reason"] = f"parse: {exc}"
            return entry
        entry["target"] = f"{p.host}:{p.port}"
        entry["tag"] = p.tag
        entry["kind"] = p.kind

        # Deep smoke test: el caller pasa el snapshot de subnets vivas para
        # que alloc_subnet evite colisión con salas y con otros workers.
        with subnets_lock:
            taken_now = frozenset(in_use_subnets)
        try:
            sok, sreason, _skind, sip, scc, sbw = backends.deep_smoke_test_uri(
                uri, timeout=timeout,
                taken_subnets=taken_now, baseline_ip=baseline_ip,
            )
        except Exception as exc:
            sok, sreason, sip, scc, sbw = (
                False, f"excepción: {exc}", "", "", 0.0)
        if not sok:
            # La fase la lleva el propio reason ("wait_tun:", "routes:",
            # "geo1:", "stability:", etc.). Clasificamos en dead vs auth para
            # que el dropdown de la UI las separe.
            entry["status"] = "dead" if sreason.startswith(
                ("wait_tun:", "routes:", "geo1:", "stability:")
            ) else "auth"
            entry["reason"] = sreason
            return entry
        # ¡pasa todo!
        entry["status"] = "ok"
        entry["ip"] = sip
        entry["country_code"] = scc
        entry["bandwidth_mbps"] = sbw
        with existing_lock:
            if uri in existing:   # carrera con otro worker que guardó la misma
                entry["status"] = "duplicated"
                entry["reason"] = "ya estaba en proxies_ok/"
                return entry
            entry["saved_as"] = _save_proxy_uri(
                uri, p.kind, p.tag, f"{p.host}:{p.port}",
                ip=sip, country_code=scc, bandwidth_mbps=sbw,
            )
            existing.add(uri)
        return entry

    # 4 workers: cada deep test arranca un xray con TUN inbound + crea netns
    # + monta veth/NAT. 4 simultáneos van bien en máquinas modestas; subir más
    # introduce ruido sensible en la medición de bandwidth de cada uno.
    n_workers = min(4, len(uris))
    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        results = list(ex.map(_check_one, uris))

    summary = {"ok": 0, "auth": 0, "dead": 0, "malformed": 0, "duplicated": 0}
    for r in results:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    return JSONResponse({"results": results, "summary": summary})


def _existing_proxy_uris() -> set[str]:
    """Set de URIs (vless/vmess/trojan/hy2) ya guardadas en proxies_ok/.
    Cada fichero tiene una URI canónica como primera línea no-comentario."""
    out: set[str] = set()
    if not PROXIES_OK_DIR.exists():
        return out
    for p in PROXIES_OK_DIR.iterdir():
        if not p.is_file() or proxyuri.kind_from_path(p) is None:
            continue
        try:
            for line in p.read_text(errors="replace").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    out.add(s)
                    break
        except OSError:
            continue
    return out


_CACHE_LOCK = threading.Lock()


def _save_proxy_uri(uri: str, kind: str, tag: str, target: str,
                    ip: str = "", country_code: str = "",
                    bandwidth_mbps: float = 0.0) -> str:
    """Persiste una URI validada en proxies_ok/ con la extensión propia del
    protocolo (`.vless`/`.vmess`/`.trojan`/`.hy2`) y actualiza el cache
    (sha1→info) para que el desplegable muestre banderita, país y Mbps sin
    tener que reconectar."""
    ext = proxyuri.KIND_TO_EXT.get(kind, ".vless")
    base = (tag or target or kind).strip()
    base = SAFE_NAME_RE.sub("_", base)[:80] or kind
    target_path = PROXIES_OK_DIR / f"{base}{ext}"
    n = 1
    while target_path.exists():
        target_path = PROXIES_OK_DIR / f"{base}.dup{n}{ext}"
        n += 1
    target_path.write_text(
        f"# guardado desde la UI ({tag or target})\n{uri}\n",
        encoding="utf-8",
    )
    # Cache: clave = sha1 del fichero (mismo formato que usa list_vpns).
    if ip or country_code or bandwidth_mbps:
        try:
            digest = riflle2.sha1_of(target_path)
            with _CACHE_LOCK:
                cache = riflle2.load_cache()
                cache[digest] = {
                    "status": "ok",
                    "reason": "deep smoke ok",
                    "external_ip": ip,
                    "country_code": (country_code or "").upper(),
                    "country": "",
                    "patched": False,
                    "bandwidth_mbps": float(bandwidth_mbps),
                    "ts": int(time.time()),
                    "kind": kind,
                }
                riflle2.save_cache(cache)
        except (OSError, ValueError):
            pass   # cache es best-effort, no bloquea el guardado
    return target_path.name


@app.post("/api/check-vless-inbox")
def api_check_vless_inbox(timeout: int = 8) -> JSONResponse:
    """Lanza `riflle2.py vless-check` en background contra ./vless_inbox/.
    Comparte CHECK_LOG y _check_proc con la validación .ovpn (solo una a la vez).
    No requiere root (vless-check sólo hace handshake DNS/TCP/TLS/WS)."""
    global _check_proc, _check_log_fh
    timeout = max(3, min(int(timeout), 60))
    with _check_lock:
        if _check_proc is not None and _check_proc.poll() is None:
            raise HTTPException(
                409, f"ya hay una validación corriendo (PID {_check_proc.pid})"
            )
        if _check_log_fh is not None:
            try:
                _check_log_fh.close()
            except OSError:
                pass
            _check_log_fh = None

        script = ROOT / "riflle2.py"
        cmd = ["python3", "-u", str(script),
               "--timeout", str(timeout), "vless-check"]
        _check_log_fh = open(CHECK_LOG, "w")
        _check_proc = subprocess.Popen(
            cmd,
            stdout=_check_log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(ROOT),
            start_new_session=True,
        )
        pid = _check_proc.pid
    return JSONResponse({"ok": True, "pid": pid, "log": str(CHECK_LOG),
                          "cmd": " ".join(cmd)})


@app.get("/api/check-log")
def api_check_log(offset: int = 0) -> JSONResponse:
    """Devuelve el contenido nuevo del log de validación desde `offset` bytes y
    si el proceso sigue corriendo. La UI hace polling con el último `offset`
    devuelto para mostrar el log incrementalmente."""
    with _check_lock:
        running = _check_proc is not None and _check_proc.poll() is None
        pid = _check_proc.pid if _check_proc is not None else None
        rc = (_check_proc.poll()
              if (_check_proc is not None and not running) else None)

    if not CHECK_LOG.exists():
        return JSONResponse({"content": "", "offset": 0,
                              "running": running, "pid": pid, "rc": rc})

    try:
        size = CHECK_LOG.stat().st_size
    except OSError:
        return JSONResponse({"content": "", "offset": 0,
                              "running": running, "pid": pid, "rc": rc})

    if offset < 0:
        offset = 0
    if offset >= size:
        return JSONResponse({"content": "", "offset": size,
                              "running": running, "pid": pid, "rc": rc})

    try:
        with open(CHECK_LOG, "rb") as f:
            f.seek(offset)
            raw = f.read().decode("utf-8", errors="replace")
    except OSError:
        return JSONResponse({"content": "", "offset": offset,
                              "running": running, "pid": pid, "rc": rc})

    clean = _ANSI_RE.sub("", raw)
    return JSONResponse({"content": clean, "offset": size,
                          "running": running, "pid": pid, "rc": rc})


# ---------------------------------------------------------------------------
# WebSocket terminal (opcionalmente dentro de un netns)
# ---------------------------------------------------------------------------

@app.websocket("/ws/terminal")
async def ws_terminal(ws: WebSocket) -> None:
    await ws.accept()
    room_name = ws.query_params.get("room", "").strip() or None
    use_tor = ws.query_params.get("tor", "") == "1"
    netns = None
    if room_name:
        room = manager.get_room(room_name)
        if room is None:
            await ws.send_json({"type": "error",
                                 "msg": f"room '{room_name}' no existe"})
            await ws.close()
            return
        if room.state != "connected":
            await ws.send_json({"type": "error",
                                 "msg": f"room '{room_name}' está en estado '{room.state}'"})
            await ws.close()
            return
        netns = room.netns

    tor_key: Optional[str] = None
    if use_tor and room_name:
        tor_key = f"room:{room_name}"

    async def send_status(line: str) -> None:
        try:
            await ws.send_bytes(("\r\n" + line + "\r\n").encode())
        except Exception:
            pass

    tor_proc: Optional[TorProcess] = None
    if tor_key is not None:
        try:
            tor_proc = tor_mgr.acquire(tor_key, netns)
        except Exception as exc:
            await ws.send_json({"type": "error",
                                 "msg": f"no se pudo lanzar tor: {exc}"})
            await ws.close()
            return
        # Stream del bootstrap al cliente. send_bytes para que xterm lo
        # imprima directamente sin pasar por la rama JSON.
        await send_status("\x1b[33m[riffle2] iniciando tor… espera al bootstrap 100%\x1b[0m")
        q = tor_proc.subscribe()
        try:
            while True:
                try:
                    line = await asyncio.wait_for(q.get(), timeout=90)
                except asyncio.TimeoutError:
                    await send_status("\x1b[31m[riffle2] tor tarda demasiado (>90s) — abortando\x1b[0m")
                    tor_proc.unsubscribe(q)
                    tor_mgr.release(tor_key)
                    await ws.close()
                    return
                if line is None:
                    # tor murió antes de bootstrap
                    await send_status("\x1b[31m[riffle2] tor terminó inesperadamente\x1b[0m")
                    tor_proc.unsubscribe(q)
                    tor_mgr.release(tor_key)
                    await ws.close()
                    return
                if line == "__BOOTSTRAPPED__":
                    break
                await send_status("\x1b[90m" + line + "\x1b[0m")
                if "Bootstrapped 100%" in line:
                    break
        finally:
            tor_proc.unsubscribe(q)
        await send_status("\x1b[32m[riffle2] tor listo — abriendo bash con torsocks\x1b[0m\r\n")

    session = PTYSession()
    try:
        cwd = "/root" if os.geteuid() == 0 else os.path.expanduser("~")
        session.start(cwd=cwd, netns=netns, tor=bool(tor_key))
    except Exception as exc:
        await ws.send_json({"type": "error", "msg": f"no se pudo arrancar pty: {exc}"})
        if tor_key is not None:
            tor_mgr.release(tor_key)
        await ws.close()
        return

    loop = asyncio.get_event_loop()
    stop = asyncio.Event()
    queue: asyncio.Queue = asyncio.Queue()

    def reader_thread() -> None:
        while True:
            data = session.read_blocking(8192, poll_timeout=0.05)
            if data:
                loop.call_soon_threadsafe(queue.put_nowait, data)
                continue
            try:
                pid, _ = os.waitpid(session.pid, os.WNOHANG)
                if pid != 0:
                    loop.call_soon_threadsafe(queue.put_nowait, b"")
                    return
            except (ChildProcessError, OSError):
                loop.call_soon_threadsafe(queue.put_nowait, b"")
                return
            if stop.is_set():
                return

    threading.Thread(target=reader_thread, daemon=True).start()

    async def from_pty() -> None:
        while not stop.is_set():
            try:
                data = await queue.get()
            except asyncio.CancelledError:
                return
            if not data:
                stop.set()
                return
            try:
                await ws.send_bytes(data)
            except Exception:
                stop.set()
                return

    async def to_pty() -> None:
        while not stop.is_set():
            try:
                msg = await ws.receive()
            except WebSocketDisconnect:
                stop.set()
                return
            except Exception:
                stop.set()
                return
            if msg.get("type") == "websocket.disconnect":
                stop.set()
                return
            if "text" in msg and msg["text"] is not None:
                txt = msg["text"]
                try:
                    obj = json.loads(txt)
                    if isinstance(obj, dict) and obj.get("action") == "resize":
                        session.resize(int(obj.get("rows", 24)),
                                       int(obj.get("cols", 80)))
                        continue
                except (json.JSONDecodeError, ValueError):
                    pass
                session.write(txt.encode("utf-8", errors="replace"))
            elif "bytes" in msg and msg["bytes"] is not None:
                session.write(msg["bytes"])

    try:
        await asyncio.gather(from_pty(), to_pty())
    finally:
        session.close()
        if tor_key is not None:
            tor_mgr.release(tor_key)
        try:
            await ws.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HTML embebido — página principal
# ---------------------------------------------------------------------------

INDEX_HTML = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>riffle2.1 — multi-VPN</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #0f0f23; color: #e0e0e0; margin: 0; padding: 24px;
         min-height: 100vh; box-sizing: border-box; }
  h1 { margin: 0 0 16px; color: #f39c12; font-size: 22px; }
  .panel { background: #16213e; border: 1px solid #333; border-radius: 8px;
           padding: 16px 20px; margin-bottom: 20px; }
  .panel h2 { margin: 0 0 12px; color: #3498db; font-size: 15px;
              font-weight: 500; }
  input, select { background: #0f0f23; color: #e0e0e0; border: 1px solid #333;
           padding: 8px 10px; border-radius: 4px; font-size: 14px; }
  select { min-width: 360px; }
  input { width: 130px; font-family: Consolas, monospace; }
  button { background: #3498db; color: white; border: 0; padding: 9px 18px;
           border-radius: 4px; cursor: pointer; font-size: 14px;
           font-weight: 500; }
  button.danger { background: #e74c3c; }
  button.secondary { background: #555; }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  .controls { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  table.rooms { border-collapse: collapse; width: 100%; }
  table.rooms th, table.rooms td { text-align: left; padding: 10px 12px;
                                    border-bottom: 1px solid #2a2a40; }
  table.rooms th { color: #888; font-size: 11px; text-transform: uppercase;
                   letter-spacing: 1px; font-weight: 500; }
  table.rooms td { font-size: 14px; }
  .flag { width: 36px; height: 24px; border-radius: 3px; object-fit: cover;
          vertical-align: middle; box-shadow: 0 1px 3px rgba(0,0,0,0.4); }
  .flag-ph { display: inline-block; width: 36px; height: 24px; border-radius: 3px;
             background: #222; vertical-align: middle; color:#555;
             text-align: center; font-size: 9px; line-height: 24px; }
  .state-pill { display: inline-block; padding: 2px 10px; border-radius: 10px;
                font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .state-creating, .state-connecting, .state-disconnecting {
    background: #f39c12; color: #000; }
  .state-connected { background: #2ecc71; color: #000; }
  .state-error { background: #e74c3c; color: #fff; }
  .muted { color: #888; font-size: 12px; }
  .mono { font-family: Consolas, monospace; font-size: 13px; }
  .host-exit { display: flex; gap: 12px; align-items: center;
               padding: 8px 12px; background: rgba(0,0,0,0.25);
               border-radius: 6px; }
  .dropzone { border: 2px dashed #444; border-radius: 6px;
              padding: 18px 20px; text-align: center; color: #888;
              transition: border-color .15s, background .15s; cursor: pointer; }
  .dropzone:hover, .dropzone.drag { border-color: #3498db;
                                    background: rgba(52,152,219,0.07);
                                    color: #ccc; }
  .upload-status { font-size: 13px; color: #aaa; margin-top: 8px;
                   font-family: Consolas, monospace; }
</style>
</head>
<body>
  <h1>riffle2.1 — multi-VPN simultáneo</h1>

  <div class="panel">
    <h2>Nueva room</h2>
    <div class="controls">
      <label class="muted">nombre</label>
      <input id="room-name" placeholder="goku" maxlength="8" pattern="[a-z0-9-]+">
      <button class="secondary" onclick="rollName()" title="Otro nombre DBZ aleatorio"
              style="padding:6px 10px;">🎲</button>
      <label class="muted">vpn</label>
      <select id="vpn-select"></select>
      <label class="muted" title="Encadena esta room sobre otra conectada (VPN-sobre-VPN). Por defecto sale directo por el host.">salir por</label>
      <select id="parent-select" title="host = salida directa; o elige un room conectado para encadenar">
        <option value="">host (directo)</option>
      </select>
      <button id="btn-create" onclick="createRoom()">Conectar</button>
      <button class="danger" id="btn-delete-tunnel"
              onclick="deleteSelectedTunnel()"
              title="Mueve el túnel seleccionado a trash/ o vless_trash/"
              style="padding:9px 12px;">🗑</button>
    </div>
    <div class="muted" id="vpn-count" style="margin-top:8px;"></div>
    <div id="create-error" style="display:none;margin-top:8px;color:#e74c3c;
         font-size:13px;"></div>
  </div>

  <div class="panel">
    <h2>Rooms activas <span class="muted" id="rooms-count"></span></h2>
    <table class="rooms" id="rooms-table">
      <thead>
        <tr><th></th><th>nombre</th><th>estado</th><th>país</th><th>IP</th>
            <th>uptime</th><th></th></tr>
      </thead>
      <tbody id="rooms-tbody">
        <tr><td colspan="7" class="muted">cargando…</td></tr>
      </tbody>
    </table>
  </div>

  <div class="panel">
    <h2>Salida real del host (sin VPN)</h2>
    <div class="host-exit" id="host-exit">
      <div class="flag-ph" id="host-flag-ph">…</div>
      <div>
        <div id="host-country" class="mono">consultando…</div>
        <div id="host-ip" class="mono muted">—</div>
      </div>
    </div>
  </div>

  <div class="panel">
    <h2>Añadir túneles nuevos (.ovpn / .vless)</h2>
    <div class="dropzone" id="dropzone" onclick="document.getElementById('fileinput').click()">
      Arrastra ficheros <code>.ovpn</code> o <code>.vless</code> aquí o haz click para seleccionarlos.
      Los <code>.ovpn</code> van a <code>inbox/</code>; los <code>.vless</code> a <code>vless_inbox/</code>.
    </div>
    <input type="file" id="fileinput" multiple accept=".ovpn,.vless" style="display:none">
    <div class="upload-status" id="upload-status"></div>
    <div style="margin-top:10px;">
      <button class="secondary" id="btn-check" onclick="launchCheck()">Comprobar inbox/ ahora</button>
      <button class="secondary" id="btn-check-vless" onclick="launchVlessCheck()"
              title="Valida los .vless de vless_inbox/ (DNS+TCP+TLS+WS)">
        Comprobar vless_inbox/ ahora
      </button>
      <span class="muted" id="check-status" style="margin-left:8px;"></span>
    </div>
    <div id="check-log-wrap" style="display:none;margin-top:12px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;">
        <span style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;">
          log de validación
        </span>
        <span class="muted" id="check-summary" style="font-size:11px;"></span>
        <span style="flex:1;"></span>
        <button class="secondary" id="btn-check-log-clear"
                onclick="hideCheckLog()" style="padding:3px 10px;font-size:11px;">
          ocultar
        </button>
      </div>
      <pre id="check-log" style="background:#000;color:#ddd;border:1px solid #333;
           border-radius:4px;padding:10px;margin:0;font-family:Consolas,monospace;
           font-size:12px;line-height:1.45;max-height:380px;overflow:auto;
           white-space:pre-wrap;word-break:break-word;"></pre>
    </div>
  </div>

  <div class="panel">
    <h2>Pegar URIs vless/hysteria2/vmess/trojan y validar</h2>
    <div class="muted" style="margin-bottom:8px;">
      Una URI por línea (<code>vless://</code>, <code>hysteria2://</code>,
      <code>vmess://</code> o <code>trojan://</code>; las que empiecen por
      <code>#</code> se ignoran). Cada URI se levanta como una sala real
      (netns + TUN + rutas + geo + estabilidad 15&nbsp;s) — lo que pase el
      chequeo conecta de verdad al crearle el room. Tarda ~50&nbsp;s por URI
      con 4 en paralelo (5 URIs ≈ 1 min, 20 URIs ≈ 4 min). hysteria2 usa
      sing-box; el resto, xray.
    </div>
    <textarea id="proxy-uris-input" rows="6"
              placeholder="vless://uuid@host:port?security=tls&type=ws&...#tag&#10;hysteria2://password@host:port?sni=...#tag&#10;vmess://<base64>&#10;trojan://password@host:port?security=tls&sni=...#tag"
              style="width:100%;box-sizing:border-box;background:#0f0f23;color:#e0e0e0;
                     border:1px solid #333;border-radius:4px;padding:8px 10px;
                     font-family:Consolas,monospace;font-size:12px;
                     resize:vertical;"></textarea>
    <div class="controls" style="margin-top:8px;">
      <button id="btn-validate-uris" onclick="validateProxyUris()">
        Validar a fondo y guardar OK
      </button>
      <span class="muted" id="proxy-uris-status"></span>
    </div>
    <div id="proxy-uris-results" style="margin-top:10px;font-size:12px;
         font-family:Consolas,monospace;"></div>
  </div>

<script>
let vpns = [];
let currentRooms = [];

// Nombres DBZ válidos para netns (regex [a-z0-9-]{1,8})
const DBZ_NAMES = [
  'goku', 'vegeta', 'gohan', 'piccolo', 'krillin', 'trunks', 'bulma',
  'chichi', 'frieza', 'cell', 'buu', 'raditz', 'nappa', 'kakarot',
  'yamcha', 'tien', 'dende', 'broly', 'beerus', 'whis', 'jiren', 'hit',
  'kale', 'goten', 'bardock', 'cooler', 'dabura', 'oolong', 'pilaf',
  'uub', 'tapion', 'zeno', 'guldo', 'zarbon', 'turles', 'videl', 'pan',
  'babidi', 'recoome', 'majin', 'gogeta', 'vegito', 'kefla'
];

function pickRandomName() {
  const taken = new Set(currentRooms.map(r => r.name));
  const free = DBZ_NAMES.filter(n => !taken.has(n));
  const pool = free.length ? free : DBZ_NAMES;
  return pool[Math.floor(Math.random() * pool.length)];
}

function rollName() {
  document.getElementById('room-name').value = pickRandomName();
}

function flagEmoji(cc) {
  if (!cc) return '⚪';
  return cc.toUpperCase().replace(/./g, c =>
    String.fromCodePoint(127397 + c.charCodeAt(0)));
}

async function loadVpns() {
  const r = await fetch('/api/vpns');
  vpns = await r.json();
  const sel = document.getElementById('vpn-select');
  sel.innerHTML = '';
  vpns.sort((a, b) => (a.country || 'ZZ').localeCompare(b.country || 'ZZ') ||
                       a.name.localeCompare(b.name));
  for (const v of vpns) {
    const opt = document.createElement('option');
    const bwTag = v.bandwidth_mbps > 0 ? ` · ${v.bandwidth_mbps.toFixed(1)} Mbps` : '';
    const validatedTag = v.validated ? ' ✓' : '';
    const kindTag = (v.kind || 'ovpn').toUpperCase();
    opt.value = v.path;
    opt.textContent = `[${kindTag}] ${flagEmoji(v.country_code)}  ${v.country || '?'} — ${v.name}${bwTag}${validatedTag}`;
    sel.appendChild(opt);
  }
  const nVless = vpns.filter(x => x.kind === 'vless').length;
  const nOvpn  = vpns.filter(x => x.kind !== 'vless').length;
  document.getElementById('vpn-count').textContent =
    `${vpns.length} túneles disponibles · ${nOvpn} OVPN · ${nVless} VLESS ` +
    `(${vpns.filter(x => x.validated).length} validados)`;
}

async function createRoom() {
  const name = document.getElementById('room-name').value.trim().toLowerCase();
  const path = document.getElementById('vpn-select').value;
  const parent = document.getElementById('parent-select').value;
  const err = document.getElementById('create-error');
  err.style.display = 'none';
  if (!name) { err.textContent = 'pon un nombre (a-z0-9-, max 8 chars)';
               err.style.display = ''; return; }
  if (!path) { err.textContent = 'elige un .ovpn'; err.style.display = ''; return; }

  document.getElementById('btn-create').disabled = true;
  try {
    const body = {name, path};
    if (parent) body.parent = parent;
    const r = await fetch('/api/rooms', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok) {
      err.textContent = d.detail || 'error desconocido';
      err.style.display = '';
    } else {
      // tras éxito, dejar el siguiente nombre DBZ listo
      await refreshRooms();   // actualizar currentRooms para que el roll evite el recién creado
      rollName();
    }
  } catch (e) {
    err.textContent = 'error de red: ' + e;
    err.style.display = '';
  }
  document.getElementById('btn-create').disabled = false;
  refreshRooms();
}

async function deleteSelectedTunnel() {
  const sel = document.getElementById('vpn-select');
  const opt = sel.options[sel.selectedIndex];
  if (!opt || !opt.value) {
    alert('no hay túnel seleccionado');
    return;
  }
  const path = opt.value;
  const label = opt.textContent;
  if (!confirm(`¿Mover a trash/ este túnel?\\n\\n${label}\\n${path}`)) {
    return;
  }
  const btn = document.getElementById('btn-delete-tunnel');
  btn.disabled = true;
  try {
    const r = await fetch('/api/tunnels?path=' + encodeURIComponent(path),
                          {method: 'DELETE'});
    const data = await r.json();
    if (!r.ok) {
      alert('error: ' + (data.detail || 'desconocido'));
    } else {
      await loadVpns();
    }
  } catch (e) {
    alert('error de red: ' + e);
  }
  btn.disabled = false;
}

function collectDescendants(name, byName) {
  // BFS sobre rm.children para devolver todos los descendientes (no incluye name)
  const out = [];
  const queue = [name];
  while (queue.length) {
    const n = queue.shift();
    const rm = byName[n];
    if (!rm) continue;
    for (const c of (rm.children || [])) {
      if (!out.includes(c)) {
        out.push(c);
        queue.push(c);
      }
    }
  }
  return out;
}

async function deleteRoom(name) {
  const byName = Object.fromEntries(currentRooms.map(r => [r.name, r]));
  const descendants = collectDescendants(name, byName);
  let msg = `¿Desconectar y borrar la room "${name}"?`;
  if (descendants.length) {
    msg += `\n\nSe destruirán en cascada también: ${descendants.join(', ')}`;
  }
  if (!confirm(msg)) return;
  await fetch('/api/rooms/' + encodeURIComponent(name), {method: 'DELETE'});
  refreshRooms();
}

function fmtDur(s) {
  if (!s) return '—';
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + (s % 60) + 's';
  return Math.floor(s/3600) + 'h ' + Math.floor((s % 3600)/60) + 'm';
}

function refreshParentSelect(rooms) {
  const sel = document.getElementById('parent-select');
  if (!sel) return;
  const prev = sel.value;
  // Limpiar todo menos la opción "host"
  while (sel.options.length > 1) sel.remove(1);
  for (const rm of rooms) {
    if (rm.state !== 'connected') continue;
    const opt = document.createElement('option');
    const cc = (rm.country_code || '').toUpperCase();
    const fe = flagEmoji(rm.country_code);
    opt.value = rm.name;
    opt.textContent = `${fe} rfl-${rm.name}${cc ? ' ('+cc+')' : ''}`;
    sel.appendChild(opt);
  }
  // Preservar selección previa si sigue válida
  if ([...sel.options].some(o => o.value === prev)) sel.value = prev;
}

async function refreshRooms() {
  try {
    const r = await fetch('/api/rooms');
    const rooms = await r.json();
    currentRooms = rooms;   // exposed to pickRandomName
    refreshParentSelect(rooms);
    const tbody = document.getElementById('rooms-tbody');
    if (!rooms.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">' +
        'sin rooms activas — crea una arriba</td></tr>';
    } else {
      tbody.innerHTML = rooms.map(rm => {
        const cc = (rm.country_code || '').toLowerCase();
        const flag = cc ? `<img class="flag" src="https://flagcdn.com/w80/${cc}.png" alt="${cc}">`
                        : `<span class="flag-ph">?</span>`;
        const ipText = rm.ip || (rm.state === 'error' ? '—' : '…');
        const country = rm.country ? `${rm.country} (${rm.country_code})` : '—';
        const shellBtn = rm.state === 'connected'
          ? `<button class="secondary" onclick="window.open('/shell?room=${encodeURIComponent(rm.name)}', '_blank', 'noopener')">SHELL</button>`
          : `<button class="secondary" disabled>SHELL</button>`;
        const torBtn = rm.state === 'connected'
          ? `<button class="secondary" title="bash con torsocks dentro del netns del room (tor → VPN)" onclick="window.open('/shell?room=${encodeURIComponent(rm.name)}&tor=1', '_blank', 'noopener')">SHELL+TOR</button>`
          : `<button class="secondary" disabled>SHELL+TOR</button>`;
        const errLine = rm.error
          ? `<div class="muted" style="color:#e74c3c;font-size:11px;margin-top:2px;">${rm.error}</div>` : '';
        const parentChip = rm.parent
          ? ` <span class="muted" title="Esta room sale por el túnel de rfl-${rm.parent}" style="font-size:11px;color:#9b59b6;">↳ rfl-${rm.parent}</span>`
          : '';
        const kindChip = rm.kind === 'vless'
          ? ` <span title="Túnel VLESS (xray)" style="font-size:10px;padding:1px 6px;border-radius:8px;background:#8e44ad;color:#fff;font-weight:600;">VLESS</span>`
          : ` <span title="Túnel OpenVPN" style="font-size:10px;padding:1px 6px;border-radius:8px;background:#2980b9;color:#fff;font-weight:600;">OVPN</span>`;
        const childrenChip = (rm.children && rm.children.length)
          ? ` <span class="muted" title="Rooms encadenadas sobre esta" style="font-size:11px;color:#16a085;">↳[${rm.children.length}]</span>`
          : '';
        return `<tr>
          <td>${flag}</td>
          <td class="mono">${rm.name}${kindChip}${parentChip}${childrenChip}${errLine}</td>
          <td><span class="state-pill state-${rm.state}">${rm.state}</span></td>
          <td>${country}</td>
          <td class="mono">${ipText}</td>
          <td>${fmtDur(rm.uptime_s)}</td>
          <td>${shellBtn} ${torBtn} <button class="danger" onclick="deleteRoom('${rm.name}')">✗</button></td>
        </tr>`;
      }).join('');
    }
    document.getElementById('rooms-count').textContent = rooms.length
      ? `(${rooms.length})` : '';
  } catch (e) {
    console.error(e);
  }
}

async function refreshHostExit() {
  try {
    const r = await fetch('/api/realip');
    const d = await r.json();
    const ph = document.getElementById('host-flag-ph');
    if (d.country_code) {
      const cc = d.country_code.toLowerCase();
      ph.outerHTML = `<img id="host-flag-ph" class="flag" src="https://flagcdn.com/w80/${cc}.png" alt="${cc}">`;
    }
    document.getElementById('host-country').textContent =
      d.country ? `${d.country} (${d.country_code})` : 'desconocido';
    document.getElementById('host-ip').textContent = d.ip || '—';
  } catch (e) {}
}

loadVpns();
refreshRooms().then(() => rollName());   // primer nombre DBZ al cargar
refreshHostExit();
setInterval(refreshRooms, 3000);
setInterval(refreshHostExit, 10000);

// -------- Upload de .ovpn --------
const dropzone = document.getElementById('dropzone');
const fileinput = document.getElementById('fileinput');
const uploadStatus = document.getElementById('upload-status');

function _preventDef(e) { e.preventDefault(); e.stopPropagation(); }

// Si el usuario suelta el fichero fuera del dropzone (aunque sea por unos
// píxeles), por defecto el navegador navega al fichero. Lo prevenimos a
// nivel de window para que esto no rompa la sesión.
['dragover', 'drop'].forEach(evt => {
  window.addEventListener(evt, _preventDef, false);
});

// Handlers explícitos por evento. Antes había dos listeners separados sobre
// 'drop' (uno marcaba la clase, otro subía); en algunos navegadores la
// combinación con stopPropagation provocaba que el segundo no se invocara.
dropzone.addEventListener('dragenter', (e) => {
  _preventDef(e);
  dropzone.classList.add('drag');
});
dropzone.addEventListener('dragover', (e) => {
  _preventDef(e);
  // dataTransfer.dropEffect debe fijarse en cada dragover, si no algunos
  // navegadores cambian el cursor a "no permitido" y rechazan el drop.
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
  dropzone.classList.add('drag');
});
dropzone.addEventListener('dragleave', (e) => {
  _preventDef(e);
  dropzone.classList.remove('drag');
});
dropzone.addEventListener('drop', (e) => {
  _preventDef(e);
  dropzone.classList.remove('drag');
  const files = (e.dataTransfer && e.dataTransfer.files)
    ? Array.from(e.dataTransfer.files) : [];
  if (files.length) uploadFiles(files);
});

fileinput.addEventListener('change', () => {
  uploadFiles(Array.from(fileinput.files));
  fileinput.value = '';
});

async function uploadFiles(files) {
  if (!files.length) return;
  uploadStatus.textContent = `Subiendo ${files.length} fichero(s)…`;
  const results = [];
  let okOvpn = 0, okVless = 0;
  for (const f of files) {
    const lf = f.name.toLowerCase();
    if (!(lf.endsWith('.ovpn') || lf.endsWith('.vless'))) {
      results.push(`✗ ${f.name} (no es .ovpn / .vless)`);
      continue;
    }
    const fd = new FormData();
    fd.append('file', f);
    try {
      const r = await fetch('/api/upload', {method: 'POST', body: fd});
      const data = await r.json();
      if (r.ok) {
        results.push(`✓ ${data.saved} (${(data.size/1024).toFixed(1)} KB)`);
        if (data.kind === 'vless') okVless += 1; else okOvpn += 1;
      } else {
        results.push(`✗ ${f.name}: ${data.detail || 'error'}`);
      }
    } catch (e) {
      results.push(`✗ ${f.name}: ${e}`);
    }
  }
  uploadStatus.innerHTML = results.join('<br>');
  // Auto-disparar la validación adecuada. Si hay ambos tipos, primero VLESS
  // (no requiere root y tarda segundos) y luego dejamos OpenVPN al usuario —
  // o también lo lanzamos en cadena cuando termine. Para mantenerlo simple,
  // priorizamos OpenVPN (más lento) y dejamos VLESS como segundo botón si
  // hace falta.
  if (okOvpn > 0) {
    uploadStatus.innerHTML +=
      '<br><span style="color:#3498db;">Lanzando validación OpenVPN…</span>';
    launchCheck();
  } else if (okVless > 0) {
    uploadStatus.innerHTML +=
      '<br><span style="color:#8e44ad;">Lanzando validación VLESS…</span>';
    launchVlessCheck();
  }
}

// ---- Validación con log en vivo ----------------------------------------
let checkPoller = null;
let checkLogOffset = 0;
let lastVpnRefreshTick = 0;

function hideCheckLog() {
  document.getElementById('check-log-wrap').style.display = 'none';
}

function showCheckLog() {
  document.getElementById('check-log-wrap').style.display = '';
}

function summarizeLog(text) {
  // Cuenta OK/KO/AUTH/BAD a partir de las líneas tipo "  [X/Y] OK  …"
  const re = /\b(OK|KO|AUTH|BAD)\b/g;
  const counts = {OK: 0, KO: 0, AUTH: 0, BAD: 0};
  for (const line of text.split('\\n')) {
    if (!/^\s*\[\s*\d+\/\d+\]/.test(line)) continue;
    const m = line.match(re);
    if (m && m.length) counts[m[0]] = (counts[m[0]] || 0) + 1;
  }
  const parts = [];
  if (counts.OK)   parts.push(`${counts.OK} OK`);
  if (counts.KO)   parts.push(`${counts.KO} KO`);
  if (counts.AUTH) parts.push(`${counts.AUTH} auth`);
  if (counts.BAD)  parts.push(`${counts.BAD} bad`);
  return parts.join(' · ');
}

function startCheckPoller(pid) {
  const statusEl = document.getElementById('check-status');
  const logEl = document.getElementById('check-log');
  const summaryEl = document.getElementById('check-summary');
  const btn = document.getElementById('btn-check');
  const btnVless = document.getElementById('btn-check-vless');
  if (checkPoller) clearInterval(checkPoller);
  lastVpnRefreshTick = 0;
  let tick = 0;
  const poll = async () => {
    try {
      const lr = await fetch('/api/check-log?offset=' + checkLogOffset);
      const ld = await lr.json();
      if (ld.content) {
        logEl.textContent += ld.content;
        logEl.scrollTop = logEl.scrollHeight;
        summaryEl.textContent = summarizeLog(logEl.textContent);
      }
      checkLogOffset = ld.offset;
      tick += 1;
      // refresco del dropdown cada ~6s (cuando el validador va moviendo
      // ficheros a ok/, queremos verlos aparecer sin esperar al final)
      if (tick - lastVpnRefreshTick >= 4) {
        lastVpnRefreshTick = tick;
        loadVpns();
      }
      if (!ld.running) {
        clearInterval(checkPoller);
        checkPoller = null;
        const summary = summarizeLog(logEl.textContent);
        statusEl.textContent = summary
          ? `validación completa — ${summary}`
          : 'validación completa';
        btn.disabled = false;
        if (btnVless) btnVless.disabled = false;
        loadVpns();
      }
    } catch (e) {
      console.error('check-log poll', e);
    }
  };
  poll();   // primer tick inmediato
  checkPoller = setInterval(poll, 1500);
}

async function launchCheck() {
  const btn = document.getElementById('btn-check');
  const statusEl = document.getElementById('check-status');
  const logEl = document.getElementById('check-log');
  const summaryEl = document.getElementById('check-summary');
  if (checkPoller) {
    // Ya hay polling activo de una validación en curso — sólo asegurar el panel
    showCheckLog();
    return;
  }
  btn.disabled = true;
  showCheckLog();
  logEl.textContent = '';
  summaryEl.textContent = '';
  checkLogOffset = 0;
  statusEl.textContent = 'lanzando…';
  try {
    const r = await fetch('/api/check-inbox', {method: 'POST'});
    const data = await r.json();
    if (!r.ok) {
      // 409 = ya hay un proceso corriendo: nos enganchamos a ese
      if (r.status === 409) {
        statusEl.textContent = data.detail || 'ya hay una validación corriendo';
        startCheckPoller();
        return;
      }
      statusEl.textContent = 'error: ' + (data.detail || 'desconocido');
      btn.disabled = false;
      return;
    }
    statusEl.textContent = `validando (PID ${data.pid})…`;
    startCheckPoller(data.pid);
  } catch (e) {
    statusEl.textContent = 'error: ' + e;
    btn.disabled = false;
  }
}

async function validateProxyUris() {
  const ta = document.getElementById('proxy-uris-input');
  const btn = document.getElementById('btn-validate-uris');
  const statusEl = document.getElementById('proxy-uris-status');
  const resultsEl = document.getElementById('proxy-uris-results');
  const uris = ta.value.split('\\n').map(s => s.trim())
                 .filter(s => s && !s.startsWith('#'));
  if (!uris.length) {
    statusEl.textContent = 'pega al menos una URI (vless/hysteria2/vmess/trojan)';
    return;
  }
  btn.disabled = true;
  // 4 workers, ~50s por URI ⇒ ceil(n/4)*50s ± solapamiento.
  const etaSec = Math.ceil(uris.length / 4) * 50;
  const etaTxt = etaSec >= 60
    ? `~${Math.round(etaSec/60)} min`
    : `~${etaSec} s`;
  statusEl.textContent =
    `validando ${uris.length} URI(s) a fondo (${etaTxt}, no cierres la pestaña)…`;
  resultsEl.innerHTML = '';
  try {
    const r = await fetch('/api/check-proxy-uris', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({uris}),
    });
    const data = await r.json();
    if (!r.ok) {
      statusEl.textContent = 'error: ' + (data.detail || 'desconocido');
      btn.disabled = false;
      return;
    }
    const s = data.summary;
    const dup = s.duplicated || 0;
    statusEl.textContent =
      `${s.ok} OK · ${s.auth} auth · ${s.dead} muertos · ` +
      `${s.malformed} malformed · ${dup} duplicados`;
    // Pintar tabla con resultados
    const rows = data.results.map(res => {
      const colors = {ok: '#2ecc71', auth: '#f39c12',
                      dead: '#e74c3c', malformed: '#888',
                      duplicated: '#7f8c8d'};
      const c = colors[res.status] || '#888';
      const kindLabel = res.kind
        ? ` <span style="color:#9b59b6;font-weight:600;">[${res.kind}]</span>` : '';
      const tag = res.tag ? ` <span style="color:#aaa;">#${res.tag}</span>` : '';
      const bw = (res.bandwidth_mbps && res.bandwidth_mbps > 0)
        ? ` <span style="color:#1abc9c;">· ${res.bandwidth_mbps.toFixed(1)} Mbps</span>` : '';
      const saved = res.saved_as
        ? `<span style="color:#3498db;">→ ${res.saved_as}</span>` : '';
      const reason = res.reason
        ? `<div style="color:#999;font-size:11px;padding-left:60px;">${res.reason}</div>` : '';
      const uriTrunc = res.uri.length > 80
        ? res.uri.slice(0, 77) + '…' : res.uri;
      return `<div style="padding:3px 0;border-bottom:1px solid #222;">
        <span style="display:inline-block;width:50px;color:${c};font-weight:600;">
          ${res.status.toUpperCase()}
        </span>${kindLabel}
        <span style="color:#ddd;">${res.target || '?'}</span>${tag}${bw}
        ${saved}
        <div style="color:#666;font-size:11px;padding-left:60px;">${uriTrunc}</div>
        ${reason}
      </div>`;
    });
    resultsEl.innerHTML = rows.join('');
    // Si guardamos alguna, refrescar el dropdown para que aparezca enseguida
    if (s.ok > 0) {
      loadVpns();
    }
    // Limpiar el textarea sólo si no quedó nada que retocar (ok+dup contaron
    // como ya resueltas; auth/dead/malformed implican algo que arreglar).
    if ((s.auth + s.dead + s.malformed) === 0) ta.value = '';
  } catch (e) {
    statusEl.textContent = 'error de red: ' + e;
  }
  btn.disabled = false;
}

async function launchVlessCheck() {
  const btn = document.getElementById('btn-check-vless');
  const statusEl = document.getElementById('check-status');
  const logEl = document.getElementById('check-log');
  const summaryEl = document.getElementById('check-summary');
  if (checkPoller) { showCheckLog(); return; }
  btn.disabled = true;
  showCheckLog();
  logEl.textContent = '';
  summaryEl.textContent = '';
  checkLogOffset = 0;
  statusEl.textContent = 'validando VLESS…';
  try {
    const r = await fetch('/api/check-vless-inbox', {method: 'POST'});
    const data = await r.json();
    if (!r.ok) {
      if (r.status === 409) {
        statusEl.textContent = data.detail || 'ya hay una validación corriendo';
        startCheckPoller();
        return;
      }
      statusEl.textContent = 'error: ' + (data.detail || 'desconocido');
      btn.disabled = false;
      return;
    }
    statusEl.textContent = `validando VLESS (PID ${data.pid})…`;
    startCheckPoller(data.pid);
  } catch (e) {
    statusEl.textContent = 'error: ' + e;
    btn.disabled = false;
  }
}

// Si al cargar la página ya hay una validación corriendo (p.ej. usuario
// recargó), reengancharse y mostrar el log donde se quedó.
async function attachIfRunning() {
  try {
    const r = await fetch('/api/check-log?offset=0');
    const d = await r.json();
    if (d.running) {
      showCheckLog();
      const logEl = document.getElementById('check-log');
      logEl.textContent = d.content || '';
      logEl.scrollTop = logEl.scrollHeight;
      checkLogOffset = d.offset;
      document.getElementById('check-status').textContent =
        `validando (PID ${d.pid})…`;
      document.getElementById('btn-check').disabled = true;
      startCheckPoller(d.pid);
    }
  } catch (e) {}
}
attachIfRunning();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTML embebido — /shell (full-screen, opcionalmente con ?room=...)
# ---------------------------------------------------------------------------

SHELL_HTML = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>riffle2.1 — shell</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<style>
  :root { color-scheme: dark; }
  html, body { margin: 0; padding: 0; height: 100%; background: #000;
               font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
               color: #ddd; overflow: hidden; }
  #topbar { display: flex; align-items: center; gap: 12px;
            background: #16213e; border-bottom: 1px solid #333;
            padding: 6px 14px; height: 36px; box-sizing: border-box;
            font-size: 13px; }
  #topbar .title { color: #f39c12; font-weight: 600; }
  #topbar .muted { color: #888; font-size: 12px; }
  #topbar .pill { display: inline-block; padding: 2px 8px; border-radius: 10px;
                  font-size: 11px; font-weight: 600; background: #555; color: #ddd; }
  #topbar .pill.live { background: #2ecc71; color: #000; }
  #topbar .pill.dead { background: #e74c3c; color: #fff; }
  #topbar button { background: #555; color: #fff; border: 0; padding: 4px 10px;
                   border-radius: 4px; font-size: 12px; cursor: pointer; }
  #real-exit { display: flex; align-items: center; gap: 8px;
               padding: 2px 10px; border-radius: 14px;
               background: rgba(255,255,255,0.04); transition: background .3s; }
  #real-exit.changed { background: rgba(46,204,113,0.28); }
  #real-flag-img, #real-flag-ph { width: 24px; height: 16px; border-radius: 2px;
                                  display: block; }
  #real-flag-img { object-fit: cover; }
  #real-flag-ph { background: #222; }
  #real-country { font-weight: 600; color: #f1c40f; font-size: 12px; }
  #real-ip { font-family: Consolas, monospace; font-size: 11px; color: #aaa; }
  #real-age { font-size: 10px; color: #666; }
  #term-host { position: absolute; top: 36px; left: 0; right: 0; bottom: 0;
               background: #000; padding: 6px; box-sizing: border-box; }
  #term-host .xterm, #term-host .xterm-viewport, #term-host .xterm-screen {
    background: #000 !important; height: 100% !important; }
</style>
</head>
<body>
  <div id="topbar">
    <span class="title" id="title">riffle2.1 shell</span>
    <span class="pill" id="pill">conectando…</span>
    <span class="muted" id="room-label"></span>
    <span style="flex:1;"></span>
    <span id="real-exit" title="Salida real (refresco cada 5s)">
      <span id="real-flag-ph"></span>
      <span id="real-country">…</span>
      <span id="real-ip"></span>
      <span id="real-age"></span>
    </span>
    <button onclick="refreshRealExit(true)" title="Forzar consulta">↻ IP</button>
    <button onclick="reconnectTerm()">Reconectar</button>
  </div>
  <div id="term-host"></div>

<script>
const params = new URLSearchParams(location.search);
const roomName = params.get('room') || '';
const useTor = params.get('tor') === '1';
const realipUrl = roomName
  ? '/api/rooms/' + encodeURIComponent(roomName) + '/realip'
  : '/api/realip';

if (roomName && useTor) {
  document.title = 'riffle2.1 — shell · tor · ' + roomName;
  document.getElementById('title').textContent = 'bash · tor @ ' + roomName;
  document.getElementById('room-label').textContent = '(netns rfl-' + roomName + ' + tor)';
} else if (roomName) {
  document.getElementById('title').textContent = 'bash @ ' + roomName;
  document.getElementById('room-label').textContent = '(netns rfl-' + roomName + ')';
}

let term, fitAddon, ws;

function setPill(text, cls) {
  const p = document.getElementById('pill');
  p.textContent = text;
  p.className = 'pill ' + (cls || '');
}

function sendResize() {
  if (!ws || ws.readyState !== 1 || !term) return;
  ws.send(JSON.stringify({action: 'resize', rows: term.rows, cols: term.cols}));
}

function connectTermWs() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const qsParts = [];
  if (roomName) qsParts.push('room=' + encodeURIComponent(roomName));
  if (useTor) qsParts.push('tor=1');
  const qs = qsParts.length ? ('?' + qsParts.join('&')) : '';
  ws = new WebSocket(proto + '//' + location.host + '/ws/terminal' + qs);
  ws.binaryType = 'arraybuffer';
  setPill('conectando…', '');
  ws.onopen = () => { setPill('en vivo', 'live'); setTimeout(sendResize, 80); };
  ws.onmessage = (e) => {
    if (e.data instanceof ArrayBuffer) {
      term.write(new Uint8Array(e.data));
    } else if (typeof e.data === 'string') {
      try {
        const obj = JSON.parse(e.data);
        if (obj.type === 'error') {
          term.write('\\r\\n\\x1b[31m[error] ' + obj.msg + '\\x1b[0m\\r\\n');
        }
      } catch (_) { term.write(e.data); }
    }
  };
  ws.onclose = () => setPill('desconectado', 'dead');
  ws.onerror = () => setPill('error', 'dead');
}

function reconnectTerm() {
  if (ws) try { ws.close(); } catch (_) {}
  setTimeout(connectTermWs, 200);
}

function initTerm() {
  term = new Terminal({
    cursorBlink: true,
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: 14,
    theme: { background: '#000', foreground: '#e0e0e0' },
    scrollback: 10000,
  });
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById('term-host'));
  term.onData((d) => {
    if (ws && ws.readyState === 1) ws.send(d);
  });
  setTimeout(() => { fitAddon.fit(); sendResize(); }, 80);
  connectTermWs();
  window.addEventListener('resize', () => {
    try { fitAddon.fit(); sendResize(); } catch (_) {}
  });
  term.focus();
}

// -------- Salida real (host o netns según ?room) --------
let lastRealIp = '';

async function refreshRealExit(force) {
  try {
    const r = await fetch(realipUrl + (force ? '?force=true' : ''));
    const d = await r.json();
    const wrap = document.getElementById('real-exit');
    const flagPh = document.getElementById('real-flag-ph');
    const country = document.getElementById('real-country');
    const ip = document.getElementById('real-ip');
    const age = document.getElementById('real-age');
    if (d.country_code) {
      const cc = d.country_code.toLowerCase();
      flagPh.outerHTML = `<img id="real-flag-ph" src="https://flagcdn.com/w40/${cc}.png" alt="${cc}" style="width:24px;height:16px;border-radius:2px;object-fit:cover;">`;
    }
    country.textContent = d.country_code
      ? `${d.country_code}` : (d.ip ? '?' : 'sin red');
    country.title = d.country || '';
    ip.textContent = d.ip || '—';
    if (d.age_s !== null && d.age_s !== undefined) {
      age.textContent = d.cached ? `· ${d.age_s}s` : '· live';
    } else {
      age.textContent = '';
    }
    if (d.ip && lastRealIp && d.ip !== lastRealIp) {
      wrap.classList.remove('changed');
      void wrap.offsetWidth;
      wrap.classList.add('changed');
      setTimeout(() => wrap.classList.remove('changed'), 1500);
    }
    if (d.ip) lastRealIp = d.ip;
  } catch (e) {
    document.getElementById('real-country').textContent = 'err';
  }
}

refreshRealExit();
setInterval(refreshRealExit, 5000);
initTerm();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _shutdown_handler(signum, frame):
    print(f"[riflle21] señal {signum} recibida", file=sys.stderr)
    try:
        manager.shutdown()
    finally:
        sys.exit(0)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="riflle21_ui",
                                description="riffle2.1 — multi-VPN UI")
    p.add_argument("--cleanup-orphans", action="store_true",
                   help="Borra todos los netns rfl-* y reglas iptables huérfanas")
    p.add_argument("--host", default=HOST)
    p.add_argument("--port", type=int, default=PORT)
    args = p.parse_args(argv)

    if args.cleanup_orphans:
        if os.geteuid() != 0:
            print("--cleanup-orphans requiere root", file=sys.stderr)
            return 2
        summary = net.cleanup_orphans()
        print(f"limpiados: netns={summary['netns']}, veth={summary['veth']}")
        net.teardown_iptables_chains()
        return 0

    if os.geteuid() != 0:
        print("AVISO: no estás como root. La UI funcionará pero crear rooms "
              "fallará. Relánzalo con: sudo python3 riflle21_ui.py",
              file=sys.stderr)

    signal.signal(signal.SIGTERM, _shutdown_handler)
    manager.bootstrap()

    print(f"[riflle21] arrancando en http://{args.host}:{args.port}/")
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    except KeyboardInterrupt:
        print("[riflle21] Ctrl-C recibido", file=sys.stderr)
    finally:
        manager.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
