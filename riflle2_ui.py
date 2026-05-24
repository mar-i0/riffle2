#!/usr/bin/env python3
"""riflle2_ui — interfaz web sobre el validador riflle2.

Lista las VPN disponibles (ok/ + inbox/), permite conectar a una con un click,
muestra estado, IP externa, país, bandera y bandwidth opcional.

Lanzar como root:
    sudo python3 riflle2_ui.py
Después abrir (escucha por defecto en 0.0.0.0, accesible desde la LAN):
    http://127.0.0.1:8060/  o  http://<IP-de-esta-maquina>:8060/
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Reutilizamos lógica del validador CLI
sys.path.insert(0, str(Path(__file__).resolve().parent))
import riflle2  # type: ignore

ROOT = Path(__file__).resolve().parent
INBOX = ROOT / "inbox"
OK_DIR = ROOT / "ok"
CACHE_FILE = ROOT / ".riflle2_cache.json"
HOST = os.environ.get("RIFLLE2_HOST", "0.0.0.0")
PORT = int(os.environ.get("RIFLLE2_PORT", "8060"))


# ---------------------------------------------------------------------------
# Estado global
# ---------------------------------------------------------------------------

@dataclass
class ConnectionState:
    state: str = "idle"  # idle | connecting | connected | disconnecting | error
    file: str = ""
    ip: str = ""
    country_code: str = ""
    country: str = ""
    bandwidth_mbps: float = 0.0
    started_at: float = 0.0
    error: str = ""
    log_tail: list[str] = field(default_factory=list)


class VPNManager:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.state = ConnectionState()
        self.proc: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        self.baseline_ip = ""

    def init_baseline(self) -> None:
        ip, code, country = riflle2.baseline_geo()
        self.baseline_ip = ip
        print(f"[riflle2_ui] baseline: {ip} [{code}] {country}")

    # -- API ------------------------------------------------------------

    def snapshot(self) -> dict:
        with self.lock:
            return asdict(self.state)

    def connect(self, ovpn_path: Path) -> None:
        with self.lock:
            if self.state.state in ("connecting", "connected"):
                raise RuntimeError(f"ya hay una conexión {self.state.state}; "
                                   f"desconecta primero")
            self.state = ConnectionState(state="connecting", file=ovpn_path.name,
                                         started_at=time.time())
        self.thread = threading.Thread(
            target=self._connect_thread, args=(ovpn_path,), daemon=True
        )
        self.thread.start()

    def disconnect(self) -> None:
        with self.lock:
            if self.state.state == "idle":
                return
            self.state.state = "disconnecting"
            proc = self.proc
        if proc:
            riflle2.kill_proc_group(proc)
        with self.lock:
            self.proc = None
            self.state = ConnectionState(state="idle")

    def measure_bandwidth_now(self) -> float:
        with self.lock:
            if self.state.state != "connected":
                raise RuntimeError("no hay conexión activa")
        bw = riflle2.measure_bandwidth()
        with self.lock:
            self.state.bandwidth_mbps = bw
        return bw

    # -- Internals ------------------------------------------------------

    def _push_log(self, line: str) -> None:
        with self.lock:
            self.state.log_tail.append(line.rstrip())
            # Conservar solo las últimas 30 líneas
            self.state.log_tail = self.state.log_tail[-30:]

    def _connect_thread(self, ovpn_path: Path) -> None:
        # Decidir si forzar redirect-gateway: si el fichero ya tiene el patch o
        # `redirect-gateway` propio, no añadimos nada. Si no, lo forzamos por CLI.
        text = ovpn_path.read_text(errors="replace")
        force = not (riflle2.has_redirect_gateway(text) or riflle2.PATCH_MARKER in text)

        cmd = [
            riflle2.OPENVPN_BIN,
            "--config", str(ovpn_path),
            "--connect-timeout", "10",
            "--connect-retry", "0",
            "--resolv-retry", "0",
            "--pull-filter", "ignore", "block-outside-dns",
            "--verb", "3",
        ]
        if force:
            cmd += [
                "--redirect-gateway", "def1",
                "--dhcp-option", "DNS", "1.1.1.1",
                "--dhcp-option", "DNS", "8.8.8.8",
            ]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd="/tmp",
                preexec_fn=os.setsid,
            )
        except OSError as exc:
            with self.lock:
                self.state.state = "error"
                self.state.error = f"openvpn spawn: {exc}"
            return

        with self.lock:
            self.proc = proc

        start = time.monotonic()
        timeout = 45
        ok = False
        dead_reason = ""

        while time.monotonic() - start < timeout:
            assert proc.stdout is not None
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            self._push_log(line)
            if riflle2.OK_MARKER in line:
                ok = True
                break
            for m in riflle2.DEAD_MARKERS:
                if m in line:
                    dead_reason = m
                    break
            if dead_reason:
                break

        if not ok:
            riflle2.kill_proc_group(proc)
            with self.lock:
                self.proc = None
                self.state.state = "error"
                self.state.error = dead_reason or "timeout esperando handshake"
            return

        # Túnel arriba: dejar que se asienten las rutas y consultar geo
        time.sleep(2)
        ip, code, country = riflle2.query_geo(timeout=8)
        if not ip:
            riflle2.kill_proc_group(proc)
            with self.lock:
                self.proc = None
                self.state.state = "error"
                self.state.error = "túnel arriba pero geo no responde"
            return
        if self.baseline_ip and ip == self.baseline_ip:
            riflle2.kill_proc_group(proc)
            with self.lock:
                self.proc = None
                self.state.state = "error"
                self.state.error = f"tráfico no enrutado por VPN (IP = baseline {ip})"
            return

        # Continuar leyendo log en background para no bloquear el pipe
        threading.Thread(target=self._drain_log, args=(proc,), daemon=True).start()

        with self.lock:
            self.state.state = "connected"
            self.state.ip = ip
            self.state.country_code = code
            self.state.country = country

    def _drain_log(self, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            self._push_log(line)
            if proc.poll() is not None:
                break
        # Si el proceso muere por su cuenta, marcar como desconectado
        with self.lock:
            if self.proc is proc and self.state.state == "connected":
                self.proc = None
                self.state = ConnectionState(state="idle")


manager = VPNManager()


# ---------------------------------------------------------------------------
# Carga de VPNs desde ok/, inbox/ y cache
# ---------------------------------------------------------------------------

def list_vpns() -> list[dict]:
    cache = {}
    if CACHE_FILE.exists():
        try:
            cache = json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            cache = {}

    entries: list[dict] = []
    for dir_, source in [(OK_DIR, "ok"), (INBOX, "inbox")]:
        if not dir_.exists():
            continue
        for p in sorted(dir_.iterdir()):
            if p.is_file() and p.suffix == ".ovpn":
                digest = riflle2.sha1_of(p)
                c = cache.get(digest, {})
                entries.append({
                    "name": p.name,
                    "path": str(p),
                    "source": source,
                    "country_code": (c.get("country_code") or "").lower(),
                    "country": c.get("country") or "",
                    "ip": c.get("external_ip") or "",
                    "bandwidth_mbps": float(c.get("bandwidth_mbps") or 0.0),
                    "validated": c.get("status") == "ok",
                })
    return entries


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="riflle2 UI")


class ConnectBody(BaseModel):
    path: str


NOCACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML, headers=NOCACHE_HEADERS)


@app.get("/shell", response_class=HTMLResponse)
def shell_full() -> HTMLResponse:
    return HTMLResponse(SHELL_HTML, headers=NOCACHE_HEADERS)


@app.get("/api/vpns")
def api_vpns() -> JSONResponse:
    return JSONResponse(list_vpns())


@app.get("/api/status")
def api_status() -> JSONResponse:
    s = manager.snapshot()
    s["uptime_s"] = int(time.time() - s["started_at"]) if s["started_at"] else 0
    return JSONResponse(s)


# Cache pequeña para no abusar de ip-api.com. La UI consulta cada 5s; la cache
# de 4s asegura que máximo 1 query/12-15s salga de verdad por VPN+host.
_REALIP_CACHE = {"ip": "", "country_code": "", "country": "", "ts": 0.0}
_REALIP_LOCK = threading.Lock()
_REALIP_TTL = 4.0


@app.get("/api/realip")
def api_realip(force: bool = False) -> JSONResponse:
    now = time.time()
    with _REALIP_LOCK:
        age = now - _REALIP_CACHE["ts"] if _REALIP_CACHE["ts"] else None
        cached_ip = _REALIP_CACHE["ip"]
        if not force and cached_ip and age is not None and age < _REALIP_TTL:
            return JSONResponse({
                "ip": _REALIP_CACHE["ip"],
                "country_code": _REALIP_CACHE["country_code"],
                "country": _REALIP_CACHE["country"],
                "age_s": round(age, 1),
                "cached": True,
                "live": True,
            })

    ip, code, country = riflle2.query_geo(timeout=6)

    with _REALIP_LOCK:
        if ip:
            _REALIP_CACHE.update({"ip": ip, "country_code": code,
                                   "country": country, "ts": time.time()})
        age2 = time.time() - _REALIP_CACHE["ts"] if _REALIP_CACHE["ts"] else None
        return JSONResponse({
            "ip": _REALIP_CACHE["ip"],
            "country_code": _REALIP_CACHE["country_code"],
            "country": _REALIP_CACHE["country"],
            "age_s": round(age2, 1) if age2 is not None else None,
            "cached": False,
            "live": bool(ip),
        })


@app.post("/api/connect")
def api_connect(body: ConnectBody) -> JSONResponse:
    if os.geteuid() != 0:
        raise HTTPException(
            503,
            "el servidor no se está ejecutando como root; openvpn no puede "
            "levantar tun0. Relánzalo con: sudo python3 riflle2_ui.py",
        )
    p = Path(body.path)
    if not p.exists() or p.suffix != ".ovpn":
        raise HTTPException(400, "fichero no encontrado o no es .ovpn")
    # Permitir solo dentro del directorio del proyecto
    if not str(p.resolve()).startswith(str(ROOT.resolve())):
        raise HTTPException(403, "path fuera del proyecto")
    try:
        manager.connect(p)
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return JSONResponse({"ok": True})


@app.post("/api/disconnect")
def api_disconnect() -> JSONResponse:
    manager.disconnect()
    return JSONResponse({"ok": True})


@app.post("/api/bandwidth")
def api_bandwidth() -> JSONResponse:
    try:
        bw = manager.measure_bandwidth_now()
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return JSONResponse({"bandwidth_mbps": bw})


# ---------------------------------------------------------------------------
# Upload de .ovpn
# ---------------------------------------------------------------------------

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._一-鿿-]+")


def safe_filename(name: str) -> str:
    base = Path(name).name  # quitar paths
    base = SAFE_NAME_RE.sub("_", base)
    if not base.endswith(".ovpn"):
        base += ".ovpn"
    return base[:200]


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)) -> JSONResponse:
    if not (file.filename or "").lower().endswith(".ovpn"):
        raise HTTPException(400, "el fichero debe tener extensión .ovpn")
    INBOX.mkdir(exist_ok=True)
    safe = safe_filename(file.filename)
    target = INBOX / safe
    n = 1
    while target.exists():
        target = INBOX / f"{safe[:-5]}.dup{n}.ovpn"
        n += 1
    data = await file.read()
    if len(data) > 2_000_000:  # 2 MB es muchísimo para un .ovpn
        raise HTTPException(413, "fichero demasiado grande (>2MB)")
    target.write_bytes(data)
    return JSONResponse({"ok": True, "saved": target.name, "size": len(data)})


@app.post("/api/check-inbox")
def api_check_inbox() -> JSONResponse:
    """Lanza riflle2.py check en background contra ./inbox/.
    Devuelve PID para que el frontend pueda saber que está corriendo."""
    if os.geteuid() != 0:
        raise HTTPException(503, "necesita ejecutarse como root")
    script = ROOT / "riflle2.py"
    log_file = ROOT / ".last_check.log"
    proc = subprocess.Popen(
        ["python3", str(script), "--bandwidth", "check"],
        stdout=open(log_file, "w"),
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
        start_new_session=True,
    )
    return JSONResponse({"ok": True, "pid": proc.pid, "log": str(log_file)})


# ---------------------------------------------------------------------------
# Terminal vía WebSocket + PTY
# ---------------------------------------------------------------------------

class PTYSession:
    """Encapsula un pty.fork + bash y bombea bytes en ambas direcciones."""

    def __init__(self) -> None:
        self.pid: int = -1
        self.fd: int = -1

    def start(self, cwd: str = "/root") -> None:
        pid, fd = pty.fork()
        if pid == 0:
            # Hijo: exec bash
            os.environ["TERM"] = "xterm-256color"
            os.environ.setdefault("HOME", cwd)
            try:
                os.chdir(cwd)
            except OSError:
                os.chdir("/")
            os.execvp("bash", ["bash", "--login"])
            # nunca llega aquí
        self.pid = pid
        self.fd = fd
        # No-block
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

    def read_nonblocking(self, maxbytes: int = 8192) -> bytes:
        if self.fd < 0:
            return b""
        try:
            r, _, _ = select.select([self.fd], [], [], 0)
            if not r:
                return b""
            return os.read(self.fd, maxbytes)
        except OSError:
            return b""

    def read_blocking(self, maxbytes: int = 8192, poll_timeout: float = 0.5) -> bytes:
        """Bloquea hasta que haya bytes (o hasta poll_timeout) y los lee.
        Devuelve b"" si llega el timeout sin datos (para que el hilo lector
        pueda comprobar la bandera de stop sin quedarse colgado para siempre)."""
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


@app.websocket("/ws/terminal")
async def ws_terminal(ws: WebSocket) -> None:
    await ws.accept()
    session = PTYSession()
    try:
        cwd = "/root" if os.geteuid() == 0 else os.path.expanduser("~")
        session.start(cwd=cwd)
    except Exception as exc:
        await ws.send_json({"type": "error", "msg": f"no se pudo arrancar pty: {exc}"})
        await ws.close()
        return

    loop = asyncio.get_event_loop()
    stop = asyncio.Event()
    # Cola alimentada por el hilo lector; bytes vacíos (b"") = sentinela de fin.
    queue: asyncio.Queue = asyncio.Queue()

    def reader_thread() -> None:
        """Lee bytes del pty con select bloqueante y los empuja a la cola.
        Vive en un hilo aparte para que el event loop no se ahogue ni dependa
        de polling con sleep — los bytes salen al WebSocket sin latencia
        añadida (ping, top, journalctl -f, etc. se ven en tiempo real)."""
        while True:
            data = session.read_blocking(8192, poll_timeout=0.05)
            if data:
                loop.call_soon_threadsafe(queue.put_nowait, data)
                continue
            # Sin datos en este tick: comprobar si el proceso sigue vivo
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
                # Mensajes de control: {"action":"resize","rows":N,"cols":N}
                try:
                    obj = json.loads(txt)
                    if isinstance(obj, dict) and obj.get("action") == "resize":
                        session.resize(int(obj.get("rows", 24)), int(obj.get("cols", 80)))
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
        try:
            await ws.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HTML embebido
# ---------------------------------------------------------------------------

INDEX_HTML = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>riflle2 — VPN switcher</title>
<style>
  :root { color-scheme: dark; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #0f0f23; color: #e0e0e0; margin: 0; padding: 24px;
    min-height: 100vh; box-sizing: border-box;
  }
  h1 { margin: 0 0 16px; color: #f39c12; font-size: 22px; }
  .panel { background: #16213e; border: 1px solid #333; border-radius: 8px;
           padding: 16px 20px; margin-bottom: 20px; }
  .panel h2 { margin: 0 0 12px; color: #3498db; font-size: 15px;
              font-weight: 500; }
  .controls { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  select { background: #0f0f23; color: #e0e0e0; border: 1px solid #333;
           padding: 8px 10px; border-radius: 4px; font-size: 14px; min-width: 360px; }
  button { background: #3498db; color: white; border: 0; padding: 9px 18px;
           border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 500; }
  button.danger { background: #e74c3c; }
  button.secondary { background: #555; }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  .status-block { display: flex; gap: 24px; align-items: center; flex-wrap: wrap; }
  .flag { width: 96px; height: 64px; border-radius: 4px; background: #222;
          object-fit: cover; box-shadow: 0 2px 8px rgba(0,0,0,0.4); }
  .flag-placeholder { width: 96px; height: 64px; border-radius: 4px;
                      background: #222; display: flex; align-items: center;
                      justify-content: center; color: #555; font-size: 11px; }
  .info { flex: 1; min-width: 260px; }
  .info-row { margin: 6px 0; }
  .label { color: #888; font-size: 12px; text-transform: uppercase;
           letter-spacing: 1px; }
  .value { color: #e0e0e0; font-size: 16px; font-weight: 500; }
  .value.big { font-size: 28px; color: #f39c12; }
  .state-pill { display: inline-block; padding: 4px 12px; border-radius: 12px;
                font-size: 12px; font-weight: 600; text-transform: uppercase; }
  .state-idle { background: #555; color: #ccc; }
  .state-connecting { background: #f39c12; color: #000; }
  .state-connected { background: #2ecc71; color: #000; }
  .state-disconnecting { background: #f39c12; color: #000; }
  .state-error { background: #e74c3c; color: white; }
  .log { background: #0a0a1a; border: 1px solid #222; border-radius: 4px;
         padding: 10px 14px; font-family: Consolas, monospace; font-size: 11px;
         color: #aaa; max-height: 180px; overflow-y: auto; margin-top: 12px; }
  .muted { color: #888; font-size: 12px; }
  /* Upload */
  .dropzone { border: 2px dashed #444; border-radius: 6px;
              padding: 16px 20px; text-align: center; color: #888;
              transition: border-color .15s, background .15s;
              cursor: pointer; }
  .dropzone:hover, .dropzone.drag { border-color: #3498db;
                                    background: rgba(52,152,219,0.07);
                                    color: #ccc; }
  .upload-status { font-size: 13px; color: #aaa; margin-top: 8px;
                   font-family: Consolas, monospace; }
</style>
</head>
<body>
  <h1>riflle2 — VPN switcher</h1>

  <div class="panel">
    <div class="controls">
      <select id="vpn-select"></select>
      <button id="btn-connect" onclick="doConnect()">Conectar</button>
      <button id="btn-disconnect" class="danger" onclick="doDisconnect()" disabled>Desconectar</button>
      <button id="btn-bw" class="secondary" onclick="doMeasureBw()" disabled>Medir bandwidth</button>
      <span class="muted" id="vpn-count" style="flex:1;"></span>
      <button id="btn-shell" class="secondary"
              onclick="window.open('/shell', '_blank', 'noopener')"
              title="Abre una shell interactiva en pestaña nueva a pantalla completa">
        SHELL
      </button>
    </div>
  </div>

  <div class="panel">
    <div class="status-block">
      <div id="flag-wrap">
        <div class="flag-placeholder">sin conexión</div>
      </div>
      <div class="info">
        <div class="info-row">
          <span class="state-pill state-idle" id="state-pill">IDLE</span>
          <span class="muted" id="uptime"></span>
        </div>
        <div class="info-row">
          <div class="label">País</div>
          <div class="value" id="country">—</div>
        </div>
        <div class="info-row">
          <div class="label">IP externa</div>
          <div class="value" id="ip">—</div>
        </div>
        <div class="info-row">
          <div class="label">Bandwidth</div>
          <div class="value big" id="bandwidth">—</div>
        </div>
        <div class="info-row">
          <div class="label">Fichero</div>
          <div class="value" id="file" style="font-size:12px;font-family:monospace;">—</div>
        </div>
        <div class="info-row" id="error-row" style="display:none;">
          <div class="label">Error</div>
          <div class="value" id="error" style="color:#e74c3c;font-size:14px;">—</div>
        </div>
      </div>
    </div>
    <div class="log" id="log" style="display:none;"></div>
  </div>

  <div class="panel">
    <h2>Añadir .ovpn nuevos</h2>
    <div class="dropzone" id="dropzone" onclick="document.getElementById('fileinput').click()">
      Arrastra ficheros <code>.ovpn</code> aquí o haz click para seleccionarlos.
      Se guardarán en <code>inbox/</code>.
    </div>
    <input type="file" id="fileinput" multiple accept=".ovpn" style="display:none">
    <div class="upload-status" id="upload-status"></div>
    <div style="margin-top:10px;">
      <button class="secondary" onclick="launchCheck()">Validar inbox/ ahora (riflle2 --bandwidth check)</button>
      <span class="muted" id="check-status"></span>
    </div>
  </div>

<script>
let vpns = [];

async function loadVpns() {
  const r = await fetch('/api/vpns');
  vpns = await r.json();
  const sel = document.getElementById('vpn-select');
  sel.innerHTML = '';
  // Ordenar por país, luego nombre
  vpns.sort((a, b) => (a.country || 'ZZ').localeCompare(b.country || 'ZZ') ||
                       a.name.localeCompare(b.name));
  for (const v of vpns) {
    const opt = document.createElement('option');
    const flagEmoji = v.country_code ? countryFlagEmoji(v.country_code) : '⚪';
    const bwTag = v.bandwidth_mbps > 0 ? ` · ${v.bandwidth_mbps.toFixed(1)} Mbps` : '';
    const validatedTag = v.validated ? ' ✓' : '';
    opt.value = v.path;
    opt.textContent = `${flagEmoji}  ${v.country || '?'} — ${v.name}${bwTag}${validatedTag}`;
    opt.dataset.cc = v.country_code;
    sel.appendChild(opt);
  }
  document.getElementById('vpn-count').textContent =
    `${vpns.length} VPN disponibles (${vpns.filter(x => x.validated).length} ya validadas)`;
}

function countryFlagEmoji(cc) {
  if (!cc) return '⚪';
  return cc.toUpperCase().replace(/./g, c =>
    String.fromCodePoint(127397 + c.charCodeAt(0)));
}

async function doConnect() {
  const sel = document.getElementById('vpn-select');
  const path = sel.value;
  if (!path) return;
  setButtons(false, false, false);
  try {
    const r = await fetch('/api/connect', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path}),
    });
    if (!r.ok) {
      const err = await r.json();
      alert('Error: ' + (err.detail || 'desconocido'));
    }
  } catch (e) {
    alert('Error de red: ' + e);
  }
  refreshStatus();
}

async function doDisconnect() {
  setButtons(false, false, false);
  await fetch('/api/disconnect', {method: 'POST'});
  refreshStatus();
}

async function doMeasureBw() {
  document.getElementById('bandwidth').textContent = 'midiendo…';
  document.getElementById('btn-bw').disabled = true;
  try {
    const r = await fetch('/api/bandwidth', {method: 'POST'});
    if (!r.ok) {
      const err = await r.json();
      document.getElementById('bandwidth').textContent = '—';
      alert('Error: ' + (err.detail || 'desconocido'));
    }
  } catch (e) {
    document.getElementById('bandwidth').textContent = '—';
  }
  refreshStatus();
}

function setButtons(canConnect, canDisconnect, canBw) {
  document.getElementById('btn-connect').disabled = !canConnect;
  document.getElementById('btn-disconnect').disabled = !canDisconnect;
  document.getElementById('btn-bw').disabled = !canBw;
  document.getElementById('vpn-select').disabled = !canConnect;
}

async function refreshStatus() {
  try {
    const r = await fetch('/api/status');
    const s = await r.json();
    const pill = document.getElementById('state-pill');
    pill.className = 'state-pill state-' + s.state;
    pill.textContent = s.state.toUpperCase();
    document.getElementById('country').textContent =
      s.country ? `${s.country} (${s.country_code})` : '—';
    document.getElementById('ip').textContent = s.ip || '—';
    document.getElementById('bandwidth').textContent =
      s.bandwidth_mbps > 0 ? `${s.bandwidth_mbps.toFixed(1)} Mbps` : '—';
    document.getElementById('file').textContent = s.file || '—';
    document.getElementById('uptime').textContent =
      s.state === 'connected' && s.uptime_s ? `· conectado ${formatDuration(s.uptime_s)}` : '';

    // Bandera
    const wrap = document.getElementById('flag-wrap');
    if (s.country_code) {
      const cc = s.country_code.toLowerCase();
      wrap.innerHTML = `<img class="flag" src="https://flagcdn.com/w160/${cc}.png" alt="${cc}">`;
    } else {
      wrap.innerHTML = '<div class="flag-placeholder">sin conexión</div>';
    }

    // Botones
    if (s.state === 'idle' || s.state === 'error') {
      setButtons(true, false, false);
    } else if (s.state === 'connecting' || s.state === 'disconnecting') {
      setButtons(false, false, false);
    } else if (s.state === 'connected') {
      setButtons(false, true, true);
    }

    // Error
    if (s.state === 'error' && s.error) {
      document.getElementById('error-row').style.display = '';
      document.getElementById('error').textContent = s.error;
    } else {
      document.getElementById('error-row').style.display = 'none';
    }

    // Log
    const logEl = document.getElementById('log');
    if (s.log_tail && s.log_tail.length > 0) {
      logEl.style.display = '';
      logEl.textContent = s.log_tail.join('\\n');
      logEl.scrollTop = logEl.scrollHeight;
    } else {
      logEl.style.display = 'none';
    }
  } catch (e) {
    console.error(e);
  }
}

function formatDuration(s) {
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + (s % 60) + 's';
  return Math.floor(s/3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

loadVpns();
refreshStatus();
setInterval(refreshStatus, 2000);

// -------- Upload de .ovpn --------
const dropzone = document.getElementById('dropzone');
const fileinput = document.getElementById('fileinput');
const uploadStatus = document.getElementById('upload-status');

['dragenter', 'dragover'].forEach(evt => {
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault(); e.stopPropagation();
    dropzone.classList.add('drag');
  });
});
['dragleave', 'drop'].forEach(evt => {
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault(); e.stopPropagation();
    dropzone.classList.remove('drag');
  });
});
dropzone.addEventListener('drop', (e) => {
  const files = Array.from(e.dataTransfer.files);
  uploadFiles(files);
});
fileinput.addEventListener('change', () => {
  uploadFiles(Array.from(fileinput.files));
  fileinput.value = '';
});

async function uploadFiles(files) {
  if (!files.length) return;
  uploadStatus.textContent = `Subiendo ${files.length} fichero(s)…`;
  const results = [];
  for (const f of files) {
    if (!f.name.toLowerCase().endsWith('.ovpn')) {
      results.push(`✗ ${f.name} (no es .ovpn)`);
      continue;
    }
    const fd = new FormData();
    fd.append('file', f);
    try {
      const r = await fetch('/api/upload', {method: 'POST', body: fd});
      const data = await r.json();
      if (r.ok) {
        results.push(`✓ ${data.saved} (${(data.size/1024).toFixed(1)} KB)`);
      } else {
        results.push(`✗ ${f.name}: ${data.detail || 'error'}`);
      }
    } catch (e) {
      results.push(`✗ ${f.name}: ${e}`);
    }
  }
  uploadStatus.innerHTML = results.join('<br>');
  loadVpns();  // refrescar dropdown
}

async function launchCheck() {
  const btn = event.target;
  btn.disabled = true;
  document.getElementById('check-status').textContent = 'lanzando…';
  try {
    const r = await fetch('/api/check-inbox', {method: 'POST'});
    const data = await r.json();
    if (r.ok) {
      document.getElementById('check-status').textContent =
        `validando en background (PID ${data.pid}). Sigue la salida con: tail -f ${data.log}`;
    } else {
      document.getElementById('check-status').textContent = 'error: ' + (data.detail || 'desconocido');
    }
  } catch (e) {
    document.getElementById('check-status').textContent = 'error: ' + e;
  }
  btn.disabled = false;
}

</script>
</body>
</html>
"""


SHELL_HTML = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>riflle2 — shell</title>
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
  /* Indicador salida real */
  #real-exit { display: flex; align-items: center; gap: 8px;
               padding: 2px 10px; border-radius: 14px;
               background: rgba(255,255,255,0.04); transition: background .3s; }
  #real-exit.changed { background: rgba(46,204,113,0.28); }
  #real-flag-img { width: 24px; height: 16px; border-radius: 2px;
                   object-fit: cover; display: block; }
  #real-flag-ph { width: 24px; height: 16px; border-radius: 2px;
                  background: #222; display: inline-block; }
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
    <span class="title">riflle2 shell</span>
    <span class="pill" id="pill">conectando…</span>
    <span style="flex:1;"></span>
    <span id="real-exit" title="Salida real a internet (refresco cada 5s)">
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
  ws = new WebSocket(proto + '//' + location.host + '/ws/terminal');
  ws.binaryType = 'arraybuffer';
  setPill('conectando…', '');

  ws.onopen = () => {
    setPill('en vivo', 'live');
    setTimeout(sendResize, 80);
  };
  ws.onmessage = (e) => {
    if (e.data instanceof ArrayBuffer) {
      term.write(new Uint8Array(e.data));
    } else if (typeof e.data === 'string') {
      try {
        const obj = JSON.parse(e.data);
        if (obj.type === 'error') {
          term.write('\\r\\n\\x1b[31m[error] ' + obj.msg + '\\x1b[0m\\r\\n');
        }
      } catch (_) {
        term.write(e.data);
      }
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
  // onData se registra UNA sola vez aquí; antes estaba en connectTermWs y
  // cada reconexión apilaba un handler nuevo → keystrokes duplicados.
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

// -------- Salida real a internet --------
let lastRealIp = '';

async function refreshRealExit(force) {
  try {
    const r = await fetch('/api/realip' + (force ? '?force=true' : ''));
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
      ? `${d.country_code}`
      : (d.ip ? '?' : 'sin red');
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

def _shutdown_openvpn(reason: str) -> None:
    proc = manager.proc
    if proc is None or proc.poll() is not None:
        return
    print(f"[riflle2_ui] {reason}: matando openvpn (pid={proc.pid})", file=sys.stderr)
    try:
        manager.disconnect()
    except Exception as exc:
        print(f"[riflle2_ui] error al matar openvpn: {exc}", file=sys.stderr)


def main() -> int:
    is_root = os.geteuid() == 0
    if not is_root:
        print("AVISO: no estás ejecutando como root. La UI funcionará pero el "
              "botón Conectar fallará. Para conectar de verdad relanza con: "
              "sudo python3 riflle2_ui.py", file=sys.stderr)
    print(f"[riflle2_ui] arrancando en http://{HOST}:{PORT}/")
    manager.init_baseline()

    # SIGTERM (sudo kill) → también cerrar openvpn limpiamente.
    # Ctrl-C lo cubre el try/finally vía KeyboardInterrupt en uvicorn.
    def _sigterm_handler(signum, frame):
        _shutdown_openvpn("SIGTERM recibido")
        sys.exit(0)
    signal.signal(signal.SIGTERM, _sigterm_handler)

    try:
        uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
    except KeyboardInterrupt:
        print("[riflle2_ui] Ctrl-C recibido", file=sys.stderr)
    finally:
        _shutdown_openvpn("saliendo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
