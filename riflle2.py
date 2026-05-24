#!/usr/bin/env python3
"""riflle2 — valida ficheros .ovpn levantando la VPN de verdad y comprobando internet.

Para cada .ovpn:
  1. Verifica sintaxis básica (debe tener remote y bloque <ca>).
  2. Si requiere auth-user-pass, lo manda a needs_auth/.
  3. Conecta la VPN forzando redirect-gateway def1 + DNS público.
  4. Una vez 'Initialization Sequence Completed', consulta IP externa y país
     via ip-api.com usando --resolve (no necesita DNS funcional).
  5. Si la IP devuelta != IP baseline (la del host sin VPN) → OK con IP+país.
     Si igual o timeout → DEAD.
  6. Si funcionó pero el .ovpn no tenía redirect-gateway, lo parchea
     añadiendo las líneas necesarias para uso futuro.

Los muertos se mueven a trash/ automáticamente sin preguntar.
Necesita ejecutarse como root (openvpn necesita levantar tun0).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

OPENVPN_BIN = "/usr/sbin/openvpn"
ROOT = Path(__file__).resolve().parent
CACHE_FILE = ROOT / ".riflle2_cache.json"

# ip-api.com — endpoint HTTP simple, IP estable, devuelve query/countryCode/country
GEO_HOST = "ip-api.com"
GEO_PATH = "/line/?fields=query,countryCode,country"
GEO_FALLBACK_IPS = ["208.95.112.1", "208.95.112.2"]

# Cloudflare speed test — anycast, descarga un blob de N bytes
BW_HOST = "speed.cloudflare.com"
BW_PATH = "/__down?bytes=10000000"  # 10 MB
BW_FALLBACK_IPS = ["104.16.0.1", "104.16.1.1", "104.16.2.1", "172.66.0.218"]
BW_TIMEOUT = 12  # cap de transferencia: si baja muy lento, lo cortamos aquí

# Líneas que añadimos a un .ovpn si funciona solo con los flags forzados
PATCH_BLOCK = """
# riflle2 patch — forzar todo el tráfico por el túnel + DNS
redirect-gateway def1
dhcp-option DNS 1.1.1.1
dhcp-option DNS 8.8.8.8
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
""".lstrip()
PATCH_MARKER = "# riflle2 patch"

OK_MARKER = "Initialization Sequence Completed"
DEAD_MARKERS = (
    "TLS Error",
    "TLS handshake failed",
    "Connection reset",
    "Network is unreachable",
    "No route to host",
    "RESOLVE: Cannot resolve host",
    "AUTH_FAILED",
    "Cannot allocate",
    "Connection refused",
)

STATUS_OK = "ok"
STATUS_DEAD = "dead"
STATUS_AUTH = "needs_auth"
STATUS_MALFORMED = "malformed"


@dataclass
class Verdict:
    path: Path
    status: str
    reason: str = ""
    external_ip: str = ""
    country_code: str = ""
    country: str = ""
    patched: bool = False
    bandwidth_mbps: float = 0.0  # 0.0 = no medido

    @property
    def is_failure(self) -> bool:
        return self.status in (STATUS_DEAD, STATUS_MALFORMED)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def sha1_of(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2, sort_keys=True))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Parsing y patching
# ---------------------------------------------------------------------------

def parse_ovpn(path: Path) -> tuple[bool, bool, str]:
    """Devuelve (valido_sintaxis, requiere_auth_user_pass, motivo_si_invalido)."""
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        return False, False, f"read error: {exc}"

    has_remote = bool(re.search(r"^\s*remote\s+\S+", text, re.MULTILINE))
    has_ca = "<ca>" in text or re.search(r"^\s*ca\s+\S+", text, re.MULTILINE)
    if not has_remote:
        return False, False, "no remote directive"
    if not has_ca:
        return False, False, "no <ca> block"

    needs_auth = bool(re.search(r"^\s*auth-user-pass(\s|$)", text, re.MULTILINE))
    return True, needs_auth, ""


def has_redirect_gateway(text: str) -> bool:
    return bool(re.search(r"^\s*redirect-gateway\b", text, re.MULTILINE))


def apply_patch(path: Path) -> bool:
    """Añade el bloque de directivas al fichero si no estaba ya parcheado.
    Inserta ANTES de los bloques <ca>/<cert>/<key> para mantener la limpieza visual.
    Devuelve True si modificó el fichero."""
    text = path.read_text(errors="replace")
    if PATCH_MARKER in text or has_redirect_gateway(text):
        return False

    # Insertar antes del primer bloque inline (<ca>, <cert>, ...)
    m = re.search(r"^<(ca|cert|key|tls-auth|tls-crypt|extra-certs|http-proxy-user-pass)>",
                  text, re.MULTILINE)
    if m:
        insert_at = m.start()
        new_text = text[:insert_at].rstrip() + "\n\n" + PATCH_BLOCK + "\n" + text[insert_at:]
    else:
        new_text = text.rstrip() + "\n\n" + PATCH_BLOCK
    path.write_text(new_text)
    return True


# ---------------------------------------------------------------------------
# IP/País
# ---------------------------------------------------------------------------

def query_geo(timeout: int = 10) -> tuple[str, str, str]:
    """Consulta ip-api.com via --resolve. Devuelve (ip, country_code, country)."""
    # Probar resolviendo a varias IPs conocidas del servicio
    for resolved_ip in GEO_FALLBACK_IPS:
        try:
            r = subprocess.run(
                [
                    "curl", "-s", "--max-time", str(timeout),
                    "--resolve", f"{GEO_HOST}:80:{resolved_ip}",
                    f"http://{GEO_HOST}{GEO_PATH}",
                ],
                capture_output=True, text=True, check=False, timeout=timeout + 2,
            )
            lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            # Formato esperado:
            #   country
            #   countryCode
            #   query  (IP)
            if len(lines) >= 3:
                country, code, ip = lines[0], lines[1], lines[2]
                if ip and "." in ip:
                    return ip, code, country
        except (subprocess.SubprocessError, OSError):
            continue
    return "", "", ""


def baseline_geo() -> tuple[str, str, str]:
    ip, code, country = query_geo(timeout=8)
    return ip, code, country


def measure_bandwidth(timeout: int = BW_TIMEOUT) -> float:
    """Descarga el blob de Cloudflare y devuelve velocidad en Mbps. 0.0 si falla."""
    for resolved_ip in BW_FALLBACK_IPS:
        try:
            r = subprocess.run(
                [
                    "curl", "-s", "-o", "/dev/null",
                    "--max-time", str(timeout),
                    "--resolve", f"{BW_HOST}:443:{resolved_ip}",
                    "-w", "%{speed_download}",
                    f"https://{BW_HOST}{BW_PATH}",
                ],
                capture_output=True, text=True, check=False, timeout=timeout + 3,
            )
            out = (r.stdout or "").strip()
            if not out:
                continue
            bytes_per_sec = float(out)
            if bytes_per_sec <= 0:
                continue
            return bytes_per_sec * 8 / 1_000_000  # bytes/s → Mbps
        except (subprocess.SubprocessError, ValueError, OSError):
            continue
    return 0.0


# ---------------------------------------------------------------------------
# Conexión VPN real
# ---------------------------------------------------------------------------

def wait_for_marker(proc: subprocess.Popen, marker: str, dead_markers: tuple[str, ...],
                    timeout: int) -> tuple[bool, str, str]:
    """Lee stdout de openvpn hasta encontrar marker, dead_marker o timeout.
    Devuelve (ok, dead_reason, full_output_chunk)."""
    output_chunks: list[str] = []
    start = time.monotonic()
    assert proc.stdout is not None
    while True:
        if time.monotonic() - start > timeout:
            return False, f"timeout {timeout}s", "".join(output_chunks)
        if proc.poll() is not None:
            joined = "".join(output_chunks)
            for m in dead_markers:
                if m in joined:
                    return False, m, joined
            return False, "openvpn exited", joined
        line = proc.stdout.readline()
        if not line:
            continue
        output_chunks.append(line)
        if marker in line:
            return True, "", "".join(output_chunks)
        for m in dead_markers:
            if m in line:
                return False, m, "".join(output_chunks)


def kill_proc_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def try_connect_and_geo(path: Path, baseline_ip: str, timeout: int,
                        force_redirect: bool, measure_bw: bool = False
                        ) -> tuple[bool, str, str, str, float, str]:
    """Levanta openvpn con la config dada, opcionalmente forzando redirect-gateway.
    Devuelve (success, external_ip, country_code, country, bandwidth_mbps, reason)."""
    cmd = [
        OPENVPN_BIN,
        "--config", str(path),
        "--connect-timeout", "10",
        "--connect-retry", "0",
        "--resolv-retry", "0",
        "--tls-exit",
        "--pull-filter", "ignore", "block-outside-dns",
        "--verb", "3",
    ]
    if force_redirect:
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
        return False, "", "", "", f"openvpn spawn: {exc}"

    try:
        ok, reason, _ = wait_for_marker(proc, OK_MARKER, DEAD_MARKERS, timeout)
        if not ok:
            return False, "", "", "", 0.0, reason

        # tun0 levantado y rutas instaladas. Dar 2s para que se asienten.
        time.sleep(2)
        ip, code, country = query_geo(timeout=8)
        if not ip:
            return False, "", "", "", 0.0, "geo query failed"
        if baseline_ip and ip == baseline_ip:
            return False, ip, code, country, 0.0, "tráfico no enrutado por VPN"

        bw = measure_bandwidth() if measure_bw else 0.0
        return True, ip, code, country, bw, ""
    finally:
        kill_proc_group(proc)
        # Limpieza: por si quedó alguna ruta colgada
        time.sleep(1)


def validate_one(path: Path, baseline_ip: str, timeout: int,
                 cache: dict, use_cache: bool, measure_bw: bool = False) -> Verdict:
    digest = sha1_of(path)
    if use_cache and digest in cache:
        c = cache[digest]
        if c.get("status") == STATUS_OK:
            cached_bw = float(c.get("bandwidth_mbps", 0.0))
            # Si se pide BW y no estaba en cache, no re-uses el cache: hay que medirlo
            if not (measure_bw and cached_bw == 0.0):
                return Verdict(
                    path, STATUS_OK, "cache",
                    c.get("external_ip", ""), c.get("country_code", ""),
                    c.get("country", ""), c.get("patched", False), cached_bw,
                )

    valid, needs_auth, reason = parse_ovpn(path)
    if not valid:
        v = Verdict(path, STATUS_MALFORMED, reason)
    elif needs_auth:
        v = Verdict(path, STATUS_AUTH, "auth-user-pass")
    else:
        # Intento 1: tal cual el fichero
        ok, ip, code, country, bw, reason = try_connect_and_geo(
            path, baseline_ip, timeout, force_redirect=False, measure_bw=measure_bw,
        )
        if ok:
            v = Verdict(path, STATUS_OK, "", ip, code, country, False, bw)
        else:
            # Intento 2: forzando redirect-gateway + DNS
            ok2, ip2, code2, country2, bw2, reason2 = try_connect_and_geo(
                path, baseline_ip, timeout, force_redirect=True, measure_bw=measure_bw,
            )
            if ok2:
                # Funciona con las directivas extra → parchear el fichero
                patched = apply_patch(path)
                v = Verdict(path, STATUS_OK, "patched" if patched else "",
                            ip2, code2, country2, patched, bw2)
            else:
                v = Verdict(path, STATUS_DEAD, reason2 or reason or "no internet")

    cache[digest] = {
        "status": v.status, "reason": v.reason,
        "external_ip": v.external_ip, "country_code": v.country_code,
        "country": v.country, "patched": v.patched,
        "bandwidth_mbps": v.bandwidth_mbps, "ts": int(time.time()),
    }
    return v


# ---------------------------------------------------------------------------
# Disposición de ficheros
# ---------------------------------------------------------------------------

def move_to(path: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(exist_ok=True)
    # Si el fichero ya está en el directorio destino, no hacemos nada
    if path.resolve().parent == dest_dir.resolve():
        return path
    target = dest_dir / path.name
    n = 1
    while target.exists():
        target = dest_dir / f"{path.name}.dup{n}"
        n += 1
    shutil.move(str(path), str(target))
    return target


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

STATUS_LABEL = {
    STATUS_OK: "\033[32mOK  \033[0m",
    STATUS_DEAD: "\033[31mKO  \033[0m",
    STATUS_AUTH: "\033[33mAUTH\033[0m",
    STATUS_MALFORMED: "\033[31mBAD \033[0m",
}


def format_line(idx: int, total: int, v: Verdict) -> str:
    label = STATUS_LABEL.get(v.status, "????")
    geo = ""
    if v.external_ip:
        cc = f" [{v.country_code}]" if v.country_code else ""
        country = f" {v.country}" if v.country else ""
        patched = " (parcheado)" if v.patched else ""
        bw = f" · {v.bandwidth_mbps:.1f} Mbps" if v.bandwidth_mbps > 0 else ""
        geo = f"  → {v.external_ip}{cc}{country}{patched}{bw}"
    elif v.reason:
        geo = f"  ({v.reason})"
    return f"  [{idx:>3}/{total}] {label}  {v.path.name}{geo}"


def print_summary_table(verdicts: list[Verdict]) -> None:
    if not verdicts:
        return
    oks = [v for v in verdicts if v.status == STATUS_OK]
    deads = [v for v in verdicts if v.status == STATUS_DEAD]
    auths = [v for v in verdicts if v.status == STATUS_AUTH]
    bads = [v for v in verdicts if v.status == STATUS_MALFORMED]

    print()
    print("=" * 78)
    print(f"RESUMEN: {len(oks)} OK · {len(deads)} muertos · "
          f"{len(auths)} need auth · {len(bads)} malformed")
    print("=" * 78)
    if oks:
        has_bw = any(v.bandwidth_mbps > 0 for v in oks)
        print()
        if has_bw:
            # Ordenar por Mbps descendente (más rápida arriba)
            ordered = sorted(oks, key=lambda x: -x.bandwidth_mbps)
            print(f"{'Estado':<7} {'IP externa':<17} {'CC':<4} {'País':<22} "
                  f"{'Mbps':>8}  Fichero")
            print("-" * 96)
            for v in ordered:
                ptag = " *" if v.patched else "  "
                bw = f"{v.bandwidth_mbps:>6.1f}" if v.bandwidth_mbps > 0 else "  n/d "
                print(f"OK{ptag}    {v.external_ip:<17} {v.country_code:<4} "
                      f"{(v.country or '')[:20]:<22} {bw} Mbps  {v.path.name}")
        else:
            print(f"{'Estado':<7} {'IP externa':<17} {'CC':<4} {'País':<22} Fichero")
            print("-" * 78)
            for v in sorted(oks, key=lambda x: x.country_code or "ZZ"):
                ptag = " *" if v.patched else "  "
                print(f"OK{ptag}    {v.external_ip:<17} {v.country_code:<4} "
                      f"{(v.country or '')[:20]:<22} {v.path.name}")
        if any(v.patched for v in oks):
            print()
            print("* = fichero parcheado con redirect-gateway/DNS automáticamente")


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------

def process_batch(files: list[Path], timeout: int, use_cache: bool,
                  inbox: Path, ok_dir: Path, trash_dir: Path, auth_dir: Path,
                  measure_bw: bool = False) -> dict:
    cache = load_cache() if use_cache else {}

    # Baseline (IP sin VPN)
    print("Obteniendo IP baseline (sin VPN)…", end=" ", flush=True)
    baseline_ip, baseline_cc, baseline_country = baseline_geo()
    if not baseline_ip:
        print("FALLO al obtener IP baseline. Abortando.")
        return {}
    print(f"{baseline_ip} [{baseline_cc}] {baseline_country}")

    if measure_bw:
        print("Midiendo bandwidth baseline (sin VPN)…", end=" ", flush=True)
        baseline_bw = measure_bandwidth()
        if baseline_bw > 0:
            print(f"{baseline_bw:.1f} Mbps")
        else:
            print("n/d")
    print()

    total = len(files)
    extras = " + bandwidth" if measure_bw else ""
    print(f"Validando {total} fichero(s) (test secuencial — levanta tun0 real{extras})")
    print(f"Timeout por intento: {timeout}s · cache: {'sí' if use_cache else 'no'}")
    print()

    verdicts: list[Verdict] = []
    for idx, p in enumerate(files, 1):
        try:
            v = validate_one(p, baseline_ip, timeout, cache, use_cache, measure_bw)
        except KeyboardInterrupt:
            print("\nInterrumpido por el usuario.")
            break
        except Exception as exc:
            v = Verdict(p, STATUS_DEAD, f"excepción: {exc}")
        verdicts.append(v)
        print(format_line(idx, total, v))

    if use_cache:
        save_cache(cache)

    # Disposición automática (sin pedir confirmación)
    for v in verdicts:
        if v.status == STATUS_OK:
            move_to(v.path, ok_dir)
        elif v.status == STATUS_AUTH:
            move_to(v.path, auth_dir)
        elif v.is_failure:
            move_to(v.path, trash_dir)

    by_status = {STATUS_OK: 0, STATUS_DEAD: 0, STATUS_AUTH: 0, STATUS_MALFORMED: 0}
    for v in verdicts:
        by_status[v.status] = by_status.get(v.status, 0) + 1

    print_summary_table(verdicts)
    return by_status


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_check(args) -> int:
    inbox = Path(args.inbox)
    ok_dir = Path(args.ok)
    trash_dir = Path(args.trash)
    auth_dir = Path(args.auth)
    inbox.mkdir(exist_ok=True)
    for d in (ok_dir, trash_dir, auth_dir):
        d.mkdir(exist_ok=True)

    files = sorted([p for p in inbox.iterdir() if p.is_file() and p.suffix == ".ovpn"])
    # Cuando se pide bandwidth, también revaluamos las VPN ya validadas en ok/
    # para medir y registrar la velocidad de cada una. Se puede desactivar con
    # --inbox-only (útil cuando lo lanza la UI tras subir ficheros nuevos: no
    # queremos re-procesar 60 ficheros del cache para evaluar 4 nuevos).
    if args.bandwidth and not getattr(args, "inbox_only", False):
        ok_files = sorted([p for p in ok_dir.iterdir() if p.is_file() and p.suffix == ".ovpn"])
        if ok_files:
            print(f"Modo --bandwidth: añadiendo {len(ok_files)} fichero(s) de {ok_dir}/")
            files += ok_files

    if not files:
        msg = f"No hay .ovpn en {inbox}/"
        if args.bandwidth and not getattr(args, "inbox_only", False):
            msg += " ni en ok/"
        print(msg)
        return 0
    process_batch(files, args.timeout, not args.no_cache,
                  inbox, ok_dir, trash_dir, auth_dir,
                  measure_bw=args.bandwidth)
    return 0


def cmd_kill() -> int:
    """Mata todos los procesos openvpn corriendo en la máquina."""
    try:
        r = subprocess.run(["pgrep", "-x", "openvpn"],
                           capture_output=True, text=True, check=False)
    except FileNotFoundError:
        # Fallback sin pgrep: scan /proc
        pids = []
        for d in Path("/proc").iterdir():
            if not d.name.isdigit():
                continue
            try:
                comm = (d / "comm").read_text().strip()
            except OSError:
                continue
            if comm == "openvpn":
                pids.append(int(d.name))
    else:
        pids = [int(p) for p in r.stdout.split() if p.isdigit()]

    if not pids:
        print("No hay procesos openvpn corriendo.")
        return 0

    print(f"Matando {len(pids)} proceso(s) openvpn: {pids}")
    for p in pids:
        try:
            os.kill(p, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            print(f"  pid {p}: permission denied (relanza como root)")

    # Esperar a que terminen; si quedan, SIGKILL
    time.sleep(2)
    survivors = []
    for p in pids:
        try:
            os.kill(p, 0)  # comprueba existencia
            survivors.append(p)
        except ProcessLookupError:
            pass
        except PermissionError:
            survivors.append(p)
    for p in survivors:
        try:
            os.kill(p, signal.SIGKILL)
            print(f"  pid {p}: SIGKILL")
        except ProcessLookupError:
            pass
        except PermissionError:
            print(f"  pid {p}: no se pudo matar (permisos)")
    print("Hecho.")
    return 0


def cmd_watch(args) -> int:
    inbox = Path(args.inbox)
    ok_dir = Path(args.ok)
    trash_dir = Path(args.trash)
    auth_dir = Path(args.auth)
    inbox.mkdir(exist_ok=True)
    for d in (ok_dir, trash_dir, auth_dir):
        d.mkdir(exist_ok=True)

    print(f"Vigilando {inbox}/ (Ctrl-C para salir)")
    seen: set[Path] = set()
    try:
        while True:
            current = {p for p in inbox.iterdir() if p.is_file() and p.suffix == ".ovpn"}
            new_files = sorted(current - seen)
            if new_files:
                process_batch(new_files, args.timeout, not args.no_cache,
                              inbox, ok_dir, trash_dir, auth_dir,
                              measure_bw=args.bandwidth)
                seen = {p for p in inbox.iterdir() if p.is_file() and p.suffix == ".ovpn"}
            else:
                seen = current
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print("\nSaliendo.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="riflle2",
                                description="Validador real de .ovpn (handshake + internet + geo)")
    p.add_argument("--inbox", default=str(ROOT / "inbox"))
    p.add_argument("--ok", default=str(ROOT / "ok"))
    p.add_argument("--trash", default=str(ROOT / "trash"))
    p.add_argument("--auth", default=str(ROOT / "needs_auth"))
    p.add_argument("--timeout", type=int, default=30,
                   help="segundos por intento de conexión (default 30)")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--bandwidth", "--bandwith", action="store_true",
                   dest="bandwidth",
                   help="medir velocidad de descarga (Mbps) en cada VPN OK")
    p.add_argument("--inbox-only", action="store_true", dest="inbox_only",
                   help="no re-añadir los .ovpn de ok/ aunque se use --bandwidth")
    p.add_argument("--kill", action="store_true",
                   help="matar todos los procesos openvpn corriendo en la máquina")
    sub = p.add_subparsers(dest="cmd", required=False)
    sub.add_parser("check", help="valida ./inbox/ una vez")
    watch = sub.add_parser("watch", help="vigila ./inbox/ continuamente")
    watch.add_argument("--poll", type=float, default=3.0)
    args = p.parse_args()

    if args.kill:
        return cmd_kill()

    if not Path(OPENVPN_BIN).exists():
        print(f"ERROR: {OPENVPN_BIN} no encontrado. Instala openvpn.", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("ERROR: necesita ejecutarse como root (openvpn levanta tun0).", file=sys.stderr)
        return 2
    if not args.cmd:
        print("ERROR: especifica un subcomando (check / watch) o usa --kill",
              file=sys.stderr)
        return 2

    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "watch":
        if not hasattr(args, "poll"):
            args.poll = 3.0
        return cmd_watch(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
