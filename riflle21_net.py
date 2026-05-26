"""riflle21_net — helpers de network namespaces, veth y iptables para riffle2.1.

Aísla todo el subprocess plumbing en un único módulo para que el resto de
la app trate los netns como una abstracción opaca.

Requiere root (ip netns, iptables, sysctl tocan kernel namespaces).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

NETNS_PREFIX = "rfl-"            # ip netns add rfl-jp
VETH_HOST_SUFFIX = "-h"
VETH_NS_SUFFIX = "-n"
RIFFLE21_NAT = "RIFFLE21-NAT"
RIFFLE21_FWD = "RIFFLE21-FWD"
# Cadena per-child instalada DENTRO del netns parent cuando un room está
# encadenado. El cleanup borra esta cadena entera y queda atómico.
RIFFLE21_CHILD_PREFIX = "RIFFLE21-C-"   # iptables limita a 28 chars: corto
SUBNET_POOL_BASE = "10.201"      # /16 partido en /30 → 16384 rooms posibles

IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"

NAME_RE = re.compile(r"^[a-z0-9-]{1,8}$")   # nombres cortos: rfl-<name>-h ≤ 15 chars

DEFAULT_RESOLVCONF = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"

# Algunas shells (sudo sin -i, contenedores, sesiones de usuario) no exportan
# /sbin ni /usr/sbin en PATH. Sin ellos, subprocess.run(["iptables", ...]) falla
# con FileNotFoundError aunque el binario exista. Garantizamos su presencia.
for _sbin in ("/usr/sbin", "/sbin"):
    _parts = os.environ.get("PATH", "").split(os.pathsep)
    if _sbin not in _parts:
        os.environ["PATH"] = _sbin + os.pathsep + os.environ.get("PATH", "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class NetworkError(RuntimeError):
    """Fallo en una operación de red (ip/iptables/sysctl)."""


def _run(cmd: list[str], *, check: bool = True, capture: bool = True,
         timeout: float = 8.0) -> subprocess.CompletedProcess:
    """subprocess.run con defaults sanos. Lanza NetworkError si check y falla."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NetworkError(f"{' '.join(cmd)}: {exc}") from exc
    if check and r.returncode != 0:
        msg = (r.stderr or r.stdout or "").strip()
        raise NetworkError(f"{' '.join(cmd)} (rc={r.returncode}): {msg}")
    return r


def _try(cmd: list[str]) -> None:
    """Ejecuta sin levantar si falla — para cleanup best-effort."""
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=8.0)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _rule_exists(check_cmd: list[str]) -> bool:
    """iptables -C devuelve 0 si la regla existe, !=0 si no."""
    r = subprocess.run(check_cmd, capture_output=True, text=True, timeout=8.0)
    return r.returncode == 0


def validate_name(name: str) -> None:
    if not NAME_RE.match(name):
        raise NetworkError(
            f"nombre inválido '{name}': usar [a-z0-9-]{{1,8}} "
            "(p.ej. 'jp', 'us-east', 'tokyo')"
        )


def netns_name(name: str) -> str:
    return f"{NETNS_PREFIX}{name}"


def veth_names(name: str) -> tuple[str, str]:
    return f"{NETNS_PREFIX}{name}{VETH_HOST_SUFFIX}", f"{NETNS_PREFIX}{name}{VETH_NS_SUFFIX}"


# ---------------------------------------------------------------------------
# Subnet allocation
# ---------------------------------------------------------------------------

def alloc_subnet(name: str, taken: Iterable[str] = ()) -> tuple[str, str, str]:
    """Devuelve (cidr_/30, host_ip, ns_ip) determinista por nombre.

    Si la subnet calculada colisiona con alguna en ``taken``, prueba las
    siguientes hasta encontrar una libre. Hay 16384 bloques /30 en /16.
    """
    taken_set = set(taken)
    seed = int(hashlib.sha1(name.encode()).hexdigest(), 16) % 16384
    for offset in range(16384):
        idx = (seed + offset) % 16384
        a = (idx >> 6) & 0xFF
        b = (idx & 0x3F) << 2
        cidr = f"{SUBNET_POOL_BASE}.{a}.{b}/30"
        if cidr not in taken_set:
            return cidr, f"{SUBNET_POOL_BASE}.{a}.{b+1}", f"{SUBNET_POOL_BASE}.{a}.{b+2}"
    raise NetworkError("pool de subnets agotado (>16384 rooms simultáneos)")


# ---------------------------------------------------------------------------
# ip_forward
# ---------------------------------------------------------------------------

def read_ip_forward() -> str:
    try:
        with open(IP_FORWARD_PATH) as f:
            return f.read().strip()
    except OSError:
        return ""


def write_ip_forward(value: str) -> None:
    try:
        with open(IP_FORWARD_PATH, "w") as f:
            f.write(value)
    except OSError as exc:
        raise NetworkError(f"no se pudo escribir {IP_FORWARD_PATH}: {exc}") from exc


def ensure_ip_forward() -> str:
    """Sube ip_forward a 1 si está a 0. Devuelve el valor previo para restaurarlo."""
    prev = read_ip_forward()
    if prev != "1":
        write_ip_forward("1")
    return prev or "0"


# ---------------------------------------------------------------------------
# iptables chains (idempotentes)
# ---------------------------------------------------------------------------

def ensure_iptables_chains() -> None:
    """Crea las cadenas RIFFLE21-NAT y RIFFLE21-FWD si no existen y las
    engancha a POSTROUTING/FORWARD. Idempotente.
    """
    # Crear cadenas (ignorar 'chain already exists')
    _try(["iptables", "-t", "nat", "-N", RIFFLE21_NAT])
    _try(["iptables", "-N", RIFFLE21_FWD])

    # Enganchar a POSTROUTING (-t nat) y FORWARD (-t filter) si no estaba
    if not _rule_exists(["iptables", "-t", "nat", "-C", "POSTROUTING",
                         "-j", RIFFLE21_NAT]):
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", RIFFLE21_NAT])
    if not _rule_exists(["iptables", "-C", "FORWARD", "-j", RIFFLE21_FWD]):
        _run(["iptables", "-A", "FORWARD", "-j", RIFFLE21_FWD])


def teardown_iptables_chains() -> None:
    """Desengancha cadenas, vacía y borra. Best-effort."""
    _try(["iptables", "-t", "nat", "-D", "POSTROUTING", "-j", RIFFLE21_NAT])
    _try(["iptables", "-D", "FORWARD", "-j", RIFFLE21_FWD])
    _try(["iptables", "-t", "nat", "-F", RIFFLE21_NAT])
    _try(["iptables", "-t", "nat", "-X", RIFFLE21_NAT])
    _try(["iptables", "-F", RIFFLE21_FWD])
    _try(["iptables", "-X", RIFFLE21_FWD])


# ---------------------------------------------------------------------------
# Room netns lifecycle
# ---------------------------------------------------------------------------

def _child_chain(name: str) -> str:
    """Nombre de la cadena per-child dentro del netns parent."""
    return f"{RIFFLE21_CHILD_PREFIX}{name}"


def create_room_netns(netns: str, subnet: str, host_ip: str, ns_ip: str,
                       veth_host: str, veth_ns: str,
                       resolv_conf: str = DEFAULT_RESOLVCONF,
                       parent_netns: str | None = None,
                       child_name: str | None = None) -> None:
    """Crea netns + veth + IPs + ruta default + NAT + DNS. Si algo falla,
    intenta limpiar lo que haya quedado a medias antes de relanzar.

    Si ``parent_netns`` se especifica, la red del room se enlaza al netns del
    parent en vez de al host: el extremo veth-host se mete dentro del parent,
    el NAT/FORWARD se aplica con iptables del parent (cadena per-child), y
    el handshake/tráfico del room sale por el tun0 del parent. Esto permite
    encadenar VPNs (VPN-sobre-VPN).
    """
    chained = parent_netns is not None
    if chained and not child_name:
        raise NetworkError("create_room_netns: child_name requerido con parent_netns")
    chain_name = _child_chain(child_name) if chained else ""

    created = {"netns": False, "resolv": False, "veth": False,
               "veth_in_parent": False,
               "nat": False, "fwd_in": False, "fwd_out": False,
               "child_chain": False, "child_jump": False}
    try:
        # 1. netns
        _run(["ip", "netns", "add", netns])
        created["netns"] = True

        # 2. resolv.conf por netns
        etc_dir = f"/etc/netns/{netns}"
        os.makedirs(etc_dir, exist_ok=True)
        with open(f"{etc_dir}/resolv.conf", "w") as f:
            f.write(resolv_conf)
        created["resolv"] = True

        # 3. veth pair (los dos extremos nacen en default ns)
        _run(["ip", "link", "add", veth_host, "type", "veth",
              "peer", "name", veth_ns])
        created["veth"] = True

        # 4. mover el peer al netns del room
        _run(["ip", "link", "set", veth_ns, "netns", netns])

        # 5. lado host: ip + up
        if chained:
            # mover veth-host al netns del parent
            _run(["ip", "link", "set", veth_host, "netns", parent_netns])
            created["veth_in_parent"] = True
            _run(["ip", "netns", "exec", parent_netns,
                  "ip", "addr", "add", f"{host_ip}/30", "dev", veth_host])
            _run(["ip", "netns", "exec", parent_netns,
                  "ip", "link", "set", veth_host, "up"])
        else:
            _run(["ip", "addr", "add", f"{host_ip}/30", "dev", veth_host])
            _run(["ip", "link", "set", veth_host, "up"])

        # 6. dentro del netns: lo + veth + ruta default
        _run(["ip", "netns", "exec", netns, "ip", "link", "set", "lo", "up"])
        _run(["ip", "netns", "exec", netns, "ip", "addr", "add",
              f"{ns_ip}/30", "dev", veth_ns])
        _run(["ip", "netns", "exec", netns, "ip", "link", "set", veth_ns, "up"])
        _run(["ip", "netns", "exec", netns, "ip", "route", "add",
              "default", "via", host_ip])

        # 7. NAT + FORWARD — host o parent según corresponda
        if chained:
            # ip_forward dentro del parent (idempotente)
            _try(["ip", "netns", "exec", parent_netns,
                  "sysctl", "-w", "net.ipv4.ip_forward=1"])
            # rp_filter loose en el parent: con doble encapsulado, los paquetes
            # encriptados del hijo (src = ns_ip_B) entran por veth y se reenvían
            # a tun0 — con rp_filter=1 (strict) el kernel los puede dropear si
            # la verificación reverse-path no le cuadra. Loose=2 es lo que usa
            # Docker/k8s en escenarios equivalentes.
            _try(["ip", "netns", "exec", parent_netns,
                  "sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"])
            _try(["ip", "netns", "exec", parent_netns,
                  "sysctl", "-w", f"net.ipv4.conf.{veth_host}.rp_filter=2"])
            # cadena per-child (cleanup atómico borrándola entera)
            _run(["ip", "netns", "exec", parent_netns,
                  "iptables", "-t", "nat", "-N", chain_name])
            created["child_chain"] = True
            _run(["ip", "netns", "exec", parent_netns,
                  "iptables", "-t", "nat", "-A", chain_name,
                  "-s", subnet, "-o", "tun0", "-j", "MASQUERADE"])
            _run(["ip", "netns", "exec", parent_netns,
                  "iptables", "-t", "nat", "-A", "POSTROUTING",
                  "-j", chain_name])
            created["child_jump"] = True
            _run(["ip", "netns", "exec", parent_netns,
                  "iptables", "-A", "FORWARD", "-i", veth_host, "-j", "ACCEPT"])
            created["fwd_in"] = True
            _run(["ip", "netns", "exec", parent_netns,
                  "iptables", "-A", "FORWARD", "-o", veth_host, "-j", "ACCEPT"])
            created["fwd_out"] = True
        else:
            _run(["iptables", "-t", "nat", "-A", RIFFLE21_NAT,
                  "-s", subnet, "-j", "MASQUERADE"])
            created["nat"] = True
            _run(["iptables", "-A", RIFFLE21_FWD, "-i", veth_host, "-j", "ACCEPT"])
            created["fwd_in"] = True
            _run(["iptables", "-A", RIFFLE21_FWD, "-o", veth_host, "-j", "ACCEPT"])
            created["fwd_out"] = True

    except NetworkError:
        # rollback parcial best-effort
        if chained:
            if created["fwd_out"]:
                _try(["ip", "netns", "exec", parent_netns,
                      "iptables", "-D", "FORWARD", "-o", veth_host, "-j", "ACCEPT"])
            if created["fwd_in"]:
                _try(["ip", "netns", "exec", parent_netns,
                      "iptables", "-D", "FORWARD", "-i", veth_host, "-j", "ACCEPT"])
            if created["child_jump"]:
                _try(["ip", "netns", "exec", parent_netns,
                      "iptables", "-t", "nat", "-D", "POSTROUTING",
                      "-j", chain_name])
            if created["child_chain"]:
                _try(["ip", "netns", "exec", parent_netns,
                      "iptables", "-t", "nat", "-F", chain_name])
                _try(["ip", "netns", "exec", parent_netns,
                      "iptables", "-t", "nat", "-X", chain_name])
            if created["veth_in_parent"]:
                _try(["ip", "netns", "exec", parent_netns,
                      "ip", "link", "del", veth_host])
        else:
            if created["fwd_out"]:
                _try(["iptables", "-D", RIFFLE21_FWD, "-o", veth_host, "-j", "ACCEPT"])
            if created["fwd_in"]:
                _try(["iptables", "-D", RIFFLE21_FWD, "-i", veth_host, "-j", "ACCEPT"])
            if created["nat"]:
                _try(["iptables", "-t", "nat", "-D", RIFFLE21_NAT,
                      "-s", subnet, "-j", "MASQUERADE"])
        if created["veth"] and not created["veth_in_parent"]:
            _try(["ip", "link", "del", veth_host])
        if created["netns"]:
            _try(["ip", "netns", "del", netns])
        if created["resolv"]:
            shutil.rmtree(f"/etc/netns/{netns}", ignore_errors=True)
        raise


def destroy_room_netns(netns: str, subnet: str,
                        veth_host: str,
                        parent_netns: str | None = None,
                        child_name: str | None = None) -> list[str]:
    """Tear down completo. Devuelve la lista de errores ignorados (para log).

    Para rooms encadenadas (parent_netns!=None), limpia las reglas y la veth
    desde dentro del netns del parent. Si el parent ya fue destruido en
    cascada, los `ip netns exec <parent>` fallarán silenciosamente — es
    intencional: el netns destruido se llevó por delante todo lo de dentro.
    """
    errors: list[str] = []
    chained = parent_netns is not None

    def step(cmd: list[str], best_effort: bool = False) -> None:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8.0)
        if r.returncode != 0 and not best_effort:
            err = (r.stderr or r.stdout or "").strip()
            errors.append(f"{' '.join(cmd)} → {err}")

    if chained:
        chain_name = _child_chain(child_name or "")
        prefix = ["ip", "netns", "exec", parent_netns]
        # 1. iptables del parent (best-effort: el parent puede haber muerto)
        step(prefix + ["iptables", "-D", "FORWARD", "-o", veth_host, "-j", "ACCEPT"],
             best_effort=True)
        step(prefix + ["iptables", "-D", "FORWARD", "-i", veth_host, "-j", "ACCEPT"],
             best_effort=True)
        step(prefix + ["iptables", "-t", "nat", "-D", "POSTROUTING",
                       "-j", chain_name], best_effort=True)
        step(prefix + ["iptables", "-t", "nat", "-F", chain_name], best_effort=True)
        step(prefix + ["iptables", "-t", "nat", "-X", chain_name], best_effort=True)
        # 2. veth-host vive dentro del parent
        step(prefix + ["ip", "link", "del", veth_host], best_effort=True)
    else:
        # 1. iptables del host
        step(["iptables", "-D", RIFFLE21_FWD, "-o", veth_host, "-j", "ACCEPT"])
        step(["iptables", "-D", RIFFLE21_FWD, "-i", veth_host, "-j", "ACCEPT"])
        step(["iptables", "-t", "nat", "-D", RIFFLE21_NAT,
              "-s", subnet, "-j", "MASQUERADE"])
        # 2. veth (lado peer dentro del netns se borra al borrar el host)
        step(["ip", "link", "del", veth_host])

    # 3. netns — esto mata los procesos que sigan dentro (openvpn, bash...)
    step(["ip", "netns", "del", netns])

    # 4. resolv.conf del netns
    try:
        shutil.rmtree(f"/etc/netns/{netns}", ignore_errors=True)
    except OSError as exc:
        errors.append(f"rmtree /etc/netns/{netns} → {exc}")

    return errors


# ---------------------------------------------------------------------------
# Geo dentro del netns
# ---------------------------------------------------------------------------

# Constantes copiadas de riflle2.py para no acoplar imports circulares.
GEO_HOST = "ip-api.com"
GEO_PATH = "/line/?fields=query,countryCode,country"
GEO_FALLBACK_IPS = ["208.95.112.1", "208.95.112.2"]


def query_geo_in_ns(netns: str, timeout: int = 8) -> tuple[str, str, str]:
    """Consulta ip-api.com desde dentro del netns. Devuelve (ip, code, country).
    Usa --resolve para no depender de DNS, igual que riflle2.query_geo."""
    for resolved_ip in GEO_FALLBACK_IPS:
        try:
            r = subprocess.run(
                [
                    "ip", "netns", "exec", netns,
                    "curl", "-s", "--max-time", str(timeout),
                    "--resolve", f"{GEO_HOST}:80:{resolved_ip}",
                    f"http://{GEO_HOST}{GEO_PATH}",
                ],
                capture_output=True, text=True, check=False, timeout=timeout + 2,
            )
            lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            if len(lines) >= 3:
                country, code, ip = lines[0], lines[1], lines[2]
                if ip and "." in ip:
                    return ip, code, country
        except (subprocess.SubprocessError, OSError):
            continue
    return "", "", ""


# ---------------------------------------------------------------------------
# Orphan cleanup (recuperación tras kill -9)
# ---------------------------------------------------------------------------

def list_orphan_netns() -> list[str]:
    """Lista los netns existentes con prefijo rfl-."""
    r = subprocess.run(["ip", "-j", "netns", "list"],
                       capture_output=True, text=True, timeout=5)
    if r.returncode != 0 or not r.stdout.strip():
        # ip -j netns falla en versiones viejas; fallback parsing texto
        r2 = subprocess.run(["ip", "netns", "list"],
                            capture_output=True, text=True, timeout=5)
        return [line.split()[0] for line in r2.stdout.splitlines()
                if line.startswith(NETNS_PREFIX)]
    try:
        items = json.loads(r.stdout)
        return [item["name"] for item in items
                if item.get("name", "").startswith(NETNS_PREFIX)]
    except (json.JSONDecodeError, KeyError):
        return []


def cleanup_orphans() -> dict:
    """Borra todos los netns y veth con prefijo rfl-*, y vacía las cadenas
    iptables. Útil tras un kill -9 de la app. Devuelve resumen para log."""
    summary = {"netns": [], "veth": [], "errors": []}
    for ns in list_orphan_netns():
        name = ns[len(NETNS_PREFIX):]
        veth_host, _ = veth_names(name)
        # No conocemos la subnet exacta — pero al matar el netns y el veth,
        # las reglas iptables MASQUERADE quedan colgando hasta el flush final.
        _try(["ip", "link", "del", veth_host])
        _try(["ip", "netns", "del", ns])
        shutil.rmtree(f"/etc/netns/{ns}", ignore_errors=True)
        summary["netns"].append(ns)
        summary["veth"].append(veth_host)
    # Flush total de la cadena RIFFLE21-NAT — los MASQUERADE huérfanos caen aquí.
    _try(["iptables", "-t", "nat", "-F", RIFFLE21_NAT])
    _try(["iptables", "-F", RIFFLE21_FWD])
    return summary


# ---------------------------------------------------------------------------
# Run command inside netns (utility)
# ---------------------------------------------------------------------------

def run_in_ns(netns: str, cmd: list[str], timeout: float = 8.0) -> subprocess.CompletedProcess:
    full = ["ip", "netns", "exec", netns, *cmd]
    return subprocess.run(full, capture_output=True, text=True, timeout=timeout)
