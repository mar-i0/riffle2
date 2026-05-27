"""riflle21_uri — parseo y normalización de URIs de proxy.

Soporta cuatro esquemas:
  - vless://       (delegado a vless_check.parse_vless)
  - vmess://       (base64 JSON estilo v2rayN)
  - trojan://      (similar a vless, sin uuid)
  - hysteria2://   (QUIC; outbound vía sing-box)

Cada parser devuelve un ProxyURI normalizado. Los generadores
`to_xray_outbound` (vless/vmess/trojan) y `to_singbox_outbound` (hysteria2)
convierten el ProxyURI en un dict listo para meter en la config del binario.

El cliente típico es `riflle21_backends.build_*` (config completa con TUN
inbound) y `backends.deep_smoke_test_uri` (validación efímera vía netns).
"""

from __future__ import annotations

import base64
import json
import sys
import uuid as uuid_mod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

# Reutilizamos el parser maduro de vless del subproyecto vless/
_VLESS_DIR = Path("/home/iam/PROYECTOS/vless")
if str(_VLESS_DIR) not in sys.path and _VLESS_DIR.exists():
    sys.path.insert(0, str(_VLESS_DIR))
try:
    import vless_check  # type: ignore
except ImportError:
    vless_check = None  # type: ignore


SUPPORTED_KINDS = ("vless", "vmess", "trojan", "hy2")
# Extensiones que cada protocolo usa al persistirse en proxies_ok/.
KIND_TO_EXT = {"vless": ".vless", "vmess": ".vmess",
               "trojan": ".trojan", "hy2": ".hy2"}
EXT_TO_KIND = {v: k for k, v in KIND_TO_EXT.items()}


@dataclass
class ProxyURI:
    """Versión normalizada de cualquier URI de proxy soportada. Los
    generadores de outbound leen sólo de los campos que les aplican
    según `kind`."""
    kind: str
    raw: str
    host: str
    port: int
    tag: str = ""
    uuid: str = ""           # vless / vmess
    password: str = ""       # trojan / hysteria2
    # alter-id (vmess legacy)
    alter_id: int = 0
    # transporte y TLS (vless/vmess/trojan)
    transport: str = "tcp"   # tcp|ws|grpc|httpupgrade
    security: str = "none"   # none|tls
    sni: str = ""
    alpn: list[str] = field(default_factory=list)
    ws_path: str = "/"
    ws_host: str = ""
    grpc_service: str = ""
    # vmess
    vmess_scy: str = "auto"
    # hysteria2
    insecure: bool = False
    # bolsa de parámetros originales por si hace falta debug
    params: dict = field(default_factory=dict)


def kind_of(uri: str) -> str:
    """Devuelve el kind canónico para una URI o '' si el esquema no se reconoce."""
    s = uri.strip().lower()
    if s.startswith("vless://"):
        return "vless"
    if s.startswith("vmess://"):
        return "vmess"
    if s.startswith("trojan://"):
        return "trojan"
    if s.startswith("hysteria2://") or s.startswith("hy2://"):
        return "hy2"
    return ""


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse(uri: str) -> ProxyURI:
    """Despacha por esquema. Lanza ValueError si la URI es malformada o el
    esquema no está soportado."""
    k = kind_of(uri)
    if k == "vless":
        return _parse_vless(uri)
    if k == "vmess":
        return _parse_vmess(uri)
    if k == "trojan":
        return _parse_trojan(uri)
    if k == "hy2":
        return _parse_hysteria2(uri)
    raise ValueError(f"esquema no soportado: {uri[:20]!r}")


def _parse_vless(uri: str) -> ProxyURI:
    if vless_check is None:
        raise RuntimeError("vless_check no disponible")
    v = vless_check.parse_vless(uri)
    return ProxyURI(
        kind="vless", raw=uri,
        host=v.host, port=v.port, tag=v.tag,
        uuid=v.uuid,
        transport=v.transport, security=v.security,
        sni=v.sni, alpn=v.alpn,
        ws_path=v.ws_path, ws_host=v.ws_host,
        grpc_service=v.params.get("serviceName", ""),
        params=dict(v.params),
    )


def _parse_vmess(uri: str) -> ProxyURI:
    body = uri[len("vmess://"):]
    # vmess está siempre en base64 (a veces con padding faltando)
    padding = (-len(body)) % 4
    try:
        decoded = base64.b64decode(body + "=" * padding).decode("utf-8")
        cfg = json.loads(decoded)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"vmess base64/JSON inválido: {exc}") from exc
    host = str(cfg.get("add", "")).strip()
    try:
        port = int(str(cfg.get("port", "")).strip())
    except ValueError as exc:
        raise ValueError(f"vmess: puerto inválido: {cfg.get('port')!r}") from exc
    user_id = str(cfg.get("id", "")).strip()
    try:
        uuid_mod.UUID(user_id)
    except ValueError as exc:
        raise ValueError(f"vmess: UUID inválido: {user_id!r}") from exc
    if not host or not (0 < port < 65536):
        raise ValueError(f"vmess: host/port inválidos ({host}:{port})")
    aid_raw = str(cfg.get("aid", "0")).strip() or "0"
    try:
        aid = int(aid_raw)
    except ValueError:
        aid = 0
    net = (str(cfg.get("net", "tcp")) or "tcp").lower()
    tls = str(cfg.get("tls", "")).lower()
    sec = "tls" if tls in ("tls", "reality", "xtls") else "none"
    alpn_raw = str(cfg.get("alpn", ""))
    alpn = [a.strip() for a in alpn_raw.split(",") if a.strip()]
    return ProxyURI(
        kind="vmess", raw=uri,
        host=host, port=port,
        tag=str(cfg.get("ps", "") or ""),
        uuid=user_id, alter_id=aid,
        transport=net, security=sec,
        sni=str(cfg.get("sni", "") or cfg.get("host", "") or host),
        alpn=alpn,
        ws_path=str(cfg.get("path", "") or "/"),
        ws_host=str(cfg.get("host", "") or ""),
        vmess_scy=str(cfg.get("scy", "auto") or "auto"),
        params=cfg,
    )


def _parse_trojan(uri: str) -> ProxyURI:
    p = urlparse(uri)
    if p.scheme != "trojan":
        raise ValueError(f"trojan: esquema inesperado {p.scheme!r}")
    password = unquote(p.username or "")
    if not password:
        raise ValueError("trojan: falta la contraseña antes de '@'")
    if not p.hostname or not p.port:
        raise ValueError("trojan: faltan host o puerto")
    if not (0 < p.port < 65536):
        raise ValueError(f"trojan: puerto fuera de rango {p.port}")
    flat = {k: unquote(v[-1]) for k, v in
            parse_qs(p.query, keep_blank_values=True).items()}
    sec = (flat.get("security", "") or "tls").lower()
    sni = flat.get("sni") or flat.get("host") or p.hostname
    alpn = [a.strip() for a in flat.get("alpn", "").split(",") if a.strip()]
    return ProxyURI(
        kind="trojan", raw=uri,
        host=p.hostname, port=p.port,
        tag=unquote(p.fragment) if p.fragment else "",
        password=password,
        transport=(flat.get("type", "tcp") or "tcp").lower(),
        security=sec, sni=sni, alpn=alpn,
        ws_path=flat.get("path", "/"),
        ws_host=flat.get("host", "") or sni,
        grpc_service=flat.get("serviceName", ""),
        params=flat,
    )


def _parse_hysteria2(uri: str) -> ProxyURI:
    p = urlparse(uri)
    if p.scheme not in ("hysteria2", "hy2"):
        raise ValueError(f"hysteria2: esquema inesperado {p.scheme!r}")
    # Userinfo es la contraseña (puede contener ':' y '/' codificados).
    # urlparse divide en username/password si hay ':', así que reconstruimos.
    if p.username is not None and p.password is not None:
        auth = f"{unquote(p.username)}:{unquote(p.password)}"
    elif p.username is not None:
        auth = unquote(p.username)
    else:
        auth = ""
    if not auth:
        raise ValueError("hysteria2: falta la contraseña antes de '@'")
    if not p.hostname or not p.port:
        raise ValueError("hysteria2: faltan host o puerto")
    if not (0 < p.port < 65536):
        raise ValueError(f"hysteria2: puerto fuera de rango {p.port}")
    flat = {k: unquote(v[-1]) for k, v in
            parse_qs(p.query, keep_blank_values=True).items()}
    insecure = (flat.get("insecure") or flat.get("allowInsecure") or "0") in (
        "1", "true", "True")
    sni = flat.get("sni") or flat.get("peer") or p.hostname
    alpn = [a.strip() for a in flat.get("alpn", "h3").split(",") if a.strip()]
    return ProxyURI(
        kind="hy2", raw=uri,
        host=p.hostname, port=p.port,
        tag=unquote(p.fragment) if p.fragment else "",
        password=auth,
        security="tls", sni=sni, alpn=alpn or ["h3"],
        insecure=insecure,
        params=flat,
    )


# ---------------------------------------------------------------------------
# Generadores de outbound — xray (vless/vmess/trojan)
# ---------------------------------------------------------------------------

def _xray_stream(p: ProxyURI) -> dict:
    stream: dict = {"network": p.transport, "security": p.security}
    if p.security == "tls":
        tls: dict = {"serverName": p.sni}
        if p.alpn:
            tls["alpn"] = p.alpn
        stream["tlsSettings"] = tls
    if p.transport == "ws":
        ws: dict = {"path": p.ws_path}
        if p.ws_host:
            ws["headers"] = {"Host": p.ws_host}
        stream["wsSettings"] = ws
    elif p.transport == "httpupgrade":
        hu: dict = {"path": p.ws_path}
        if p.ws_host:
            hu["host"] = p.ws_host
        stream["httpupgradeSettings"] = hu
    elif p.transport == "grpc":
        stream["grpcSettings"] = {"serviceName": p.grpc_service}
    return stream


def to_xray_outbound(p: ProxyURI) -> dict:
    """xray-core outbound para vless/vmess/trojan. Lanza ValueError para
    cualquier otro kind (hysteria2 no es xray-soportado)."""
    if p.kind == "vless":
        return {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{
                "address": p.host, "port": p.port,
                "users": [{"id": p.uuid, "encryption": "none",
                            "flow": p.params.get("flow", "")}],
            }]},
            "streamSettings": _xray_stream(p),
        }
    if p.kind == "vmess":
        return {
            "tag": "proxy", "protocol": "vmess",
            "settings": {"vnext": [{
                "address": p.host, "port": p.port,
                "users": [{"id": p.uuid, "alterId": p.alter_id,
                            "security": p.vmess_scy}],
            }]},
            "streamSettings": _xray_stream(p),
        }
    if p.kind == "trojan":
        return {
            "tag": "proxy", "protocol": "trojan",
            "settings": {"servers": [{
                "address": p.host, "port": p.port,
                "password": p.password,
            }]},
            "streamSettings": _xray_stream(p),
        }
    raise ValueError(f"to_xray_outbound: kind no soportado por xray: {p.kind}")


# ---------------------------------------------------------------------------
# Generadores — sing-box (hysteria2)
# ---------------------------------------------------------------------------

def to_singbox_outbound(p: ProxyURI) -> dict:
    """sing-box outbound. Hoy sólo cubrimos hysteria2 (el resto lo hace xray)."""
    if p.kind != "hy2":
        raise ValueError(f"to_singbox_outbound: kind {p.kind} se gestiona en xray")
    return {
        "type": "hysteria2",
        "tag": "proxy",
        "server": p.host,
        "server_port": p.port,
        "password": p.password,
        "tls": {
            "enabled": True,
            "server_name": p.sni,
            "insecure": p.insecure,
            "alpn": p.alpn or ["h3"],
        },
    }


def singbox_config(p: ProxyURI, tun_name: str, tun_addr_cidr: str,
                   mtu: int = 1500) -> dict:
    """Config sing-box mínima: TUN inbound + outbound. auto_route=false
    porque las rutas las instalamos nosotros con install_vless_routes,
    igual que con xray (para mantener un único path de routing)."""
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": tun_name,
            "address": [tun_addr_cidr],
            "mtu": mtu,
            "auto_route": False,
            "strict_route": False,
            "stack": "system",
            "sniff": True,
        }],
        "outbounds": [
            to_singbox_outbound(p),
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [{"inbound": ["tun-in"], "outbound": "proxy"}],
            "auto_detect_interface": False,
        },
    }


# ---------------------------------------------------------------------------
# Lectura de fichero persistido (.vless/.vmess/.trojan/.hy2)
# ---------------------------------------------------------------------------

def read_uri_from_file(path: Path) -> str:
    """Devuelve la primera línea no-comentario del fichero. Los ficheros
    persistidos en proxies_ok/ tienen un comentario opcional en la línea 1
    y la URI cruda en la siguiente."""
    for raw in path.read_text(errors="replace").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            return s
    raise ValueError(f"{path.name}: no contiene URI")


def kind_from_path(path: Path) -> Optional[str]:
    """Devuelve el kind a partir de la extensión, o None si no aplica."""
    return EXT_TO_KIND.get(path.suffix.lower())
