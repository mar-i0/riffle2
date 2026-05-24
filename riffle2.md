# riflle2 — Progreso completo del proyecto

Validador y switcher de ficheros OpenVPN (`.ovpn`) con:
- CLI batch que prueba cada VPN levantando tun0 de verdad y midiendo IP / país / bandwidth.
- Auto-parche de ficheros que conectan pero no enrutan tráfico (faltaba `redirect-gateway`).
- Frontal web interactivo con bandera del país, terminal bash embebido, upload de ficheros y disparo de validaciones.
- Comando `--kill` para matar procesos `openvpn` huérfanos.

## Estructura de ficheros

```
/home/iam/PROYECTOS/riflle2/
├── riflle2.py              # CLI: validador batch + --kill
├── riflle2_ui.py           # Frontal web (FastAPI + WebSocket + xterm.js)
├── inbox/                  # .ovpn pendientes de validar
├── ok/                     # .ovpn validados (conectan + enrutan)
├── needs_auth/             # .ovpn con auth-user-pass (no probados sin credenciales)
├── trash/                  # .ovpn muertos (movidos automáticamente)
├── .riflle2_cache.json     # cache de veredictos por SHA1 del fichero
├── .last_check.log         # salida del último check disparado desde la UI
└── riffle2.md              # este fichero
```

## Diagnóstico que originó el proyecto

Al hacer `openvpn cualquier.ovpn` la conexión llegaba a `Initialization Sequence Completed` pero **no había internet**. Causa raíz:

- Los `.ovpn` del paquete original NO incluyen `redirect-gateway def1`, así que tun0 se levanta pero la ruta por defecto sigue apuntando al ISP local.
- Tampoco incluyen `dhcp-option DNS …` → no se resuelve nada por DNS.

Fix manual (probado):
```bash
sudo openvpn --config x.ovpn \
  --redirect-gateway def1 \
  --dhcp-option DNS 1.1.1.1 --dhcp-option DNS 8.8.8.8 \
  --script-security 2 \
  --up /etc/openvpn/update-resolv-conf \
  --down /etc/openvpn/update-resolv-conf
```

El script `riflle2.py` automatiza esto: prueba el fichero tal cual, y si no enruta, reintenta con los flags forzados y parchea el fichero permanentemente añadiendo el bloque marcado con `# riflle2 patch`.

## CLI — `riflle2.py`

### Uso

```bash
# Validar todo lo que haya en inbox/
sudo python3 riflle2.py check

# Validar + medir bandwidth de cada VPN OK (también re-mide las ya en ok/)
sudo python3 riflle2.py --bandwidth check

# Vigilar inbox/ en bucle (procesa lo nuevo)
sudo python3 riflle2.py watch

# Matar todos los procesos openvpn corriendo en la máquina
sudo python3 riflle2.py --kill

# Refrescar la cache (descartar veredictos previos)
sudo python3 riflle2.py --no-cache check
```

### Flujo de validación por fichero

1. **Sintaxis**: requiere `remote` y `<ca>` → si falta, BAD → `trash/`.
2. **Auth**: si tiene `auth-user-pass` → `needs_auth/` (no se prueba sin credenciales).
3. **Test #1 (tal cual)**: lanza openvpn real, espera `Initialization Sequence Completed`, consulta `http://ip-api.com/line/?fields=query,countryCode,country` vía `curl --resolve` (no necesita DNS funcional), compara IP con la baseline (sin VPN).
4. **Test #2 (parcheado en memoria)**: si #1 no devolvió internet, reintenta con `--redirect-gateway def1` + DNS forzados.
5. **Si #2 funciona**: añade al fichero el bloque `# riflle2 patch` antes del bloque `<ca>` para que próximas conexiones funcionen sin flags extra.
6. **Si ambos fallan**: KO → `trash/` (sin pedir confirmación).
7. **Cache**: SHA1 del fichero → `{status, external_ip, country_code, country, bandwidth_mbps, patched, ts}`. Se reutiliza salvo `--no-cache`.

### Endpoints externos usados

| Servicio | URL | Para qué | IP fija usada |
|---|---|---|---|
| ip-api.com | `http://ip-api.com/line/?fields=query,countryCode,country` | IP + país | 208.95.112.1 / .2 |
| Cloudflare speed | `https://speed.cloudflare.com/__down?bytes=10000000` | Bandwidth (10 MB) | 104.16.0.1, 104.16.1.1, 104.16.2.1, 172.66.0.218 |
| flagcdn.com | `https://flagcdn.com/w160/{cc}.png` | Imagen bandera | DNS normal (lado cliente) |

Las llamadas a ip-api y Cloudflare usan `curl --resolve host:port:ip` para bypasear DNS — esencial porque con la VPN levantada el DNS local no resuelve nada.

### Bandwidth

`measure_bandwidth()` descarga 10 MB de `speed.cloudflare.com` con `--max-time 12` y reporta `speed_download * 8 / 1e6` (Mbps). Si la VPN va a <8 Mbps el fichero no se completa pero curl mide igualmente lo que descargó en esos 12 s.

### Auto-patch del .ovpn

```python
PATCH_BLOCK = """
# riflle2 patch — forzar todo el tráfico por el túnel + DNS
redirect-gateway def1
dhcp-option DNS 1.1.1.1
dhcp-option DNS 8.8.8.8
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
"""
PATCH_MARKER = "# riflle2 patch"
```

Se inserta antes del primer bloque inline (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`). Solo se aplica si el fichero no contiene ya `redirect-gateway` ni el marcador.

## Frontal web — `riflle2_ui.py`

### Lanzamiento

```bash
sudo python3.10 /home/iam/PROYECTOS/riflle2/riflle2_ui.py
```

Importante usar **python3.10** (no `python3` a secas) porque `python-multipart` solo está instalado en 3.10 y hace falta para el upload.

Por defecto escucha en `0.0.0.0:8060`, accesible desde:
- `http://127.0.0.1:8060/` (local)
- `http://<IP-de-la-máquina>:8060/` (LAN)

Variables de entorno opcionales: `RIFLLE2_HOST`, `RIFLLE2_PORT`.

### Layout

1. **Selector de VPN**
   - Desplegable con `ok/` + `inbox/`, ordenado por país.
   - Cada entrada: emoji bandera + país + nombre + `Mbps` (si en cache) + `✓` (si validada).
   - Botones: **Conectar** · **Desconectar** · **Medir bandwidth**.

2. **Panel de estado**
   - Bandera grande (96×64, `flagcdn.com/w160/{cc}.png`).
   - Píldora de estado: `IDLE` → `CONNECTING` → `CONNECTED` → `DISCONNECTING` (o `ERROR`).
   - País · IP externa · Bandwidth grande · Fichero · Uptime.
   - Cuadro con las últimas 30 líneas de log de openvpn.

3. **Terminal bash embebido**
   - xterm.js + WebSocket binario + `pty.fork()` en backend.
   - Bash interactivo: colores, prompt, vim, historial, autocompletado.
   - Hereda los privilegios del servidor (root si lanzaste con sudo).
   - Resize automático al cambiar ventana (envía `TIOCSWINSZ` al PTY).

4. **Upload + check**
   - Dropzone para arrastrar `.ovpn` (o click → file picker, multi-selección).
   - Nombres saneados (no ASCII → `_`, salvo CJK).
   - Detecta duplicados (`.dup1.ovpn`, `.dup2.ovpn`…).
   - Límite 2 MB.
   - Botón **"Validar inbox/ ahora"** lanza `riflle2.py --bandwidth check` en background y muestra el PID + ruta del log.

### Endpoints HTTP

| Método | Ruta | Función |
|---|---|---|
| GET | `/` | UI HTML |
| GET | `/api/vpns` | Lista de VPN con metadatos de cache |
| GET | `/api/status` | Estado actual de la conexión |
| POST | `/api/connect` | Body: `{"path": "..."}` — conectar |
| POST | `/api/disconnect` | Cerrar conexión activa |
| POST | `/api/bandwidth` | Medir bandwidth ahora |
| POST | `/api/upload` | Multipart upload de `.ovpn` |
| POST | `/api/check-inbox` | Lanzar `riflle2.py --bandwidth check` en background |
| WS | `/ws/terminal` | Terminal bash con PTY |
| GET | `/docs` | Swagger UI (FastAPI) |

### Aviso de seguridad

⚠️ **El terminal expone bash con los privilegios del proceso servidor**. Si lanzaste con `sudo`, cualquier cliente que abra `ws://host:8060/ws/terminal` tendrá shell root **sin autenticación**.

Por defecto escucha en `0.0.0.0:8060` — accesible desde toda la LAN. Si la red no es de absoluta confianza, sobrescribe con:

```bash
sudo RIFLLE2_HOST=127.0.0.1 python3.10 riflle2_ui.py
```

para limitarlo al host local.

## Cache (`.riflle2_cache.json`)

Esquema por entrada:
```json
{
  "<sha1-del-fichero>": {
    "status": "ok | dead | needs_auth | malformed",
    "reason": "",
    "external_ip": "176.97.69.174",
    "country_code": "AU",
    "country": "Australia",
    "bandwidth_mbps": 18.4,
    "patched": false,
    "ts": 1779561197
  }
}
```

La UI lee este cache para precalcular los emojis bandera / Mbps del desplegable sin necesidad de reconectar.

## Snapshot de resultados (después de la primera ejecución completa)

| Métrica | Valor |
|---|---|
| Total ficheros procesados | 41 / 66 |
| OK validados con bandwidth | 36 |
| KO movidos a `trash/` | 5 |
| Pendientes en `inbox/` | 25 |

**Top 10 por bandwidth** (después de validar):

| Mbps | País | IP |
|---:|---|---|
| 47.9 | 🇫🇷 France | 23.162.152.32 |
| 47.4 | 🇨🇭 Switzerland | 134.195.199.50 |
| 46.6 | 🇮🇹 Italy | 38.180.224.7 |
| 46.1 | 🇬🇧 United Kingdom | 186.190.211.2 |
| 45.4 | 🇳🇱 Netherlands | 108.181.58.239 |
| 45.3 | 🇩🇪 Germany | 209.46.102.22 |
| 41.8 | 🇪🇸 Spain | 108.181.70.65 |
| 39.5 | 🇧🇪 Belgium | 38.244.131.89 |
| 39.1 | 🇩🇰 Denmark | 38.180.214.188 |
| 35.7 | 🇧🇬 Bulgaria | 38.180.2.24 |

(Baseline sin VPN: 93.176.176.255 [ES] Spain, 41.2 Mbps.)

## Dependencias

```bash
# Sistema
apt install openvpn curl  # update-resolv-conf viene con openvpn

# Python (3.10)
pip install --break-system-packages fastapi uvicorn pydantic python-multipart websockets
```

`xterm.js` y `flagcdn` se cargan vía CDN desde el HTML, no requieren instalación local.

## Decisiones de diseño relevantes

- **Test secuencial**: el CLI nunca paraleliza la validación con openvpn real, porque cada conexión usa tun0 y entrarían en conflicto. La versión vieja con `--dev null` era paralela pero no probaba conectividad real.
- **Polling vs WebSocket** para el estado de la VPN: polling cada 2 s (más simple, suficiente). WebSocket solo para el terminal (bytes en tiempo real).
- **No interactividad para mover a trash**: el usuario pidió que los KO se muevan automáticamente sin preguntar. Se eliminó el prompt `[y/N/a/q]` del script original.
- **Cache reusa OK pero re-mide BW si se pide y no estaba**: si validas sin `--bandwidth` y luego con `--bandwidth`, las VPN ya OK se vuelven a conectar para obtener su Mbps.
- **`move_to` detecta no-op**: si la ruta destino es el mismo directorio del fichero, no hace nada (evita crear `.dup1` al re-procesar `ok/`).
- **Endpoint geo con `--resolve`**: el truco para hacer HTTP sin DNS. Pre-resolución hardcodeada de IPs estables de `ip-api.com` (208.95.112.1/2) y Cloudflare (104.16.x.x).

## Comandos útiles para depuración

```bash
# Ver qué openvpn corren (y sus configs)
ps aux | grep openvpn

# Matarlos todos
sudo python3 /home/iam/PROYECTOS/riflle2/riflle2.py --kill
# o manualmente:
sudo pkill -TERM openvpn

# Ver las rutas actuales (¿está la VPN enrutando?)
ip route show table all | head -20

# Ver DNS efectivo
cat /etc/resolv.conf

# Probar conectividad sin DNS (truco usado por el script)
curl -s --resolve ip-api.com:80:208.95.112.1 \
  'http://ip-api.com/line/?fields=query,countryCode,country'

# Inspeccionar el cache
python3 -c "import json; d=json.load(open('.riflle2_cache.json')); print(len(d), 'entradas')"

# Limpiar cache (forzar re-validación completa)
rm -f /home/iam/PROYECTOS/riflle2/.riflle2_cache.json

# Mover de trash de vuelta a inbox para reprobarlos
mv /home/iam/PROYECTOS/riflle2/trash/*.ovpn /home/iam/PROYECTOS/riflle2/inbox/
```

---

# riffle2.1 — multi-VPN simultáneo con shells por país

Evolución de v1 que mantiene **N conexiones OpenVPN a la vez**, cada una en su propio network namespace, con una shell `bash` por país que sale a internet por esa VPN. v1 queda intacta y funcional en :8060; v2.1 vive en paralelo en :8061.

## Ficheros nuevos

```
/home/iam/PROYECTOS/riflle2/
├── riflle21_net.py        # helpers ip netns / veth / iptables (~290 líneas)
├── riflle21_ui.py         # FastAPI multi-room (~900 líneas, puerto 8061)
├── lanzar_riffle21.sh     # launcher rápido (mata puerto + arranca)
└── riflle2.py / riflle2_ui.py    # v1 sin cambios, sigue en :8060
```

## Lanzamiento

```bash
sudo modprobe tun
sudo bash /home/iam/PROYECTOS/riflle2/lanzar_riffle21.sh
# o:
sudo python3.10 /home/iam/PROYECTOS/riflle2/riflle21_ui.py
```

UI en `http://0.0.0.0:8061/`. Si quedan rooms huérfanos tras un kill -9:
```bash
sudo python3.10 riflle21_ui.py --cleanup-orphans
```

## Arquitectura

```
host (IP ES) ─┬─ netns rfl-goku ─ openvpn ─ tun0  → IP Japón
              ├─ netns rfl-vegeta ─ openvpn ─ tun0 → IP USA
              └─ shell host (sin VPN, IP ES real)

pestaña /shell?room=goku   → bash dentro de rfl-goku
pestaña /shell?room=vegeta → bash dentro de rfl-vegeta
pestaña /shell             → bash en el host (IP real ES)
```

Cada room reserva un /30 determinista en `10.201.0.0/16`, crea un veth pair host↔netns con NAT MASQUERADE en cadenas dedicadas `RIFFLE21-NAT` y `RIFFLE21-FWD` (no toca POSTROUTING/FORWARD existentes), escribe `/etc/netns/<ns>/resolv.conf` con `1.1.1.1` + `8.8.8.8` (DNS por namespace, soluciona el bug que tenía v1) y arranca `ip netns exec <ns> openvpn --config <ovpn>` con `--redirect-gateway def1` si el fichero no lo trae.

## Endpoints HTTP

| Método | Ruta | Función |
|---|---|---|
| GET | `/` | UI principal con tabla de rooms |
| GET | `/shell` | Shell del host (sin VPN) |
| GET | `/shell?room=goku` | Shell dentro del netns rfl-goku |
| GET | `/api/vpns` | Lista de .ovpn con flag, país, Mbps, validated |
| GET | `/api/rooms` | Snapshot de rooms activas con state/ip/country/uptime |
| POST | `/api/rooms` | Body `{name, path}` — crear room (202) |
| DELETE | `/api/rooms/{name}` | Destruir room (mata openvpn, borra netns/veth/iptables) |
| GET | `/api/rooms/{name}/realip` | Geo desde dentro del netns (?force=true bypass cache) |
| GET | `/api/realip` | Geo desde el host (sin VPN) |
| POST | `/api/upload` | Subir .ovpn → inbox/ |
| POST | `/api/check-inbox` | Lanzar `riflle2.py --bandwidth check` en background |
| WS | `/ws/terminal?room=<name>` | PTY bash, opcionalmente dentro del netns |

## Frontend

- **Panel de nueva room**: campo nombre (auto-rellenado con personaje DBZ aleatorio: goku, vegeta, gohan, piccolo, krillin, trunks…), botón 🎲 para tirar otro, dropdown de VPN ordenado por país mostrando `🇯🇵  Japan — Tokyo.ovpn · 87.4 Mbps ✓`, botón **Conectar**.
- **Tabla de rooms activas** con flag, nombre, state-pill coloreada, país, IP, uptime, botones **SHELL** (abre `/shell?room=X` en nueva pestaña) y **✗** (DELETE).
- **Salida real del host** (sin VPN) — flag pequeña + IP, refresca cada 10 s.
- **Dropzone + Comprobar inbox/ ahora** — sube ficheros, lanza `riflle2.py --bandwidth check`, refresca el dropdown cada 5 s durante 60 s para ver aparecer las nuevas con su Mbps.
- **/shell** topbar tiene chip "salida real" con flag+país+IP del netns (o del host), actualizado cada 5 s. Flash verde cuando cambia la IP — útil si la VPN se cae.

## Reglas / convenciones

- Nombres de room: `[a-z0-9-]{1,8}` (regex en `riflle21_net.NAME_RE`). Por eso los DBZ van en minúsculas y abreviados (kakarot, gogeta).
- Cadenas iptables: `RIFFLE21-NAT` y `RIFFLE21-FWD` solo se enganchan UNA vez a POSTROUTING/FORWARD al arrancar; al salir se desenganchan y se borran. Las rules de cada room se hacen `-A` / `-D` dentro de esas cadenas.
- `ip_forward`: si está a 0 al arrancar, se sube a 1 y se restaura al salir.
- Cleanup al salir (Ctrl-C o SIGTERM): mata todos los rooms en orden, vacía cadenas iptables, restaura `ip_forward`. `kill -9` deja huérfanos → recuperar con `--cleanup-orphans`.

## Bugs corregidos en sesión inicial

- **`TypeError: cannot pickle '_thread.lock' object`** en `GET /api/rooms`: `dataclasses.asdict()` hace deepcopy de `subprocess.Popen` que contiene un lock no picklable. Fix: `Room.to_dict()` construye el dict campo a campo sin tocar `proc`. Síntoma: la UI se quedaba eternamente en CREATING naranja porque el polling fallaba sin que el usuario lo viera.
- **Warnings de doble cleanup**: cuando un room fallaba en setup, `_cleanup_failed` ya limpiaba netns/veth/iptables; luego el DELETE manual del usuario emitía warnings por intentar borrar cosas inexistentes. Fix: flag `Room.net_torn_down`.

## Estado al cerrar la sesión

- ✅ v1 estable en :8060.
- ✅ v2.1 arranca, bootstrap idempotente (ip_forward + cadenas iptables).
- ✅ Crear/destruir rooms desde la UI funciona.
- ✅ Shell por netns abre y stream en tiempo real (verificado con `ping -n 1.1.1.1` y `curl --resolve`).
- ✅ Dropdown muestra bandwidth de la cache.
- ✅ Dropzone + Comprobar inbox/ ahora dispara validación y refresca dropdown.
- ✅ Nombre auto-rellenado con DBZ aleatorio + botón 🎲 + re-roll tras crear.
- ⏳ **Pendiente probar dos rooms simultáneos confirmando que cada shell sale por su IP distinta** (POC del diseño multi-VPN). Si DNS falla dentro de algún netns, revisar que `/etc/netns/<ns>/resolv.conf` se escriba correctamente y que el FORWARD entre veth permita 53/udp.
- ⏳ **Pendiente medir latencia/bandwidth real desde dentro de un netns** — todavía no portamos un equivalente a `/api/bandwidth` para rooms.

## Resumen de cara a otra sesión

Para retomar mañana:

```bash
cd /home/iam/PROYECTOS/riflle2
ls -la *.py *.sh                                  # inspeccionar ficheros
sudo bash lanzar_riffle21.sh                      # arrancar v2.1 en :8061
# luego abrir http://192.168.1.194:8061/
```

El plan de diseño completo y verificación está en
`/home/iam/.claude/plans/tengo-todos-esos-ficheros-streamed-tower.md`.
