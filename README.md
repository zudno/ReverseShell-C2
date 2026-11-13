# ReverseShell — Reverse-Shell C2 Framework

[![Go](https://img.shields.io/badge/go-1.23%2B-00ADD8?logo=go)](https://go.dev/)
[![Dependencias core](https://img.shields.io/badge/deps-stdlib%20%2B%201-green)](#12-desarrollo-y-calidad)
[![Uso](https://img.shields.io/badge/uso-solo%20autorizado-orange)](#16-uso-responsable)

**Framework C2 de tipo reverse shell** escrito en **Go**, para pruebas de seguridad
autorizadas, laboratorios de formación y práctica de CTF. Arquitectura de **4 componentes
/ 3 planos** siguiendo el modelo de los C2 profesionales (implant, listener, teamserver,
cliente-operador). El agent (lado implant) inicia las conexiones hacia fuera — el modelo
"reverse" que funciona a través de redes con NAT o salida restringida.

> [!WARNING]
> **Herramienta dual-use.** Solo para: sistemas de tu propiedad, entornos de laboratorio/CTF,
> o compromisos con **autorización escrita y alcance firmado**. Su uso contra sistemas de
> terceros sin autorización explícita es ilegal. Los contribuidores deben leer
> [`AGENTS.md`](AGENTS.md) antes de escribir código.

---

## Tabla de contenidos

1. [Ficha técnica](#1-ficha-técnica)
2. [Modelo operativo y componentes](#2-modelo-operativo-y-componentes)
3. [Arquitectura](#3-arquitectura)
4. [Protocolo del plano de sesiones (implant ↔ listener)](#4-protocolo-del-plano-de-sesiones-implant--listener)
5. [Operator API (plano de control)](#5-operator-api-plano-de-control)
6. [Plano de relay (listener ↔ teamserver)](#6-plano-de-relay-listener--teamserver)
7. [Sesiones](#7-sesiones)
8. [Transports](#8-transports)
9. [Seguridad y auditoría](#9-seguridad-y-auditoría)
10. [Estructura del repositorio](#10-estructura-del-repositorio)
11. [Configuración](#11-configuración)
12. [Desarrollo y calidad](#12-desarrollo-y-calidad)
13. [Testing](#13-testing)
14. [Uso](#14-uso)
15. [Roadmap](#15-roadmap)
16. [Uso responsable](#16-uso-responsable)

---

## 1. Ficha técnica

| Aspecto | Valor |
|---|---|
| Lenguaje | Go 1.23+ |
| Arquitectura | 4 componentes / 3 planos (modelo C2 estándar) |
| Concurrencia | Goroutines + channels; `context.Context` para cancelación y shutdown |
| Dependencias core | stdlib (`net`, `net/http`, `crypto/tls`, `crypto/hmac`, `crypto/rand`, `os/exec`, `log/slog`, `encoding/binary`, `encoding/json`) + **una** externa: `github.com/BurntSushi/toml` |
| Logging | `log/slog` con handler JSON |
| Binarios | Estáticos (`CGO_ENABLED=0`), cross-compilables vía `GOOS`/`GOARCH` |
| Plataformas | Linux y Windows (amd64, arm64) |
| Modelo | Agent (implant) activo → conecta → Listener pasivo ← Teamserver ← Console |
| Config | `config.toml` (gitignored) + overrides por env vars |

**Por qué Go para un C2 de laboratorio:**

- **Binario único y estático** para el agent: sin runtime que instalar en el target del
  laboratorio; cross-compile con una variable de entorno.
- **Goroutines baratas**: una por conexión permite N sesiones sin complejidad de event loop.
- **stdlib seria**: `net`, `net/http`, `crypto/tls`, `crypto/hmac`, `os/exec` cubren los tres planos.
- **Race detector** (`go test -race`): la corrección de la concurrencia se verifica en CI.
- El protocolo del wire (§4) es **agnóstico del lenguaje** — un futuro implant en otro
  lenguaje solo debe implementar la especificación.

---

## 2. Modelo operativo y componentes

### 2.1 Los cuatro componentes

```
  PLANO DE CONTROL             PLANO DE RELAY                 PLANO DE SESIONES (reverse)
┌──────────┐   REST+SSE  ┌───────────────┐   in-process /  ┌────────────┐   conecta    ┌─────────┐
│ CONSOLE  │◀───────────▶│  TEAMSERVER   │   relay TLS     │  LISTENER  │◀─────────────│  AGENT  │
│(operador)│ 127.0.0.1   │ estado central │◀───────────────▶│ (embebido) │  hacia fuera │(implant)│
│ CLI → web│  + token    │ registry,      │                 └────────────┘              └─────────┘
└──────────┘             │ dispatcher,    │
                         │ auditoría      │
                         └───────────────┘
```

| Componente (estándar C2) | Nuestro binario | Paquetes | Rol |
|---|---|---|---|
| **Implant** (agent/beacon) | `cmd/agent` | `internal/agent` | Conecta hacia fuera, ejecuta tareas, reporta resultados |
| **Listener** | Embebido en el teamserver; `cmd/listener` standalone en F4 | `internal/transport` | Termina la conexión del implant; extrae frames |
| **Teamserver** | `cmd/teamserver` | `internal/server`, `internal/api`, `internal/session` | Estado central: registry de sesiones, dispatcher de tareas, auditoría; expone el operator API |
| **Cliente** (frontend) | `cmd/console` (CLI); futuro: web React/Vue | `internal/console` | Interfaz del operador humano — solo habla con el operator API |

### 2.2 Los tres planos

| Plano | Endpoints | Protocolo | Default bind |
|---|---|---|---|
| **Sesiones** | agent ↔ listener | Wire protocol binario propio (§4) sobre transports pluggables | Listener: `127.0.0.1` |
| **Control** | console ↔ teamserver | REST + SSE sobre HTTP (§5), bearer token | Teamserver API: `127.0.0.1` |
| **Relay** | listener ↔ teamserver | In-process (canales) por defecto; relay protocol sobre TLS en F4 (§6) | — |

### 2.3 Inversión de responsabilidades (plano de sesiones)

El teamserver nunca inicia conexiones hacia un implant; el agent nunca escucha. Todo el
estado de sesión vive en el teamserver; el agent es deliberadamente simple y mínimamente
persistente. El operador **jamás toca el plano de sesiones**: toda acción fluye por el
operator API del teamserver — un único choke point autenticado y auditable.

---

## 3. Arquitectura

### 3.1 Capas (plano de sesiones)

```
┌──────────────────────────────────────────────────────────────────┐
│  LÓGICA      cmd/teamserver + internal/server                     │
│              cmd/agent      + internal/agent                       │
├──────────────────────────────────────────────────────────────────┤
│  PROTOCOLO   internal/protocol — framing, envelope, tipos, errores │
├──────────────────────────────────────────────────────────────────┤
│  TRANSPORTE  internal/transport — tcp, tls, http(s)                │
└──────────────────────────────────────────────────────────────────┘
```

Reglas de dependencia: **solo hacia abajo**. La lógica nunca toca sockets directamente; los
transports nunca definen tipos de mensaje propios; el framing vive **una sola vez** en
`internal/protocol` y los transports lo consumen. El compilador lo refuerza: `internal/`
no es importable desde fuera del módulo.

Los planos de control y relay son HTTP/plain-TCP y no atraviesan `internal/transport`:
cada plano tiene su propio protocolo (§5, §6), sin compartir abstracciones por accidente.

### 3.2 Componentes del teamserver

| Archivo | Responsabilidad |
|---|---|
| `cmd/teamserver/main.go` | Entrypoint: flags, carga de config, arranque y shutdown |
| `internal/server/listener.go` | Gestor de listeners embebidos: accept loop, una goroutine por conexión |
| `internal/server/registry.go` | Registro de sesiones (`map[sid]*Session`), detección de STALE |
| `internal/server/dispatcher.go` | Encola TASK hacia sesiones, correlaciona RESULT↔TASK por `tid` |
| `internal/server/audit.go` | Log de auditoría estructurado (`slog` JSON → JSONL) |
| `internal/api/` | Operator API: handlers REST + stream SSE (§5) |

### 3.3 Componentes del agent

| Archivo | Responsabilidad |
|---|---|
| `cmd/agent/main.go` | Entrypoint: flags, carga de config, arranque |
| `internal/agent/beacon.go` | Loop: conectar → registrar → latir → ejecutar; reconexión con backoff+jitter |
| `internal/agent/executor.go` | Ejecución de tareas con `os/exec` y timeout por contexto |
| `internal/agent/tasks.go` | Implementaciones de los `task kinds` (tabla en §4.5) |

### 3.4 Componentes de la console

| Archivo | Responsabilidad |
|---|---|
| `cmd/console/main.go` | Entrypoint: flags (server, token), arranque |
| `internal/console/client.go` | Cliente HTTP del operator API (REST) + lector SSE |
| `internal/console/repl.go` | REPL interactivo: `sessions`, `use`, `exec`, `sysinfo`, `back`, `shutdown` |

### 3.5 Concurrencia

- **Teamserver**: el accept loop lanza una goroutine por conexión de implant. El registry
  se protege con `sync.RWMutex`. Cada sesión tiene un canal de salida para TASKs
  pendientes; los RESULT fluyen al dispatcher (fan-in). El operator API atiende con
  `net/http` (una goroutine por request, estándar). Consola y dispatcher se comunican
  por canales — sin locks en la lógica.
- **Agent**: goroutines separadas para heartbeat (`time.Ticker` + jitter) y para el
  ejecutor; una tarea larga no interrumpe el keepalive.
- **Shutdown limpio**: todo goroutine respeta `context.Context`; el teamserver propaga la
  cancelación a listeners, sesiones, API y dispatcher. Sin leaks — verificado con
  `go test -race`.

### 3.6 Contratos de tipo principales

```go
// internal/protocol/envelope.go
type Envelope struct {
    V    int             `json:"v"`
    Type MsgType         `json:"type"`
    SID  string          `json:"sid,omitempty"`
    TID  string          `json:"tid,omitempty"`
    TS   float64         `json:"ts"`
    Data json.RawMessage `json:"data"`
}
```

`json.RawMessage` difiere el decoding del campo `data` hasta conocer el `type` — el
envelope se valida siempre, el payload solo bajo el schema del tipo.

```go
// internal/protocol/framing.go

// WriteFrame escribe [u32 BE longitud][payload] en w de forma atómica.
func WriteFrame(w io.Writer, payload []byte) error

// ReadFrame lee exactamente un frame completo de r (io.ReadFull),
// rechazando frames mayores que maxFrame.
func ReadFrame(r io.Reader, maxFrame int) ([]byte, error)
```

---

## 4. Protocolo del plano de sesiones (implant ↔ listener)

> Esta especificación define el wire format — es independiente del lenguaje.

### 4.1 Framing

```
+------------------+------------------------------+
| LENGTH (u32, BE) |     PAYLOAD (UTF-8 JSON)      |
+------------------+------------------------------+
```

- `MAX_FRAME_BYTES = 4 MiB` (configurable). Frames que excedan el límite cierran la conexión
  con `ERROR MSG_TOO_LARGE`.
- **Nunca** se asume que una lectura del stream equivale a un mensaje completo:
  `ReadFrame` usa `io.ReadFull` y acumula hasta recomponer el frame por longitud.
- `encoding/binary.BigEndian` para el header; un frame nunca se escribe parcialmente
  sin bloquear el writer completo.

### 4.2 Envelope

Todo payload es un JSON con esta forma (véase el struct en §3.6):

```json
{
  "v": 1,
  "type": "TASK",
  "sid": "b3f1a2c9d0e8",
  "tid": "77c2e4a1",
  "ts": 1762940000.123,
  "data": {}
}
```

| Campo | Tipo | Reglas |
|---|---|---|
| `v` | `int` | Versión de protocolo. Incompatible → `ERROR BAD_ENVELOPE` + close |
| `type` | `str` enum | Uno de los 8 tipos de §4.3 |
| `sid` | `str` opaco | ID de sesión; obligatorio salvo en `REGISTER` |
| `tid` | `str` opaco | ID de tarea; solo en `TASK`/`RESULT` |
| `ts` | `float` | Unix timestamp del emisor |
| `data` | `dict` | Payload específico del tipo (ver abajo) |

Decoding estricto: `json.Decoder.DisallowUnknownFields()` en desarrollo para detectar
descoordinación de schema; el peer es no confiable (§9.4).

### 4.3 Tipos de mensaje

| type | Dirección | `data` | Propósito |
|---|---|---|---|
| `REGISTER` | C → H | `agent_info` | Primer mensaje; identifica al agente |
| `REGISTERED` | H → C | `session_config` | Confirma sesión y entrega parámetros |
| `TASK` | H → C | `task` | Orden emitida por el operador |
| `RESULT` | C → H | `result` | Salida de una tarea (correlaciona por `tid`) |
| `HEARTBEAT` | C → H | `{}` | Keepalive periódico |
| `ACK` | H → C | `{}` | Respuesta al heartbeat |
| `ERROR` | ambos | `error` | Error protocolar |
| `BYE` | ambos | `{"reason": str}` | Cierre limpio de la conexión |

**`agent_info`** (REGISTER):

```json
{
  "hostname": "lab-01",
  "os": "windows",
  "os_version": "10.0.19045",
  "arch": "amd64",
  "user": "labuser",
  "pid": 1234,
  "client_version": "0.1.0",
  "nonce": "e4f9..."   // persistente: permite reasignar la sesión tras reconectar
}
```

**`session_config`** (REGISTERED):

```json
{
  "heartbeat_interval": 15.0,
  "heartbeat_jitter": 0.2,
  "max_frame_bytes": 4194304
}
```

**`task`** (TASK):

```json
{ "kind": "shell", "args": { "cmd": "whoami" }, "timeout": 30 }
```

**`result`** (RESULT):

```json
{
  "status": "ok",
  "exit_code": 0,
  "stdout": "desktop-abc\\labuser\n",
  "stderr": "",
  "duration_ms": 41
}
```

`status ∈ {ok, error, timeout, unsupported}`. En `error`/`timeout` se incluye `detail: str`.

**`error`** (ERROR):

```json
{ "code": "MSG_TOO_LARGE", "message": "frame exceeds 4194304 bytes", "recoverable": false }
```

### 4.4 Códigos de error protocolares

| Código | Origen típico | ¿Recuperable? |
|---|---|---|
| `BAD_FRAME` | Longitud truncada / no numérica | No — cierra conexión |
| `BAD_ENVELOPE` | JSON inválido, campo ilegal, versión incompatible | No |
| `MSG_TOO_LARGE` | Frame > `max_frame_bytes` | No |
| `UNKNOWN_TYPE` | `type` fuera del enum | No |
| `UNKNOWN_SESSION` | `sid` no registrado (handler) | No |
| `AUTH_FAILED` | HMAC inválido (fase 3) | No — y se registra en auditoría |
| `UNSUPPORTED_KIND` | El agent no implementa el `kind` | Sí — responde `RESULT unsupported` |
| `INTERNAL` | Excepción inesperada | No |

### 4.5 Task kinds

| kind | `args` | Salida en `result` | Fase |
|---|---|---|---|
| `shell` | `cmd: str`, `timeout: float` | `exit_code, stdout, stderr` | F1 |
| `sysinfo` | — | snapshot de `agent_info` + uptime | F1 |
| `upload` | `path: str`, payload troceado | `status` | F5 |
| `download` | `path: str` | payload troceado + checksum | F5 |
| `exit` | — | el agent cierra con `BYE` | F2 |

Ejecución de `shell` (cross-platform): `exec.CommandContext` con
`context.WithTimeout` envolviendo el shell del sistema — `cmd /C` en Windows,
`/bin/sh -c` en Unix — capturando stdout/stderr por separado. El timeout mata el
proceso y produce `RESULT status=timeout`.

### 4.6 Ciclo de vida de una sesión

```
                ┌────────────┐
                │ CONNECTING │
                └─────┬──────┘
              REGISTER│
                ┌─────▼───────┐
        ┌──────▶│ REGISTERED  │
        │       └─────┬───────┘
        │             │
   re-REGISTER        │
   (mismo nonce)      │
        │       ┌─────▼────┐  TASK         ┌────────┐
        └───────│  READY   │──────────────▶│ TASKED │
                └─────┬────┘◀──────────────└────────┘
                      │        RESULT            │
                      │ BYE / drop               │ timeout
                ┌─────▼──────┐                   │
                │   CLOSED   │◀──────────────────┘
                └─────┬──────┘
                      │ backoff + jitter
                      └──────────▶ CONNECTING
```

Secuencia nominal:

```
Agent                                 Listener/Teamserver
  │── REGISTER ────────────────────────▶│
  │◀──────────────────── REGISTERED ───│  (sid + parámetros)
  │        [en espera de tareas]        │
  │◀─── TASK (shell: whoami) ───────────│  ← emitido vía operator API
  │─── RESULT (ok, stdout) ────────────▶│
  │─── HEARTBEAT ─ (c/interval ± jit) ─▶│
  │◀────────────────────────── ACK ─────│
  │─── BYE ────────────────────────────▶│
```

### 4.7 Reconexión

El agent reintenta con **backoff exponencial con jitter**:

```
delay(n) = min(base · 2^n, cap) · uniform(1 − jitter, 1 + jitter)
defaults: base = 1s, cap = 300s, jitter = 0.2
```

El `nonce` del `REGISTER` es persistente durante la vida del proceso: si el teamserver
reconoce el nonce, reasigna el mismo `sid` y la sesión continúa en lugar de duplicarse.

---

## 5. Operator API (plano de control)

REST + Server-Sent Events sobre `net/http` (stdlib). El plano que consume la console hoy
y un frontend web (React/Vue) mañana — **sin cambios en el teamserver**.

| Método | Ruta | Cuerpo / Respuesta | Descripción |
|---|---|---|---|
| `GET` | `/v1/sessions` | → lista con `sid`, peer, os, estado, `last_seen` | Sesiones activas |
| `GET` | `/v1/sessions/{sid}` | → detalle + tareas recientes | Detalle de sesión |
| `POST` | `/v1/sessions/{sid}/tasks` | `{kind, args, timeout}` → `202 {tid}` | Crea una tarea |
| `GET` | `/v1/tasks/{tid}` | → estado y resultado | Resultado de una tarea |
| `DELETE` | `/v1/sessions/{sid}` | → `204` | Cierra la sesión (envía `BYE`) |
| `GET` | `/v1/events` | → stream SSE | Eventos en tiempo real (ver abajo) |
| `POST` | `/v1/shutdown` | → `202` | Apagado limpio del teamserver (auditado) |

**Autenticación**: `Authorization: Bearer <operator_token>` en cada request. Token en
`config.toml` (gitignored). Sin token o inválido → `401` + evento en el log de auditoría.

**Bind**: `127.0.0.1` por defecto. Exponer el operator API a una red (p. ej. para una
consola remota en el laboratorio) exige flag explícito **y** TLS.

**Eventos SSE** (`/v1/events`) — espejo en tiempo real de los eventos de auditoría:

```
event: session.register  data: {"sid":"b3f1...","os":"windows","user":"labuser"}
event: task.result       data: {"sid":"b3f1...","tid":"77c2...","status":"ok","exit_code":0}
event: session.stale     data: {"sid":"b3f1..."}
```

**Retención de resultados**: el contenido de los RESULT se mantiene **en memoria** en el
teamserver (buffer acotado por sesión) para que el operador lo recupere por
`GET /v1/tasks/{tid}` o por SSE. El **audit log solo registra metadatos** (§9.3) — la
funcionalidad del operador y la accountability quedan separadas por diseño.

**Decisión de diseño — REST+SSE vs gRPC**: gRPC (como Sliver) ofrece contract-first y
streams bidireccionales, pero requiere protobuf + grpc-go — rompe el stdlib-first y
necesitaría un gateway para un frontend web. REST+SSE es 100 % stdlib y consumible
directamente por CLI y por React/Vue.

---

## 6. Plano de relay (listener ↔ teamserver)

### 6.1 Modo embebido (default, F1)

El listener corre **in-process** dentro del teamserver (modelo "jobs" de Sliver / Havoc):
`internal/server` consume `internal/transport` directamente. No hay red entre listener y
teamserver — el relay son canales de Go. Un teamserver puede ejecutar varios listeners
(p. ej. TCP 4444 + HTTP 8080) simultáneamente.

### 6.2 Listener remoto standalone (F4)

`cmd/listener` corre en otro host del laboratorio y alimenta al teamserver central sobre
TLS, reutilizando el framing length-prefix con mensajes de relay:

| type | Dirección | Propósito |
|---|---|---|
| `LISTENER_HELLO` | L → T | Autenticación del listener con token propio |
| `SESSION_UP` / `SESSION_DOWN` | L → T | Un implant conectó / cayó |
| `FRAME_RELAY` | ambos | Frame del plano de sesiones + `sid`, reenviado íntegro |

El teamserver trata al listener remoto como **semi-confiable**: valida frames, limita
tasas, y un listener comprometido solo expone las sesiones que terminan en él (no el
estado central ni el operator API).

---

## 7. Sesiones (lado teamserver)

- **IDs opacos**: `crypto/rand` → `hex.EncodeToString`; `sid` = 6 bytes, `tid` = 4 bytes.
  Nunca información derivada del target en los IDs.
- **Registry**: `map[sid]*Session` protegido por `sync.RWMutex`. `Session` contiene
  `agent_info`, estado, `last_seen`, `Conn` y el canal de TASKs pendientes.
- **STALE**: una sesión sin señal (heartbeat, resultado ni tráfico) durante
  `stale_multiplier × heartbeat_interval` se marca STALE y se retira de la lista activa
  (queda en el log de auditoría).
- **Consola del operador** (REPL en `cmd/console`):

```
rs> sessions
 #  sid          peer              os                last_seen
 1  b3f1a2c9d0e8 127.0.0.1:52411   windows/10.0.19   hace 2s
rs> use 1
rs[b3f1a2c9d0e8]> exec whoami
[77c2e4a1] ok (41 ms)
 desktop-abc\labuser
rs[b3f1a2c9d0e8]> sysinfo
rs[b3f1a2c9d0e8]> back
rs> shutdown
```

---

## 8. Transports

### 8.1 Interfaz común

Todo transport implementa la misma interfaz **message-oriented** — cada `Send`/`Recv`
transporta exactamente un frame, reensamblado con `internal/protocol`:

```go
// internal/transport/transport.go

// Conn entrega frames de mensaje completos.
type Conn interface {
    Send(ctx context.Context, frame []byte) error
    Recv(ctx context.Context) ([]byte, error)
    Close() error
}

// Listener produce Conns aceptados (lado teamserver).
type Listener interface {
    Accept(ctx context.Context) (Conn, error)
    Close() error
}

// Transport se registra en la factoría por nombre ("tcp", "tls", "http").
type Transport interface {
    Name() string
    Dial(ctx context.Context, addr string, opt Options) (Conn, error)     // lado agent
    Listen(ctx context.Context, addr string, opt Options) (Listener, error) // lado listener
}
```

Teamserver y agent solo ven `Conn`/`Transport`: pasar de `tcp` a `http` no toca lógica.
Añadir un transport nuevo es un archivo en `internal/transport/` más su registro en la
factoría (ver skill `transport-module`).

### 8.2 Catálogo

| Transport | Archivo | Modelo | Fase |
|---|---|---|---|
| `tcp` | `internal/transport/tcp.go` | Stream persistente, framing length-prefix | F1 (MVP) |
| `tls` | `internal/transport/tls.go` | Igual que TCP sobre `crypto/tls` con cert local; auth token + HMAC | F3 |
| `http` | `internal/transport/http.go` | Polling: `GET /beacon?sid=` → `204` (nada) o `200 TASK`; `POST /result` | F4 |

---

## 9. Seguridad y auditoría

### 9.1 Safe defaults

- Listener de sesiones y operator API **bind `127.0.0.1` por defecto**. Escuchar en otra
  interfaz exige flag explícito (`--host`), y queda registrado en el log de auditoría.
- Tests automatizados: **solo loopback**, puertos efímeros (`port 0`), teardown garantizado
  con `t.Cleanup`.
- Sin IPs, hosts, tokens ni credenciales en el repo: la configuración real
  (`config.toml`) está gitignored; solo se versiona `config.example.toml`.

### 9.2 El teamserver es la joya de la corona

Compromete el teamserver = compromete **todas** las sesiones y la auditoría. Por eso:

- Operator API: loopback por defecto + bearer token **obligatorio desde F1**; exponerlo
  a red exige flag explícito + TLS (F3).
- El operador nunca tiene acceso directo al plano de sesiones — toda acción pasa por el
  API autenticado y queda auditada.
- Auth del implant (fase 3): token compartido en `config.toml`; el `REGISTER` viaja con
  `hmac_sha256(token, nonce || hostname || str(ts))` (`crypto/hmac` + `crypto/sha256`).
  HMAC inválido → `ERROR AUTH_FAILED`, cierre, y evento en auditoría. El token jamás se
  loguea ni se pone en el wire.
- Token de operator API generado con `openssl rand -hex 32`.

### 9.3 Log de auditoría (JSONL)

Toda acción del operador y todo evento de sesión queda registrado con timestamp en
`logs/audit-YYYYMMDD.jsonl` mediante `log/slog` con `slog.JSONHandler`:

```json
{"ts":"2026-11-12T10:00:01Z","event":"listener.start","bind":"127.0.0.1:4444","transport":"tcp"}
{"ts":"2026-11-12T10:00:04Z","event":"session.register","sid":"b3f1a2c9d0e8","src":"127.0.0.1:52411","agent":{"os":"windows","user":"labuser"}}
{"ts":"2026-11-12T10:00:31Z","event":"operator.task","sid":"b3f1a2c9d0e8","tid":"77c2e4a1","kind":"shell","cmd":"whoami"}
{"ts":"2026-11-12T10:00:32Z","event":"session.result","sid":"b3f1a2c9d0e8","tid":"77c2e4a1","status":"ok","exit_code":0,"result_bytes":21}
{"ts":"2026-11-12T10:05:00Z","event":"session.stale","sid":"b3f1a2c9d0e8"}
```

**Regla de contenido**: el log registra *qué hizo el operador* (comando emitido, hora,
sesión) pero **no** el contenido capturado del target — los RESULT se registran como
metadatos (`status`, `exit_code`, tamaño). Sin secretos en claro, jamás.

### 9.4 Validación de entrada

Todo lo decodificado del wire se trata como no confiable: límites de tamaño (`ReadFrame`),
decoding estricto (`DisallowUnknownFields`), enum cerrados, timeouts/deadlines en toda
lectura. Los fallos se loguean y se elevan — nunca se tragan en silencio.

---

## 10. Estructura del repositorio

```
ReverseShell/
├── README.md
├── AGENTS.md                  # contrato de contribución y reglas de uso
├── go.mod                     # module path + la única dep externa pinneada
├── go.sum
├── Makefile                   # build / lint / test / cross-compile
├── config.example.toml        # plantilla de config (la real es gitignored)
├── .gitignore
├── bin/                       # binarios de build (gitignored)
├── cmd/
│   ├── agent/
│   │   └── main.go            # implant (beacon)
│   ├── teamserver/
│   │   └── main.go            # servidor central: listeners embebidos + operator API
│   ├── console/
│   │   └── main.go            # CLI del operador (→ operator API)
│   └── listener/
│       └── main.go            # listener remoto standalone (F4, plano de relay)
├── internal/
│   ├── protocol/
│   │   ├── framing.go         # + framing_test.go
│   │   ├── envelope.go        # + envelope_test.go
│   │   ├── message.go         # tipos, schemas de data
│   │   └── errors.go          # códigos de error protocolares
│   ├── transport/
│   │   ├── transport.go       # interfaces Conn / Listener / Transport + factoría
│   │   ├── tcp.go             # + tcp_test.go
│   │   ├── tls.go             # F3
│   │   └── http.go            # F4
│   ├── session/
│   │   ├── ids.go             # sid/tid/nonce opacos (crypto/rand)
│   │   └── registry.go        # + registry_test.go — máquina de estados
│   ├── config/
│   │   └── config.go          # + config_test.go — TOML + env overrides
│   ├── server/
│   │   ├── server.go          # núcleo teamserver; implementa api.Backend
│   │   ├── listener.go        # accept loop + handleConn + writeLoop
│   │   ├── dispatcher.go      # + dispatcher_test.go
│   │   ├── audit.go           # slog JSON → JSONL con el shape de §9.3
│   │   ├── events.go          # EventBus → SSE
│   │   └── e2e_test.go        # e2e loopback (criterio de aceptación F1)
│   ├── api/
│   │   └── api.go             # + api_test.go (httptest) — REST+SSE + auth bearer
│   ├── relay/
│   │   └── relay.go           # protocolo listener↔teamserver (F4)
│   ├── agent/
│   │   ├── beacon.go          # loop de sesión del implant
│   │   └── executor.go        # + executor_test.go — shell / sysinfo
│   └── console/
│       ├── client.go          # cliente REST + lector SSE
│       └── repl.go            # REPL del operador
└── labs/                      # laboratorios desechables (gitignored si contienen IPs)
```

Convenciones Go aplicadas:

- **Tests junto al código** (`*_test.go` en el mismo paquete) — es el estándar Go y
  permite testear sin exportar.
- **`internal/`** prohíbe imports externos; solo `cmd/*/main.go` es entrypoint.
- `bin/` nunca se commitea.

---

## 11. Configuración

Config en TOML. `config.toml` es **gitignored**; se versiona `config.example.toml` como
plantilla. Cada clave admite override por env var (`RS_<SECCION>_<CLAVE>`).

> La stdlib de Go no incluye TOML: la única dependencia externa del proyecto es
> `github.com/BurntSushi/toml`, pinneada en `go.mod`. (Alternativa cero-dep: config en
> JSON con `encoding/json` — se mantiene TOML por ergonomía de edición manual.)

```toml
# config.example.toml
[teamserver]
api_host = "127.0.0.1"     # bind del operator API — loopback por defecto
api_port = 5555
operator_token = "<openssl rand -hex 32>"   # bearer token del plano de control

[listener]                 # listener embebido en el teamserver
host = "127.0.0.1"         # bind de sesiones — loopback por defecto
port = 4444
transport = "tcp"          # tcp | tls | http
max_frame_bytes = 4194304  # 4 MiB

[session]
heartbeat_interval = 15.0  # segundos
heartbeat_jitter = 0.2     # ±20 %
stale_multiplier = 3       # sin señal 3×interval → STALE

[agent]
connect_host = "127.0.0.1" # a dónde conecta el implant
connect_port = 4444
transport = "tcp"
reconnect_base = 1.0       # segundos (backoff exponencial)
reconnect_cap = 300.0

[auth]                     # fase 3 — HMAC del implant; deshabilitado si ausente
# implant_token = "<openssl rand -hex 32>"

[audit]
log = "logs/audit.jsonl"
```

---

## 12. Desarrollo y calidad

```bash
# Requisito: Go 1.23+ — https://go.dev/dl/
go version

# Quality gates — obligatorios antes de dar por terminada una tarea
gofmt -l .                  # debe imprimir vacío (o: gofmt -w .)
go vet ./...
go test -race ./...
go build ./...

# Atajos (Makefile)
make lint                   # gofmt + vet
make test                   # go test -race ./...
make build                  # bin/teamserver, bin/agent, bin/console

# Ejecutar directo
go run ./cmd/teamserver
go run ./cmd/agent --host 127.0.0.1 --port 4444
go run ./cmd/console --token <operator_token>
```

**Cross-compilation del agent** (binario estático, sin CGO):

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/agent.exe    ./cmd/agent
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o bin/agent-linux  ./cmd/agent
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o bin/agent-arm64  ./cmd/agent
```

Convenciones:

- `gofmt` es el formato — no se discute estilo a mano. `go vet` y `-race` pasan siempre.
- Doc comments en identificadores exportados; comentarios explican el *porqué*, no el *qué*.
- Errores se envuelven con `%w` y se elevan; jamás fallos silenciosos.
- Todo bloqueo/reserva de recursos lleva `defer` de liberación; toda espera respeta `ctx`.

---

## 13. Testing

Jerarquía (de más a menos valiosa):

1. **Unitarios** (`internal/protocol`): framing con splits raros (1 byte a la vez, frames
   pegados, longitudes truncadas), decoding de envelope, validación de schemas.
   Table-driven tests estilo Go; deterministas y rápidos.
2. **Integración** (`registry`, `dispatcher`, `api`): lógica de sesiones sobre
   `net.Pipe()` — conexiones in-memory, sin sockets. El operator API se testea con
   `net/http/httptest` sin abrir puertos.
3. **E2E loopback** (`internal/agent` + `internal/server`): un smoke test agent↔teamserver
   real en `127.0.0.1` atravesando los tres componentes.

Reglas fijas: **nunca** un listener fuera de loopback; puertos efímeros
(`net.Listen("tcp", "127.0.0.1:0")` + lectura de `Addr().(*net.TCPAddr).Port`);
teardown garantizado con `t.Cleanup`; `go test -race ./...` obligatorio en CI —
la concurrencia de este proyecto es exactamente el tipo de código que el race
detector existe para atrapar. (Ver skill `safe-test` para el checklist completo.)

> **Nota Windows**: `-race` requiere cgo (gcc/mingw). Sin toolchain C local,
> ejecuta `go test ./...` en la máquina y confía en la CI (Linux) para el gate
> con `-race`; o instala mingw-w64 para tenerlo local.

---

## 14. Uso

```powershell
# Terminal 1 — teamserver (listener embebido 4444 + operator API 5555, loopback)
go run ./cmd/teamserver

# Terminal 2 — agent (implant) conecta al listener LOCAL
go run ./cmd/agent --host 127.0.0.1 --port 4444

# Terminal 3 — console del operador → operator API
go run ./cmd/console --token <operator_token>
```

La consola lista la sesión y permite operarla:
`sessions → use 1 → exec whoami → sysinfo → back → shutdown` (ejemplo en §7).

> Para probar contra una segunda máquina, usa el skill `lab-setup`: red aislada sin
> egreso, VMs/contenedores desechables. Nunca contra redes reales sin autorización escrita.

---

## 15. Roadmap

| Fase | Entregable | Criterio de done |
|---|---|---|
| **F0** | `go.mod`, `Makefile`, `.gitignore`, `config.example.toml`, CI con quality gates | `gofmt+vet+test -race+build` en verde desde el primer commit |
| **F1** | MVP de los 4 componentes: agent + teamserver (listener TCP embebido) + operator API mínimo (`sessions`, `tasks`, `events`) + console (`sessions`/`exec`) | `whoami` de punta a punta **desde la console**, atravesando los 3 planos en loopback |
| **F2** | Robustez de sesiones: HEARTBEAT/ACK, reconexión backoff+jitter, STALE, audit JSONL completo, cola de tasks, `exit` | Matar el agent y verlo retomar la misma sesión; la auditoría reproduce la sesión completa |
| **F3** | Hardening: TLS en plano de sesiones, HMAC del implant, TLS+token del operator API fuera de loopback | Conexión sin credenciales rechazada y auditada en ambos planos |
| **F4** | Transport HTTP(S) del implant + `cmd/listener` remoto (relay sobre TLS) | Un listener remoto en otro host del laboratorio alimenta al teamserver central |
| **F5** | `upload`/`download` con troceado+checksum, persistencia de tasks, multi-operador, web frontend (React/Vue) sobre la misma API | Archivo íntegro verificado por hash; dos operadores concurrentes sin interferirse |

---

## 16. Uso responsable

**Dentro de alcance**: sistemas propios, laboratorios/CTF, compromisos con autorización
escrita y alcance firmado. Detection, logging y auditabilidad (lo contrario a la evasión)
son bienvenidos como features.

**Fuera de alcance — no se implementará ni por petición**:

- Worming / auto-propagación.
- Ataque a terceros, despliegue masivo o no dirigido.
- Inserción en cadenas de suministro.
- Evasión de AV/EDR, anti-forensia, o cualquier función cuyo propósito sea ocultar
  actividad al propietario legítimo del sistema.

Este repo no contiene datos de targets reales: ni credenciales capturadas, ni IPs/hostnames
en vivo, ni grabaciones de sesiones de compromisos reales. Mantenlo así.
