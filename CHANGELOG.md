# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]

### Added

- Notificaciones por Telegram (`ureq`, sin runtime async), opcionales
  (`[telegram]`): alerta inmediata por anomalia, reporte de status del
  servidor cada `status_interval_hours` (12h por defecto) y resumen
  semanal consolidado de auditorias, cada uno en un hilo nativo propio
  (`scheduler.rs`) independiente del loop de monitoreo. Token y chat_id
  se leen de `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` (env vars, nunca del
  repo ni del TOML).
- Regla de red dividida en dos (`[network]`, sigue deshabilitada por
  defecto): `nuevo_puerto_listen` (tcp/tcp6/udp/udp6, compara contra el
  snapshot del ciclo anterior) y `conexion_saliente_no_esperada`
  (reemplaza a la anterior `unexpected_network`, TCP ESTABLISHED IPv4).
- Modo CLI `panoptesd --send-telegram "<mensaje>" [--config <ruta>]`:
  manda un unico mensaje por Telegram y sale, sin arrancar el loop de
  monitoreo ni los schedulers. Reutiliza la config completa (`[telegram]`:
  `enabled`, `request_timeout_secs`) y las credenciales de
  `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID`, via la misma
  `telegram_client_from_env()` que usa el daemon. El texto pasa por
  `escape_markdown()` (nuevo `format_external_message()`), asi un script
  puede pasar paths o timestamps crudos. Sale con 0 si envio (o si
  `telegram.enabled = false`, silencioso), 1 si fallo (motivo en stderr),
  2 ante uso invalido; `--help` imprime el uso. Los argumentos
  desconocidos ahora son error en vez de ignorarse.

- Monitoreo de logins SSH exitosos (`src/ssh_watch.rs`, seccion
  `[ssh_watch]`, deshabilitado por defecto), separado del motor de
  anomalias por polling de `/proc`: lanza `journalctl -f -n 0 -o cat -u
  <unit_name>` como subproceso y un hilo dedicado lee su stdout linea por
  linea (bloqueante, sin costo cuando no hay eventos). Cada `Accepted
  password|publickey for <user> from <ip> port <port>` manda al instante
  un mensaje 🔑 *Login SSH exitoso* por Telegram (usuario, IP, puerto de
  origen, metodo, timestamp), sin cooldown y sin pasar por el script de
  auditoria; usuario e IP pasan por `escape_markdown()`. Si `journalctl`
  muere se loguea y se relanza a los 5s (backoff hasta 60s si falla en
  cadena); al apagar el daemon se mata el hijo para desbloquear la
  lectura. `unit_name` (default `ssh.service`, Debian/Ubuntu) permite
  usar `sshd.service` (Fedora/RHEL) sin recompilar. Solo logins
  exitosos: sin intentos fallidos ni otros patrones.

### Fixed

- `root_not_whitelisted` generaba falsos positivos masivos con kernel
  threads de nombre dinamico (`kworker/*`, `irq/*`, `kswapd0`,
  `migration/*`, threads de drivers como `card1-crtc*`, etc.) — detectado
  en una prueba real que disparo ~377 auditorias en 2 minutos en un
  equipo de escritorio con GPU. Ahora se excluyen antes de evaluar la
  whitelist si son hijos directos de `kthreadd` (`PPID == 2`) o si
  `/proc/<pid>/exe` no resuelve a un binario real; siguen evaluados por
  CPU/memoria igual que cualquier otro proceso.
- Los mensajes de Telegram fallaban con 400 `can't parse entities` cuando
  un campo dinamico contenia un numero impar de `_`/`*` (p.ej. el tipo
  `conexion_saliente_no_esperada`, 3 guiones bajos): Markdown legacy los
  tomaba como marcadores de formato sin cerrar. Ahora `escape_markdown()`
  escapa `_ * \` [` en todos los campos que vienen de datos (tipo de
  anomalia, proceso, usuario, detalle, path de disco) y nunca en los
  literales del template; los campos en span de codigo solo neutralizan
  backticks, porque dentro de un span Telegram no interpreta escapes. El
  marcador `[✅]` del resumen semanal ya no se pierde como link vacio.
- `conexion_saliente_no_esperada` trataba las conexiones ENTRANTES como
  salientes: `/proc/net/tcp` no indica el sentido de un socket
  ESTABLISHED y la regla solo miraba la IP/puerto remotos, asi que cada
  login por ssh desde una IP fuera de `allowed_cidrs_v4` (sshd con puerto
  local 22 y remoto efimero, p.ej. 10773) disparaba una falsa alerta.
  Ahora `Connection` conserva el puerto local y `network::is_inbound()`
  descarta antes de evaluar la whitelist toda conexion cuyo puerto local
  es de servicio: en `allowed_listen_ports`, privilegiado (< 1024), en
  LISTEN en ese mismo ciclo, o fuera del rango efimero real del kernel
  (`/proc/sys/net/ipv4/ip_local_port_range`, fallback 32768-60999). Los
  sockets en escucha se parsean una sola vez por chequeo y se comparten
  con `nuevo_puerto_listen`. El detalle de la alerta incluye ahora el
  puerto local.

## [0.1.0] - 2026-08-21

Primer release publico (open source) de panoptesd.

### Added

- Loop de monitoreo por polling (intervalo configurable), sin `tokio`,
  leyendo `/proc/<pid>/stat` a mano con buffers reutilizados.
- Reglas de deteccion de anomalias:
  - CPU sostenida por encima de un umbral (no picos aislados).
  - RSS de memoria por encima de un maximo configurado.
  - Procesos corriendo como root fuera de una whitelist de nombres.
  - Procesos efimeros (aparecen y desaparecen rapido).
  - Conexiones de red inesperadas (IPv4, opcional, correlacion via
    `/proc/net/tcp` + `/proc/<pid>/fd`).
- Disparo de un script bash de auditoria externo por anomalia, con cooldown
  configurable por (PID, tipo de anomalia) y un pool acotado de hilos para
  no bloquear el loop principal.
- Logging estructurado con `tracing`, a stdout (compatible con journald) y
  opcionalmente a archivo.
- Manejo de `SIGTERM`/`SIGINT` para shutdown limpio.
- Configuracion externa via TOML (`config/config.example.toml`).
- Script de auditoria de ejemplo (`scripts/auditoria.sh`) que captura
  `ps`, `lsof`, `ss`/`netstat` y arbol de procesos en un log con timestamp.
- Unit de systemd de ejemplo (`systemd/panoptesd.service`).

[0.1.0]: https://github.com/diazshejo/panoptesd/releases/tag/v0.1.0
