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

### Fixed

- `root_not_whitelisted` generaba falsos positivos masivos con kernel
  threads de nombre dinamico (`kworker/*`, `irq/*`, `kswapd0`,
  `migration/*`, threads de drivers como `card1-crtc*`, etc.) — detectado
  en una prueba real que disparo ~377 auditorias en 2 minutos en un
  equipo de escritorio con GPU. Ahora se excluyen antes de evaluar la
  whitelist si son hijos directos de `kthreadd` (`PPID == 2`) o si
  `/proc/<pid>/exe` no resuelve a un binario real; siguen evaluados por
  CPU/memoria igual que cualquier otro proceso.

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
