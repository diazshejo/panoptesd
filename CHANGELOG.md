# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

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
