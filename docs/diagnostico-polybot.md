# Revision de Panoptesd y alerta ausente de Polybot — 2026-09-28

## Conclusion comprobada y limite de la investigacion

**No se pudo establecer la causa historica del incidente de Polybot.** No
se proporcionaron su fecha/hora, acceso identificado al servidor, config
instalada alli, log de Polybot ni journal del incidente. Se solicito host y
ventana temporal. Solo se encontro el alias SSH `dropsmart`; no se asumio
que corresponde al servidor afectado.

Si ese servidor usaba el ejemplo de 2048 MiB, el detector RSS estaba por
encima de su RAM total reportada (~1.9 GiB). **Eso demuestra que ese valor
no era preventivo para ese host**, no que fuera su configuracion efectiva.
El codigo revisado solo generaba `memory_out_of_range` al superar ese RSS
en una muestra de un proceso. Leer memoria del servidor para un status
cada 12h no era una regla de alarma por presion de memoria.

## Evidencia antes de modificar codigo

Se revisaron todos los modulos de `src/`, Cargo.toml/lock, README, CHANGELOG,
CI, config de ejemplo, unit systemd, `scripts/auditoria.sh`, la instalacion
local y el archivo `alertas .txt` (conservado sin modificar).

| Comprobacion | Evidencia disponible | Que no demuestra |
|---|---|---|
| Alertas recibidas | 111 eventos, todos `root_not_whitelisted`, entre 2026-09-24 y 27; hay status y logins SSH | No hay intento fallido de envio ni metrica de Polybot en esta exportacion |
| RAM del servidor | Status en lineas 295, 410, 558, 589, 766 y 811: total `1.9GB`; el formateador divide por 2^30, es GiB aunque diga GB | Falta MemTotal exacto y MemAvailable durante el pico |
| Umbral RSS | Ejemplo previo: 2048 MiB; regla `rss_bytes > max_rss_mb * 1024 * 1024`, campo 24 de stat, paginas convertidas por sysconf | Config instalada en produccion, RSS maximo y duracion del pico |
| Polling | Ejemplo: 5s; alertas a veces separadas 5s | Los timestamps se generaban en workers; no prueban el intervalo efectivo ni que el pico se muestreara |
| Cooldown | Ejemplo: 300s; packagekitd PID 386553 repite 19:05:15 → 19:10:15; clave previa `(PID,tipo)` | Compatible con 300s, no prueba config ni supresion de una alerta de memoria |
| Telegram | Root y status llegaron: el bot funcionaba en esos momentos. Codigo anterior: send una vez, sin retry, cooldown marcado antes de try_send | No descarta un fallo HTTP, rate limit, credenciales o red durante el incidente |
| Cola/auditoria | Cola 256; mismos workers para notificar y esperar scripts; `child.wait()` sin timeout | No hay logs remotos que prueben saturacion o bloqueo en el incidente |
| Auditoria | Script lanza ps, pstree, tr, lsof, ss, awk, head, who, logger sin contexto propio reconocido por detector | Coincidencia temporal no prueba ascendencia de los grep/find de la exportacion |
| Auditoria externa | El mensaje de 2026-09-26 09:00 menciona `/opt/security-audits/scripts/linux-security-audit.sh` | Ese script es distinto de `scripts/auditoria.sh` y no se obtuvo su codigo |
| Swap, limites, OOM | No aparecen en la exportacion | No se pueden descartar OOM de host, cgroup, systemd-oomd, ni fallo interno de asignacion de Polybot |

### Instalacion local: evidencia de otra maquina

`/etc/panoptesd/config.toml`: polling 2s, cooldown 60s, RSS 2048 MiB,
CPU 5%/5s, dos workers, Telegram enabled. `systemctl show` (consulta fuera
del sandbox porque este bloqueo el bus): Panoptesd loaded/inactive,
MemoryHigh/Max/SwapMax infinity; Polybot not-found/inactive. No es evidencia
de limites del servidor remoto.

`/proc/meminfo` local: MemTotal 11616588 KiB (~11.08 GiB), MemAvailable
6265260 KiB en la lectura; swap zram ~8 GiB, ~150000 KiB usados. El journal
local de Panoptesd tiene pruebas del 21 de agosto, incluidos scripts que
seguian ejecutandose al terminar el servicio y un timeout de parada; no
corresponde al pico de Polybot. `journalctl -u polybot` no devolvio entradas.
La busqueda OOM en el journal del kernel accesible solo devolvio el socket
de systemd-oomd, sin muerte OOM visible. Esto **no descarta OOM remoto ni
historico**: se consulto otro host y solo sus registros disponibles.

## Los nombres extranos

El parser original ya usaba el primer `(` y el ultimo `)` de stat; no
se encontro un corrimiento de campos que explique esos cuatro nombres.
Las pruebas nuevas usan `9`, `https`, `(sa1)`, `(fwupdmgr)` y nombres con
espacios/parentesis internos; comprueban comm, PPID, inicio, RSS, CPU y
flags. Tambien se compara comm leido de stat con `/proc/self/comm` real.

- `https` existe como auxiliar de APT, pero falta exe/ascendencia del PID
  422038 para confirmar que ese era su origen. Fuente primaria:
  [prueba de APT en Debian Sources](https://sources.debian.org/src/apt/2.6.1/test/integration/test-apt-update-failure-propagation/).
- `9`, `(sa1)` y `(fwupdmgr)`: identidad historica **sin confirmar**. Los
  parentesis pueden ser parte literal de comm; no se eliminan ni se
  autoriza un proceso por esa apariencia.
- Se agrego exe, padre e inicio a la evidencia de grupos y stat/status a
  la auditoria. Una repeticion futura permitira contrastar nombre,
  ejecutable, ascendencia, cgroup y paquete propietario (`dpkg -S`/`rpm -qf`).

## Correcciones realizadas

1. Presion de memoria del host via MemAvailable, con umbral absoluto o
   porcentual y duracion configurable; RSS sigue funcionando por separado.
2. Ejemplo RSS 768 MiB, host 256 MiB/15% durante 10s. Son valores iniciales
   a ajustar, **no una instalacion ni una confirmacion de la config remota**.
3. Root agrupado por ejecutable/instancia del padre; contexto de gestores
   de paquetes validado por exe, permisos y ascendencia. Ninguna whitelist
   generica nueva. Evidencia de cada integrante en log, resumen en Telegram,
   repeticion tras cooldown y retencion de auxiliares ya terminados.
4. Auditorias propias registradas por grupo de procesos creado al lanzar
   el script. Root/efimero no se retroalimentan; CPU/RSS/red conservan
   cobertura y no disparan otra auditoria para procesos de ese grupo.
5. Memoria usa cola/hilo independiente; scripts en pool separado con timeout.
   Fallos de cola/envio no consumen cooldown; deduplicacion mientras hay un
   envio en curso; hasta tres intentos; confirmacion HTTP + `ok=true`.
6. PID+starttime evita heredar cooldown/estado al reutilizar PID. La exclusion
   de kernel threads usa PF_KTHREAD; un exe borrado/inaccesible ya no oculta
   procesos de usuario.
7. Script captura memoria, swap, PSI, mayores RSS, OOM y cgroup v2/ancestros;
   PID 0 representa host. Nombres de log incluyen tipo y PID de auditoria.

La semantica de RSS/MemAvailable y los limites de cgroup se contrasto con
la documentacion primaria del [kernel (/proc)](https://www.kernel.org/doc/html/v6.9/filesystems/proc.html)
y [cgroup v2](https://www.kernel.org/doc/html/v6.5/admin-guide/cgroup-v2.html).
La confirmacion se valida segun la [API oficial de Telegram](https://core.telegram.org/bots/api#making-requests).

## Evidencia pendiente para cerrar el incidente

En el servidor correcto, con la ventana UTC del pico:

```bash
# Sin imprimir Environment ni telegram.env (contienen credenciales).
cat /etc/panoptesd/config.toml
systemctl show panoptesd polybot -p ExecStart -p FragmentPath -p DropInPaths \
  -p ControlGroup -p MemoryCurrent -p MemoryPeak -p MemoryHigh -p MemoryMax \
  -p MemorySwapMax -p Result -p ExecMainStatus
journalctl -u panoptesd -u polybot --since 'INICIO UTC' --until 'FIN UTC' --no-pager
journalctl -k --since 'INICIO UTC' --until 'FIN UTC' --no-pager \
  -g 'oom|Out of memory|Killed process'
journalctl -u systemd-oomd --since 'INICIO UTC' --until 'FIN UTC' --no-pager
cat /proc/meminfo /proc/swaps
```

Confirmar el nombre real de la unit o contenedor de Polybot. Leer
`memory.current`, `memory.high`, `memory.max`, `memory.swap.max`,
`memory.events` y `memory.events.local` de su ControlGroup **y ancestros**;
para cgroup v1 revisar `memory.limit_in_bytes`, `memory.failcnt` y
`memory.oom_control`. Obtener tambien sus logs de aplicacion y medidas
historicas de RSS/MemAvailable/swap si existen. Los valores actuales no
reconstruyen la memoria anterior al OOM. Relacionar deteccion, rechazo de
cola, intento HTTP, confirmacion o fallo y reinicios del daemon en esa ventana.

No se envio un mensaje al chat real ni se desplegaron cambios. Las pruebas
HTTP usan localhost con credenciales ficticias. Ver README para comandos
de validacion y limites de entrega (colas acotadas, sin outbox persistente,
posible duplicacion ante respuesta perdida, OOM mas rapido que el polling).

## Archivos y validacion final

| Archivos | Cambio |
|---|---|
| `src/root_events.rs` (nuevo), `src/rules.rs` | Agrupacion root y regla host, regresiones de seguridad |
| `src/main.rs`, `src/process.rs` | Muestreo, identidad, contexto de auditorias y rutas de envio |
| `src/trigger.rs`, `src/telegram.rs`, `src/scheduler.rs` | Colas, confirmacion/cooldown, reintentos, timeout y adaptacion del scheduler |
| `src/config.rs`, `src/hoststats.rs`, `config/config.example.toml` | Configuracion validada, defaults y MemAvailable |
| `src/test_support.rs` (nuevo) | Fixtures compartidas de pruebas |
| `scripts/auditoria.sh` | Evidencia de memoria/OOM/cgroup y validacion de PID del host |
| `Cargo.toml`, `Cargo.lock` | serde_json para confirmar respuesta API |
| `README.md`, `CHANGELOG.md`, este informe, `.github/workflows/ci.yml` | Comportamiento, limites, evidencia y CI de fmt/test |
| `src/logging.rs`, `src/network.rs`, `src/ssh_watch.rs` | Solo formato de cargo fmt |

Validacion ejecutada el 2026-09-28:

- `cargo fmt` y `cargo fmt --check`: OK.
- `cargo test --locked`: **39 passed, 0 failed**. Las pruebas HTTP necesitaron
  salir del sandbox para enlazar localhost; no accedieron al bot real.
- `cargo clippy --locked --all-targets -- -D warnings`: OK, sin warnings.
- `cargo build --locked`: OK.
- `bash -n scripts/auditoria.sh` y `git diff --check`: OK.
- Prueba funcional del binario final con config temporal, sin carga real de
  memoria: presion host forzada mediante umbral, un evento confirmado
  localmente, cooldown sin repeticion y salida limpia por SIGTERM.
- Script real ejecutado con PID 0 y un PID vivo, escribiendo solo sus
  archivos de auditoria en un directorio temporal: dos logs distintos con
  memoria y bloque de cgroup, finalizacion correcta. Los registros de OOM
  de esa prueba son locales, no evidencia del incidente remoto.

Artefactos locales de las pruebas funcionales:
`/tmp/panoptesd-validation-uniznp75/` (config y logs; sin credenciales).
