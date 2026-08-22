# panoptesd

Daemon de monitoreo de procesos para Linux, escrito en Rust, orientado a bajo
consumo de CPU/memoria. Corre en polling (sin `tokio`, sin async), lee
`/proc` a mano, y dispara un script bash de auditoria configurable cuando
detecta comportamiento anomalo. Opcionalmente notifica todo por Telegram:
alerta inmediata por anomalia, status del servidor cada 12h, y resumen
semanal de auditoria.

## Que detecta hoy (alcance actual)

| Regla | Tipo (`AnomalyKind`) | Donde se configura |
|---|---|---|
| CPU sostenida por encima de un umbral | `cpu_sustained` | `[rules.cpu]` |
| RSS de un proceso fuera de rango | `memory_out_of_range` | `[rules.memory]` |
| Proceso corriendo como root fuera de whitelist (excluye kernel threads, ver mas abajo) | `root_not_whitelisted` | `[rules.root_whitelist]` |
| Proceso que vive menos de N segundos (cryptominer/malware efimero) | `ephemeral_process` | `[rules.ephemeral]` |
| Puerto nuevo en LISTEN/bindeado (tcp/tcp6/udp/udp6) | `nuevo_puerto_listen` | `[network]`, deshabilitado por defecto |
| Conexion TCP saliente ESTABLISHED fuera de los CIDRs/puertos esperados (solo IPv4) | `conexion_saliente_no_esperada` | `[network]`, deshabilitado por defecto |

Todas comparten el mismo `cooldown_secs` por (pid, tipo) y el mismo pool de
workers que ejecuta `audit_script_path`. Las notificaciones de Telegram
(`[telegram]`) son ortogonales a todo esto: si estan habilitadas, cualquiera
de las anomalias de arriba dispara ademas un mensaje 🚨, sin cambiar la
logica de deteccion.

## Estructura del proyecto

```
panoptesd/
├── Cargo.toml
├── src/
│   ├── main.rs        # loop principal, wiring de todos los modulos
│   ├── config.rs       # carga y structs de configuracion (TOML)
│   ├── process.rs      # parseo manual de /proc/<pid>/stat, estado por proceso
│   ├── rules.rs         # tipos de anomalia y evaluacion de reglas
│   ├── trigger.rs       # cooldown + pool de hilos que ejecutan el script
│   ├── network.rs       # correlacion opcional de sockets (/proc/net/tcp)
│   ├── userdb.rs        # cache uid -> username (/etc/passwd)
│   ├── signals.rs       # SIGTERM/SIGINT y sleep interrumpible
│   ├── logging.rs       # tracing a stdout (journald) + archivo opcional
│   ├── telegram.rs      # cliente ureq + formateo de los 3 tipos de mensaje
│   ├── scheduler.rs     # hilos nativos: status cada 12h y resumen semanal
│   ├── hoststats.rs     # uptime/CPU/memoria/disco del servidor (/proc, statvfs)
│   ├── history.rs       # historial en memoria de auditorias (para status/resumen)
│   └── timefmt.rs       # timestamps UTC via libc, sin crate de fechas
├── config/
│   └── config.example.toml
├── scripts/
│   └── auditoria.sh
└── systemd/
    └── panoptesd.service
```

## Por que este stack

- **Sin `procfs` ni `sysinfo`**: solo necesitamos 4 campos de un unico
  archivo por proceso (`/proc/<pid>/stat`: comm, utime, stime, rss) mas el
  uid (gratis, via metadata del directorio `/proc/<pid>`). Parsear a mano
  con un buffer de `String` reutilizado y un array fijo en stack (sin
  `Vec` por proceso) es mas liviano que pasar por la capa de abstraccion
  de un crate generico.
- **Sin `tokio`**: es un loop de polling secuencial, no hay I/O concurrente
  que justifique un runtime async. Se usan hilos nativos solo donde aporta
  valor real: un pool acotado de workers que ejecutan el script de
  auditoria sin bloquear el ciclo de monitoreo.
- **`tracing` + `tracing-subscriber`**: logging estructurado a stdout
  (capturado por journald bajo systemd) y opcionalmente a archivo.

## Compilacion

Requiere Rust estable (edicion 2021), instalado por ejemplo via
[rustup](https://rustup.rs/).

```bash
cargo build --release
```

El binario queda en `target/release/panoptesd`.

Verificado en este entorno (Fedora, Rust 1.98): `cargo build --release` y
`cargo clippy --release` compilan sin warnings, y una prueba funcional con
umbrales bajos confirmo el circuito completo (deteccion -> log -> ejecucion
del script -> log de auditoria -> shutdown limpio por SIGTERM).

## Instalacion como servicio systemd

```bash
# 1. Compilar
cargo build --release

# 2. Instalar el binario
sudo mkdir -p /opt/panoptesd
sudo cp target/release/panoptesd /opt/panoptesd/

# 3. Instalar configuracion
sudo mkdir -p /etc/panoptesd
sudo cp config/config.example.toml /etc/panoptesd/config.toml
sudo nano /etc/panoptesd/config.toml   # ajustar umbrales, whitelist, etc.

# 4. Instalar el script de auditoria
sudo mkdir -p /opt/panoptesd/scripts
sudo cp scripts/auditoria.sh /opt/panoptesd/scripts/auditoria.sh
sudo chmod +x /opt/panoptesd/scripts/auditoria.sh

# 5. Crear directorios de logs
sudo mkdir -p /var/log/panoptesd/audit

# 6. (Opcional) Configurar Telegram — ver seccion "Notificaciones por
#    Telegram" mas abajo para como obtener el token y el chat_id.
sudo touch /etc/panoptesd/telegram.env
sudo chmod 600 /etc/panoptesd/telegram.env
sudo nano /etc/panoptesd/telegram.env
# contenido:
#   TELEGRAM_BOT_TOKEN=123456:ABC-...
#   TELEGRAM_CHAT_ID=987654321
# y en /etc/panoptesd/config.toml, dentro de [telegram]: enabled = true

# 7. Instalar el unit de systemd
sudo cp systemd/panoptesd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now panoptesd.service
```

## Verificar que esta corriendo

```bash
sudo systemctl status panoptesd.service
sudo journalctl -u panoptesd.service -f
```

## Probar la deteccion

Para forzar una alerta y verificar que todo el circuito funciona
(deteccion -> log -> ejecucion del script -> log de auditoria):

```bash
# Genera CPU sostenida por encima del umbral configurado (ajustar
# threshold_percent/sustained_secs en config.toml para una prueba rapida,
# ej. threshold_percent=5, sustained_secs=5):
yes > /dev/null &

# Mirar los logs del daemon:
sudo journalctl -u panoptesd.service -f

# Una vez disparada la anomalia, revisar el log de auditoria generado:
ls -la /var/log/panoptesd/audit/
cat /var/log/panoptesd/audit/audit_*.log

# Limpiar el proceso de prueba:
kill %1
```

Para probar la regla de "root no en whitelist", corre temporalmente algo
como `sudo nc -l 4444 &` (si `nc` no esta en `allowed_names`) y verifica que
se dispare `root_not_whitelisted`.

Para probar la regla de proceso efimero, algo como `bash -c 'true' &`
repetidas veces con `max_lifetime_secs` bajo (ej. 2s) deberia disparar
`ephemeral_process` si el intervalo de polling es lo bastante corto para
capturarlo (limitacion inherente al polling: procesos mas cortos que
`poll_interval_secs` pueden no llegar a verse ni siquiera aparecer en un
ciclo, en cuyo caso ni se detectan; la regla cubre el rango entre un tick
y `max_lifetime_secs`).

## Configuracion

Ver `config/config.example.toml`, comentado campo por campo: intervalo de
polling, umbrales de CPU/memoria, whitelist de procesos root, regla de
procesos efimeros, correlacion de red opcional (cara en CPU: recorre los
file descriptors de todos los procesos, por eso esta deshabilitada por
defecto y corre cada `check_every_n_cycles` ciclos cuando se habilita).

### Whitelist de root y kernel threads (`[rules.root_whitelist]`)

`allowed_names` es una lista de nombres exactos para **procesos de usuario
reales** que corren como root (`systemd`, `sshd`, `cron`, `crond`,
`rsyslogd`, `systemd-journal`, `systemd-udevd`, `systemd-logind`,
`dbus-daemon`, `NetworkManager`, `panoptesd`). No hace falta agregar
kernel threads ahi (`kworker/*`, `irq/*`, `ksoftirqd/*`, `migration/*`,
`kswapd0`, threads de drivers como `card1-crtc*`, etc.): el daemon los
excluye automaticamente de esta regla antes de mirar el nombre, porque
tienen nombres dinamicos que no se pueden whitelistear uno por uno. Un
proceso se clasifica como kernel thread (y se salta `root_not_whitelisted`,
aunque sigue evaluado por CPU/memoria) si cumple cualquiera de:

1. Es hijo directo de `kthreadd` (`PPID == 2`).
2. `/proc/<pid>/exe` no resuelve a un binario real (falla, o el symlink
   esta borrado).

Este filtro fue necesario porque en una prueba real (escritorio con GPU
AMD) la regla, tal como estaba, disparo ~377 auditorias en 2 minutos
solo por los kernel threads de video/scheduler del kernel — ver
`CHANGELOG.md` para el detalle. En un servidor sin
esa carga de drivers de escritorio el volumen deberia ser mucho menor,
pero conviene tenerlo presente al calibrar un servidor nuevo: si
`root_not_whitelisted` dispara mucho al arrancar, revisar primero si son
procesos de usuario reales faltantes en `allowed_names` (agregarlos) o
si aun asi hay ruido (reportar, seria un caso no cubierto por el filtro
de kernel threads).

### Reglas de red (`[network]`, opcional)

Dos reglas independientes, ambas gateadas por el mismo
`check_every_n_cycles` (no corren en cada tick):

- **`nuevo_puerto_listen`**: lee `/proc/net/{tcp,udp}{,6}` buscando sockets
  en LISTEN (TCP) o bindeados sin conectar (UDP, el equivalente practico a
  "escuchando"), cruza el inodo con `/proc/<pid>/fd/*` para identificar el
  proceso dueño, y compara contra el snapshot del ciclo anterior. Un
  puerto que no estaba antes y no figura en `allowed_listen_ports` dispara
  la alerta, con protocolo, IP local (distingue `0.0.0.0` de una IP
  especifica) y puerto. El primer chequeo desde que arranca el daemon solo
  releva la linea de base sin alertar, para no reportar como "nuevos" los
  puertos que ya estaban escuchando al iniciar.
- **`conexion_saliente_no_esperada`**: de las conexiones TCP ESTABLISHED
  (solo IPv4), la IP remota se valida contra `allowed_cidrs_v4` y el
  puerto remoto contra `allowed_remote_ports`; si no matchea ninguno de
  los dos, dispara la alerta.

Ambas reparten el mismo mapeo inodo->pid (el paso costoso) y usan el mismo
`cooldown_secs` por (pid, tipo) que el resto de las reglas.

## Notificaciones por Telegram

Opcional (`telegram.enabled = false` por defecto). Cubre tres tipos de
mensaje, cada uno con un encabezado distinto para distinguirlos de un
vistazo en el chat:

| Mensaje | Encabezado | Cuando se envia |
|---|---|---|
| Alerta de anomalia | 🚨 *Anomalia detectada* | Al momento de cada anomalia real (CPU, memoria, root fuera de whitelist, red, proceso efimero), respetando el mismo `cooldown_secs` que ya limita el disparo del script de auditoria. Incluye timestamp, PID, nombre de proceso, usuario, tipo de anomalia y la metrica/detalle que la disparo. |
| Status periodico | 📊 *Status de panoptesd* | Cada `status_interval_hours` (12h por defecto). Uptime del servidor, %CPU y memoria (total/disponible), uso de disco por particion, cantidad de procesos vigilados, anomalias reales en las ultimas 12h, y version/uptime/ultima anomalia del propio daemon. |
| Resumen semanal | 🗂️ *Resumen semanal de auditoria* | En `weekly_summary_day`/`weekly_summary_hour` (domingo 23:00 UTC por defecto). Dispara ademas una auditoria de rutina programada y consolida todas las auditorias de la semana (por anomalia real o de rutina): cuantas corrieron, motivo de cada una y si el script de auditoria termino bien (✅) o con error (⚠️). Si no hubo ninguna anomalia real esa semana, el mensaje lo indica igual, sin necesidad de revisar logs. |

### Configurar el bot

1. Crear un bot con [@BotFather](https://t.me/BotFather) (`/newbot`) y
   guardar el token que te da (formato `123456:ABC-...`).
2. Obtener el `chat_id` donde queres recibir las notificaciones: escribile
   algo al bot (o agregalo a un grupo) y despues abri
   `https://api.telegram.org/bot<TOKEN>/getUpdates` en el navegador — el
   `chat_id` aparece en la respuesta JSON (`message.chat.id`).
3. Guardar ambos valores en `/etc/panoptesd/telegram.env` (permisos `600`,
   solo root), **nunca** en `config.toml` ni en el repo:
   ```
   TELEGRAM_BOT_TOKEN=123456:ABC-...
   TELEGRAM_CHAT_ID=987654321
   ```
4. En `/etc/panoptesd/config.toml`, dentro de `[telegram]`, poner
   `enabled = true` y ajustar `status_interval_hours`,
   `weekly_summary_day`/`weekly_summary_hour` y `disk_paths` segun
   necesites (ver `config/config.example.toml`).
5. `sudo systemctl restart panoptesd.service`. Si el token/chat_id faltan
   o son invalidos, el daemon arranca igual: se loguea un error y Telegram
   queda deshabilitado para esa corrida (nunca es motivo de caida).

El envio HTTP a la API de Telegram (via `ureq`, sincrono) corre solo en los
hilos de los workers de auditoria y en los dos hilos de los schedulers —
nunca en el loop principal de polling de `/proc`, asi que un timeout o una
caida de red hacia Telegram no afecta la deteccion de anomalias.

## Shutdown limpio

El daemon captura `SIGTERM`/`SIGINT`: al recibir la señal, termina el ciclo
de polling en curso, cierra la cola de auditoria (dejando que los workers
terminen los scripts ya en ejecucion) y sale. `systemctl stop` y
`systemctl restart` usan `SIGTERM` por defecto, por lo que el shutdown
via systemd ya queda cubierto.

## Checklist para pasar a produccion

Lo que probamos hasta ahora fue una instalacion de prueba en un escritorio
de desarrollo (`devsergi`), no el servidor real. Antes de instalar en el
servidor de produccion:

1. **Config de reglas**: partir de `config/config.example.toml` (no de la
   config de prueba usada en `devsergi`, que tenia umbrales relajados a
   proposito: `poll_interval_secs=2`, `cpu.threshold_percent=5.0`,
   `cpu.sustained_secs=5`). Los valores de referencia para produccion son
   los del ejemplo: `poll_interval_secs=5`, `cooldown_secs=300`,
   `cpu.threshold_percent=85.0` sostenido `60s`, `memory.max_rss_mb=2048`,
   `ephemeral.max_lifetime_secs=2`.
2. **`allowed_names` de `root_whitelist`**: revisar que binarios propios de
   ese servidor corren como root ademas de los 11 ya listados (por
   ejemplo un reverse proxy, un agente de monitoreo, etc.). Los kernel
   threads ya se excluyen solos (ver seccion de arriba), no hace falta
   whitelistearlos.
3. **`[network]`** (si se va a habilitar): definir `allowed_listen_ports`
   (puertos que ese servidor realmente expone), `allowed_cidrs_v4` y
   `allowed_remote_ports` segun su topologia real de red. No habilitarlo
   "a ciegas" el primer dia: activarlo, mirar `journalctl` un rato con
   `cooldown_secs` bajo antes de confiar en que el volumen de alertas es
   razonable — la misma leccion que dejo el incidente de `root_whitelist`
   aplica a cualquier regla nueva en un host que todavia no conocemos bien.
4. **Telegram**: crear un bot nuevo (o rotar el token) — el token usado en
   la prueba de `devsergi` quedo en texto plano en una conversacion y no
   deberia reusarse en produccion. Cargar `TELEGRAM_BOT_TOKEN`/
   `TELEGRAM_CHAT_ID` en `/etc/panoptesd/telegram.env` (permisos `600`,
   nunca en el repo), y `telegram.enabled = true` en `config.toml`. Ver
   seccion "Notificaciones por Telegram" para el detalle completo.
5. **Instalar y habilitar** siguiendo "Instalacion como servicio systemd"
   mas arriba, terminando en `sudo systemctl enable --now panoptesd.service`
   (`enable`, no solo `start`, para que sobreviva un reinicio del server).
6. **Verificar** con `systemctl status` + `journalctl -u panoptesd -f`
   durante un rato antes de darlo por andando, y confirmar que llega al
   menos un mensaje de Telegram (la alerta o, si no hay anomalias, esperar
   el primer status a las `status_interval_hours`).

## Limitaciones conocidas

- La correlacion de red (`network.enabled`) es deliberadamente costosa
  (recorre `/proc/<pid>/fd` de todos los procesos); usala con un
  `check_every_n_cycles` alto en servidores con muchos procesos/conexiones.
  `nuevo_puerto_listen` cubre tcp/tcp6/udp/udp6; `conexion_saliente_no_esperada`
  (conexiones ESTABLISHED) sigue siendo solo IPv4, igual que
  `allowed_cidrs_v4`.
- El nombre de proceso (`comm`) que usa la whitelist de root viene de
  `/proc/<pid>/stat` y esta truncado a 15 caracteres por el kernel; si dos
  binarios distintos comparten un nombre truncado, la whitelist no los
  distingue.
- La deteccion de procesos efimeros depende del intervalo de polling: un
  proceso que vive menos que `poll_interval_secs` puede no llegar a
  observarse en ningun ciclo.
