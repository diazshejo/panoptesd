# panoptesd

Daemon de monitoreo de procesos para Linux, escrito en Rust, orientado a bajo
consumo de CPU/memoria. Corre en polling (sin `tokio`, sin async), lee
`/proc` a mano, y dispara un script bash de auditoria configurable cuando
detecta comportamiento anomalo (CPU sostenida, memoria fuera de rango,
procesos root fuera de whitelist, conexiones de red inesperadas, o procesos
efimeros tipo cryptominer). Opcionalmente notifica todo por Telegram: alerta
inmediata por anomalia, status del servidor cada 12h, y resumen semanal de
auditoria.

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
defecto y corre cada N ciclos cuando se habilita).

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

## Limitaciones conocidas

- La correlacion de red (`network.enabled`) solo cubre IPv4 (`/proc/net/tcp`,
  no `tcp6`) y es deliberadamente costosa (recorre `/proc/<pid>/fd` de todos
  los procesos); usala con un `check_every_n_cycles` alto en servidores con
  muchos procesos/conexiones.
- El nombre de proceso (`comm`) que usa la whitelist de root viene de
  `/proc/<pid>/stat` y esta truncado a 15 caracteres por el kernel; si dos
  binarios distintos comparten un nombre truncado, la whitelist no los
  distingue.
- La deteccion de procesos efimeros depende del intervalo de polling: un
  proceso que vive menos que `poll_interval_secs` puede no llegar a
  observarse en ningun ciclo.
