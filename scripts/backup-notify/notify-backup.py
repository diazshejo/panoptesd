#!/usr/bin/env python3
"""Notifica resultados de backups; credenciales solo en el entorno de systemd."""
import datetime
import os
from pathlib import Path
import subprocess
import sys
import time
import tomllib

CONFIG = Path('/etc/panoptesd/config.toml')
BINARY = '/opt/panoptesd/panoptesd'


def message_for(mode, result, timestamp):
    if mode == 'test':
        return ('🧪 Prueba de avisos de backups\n'
                'El canal de notificaciones funciona. Esta prueba no ejecutó ningún backup.\n'
                f'Hora: {timestamp}')
    if mode == 'weekly':
        name = 'Backup semanal de MySQL'
        success = result == 'success'
    elif mode in ('manual-success', 'manual-failure'):
        name = 'Backup del despliegue de Dropsmart'
        success = mode == 'manual-success'
    else:
        raise ValueError('Modo de notificación desconocido')
    if success:
        detail = ('La tarea terminó sin errores.' if mode == 'weekly' else
                  'Se verificaron el volcado de la base de datos y el archivo de uploads.')
        return f'✅ {name} completado\n{detail}\nHora: {timestamp}'
    return (f'🚨 {name} falló\n'
            'No des por válido este respaldo. Revisa los registros de la tarea antes de reintentarlo.\n'
            f'Hora: {timestamp}')


def notify(mode):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    try:
        message = message_for(mode, os.environ.get('SERVICE_RESULT', 'unknown'), stamp)
        config = tomllib.loads(CONFIG.read_text())
    except (OSError, ValueError):
        print('No se pudo preparar el aviso de backup: modo o configuración inválidos.', file=sys.stderr)
        return 1
    if not config.get('telegram', {}).get('enabled', False):
        print('Aviso de backup no enviado: Telegram está deshabilitado.', file=sys.stderr)
        return 1
    if not all(os.environ.get(key) for key in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID')):
        print('Aviso de backup no enviado: faltan credenciales en el servicio.', file=sys.stderr)
        return 1
    timeout = min(30, max(1, int(config['telegram'].get('request_timeout_secs', 5))) + 5)
    for attempt in range(1, 4):
        try:
            sent = subprocess.run([BINARY, '--config', str(CONFIG), '--send-telegram', message],
                                  capture_output=True, timeout=timeout, check=False)
            if sent.returncode == 0:
                print(f'Aviso de backup confirmado: {mode}.')
                return 0
        except (OSError, subprocess.TimeoutExpired):
            pass
        # No imprimir entorno, argumentos ni salida de herramientas externas.
        print(f'Falló el envío del aviso de backup (intento {attempt}/3).', file=sys.stderr)
        if attempt < 3:
            time.sleep(attempt)
    return 1


if __name__ == '__main__':
    sys.exit(notify(sys.argv[1] if len(sys.argv) == 2 else 'invalid'))
