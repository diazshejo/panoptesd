#!/usr/bin/env python3
"""Ejecuta un backup como el usuario actual y notifica mediante una unit fija."""
import subprocess
import sys


def run_backup(command):
    try:
        outcome = subprocess.run(command, check=False)
        code = outcome.returncode
    except OSError:
        print('No se pudo iniciar el backup.', file=sys.stderr)
        code = 1
    except KeyboardInterrupt:
        code = 130
    mode = 'manual-success' if code == 0 else 'manual-failure'
    try:
        notice = subprocess.run(['sudo', '-n', '/usr/bin/systemctl', 'start',
                                 f'panoptesd-backup-notify@{mode}.service'],
                                check=False, timeout=130)
        delivered = notice.returncode == 0
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
        delivered = False
    if not delivered:
        print('El aviso de Telegram falló. El resultado del backup se conserva; '
              'revisar journalctl -u panoptesd-backup-notify@' + mode + '.service.',
              file=sys.stderr)
    return code if code >= 0 else 128 - code


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('Uso: run-backup-notified.py COMANDO [ARGUMENTOS...]')
    sys.exit(run_backup(sys.argv[1:]))
