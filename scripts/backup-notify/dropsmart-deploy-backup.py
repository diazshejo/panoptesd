#!/usr/bin/env python3
"""Lanzador instalado en dropsmart-release-20261119/backup.py."""
import os
import sys

os.execv(
    "/usr/bin/python3",
    [
        "/usr/bin/python3",
        "/opt/panoptesd/scripts/run-backup-notified.py",
        "/usr/bin/python3",
        "/home/deploy/dropsmart-release-20261119/backup_original_20261119.py",
        *sys.argv[1:],
    ],
)
