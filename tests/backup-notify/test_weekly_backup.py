import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'backup-notify' / 'backup-mysql.sh'


class WeeklyBackup(unittest.TestCase):
    def execute(self, failure):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        binaries = root / 'bin'
        binaries.mkdir()
        backup = root / 'backup'
        backup.mkdir()
        old = backup / 'dropsmart_old.sql.gz'
        old.write_text('older-backup')
        scripts = {
            'mysqldump': '#!/bin/sh\necho partial-or-complete-dump\n[ "$FAIL_AT" != dump ]\n',
            'mysql': '''#!/bin/sh
case "$*" in
 *SELECT*) [ "$FAIL_AT" = accounts ] && exit 1; [ "$FAIL_AT" = noaccounts ] || echo '172.18.%' ;;
 *GRANTS*) [ "$FAIL_AT" = grants ] && exit 1; echo 'GRANT SELECT ON dropsmart.* TO account;' ;;
esac
exit 0
''',
            'find': '#!/bin/sh\necho retention >> "$RETENTION_LOG"\n',
        }
        for name, text in scripts.items():
            path = binaries / name
            path.write_text(text)
            path.chmod(0o755)
        env = dict(os.environ, PATH=str(binaries) + ':' + os.environ['PATH'],
                   BACKUP_MYSQL_DIR=str(backup), FAIL_AT=failure,
                   RETENTION_LOG=str(root / 'retention.log'))
        result = subprocess.run(['bash', str(SCRIPT)], env=env, capture_output=True, text=True)
        return root, backup, old, result

    def test_success_publishes_verified_files_and_runs_retention(self):
        root, backup, old, result = self.execute('')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('completado', result.stdout)
        self.assertEqual(len(list(backup.glob('*.gz'))), 2)
        self.assertEqual(len(list(backup.glob('*grants*'))), 1)
        self.assertTrue((root / 'retention.log').exists())
        self.assertFalse(list(backup.glob('.*')))

    def test_failures_do_not_announce_success_or_prune_existing_backups(self):
        for failure in ['dump', 'accounts', 'grants', 'noaccounts']:
            with self.subTest(failure=failure):
                root, backup, old, result = self.execute(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('completado', result.stdout)
                self.assertEqual(list(backup.iterdir()), [old])
                self.assertEqual(old.read_text(), 'older-backup')
                self.assertFalse((root / 'retention.log').exists())


if __name__ == '__main__':
    unittest.main()
