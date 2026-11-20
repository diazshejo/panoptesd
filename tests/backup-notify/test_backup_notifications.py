import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


notify = module('notify-backup')
runner = module('run-backup-notified')


class BackupNotifications(unittest.TestCase):
    def test_outcomes_and_test_do_not_claim_a_backup_was_run(self):
        self.assertIn('completado', notify.message_for('weekly', 'success', 't'))
        for result in ['exit-code', 'signal', 'timeout', 'unknown', '']:
            self.assertIn('falló', notify.message_for('weekly', result, 't'))
        self.assertIn('verificaron', notify.message_for('manual-success', '', 't'))
        self.assertIn('falló', notify.message_for('manual-failure', '', 't'))
        self.assertIn('no ejecutó ningún backup', notify.message_for('test', '', 't'))
        with self.assertRaises(ValueError):
            notify.message_for('arbitrary-message', '', 't')

    def test_disabled_or_missing_credentials_is_not_a_success(self):
        with patch.object(Path, 'read_text', return_value='[telegram]\nenabled=false'), \
             patch.object(notify.subprocess, 'run') as run:
            self.assertEqual(notify.notify('test'), 1)
            run.assert_not_called()
        with patch.object(Path, 'read_text', return_value='[telegram]\nenabled=true'), \
             patch.dict(notify.os.environ, {}, clear=True), \
             patch.object(notify.subprocess, 'run') as run:
            self.assertEqual(notify.notify('test'), 1)
            run.assert_not_called()

    def test_transport_retries_and_confirms_only_success(self):
        with patch.object(Path, 'read_text', return_value='[telegram]\nenabled=true'), \
             patch.dict(notify.os.environ, {'TELEGRAM_BOT_TOKEN': 'dummy', 'TELEGRAM_CHAT_ID': 'dummy'}), \
             patch.object(notify.time, 'sleep'), \
             patch.object(notify.subprocess, 'run') as run:
            run.side_effect = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
            self.assertEqual(notify.notify('test'), 0)
            self.assertEqual(run.call_count, 2)
            run.reset_mock(side_effect=True)
            run.return_value = subprocess.CompletedProcess([], 1)
            self.assertEqual(notify.notify('test'), 1)
            self.assertEqual(run.call_count, 3)

    def test_backup_result_is_preserved_if_notification_fails(self):
        for code in [0, 7, -15]:
            with patch.object(runner.subprocess, 'run') as run:
                run.side_effect = [subprocess.CompletedProcess([], code), subprocess.CompletedProcess([], 1)]
                self.assertEqual(runner.run_backup(['backup']), code if code >= 0 else 143)
                expected = 'manual-success' if code == 0 else 'manual-failure'
                self.assertEqual(run.call_args_list[1].args[0][-1], f'panoptesd-backup-notify@{expected}.service')

    def test_failed_start_sends_failure_notice(self):
        with patch.object(runner.subprocess, 'run') as run:
            run.side_effect = [FileNotFoundError(), subprocess.CompletedProcess([], 0)]
            self.assertEqual(runner.run_backup(['missing']), 1)
            self.assertIn('manual-failure', run.call_args_list[1].args[0][-1])


if __name__ == '__main__':
    unittest.main()
