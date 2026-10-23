"""Run TV scripts only after mapping all mutable paths into temporary fixtures."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        for name in ('var/luna/preferences', 'var/lib', 'tmp', 'etc', 'home/root', 'proc'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        TEST_ROOT=str(self.root), TEST_LOG=str(self.root / 'events'))
        self.stub('id', 'echo 0')
        self.stub('systemctl', 'echo restart >> "$TEST_LOG"')
        self.env.update(TEST_APPS=json.dumps({'returnValue': True, 'apps': []}),
                        TEST_INSTALL=json.dumps({'statusValue': 30, 'details': {'packageId': 'org.webosbrew.hbchannel'}}),
                        TEST_ROOT_RESULT=json.dumps({'returnValue': True}))
        self.stub('luna-send', '''
case "$*" in
  *listApps*) printf '%s\\n' "$TEST_APPS" ;;
  *dev/install*) echo install >> "$TEST_LOG"; printf '%s\\n' "$TEST_INSTALL" ;;
  *checkRoot*) echo check-root >> "$TEST_LOG"; printf '%s\\n' "$TEST_ROOT_RESULT" ;;
esac
''')
        for name in ('luna-helper.js', 'hbchannel-startup.sh'):
            (self.stage / name).write_bytes((ROOT / 'wwwroot' / name).read_bytes())
        (self.stage / 'hbchannel.ipk').write_bytes(b'inert test package')
        source = (ROOT / 'wwwroot/autoroot.sh').read_text()
        source = source.replace('d10bf3c753551d7c72fb7a92b20fcd2317e502a220ac668ba8e76f6ea78b363c',
                                hashlib.sha256(b'inert test package').hexdigest())
        self.script = self.stage / 'autoroot.sh'
        self.script.write_text(self.map_paths(source))
        service = self.root / 'media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service'
        service.mkdir(parents=True)
        elevation = service / 'elevate-service'
        elevation.write_text('''#!/bin/bash
test -f "$TEST_ROOT/var/luna/preferences/webosbrew_telnet_disabled" || exit 9
test ! -e "$TEST_ROOT/var/luna/preferences/webosbrew_sshd_enabled" || exit 10
! grep -q telnetd "$TEST_ROOT/var/lib/webosbrew/startup.sh" || exit 11
echo elevate >> "$TEST_LOG"
''')
        elevation.chmod(0o755)

    def map_paths(self, source):
        return re.sub(r'(?<![A-Za-z0-9_.-])/(?:var|tmp|media|home|etc|proc|usr)/', lambda match: str(self.root) + match[0], source)

    def stub(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o755)

    def run_installer(self):
        return subprocess.run(['bash', str(self.script)], env=self.env, capture_output=True, text=True, timeout=12)

    def events(self):
        path = self.root / 'events'
        return path.read_text().splitlines() if path.exists() else []

    def test_success_predeploys_policy_and_checks_current_root(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), ['restart', 'install', 'elevate', 'check-root'])
        state = json.loads((self.stage / 'install-state.json').read_text())
        self.assertTrue(state['success'])
        self.assertTrue(state['root_verified'])
        self.assertFalse(state['reboot_verified'])
        self.assertFalse((self.root / 'tmp/slopbro-autoroot.lockdir').exists())

    def test_tampered_package_does_not_change_persistent_state(self):
        (self.stage / 'hbchannel.ipk').write_bytes(b'tampered')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA-256 mismatch', result.stderr)
        self.assertFalse((self.root / 'var/lib/webosbrew').exists())
        self.assertEqual(self.events(), [])

    def test_developer_mode_or_unknown_app_state_stops_before_writes(self):
        for value in ({'returnValue': True, 'apps': [{'id': 'com.palmdts.devmode'}]},
                      {'returnValue': True}, {'returnValue': False}):
            with self.subTest(value=value):
                self.env['TEST_APPS'] = json.dumps(value)
                self.assertNotEqual(self.run_installer().returncode, 0)
                self.assertFalse((self.root / 'var/lib/webosbrew').exists())
                self.assertEqual(self.events(), [])

    def test_custom_startup_is_not_overwritten(self):
        startup = self.root / 'var/lib/webosbrew/startup.sh'
        startup.parent.mkdir()
        startup.write_text('custom startup')
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(startup.read_text(), 'custom startup')
        self.assertEqual(self.events(), [])

    def test_unsigned_devmode_script_is_rejected_before_persistent_writes(self):
        script = self.root / 'media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service/start-devmode.sh'
        script.parent.mkdir(parents=True)
        script.write_text('untrusted script')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'var/lib/webosbrew').exists())
        self.assertEqual(script.read_text(), 'untrusted script')

    def test_install_failure_does_not_elevate_or_report_success(self):
        self.env['TEST_INSTALL'] = json.dumps({'returnValue': False, 'errorText': 'package not installed'})
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), ['restart', 'install'])
        state = json.loads((self.stage / 'install-state.json').read_text())
        self.assertFalse(state['success'])
        self.assertEqual(state['phase'], 'installing')
        self.assertTrue((self.root / 'var/luna/preferences/webosbrew_telnet_disabled').exists())

    def test_failed_root_check_is_not_success(self):
        self.env['TEST_ROOT_RESULT'] = '{"returnValue":false}'
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertFalse(json.loads((self.stage / 'install-state.json').read_text())['success'])

    def test_marker_is_restored_if_preinstall_mkdir_fails(self):
        marker = self.root / 'var/luna/preferences/devmode_enabled'
        marker.write_text('original marker')
        self.stub('mkdir', '''
for arg in "$@"; do
  if [[ "$arg" == "$TEST_ROOT/var/luna/preferences/devmode_enabled" ]]; then exit 1; fi
done
exec /bin/mkdir "$@"
''')
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(marker.read_text(), 'original marker')
        self.assertNotIn('install', self.events())

    def test_normal_and_failsafe_startup_never_start_telnet(self):
        for command in ('mount', 'chattr', 'run-parts', 'sleep', 'sync', 'chown'):
            self.stub(command, 'echo "' + command + ' $*" >> "$TEST_LOG"')
        self.stub('ls', 'printf "0\\n1\\n2\\n200\\n"')
        service = self.root / 'service'
        (service / 'bin').mkdir(parents=True)
        dropbear = service / 'bin/dropbear'
        dropbear.write_text('#!/bin/bash\necho "SSH $*" >> "$TEST_LOG"\n')
        dropbear.chmod(0o755)
        self.env.update(SERVICE_DIR=str(service), SKIP_ELEVATION='1')
        script = self.root / 'startup.sh'
        script.write_text(self.map_paths((ROOT / 'wwwroot/hbchannel-startup.sh').read_text()))
        prefs = self.root / 'var/luna/preferences'
        keys = self.root / 'home/root/.ssh/authorized_keys'
        keys.parent.mkdir()
        for failsafe in (False, True):
            for enabled, key_present in ((False, False), (True, False), (True, True)):
                with self.subTest(failsafe=failsafe, enabled=enabled, key_present=key_present):
                    for name in ('tmp/webosbrew_startup', 'events', 'var/luna/preferences/webosbrew_failsafe',
                                 'var/luna/preferences/webosbrew_sshd_enabled'):
                        (self.root / name).unlink(missing_ok=True)
                    if failsafe: (prefs / 'webosbrew_failsafe').touch()
                    if enabled: (prefs / 'webosbrew_sshd_enabled').touch()
                    keys.write_text('ssh-ed25519 inert-test-key' if key_present else '')
                    result = subprocess.run(['bash', str(script)], env=self.env, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    ssh = [entry for entry in self.events() if entry.startswith('SSH ')]
                    self.assertEqual(ssh, ['SSH -R -s'] if enabled and key_present else [])
                    self.assertFalse((self.root / 'etc/shadow').exists())
        self.assertNotIn('telnetd', script.read_text())


if __name__ == '__main__':
    unittest.main()
