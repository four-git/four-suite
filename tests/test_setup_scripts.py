from pathlib import Path
import os
import shutil
import subprocess
import unittest
import tempfile


ROOT = Path(__file__).parents[1]
BASH = shutil.which('bash')
if not BASH and Path('C:/Program Files/Git/bin/bash.exe').exists():
    BASH = 'C:/Program Files/Git/bin/bash.exe'


@unittest.skipUnless(BASH, 'Bash is required')
class SetupScriptTests(unittest.TestCase):
    def test_bash_syntax(self):
        for name in ('pre-req.sh', 'install-suite.sh'):
            with self.subTest(name=name):
                subprocess.run([BASH, '-n', 'scripts/' + name], cwd=ROOT, check=True)

    def test_prerequisite_help_needs_no_root_or_host_changes(self):
        result = subprocess.run([BASH, 'scripts/pre-req.sh', '--help'], cwd=ROOT,
                                capture_output=True, text=True, check=True)
        self.assertIn('--migrate-native', result.stdout)
        self.assertIn('--mount', result.stdout)

    def test_unknown_option_fails_before_any_host_changes(self):
        result = subprocess.run([BASH, 'scripts/pre-req.sh', '--invalid'], cwd=ROOT,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Unknown option', result.stderr)

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0,
                         'Host dry-run harness requires Linux root')
    def test_prerequisite_dry_run_skips_mutations_and_downloads(self):
        # Substitute inventory commands; mutating commands fail if the dry-run invokes them.
        harness = r'''
source() { ID=debian; VERSION_ID=13; }
uname() { echo aarch64; }
dpkg() { echo arm64; }
getent() { return 1; }
dpkg-query() { return 1; }
pgrep() { return 1; }
findmnt() { return 1; }
command() { if [[ $* == '-v docker' ]]; then return 1; fi; builtin command "$@"; }
grep() { if [[ $* == *download.docker.com* ]]; then return 1; fi; /usr/bin/grep "$@"; }
systemctl() { if [[ $1 == cat ]]; then return 0; fi; return 1; }
for name in apt-get curl install chmod chown groupadd useradd cp; do
  eval "$name() { echo 'MUTATION CALLED' >&2; return 99; }"
  export -f "$name"
done
export -f source uname dpkg getent dpkg-query pgrep findmnt command grep systemctl
bash scripts/pre-req.sh --dry-run --migrate-native
'''
        # Do not let the real Pi's still-existing legacy config affect this
        # simulated fresh-host inventory. Change only that path in a temp copy.
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory)
            (fixture_root / 'scripts').mkdir()
            script = (ROOT / 'scripts/pre-req.sh').read_text().replace(
                '/etc/four-securitycenter', str(fixture_root / 'absent-legacy-config'))
            (fixture_root / 'scripts/pre-req.sh').write_text(script)
            result = subprocess.run([BASH, '-c', harness], cwd=fixture_root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('MUTATION CALLED', result.stderr)
        self.assertIn('docker-ce', result.stdout)
        self.assertIn('groupadd', result.stdout)
        self.assertIn('Native snapshot', result.stdout)


if __name__ == '__main__':
    unittest.main()
