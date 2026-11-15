"""Actual Bash boundary test with all external mutations replaced by functions."""
import os
from pathlib import Path
import subprocess
import unittest


@unittest.skipIf(os.name == 'nt', 'Bash execution is covered by Linux CI')
class ResumeNamespace(unittest.TestCase):
    def test_inherited_project_and_context_cannot_select_another_runtime(self):
        script = Path(__file__).resolve().parents[1] / 'experiments/server/resume-runtime.sh'
        # Validate the Python binding separately. Here stop at the first Docker
        # call and record its real shell argument expansion and environment.
        driver = '''
python3() { printf '%s\\n' santa-zentral-eval-aaaaaaaaaaaa; }
mkdir() { return 0; }
sysctl() { printf '%s\\n' 1048576; }
docker() {
    printf 'DOCKER_CAPTURE'; printf ' <%s>' "$@"; printf '\\n'
    if test -z "${COMPOSE_PROJECT_NAME-}${COMPOSE_FILE-}${DOCKER_CONTEXT-}${DOCKER_HOST-}"; then
        echo OVERRIDES_CLEARED
    fi
    exit 91
}
source "$1" namespace-check chosen.json fixture.json sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
'''
        env = dict(os.environ, COMPOSE_PROJECT_NAME='unexpected-project', COMPOSE_FILE='wrong.json',
                   DOCKER_CONTEXT='wrong-context', DOCKER_HOST='tcp://127.0.0.1:1')
        result = subprocess.run(['bash', '-c', driver, 'test', str(script)], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 91, result.stderr)
        self.assertIn('OVERRIDES_CLEARED', result.stdout)
        self.assertIn('<--project-name> <santa-zentral-eval-aaaaaaaaaaaa>', result.stdout)
        self.assertIn('<--host> <unix:///var/run/docker.sock>', result.stdout)
        self.assertNotIn('unexpected-project', result.stdout)


if __name__ == '__main__':
    unittest.main()
