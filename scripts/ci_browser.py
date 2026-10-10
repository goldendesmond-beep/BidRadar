"""CI browser runner: actual HTTP, temporary persistent DB, real seed data.

Writes fresh evidence even if the backend never reaches readiness. Browser
results remain Not Run when startup fails; stale delivered reports cannot stand
in for the CI run.
"""
from datetime import datetime, timezone
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright

root = pathlib.Path(__file__).resolve().parent.parent
report_path = root / 'tests' / 'ci-e2e-results.json'
log_path = root / 'tests' / 'browser-runtime-output.txt'


def main():
    # Delete only the CI-specific report. Imported historic evidence is retained.
    report_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix='bidpilot-ci-') as folder, log_path.open('w') as log:
        env = {**os.environ, 'BIDPILOT_HOST': '127.0.0.1', 'BIDPILOT_PORT': '8080',
               'BIDPILOT_DB': str(pathlib.Path(folder) / 'bidpilot.sqlite3'),
               'BIDPILOT_SCHEDULER': 'false'}
        proc = None
        try:
            with sync_playwright() as p:
                env['CHROMIUM_PATH'] = p.chromium.executable_path
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            proc = subprocess.Popen([sys.executable, '-m', 'app.server'], cwd=root, env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
            ready = False
            for _ in range(80):
                try:
                    with opener.open('http://localhost:8080/api/summary', timeout=1) as response:
                        result = json.load(response)
                    if result['tenders'] > 0:
                        ready = True
                        break
                except (OSError, ValueError):
                    pass
                if proc.poll() is not None:
                    break
                time.sleep(.25)
            if not ready:
                raise RuntimeError('Real HTTP backend did not initialize persisted procurement data')
            result = subprocess.run([sys.executable, 'tests/e2e.py', '--url', 'http://localhost:8080',
                                     '--output', str(report_path)], cwd=root, env=env)
            return result.returncode
        except Exception as exc:
            report = {'mode': 'local-HTTP-integration', 'base_url': 'http://localhost:8080',
                      'executed_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                      'results': [{'test': 'CI backend initialization', 'status': 'Failed',
                                   'reason': str(exc)[:1500]},
                                  {'test': 'Playwright browser integration', 'status': 'Not Run',
                                   'reason': 'Backend or browser dependency initialization failed; see runtime log.'}],
                      'summary': {'Passed': 0, 'Failed': 1, 'Not Run': 1}}
            report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
            print('CI initialization failed:', str(exc), flush=True)
            return 1
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == '__main__':
    sys.exit(main())
