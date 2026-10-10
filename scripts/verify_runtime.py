"""Run the local HTTP/browser checks and read connected GitHub identity.

Requires supported sandbox network permission for localhost and Chromium IPC.
Never prints credentials or publishes to a host.
"""
import json
import os
import pathlib
import subprocess
import sys
import time
import tempfile
import sqlite3
import urllib.error
import urllib.request

root=pathlib.Path(__file__).resolve().parent.parent
output=root/'tests'/'runtime-results.json'
report={}
env={**os.environ,'BIDPILOT_HOST':'127.0.0.1','BIDPILOT_PORT':'8080','BIDPILOT_SCHEDULER':'false'}
server=None
temp=tempfile.TemporaryDirectory(prefix='bidpilot-http-')
sys.path.insert(0,str(root))
from app import database as db
if db.DB_PATH.exists():
 with sqlite3.connect(str(db.DB_PATH)) as source, sqlite3.connect(str(pathlib.Path(temp.name)/'bidpilot.sqlite3')) as dest:source.backup(dest)
env['BIDPILOT_DB']=str(pathlib.Path(temp.name)/'bidpilot.sqlite3')
try:
 server=subprocess.Popen([sys.executable,'-m','app.server'],cwd=root,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 # Only localhost test traffic avoids the outbound proxy; external tools preserve it.
 for _ in range(40):
  try:
   with opener.open('http://localhost:8080/api/summary',timeout=1) as response:summary=json.load(response)
   report['http_server']={'status':'Passed','summary':summary};break
  except (OSError,urllib.error.URLError):
   if server.poll() is not None:break
   time.sleep(.25)
 else:report['http_server']={'status':'Failed','reason':'Local HTTP server did not become available'}
 if 'http_server' not in report:report['http_server']={'status':'Failed','reason':'Local server process exited'}
 if report['http_server']['status']=='Passed':
  browser=subprocess.run([sys.executable,'tests/e2e.py','--url','http://localhost:8080'],cwd=root,env=env,capture_output=True,text=True,timeout=180)
  (root/'tests'/'browser-runtime-output.txt').write_text(browser.stdout+'\n'+browser.stderr)
  report['browser']={'exit_code':browser.returncode,'status':'Passed' if browser.returncode==0 else 'Not Run' if browser.returncode==2 else 'Failed'}
except Exception as e:
 report['http_server']={'status':'Failed','reason':type(e).__name__+': '+str(e)[:250]}
finally:
 if server:
  server.terminate()
  try:server.wait(timeout=5)
  except subprocess.TimeoutExpired:server.kill();server.wait()
 temp.cleanup()
try:
 result=subprocess.run(['gh','api','user','--jq','{login: .login, name: .name}'],cwd=root,capture_output=True,text=True,timeout=25)
 report['github']={'status':'Connected' if result.returncode==0 else 'Unavailable','result':result.stdout.strip() if result.returncode==0 else result.stderr.strip()[:800]}
 if result.returncode==0:
  repos=subprocess.run(['gh','repo','list','--limit','100','--json','name,description,url,isPrivate'],cwd=root,capture_output=True,text=True,timeout=25)
  report['github_repositories']=json.loads(repos.stdout) if repos.returncode==0 else {'error':repos.stderr[:500]}
except Exception as e:report['github']={'status':'Unavailable','reason':type(e).__name__}
output.write_text(json.dumps(report,ensure_ascii=False,indent=2))
print(json.dumps(report,ensure_ascii=False,indent=2))
