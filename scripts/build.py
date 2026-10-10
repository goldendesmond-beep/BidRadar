"""Production package, dependency-free. No network or payment required."""
import ast
import hashlib
import json
import pathlib
import shutil
import subprocess
import zipfile

root=pathlib.Path(__file__).resolve().parent.parent
for file in (root/'app').glob('*.py'):ast.parse(file.read_text(),filename=str(file))
for file in (root/'public').glob('*.js'):subprocess.run(['node','--check',str(file)],check=True)
records=json.loads((root/'data/seed.json').read_text())
assert len(records)==len({r['id'] for r in records})
assert all(r.get('source_url') or r.get('sourceUrl') for r in records)
output=root/'dist';output.mkdir(exist_ok=True)
paths=[]
for directory in ['app','public','data','scripts','docs','vendor','tests','.github']:
 for path in (root/directory).rglob('*'):
  if path.is_file() and not any(x in path.parts for x in ['__pycache__','test-results','backups']) and not any(x in path.name for x in ['.sqlite','.pyc']):paths.append(path)
paths += [p for p in root.iterdir() if p.is_file() and p.name not in ['.env','.gitignore']]
with zipfile.ZipFile(output/'saudi-bidpilot-production.zip','w',zipfile.ZIP_DEFLATED) as z:
 for path in paths:z.write(path,'saudi-bidpilot/'+str(path.relative_to(root)))
manifest={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
(output/'BUILD_MANIFEST.json').write_text(json.dumps(manifest,indent=2))
print('Production package built:',output/'saudi-bidpilot-production.zip')
print('Files:',len(paths),'Verified records:',len(records))
