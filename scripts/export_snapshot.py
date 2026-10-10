"""Export collected records to a portable JSON artifact (no private profiles)."""
import json
import pathlib
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from app import database as db
with db.connect() as conn:records=[json.loads(r['data']) for r in conn.execute('SELECT data FROM opportunities')]
(db.ROOT/'data'/'collected-records.json').write_text(json.dumps(records,ensure_ascii=False,indent=2))
print('Exported',len(records),'records; company sessions and saved items excluded.')
