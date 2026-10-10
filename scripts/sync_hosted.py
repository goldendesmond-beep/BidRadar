"""Authenticated daily import bridge to an existing authorized Python host.

No endpoint is inferred from tender text. No redirect or paid service is used.
Unset configuration yields Not Configured, never a claimed database update.
"""
import io
import json
import os
import pathlib
import sys
import urllib.request
from urllib.parse import urlsplit

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from app import database as db
from app.refresh import NoRedirect

def sync(records,endpoint,token,send=None):
    parsed=urlsplit(endpoint)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None,443) or parsed.path not in ('','/') or parsed.query or parsed.fragment:
        raise ValueError('Configure an HTTPS host origin without a path or credentials')
    db.safe_url(endpoint)
    if len(token)<32:raise ValueError('Strong admin token required')
    send=send or urllib.request.build_opener(NoRedirect()).open
    batches=[];batch=[]
    for record in records:
        size=len(json.dumps({'items':batch+[record]},ensure_ascii=False).encode())
        if size>30000 or len(batch)>=50:
            if batch:batches.append(batch);batch=[]
        if len(json.dumps({'items':[record]},ensure_ascii=False).encode())>30000:raise ValueError('Record exceeds safe import payload limit')
        batch.append(record)
    if batch:batches.append(batch)
    imported=0
    for batch in batches:
        request=urllib.request.Request(endpoint.rstrip('/')+'/api/admin/import',data=json.dumps({'items':batch},ensure_ascii=False).encode(),method='POST',headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
        with send(request,timeout=30) as response:
            result=json.load(response)
            if result.get('imported')!=len(batch):raise RuntimeError('Hosted import acknowledgement mismatch')
            imported+=result['imported']
    return {'status':'imported','records_acknowledged':imported,'batches':len(batches)}

def main():
    endpoint=os.environ.get('BIDPILOT_SYNC_URL','');token=os.environ.get('BIDPILOT_ADMIN_TOKEN','')
    if not endpoint or not token:
        print(json.dumps({'status':'NOT_CONFIGURED','reason':'No authorized persistent host URL/admin credential configured'}));return
    with db.connect() as conn:records=[json.loads(row['data']) for row in conn.execute('SELECT data FROM opportunities')]
    report=sync(records,endpoint,token)
    (db.ROOT/'data/hosted-sync-results.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))

if __name__=='__main__':main()
