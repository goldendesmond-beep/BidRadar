"""Recheck identity/deadlines against preserved official HTML; no network claim."""
import json
import pathlib
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from app import database as db, saudi_sources as sources

def main():
 seed=json.loads((db.ROOT/'data/seed.json').read_text());matches={}
 for file in (db.ROOT/'data/verification').glob('*.json'):
  for sid in ['etimad','ksau-hs','geosa','taqeem']:
   try:
    result=sources.import_tinyfish_snapshot(str(file),'2026-10-09T13:21:00+00:00',sid)
    for record in result['records']:
     if record.get('reference'):matches.setdefault(str(record['reference']),[]).append({'file':file.name,'record':record})
   except (TypeError,ValueError,KeyError):continue
 checked=[];missing=[];mismatch=[]
 for record in seed:
  if record.get('kind') not in ['tender','rfp','rfq','qualification']:continue
  candidates=matches.get(str(record.get('reference')),[])
  if not candidates:missing.append({'id':record['id'],'source_id':record['source_id'],'reference':record.get('reference'),'status':record['status']});continue
  valid=[x for x in candidates if str(x['record'].get('deadline') or '')[:10]==str(record.get('deadline') or '')[:10]]
  if not valid:mismatch.append({'id':record['id'],'deadline':record.get('deadline'),'parsed':[x['record'].get('deadline') for x in candidates]});continue
  checked.append({'id':record['id'],'reference':record.get('reference'),'deadline':record.get('deadline'),'status':record['status'],'snapshot':valid[0]['file'],'organization_parsed':valid[0]['record'].get('organization')})
 report={'verified_from_saved_original_HTML':len(checked),'active_verified':sum(r['status']=='open' for r in checked),'missing_parser_support':missing,'deadline_mismatches':mismatch,'checks':checked,'scope':'Stored official snapshots; no fresh network request'}
 (db.ROOT/'data/revalidation-evidence.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
 print(json.dumps({k:v for k,v in report.items() if k!='checks'},ensure_ascii=False,indent=2))
 active={r['id'] for r in seed if r.get('kind') in ['tender','rfp','rfq','qualification'] and r.get('status')=='open'}
 assert active <= {r['id'] for r in checked},'An active record could not be revalidated against its original snapshot'

if __name__=='__main__':main()
