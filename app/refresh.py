"""Persisted import and independent, bounded source refresh. No browser required."""
import argparse
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from . import database as db
from . import saudi_sources as sources

LOCK=threading.Lock()
SOURCE_IDS={'ksau-hs':'ksau_hs','rcjy-jazan':'rcjy'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

class EnvironmentFetcher(sources.PublicFetcher):
    """Keep managed proxy/CA settings; never use a direct route around a proxy.

    Fixed host allowlist and manual redirect validation apply in both paths.
    Direct deployments additionally pin validated public DNS through the base client.
    """
    def _request(self,url,hosts):
        proxies=urllib.request.getproxies()
        if not proxies.get('https') and not proxies.get('http'):
            return super()._request(url,hosts)
        url=sources.safe_url(url,hosts)
        host=urlsplit(url).hostname
        elapsed=time.monotonic()-self.last_requests.get(host,0)
        if elapsed<self.interval:time.sleep(min(self.interval-elapsed,30))
        self.last_requests[host]=time.monotonic()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler(proxies),NoRedirect())
        last_error=None
        for attempt in range(self.retries+1):
            req=urllib.request.Request(url,headers={'User-Agent':sources.USER_AGENT,'Accept':'text/html,application/json,text/plain;q=0.8','Accept-Encoding':'identity'})
            try:
                try:response=opener.open(req,timeout=self.timeout)
                except urllib.error.HTTPError as e:response=e
                with response:
                    headers={k.lower():v for k,v in response.headers.items()}
                    if int(headers.get('content-length','0'))>sources.MAX_BYTES:raise sources.FetchError('DEGRADED','response_too_large')
                    body=response.read(sources.MAX_BYTES+1)
                    if len(body)>sources.MAX_BYTES:raise sources.FetchError('DEGRADED','response_too_large')
                    status=response.code
                    if status in (429,500,502,503,504) and attempt<self.retries:
                        retry=headers.get('retry-after','')
                        if retry.isdigit() and int(retry)>4:raise sources.FetchError('DEGRADED','retry_later')
                        time.sleep(2**attempt);continue
                    return status,headers,body
            except (OSError,urllib.error.URLError) as e:
                last_error=e
                if attempt<self.retries:time.sleep(2**attempt)
        raise sources.FetchError('UNAVAILABLE','network_or_proxy_failure') from last_error

def audit(event,target,data):
    with db.connect() as conn:conn.execute('INSERT INTO audit_logs(event,target,occurred_at,data) VALUES(?,?,?,?)',(event,target,db.now(),json.dumps(data,ensure_ascii=False)))

def seed():
    file=db.ROOT/'data'/'seed.json'
    if not file.exists():return {'imported':0}
    digest=hashlib.sha256(file.read_bytes()).hexdigest()
    with db.connect() as conn:
        if conn.execute('SELECT 1 FROM imports WHERE file_hash=?',(digest,)).fetchone():return {'imported':0,'already_imported':True}
    count=0
    for raw in json.loads(file.read_text()):
        existing=db.detail(raw.get('id',''))
        if existing and existing['last_verified']>raw.get('last_verified',raw.get('lastVerifiedAt','')):continue
        db.upsert(raw);count+=1
    for source in json.loads((db.ROOT/'data'/'sources.json').read_text()):
        with db.connect() as conn:exists=conn.execute('SELECT 1 FROM sources WHERE id=?',(source['id'],)).fetchone()
        if not exists:db.set_source(source)
    with db.connect() as conn:conn.execute('INSERT OR IGNORE INTO imports(file_hash,imported_at) VALUES(?,?)',(digest,db.now()))
    db.close_expired();audit('verified_seed_import',digest,{'records':count,'mode':'MANUAL_IMPORT'})
    return {'imported':count,'mode':'MANUAL_IMPORT'}

def refresh(fetcher=None):
    if not LOCK.acquire(blocking=False):return {'status':'already_running'}
    started=db.now();results=[];runid=None
    try:
        db.initialize();seed()
        with db.connect() as conn:runid=conn.execute('INSERT INTO runs(started_at,status,data) VALUES(?,?,?)',(started,'running','{}')).lastrowid
        fetcher=fetcher or EnvironmentFetcher(timeout=10,interval=2,retries=1)
        existing_sources={s['id']:s for s in db.get_sources()}
        for source in sources.SOURCES:
            sid=SOURCE_IDS.get(source.id,source.id)
            with db.connect() as conn:
                existing_rows=conn.execute("SELECT data FROM opportunities WHERE source_id=? ORDER BY CASE WHEN status IN ('open','unknown') THEN 0 ELSE 1 END,deadline",(sid,)).fetchall()
            existing_records=[json.loads(row['data']) for row in existing_rows]
            known_urls=list(dict.fromkeys(record['source_url'] for record in existing_records))[:40]
            try:
                result=sources.probe(source,fetcher,known_urls=known_urls)
                records=result.get('records',[])
                actual=0
                for record in records:
                    record['source_id']=sid
                    # Do not discard richer previously verified metadata when a list is shallow.
                    found=None
                    if record.get('reference'):
                        with db.connect() as conn:
                            found=conn.execute('SELECT data FROM opportunities WHERE source_id=? AND json_extract(data,\'$.reference\')=?',(sid,record['reference'])).fetchone()
                    if found:
                        old=json.loads(found['data']);record={**old,**{k:v for k,v in record.items() if v not in (None,[], '')}}
                    record['verification_status']='verified'
                    record['verification_error']=None
                    db.verification_success(record,result.get('last_checked'));actual+=1
                for failure in result.get('verification_failures',[]):
                    db.verification_failure(sid,failure['source_url'],failure.get('reason'),failure.get('last_checked'))
                prior=existing_sources.get(sid,{})
                status=result.get('status','UNAVAILABLE')
                if status=='LIVE' and not actual:status='DEGRADED'
                report={**prior,'id':sid,'name':source.name,'url':source.url,'status':status,'last_attempt':db.now(),
                  'last_success':db.now() if actual else prior.get('last_success'),'automatic_runtime_verified':bool(actual),
                  'notes':result.get('reason') or result.get('message') or ('استخراج آلي ناجح.' if actual else 'لم يستخرج الموصل بيانات في هذه المحاولة.'),'records_extracted':actual}
                report['listing_status']=result.get('listing_status',status)
                report['verification_failures']=len(result.get('verification_failures',[]))
                db.set_source(report)
                if status!='LIVE':
                    with db.connect() as conn:conn.execute('INSERT INTO error_logs(source_id,run_id,occurred_at,message) VALUES(?,?,?,?)',(sid,runid,db.now(),report['notes']))
                results.append(report)
            except Exception as e:
                # No sensitive response bodies or credentials in error logs.
                report={**existing_sources.get(sid,{}),'id':sid,'name':source.name,'url':source.url,'status':'UNAVAILABLE','last_attempt':db.now(),'notes':type(e).__name__,'automatic_runtime_verified':False,'records_extracted':0}
                for record in existing_records:db.verification_failure(sid,record['source_url'],type(e).__name__,report['last_attempt'])
                db.set_source(report);results.append(report)
                with db.connect() as conn:conn.execute('INSERT INTO error_logs(source_id,run_id,occurred_at,message) VALUES(?,?,?,?)',(sid,runid,db.now(),type(e).__name__))
        closed=db.close_expired()
        status='success' if any(r['status']=='LIVE' for r in results) else 'degraded'
        output={'status':status,'started_at':started,'finished_at':db.now(),'closed':closed,'sources':results,'zero_cost_only':True}
        with db.connect() as conn:conn.execute('UPDATE runs SET finished_at=?,status=?,data=? WHERE id=?',(db.now(),status,json.dumps(output,ensure_ascii=False),runid))
        audit('source_refresh',str(runid),{'status':status,'closed':closed})
        return output
    finally:LOCK.release()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--seed-only',action='store_true');parser.add_argument('--import-json')
    args=parser.parse_args();db.initialize()
    if args.import_json:
        # CLI-only trusted local path; never exposed as arbitrary file upload/URL fetch.
        raw=json.load(open(args.import_json));records=raw if isinstance(raw,list) else raw['items']
        result={'imported':len([db.upsert(r) for r in records]),'mode':'MANUAL_IMPORT'};audit('manual_import','CLI',result)
    else:result=seed() if args.seed_only else refresh()
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
