"""WSGI HTTP API and static frontend, using Python standard library only."""
import hashlib
import hmac
import io
import json
import logging
import mimetypes
import os
import secrets
import threading
import time
import zipfile
from collections import defaultdict, deque
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server, WSGIServer, WSGIRequestHandler
from socketserver import ThreadingMixIn
from xml.sax.saxutils import escape
from . import database as db
from .intelligence import SECTORS, engines

PUBLIC = db.ROOT / 'public'
LOG = logging.getLogger('bidpilot')
RATE_LOCK = threading.Lock()
RATE = defaultdict(deque)
ADMIN_TOKEN = os.environ.get('BIDPILOT_ADMIN_TOKEN','')
ALLOWED_HOSTS = set(os.environ.get('BIDPILOT_ALLOWED_HOSTS','localhost,127.0.0.1').split(','))
SECURE_COOKIE = os.environ.get('BIDPILOT_SECURE_COOKIE','false').lower() == 'true'
COOKIE = 'bidpilot_session'
MAX_BODY = 32768
CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

def xlsx(records):
    fields=['title','organization','kind','city','status','published_at','deadline','reference','source_url','apply_url','registration_url','last_verified','confidence']
    def row(values,n):
        cells=[]
        for i,value in enumerate(values):
            column='';x=i+1
            while x: x,m=divmod(x-1,26);column=chr(65+m)+column
            # Inline strings cannot become formulas, even when beginning with '='.
            clean=''.join(c for c in str(value or '') if ord(c)>=32 or c in '\t\n\r')
            cells.append(f'<c r="{column}{n}" t="inlineStr"><is><t xml:space="preserve">{escape(clean)}</t></is></c>')
        return f'<row r="{n}">'+''.join(cells)+'</row>'
    sheet='<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'+row(fields,1)+''.join(row([r.get(f) for f in fields],i+2) for i,r in enumerate(records))+'</sheetData></worksheet>'
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml','<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
        z.writestr('_rels/.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr('xl/workbook.xml','<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Opportunities" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr('xl/_rels/workbook.xml.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr('xl/worksheets/sheet1.xml',sheet)
    return out.getvalue()

def rate_ok(key,write=False):
    tick=time.monotonic();limit=30 if write else 150
    key=(key,'write' if write else 'read')
    with RATE_LOCK:
        q=RATE[key]
        while q and q[0]<tick-60:q.popleft()
        if len(q)>=limit:return False
        q.append(tick)
        if len(RATE)>10000:
            for k in list(RATE):
                if not RATE[k] or RATE[k][-1]<tick-60:del RATE[k]
    return True

def application(env,start_response):
    method=env.get('REQUEST_METHOD','GET').upper()
    path=env.get('PATH_INFO','/')
    host=env.get('HTTP_HOST','localhost')
    host_name=host.split(':',1)[0].lower()
    headers=[('X-Content-Type-Options','nosniff'),('Referrer-Policy','no-referrer'),
      ('X-Frame-Options','DENY'),('Permissions-Policy','camera=(), microphone=(), geolocation=()'),('Content-Security-Policy',CSP)]
    if SECURE_COOKIE:headers.append(('Strict-Transport-Security','max-age=31536000'))
    session=None
    def respond(status,value=None,content_type='application/json; charset=utf-8',extra=None):
        if isinstance(value,bytes):body=value
        elif content_type.startswith('application/json'):body=json.dumps(value,ensure_ascii=False).encode()
        else:body=str(value or '').encode()
        out=headers+[('Content-Type',content_type),('Content-Length',str(len(body))),('Cache-Control','no-store' if path.startswith('/api') else 'no-cache')]+(extra or [])
        start_response(f'{status} '+{200:'OK',201:'Created',400:'Bad Request',401:'Unauthorized',403:'Forbidden',404:'Not Found',405:'Method Not Allowed',413:'Payload Too Large',429:'Too Many Requests',500:'Internal Server Error',503:'Service Unavailable'}.get(status,'Error'),out)
        return [b'' if method=='HEAD' else body]
    try:
        if host_name not in ALLOWED_HOSTS:return respond(400,{'error':'Untrusted host'})
        if not rate_ok(env.get('REMOTE_ADDR','local'),method not in ('GET','HEAD')):
            return respond(429,{'error':'Too many requests'},extra=[('Retry-After','60')])
        if path.startswith('/api/'):
            cookie=SimpleCookie()
            try:cookie.load(env.get('HTTP_COOKIE',''))
            except CookieError:cookie=SimpleCookie()
            session,is_new=db.get_session(cookie[COOKIE].value if COOKIE in cookie else None)
            if is_new:
                headers.append(('Set-Cookie',f'{COOKIE}={session["id"]}; HttpOnly; SameSite=Strict; Path=/; Max-Age=7776000'+('; Secure' if SECURE_COOKIE else '')))
            sid=session['id']
            params={k:v[-1] for k,v in parse_qs(env.get('QUERY_STRING',''),keep_blank_values=True).items()}
            if any(len(v)>1500 for v in params.values()):return respond(400,{'error':'Query too long'})
            body={}
            if method not in ('GET','HEAD'):
                if path.startswith('/api/admin/'):
                    # No default credential, query-string token or public refresh endpoint.
                    if len(ADMIN_TOKEN)<32:return respond(503,{'error':'Admin refresh disabled: no strong server credential configured'})
                    token=env.get('HTTP_AUTHORIZATION','')
                    if not hmac.compare_digest(token,'Bearer '+ADMIN_TOKEN):return respond(401,{'error':'Admin authorization required'})
                else:
                    origin=env.get('HTTP_ORIGIN','')
                    expected=env.get('wsgi.url_scheme','http')+'://'+host
                    if origin!=expected:return respond(403,{'error':'Same-origin request required'})
                    if not hmac.compare_digest(env.get('HTTP_X_CSRF_TOKEN',''),session['csrf']):return respond(403,{'error':'Invalid CSRF token'})
                length=int(env.get('CONTENT_LENGTH') or 0)
                if length<0 or length>MAX_BODY:return respond(413,{'error':'Request too large'})
                if length:
                    if env.get('CONTENT_TYPE','').split(';')[0]!='application/json':return respond(400,{'error':'JSON required'})
                    body=json.loads(env['wsgi.input'].read(length))
                    if not isinstance(body,dict):return respond(400,{'error':'Object required'})
            if path=='/api/session' and method=='GET':return respond(200,{'csrf':session['csrf'],'company':db.get_company(sid),'privacy':'Device-specific private workspace; no cross-device account.'})
            if path=='/api/meta' and method=='GET':return respond(200,{'sectors':{k:{'ar':v[0],'en':v[1]} for k,v in SECTORS.items()},'engines':engines()})
            if path=='/api/summary' and method=='GET':return respond(200,db.summary())
            if path=='/api/sources' and method=='GET':return respond(200,{'items':db.get_sources(),'scheduler':{'configured':os.environ.get('BIDPILOT_SCHEDULER','true')=='true','active':SCHEDULER_ACTIVE,'production_verified':False,'interval_hours':24}})
            if path=='/api/opportunities' and method=='GET':return respond(200,db.list_opportunities(params,sid))
            if path.startswith('/api/opportunities/') and method=='GET':
                record=db.detail(path.rsplit('/',1)[1],sid)
                return respond(200,record) if record else respond(404,{'error':'Opportunity not found'})
            if path=='/api/company' and method=='GET':return respond(200,db.get_company(sid))
            if path=='/api/company' and method=='POST':return respond(200,db.save_company(sid,body))
            if path.startswith('/api/saved/') and method=='POST':
                db.track(sid,path.rsplit('/',1)[1],body);return respond(200,{'ok':True})
            if path=='/api/admin/refresh' and method=='POST':
                from .refresh import refresh
                return respond(200,refresh())
            if path=='/api/admin/import' and method=='POST':
                records=body.get('items')
                if not isinstance(records,list) or len(records)>50:return respond(400,{'error':'Provide up to 50 verified records'})
                # Validate entire batch before mutation; identity-preserving parameterized upserts.
                clean=[db.normalize_record(r) for r in records]
                for record in clean:db.upsert(record)
                from .refresh import audit
                audit('admin_manual_import','HTTP',{'records':len(clean)})
                return respond(200,{'imported':len(clean),'mode':'MANUAL_IMPORT'})
            if path in ('/api/export.csv','/api/export.xlsx') and method=='GET':
                records=db.list_opportunities({**params,'limit':200,'offset':0},sid)['items']
                ext='csv' if path.endswith('.csv') else 'xlsx'
                payload=db.export_csv(records) if ext=='csv' else xlsx(records)
                mime='text/csv; charset=utf-8' if ext=='csv' else 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                return respond(200,payload,mime,[('Content-Disposition',f'attachment; filename="saudi-bidpilot.{ext}"')])
            return respond(404,{'error':'Unknown endpoint'})
        if method not in ('GET','HEAD'):return respond(405,{'error':'Read only'})
        allowed={'/app.js','/style.css','/score-bars.js','/favicon.svg'}
        if path in allowed:
            file=PUBLIC/path[1:]
        elif path=='/' or path.startswith(('/tenders','/hotels','/manpower','/housekeeping','/construction','/maintenance','/services','/subcontracts','/suppliers','/saved','/tracking','/sources','/company','/dashboard')):
            file=PUBLIC/'index.html'
        else:return respond(404,{'error':'Page not found'})
        if not file.is_file():return respond(404,{'error':'Asset not found'})
        mime=mimetypes.guess_type(str(file))[0] or 'application/octet-stream'
        return respond(200,file.read_bytes(),mime+('; charset=utf-8' if mime.startswith(('text/','application/javascript')) else ''))
    except (ValueError,TypeError,json.JSONDecodeError) as e:
        return respond(400,{'error':'Invalid request data'})
    except KeyError:
        return respond(404,{'error':'Opportunity not found'})
    except Exception:
        LOG.exception('Request failed at %s',path)
        return respond(500,{'error':'Temporary server error. Please retry.'})

SCHEDULER_ACTIVE=False
def scheduler():
    global SCHEDULER_ACTIVE
    SCHEDULER_ACTIVE=True
    # Refresh immediately only if the last attempt is >24h; otherwise use persisted due time.
    while True:
        try:
            summary=db.summary();run=summary.get('last_run')
            from datetime import datetime, timezone
            elapsed=86400 if not run else (datetime.now(timezone.utc)-datetime.fromisoformat(run['started_at'])).total_seconds()
            if elapsed>=86400:
                from .refresh import refresh
                refresh()
        except Exception:LOG.exception('Daily refresh failed')
        time.sleep(60)

class ThreadingServer(ThreadingMixIn,WSGIServer):
    daemon_threads=True

def main():
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    db.initialize()
    from .refresh import seed
    seed()
    if os.environ.get('BIDPILOT_SCHEDULER','true').lower()=='true':
        threading.Thread(target=scheduler,daemon=True,name='daily-source-refresh').start()
    host=os.environ.get('BIDPILOT_HOST','127.0.0.1');port=int(os.environ.get('BIDPILOT_PORT','8080'))
    with make_server(host,port,application,server_class=ThreadingServer) as server:
        LOG.info('Saudi BidPilot serving on %s:%s',host,port)
        server.serve_forever()

if __name__=='__main__':main()
