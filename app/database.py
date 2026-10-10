import contextlib
import csv
import hashlib
import io
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from zoneinfo import ZoneInfo
from .intelligence import classify, fit, relevance

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get('BIDPILOT_DB', str(ROOT / 'data' / 'bidpilot.sqlite3')))
VALID_KINDS = {'tender','rfq','rfp','qualification','supplier_registration','subcontract_announced','subcontract_potential','planned'}
VALID_STATUSES = {'open','closed','unknown','planned','registration_available','awarded'}
SOURCE_STATES = {'LIVE','AUTH_REQUIRED','BLOCKED','DEGRADED','MANUAL_IMPORT','UNAVAILABLE'}

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def today():
    return datetime.now(ZoneInfo('Asia/Riyadh')).date().isoformat()

def expired(record):
    if record.get('deadline') and record['deadline']<today():return True
    if record.get('deadline_at'):
        try:
            when=datetime.fromisoformat(record['deadline_at'])
            if not when.tzinfo:when=when.replace(tzinfo=ZoneInfo('Asia/Riyadh'))
            return when<=datetime.now(timezone.utc)
        except (ValueError,TypeError):pass
    return False

def safe_url(value):
    if not value:
        return None
    p = urlsplit(str(value).strip())
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.port not in (None, 443):
        raise ValueError('Only public HTTPS source URLs are accepted')
    host = p.hostname.lower()
    if host in {'localhost'} or ':' in host or host.replace('.', '').isdigit() or host.endswith('.local'):
        raise ValueError('Private URL rejected')
    return urlunsplit(('https', host, p.path or '/', p.query, p.fragment))

def canonical_url(value):
    p = urlsplit(safe_url(value))
    pairs = [(k,v) for k,v in parse_qsl(p.query, keep_blank_values=True) if not k.lower().startswith('utm_')]
    return urlunsplit((p.scheme,p.netloc,p.path.rstrip('/') or '/',urlencode(sorted(pairs)),''))

@contextlib.contextmanager
def connect(path=None):
    path = Path(path or DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=15000')
    try:
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()

def initialize():
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS opportunities (
          id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, source_id TEXT NOT NULL,
          kind TEXT NOT NULL, status TEXT NOT NULL, deadline TEXT, title TEXT NOT NULL,
          city TEXT, organization TEXT, data TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS opp_status ON opportunities(status,kind,deadline);
        CREATE TABLE IF NOT EXISTS versions (
          id INTEGER PRIMARY KEY, opportunity_id TEXT NOT NULL, data TEXT NOT NULL, recorded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sources (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, status TEXT NOT NULL,
          data TEXT NOT NULL, last_attempt TEXT, last_success TEXT
        );
        CREATE TABLE IF NOT EXISTS runs (
          id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, data TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS imports (file_hash TEXT PRIMARY KEY, imported_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY, event TEXT NOT NULL, target TEXT, occurred_at TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS error_logs (id INTEGER PRIMARY KEY, source_id TEXT, run_id INTEGER, occurred_at TEXT NOT NULL, message TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, name_ar TEXT NOT NULL, name_en TEXT NOT NULL, keywords TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS verification_history (
          id INTEGER PRIMARY KEY, opportunity_id TEXT NOT NULL REFERENCES opportunities(id),
          verified_at TEXT NOT NULL, method TEXT NOT NULL, source_url TEXT NOT NULL,
          UNIQUE(opportunity_id,verified_at,method)
        );
        CREATE TABLE IF NOT EXISTS verification_attempts (
          id INTEGER PRIMARY KEY, opportunity_id TEXT REFERENCES opportunities(id), source_id TEXT NOT NULL,
          source_url TEXT NOT NULL, attempted_at TEXT NOT NULL, outcome TEXT NOT NULL, error TEXT
        );
        CREATE INDEX IF NOT EXISTS verification_attempt_opp ON verification_attempts(opportunity_id,attempted_at);
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY, csrf TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS companies (
          session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE, data TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS saved (
          session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
          opportunity_id TEXT NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
          stage TEXT NOT NULL DEFAULT 'saved', notes TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
          PRIMARY KEY (session_id,opportunity_id)
        );
        ''')
        db.execute('INSERT OR IGNORE INTO migrations(version,applied_at) VALUES(1,?)',(now(),))
        from .intelligence import SECTORS
        for key,value in SECTORS.items():
            db.execute('INSERT INTO categories(id,name_ar,name_en,keywords) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET name_ar=excluded.name_ar,name_en=excluded.name_en,keywords=excluded.keywords',(key,value[0],value[1],json.dumps(value[2],ensure_ascii=False)))
        db.execute('INSERT OR IGNORE INTO migrations(version,applied_at) VALUES(2,?)',(now(),))
        db.execute('INSERT OR IGNORE INTO migrations(version,applied_at) VALUES(3,?)',(now(),))
        # Cookie lifetime and server retention are both 90 days.
        db.execute('DELETE FROM sessions WHERE expires_at < ?', (now(),))

def normalize_record(raw):
    r = dict(raw)
    mapping = {'issuer':'organization','issuerEn':'organization_en','titleEn':'title_en','descriptionEn':'description_en',
      'sourceUrl':'source_url','lastVerifiedAt':'last_verified','loginRequired':'login_required','requiredDocuments':'documents',
      'publishedAt':'published_at','closingDate':'deadline','sourceId':'source_id','applicationUrl':'apply_url','referenceNumber':'reference'}
    for a,b in mapping.items():
        if a in r and b not in r: r[b] = r[a]
    r['kind'] = str(r.get('kind') or r.get('type') or 'tender').lower()
    if r['kind'] not in VALID_KINDS: raise ValueError('Unsupported opportunity kind')
    r['title'] = str(r.get('title') or '').strip()[:1200]
    r['organization'] = str(r.get('organization') or '').strip()[:300]
    if not r['title'] or not r['organization']: raise ValueError('Missing title or organization')
    r['source_url'] = safe_url(r.get('source_url'))
    if not r['source_url']: raise ValueError('Missing original source URL')
    r['source_id'] = str(r.get('source_id') or urlsplit(r['source_url']).hostname).lower()[:200]
    for k in ['apply_url','registration_url','award_url','contractor_url']:
        r[k] = safe_url(r.get(k))
    if r.get('actionUrl') and not r.get('registration_url') and r['kind'] == 'supplier_registration':
        r['registration_url'] = safe_url(r['actionUrl'])
    # Never turn a general source or registration link into a tender-apply action.
    if r['kind'] in ('supplier_registration','subcontract_potential','planned'):
        r['apply_url'] = None
    if r.get('apply_url') and (not r.get('apply_verified') or r['apply_url'] == r.get('registration_url')):
        r['apply_url'] = None
    if r.get('registration_url') and not (r.get('registration_verified') or r.get('actionUrl')):
        r['registration_url'] = None
    for k in ['deadline','published_at']:
        value = r.get(k)
        if value:
            try:
                datetime.fromisoformat(str(value)[:10])
                if k=='deadline' and 'T' in str(value):r['deadline_at']=datetime.fromisoformat(str(value)).isoformat()
                r[k] = str(value)[:10]
            except ValueError:
                r[k] = None
    if r.get('deadline') and r.get('deadline_time'):
        try:r['deadline_at']=datetime.strptime(r['deadline']+' '+r['deadline_time'],'%Y-%m-%d %H:%M').replace(tzinfo=ZoneInfo('Asia/Riyadh')).isoformat()
        except ValueError:pass
    r['status'] = str(r.get('status','unknown')).lower()
    if r['kind'] == 'supplier_registration': r['status'] = 'registration_available' if r.get('registration_url') else 'unknown'
    if r['kind'] == 'planned': r['status'] = 'planned'
    if r['status'] not in VALID_STATUSES: r['status'] = 'unknown'
    if expired(r) and r['status'] in ('open','unknown'):
        r['status'] = 'closed'
    # Future date alone does not establish that submission is open.
    r['sectors'] = r.get('sectors') or classify(r['title'] + ' ' + str(r.get('description','')))
    if r['kind'] in ('tender','rfq','rfp','qualification'):
        import re
        body=(r['title']+' '+str(r.get('description',''))).lower()
        if 'manpower' in r['sectors'] and not re.search(r'عمالة|العمال|manpower|staffing|توريد عمال|تعهيد',body):
            r['sectors']=[s for s in r['sectors'] if s!='manpower']
        for sector in classify(body):
            if sector in ('mep','renovation','hotel_renovation','waste','general_contracting') and sector not in r['sectors']:r['sectors'].append(sector)
    r['last_verified'] = r.get('last_verified') or now()
    r['verification_status']=r.get('verification_status','verified')
    conf=float(r.get('confidence',70))
    r['confidence'] = min(100,max(0,round(conf*100 if 0<=conf<=1 else conf)))
    r['city'] = r.get('city') or 'السعودية'
    r['requirements'] = r.get('requirements') or []
    r['documents'] = r.get('documents') or []
    if isinstance(r['requirements'], str): r['requirements'] = [r['requirements']]
    if isinstance(r['documents'], str): r['documents'] = [r['documents']]
    return r

def upsert(raw):
    r = normalize_record(raw)
    fingerprint = hashlib.sha256((r['source_id'] + '|' + (str(r.get('reference')) if r.get('reference') else canonical_url(r['source_url']) + '|' + r['title'])).encode()).hexdigest()
    rid = r.get('id') or fingerprint[:20]
    with connect() as db:
        existing = db.execute('SELECT id,data FROM opportunities WHERE fingerprint=?', (fingerprint,)).fetchone()
        if existing:
            rid = existing['id']
            if json.loads(existing['data']) != {**r,'id':rid}:
                db.execute('INSERT INTO versions(opportunity_id,data,recorded_at) VALUES (?,?,?)', (rid,existing['data'],now()))
        r['id'] = rid
        payload = json.dumps(r,ensure_ascii=False,sort_keys=True)
        db.execute('''INSERT INTO opportunities(id,fingerprint,source_id,kind,status,deadline,title,city,organization,data,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET
          kind=excluded.kind,status=excluded.status,deadline=excluded.deadline,title=excluded.title,city=excluded.city,
          organization=excluded.organization,data=excluded.data,updated_at=excluded.updated_at''',
          (rid,fingerprint,r['source_id'],r['kind'],r['status'],r.get('deadline'),r['title'],r['city'],r['organization'],payload,now(),now()))
        db.execute('INSERT OR IGNORE INTO verification_history(opportunity_id,verified_at,method,source_url) VALUES(?,?,?,?)',(rid,r['last_verified'],r.get('verification_method','verified public extraction'),r['source_url']))
    return r

def set_source(source):
    s = dict(source)
    if s.get('status') not in SOURCE_STATES: s['status'] = 'UNAVAILABLE'
    s['url'] = safe_url(s['url'])
    with connect() as db:
        prev = db.execute('SELECT last_success FROM sources WHERE id=?',(s['id'],)).fetchone()
        success = s.get('last_success') or (prev['last_success'] if prev else None)
        db.execute('''INSERT INTO sources(id,name,url,status,data,last_attempt,last_success) VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,status=excluded.status,
          data=excluded.data,last_attempt=excluded.last_attempt,last_success=excluded.last_success''',
          (s['id'],s['name'],s['url'],s['status'],json.dumps(s,ensure_ascii=False),s.get('last_attempt'),success))

def get_sources():
    with connect() as db:
        return [{**json.loads(row['data']),'last_success':row['last_success'],'last_attempt':row['last_attempt']} for row in db.execute('SELECT * FROM sources ORDER BY name')]

def verification_failure(source_id,source_url,error,attempted_at=None):
    attempted_at=attempted_at or now()
    wanted=canonical_url(source_url)
    affected=0
    with connect() as conn:
        rows=conn.execute('SELECT id,data FROM opportunities WHERE source_id=?',(source_id,)).fetchall()
        for row in rows:
            record=json.loads(row['data'])
            if canonical_url(record['source_url'])!=wanted:continue
            conn.execute('INSERT INTO versions(opportunity_id,data,recorded_at) VALUES(?,?,?)',(row['id'],row['data'],attempted_at))
            record['verification_status']='failed'
            record['last_verification_attempt']=attempted_at
            record['verification_error']=str(error or 'verification_failed')[:200]
            if record['status']=='open':
                record['last_confirmed_status']='open'
                record['status']='unknown'
            conn.execute('UPDATE opportunities SET status=?,data=?,updated_at=? WHERE id=?',(record['status'],json.dumps(record,ensure_ascii=False),attempted_at,row['id']))
            conn.execute('INSERT INTO verification_attempts(opportunity_id,source_id,source_url,attempted_at,outcome,error) VALUES(?,?,?,?,?,?)',(row['id'],source_id,source_url,attempted_at,'failed',record['verification_error']))
            affected+=1
    return affected

def verification_success(record,attempted_at=None):
    attempted_at=attempted_at or now()
    record={**record,'verification_status':'verified','last_verification_attempt':attempted_at,'verification_error':None}
    result=upsert(record)
    with connect() as conn:
        conn.execute('INSERT INTO verification_attempts(opportunity_id,source_id,source_url,attempted_at,outcome,error) VALUES(?,?,?,?,?,?)',(result['id'],result['source_id'],result['source_url'],attempted_at,'verified',None))
    return result

def close_expired():
    with connect() as db:
        rows = db.execute("SELECT id,data FROM opportunities WHERE status IN ('open','unknown') AND deadline <= ?",(today(),)).fetchall()
        closed=0
        for row in rows:
            r = json.loads(row['data'])
            if not expired(r):continue
            r['status']='closed';closed+=1
            db.execute('INSERT INTO versions(opportunity_id,data,recorded_at) VALUES(?,?,?)',(row['id'],row['data'],now()))
            db.execute("UPDATE opportunities SET status='closed',data=?,updated_at=? WHERE id=?",(json.dumps(r,ensure_ascii=False),now(),row['id']))
        return closed

def get_session(sid=None):
    with connect() as db:
        row = db.execute('SELECT * FROM sessions WHERE id=? AND expires_at>?',(sid or '',now())).fetchone()
        if row: return dict(row),False
        row = {'id':secrets.token_urlsafe(32),'csrf':secrets.token_urlsafe(32),'created_at':now(),
          'expires_at':(datetime.now(timezone.utc)+timedelta(days=90)).isoformat(timespec='seconds')}
        db.execute('INSERT INTO sessions(id,csrf,created_at,expires_at) VALUES(?,?,?,?)',tuple(row.values()))
        return row,True

def get_company(sid):
    with connect() as db:
        r=db.execute('SELECT data FROM companies WHERE session_id=?',(sid,)).fetchone()
        return json.loads(r['data']) if r else {}

def list_opportunities(params=None, sid=None):
    params=params or {}
    where=[]; values=[]
    if params.get('procurement_only')=='true':where.append("kind IN ('tender','rfq','rfp','qualification')")
    for key in ['kind','status','source_id']:
        if params.get(key): where.append(key+'=?'); values.append(params[key])
    for key in ['city','organization']:
        if params.get(key):where.append(key+" LIKE ? ESCAPE '\\'");values.append('%'+params[key].replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%')
    if params.get('published_after'):
        where.append("json_extract(data,'$.published_at')>=?");values.append(params['published_after'])
    if params.get('deadline_before'):
        where.append('deadline<=?'); values.append(params['deadline_before'])
    with connect() as db:
        saved = {r['opportunity_id']:dict(r) for r in db.execute('SELECT * FROM saved WHERE session_id=?',(sid or '',))}
        rows = db.execute('SELECT data FROM opportunities'+(' WHERE '+' AND '.join(where) if where else '')+' ORDER BY COALESCE(deadline,\'9999-12-31\'),title',values).fetchall()
    company=get_company(sid) if sid else {}
    records=[]
    for row in rows:
        r=json.loads(row['data'])
        if params.get('sector') and params['sector'] not in r['sectors']:continue
        if params.get('saved')=='true' and r['id'] not in saved:continue
        rel=relevance(params.get('q',''),r)
        if params.get('q') and rel < .25:continue
        r['saved']=r['id'] in saved
        r['tracking']=saved.get(r['id'])
        r['fit']=fit(r,company)
        r['search_relevance']=rel
        records.append(r)
    if params.get('q'):records.sort(key=lambda r:r['search_relevance'],reverse=True)
    if params.get('sort')=='fit':records.sort(key=lambda r:r['fit']['score'] or 0,reverse=True)
    total=len(records)
    offset=max(0,int(params.get('offset',0)));limit=min(200,max(1,int(params.get('limit',50))))
    return {'items':records[offset:offset+limit],'total':total,'offset':offset,'limit':limit}

def detail(rid,sid=None):
    with connect() as db:
        row=db.execute('SELECT data FROM opportunities WHERE id=?',(rid,)).fetchone()
        if not row:return None
        saved=db.execute('SELECT stage,notes,updated_at FROM saved WHERE session_id=? AND opportunity_id=?',(sid or '',rid)).fetchone()
    r=json.loads(row['data']);r['saved']=bool(saved);r['tracking']=dict(saved) if saved else None
    r['fit']=fit(r,get_company(sid) if sid else {})
    return r

def save_company(sid,data):
    from .intelligence import SECTORS
    clean={'name':str(data.get('name',''))[:200],'size':data.get('size','small'),'city':str(data.get('city',''))[:100],
      'sectors':[s for s in data.get('sectors',[]) if s in SECTORS][:20],'services':str(data.get('services',''))[:3000],
      'workers':max(0,min(100000,int(data.get('workers',0))))}
    clean['target_cities']=[str(x).strip()[:100] for x in data.get('target_cities',[])[:20] if str(x).strip()]
    clean['certifications']=[str(x).strip()[:200] for x in data.get('certifications',[])[:30] if str(x).strip()]
    clean['contract_min']=max(0,min(10**12,float(data.get('contract_min') or 0)))
    clean['contract_max']=max(clean['contract_min'],min(10**12,float(data.get('contract_max') or 0)))
    if clean['size'] not in ('small','medium','large'):raise ValueError('Invalid company size')
    with connect() as db:
        db.execute('INSERT INTO companies(session_id,data,updated_at) VALUES(?,?,?) ON CONFLICT(session_id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at',(sid,json.dumps(clean,ensure_ascii=False),now()))
        db.execute('INSERT INTO audit_logs(event,target,occurred_at,data) VALUES(?,?,?,?)',('company_updated',hashlib.sha256(sid.encode()).hexdigest()[:16],now(),'{}'))
    return clean

def track(sid,rid,data):
    if not detail(rid):raise KeyError('Opportunity not found')
    stage=data.get('stage','saved')
    if stage not in ('saved','reviewing','preparing','submitted','won','lost','remove'):raise ValueError('Invalid tracking stage')
    with connect() as db:
        if stage=='remove':db.execute('DELETE FROM saved WHERE session_id=? AND opportunity_id=?',(sid,rid))
        else:db.execute('INSERT INTO saved(session_id,opportunity_id,stage,notes,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(session_id,opportunity_id) DO UPDATE SET stage=excluded.stage,notes=excluded.notes,updated_at=excluded.updated_at',(sid,rid,stage,str(data.get('notes',''))[:3000],now()))

def summary():
    with connect() as db:
        rows=[json.loads(r['data']) for r in db.execute('SELECT data FROM opportunities')]
        run=db.execute('SELECT * FROM runs ORDER BY id DESC LIMIT 1').fetchone()
    sources=get_sources()
    return {'total':len(rows),'tenders':sum(r['kind'] in ('tender','rfq','rfp','qualification') for r in rows),
      'open':sum(r['status']=='open' and r['kind'] in ('tender','rfq','rfp','qualification') for r in rows),
      'registrations':sum(r['kind']=='supplier_registration' for r in rows),
      'live_sources':sum(s['status']=='LIVE' for s in sources),'manual_sources':sum(s['status']=='MANUAL_IMPORT' for s in sources),
      'latest_verification':max((r['last_verified'] for r in rows),default=None),
      'last_run':dict(run) if run else None,'today':today(),'zero_cost_only':True}

def csv_cell(value):
    value=str(value or '')
    if value.lstrip().startswith(('=','+','-','@','\t','\r','\n')):return "'"+value
    return value

def export_csv(records):
    out=io.StringIO();out.write('\ufeff')
    writer=csv.writer(out)
    fields=['title','organization','kind','city','status','published_at','deadline','reference','source_url','apply_url','registration_url','last_verified','confidence']
    writer.writerow(fields)
    for r in records:writer.writerow([csv_cell(r.get(k)) for k in fields])
    return out.getvalue().encode('utf-8')
