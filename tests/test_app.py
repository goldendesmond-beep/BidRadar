"""Executed API/security regression tests; synthetic fixtures live in temporary DBs only."""
import csv
import importlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import database as db, server, intelligence


def request(path='/', method='GET', body=None, cookie='', csrf='', origin='http://localhost', host='localhost', headers=None):
    query = ''
    if '?' in path:
        path, query = path.split('?', 1)
    payload = body if isinstance(body, bytes) else (json.dumps(body, ensure_ascii=False).encode() if body is not None else b'')
    env = {'REQUEST_METHOD':method, 'PATH_INFO':path, 'QUERY_STRING':query,
           'HTTP_HOST':host, 'REMOTE_ADDR':'qa-local', 'wsgi.url_scheme':'http',
           'wsgi.input':io.BytesIO(payload), 'CONTENT_LENGTH':str(len(payload)),
           'CONTENT_TYPE':'application/json', 'HTTP_COOKIE':cookie,
           'HTTP_ORIGIN':origin, 'HTTP_X_CSRF_TOKEN':csrf}
    if headers:
        env.update(headers)
    captured = {}
    def start(status, response_headers):
        captured['status'] = int(status.split()[0])
        captured['headers'] = dict(response_headers)
    captured['body'] = b''.join(server.application(env, start))
    if captured['headers'].get('Content-Type','').startswith('application/json'):
        captured['json'] = json.loads(captured['body'])
    return captured


def fixture(**overrides):
    return {'id':'test-cleaning', 'title':'عقد خدمات نظافة وتشغيل مرافق',
            'title_en':'Cleaning and facility maintenance contract',
            'organization':'TEST ONLY authority', 'source_id':'qa-fixture',
            'source_url':'https://example.com/test-opportunity', 'kind':'tender',
            'status':'open','deadline':'2099-12-31','published_at':'2026-01-01',
            'city':'الرياض', 'reference':'QA-001', 'last_verified':db.now(),
            'description':'خدمات النظافة والصيانة', 'sectors':['cleaning','maintenance','facilities'],
            **overrides}


class ApiRegression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bidpilot-qa-')
        self.old_path = db.DB_PATH
        db.DB_PATH = Path(self.tmp.name)/'test.sqlite3'
        server.RATE.clear()
        db.initialize()
        db.upsert(fixture())
        db.upsert(fixture(id='test-hotel', reference='QA-002', title='تدبير فندقي وتوريد عمالة',
                          source_url='https://example.com/test-hotel', sectors=['hospitality','housekeeping','manpower'], city='جدة'))
        response = request('/api/session')
        self.cookie = response['headers']['Set-Cookie'].split(';')[0]
        self.csrf = response['json']['csrf']

    def tearDown(self):
        db.DB_PATH = self.old_path
        self.tmp.cleanup()

    def write(self, path, body, **kwargs):
        return request(path, 'POST', body, self.cookie, self.csrf, **kwargs)

    def test_home_and_assets_security_headers(self):
        home = request('/')
        self.assertEqual(home['status'],200)
        self.assertIn(b'dir="rtl"', home['body'])
        self.assertEqual(home['headers']['X-Frame-Options'],'DENY')
        self.assertEqual(home['headers']['X-Content-Type-Options'],'nosniff')
        self.assertIn("script-src 'self'", home['headers']['Content-Security-Policy'])
        self.assertNotIn('unsafe-inline', home['headers']['Content-Security-Policy'])
        for asset in ['/app.js','/style.css','/score-bars.js','/favicon.svg']:
            with self.subTest(asset=asset):self.assertEqual(request(asset)['status'],200)

    def test_database_persists_and_integrity(self):
        db.initialize()
        self.assertEqual(db.detail('test-cleaning')['reference'],'QA-001')
        with db.connect() as conn:
            self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            self.assertEqual(conn.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_session_cookie_private_flags(self):
        cookie = request('/api/session')['headers']['Set-Cookie']
        for flag in ['HttpOnly','SameSite=Strict','Path=/']:self.assertIn(flag,cookie)

    def test_company_saved_private_isolation_and_persistence(self):
        profile = {'name':'QA Company','size':'medium','city':'الرياض','sectors':['cleaning'], 'services':'cleaning','workers':20}
        self.assertEqual(self.write('/api/company',profile)['status'],200)
        self.assertEqual(self.write('/api/saved/test-cleaning',{'stage':'preparing','notes':'private'})['status'],200)
        self.assertEqual(request('/api/company',cookie=self.cookie)['json']['name'],'QA Company')
        saved = request('/api/opportunities?saved=true',cookie=self.cookie)['json']
        self.assertEqual(saved['total'],1)
        self.assertEqual(saved['items'][0]['tracking']['notes'],'private')
        other = request('/api/session')
        other_cookie = other['headers']['Set-Cookie'].split(';')[0]
        self.assertEqual(request('/api/company',cookie=other_cookie)['json'],{})
        self.assertEqual(request('/api/opportunities?saved=true',cookie=other_cookie)['json']['total'],0)
        db.initialize()
        self.assertEqual(request('/api/company',cookie=self.cookie)['json']['name'],'QA Company')

    def test_csrf_and_origin_reject_unauthorized_writes(self):
        for token, origin in [('','http://localhost'),('incorrect','http://localhost'),(self.csrf,'https://attacker.example'),(self.csrf,'')]:
            with self.subTest(token=token,origin=origin):
                self.assertEqual(request('/api/company','POST',{'name':'evil'},self.cookie,token,origin)['status'],403)
        self.assertEqual(request('/api/company',cookie=self.cookie)['json'],{})

    def test_admin_disabled_and_missing_credentials(self):
        with patch.object(server,'ADMIN_TOKEN',''):
            self.assertEqual(self.write('/api/admin/refresh',{})['status'],503)
        with patch.object(server,'ADMIN_TOKEN','a'*40):
            self.assertEqual(self.write('/api/admin/refresh',{})['status'],401)
            self.assertEqual(request('/api/admin/refresh?token='+('a'*40),'POST',{},headers={'HTTP_AUTHORIZATION':'Bearer bad'})['status'],401)

    def test_host_allowlist(self):
        self.assertEqual(request('/',host='attacker.example')['status'],400)
        self.assertEqual(request('/',host='localhost:8080')['status'],200)

    def test_arabic_and_english_search_and_filters(self):
        for term in ['نظافة','cleaning','maintenance','QA-001']:
            found = request('/api/opportunities?'+urlencode({'q':term}))['json']
            with self.subTest(term=term):self.assertIn('test-cleaning',[r['id'] for r in found['items']])
        for params, count in [({'city':'جدة'},1),({'sector':'housekeeping'},1),({'status':'closed'},0),({'organization':'TEST ONLY authority'},2),({'kind':'supplier_registration'},0),({'q':'zzzz_missing_123'},0)]:
            with self.subTest(params=params):self.assertEqual(request('/api/opportunities?'+urlencode(params))['json']['total'],count)

    def test_search_uses_published_english_fields(self):
        db.upsert(fixture(title_en='Window refurbishment contract',organization_en='Eastern Window Bureau',description_en='Glass facade refurbishment'))
        for term in ['Window refurbishment','Eastern Window Bureau','Glass facade']:
            found=request('/api/opportunities?'+urlencode({'q':term}))['json']
            with self.subTest(term=term):self.assertIn('test-cleaning',[r['id'] for r in found['items']])

    def test_details_404_and_invalid_parameters(self):
        detail = request('/api/opportunities/test-cleaning',cookie=self.cookie)
        self.assertEqual(detail['status'],200)
        self.assertEqual(detail['json']['source_url'],'https://example.com/test-opportunity')
        for path in ['/api/opportunities/nonexistent','/api/missing','/nonexistent','/../../etc/passwd']:
            with self.subTest(path=path):self.assertEqual(request(path)['status'],404)
        self.assertEqual(request('/api/opportunities?limit=not-a-number')['status'],400)
        self.assertEqual(request('/api/opportunities?limit=999999')['json']['limit'],200)

    def test_sql_injection_does_not_expand_results(self):
        for key in ['city','organization','source_id','status']:
            response = request('/api/opportunities?'+urlencode({key:"' OR 1=1; DROP TABLE opportunities; --"}))
            with self.subTest(key=key):
                self.assertEqual(response['status'],200)
                self.assertEqual(response['json']['total'],0)
        self.assertEqual(db.summary()['total'],2)

    def test_xss_is_data_and_frontend_escapes(self):
        payload='<img src=x onerror=alert(1)><script>alert(1)</script>'
        self.assertEqual(self.write('/api/company',{'name':payload})['status'],200)
        response = request('/api/company',cookie=self.cookie)
        self.assertEqual(response['json']['name'],payload)
        self.assertTrue(response['headers']['Content-Type'].startswith('application/json'))
        script = request('/app.js')['body'].decode()
        self.assertIn('const esc=',script)
        self.assertIn('esc(company.name)',script)
        self.assertIn('esc(label(r,\'title\'))',script)

    def test_json_validation_and_body_limit(self):
        self.assertEqual(self.write('/api/company',b'{invalid')['status'],400)
        self.assertEqual(self.write('/api/company',b'[]')['status'],400)
        self.assertEqual(self.write('/api/company',b'x'*(server.MAX_BODY+1))['status'],413)
        self.assertEqual(self.write('/api/company',{'size':'unknown'})['status'],400)
        self.assertEqual(self.write('/api/company',{'workers':'twenty'})['status'],400)
        self.assertEqual(self.write('/api/saved/test-cleaning',{'stage':'unexpected'})['status'],400)
        self.assertEqual(self.write('/api/saved/nonexistent',{'stage':'saved'})['status'],404)

    def test_company_workers_bounded_and_sectors_validated(self):
        response=self.write('/api/company',{'workers':9999999,'sectors':['cleaning','evil']})
        self.assertEqual(response['status'],200)
        self.assertEqual(response['json']['workers'],100000)
        self.assertEqual(response['json']['sectors'],['cleaning'])

    def test_deduplication_and_history(self):
        record=fixture(title='عنوان جديد للمنافسة نفسها')
        db.upsert(record)
        self.assertEqual(db.summary()['total'],2)
        self.assertEqual(db.detail('test-cleaning')['title'],record['title'])
        with db.connect() as conn:self.assertEqual(conn.execute('SELECT COUNT(*) FROM versions').fetchone()[0],1)

    def test_expiry_normalization_and_daily_close(self):
        expired=db.upsert(fixture(id='test-expired',reference='QA-expired',deadline='2000-01-01'))
        self.assertEqual(expired['status'],'closed')
        with db.connect() as conn:
            row=conn.execute('SELECT data FROM opportunities WHERE id=?',('test-cleaning',)).fetchone()
            record=json.loads(row['data']);record['deadline']='2000-01-01'
            conn.execute('UPDATE opportunities SET deadline=?,data=? WHERE id=?',('2000-01-01',json.dumps(record),'test-cleaning'))
        self.assertEqual(db.close_expired(),1)
        self.assertEqual(db.detail('test-cleaning')['status'],'closed')
        self.assertEqual(db.close_expired(),0)

    def test_application_actions_require_verification(self):
        record=db.normalize_record(fixture(apply_url='https://example.com/apply'))
        self.assertIsNone(record['apply_url'])
        record=db.normalize_record(fixture(apply_url='https://example.com/apply',apply_verified=True))
        self.assertEqual(record['apply_url'],'https://example.com/apply')
        record=db.normalize_record(fixture(kind='supplier_registration',registration_url='https://example.com/register',registration_verified=True,apply_url='https://example.com/register',apply_verified=True))
        self.assertIsNone(record['apply_url'])
        self.assertEqual(record['status'],'registration_available')

    def test_urls_reject_local_and_unsafe_schemes(self):
        for url in ['http://example.com/','javascript:alert(1)','https://localhost/','https://127.0.0.1/','https://192.168.1.1/','https://[::1]/','https://user:pass@example.com/','https://example.local/','https://example.com:8443/']:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):db.safe_url(url)

    def test_csv_formula_injection_protection(self):
        records=[{'title':x,'organization':'Authority'} for x in ['=SUM(1,2)','+cmd','-cmd','@cmd','  =HYPERLINK("evil")','\t=1','\r=1']]
        parsed=list(csv.reader(io.StringIO(db.export_csv(records).decode('utf-8-sig'))))
        for row in parsed[1:]:self.assertTrue(row[0].startswith("'"))
        response=request('/api/export.csv')
        self.assertEqual(response['status'],200)
        self.assertIn('attachment',response['headers']['Content-Disposition'])

    def test_xlsx_valid_zip_schema_and_strings(self):
        payload=server.xlsx([{'title':'=DANGEROUS()', 'organization':'<Authority>&'}])
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            required={'[Content_Types].xml','_rels/.rels','xl/workbook.xml','xl/_rels/workbook.xml.rels','xl/worksheets/sheet1.xml'}
            self.assertEqual(set(archive.namelist()),required)
            for name in required:ElementTree.fromstring(archive.read(name))
            root=ElementTree.fromstring(archive.read('xl/worksheets/sheet1.xml'))
            ns={'s':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
            self.assertEqual(root.findall('.//s:f',ns),[])
            self.assertIn('=DANGEROUS()',archive.read('xl/worksheets/sheet1.xml').decode())
        self.assertEqual(request('/api/export.xlsx')['status'],200)

    def test_rate_limit_and_retry_after(self):
        server.RATE.clear()
        statuses=[request('/api/summary')['status'] for _ in range(151)]
        self.assertEqual(statuses.count(200),150)
        self.assertEqual(statuses[-1],429)
        self.assertEqual(request('/api/summary')['headers']['Retry-After'],'60')

    def test_sources_status_and_summary(self):
        db.set_source({'id':'qa','name':'QA fixture','url':'https://example.com','status':'MANUAL_IMPORT','last_attempt':db.now()})
        response=request('/api/sources')['json']
        self.assertEqual(response['items'][0]['status'],'MANUAL_IMPORT')
        self.assertFalse(response['scheduler']['production_verified'])
        self.assertEqual(request('/api/summary')['json']['live_sources'],0)

    def test_fit_score_does_not_claim_eligibility(self):
        fit=intelligence.fit(db.detail('test-cleaning'),{'sectors':['cleaning'],'city':'الرياض','services':'cleaning'})
        self.assertGreaterEqual(fit['score'],70)
        self.assertTrue(fit['limits'])
        self.assertIsNone(intelligence.fit(db.detail('test-cleaning'),{})['score'])


if __name__=='__main__':unittest.main(verbosity=2)
