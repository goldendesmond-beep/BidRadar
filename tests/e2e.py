"""Playwright integration: real browser, frontend and WSGI API, no listening socket.

Use --url https://deployed-host.example for ordinary network production testing.
Local mode copies the real persistent SQLite DB to a temporary path and routes
browser requests through the actual WSGI application. No fixtures are inserted.
"""
import argparse
from datetime import datetime, timezone
import io
import json
import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import database as db, server
from playwright.sync_api import sync_playwright, expect

ROOT=Path(__file__).resolve().parents[1]
RESULTS=[]

def record(name, fn):
    try:
        fn();RESULTS.append({'test':name,'status':'Passed'});print('Passed:',name,flush=True)
    except Exception as exc:
        RESULTS.append({'test':name,'status':'Failed','reason':str(exc)[:1500]})
        print('Failed:',name,str(exc)[:400],flush=True)


def browser_route(route):
    req=route.request
    parsed=urlsplit(req.url)
    if parsed.hostname!='localhost':
        route.abort();return
    payload=(req.post_data or '').encode()
    headers=req.all_headers()
    env={'REQUEST_METHOD':req.method,'PATH_INFO':parsed.path,'QUERY_STRING':parsed.query,
         'HTTP_HOST':parsed.netloc,'REMOTE_ADDR':'playwright-local','wsgi.url_scheme':parsed.scheme,
         'wsgi.input':io.BytesIO(payload),'CONTENT_LENGTH':str(len(payload)),
         'CONTENT_TYPE':headers.get('content-type','')}
    for name,value in headers.items():
        if name not in ('content-type','content-length'):
            env['HTTP_'+name.upper().replace('-','_')]=value
    response={}
    def start(status,response_headers):
        response['status']=int(status.split()[0]);response['headers']=dict(response_headers)
    response['body']=b''.join(server.application(env,start))
    route.fulfill(status=response['status'],headers=response['headers'],body=response['body'])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--url')
    parser.add_argument('--output',default=str(ROOT/'tests'/'e2e-results.json'))
    args=parser.parse_args()
    original_db=db.DB_PATH
    temp=None
    mode=('local-HTTP-integration' if urlsplit(args.url).hostname in ('localhost','127.0.0.1') else 'network-production') if args.url else 'local-browser-WSGI-integration'
    if not args.url:
        temp=tempfile.TemporaryDirectory(prefix='bidpilot-browser-')
        target=Path(temp.name)/'bidpilot.sqlite3'
        if db.DB_PATH.exists():
            # SQLite backup includes WAL data consistently, without mutating live data.
            import sqlite3
            with sqlite3.connect(str(db.DB_PATH)) as source, sqlite3.connect(str(target)) as dest:source.backup(dest)
        db.DB_PATH=target
        db.initialize()
    base=(args.url or 'http://localhost').rstrip('/')
    errors=[]
    try:
        with sync_playwright() as playwright:
            browser=playwright.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
            context=browser.new_context(viewport={'width':1440,'height':1000},locale='ar-SA')
            if not args.url:context.route('**/*',browser_route)
            page=context.new_page();page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(base+'/',wait_until='networkidle')
            def startup():
                expect(page.locator('#filter-form')).to_be_visible()
                expect(page.locator('html')).to_have_attribute('dir','rtl')
                expect(page.locator('#navigation a')).to_have_count(14)
            record('Arabic RTL dashboard connects to backend',startup)
            real_count=page.evaluate("async()=> (await (await fetch('/api/opportunities')).json()).total")
            def real_rows():
                assert real_count>0, 'No persisted verified records in database'
                page.goto(base+'/tenders?status=',wait_until='networkidle')
                expect(page.locator('article.opportunity').first).to_be_visible()
            record('Persisted real opportunities display',real_rows)
            if real_count>0:
                record('Tender details show original HTTPS source',lambda:detail_test(page))
                record('Saved opportunity persists after reload',lambda:save_test(page,base))
                record('Tender and supplier actions use honest link labels',lambda:application_labels_test(page,base))
                record('Saved tracking notes persist and stay private',lambda:tracking_privacy_test(page,base,args.url))
            else:
                RESULTS.extend([{'test':name,'status':'Not Run','reason':'No actual data loaded'} for name in ['Tender details show original HTTPS source','Saved opportunity persists after reload','Tender and supplier actions use honest link labels','Saved tracking notes persist and stay private']])
            record('English language switch',lambda:language_test(page,base))
            record('Search and sector filter empty state',lambda:filter_test(page,base))
            record('Arabic and English search find persisted source records',lambda:real_search_test(page,base))
            record('Sector pages preserve open procurement filters and honest empty state',lambda:sector_test(page,base))
            record('Company profile persistence',lambda:company_test(page,base))
            record('Source health page renders',lambda:sources_test(page,base))
            record('API failure shows retry and recovers',lambda:network_error_test(page,base,args.url))
            record('Mobile viewport no horizontal overflow',lambda:mobile_test(page,base))
            record('Browser JavaScript has no uncaught errors',lambda:assert_no_errors(errors))
            context.close();browser.close()
    except Exception as exc:
        RESULTS.append({'test':'Playwright browser execution','status':'Not Run','reason':str(exc)[-4500:]})
        print('Browser blocked:',str(exc)[:500],flush=True)
    finally:
        db.DB_PATH=original_db
        if temp:temp.cleanup()
        report={'mode':mode,'base_url':base,'executed_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),'results':RESULTS,'summary':{s:sum(r['status']==s for r in RESULTS) for s in ['Passed','Failed','Not Run']}}
        Path(args.output).write_text(json.dumps(report,ensure_ascii=False,indent=2))
        print(json.dumps(report['summary']))
    if any(r['status']=='Failed' for r in RESULTS):return 1
    if any(r['status']=='Not Run' for r in RESULTS):return 2
    return 0


def detail_test(page):
    page.locator('a.card-title').first.click()
    expect(page.locator('#details')).to_be_visible()
    expect(page.locator('#detail-title')).not_to_be_empty()
    links=page.locator('#details a[target="_blank"]').all()
    assert links,'No original source link'
    for link in links:
        assert link.get_attribute('href').startswith('https://')
        assert 'noopener' in link.get_attribute('rel')
    page.locator('#details button[data-close]').click()


def save_test(page,base):
    button=page.locator('.bookmark').first
    rid=button.get_attribute('data-save')
    if button.get_attribute('data-is-saved')!='true':
        button.click()
        expect(page.locator(f'.bookmark[data-save="{rid}"]')).to_have_attribute('aria-pressed','true')
    page.goto(base+'/saved',wait_until='networkidle')
    expect(page.locator(f'.bookmark[data-save="{rid}"]')).to_be_visible()
    page.reload(wait_until='networkidle')
    expect(page.locator(f'.bookmark[data-save="{rid}"]')).to_have_attribute('aria-pressed','true')


def language_test(page,base):
    if page.locator('html').get_attribute('lang')!='en':page.locator('#lang-toggle').click()
    expect(page.locator('html')).to_have_attribute('lang','en')
    expect(page.locator('html')).to_have_attribute('dir','ltr')
    expect(page.locator('#navigation')).to_contain_text('All tenders')
    page.goto(base+'/manpower',wait_until='networkidle')
    expect(page.locator('#main h1')).to_contain_text('Manpower')


def get_json(page,path):
    return page.evaluate("async path=>{const response=await fetch(path);if(!response.ok)throw new Error('API '+response.status);return response.json()}",path)


def application_labels_test(page,base):
    records=get_json(page,'/api/opportunities?limit=200')['items']
    tenders=[r for r in records if r['kind'] in ('tender','rfq','rfp','qualification')]
    assert tenders,'No real procurement record available for action-label test'
    apply_label='Apply for tender' if page.locator('html').get_attribute('lang')=='en' else 'تقديم على المناقصة'
    register_label='Register as supplier' if page.locator('html').get_attribute('lang')=='en' else 'تسجيل كمورد'
    source_label='Original source' if page.locator('html').get_attribute('lang')=='en' else 'المصدر الأصلي'
    # Validate actual persisted data, including every submission-action claim.
    for r in records:
        if r.get('apply_url'):
            assert r.get('apply_verified') is True,'Unverified application link in actual API data'
            assert r['kind'] in ('tender','rfq','rfp','qualification','subcontract_announced')
            assert r['apply_url']!=r.get('registration_url'),'Registration mislabeled as tender submission'
    r=next((r for r in tenders if not r.get('apply_url')),tenders[0])
    page.goto(base+'/tenders/'+r['id'],wait_until='networkidle')
    expect(page.locator('#details')).to_be_visible()
    source=page.locator('#details').get_by_role('link',name=source_label,exact=True)
    expect(source).to_have_attribute('href',page.evaluate('(url)=>new URL(url).href',r['source_url']))
    if not r.get('apply_url') or r['status']!='open':
        expect(page.locator('#details').get_by_role('link',name=apply_label,exact=True)).to_have_count(0)
    else:
        expect(page.locator('#details').get_by_role('link',name=apply_label,exact=True)).to_have_attribute('href',r['apply_url'])
    supplier=next((r for r in records if r['kind']=='supplier_registration' and r.get('registration_url') and r.get('actionType')!='interest'),None)
    assert supplier,'No verified supplier portal available for label test'
    page.goto(base+'/tenders/'+supplier['id'],wait_until='networkidle')
    expect(page.locator('#details').get_by_role('link',name=register_label,exact=True)).to_have_attribute('href',supplier['registration_url'])
    expect(page.locator('#details').get_by_role('link',name=apply_label,exact=True)).to_have_count(0)
    page.locator('#details button[data-close]').click()


def tracking_privacy_test(page,base,is_network):
    saved=get_json(page,'/api/opportunities?saved=true')['items']
    assert saved,'Save prerequisite did not persist a source record'
    rid=saved[0]['id']
    notes='Browser audit private tracking note'
    page.goto(base+'/tracking',wait_until='networkidle')
    row=page.locator('article.opportunity').filter(has=page.locator(f'[data-track="{rid}"]'))
    row.locator('select').select_option('preparing')
    row.locator('textarea').fill(notes)
    with page.expect_response(lambda response:'/api/saved/'+rid in response.url and response.request.method=='POST') as pending:
        row.locator('[data-track]').click()
    assert pending.value.status==200,'Tracking write rejected'
    page.reload(wait_until='networkidle')
    row=page.locator('article.opportunity').filter(has=page.locator(f'[data-track="{rid}"]'))
    expect(row.locator('select')).to_have_value('preparing')
    expect(row.locator('textarea')).to_have_value(notes)
    other=page.context.browser.new_context()
    try:
        if not is_network:other.route('**/*',browser_route)
        other_page=other.new_page()
        other_page.goto(base+'/saved',wait_until='networkidle')
        expect(other_page.locator('#results .empty')).to_be_visible()
        assert get_json(other_page,'/api/opportunities?saved=true')['total']==0,'Saved records leaked between sessions'
        private=get_json(other_page,'/api/opportunities/'+rid)
        assert private['saved'] is False and private['tracking'] is None,'Private tracking notes leaked in public detail'
    finally:
        other.close()


def filter_test(page,base):
    page.goto(base+'/tenders?status=',wait_until='networkidle')
    page.locator('#filter-q').fill('zzzz_no_real_opportunity_12345')
    expect(page.locator('#results .empty')).to_be_visible(timeout=10000)
    page.locator('#more-filters').click()
    page.locator('#reset-filters').click()
    page.locator('#filter-sector').select_option('housekeeping')
    expect(page.locator('#filter-sector')).to_have_value('housekeeping')
    page.wait_for_timeout(600)
    assert 'sector=housekeeping' in page.url


def real_search_test(page,base):
    records=get_json(page,'/api/opportunities?procurement_only=true&limit=200')['items']
    for field in ('title','title_en'):
        record=next((r for r in records if r.get(field)),None)
        assert record,f'No actual {field} available for search verification'
        page.goto(base+'/tenders?status=',wait_until='networkidle')
        term=record[field]
        with page.expect_response(lambda response:'/api/opportunities?' in response.url and 'q=' in response.url) as pending:
            page.locator('#filter-q').fill(term)
        data=pending.value.json()
        assert record['id'] in [r['id'] for r in data['items']],f'{field} search missed its persisted source record'
        expect(page.locator(f'a.card-title[data-detail="{record["id"]}"]')).to_be_visible()
        assert all(r['kind'] in ('tender','rfq','rfp','qualification') for r in data['items']),'Search removed procurement boundary'


def sector_test(page,base):
    for route,sector in [('hotels','hospitality'),('manpower','manpower'),('housekeeping','housekeeping')]:
        expected=get_json(page,f'/api/opportunities?sector={sector}&status=open&procurement_only=true')
        page.goto(base+'/'+route,wait_until='networkidle')
        expect(page.locator('#filter-status')).to_have_value('open')
        expect(page.locator('#result-count')).to_contain_text(str(expected['total']))
        assert page.locator('article.opportunity').count()==len(expected['items'])
        assert all(r['status']=='open' and r['kind'] in ('tender','rfq','rfp','qualification') for r in expected['items'])
        if expected['total']==0:expect(page.locator('#results .empty')).to_be_visible()
        # Changing a form filter must retain the route's procurement-only boundary.
        with page.expect_response(lambda response:'/api/opportunities?' in response.url and 'sort=fit' in response.url) as pending:
            page.locator('#sort').select_option('fit')
        response=pending.value
        assert 'procurement_only=true' in response.url and 'status=open' in response.url,'Form updates lost sector procurement defaults'
        data=response.json()
        assert data['total']==expected['total']
        assert all(r['status']=='open' and r['kind'] in ('tender','rfq','rfp','qualification') for r in data['items'])
    # The current official saved snapshot really has no open Housekeeping tender.
    # This expectation is data-driven, so an actually collected new tender can appear.
    housekeeping=get_json(page,'/api/opportunities?sector=housekeeping&status=open&procurement_only=true')
    if not housekeeping['items']:
        expect(page.locator('#results .empty')).to_be_visible()
        expect(page.locator('article.opportunity')).to_have_count(0)


def company_test(page,base):
    page.goto(base+'/company',wait_until='networkidle')
    page.locator('#filter-companyName').fill('Browser integration company')
    page.locator('#filter-workers').fill('35')
    page.locator('input[name="sectors"][value="cleaning"]').check()
    with page.expect_response(lambda response: '/api/company' in response.url and response.request.method=='POST') as pending:
        page.locator('#company-form button[type="submit"]').click()
    assert pending.value.status==200,'Company API did not persist profile'
    expect(page.locator('#toast')).to_contain_text('Saved')
    page.reload(wait_until='networkidle')
    expect(page.locator('#filter-companyName')).to_have_value('Browser integration company')
    expect(page.locator('#filter-workers')).to_have_value('35')


def sources_test(page,base):
    page.goto(base+'/sources',wait_until='networkidle')
    expect(page.locator('#main')).to_contain_text('Daily refresh')
    sources=page.evaluate("async()=> (await (await fetch('/api/sources')).json()).items")
    expect(page.locator('.source')).to_have_count(len(sources))
    assert sorted(page.locator('.source .badge').all_text_contents())==sorted(source['status'] for source in sources)


def network_error_test(page,base,is_network):
    page.route('**/api/opportunities?**',lambda route:route.fulfill(status=503,content_type='application/json',body='{"error":"QA transient failure"}'))
    page.goto(base+'/tenders',wait_until='networkidle')
    expect(page.locator('[data-retry]')).to_be_visible()
    page.unroute('**/api/opportunities?**')
    page.locator('[data-retry]').click()
    expect(page.locator('[data-retry]')).not_to_be_visible()


def mobile_test(page,base):
    page.set_viewport_size({'width':390,'height':844})
    page.goto(base+'/tenders?status=',wait_until='networkidle')
    expect(page.locator('#filter-form')).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 2'), 'Horizontal overflow at 390px'
    Path(ROOT/'tests'/'artifacts').mkdir(exist_ok=True)
    page.screenshot(path=str(ROOT/'tests'/'artifacts'/'mobile.png'),full_page=True)


def assert_no_errors(errors):
    assert not errors, '\n'.join(errors)

if __name__=='__main__':sys.exit(main())
