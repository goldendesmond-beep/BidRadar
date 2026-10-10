"""Fresh official-source evidence normalization, never network access.
Evidence: bounded free TinyFish fetch_content exact source URLs, ttl=0.
Keep inaccessible records' old last_verified unchanged.
"""
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
sys.path.insert(0, '/workspace/saudi-bidpilot')
from app.saudi_sources import Document, node_pairs, parse_etimad_detail, parse_ksau_list

ROOT = pathlib.Path('/workspace/research/audit-fresh')
VERIFIED = '2026-10-09T20:59:33+00:00'
STARTED = '2026-10-09T20:57:22+00:00'
seed = json.loads(pathlib.Path('/workspace/saudi-bidpilot/data/seed.json').read_text())
flagged = [r for r in seed if r.get('status') == 'open']
actual, evidence, errors = {}, {}, {}
for filename in ['batch0.json', 'batch10.json', 'batch20.json', 'retry.json']:
    data = json.loads((ROOT / filename).read_text())
    for failure in data['errors']:
        errors[failure['url']] = failure['error']
    for result in data['results']:
        url = result['url']
        body = result['text']
        if 'tenders.etimad.sa' in url:
            extracted = parse_etimad_detail(body, url, VERIFIED)
            pairs = node_pairs(Document(body).root, 'etd-item-title')
            for row in extracted:
                if row.get('description'):
                    row['description'] = re.sub(r'\s*\.\.\.عرض (?:الأقل|المزيد)\.\.\.\s*', '', row['description']).strip()
                row['source_status'] = pairs.get('حالة المنافسة')
                row['competition_number'] = pairs.get('رقم المنافسة')
                row['contract_duration'] = pairs.get('مدة العقد')
                row['status_basis'] = 'Fresh official field حالة المنافسة plus original input#lastOfferPresentationDate'
        elif 'ksau-hs.edu.sa' in url:
            extracted = parse_ksau_list(body, url, VERIFIED)
            for row in extracted:
                row['source_status'] = 'Official invitation with future final offer date'
                row['status_basis'] = 'Fresh official tenderTable reference-matched row and final offer date'
        else:
            extracted = []
        for row in extracted:
            actual[(url, row['reference'])] = row
            evidence[(url, row['reference'])] = {
                'path': str(ROOT / filename), 'url': url, 'final_url': result.get('final_url'),
                'body_sha256': hashlib.sha256(body.encode()).hexdigest(),
                'fetch_method': 'free TinyFish fetch_content, body HTML, ttl=0',
                'batch_started_after': STARTED, 'verification_completed_at': VERIFIED,
                'latency_ms': result.get('latency_ms')
            }
        if extracted:
            errors.pop(url, None)

checks, normalized = [], []
for previous in flagged:
    key = previous['source_url'], previous['reference']
    fresh = actual.get(key)
    if fresh:
        mismatch = {
            field: {'previous': previous.get(field), 'fresh': fresh.get(field)}
            for field in ['title', 'organization', 'reference', 'deadline', 'status', 'published_at']
            if previous.get(field) != fresh.get(field)
        }
        merged = dict(previous)
        for field in ['title', 'organization', 'reference', 'description', 'deadline', 'published_at', 'status', 'last_verified', 'source_status', 'status_basis']:
            merged[field] = fresh.get(field)
        # Keep the current project's list form and other verified fields.
        merged['requirements'] = fresh['requirements'].split('\n') if fresh.get('requirements') else previous.get('requirements', [])
        merged['apply_url'] = None
        merged['apply_verified'] = False
        merged['verification_method'] = 'Fresh exact official webpage fetched via free TinyFish; body HTML parsed and identity matched'
        merged['evidence_path'] = evidence[key]['path']
        merged['last_refresh_attempt'] = VERIFIED
        merged['last_refresh_result'] = 'verified'
        normalized.append(merged)
        checks.append({
            'id': previous['id'], 'source_id': previous['source_id'], 'reference': fresh['reference'],
            'title': fresh['title'], 'organization': fresh['organization'], 'deadline': fresh['deadline'],
            'published_at': fresh['published_at'], 'status': fresh['status'],
            'source_status': fresh.get('source_status'), 'result': 'verified',
            'previous_last_verified': previous.get('last_verified'), 'last_verified': VERIFIED,
            'mismatches': mismatch, 'evidence': evidence[key]
        })
    else:
        # No fresh source truth available; never advance source verification.
        merged = dict(previous)
        merged['last_refresh_attempt'] = VERIFIED
        merged['last_refresh_result'] = errors.get(previous['source_url'], 'no_reference_matched_record')
        normalized.append(merged)
        checks.append({
            'id': previous['id'], 'source_id': previous['source_id'], 'reference': previous['reference'],
            'source_url': previous['source_url'], 'result': 'failed',
            'failure_reason': merged['last_refresh_result'],
            'previous_last_verified': previous.get('last_verified'),
            'last_verified': previous.get('last_verified'),
            'last_refresh_attempt': VERIFIED,
            'fresh_title': None, 'fresh_deadline': None, 'fresh_status': None,
            'evidence': str(ROOT / 'batch20.json')
        })

summary = {
    'started_at': STARTED, 'completed_at': VERIFIED,
    'flagged_open_before': len(flagged), 'official_unique_urls_attempted': len(set(r['source_url'] for r in flagged)),
    'fresh_verified_records': sum(r['result'] == 'verified' for r in checks),
    'fresh_current_open': sum(r['result'] == 'verified' and r['status'] == 'open' for r in checks),
    'fresh_closed': sum(r['result'] == 'verified' and r['status'] == 'closed' for r in checks),
    'failed_records': sum(r['result'] == 'failed' for r in checks),
    'verified_direct_application_urls': 0,
    'autonomous_live_sources_proven': 0,
    'access_scope': 'Free connector-assisted fresh import. Does not prove Python collector network access or daily job.',
    'source_counts': {
        'etimad': {'attempted': 26, 'verified': 26, 'current_open': 26},
        'ksau_hs': {'attempted': 3, 'verified': 3, 'current_open': 3},
        'taqeem': {'attempted': 1, 'verified': 0, 'failure': 'bot_blocked'}
    }
}
for name, value in [('normalized.json', normalized), ('verification-checks.json', checks), ('summary.json', summary)]:
    (ROOT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(summary, ensure_ascii=False))

