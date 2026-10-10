"""Daily collection contracts missing from the original regression suite.

Only recorded official HTML and injected transports are used. Neither fixtures nor
their LIVE states enter the application's persistent database or call the network.
"""
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import database as db, saudi_sources as sources

collector = importlib.import_module('app.refresh')
FRESH = '2026-10-09T16:00:00+00:00'
PREVIOUS = '2026-10-09T13:00:00+00:00'


def snapshot_results(filename):
    raw = json.loads((db.ROOT / 'data' / 'verification' / filename).read_text())
    if 'content' in raw:
        raw = json.loads('\n'.join(x['text'] for x in raw['content'] if x.get('type') == 'text'))
    return raw['results']


def official_response(source_id):
    source = next(s for s in sources.SOURCES if s.id == source_id)
    filename = 'current0.json' if source_id == 'etimad' else 'bodyRecords.json'
    for row in snapshot_results(filename):
        url = row.get('final_url') or row['url']
        if urlsplit(url).hostname in source.hosts:
            records = sources.parse_public_html(source, row.get('text', ''), url, PREVIOUS)
            if records:
                return source, sources.Response(url, row['text'], 200, 'text/html'), records[0]
    raise AssertionError('No parseable official snapshot for ' + source_id)


class InjectedFetcher:
    """Deterministic allowlisted responses, including real denial outcomes."""
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def fetch(self, url, hosts):
        sources.safe_url(url, hosts)
        self.calls.append(url)
        response = self.routes.get(url)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise AssertionError('Unexpected HTTP request: ' + url)
        return response


class KnownOfficialDetailContracts(unittest.TestCase):
    def test_etimad_known_detail_is_refreshed_when_visitor_discovery_is_degraded(self):
        source, response, original = official_response('etimad')
        transport = InjectedFetcher({source.url: sources.Response(source.url, '<html>Public visitor listing unavailable</html>', 200, 'text/html'), response.url: response})
        with patch.object(sources, 'utc_now', return_value=FRESH):
            result = sources.probe(source, transport, known_urls=[response.url])
        self.assertIn(response.url, transport.calls)
        self.assertEqual(result['status'], 'DEGRADED')
        self.assertEqual(result['extracted_count'], 1)
        self.assertEqual(result['records'][0]['reference'], original['reference'])
        self.assertEqual(result['records'][0]['last_verified'], FRESH)
        self.assertIsNone(result['records'][0]['apply_url'])
        self.assertEqual(result['records'][0]['verification_method'], 'live_public_fetch')
        self.assertEqual(result['verification_failures'], [])

    def test_known_detail_failure_is_recorded_without_inventing_extraction(self):
        source, response, _ = official_response('etimad')
        transport = InjectedFetcher({source.url: sources.FetchError('DEGRADED', 'public_list_unavailable'), response.url: sources.FetchError('BLOCKED', 'http_403')})
        with patch.object(sources, 'utc_now', return_value=FRESH):
            result = sources.probe(source, transport, known_urls=[response.url])
        self.assertIn(response.url, transport.calls)
        self.assertNotEqual(result['status'], 'LIVE')
        self.assertEqual(result['records'], [])
        self.assertEqual(result['extracted_count'], 0)
        self.assertIsNone(result['last_successful_update'])
        failure = result['verification_failures'][0]
        self.assertEqual(failure['source_url'], response.url)
        self.assertEqual(failure['status'], 'BLOCKED')
        self.assertEqual(failure['reason'], 'http_403')
        self.assertEqual(failure['last_checked'], FRESH)

    def test_known_detail_urls_are_deduplicated_and_cannot_escape_source_allowlist(self):
        source, response, _ = official_response('etimad')
        transport = InjectedFetcher({source.url: sources.Response(source.url, '<html>No verified list records</html>', 200, 'text/html'), response.url: response})
        result = sources.probe(source, transport, known_urls=[response.url, response.url, 'https://evil.example/injected-detail'])
        self.assertEqual(transport.calls.count(response.url), 1)
        self.assertNotIn('https://evil.example/injected-detail', transport.calls)
        self.assertEqual(result['extracted_count'], 1)

    def test_failed_taqeem_detail_does_not_turn_shallow_listing_into_full_verification(self):
        source, detail, original = official_response('taqeem')
        # DOM-shape fixture surrounds the title/reference of an actual official
        # record. It does not add a production opportunity or claim LIVE access.
        relative = urlsplit(detail.url).path
        listing = '<article><span class="ot-overflow">' + original['title'] + '</span><a href="' + relative + '">Details</a><span class="ot-rec-active">Active</span></article>'
        transport = InjectedFetcher({source.url: sources.Response(source.url, listing, 200, 'text/html'), detail.url: sources.FetchError('BLOCKED', 'http_403')})
        result = sources.probe(source, transport)
        self.assertEqual(result['status'], 'DEGRADED')
        self.assertEqual(result['extracted_count'], 0)
        self.assertEqual(result['records'], [])
        self.assertEqual(result['verification_failures'][0]['source_url'], detail.url)


class PersistedRefreshContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bidpilot-contract-qa-')
        self.original_path = db.DB_PATH
        db.DB_PATH = Path(self.tmp.name) / 'test.sqlite3'
        db.initialize()
        self.source, self.response, self.record = official_response('etimad')
        self.record.update(status='open', last_verified=PREVIOUS, verification_method='official_snapshot_import')
        self.stored = db.upsert(self.record)
        self.seed_patch = patch.object(collector, 'seed', return_value={'imported': 0})
        self.sources_patch = patch.object(sources, 'SOURCES', (self.source,))
        self.time_patch = patch.object(sources, 'utc_now', return_value=FRESH)
        self.today_patch = patch.object(db, 'today', return_value='2026-10-09')
        for p in [self.seed_patch, self.sources_patch, self.time_patch, self.today_patch]:
            p.start()

    def tearDown(self):
        for p in [self.today_patch, self.time_patch, self.sources_patch, self.seed_patch]:
            p.stop()
        db.DB_PATH = self.original_path
        self.tmp.cleanup()

    def transport(self, detail_response):
        return InjectedFetcher({self.source.url: sources.Response(self.source.url, '<html>No verified list records</html>', 200, 'text/html'), self.response.url: detail_response})

    def test_refresh_supplies_existing_detail_urls_and_keeps_identity_and_evidence(self):
        transport = self.transport(self.response)
        result = collector.refresh(transport)
        self.assertIn(self.response.url, transport.calls)
        after = db.detail(self.stored['id'])
        self.assertEqual(after['reference'], self.stored['reference'])
        self.assertEqual(after['last_verified'], FRESH)
        self.assertEqual(after['verification_status'], 'verified')
        self.assertEqual(db.summary()['total'], 1)
        health = result['sources'][0]
        self.assertEqual(health['status'], 'DEGRADED')
        self.assertEqual(health['records_extracted'], 1)
        self.assertTrue(health['automatic_runtime_verified'])
        self.assertTrue(health['last_success'])

    def test_failed_fresh_check_preserves_prior_evidence_but_does_not_claim_confirmed_open(self):
        result = collector.refresh(self.transport(sources.FetchError('BLOCKED', 'http_403')))
        after = db.detail(self.stored['id'])
        self.assertEqual(after['last_verified'], PREVIOUS)
        self.assertEqual(after['reference'], self.stored['reference'])
        self.assertEqual(after['deadline'], self.stored['deadline'])
        self.assertEqual(after['verification_status'], 'failed')
        self.assertEqual(after['last_verification_attempt'], FRESH)
        self.assertEqual(after['verification_error'], 'http_403')
        self.assertEqual(after['status'], 'unknown')
        self.assertEqual(db.summary()['open'], 0)
        self.assertFalse(result['sources'][0]['automatic_runtime_verified'])
        self.assertEqual(result['sources'][0]['records_extracted'], 0)

    def test_successful_retry_restores_fresh_verification_and_deduplicates(self):
        collector.refresh(self.transport(sources.FetchError('BLOCKED', 'http_403')))
        collector.refresh(self.transport(self.response))
        after = db.detail(self.stored['id'])
        self.assertEqual(after['verification_status'], 'verified')
        self.assertEqual(after['last_verified'], FRESH)
        self.assertEqual(after['status'], 'open')
        self.assertFalse(after.get('verification_error'))
        self.assertEqual(db.summary()['total'], 1)
        with db.connect() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM runs WHERE finished_at IS NOT NULL').fetchone()[0], 2)

    def test_exception_clears_current_extraction_count_but_keeps_previous_success_timestamp(self):
        db.set_source({'id': self.source.id, 'name': self.source.name, 'url': self.source.url, 'status': 'LIVE', 'last_success': PREVIOUS, 'records_extracted': 7, 'automatic_runtime_verified': True})
        with patch.object(sources, 'probe', side_effect=RuntimeError('adapter failed')):
            result = collector.refresh(InjectedFetcher({}))
        health = result['sources'][0]
        self.assertEqual(health['status'], 'UNAVAILABLE')
        self.assertEqual(health['records_extracted'], 0)
        self.assertFalse(health['automatic_runtime_verified'])
        self.assertEqual(health['last_success'], PREVIOUS)
        self.assertEqual(db.detail(self.stored['id'])['last_verified'], PREVIOUS)


if __name__ == '__main__':
    unittest.main(verbosity=2)
