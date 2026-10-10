"""Audit contracts; synthetic records are isolated in temporary SQLite databases."""
import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import database as db, server
from test_app import fixture, request


class AuditProcurementContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bidpilot-audit-')
        self.old_path = db.DB_PATH
        db.DB_PATH = Path(self.tmp.name) / 'audit.sqlite3'
        server.RATE.clear()
        db.initialize()
        for kind in ('tender', 'rfq', 'rfp', 'qualification'):
            db.upsert(fixture(id='open-' + kind, reference='open-' + kind,
                              title='عقد نظافة وتوريد عمالة', kind=kind, sectors=['hospitality', 'manpower']))
        db.upsert(fixture(id='closed-housekeeping', reference='closed-housekeeping',
                          status='closed', sectors=['housekeeping', 'hospitality']))
        db.upsert(fixture(id='awarded-housekeeping', reference='awarded-housekeeping',
                          status='awarded', sectors=['housekeeping', 'hospitality']))
        db.upsert(fixture(id='supplier-housekeeping', reference='supplier-housekeeping',
                          kind='supplier_registration', sectors=['housekeeping', 'hospitality', 'manpower'],
                          registration_url='https://example.com/supplier-registration',
                          registration_verified=True))
        db.upsert(fixture(id='potential-housekeeping', reference='potential-housekeeping',
                          kind='subcontract_potential', sectors=['housekeeping', 'hospitality', 'manpower']))

    def tearDown(self):
        db.DB_PATH = self.old_path
        self.tmp.cleanup()

    def listing(self, **params):
        response = request('/api/opportunities?' + urlencode(params))
        self.assertEqual(response['status'], 200)
        return response['json']

    def test_procurement_listing_excludes_registration_and_inferred_leads(self):
        found = self.listing(procurement_only='true', sector='manpower', status='open')
        self.assertEqual(found['total'], 4)
        self.assertEqual({row['kind'] for row in found['items']}, {'tender', 'rfq', 'rfp', 'qualification'})
        self.assertEqual({row['status'] for row in found['items']}, {'open'})

    def test_housekeeping_open_empty_preserves_the_archive_and_supplier_route(self):
        self.assertEqual(self.listing(procurement_only='true', sector='housekeeping', status='open')['total'], 0)
        archive = self.listing(procurement_only='true', sector='housekeeping')
        self.assertEqual({r['id'] for r in archive['items']}, {'closed-housekeeping', 'awarded-housekeeping'})
        suppliers = self.listing(kind='supplier_registration', sector='housekeeping')
        self.assertEqual([r['id'] for r in suppliers['items']], ['supplier-housekeeping'])
        self.assertEqual(suppliers['items'][0]['status'], 'registration_available')

    def test_procurement_search_filters_and_export_keep_the_same_boundary(self):
        params = {'procurement_only': 'true', 'sector': 'hospitality', 'status': 'open', 'q': 'نظافة'}
        found = self.listing(**params)
        self.assertEqual(found['total'], 4)
        exported = request('/api/export.csv?' + urlencode(params))
        self.assertEqual(exported['status'], 200)
        rows = list(csv.DictReader(io.StringIO(exported['body'].decode('utf-8-sig'))))
        self.assertEqual(len(rows), found['total'])
        self.assertTrue(all(r['kind'] in {'tender', 'rfq', 'rfp', 'qualification'} and r['status'] == 'open' for r in rows))
        self.assertEqual(self.listing(procurement_only='true', sector='hospitality', status='closed')['total'], 1)

    def test_session_tracking_isolation_in_detail_response(self):
        first = request('/api/session')
        first_cookie = first['headers']['Set-Cookie'].split(';')[0]
        result = request('/api/saved/open-tender', 'POST', {'stage': 'preparing', 'notes': 'Private offer note'},
                         cookie=first_cookie, csrf=first['json']['csrf'])
        self.assertEqual(result['status'], 200)
        private = request('/api/opportunities/open-tender', cookie=first_cookie)['json']
        self.assertTrue(private['saved'])
        self.assertEqual(private['tracking']['notes'], 'Private offer note')
        second = request('/api/session')
        second_cookie = second['headers']['Set-Cookie'].split(';')[0]
        public = request('/api/opportunities/open-tender', cookie=second_cookie)['json']
        self.assertFalse(public['saved'])
        self.assertIsNone(public['tracking'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
