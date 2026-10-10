"""Exercise daily import against the actual WSGI API in a temporary database."""
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
from app import database as db,server
from test_app import request

spec=importlib.util.spec_from_file_location('hosted_sync',db.ROOT/'scripts/sync_hosted.py')
sync_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(sync_module)

class HostedSyncContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.original=db.DB_PATH
        db.DB_PATH=Path(self.temp.name)/'hosted.sqlite3';db.initialize();server.RATE.clear()
    def tearDown(self):db.DB_PATH=self.original;self.temp.cleanup()
    def test_actual_admin_import_persists_real_records_and_deduplicates(self):
        records=json.loads((db.ROOT/'data/seed.json').read_text())[:3]
        def send(req,timeout):
            response=request(urlsplit(req.full_url).path,method=req.method,body=req.data,headers={'HTTP_AUTHORIZATION':req.get_header('Authorization')})
            self.assertEqual(response['status'],200)
            return io.BytesIO(response['body'])
        with patch.object(server,'ADMIN_TOKEN','audit-only-test-token-'+'x'*32):
            first=sync_module.sync(records,'https://authorized.example','audit-only-test-token-'+'x'*32,send)
            second=sync_module.sync(records,'https://authorized.example','audit-only-test-token-'+'x'*32,send)
        self.assertEqual(first['records_acknowledged'],3);self.assertEqual(second['records_acknowledged'],3)
        self.assertEqual(db.summary()['total'],3)
        for record in records:
            actual=db.detail(record['id'])
            self.assertEqual(actual['last_verified'],record['last_verified'])
            self.assertEqual(actual['source_url'],record['source_url'])
    def test_bridge_rejects_insecure_origin_token_and_bad_acknowledgement(self):
        for endpoint in ['http://authorized.example','https://localhost','https://127.0.0.1','https://user:pass@authorized.example','https://authorized.example/untrusted']:
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):sync_module.sync([],endpoint,'x'*40)
        with self.assertRaises(ValueError):sync_module.sync([],'https://authorized.example','short')
        records=json.loads((db.ROOT/'data/seed.json').read_text())[:1]
        with self.assertRaises(RuntimeError):sync_module.sync(records,'https://authorized.example','x'*40,lambda request,timeout:io.BytesIO(b'{"imported":0}'))

if __name__=='__main__':unittest.main()
