import csv
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from contextlib import closing
from dataclasses import replace

from engine import Settings, Job, Client, SafetyError, connect, initialize, import_csv, bounded_map, application_locks

ORG = '11111111-1111-1111-1111-111111111111'
APP = '22222222-2222-2222-2222-222222222222'
OTHER = '33333333-3333-3333-3333-333333333333'
H = 'A' * 64
KEEP = 'B' * 64


class FakeClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.rows = [{'applicationId': APP, 'applicationFileId': 'target', 'hash': H, 'isHashOnly': True},
                     {'applicationId': APP, 'applicationFileId': 'keep', 'hash': KEEP, 'isHashOnly': True}]
        self.deleted = []
        self.fail = False

    def application(self, app, os):
        if app != APP:
            raise SafetyError('Application organization mismatch or missing owner; blocked.')
        return {'applicationId': app, 'organizationId': ORG, 'osType': os, 'name': 'Fixture'}

    def files(self, app, search='', cancelled=lambda: False):
        return iter([r for r in self.rows if not search or r['hash'] == search])

    def delete(self, body):
        if self.fail:
            return False, 'HTTP 429'
        self.deleted.append(body)
        self.rows = [r for r in self.rows if r['applicationFileId'] != body['applicationFileId']]
        return True, 'HTTP 200'

    def close(self):
        pass


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make(self, mode='Bulk', rows=None):
        cfg = Settings(ORG, 'test-secret-do-not-log', mode=mode, workers=1)
        fake = FakeClient(cfg)
        job = Job(cfg, self.root, lambda _: fake)
        with (self.root/'input.csv').open('w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['ApplicationId', 'Hash', 'OsType', 'RecordType'])
            w.writerows(rows or [[APP, H, 2, 'SHA256']])
        return job, fake

    def wait(self, job):
        job.thread.join(10)
        self.assertFalse(job.active)

    def test_bulk_and_selective_execute(self):
        for mode in ['Bulk', 'Selective']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                original = self.root
                self.root = Path(tmp)
                job, fake = self.make(mode)
                job.start()
                self.wait(job)
                self.assertEqual(job.phase, 'Ready')
                self.assertEqual(fake.deleted, [])
                job.start(execute=True)
                self.wait(job)
                self.assertEqual(job.phase, 'Complete', job.message)
                self.assertEqual(job.snapshot()['verified'], 1)
                self.assertEqual([r['applicationFileId'] for r in fake.rows], ['keep'])
                self.assertEqual(fake.deleted[0]['organizationId'], ORG)
                self.assertNotIn('test-secret-do-not-log', (self.root/'summary.json').read_text())
                self.assertNotIn('test-secret-do-not-log', (self.root/'results.csv').read_text())
                self.root = original

    def test_all_apps_validated_before_deletion(self):
        job, fake = self.make(rows=[[APP, H, 2, 'HASH'], [OTHER, H, 2, 'HASH']])
        job.start()
        self.wait(job)
        self.assertEqual(job.phase, 'Failed')
        self.assertFalse(fake.deleted)
        with self.assertRaises(SafetyError):
            job.start(execute=True)

    def test_invalid_csv_blocks(self):
        job, fake = self.make(rows=[[APP, 'not-a-hash', 2, 'HASH']])
        job.start()
        self.wait(job)
        self.assertEqual(job.phase, 'Failed')
        self.assertFalse(fake.deleted)

    def test_duplicate_rows_deduplicated(self):
        job, _ = self.make(rows=[[APP, H, 2, 'HASH']] * 3)
        job.start()
        self.wait(job)
        self.assertEqual(job.snapshot()['duplicates'], 2)
        self.assertEqual(job.snapshot()['planned'], 1)

    def test_non_hash_only_skipped(self):
        job, fake = self.make()
        fake.rows[0]['isHashOnly'] = False
        job.start()
        self.wait(job)
        self.assertEqual(job.snapshot()['planned'], 0)
        self.assertEqual(job.snapshot()['unmatched'], 1)

    def test_ambiguous_post_not_retried(self):
        job, fake = self.make(rows=[[APP, H, 2, 'HASH'], [APP, KEEP, 2, 'HASH']])
        fake.fail = True
        job.start()
        self.wait(job)
        job.start(execute=True)
        self.wait(job)
        self.assertEqual(job.snapshot()['sent'], 1)
        self.assertEqual(job.snapshot()['verified'], 0)
        self.assertEqual(job.phase, 'Stopped / review required')
        self.assertIn('StillPresent', (self.root/'results.csv').read_text())

    def test_expired_preview(self):
        job, _ = self.make()
        job.start()
        self.wait(job)
        job.prepared_at = time.time()-1801
        with self.assertRaises(SafetyError):
            job.start(execute=True)

    def test_cancel_bounded_work(self):
        stop = False
        completed = []
        def work(x):
            nonlocal stop
            completed.append(x)
            stop = True
            return x
        list(bounded_map(work, range(1000), 1, lambda: stop))
        self.assertEqual(completed, [0])

    def test_application_metadata_strict(self):
        c = Client(Settings(ORG, 'secret'))
        for row in [{'applicationId': OTHER, 'organizationId': ORG, 'osType': 2},
                    {'applicationId': APP, 'organizationId': OTHER, 'osType': 2},
                    {'applicationId': APP, 'organizationId': ORG, 'osType': 1},
                    {'applicationId': APP, 'osType': 2}]:
            with patch.object(c, 'get', return_value=row), self.assertRaises(SafetyError):
                c.application(APP, 2)

    def test_cross_app_file_blocked(self):
        c = Client(Settings(ORG, 'secret'))
        with patch.object(c, 'get', return_value=[{'applicationId': OTHER, 'applicationFileId': 'x'}]):
            with self.assertRaises(SafetyError):
                list(c.files(APP))

    def test_repeated_page_blocked(self):
        c = Client(Settings(ORG, 'secret', page_size=100))
        rows = [{'applicationFileId': str(i)} for i in range(100)]
        with patch.object(c, 'get', return_value=rows), self.assertRaises(SafetyError):
            list(c.files(APP))

    def test_secret_not_in_repr(self):
        self.assertNotIn('sensitive', repr(Settings(ORG, 'sensitive')))

    def test_bad_host_blocked(self):
        with self.assertRaises(SafetyError):
            Settings(ORG, 'secret', instance='evil.example').validate()

    def test_recovery_reconciles_uncertain_without_replay(self):
        job,fake=self.make(rows=[[APP,H,2,'HASH'],[APP,KEEP,2,'HASH']])
        job.start();self.wait(job)
        with closing(connect(job.path)) as db:
            db.execute("UPDATE targets SET status='Reserved'")
            db.commit()
        # Simulate remote success followed by a crash before its outcome commit.
        fake.rows=[r for r in fake.rows if r['hash']!=H]
        restored=Job.restore(job.cfg,self.root,lambda _:fake)
        restored.start(recover=True);self.wait(restored)
        self.assertEqual(restored.phase,'Ready',restored.message)
        self.assertEqual(restored.snapshot()['planned'],1)
        self.assertFalse(fake.deleted)
        restored.start(execute=True);self.wait(restored)
        self.assertEqual(restored.phase,'Complete',restored.message)
        self.assertEqual([r['hash'] for r in fake.deleted],[KEEP])

    def test_recovery_wrong_org_blocked(self):
        job,fake=self.make();job.start();self.wait(job)
        with self.assertRaises(SafetyError):
            Job.restore(replace(job.cfg,org=OTHER),self.root,lambda _:fake)

    def test_recovery_changed_hash_blocked(self):
        job,fake=self.make();job.start();self.wait(job)
        fake.rows[0]['hash']='C'*64
        recovered=Job.restore(job.cfg,self.root,lambda _:fake)
        recovered.start(recover=True);self.wait(recovered)
        self.assertEqual(recovered.phase,'Failed')
        self.assertFalse(fake.deleted)

    def test_recovery_changed_rule_blocked(self):
        job,fake=self.make();job.start();self.wait(job)
        fake.rows[0]['isHashOnly']=False
        recovered=Job.restore(job.cfg,self.root,lambda _:fake)
        recovered.start(recover=True);self.wait(recovered)
        self.assertEqual(recovered.phase,'Failed')
        self.assertFalse(fake.deleted)

    def test_short_pages_continue_until_empty(self):
        c=Client(Settings(ORG,'secret',page_size=1000))
        pages=[[{'applicationFileId':str(i)} for i in range(25)],
               [{'applicationFileId':str(i)} for i in range(25,30)],[]]
        with patch.object(c,'get',side_effect=pages) as query:
            self.assertEqual(len(list(c.files(APP))),30)
            self.assertEqual(query.call_count,3)
            self.assertTrue(all(call.args[1]['applicationId']==APP for call in query.call_args_list))

    def test_partial_overlapping_pages_blocked(self):
        c=Client(Settings(ORG,'secret',page_size=100))
        pages=[[{'applicationFileId':'1'},{'applicationFileId':'2'}],
               [{'applicationFileId':'2'},{'applicationFileId':'3'}]]
        with patch.object(c,'get',side_effect=pages),self.assertRaises(SafetyError):
            list(c.files(APP))

    def test_durable_batch_reduces_commits(self):
        values=[f'{i:064X}' for i in range(200)]
        job,fake=self.make(rows=[[APP,h,2,'HASH'] for h in values])
        fake.rows=[dict(applicationId=APP,applicationFileId=str(i),hash=h,isHashOnly=True) for i,h in enumerate(values)]
        job.start();self.wait(job)
        job.start(execute=True);self.wait(job)
        self.assertEqual(job.phase,'Complete',job.message)
        self.assertLess(job.snapshot()['deletion_commits'],10)
        self.assertTrue(all(r['applicationId']==APP for r in fake.deleted))

    def test_throttling_reduces_capacity(self):
        c=Client(Settings(ORG,'secret',workers=6))
        from types import SimpleNamespace
        c.throttle(SimpleNamespace(status_code=429,headers={'Retry-After':'2'}))
        self.assertEqual(c.capacity,3)
        self.assertEqual(c.throttles,1)

    def test_local_application_lock(self):
        cfg=Settings(ORG,'secret')
        with application_locks(cfg,[APP]):
            with self.assertRaises(SafetyError):
                with application_locks(cfg,[APP]):
                    pass
        with application_locks(cfg,[APP]):
            pass

    def test_same_hash_in_other_app_never_deleted(self):
        job,fake=self.make(mode='Selective')
        fake.rows.append(dict(applicationId=OTHER,applicationFileId='other',hash=H,isHashOnly=True))
        original_files=fake.files
        fake.files=lambda app,search='',cancelled=lambda:False: iter([r for r in original_files(app,search,cancelled) if r['applicationId']==app])
        job.start();self.wait(job)
        self.assertEqual(job.snapshot()['planned'],1)
        job.start(execute=True);self.wait(job)
        self.assertEqual(job.phase,'Complete')
        self.assertTrue(any(r['applicationFileId']=='other' for r in fake.rows))


if __name__ == '__main__':
    unittest.main()
