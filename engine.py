"""Application-scoped deletion engine. Credentials never enter the audit database.

Only GETs are retried. POST outcomes are reconciled by a subsequent read, never
blindly replayed. Workers receive bounded tasks; SQLite holds large plans.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

import requests


class SafetyError(Exception):
    pass


class Cancelled(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    org: str
    token: str = field(repr=False)
    instance: str = 'd'
    user_instance: str = 'D'
    workers: int = 6
    mode: str = 'Selective'
    page_size: int = 1000
    timeout: int = 60

    def validate(self):
        try:
            uuid.UUID(self.org)
        except ValueError:
            raise SafetyError('Organization ID must be a UUID.') from None
        if not self.token.strip() or any(c in self.token for c in '\r\n'):
            raise SafetyError('A valid authorization value is required.')
        if not re.fullmatch('[a-z]', self.instance):
            raise SafetyError('API instance must be one lowercase letter.')
        if not re.fullmatch('[A-Za-z]', self.user_instance):
            raise SafetyError('UserInstance must be one letter.')
        if not 1 <= self.workers <= 16 or not 100 <= self.page_size <= 10000:
            raise SafetyError('Invalid worker count or page size.')
        if self.mode not in ('Selective', 'Bulk') or not 10 <= self.timeout <= 120:
            raise SafetyError('Invalid lookup mode or timeout.')

    @property
    def base(self):
        return f'https://portalapi.{self.instance}.threatlocker.com/portalApi'


def hashes(row):
    return {str(row.get(k) or '').strip().upper()
            for k in ('hash', 'originalHash', 'sha256', 'sha256Hash')} - {''}


class Client:
    def __init__(self, settings):
        self.cfg = settings
        self.local = threading.local()
        self.sessions = []
        self.lock = threading.Lock()

    def session(self):
        if not hasattr(self.local, 'session'):
            s = requests.Session()
            s.headers.update({'Authorization': self.cfg.token,
                              'ManagedOrganizationId': self.cfg.org,
                              'OverrideManagedOrganizationId': self.cfg.org,
                              'UserInstance': self.cfg.user_instance,
                              'UseNewSearch': 'true',
                              'Origin': 'https://portal.threatlocker.com',
                              'Referer': 'https://portal.threatlocker.com/'})
            self.local.session = s
            with self.lock:
                self.sessions.append(s)
        return self.local.session

    def close(self):
        for s in self.sessions:
            s.close()

    def get(self, endpoint, params):
        for attempt in range(4):
            try:
                r = self.session().get(self.cfg.base + endpoint, params=params,
                                       timeout=(10, self.cfg.timeout), allow_redirects=False)
            except requests.RequestException:
                if attempt == 3:
                    raise SafetyError('GET failed after retries (network/timeout).') from None
                time.sleep(2 ** attempt)
                continue
            if r.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                try:
                    delay = min(60, max(1, float(r.headers.get('Retry-After', 2 ** attempt))))
                except ValueError:
                    delay = 2 ** attempt
                time.sleep(delay)
                continue
            if r.status_code != 200:
                raise SafetyError(f'GET failed: HTTP {r.status_code}. Check authorization, organization and instance.')
            try:
                return r.json()
            except ValueError:
                raise SafetyError('GET returned invalid JSON.') from None

    def application(self, app_id, os_type):
        row = self.get('/Application/ApplicationGetById', {'applicationId': app_id})
        if not isinstance(row, dict):
            raise SafetyError('Unexpected application response.')
        if str(row.get('applicationId', '')).lower() != app_id:
            raise SafetyError('Application ID mismatch; blocked.')
        if str(row.get('organizationId', '')).lower() != self.cfg.org.lower():
            raise SafetyError('Application organization mismatch or missing owner; blocked.')
        if str(row.get('osType')) != str(os_type):
            raise SafetyError('Application OS differs from CSV; blocked.')
        return row

    def files(self, app_id, search='', cancelled=lambda: False):
        size = self.cfg.page_size if not search else 100
        page = 1
        # Page fingerprints bound memory by number of pages, not application size.
        seen_pages = set()
        while True:
            if cancelled():
                raise Cancelled()
            rows = self.get('/ApplicationFile/ApplicationFileGetByApplicationId', {
                'applicationId': app_id, 'searchText': search, 'pageNumber': page,
                'pageSize': size, 'hashOnly': 'false', 'isCustomRule': 'false',
                'showTotalCount': 'false'})
            if not isinstance(rows, list):
                raise SafetyError('Unexpected application-file response; blocked.')
            ids = []
            for row in rows:
                if not isinstance(row, dict) or not row.get('applicationFileId'):
                    raise SafetyError('File is missing its ID; blocked.')
                if row.get('applicationId') and str(row['applicationId']).lower() != app_id:
                    raise SafetyError('Returned file belongs to another application; blocked.')
                ids.append(str(row['applicationFileId']))
            fingerprint = hashlib.sha256('\0'.join(ids).encode()).digest()
            if rows and (fingerprint in seen_pages or len(ids) != len(set(ids))):
                raise SafetyError('Repeated page or file ID; blocked.')
            seen_pages.add(fingerprint)
            yield from rows
            if len(rows) < size:
                break
            page += 1

    def delete(self, body):
        try:
            r = self.session().post(self.cfg.base + '/ApplicationFile/ApplicationFileDeleteById',
                                    json=body, timeout=(10, self.cfg.timeout), allow_redirects=False)
            return 200 <= r.status_code < 300, f'HTTP {r.status_code}'
        except requests.RequestException:
            return False, 'Network/timeout; outcome unknown (not retried)'


def connect(path):
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    return db


def initialize(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS requested (
            app TEXT, hash TEXT, os INTEGER, kind TEXT,
            PRIMARY KEY(app,hash));
        CREATE TABLE IF NOT EXISTS applications (
            app TEXT PRIMARY KEY, name TEXT, os INTEGER, mode TEXT);
        CREATE TABLE IF NOT EXISTS targets (
            app TEXT, fid TEXT, hash TEXT, body TEXT,
            status TEXT DEFAULT 'Planned', detail TEXT DEFAULT '',
            PRIMARY KEY(app,fid));
        CREATE INDEX IF NOT EXISTS target_hash ON targets(app,hash);
        CREATE TABLE IF NOT EXISTS matched(app TEXT, hash TEXT, PRIMARY KEY(app,hash));
    ''')


def import_csv(db, path, cancelled=lambda: False):
    count = duplicates = 0
    with Path(path).open('r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        normalized = [h.strip().lower() for h in header]
        if len(set(normalized)) != len(normalized) or not {'applicationid', 'hash', 'ostype'} <= set(normalized):
            raise SafetyError('CSV requires unique ApplicationId, Hash, OsType columns. RecordType is optional.')
        for line, raw in enumerate(reader, 2):
            if cancelled():
                raise Cancelled()
            if None in raw:
                raise SafetyError(f'CSV row {line}: too many fields.')
            row = {k.strip().lower(): (v or '').strip() for k, v in raw.items()}
            try:
                app = str(uuid.UUID(row['applicationid']))
                os_type = int(row['ostype'])
            except ValueError:
                raise SafetyError(f'CSV row {line}: invalid application UUID or numeric OS type.') from None
            if os_type not in (1, 2):
                raise SafetyError(f'CSV row {line}: supported OS types are 1 (Windows) and 2 (macOS).')
            h = row['hash'].upper()
            kind = row.get('recordtype', 'HASH').upper() or 'HASH'
            kind = {'SHA256': 'SHA256ONLY', 'SHA-256': 'SHA256ONLY'}.get(kind, kind)
            if kind not in ('HASH', 'SHA256ONLY') or not re.fullmatch(r'(?:[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64})', h):
                raise SafetyError(f'CSV row {line}: invalid hexadecimal hash or RecordType.')
            if kind == 'SHA256ONLY' and len(h) != 64:
                raise SafetyError(f'CSV row {line}: SHA256 requires 64 hexadecimal characters.')
            previous = db.execute('SELECT os,kind FROM requested WHERE app=? AND hash=?', (app, h)).fetchone()
            if previous and (previous['os'] != os_type or previous['kind'] != kind):
                raise SafetyError(f'CSV row {line}: conflicting duplicate.')
            duplicates += bool(previous)
            db.execute('INSERT OR IGNORE INTO requested VALUES (?,?,?,?)', (app, h, os_type, kind))
            count += 1
            if count % 10000 == 0:
                db.commit()
    if not count:
        raise SafetyError('CSV is empty.')
    if db.execute('SELECT app FROM requested GROUP BY app HAVING COUNT(DISTINCT os)>1').fetchone():
        raise SafetyError('One application has conflicting OS types.')
    db.commit()
    return count, duplicates


def bounded_map(fn, values, workers, cancelled=lambda: False):
    """Never queue more than workers requests, and stop submitting on cancellation."""
    iterator = iter(values)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = set()
        while True:
            while len(pending) < workers and not cancelled():
                try:
                    value = next(iterator)
                except StopIteration:
                    break
                pending.add(pool.submit(fn, value))
            if not pending:
                return
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                yield future.result()


class Job:
    def __init__(self, cfg, directory, client_factory=Client):
        cfg.validate()
        self.cfg = cfg
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'audit.sqlite3'
        self.client_factory = client_factory
        self.stop = threading.Event()
        self.lock = threading.RLock()
        self.thread = None
        self.phase = 'New'
        self.message = ''
        self.counts = {}
        self.started = time.time()
        self.finished = None
        self.prepared_at = None

    def snapshot(self):
        with self.lock:
            return dict(phase=self.phase, message=self.message, **self.counts,
                        elapsed=round((self.finished or time.time())-self.started, 1))

    def update(self, phase=None, message=None, **counts):
        with self.lock:
            if phase:
                self.phase = phase
            if message is not None:
                self.message = message
            self.counts.update(counts)

    @property
    def active(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, execute=False):
        if self.active:
            raise SafetyError('A job is already running.')
        if execute and (self.phase != 'Ready' or time.time() - self.prepared_at > 1800):
            raise SafetyError('A successful dry run from the last 30 minutes is required.')
        self.stop.clear()
        self.started = time.time()
        self.finished = None
        self.thread = threading.Thread(target=self._run, args=(execute,), daemon=True)
        self.thread.start()

    def _run(self, execute):
        client = self.client_factory(self.cfg)
        db = connect(self.path)
        try:
            initialize(db)
            if execute:
                self.execute(db, client)
            else:
                self.prepare(db, client)
        except Cancelled:
            self.update('Stopped', 'Stopped. No new requests will be submitted.')
        except Exception as e:
            # Never expose arbitrary exception strings, HTTP bodies, or credentials.
            message = str(e) if isinstance(e, SafetyError) else f'{type(e).__name__}; inspect local inputs or contact support.'
            self.update('Failed', message)
        finally:
            db.commit()
            db.close()
            client.close()
            self.finished = time.time()
            self.export()

    def prepare(self, db, client):
        self.update('Validating', 'Importing CSV into the disk-backed plan.')
        count, duplicates = import_csv(db, self.directory / 'input.csv', self.stop.is_set)
        self.update(rows=count, duplicates=duplicates, requested=count-duplicates)
        # Validate ALL applications before discovering any deletion candidates.
        apps = db.execute('SELECT app,MIN(os) os,COUNT(*) n FROM requested GROUP BY app').fetchall()
        metadata = {}
        for group in apps:
            if self.stop.is_set():
                raise Cancelled()
            app_id = group['app']
            app = client.application(app_id, group['os'])
            metadata[app_id] = app
            db.execute('INSERT INTO applications VALUES (?,?,?,?)',
                       (app_id, str(app.get('name', '')), group['os'], self.cfg.mode))
        db.commit()
        self.update('Discovering', applications=len(apps), scanned=0, planned=0)
        scanned = 0

        def add(app_id, row, requested_hashes):
            nonlocal scanned
            scanned += 1
            if row.get('isHashOnly') is not True and row.get('isHashOnly') not in ('true', 'True'):
                return
            matches = hashes(row) & requested_hashes
            if not matches:
                return
            for h in matches:
                db.execute('INSERT OR IGNORE INTO matched VALUES (?,?)', (app_id, h))
            app = metadata[app_id]
            body = dict(row, osType=app['osType'], applicationName=app.get('name', ''), organizationId=self.cfg.org)
            db.execute('INSERT OR IGNORE INTO targets(app,fid,hash,body) VALUES (?,?,?,?)',
                       (app_id, str(row['applicationFileId']), sorted(matches)[0], json.dumps(body)))

        for group in apps:
            app_id = group['app']
            self.update(message=f'{self.cfg.mode} lookup: {app_id}')
            if self.cfg.mode == 'Bulk':
                for row in client.files(app_id, cancelled=self.stop.is_set):
                    hs = hashes(row)
                    wanted = {h for h in hs if db.execute('SELECT 1 FROM requested WHERE app=? AND hash=?', (app_id, h)).fetchone()}
                    add(app_id, row, wanted)
                    if scanned % 1000 == 0:
                        db.commit()
                        self.update(scanned=scanned, planned=db.execute('SELECT COUNT(*) FROM targets').fetchone()[0])
            else:
                def lookup(h):
                    return h, list(client.files(app_id, h, self.stop.is_set))
                source = (r[0] for r in db.execute('SELECT hash FROM requested WHERE app=?', (app_id,)))
                for h, rows in bounded_map(lookup, source, self.cfg.workers, self.stop.is_set):
                    for row in rows:
                        add(app_id, row, {h})
                    self.update(scanned=scanned)
            db.commit()
        if self.stop.is_set():
            raise Cancelled()
        planned = db.execute('SELECT COUNT(*) FROM targets').fetchone()[0]
        # A hash may have multiple exact hash-only records; all IDs are explicitly previewed.
        unmatched = db.execute('SELECT COUNT(*) FROM requested r WHERE NOT EXISTS (SELECT 1 FROM matched m WHERE m.app=r.app AND m.hash=r.hash)').fetchone()[0]
        self.prepared_at = time.time()
        self.update('Ready', 'Dry run complete. No deletions sent. Review the exact record count before confirming.',
                    planned=planned, unmatched=unmatched, scanned=scanned)

    def execute(self, db, client):
        self.update('Revalidating', 'Rechecking application ownership and OS before deletion.')
        for app in db.execute('SELECT * FROM applications'):
            client.application(app['app'], app['os'])
        if self.stop.is_set():
            raise Cancelled()
        self.update('Deleting', 'Stop prevents new requests; in-flight requests finish and are verified.', sent=0, accepted=0)
        total = accepted = 0

        def source():
            # Keyset paging avoids loading the plan or an unbounded Future list.
            last = 0
            while not self.stop.is_set():
                batch = db.execute("SELECT rowid,* FROM targets WHERE rowid>? AND status='Planned' ORDER BY rowid LIMIT 100", (last,)).fetchall()
                if not batch:
                    break
                for row in batch:
                    if self.stop.is_set():
                        return
                    last = row['rowid']
                    db.execute("UPDATE targets SET status='Dispatched' WHERE rowid=?", (last,))
                    db.commit()  # Durable intent before POST; never auto-resume uncertain writes.
                    yield dict(row)

        def remove(row):
            ok, detail = client.delete(json.loads(row['body']))
            return row['rowid'], ok, detail

        delete_start = time.perf_counter()
        for rowid, ok, detail in bounded_map(remove, source(), self.cfg.workers, self.stop.is_set):
            total += 1
            accepted += ok
            db.execute('UPDATE targets SET status=?,detail=? WHERE rowid=?',
                       ('Accepted' if ok else 'Uncertain', detail, rowid))
            db.commit()
            self.update(sent=total, accepted=accepted)
            if not ok:
                self.stop.set()  # Fail closed on throttling, auth errors, or ambiguous POSTs.
        self.update(deletion_seconds=round(time.perf_counter()-delete_start, 2))
        self.update('Verifying', 'Checking dispatched file IDs. No POST retries are performed.')
        verify_start = time.perf_counter()
        # Stopping deletion still reconciles its bounded set of dispatched writes.
        for app in db.execute('SELECT * FROM applications').fetchall():
            app_id = app['app']
            if not db.execute("SELECT 1 FROM targets WHERE app=? AND status IN ('Accepted','Uncertain','Dispatched')", (app_id,)).fetchone():
                continue
            if self.cfg.mode == 'Bulk':
                db.execute('CREATE TEMP TABLE IF NOT EXISTS remaining(fid TEXT PRIMARY KEY)')
                db.execute('DELETE FROM remaining')
                for row in client.files(app_id):
                    db.execute('INSERT OR IGNORE INTO remaining VALUES (?)', (str(row['applicationFileId']),))
                db.execute("UPDATE targets SET status=CASE WHEN fid IN (SELECT fid FROM remaining) THEN 'StillPresent' ELSE 'VerifiedAbsent' END WHERE app=? AND status IN ('Accepted','Uncertain','Dispatched')", (app_id,))
            else:
                def verify(row):
                    present = any(str(r['applicationFileId']) == row['fid'] for r in client.files(app_id, row['hash']))
                    return row['fid'], present
                source_rows = (dict(r) for r in db.execute("SELECT fid,hash FROM targets WHERE app=? AND status IN ('Accepted','Uncertain','Dispatched')", (app_id,)))
                for fid, present in bounded_map(verify, source_rows, self.cfg.workers):
                    db.execute('UPDATE targets SET status=? WHERE app=? AND fid=?',
                               ('StillPresent' if present else 'VerifiedAbsent', app_id, fid))
            db.commit()
        verified = db.execute("SELECT COUNT(*) FROM targets WHERE status='VerifiedAbsent'").fetchone()[0]
        planned = db.execute('SELECT COUNT(*) FROM targets').fetchone()[0]
        complete = verified == planned and total == planned
        self.update('Complete' if complete else 'Stopped / review required',
                    'All planned file IDs verified absent.' if complete else 'Some targets remain or were not attempted. Review results; create a new dry run to continue.',
                    verified=verified, verification_seconds=round(time.perf_counter()-verify_start, 2))

    def export(self):
        with closing(connect(self.path)) as db, (self.directory / 'results.csv').open('w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ApplicationId', 'ApplicationFileId', 'Hash', 'Status', 'Detail'])
            for row in db.execute('SELECT app,fid,hash,status,detail FROM targets'):
                writer.writerow(row)
        public = dict(self.snapshot(), organization=self.cfg.org, instance=self.cfg.instance,
                      user_instance=self.cfg.user_instance, workers=self.cfg.workers, mode=self.cfg.mode)
        (self.directory / 'summary.json').write_text(json.dumps(public, indent=2), encoding='utf-8')

    def preview(self):
        if not self.path.exists():
            return [], []
        with closing(connect(self.path)) as db:
            apps = [dict(r) for r in db.execute('SELECT a.*, (SELECT COUNT(*) FROM requested r WHERE r.app=a.app) requested_hashes, (SELECT COUNT(*) FROM targets t WHERE t.app=a.app) target_records FROM applications a')]
            rows = [dict(r) for r in db.execute('SELECT app,fid,hash,status,detail FROM targets LIMIT 100')]
        return apps, rows
