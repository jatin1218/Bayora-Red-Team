"""SQLite development queue; a partial unique index enforces one running job."""
from contextlib import contextmanager
import json
import sqlite3
from pathlib import Path
from uuid import uuid4
from .evidence import utcnow

TERMINAL = ('COMPLETED', 'CANCELLED', 'TIMED_OUT', 'FAILED')

class Store:
    def __init__(self, path):
        self.path = str(Path(path).resolve())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, project TEXT NOT NULL, created TEXT NOT NULL,
                state TEXT NOT NULL, contract TEXT NOT NULL,
                cancel_requested INTEGER NOT NULL DEFAULT 0, result TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_job ON jobs(state) WHERE state='RUNNING';
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, contract):
        job_id = str(uuid4())
        with self.connect() as db:
            db.execute('INSERT INTO jobs(id, project, created, state, contract) VALUES(?,?,?,?,?)',
                       (job_id, contract.project_id, utcnow(), 'QUEUED', contract.model_dump_json()))
        return job_id

    def get(self, job_id, project=None):
        with self.connect() as db:
            row = db.execute('SELECT * FROM jobs WHERE id=?' + (' AND project=?' if project else ''),
                             (job_id, project) if project else (job_id,)).fetchone()
        if not row:
            raise KeyError('Run not found')
        out = dict(row)
        for k in ('contract','result'):
            out[k] = json.loads(out[k]) if out[k] else None
        return out

    def list(self, project):
        with self.connect() as db:
            return [dict(row) for row in db.execute('SELECT id,project,created,state,cancel_requested FROM jobs WHERE project=? ORDER BY created DESC LIMIT 100', (project,))]

    def claim(self, job_id=None):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM jobs WHERE state='RUNNING'").fetchone():
                return None
            row = db.execute("SELECT id FROM jobs WHERE state='QUEUED' AND cancel_requested=0" + (' AND id=?' if job_id else '') + ' ORDER BY created LIMIT 1', (job_id,) if job_id else ()).fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET state='RUNNING' WHERE id=?", (row['id'],))
            return row['id']

    def cancelled(self, job_id):
        return bool(self.get(job_id)['cancel_requested'])

    def cancel(self, job_id, project):
        self.get(job_id, project)
        with self.connect() as db:
            db.execute("UPDATE jobs SET cancel_requested=1, state=CASE WHEN state='QUEUED' THEN 'CANCELLED' ELSE state END WHERE id=? AND project=? AND state IN ('QUEUED','RUNNING')", (job_id, project))
        return self.get(job_id, project)

    def finish(self, job_id, state, result):
        assert state in TERMINAL
        with self.connect() as db:
            db.execute('UPDATE jobs SET state=?,result=? WHERE id=? AND state=\'RUNNING\'', (state,json.dumps(result,allow_nan=False),job_id))

    def recover(self):
        # Operator-only action: use only after verifying no worker remains alive.
        with self.connect() as db:
            n = db.execute("UPDATE jobs SET state='FAILED' WHERE state='RUNNING'").rowcount
        return n
