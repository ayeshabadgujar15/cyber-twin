"""Mailbox-isolated SQLite state. Never persist message subjects/bodies/tokens."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sqlite3
from threading import RLock


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class MonitorStore:
    def __init__(self, path):
        self.path, self.lock = Path(path), RLock()

    @contextmanager
    def connection(self):
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                db.executescript('''
                CREATE TABLE IF NOT EXISTS mailboxes(email TEXT PRIMARY KEY, history_id TEXT,
                  coverage TEXT DEFAULT '{}', gmail_checked_at TEXT, breach_checked_at TEXT);
                CREATE TABLE IF NOT EXISTS accounts(email TEXT,domain TEXT,name TEXT,first_seen TEXT,last_seen TEXT,
                  signup_clue INTEGER DEFAULT 0,security_alert INTEGER DEFAULT 0,password_event INTEGER DEFAULT 0,
                  check_json TEXT DEFAULT '{}',PRIMARY KEY(email,domain));
                CREATE TABLE IF NOT EXISTS finding_reviews(email TEXT,domain TEXT,status TEXT,PRIMARY KEY(email,domain));
                CREATE TABLE IF NOT EXISTS action_items(email TEXT,domain TEXT,action_id TEXT,title TEXT,status TEXT,due_date TEXT,PRIMARY KEY(email,domain,action_id));
                CREATE TABLE IF NOT EXISTS processed(email TEXT,message_id TEXT,seen_at TEXT,PRIMARY KEY(email,message_id));
                CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT,domain TEXT,
                  kind TEXT,title TEXT,detail TEXT,created_at TEXT,acknowledged INTEGER DEFAULT 0,
                  unique_key TEXT,UNIQUE(email,unique_key));
                ''')
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def _mailbox(self, db, email):
        db.execute('INSERT OR IGNORE INTO mailboxes(email) VALUES (?)',(email,))

    def _alert(self, db, email, domain, kind, title, detail, key):
        db.execute('INSERT OR IGNORE INTO alerts(email,domain,kind,title,detail,created_at,unique_key) VALUES (?,?,?,?,?,?,?)',
                   (email,domain,kind,title,detail,utc_now(),key))

    def _upsert(self, db, email, service, notify):
        domain = service['domain']
        previous = db.execute('SELECT * FROM accounts WHERE email=? AND domain=?',(email,domain)).fetchone()
        dates_first = [v for v in [service.get('first_seen'), previous['first_seen'] if previous else None] if v]
        dates_last = [v for v in [service.get('last_seen'), previous['last_seen'] if previous else None] if v]
        signup = bool(service.get('signup_clue'))
        db.execute('''INSERT INTO accounts(email,domain,name,first_seen,last_seen,signup_clue,security_alert,password_event)
          VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(email,domain) DO UPDATE SET name=excluded.name,
          first_seen=excluded.first_seen,last_seen=excluded.last_seen,
          signup_clue=MAX(accounts.signup_clue,excluded.signup_clue),
          security_alert=MAX(accounts.security_alert,excluded.security_alert),password_event=MAX(accounts.password_event,excluded.password_event)''',
          (email,domain,service.get('service_name') or domain,min(dates_first) if dates_first else None,
           max(dates_last) if dates_last else None,int(signup),int(bool(service.get('security_alert'))),int(bool(service.get('password_event')))))
        review=db.execute('SELECT status FROM finding_reviews WHERE email=? AND domain=?',(email,domain)).fetchone()
        if notify and signup and (previous is None or not previous['signup_clue']) and (review is None or review['status']!='dismissed'):
            self._alert(db,email,domain,'signup_clue','New signup evidence: '+domain,
                        'A registration/verification notification matched this service. Completed signup and ownership are not verified.',
                        'signup:'+domain)

    def seed(self, email, services, coverage):
        with self.connection() as db:
            self._mailbox(db,email)
            for service in services:
                self._upsert(db,email,service,False)
            old=json.loads(db.execute('SELECT coverage FROM mailboxes WHERE email=?',(email,)).fetchone()['coverage'])
            db.execute('UPDATE mailboxes SET coverage=? WHERE email=?',(json.dumps({**old,**coverage}),email))

    def processed(self, email, message_id):
        with self.connection() as db:
            return db.execute('SELECT 1 FROM processed WHERE email=? AND message_id=?',(email,message_id)).fetchone() is not None

    def ingest_message(self, email, message_id, service=None, notify=True):
        with self.connection() as db:
            self._mailbox(db,email)
            if db.execute('SELECT 1 FROM processed WHERE email=? AND message_id=?',(email,message_id)).fetchone():
                return False
            new_service=bool(service and db.execute('SELECT 1 FROM accounts WHERE email=? AND domain=?',(email,service['domain'])).fetchone() is None)
            if service:
                self._upsert(db,email,service,notify)
            db.execute('INSERT INTO processed VALUES (?,?,?)',(email,message_id,utc_now()))
            return {'processed':True,'new_service':new_service}

    def cursor(self, email):
        with self.connection() as db:
            row=db.execute('SELECT history_id FROM mailboxes WHERE email=?',(email,)).fetchone()
            return row['history_id'] if row else None

    def set_cursor(self, email, history_id):
        value=str(history_id)
        if not value.isdigit():
            raise ValueError('Invalid Gmail history checkpoint')
        with self.connection() as db:
            self._mailbox(db,email)
            db.execute('UPDATE mailboxes SET history_id=? WHERE email=?',(value,email))

    def record_gmail_check(self,email,coverage=None):
        with self.connection() as db:
            self._mailbox(db,email)
            db.execute('UPDATE mailboxes SET gmail_checked_at=? WHERE email=?',(utc_now(),email))
            if coverage is not None:
                row=db.execute('SELECT coverage FROM mailboxes WHERE email=?',(email,)).fetchone()
                data=json.loads(row['coverage']); data.update(coverage)
                db.execute('UPDATE mailboxes SET coverage=? WHERE email=?',(json.dumps(data),email))
            cutoff=(datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
            db.execute('DELETE FROM processed WHERE email=? AND seen_at<?',(email,cutoff))

    def coverage_gap(self,email,detail):
        with self.connection() as db:
            self._mailbox(db,email)
            self._alert(db,email,'','coverage_gap','Monitoring coverage needs review',detail,'gap:'+utc_now())
            row=db.execute('SELECT coverage FROM mailboxes WHERE email=?',(email,)).fetchone()
            data=json.loads(row['coverage']);data['history_gap']=True;data['gap_note']=detail
            db.execute('UPDATE mailboxes SET coverage=? WHERE email=?',(json.dumps(data),email))

    def accounts(self,email):
        if not self.path.exists():return []
        with self.connection() as db:
            rows=db.execute("SELECT a.*,COALESCE(r.status,'unconfirmed') AS finding_status FROM accounts a LEFT JOIN finding_reviews r ON a.email=r.email AND a.domain=r.domain WHERE a.email=? ORDER BY a.domain",(email,)).fetchall()
        return [{'domain':row['domain'],'service_name':row['name'],'first_seen':row['first_seen'],'last_seen':row['last_seen'],
                 'finding_status':row['finding_status'],'signup_clue':bool(row['signup_clue']),'security_alert':bool(row['security_alert']),
                 'password_event':bool(row['password_event']),'breach_check':json.loads(row['check_json'])} for row in rows]

    def apply_checks(self,email,checks):
        now=utc_now()
        with self.connection() as db:
            for check in checks:
                domain=check['domain']
                row=db.execute('SELECT check_json FROM accounts WHERE email=? AND domain=?',(email,domain)).fetchone()
                if row is None:continue
                old=json.loads(row['check_json'])
                if check.get('status') != 'checked':
                    saved={**old,'domain':domain,'status':'unavailable','last_attempt_at':now,
                           'note':'Provider check failed. Any earlier breach findings are retained and may be stale.'}
                else:
                    saved={**check,'last_attempt_at':now,'last_success_at':now}
                    review=db.execute('SELECT status FROM finding_reviews WHERE email=? AND domain=?',(email,domain)).fetchone()
                    for breach in ([] if review and review['status']=='dismissed' else check.get('breaches',[])):
                        version=breach.get('modified_date') or breach.get('added_date') or breach.get('breach_date') or ''
                        identity=breach.get('id') or breach.get('name') or 'unknown'
                        self._alert(db,email,domain,'service_breach','Service breach history found: '+domain,
                                    str(breach.get('name') or identity)+'; reported incident '+str(breach.get('breach_date') or 'date unknown')+
                                    '. Newly detected or updated by Cyber Twin; this does not prove personal exposure.',
                                    'breach:'+domain+':'+identity+':'+version)
                db.execute('UPDATE accounts SET check_json=? WHERE email=? AND domain=?',(json.dumps(saved),email,domain))
            self._mailbox(db,email)
            db.execute('UPDATE mailboxes SET breach_checked_at=? WHERE email=?',(now,email))

    def snapshot(self,email):
        with self.lock:
            return self._snapshot(email)

    def _snapshot(self,email):
        if not self.path.exists():return {'email':email,'accounts':[],'alerts':[],'coverage':{},'unread_alerts':0}
        with self.connection() as db:
            box=db.execute('SELECT * FROM mailboxes WHERE email=?',(email,)).fetchone()
            alerts=[dict(row) for row in db.execute('SELECT id,domain,kind,title,detail,created_at,acknowledged FROM alerts WHERE email=? ORDER BY id DESC LIMIT 100',(email,))]
            count=db.execute('SELECT COUNT(*) FROM alerts WHERE email=? AND acknowledged=0',(email,)).fetchone()[0]
            total=db.execute('SELECT COUNT(*) FROM alerts WHERE email=?',(email,)).fetchone()[0]
        return {'email':email,'accounts':self.accounts(email),'alerts':alerts,'unread_alerts':count,'alert_count':total,
                'coverage':json.loads(box['coverage']) if box else {},
                'gmail_checked_at':box['gmail_checked_at'] if box else None,
                'breach_checked_at':box['breach_checked_at'] if box else None}

    def acknowledge(self,email,alert_id):
        with self.connection() as db:
            return db.execute('UPDATE alerts SET acknowledged=1 WHERE email=? AND id=?',(email,alert_id)).rowcount>0

    def forget(self,email):
        if not self.path.exists():return
        with self.connection() as db:
            for table in ['alerts','processed','accounts','mailboxes','finding_reviews','action_items']:
                db.execute(f'DELETE FROM {table} WHERE email=?',(email,))


    def preferences(self,email,today=None):
        if not self.path.exists():return {'email':email,'reviews':{},'actions':[],'reminders':[]}
        today=today or datetime.now().date().isoformat()
        with self.connection() as db:
            reviews={row['domain']:row['status'] for row in db.execute('SELECT domain,status FROM finding_reviews WHERE email=?',(email,))}
            actions=[dict(row) for row in db.execute('SELECT domain,action_id,title,status,due_date FROM action_items WHERE email=?',(email,))]
        reminders=[item for item in actions if item['status']=='pending' and item['due_date'] and item['due_date']<=today and reviews.get(item['domain'])!='dismissed']
        return {'email':email,'reviews':reviews,'actions':actions,'reminders':reminders}

    def review_finding(self,email,domain,status):
        with self.connection() as db:
            db.execute('INSERT INTO finding_reviews VALUES (?,?,?) ON CONFLICT(email,domain) DO UPDATE SET status=excluded.status',(email,domain,status))
            if status=='dismissed':
                db.execute("UPDATE alerts SET acknowledged=1 WHERE email=? AND domain=? AND kind IN ('signup_clue','service_breach')",(email,domain))

    def save_action(self,email,domain,action_id,title,status,due_date):
        with self.connection() as db:
            db.execute('INSERT INTO action_items VALUES (?,?,?,?,?,?) ON CONFLICT(email,domain,action_id) DO UPDATE SET title=excluded.title,status=excluded.status,due_date=excluded.due_date',
                       (email,domain,action_id,title,status,due_date))

    def clear_preferences(self,email):
        with self.connection() as db:
            for table in ['finding_reviews','action_items']:
                db.execute(f'DELETE FROM {table} WHERE email=?',(email,))
