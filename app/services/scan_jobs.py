"""One local scan worker. Results are normalized, bounded and expire in memory."""
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock, Thread


class ScanCancelled(Exception):
    pass


class ScanFailure(Exception):
    def __init__(self, status, detail):
        self.status, self.detail = status, detail


class ScanJobManager:
    def __init__(self, ttl=600, max_jobs=3):
        self.ttl, self.max_jobs = ttl, max_jobs
        self.lock = Lock()
        self.jobs = {}
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='cybertwin-scan')
        self.stop_cleanup = Event()
        self.cleanup_thread = Thread(target=self._cleanup_loop, name='cybertwin-expiry', daemon=True)
        self.cleanup_thread.start()

    def _cleanup_loop(self):
        while not self.stop_cleanup.wait(min(30, self.ttl)):
            with self.lock:
                self._prune()

    def _prune(self):
        cutoff = time.monotonic() - self.ttl
        for key in list(self.jobs):
            if self.jobs[key]['touched'] < cutoff:
                self.jobs[key]['cancel'].set()
                del self.jobs[key]

    def start(self, owner, task, message_limit):
        with self.lock:
            self._prune()
            if any(job['status'] in {'queued', 'running', 'cancelling'} for job in self.jobs.values()):
                raise RuntimeError('A mailbox scan is already running. Wait or cancel it before starting another.')
            while len(self.jobs) >= self.max_jobs:
                oldest = min(self.jobs, key=lambda key: self.jobs[key]['touched'])
                del self.jobs[oldest]
            key = secrets.token_urlsafe(24)
            self.jobs[key] = {'owner': owner, 'status': 'queued', 'progress': {'message_fetches': 0, 'messages_scanned': 0, 'message_limit': message_limit, 'pages_scanned': 0},
                              'cancel': Event(), 'result': None, 'error': None, 'touched': time.monotonic()}
        self.executor.submit(self._run, key, task)
        return key

    def _run(self, key, task):
        def report(progress):
            with self.lock:
                job = self.jobs.get(key)
                if job is None or job['cancel'].is_set():
                    raise ScanCancelled()
                job['progress'] = dict(progress)
                job['status'] = 'running'
                job['touched'] = time.monotonic()
        try:
            with self.lock:
                initial = self.jobs.get(key)
                if initial is None:
                    return
                initial_progress = dict(initial['progress'])
            report(initial_progress)
            result = task(report)
            with self.lock:
                job = self.jobs.get(key)
                if job is not None:
                    job['status'] = 'cancelled' if job['cancel'].is_set() else 'completed'
                    job['result'] = None if job['cancel'].is_set() else result
                    job['touched'] = time.monotonic()
        except ScanCancelled:
            with self.lock:
                if key in self.jobs:
                    self.jobs[key]['status'] = 'cancelled'
                    self.jobs[key]['result'] = None
                    self.jobs[key]['touched'] = time.monotonic()
        except Exception as error:
            with self.lock:
                if key in self.jobs:
                    self.jobs[key]['status'] = 'cancelled' if self.jobs[key]['cancel'].is_set() else 'failed'
                    self.jobs[key]['error'] = ({'status': error.status, 'detail': error.detail} if isinstance(error, ScanFailure) else
                                             {'status': 502, 'detail': 'Mailbox scan could not be completed. Try again or reconnect Gmail.'})
                    self.jobs[key]['touched'] = time.monotonic()

    def snapshot(self, key, owner):
        with self.lock:
            self._prune()
            job = self.jobs.get(key)
            if job is None or job['owner'] != owner:
                return None
            # Polling does not extend retention of completed results.
            return {'scan_id': key, 'status': job['status'], 'progress': dict(job['progress']),
                    'result': job['result'], 'error': job['error']}

    def cancel(self, key, owner):
        with self.lock:
            job = self.jobs.get(key)
            if job is None or job['owner'] != owner:
                return False
            job['cancel'].set()
            job['result'] = None
            job['status'] = 'cancelling' if job['status'] in {'queued', 'running', 'cancelling'} else 'cancelled'
            return True

    def clear(self):
        with self.lock:
            for job in self.jobs.values():
                job['cancel'].set()
            self.jobs.clear()

    def shutdown(self):
        self.stop_cleanup.set()
        self.clear()
        self.executor.shutdown(wait=False, cancel_futures=True)
