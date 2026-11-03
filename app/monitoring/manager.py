"""One opt-in local polling worker. Gmail history checkpoints are crash-safe."""
from datetime import datetime, timezone
from email.utils import parseaddr
import re
from threading import Event, RLock, Thread
import time

from google.auth.exceptions import GoogleAuthError
from googleapiclient.errors import HttpError

from app.gmail.scanner import GmailScanner
from app.security.breach_checker import BreachChecker
from app.services.activity_reconstruction import ActivityReconstructionService
from app.monitoring.store import MonitorStore

MAX_MESSAGES_PER_PASS=1000


class MonitoringStopped(Exception):
    pass


class NotConnected(Exception):
    pass


def service_summary(service):
    data=service.model_dump(mode='json') if hasattr(service,'model_dump') else service
    events=data.get('timeline',[])
    return {'domain':data['domain'],'service_name':data.get('service_name') or data['domain'],
            'first_seen':data.get('first_seen'),'last_seen':data.get('last_seen'),
            'signup_clue':any(event.get('event_type') in {'account_creation','account_verification'} for event in events),
            'security_alert':any(event.get('event_type')=='security' and event.get('confidence_score',0)>=85 for event in events),
            'password_event':any(event.get('event_type')=='password' for event in events)}


class MonitorManager:
    def __init__(self,credential_provider,path,scanner_factory=GmailScanner,breach_factory=BreachChecker):
        self.provider,self.store=credential_provider,MonitorStore(path)
        self.scanner_factory,self.breach_factory=scanner_factory,breach_factory
        self.lock=RLock();self.event=Event();self.wake=Event();self.thread=None
        self.owner=None;self.email=None;self.state='stopped';self.error=None;self.errors={'gmail':None,'breach':None}
        self.gmail_interval=120;self.breach_interval=1800
        self.next_gmail=0;self.next_breach=0

    def _check(self):
        if self.event.is_set() or self.owner is None:
            raise MonitoringStopped()
        credentials,generation=self.provider()
        if credentials is not self.owner[0] or generation != self.owner[1]:
            raise MonitoringStopped()

    def _write(self,operation,*args,**kwargs):
        with self.lock:
            self._check()
            return operation(*args,**kwargs)

    def current_owner(self):
        credentials,generation=self.provider()
        return self.owner is not None and credentials is self.owner[0] and generation==self.owner[1]

    def start(self,seed_services=None,seed_email=None,coverage=None,gmail_interval=120,breach_interval=1800):
        if not 60<=gmail_interval<=3600 or not 600<=breach_interval<=86400:
            raise ValueError('Choose inbox checks from 1–60 minutes and breach checks from 10 minutes–24 hours.')
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                raise RuntimeError('Monitoring is running or stopping. Stop it before starting again.')
            credentials,generation=self.provider()
            if credentials is None:raise NotConnected('Connect Gmail first.')
            profile=self.scanner_factory(credentials).service.users().getProfile(userId='me').execute(num_retries=2)
            email=profile.get('emailAddress');history=str(profile.get('historyId',''))
            if not isinstance(email,str) or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or not history.isdigit():
                raise ValueError('Gmail did not provide a valid mailbox identity and history checkpoint.')
            email=email.lower()
            if seed_services and (not seed_email or email != seed_email.lower()):
                raise ValueError('The loaded scan must belong to the connected Gmail account.')
            current=self.provider()
            if current[0] is not credentials or current[1]!=generation:
                raise RuntimeError('Gmail connection changed. Try again.')
            self.owner=(credentials,generation);self.email=email
            self.gmail_interval,self.breach_interval=gmail_interval,breach_interval
            self.store.seed(email,[service_summary(service) for service in seed_services or []],
                            {'initial_scan_complete':bool((coverage or {}).get('scan_complete')),
                             'seed_messages_scanned':(coverage or {}).get('messages_scanned',0),
                             'note':'Monitoring records signup clues; account ownership and completed registration remain unverified.'})
            self.initial_history=history
            self.event=Event();self.wake=Event();self.state='running';self.error=None;self.errors={'gmail':None,'breach':None}
            self.next_gmail=self.next_breach=0
            self.thread=Thread(target=self._run,name='cybertwin-monitor',daemon=True)
            self.thread.start()

    def stop(self,wait=False):
        with self.lock:
            self.event.set();self.wake.set()
            if self.state=='running':self.state='stopping'
            thread=self.thread
        if wait and thread is not None:thread.join(timeout=3)
        stopped=thread is None or not thread.is_alive()
        if stopped and self.state=='stopping':self.state='stopped'
        return stopped

    def check_now(self):
        with self.lock:
            if self.state!='running' or not self.current_owner():raise RuntimeError('Start monitoring first.')
            self.next_gmail=self.next_breach=0;self.wake.set()

    def status(self,include_accounts=True):
        with self.lock:
            if not self.current_owner():
                return {'state':'stopped','running':False,'email':None,'accounts':[],'alerts':[],
                        'unread_alerts':0,'note':'Connect Gmail and start monitoring to resume its saved local records.'}
            data=self.store.snapshot(self.email)
            data['account_count']=len(data['accounts'])
            if not include_accounts:data['accounts']=data['accounts'][:100]
            return {**data,'state':self.state,'running':self.state=='running','error':self.error or '; '.join(value for value in self.errors.values() if value) or None,
                    'gmail_interval_seconds':self.gmail_interval,'breach_interval_seconds':self.breach_interval,
                    'note':'Local connector polling. Monitoring requires this server to remain running and Gmail permission to stay valid.'}

    def _run(self):
        try:
            while not self.event.is_set():
                self._check()
                now=time.monotonic()
                if now>=self.next_gmail:
                    self.next_gmail=now+self.gmail_interval
                    self._attempt(self.poll_gmail,'gmail')
                self._check()
                if time.monotonic()>=self.next_breach:
                    self.next_breach=time.monotonic()+self.breach_interval
                    self._attempt(self.poll_breaches,'breach')
                self.wake.wait(1);self.wake.clear()
        except MonitoringStopped:
            pass
        finally:
            with self.lock:
                if self.state in {'running','stopping'}:self.state='stopped'

    def _attempt(self,operation,channel):
        try:
            operation()
            with self.lock:self.errors[channel]=None
        except MonitoringStopped:raise
        except (GoogleAuthError,HttpError) as error:
            code=getattr(getattr(error,'resp',None),'status',None)
            if isinstance(error,GoogleAuthError) or code==401:
                with self.lock:self.state='reconnect_required';self.error='Gmail permission expired. Reconnect Gmail, then resume monitoring.'
                self.event.set();raise MonitoringStopped() from None
            with self.lock:self.errors[channel]='A provider refused the '+channel+' check. Coverage may be incomplete; monitoring will retry.'
        except Exception:
            with self.lock:self.errors[channel]='The '+channel+' check could not finish. It will retry; an unprocessed Gmail checkpoint is never skipped.'

    def _ingest(self,message,notify):
        message_id=message.get('message_id')
        if not message_id:raise ValueError('Message ID missing')
        try:
            services=ActivityReconstructionService().reconstruct([message])
            summary=service_summary(services[0]) if services else None
            result=self._write(self.store.ingest_message,self.email,message_id,summary,notify)
            if result and result.get('new_service'):self.next_breach=0
        finally:
            message.clear()

    def _baseline(self,scanner,resync=False):
        self._check()
        profile=scanner.service.users().getProfile(userId='me').execute(num_retries=2)
        history=str(profile.get('historyId',''))
        emails,coverage=scanner.scan_activity_emails(500,progress_callback=lambda values:self._check())
        try:
            for message in emails:self._ingest(message,notify=resync)
        finally:emails.clear()
        self._write(self.store.set_cursor,self.email,history)
        self._write(self.store.record_gmail_check,self.email,{'recent_baseline_limit':500,'recent_baseline_complete':coverage.get('scan_complete',False),
                                                            'unavailable_messages':coverage.get('unavailable_messages',0)})

    def poll_gmail(self):
        self._check();scanner=self.scanner_factory(self.owner[0]);cursor=self.store.cursor(self.email)
        if cursor is None:
            # Capture checkpoint before the baseline, so arrivals during scanning
            # remain eligible for history synchronization on the next poll.
            self._baseline(scanner)
            return
        page_token=None;seen_tokens=set();fetched=0;unavailable=0
        try:
            while True:
                self._check()
                response=scanner.service.users().history().list(userId='me',startHistoryId=cursor,
                           historyTypes=['messageAdded'],maxResults=100,
                           **({'pageToken':page_token} if page_token else {})).execute(num_retries=2)
                for history in response.get('history',[]):
                    self._check()
                    for added in history.get('messagesAdded',[]):
                        message_id=added.get('message',{}).get('id')
                        if not message_id or self.store.processed(self.email,message_id):continue
                        if fetched>=MAX_MESSAGES_PER_PASS:
                            self._write(self.store.record_gmail_check,self.email,{'backlog_pending':True,'unavailable_messages':unavailable})
                            return  # Keep this history record uncommitted; resume it next poll.
                        self._check();fetched+=1
                        try:
                            raw=scanner.service.users().messages().get(userId='me',id=message_id,format='metadata',
                                metadataHeaders=['From','Subject','Date'],fields='internalDate,labelIds,payload/headers').execute(num_retries=2)
                        except HttpError as error:
                            if error.resp.status!=404:raise
                            unavailable+=1
                            self._write(self.store.ingest_message,self.email,message_id)
                            continue
                        try:
                            if {'SENT','DRAFT'}.intersection(raw.get('labelIds',[])):
                                self._write(self.store.ingest_message,self.email,message_id)
                                continue
                            headers={h['name'].lower():h['value'] for h in raw.get('payload',{}).get('headers',[])}
                            _,sender=parseaddr(headers.get('from',''))
                            self._ingest({'message_id':message_id,'sender_domain':sender.rsplit('@',1)[-1].lower() if '@' in sender else '',
                                          'subject':scanner._decode_subject(headers.get('subject','')),'date':headers.get('date',''),
                                          'internal_date':raw.get('internalDate')},notify=True)
                        finally:raw.clear()
                    self._write(self.store.set_cursor,self.email,history['id'])
                page_token=response.get('nextPageToken')
                if not page_token:
                    self._write(self.store.set_cursor,self.email,response.get('historyId',''))
                    self._write(self.store.record_gmail_check,self.email,{'backlog_pending':False,'unavailable_messages':unavailable})
                    return
                if page_token in seen_tokens:raise ValueError('Repeated Gmail history page')
                seen_tokens.add(page_token)
        except HttpError as error:
            if error.resp.status!=404:raise
            self._write(self.store.coverage_gap,self.email,'Gmail history expired. Only a recent 500-message recovery scan was used; run a full Module 1 scan to review older service evidence.')
            self._baseline(scanner,resync=True)

    def poll_breaches(self):
        self._check();accounts=self.store.accounts(self.email)
        if not accounts:return
        try:
            checks=self.breach_factory().check_breaches([item['domain'] for item in accounts])
            if len(checks)!=len(accounts):raise ValueError('Incomplete provider results')
            checks=[{**check,'status':'checked'} for check in checks]
        except Exception:
            self._write(self.store.apply_checks,self.email,[{'domain':item['domain'],'status':'unavailable'} for item in accounts])
            raise
        self._write(self.store.apply_checks,self.email,checks)
