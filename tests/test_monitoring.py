import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock,patch

from fastapi import FastAPI
from googleapiclient.errors import HttpError
from httplib2 import Response

from app.monitoring.monitor_manager import MonitorManager,MonitoringStopped
from app.monitoring.report_export import html_report,pdf_report,report_data
from app.monitoring.api_routes import create_monitor_router
from app.main import require_local_request


def http_error(code):return HttpError(Response({'status':code}),b'{}')
def mail(domain='new.example.com'):
    return {'internalDate':'1767225600000','payload':{'headers':[
        {'name':'From','value':'notice@'+domain},{'name':'Subject','value':'Thanks for signing up'}]}}
def breach(version='2026-01-01'):
    return {'domain':'new.example.com','status':'checked','known_breach':True,
            'breaches':[{'id':'incident','name':'Test incident','modified_date':version,'breach_date':'2025-01-02',
                         'description':'Example description','data_exposed':['Passwords'],'verified':True}]}


def raw_request(app,path,method='GET',payload=None):
    async def run():
        output=[]
        async def receive():return {'type':'http.request','body':json.dumps(payload).encode() if payload is not None else b'','more_body':False}
        async def send(message):output.append(message)
        await app({'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':method,'scheme':'http',
                   'path':path,'raw_path':path.encode(),'query_string':b'','root_path':'','headers':[(b'content-type',b'application/json')],
                   'server':('localhost',8000),'client':('localhost',1234)},receive,send)
        return output[0]['status'],b''.join(item.get('body',b'') for item in output)
    return asyncio.run(run())


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        base=Path(__file__).parent/'tmp';base.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=base)
        assert Path(self.temp.name).resolve().is_relative_to(base.resolve())
        self.credentials=object();self.current=[self.credentials,1]
        self.scanner=MagicMock();self.scanner._decode_subject.side_effect=lambda value:value
        self.manager=MonitorManager(lambda:tuple(self.current),Path(self.temp.name)/'monitor.sqlite3',lambda credentials:self.scanner)
        self.manager.owner=(self.credentials,1);self.manager.email='owner@example.com';self.manager.state='running'
        self.manager.store.seed(self.manager.email,[],{})
        self.manager.store.set_cursor(self.manager.email,'100')

    def tearDown(self):
        self.manager.stop(wait=True);self.temp.cleanup()

    def page(self,ids,history_id='110',latest='120'):
        return {'history':[{'id':history_id,'messagesAdded':[{'message':{'id':key}} for key in ids]}],'historyId':latest}

    def test_signup_record_cursor_dedup_and_no_raw_mail_retention(self):
        self.scanner.service.users().history().list().execute.return_value=self.page(['m1'])
        self.scanner.service.users().messages().get().execute.return_value=mail()
        self.manager.poll_gmail()
        data=self.manager.status()
        self.assertEqual(len(data['accounts']),1);self.assertEqual(len(data['alerts']),1)
        self.assertEqual(self.manager.store.cursor(self.manager.email),'120')
        self.assertEqual(self.manager.next_breach,0)
        self.assertFalse(self.manager.store.ingest_message(self.manager.email,'m1'))
        self.assertNotIn(b'Thanks for signing up',self.manager.store.path.read_bytes())
        self.assertNotIn('notice@',str(data))

    def test_failure_does_not_skip_partially_processed_history_record(self):
        self.scanner.service.users().history().list().execute.return_value=self.page(['m1','m2'])
        self.scanner.service.users().messages().get().execute.side_effect=[mail(),http_error(500),mail('second.example.com')]
        with self.assertRaises(HttpError):self.manager.poll_gmail()
        self.assertEqual(self.manager.store.cursor(self.manager.email),'100')
        self.manager.poll_gmail()
        self.assertEqual(len(self.manager.store.accounts(self.manager.email)),2)
        self.assertEqual(self.scanner.service.users().messages().get().execute.call_count,3)

    def test_backlog_limit_resumes_without_losing_messages(self):
        self.scanner.service.users().history().list().execute.return_value=self.page(['m1','m2','m3'])
        self.scanner.service.users().messages().get().execute.side_effect=[mail('one.example.com'),mail('two.example.com'),mail('three.example.com')]
        with patch('app.monitoring.monitor_manager.MAX_MESSAGES_PER_PASS',2):self.manager.poll_gmail()
        self.assertEqual(self.manager.store.cursor(self.manager.email),'100')
        self.assertTrue(self.manager.status()['coverage']['backlog_pending'])
        self.manager.poll_gmail()
        self.assertEqual(len(self.manager.store.accounts(self.manager.email)),3)
        self.assertFalse(self.manager.status()['coverage']['backlog_pending'])

    def test_expired_history_is_labelled_and_recent_recovery_is_bounded(self):
        self.scanner.service.users().history().list().execute.side_effect=http_error(404)
        self.scanner.service.users().getProfile().execute.return_value={'historyId':'200'}
        self.scanner.scan_activity_emails.return_value=([],{'scan_complete':False})
        self.manager.poll_gmail()
        self.assertTrue(self.manager.status()['coverage']['history_gap'])
        self.assertEqual(self.manager.store.cursor(self.manager.email),'200')
        self.assertEqual(self.scanner.scan_activity_emails.call_args.args[0],500)

    def test_breach_dedup_updated_record_and_failed_refresh_retention(self):
        self.manager.store.seed(self.manager.email,[{'domain':'new.example.com'}],{})
        for _ in range(2):self.manager.store.apply_checks(self.manager.email,[breach()])
        self.assertEqual(len(self.manager.status()['alerts']),1)
        self.manager.store.apply_checks(self.manager.email,[breach('2026-02-01')])
        self.assertEqual(len(self.manager.status()['alerts']),2)
        self.manager.store.apply_checks(self.manager.email,[{'domain':'new.example.com','status':'unavailable'}])
        data=self.manager.status();check=data['accounts'][0]['breach_check']
        self.assertTrue(check['known_breach']);self.assertEqual(check['status'],'unavailable')
        self.assertEqual(report_data(data)['action_count'],1)

    def test_mailbox_isolation_acknowledgement_and_connection_change(self):
        self.manager.store.seed('other@example.com',[{'domain':'private.example.com'}],{})
        self.assertEqual(self.manager.status()['accounts'],[])
        self.manager.store.coverage_gap('other@example.com','gap')
        alert=self.manager.store.snapshot('other@example.com')['alerts'][0]
        self.assertFalse(self.manager.store.acknowledge(self.manager.email,alert['id']))
        self.current[1]=2
        self.assertIsNone(self.manager.status()['email'])
        with self.assertRaises(MonitoringStopped):self.manager.poll_gmail()

    def test_provider_errors_are_not_hidden_by_other_successful_checks(self):
        self.manager._attempt(lambda:(_ for _ in ()).throw(OSError()),'gmail')
        self.manager._attempt(lambda:None,'breach')
        self.assertIn('gmail',self.manager.status()['error'])

    def test_report_complete_inventory_colors_and_escaping(self):
        self.manager.store.seed(self.manager.email,[{'domain':'new.example.com','service_name':'<script>alert(1)</script>'},
            {'domain':'unknown.example.com'}],{})
        self.manager.store.apply_checks(self.manager.email,[breach()])
        snapshot=self.manager.status();html=html_report(snapshot)
        self.assertIn('class="action"',html);self.assertIn('class="unknown"',html)
        self.assertIn('unknown.example.com',html);self.assertIn('&lt;script&gt;',html)
        self.assertNotIn('<script>alert(1)</script>',html)
        pdf=pdf_report(snapshot);self.assertTrue(pdf.startswith(b'%PDF-'));self.assertGreater(len(pdf),1000)

    def test_report_routes_do_not_expose_another_mailbox(self):
        app=FastAPI();app.include_router(create_monitor_router(self.manager,require_local_request))
        self.manager.store.seed(self.manager.email,[{'domain':'new.example.com'}],{})
        code,body=raw_request(app,'/monitor/report.pdf');self.assertEqual(code,200);self.assertTrue(body.startswith(b'%PDF-'))
        self.current[0]=None
        self.assertEqual(raw_request(app,'/monitor/report.pdf')[0],401)

    def test_start_checks_mailbox_seed_and_disconnect_stops_writes(self):
        self.manager.owner=None;self.manager.state='stopped'
        self.scanner.service.users().getProfile().execute.return_value={'emailAddress':'owner@example.com','historyId':'100'}
        with patch('app.monitoring.monitor_manager.Thread') as thread:
            thread.return_value.is_alive.return_value=False
            with self.assertRaises(ValueError):self.manager.start([{'domain':'wrong.example.com'}],'someoneelse@example.com')
            self.manager.start([],None)
        self.manager.stop()
        with self.assertRaises(MonitoringStopped):self.manager._ingest({'message_id':'m1','subject':'Thanks for signing up'},True)

    def test_unstarted_status_creates_no_database(self):
        other=MonitorManager(lambda:(None,0),Path(self.temp.name)/'never-created.sqlite3')
        self.assertFalse(other.status()['running']);self.assertFalse(other.store.path.exists())

    def test_loaded_demo_snapshot_can_download_pdf_without_gmail(self):
        from app.services.activity_demo import activity_demo
        from app.services.breach_demo import demo_breaches
        from app.monitoring.monitor_manager import service_summary
        data=activity_demo();services=data['services']
        checks=demo_breaches([service_summary(service) for service in services])['checks']
        app=FastAPI();app.include_router(create_monitor_router(self.manager,require_local_request))
        self.current[0]=None
        code,content=raw_request(app,'/reports/footprint.pdf','POST',{
            'services':[service.model_dump(mode='json') for service in services],
            'checks':checks,'coverage':data['coverage'],'is_demo':True})
        self.assertEqual(code,200);self.assertTrue(content.startswith(b'%PDF-'))
