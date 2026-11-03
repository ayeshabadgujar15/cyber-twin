from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from fastapi import FastAPI
from app.monitoring.manager import MonitorManager
from app.monitoring.preferences import create_preferences_router
from app.main import require_local_request
from test_monitoring import raw_request,breach


class PreferenceTests(unittest.TestCase):
    def setUp(self):
        base=Path(__file__).parent/'tmp';base.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=base)
        assert Path(self.temp.name).resolve().is_relative_to(base.resolve())
        self.credentials=object()
        self.manager=MonitorManager(lambda:(self.credentials,1),Path(self.temp.name)/'preferences.sqlite3')
        self.manager.owner=(self.credentials,1);self.manager.email='owner@example.com'
        self.app=FastAPI();self.app.include_router(create_preferences_router(self.manager,require_local_request))

    def tearDown(self):self.temp.cleanup()

    def test_reviews_survive_rescan_and_suppress_breach_alerts(self):
        store=self.manager.store;email=self.manager.email
        store.seed(email,[{'domain':'new.example.com'}],{})
        store.review_finding(email,'new.example.com','dismissed')
        store.seed(email,[{'domain':'new.example.com'}],{})
        store.apply_checks(email,[breach()])
        self.assertEqual(store.accounts(email)[0]['finding_status'],'dismissed')
        self.assertEqual(store.snapshot(email)['alerts'],[])
        store.review_finding(email,'new.example.com','unconfirmed')
        store.apply_checks(email,[breach()])
        self.assertEqual(len(store.snapshot(email)['alerts']),1)

    def test_pending_done_reminder_and_mailbox_isolation(self):
        store=self.manager.store;email=self.manager.email
        store.save_action(email,'new.example.com','password','Change password','pending','2026-01-01')
        self.assertEqual(len(store.preferences(email,'2026-01-02')['reminders']),1)
        store.save_action(email,'new.example.com','password','Change password','done','2026-01-01')
        self.assertEqual(store.preferences(email,'2026-01-02')['reminders'],[])
        self.assertEqual(store.preferences('other@example.com')['actions'],[])
        store.clear_preferences(email)
        self.assertEqual(store.preferences(email)['actions'],[])

    def test_api_uses_actual_mailbox_and_rejects_wrong_mailbox(self):
        code,_=raw_request(self.app,'/preferences/finding','POST',{'email':'owner@example.com','domain':'new.example.com','status':'confirmed'})
        self.assertEqual(code,200)
        self.assertEqual(raw_request(self.app,'/preferences/finding','POST',{'email':'other@example.com','domain':'new.example.com','status':'dismissed'})[0],409)
        self.assertEqual(self.manager.store.preferences(self.manager.email)['reviews']['new.example.com'],'confirmed')

    def test_api_saves_actions_without_enabling_monitoring(self):
        code,body=raw_request(self.app,'/preferences/action','POST',{'email':'owner@example.com','domain':'new.example.com','action_id':'mfa','title':'Enable MFA','status':'pending','due_date':'2026-01-01','today':'2026-01-02'})
        self.assertEqual(code,200)
        import json
        self.assertEqual(len(json.loads(body)['reminders']),1)
        self.assertFalse(self.manager.status()['running'])
