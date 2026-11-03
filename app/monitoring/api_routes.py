from typing import Literal
from fastapi import APIRouter,Depends,HTTPException,Request
from fastapi.responses import Response
from google.auth.exceptions import GoogleAuthError
from googleapiclient.errors import HttpError
from pydantic import BaseModel,Field

from app.models import DiscoveredService
from app.monitoring.monitor_manager import service_summary,NotConnected
from app.monitoring.report_export import html_report,pdf_report


class MonitorStart(BaseModel):
    seed_services:list[DiscoveredService]=Field(default_factory=list,max_length=10000)
    seed_email:str|None=Field(default=None,max_length=254)
    scan_complete:bool=False
    messages_scanned:int=Field(default=0,ge=0)
    gmail_interval:int=Field(default=120,ge=60,le=3600)
    breach_interval:int=Field(default=1800,ge=600,le=86400)


class ReportBreach(BaseModel):
    id:str=Field(default='',max_length=300)
    name:str=Field(default='Unknown incident',max_length=300)
    description:str=Field(default='No description supplied.',max_length=100000)
    breach_date:str|None=Field(default=None,max_length=40)
    data_exposed:list[str]=Field(default_factory=list,max_length=200)
    affected_records:int|None=Field(default=None,ge=0)
    verified:bool=False
    source_url:str|None=Field(default=None,max_length=2048)


class ReportCheck(BaseModel):
    domain:str=Field(max_length=253)
    status:Literal['checked','unavailable']='unavailable'
    known_breach:bool|None=None
    breaches:list[ReportBreach]=Field(default_factory=list,max_length=2000)
    last_success_at:str|None=Field(default=None,max_length=80)


class SnapshotReport(BaseModel):
    services:list[DiscoveredService]=Field(min_length=1,max_length=10000)
    checks:list[ReportCheck]=Field(default_factory=list,max_length=10000)
    email:str|None=Field(default=None,max_length=254)
    coverage:dict=Field(default_factory=dict)
    is_demo:bool=False
    checked_at:str|None=Field(default=None,max_length=80)


def create_monitor_router(manager,require_local):
    def local_host(request:Request):
        if request.url.hostname not in {'localhost','127.0.0.1'}:
            raise HTTPException(403,'Use the local Cyber Twin dashboard.')
    router=APIRouter(dependencies=[Depends(local_host)])

    def own_mailbox():
        if not manager.current_owner():raise HTTPException(401,'Connect Gmail and start/resume monitoring for this mailbox first.')
        return manager.email

    def download(snapshot,kind):
        if not snapshot.get('accounts'):raise HTTPException(404,'No services are available for this report yet.')
        try:
            content=pdf_report(snapshot) if kind=='pdf' else html_report(snapshot)
        except ImportError:
            raise HTTPException(503,'PDF support is missing. Install the updated requirements or choose the HTML report.') from None
        return Response(content,media_type='application/pdf' if kind=='pdf' else 'text/html',
                        headers={'Content-Disposition':f'attachment; filename="digital-footprint-security-report.{kind}"','Cache-Control':'no-store'})

    @router.post('/monitor/start',status_code=202)
    def start(body:MonitorStart,request:Request):
        require_local(request)
        if any(any(event.source!='gmail' for event in service.timeline) for service in body.seed_services):
            raise HTTPException(422,'Only a real Gmail scan can seed live monitoring. Demo/public profile evidence is excluded.')
        try:
            manager.start(body.seed_services,body.seed_email,{'scan_complete':body.scan_complete,'messages_scanned':body.messages_scanned},body.gmail_interval,body.breach_interval)
        except NotConnected:raise HTTPException(401,'Connect Gmail first.') from None
        except ValueError as error:raise HTTPException(422,str(error)) from None
        except RuntimeError as error:raise HTTPException(409,str(error)) from None
        except GoogleAuthError:raise HTTPException(401,'Google connection expired. Reconnect Gmail and try again.') from None
        except HttpError as error:raise HTTPException(401 if error.resp.status==401 else 429 if error.resp.status==429 else 502,'Google could not complete the mailbox check. Retry or reconnect if permission expired.') from None
        except OSError:raise HTTPException(502,'Monitoring could not start. Check the connection and local data folder access.') from None
        return manager.status(include_accounts=False)

    @router.get('/monitor/status')
    def status(response:Response):
        response.headers['Cache-Control']='no-store'
        return manager.status(include_accounts=False)

    @router.post('/monitor/stop',status_code=202)
    def stop(request:Request):
        require_local(request);manager.stop();return {'state':manager.state,'message':'Stopping after the current network request. Saved records and alerts are retained.'}

    @router.post('/monitor/check-now',status_code=202)
    def check_now(request:Request):
        require_local(request);own_mailbox()
        try:manager.check_now()
        except RuntimeError as error:raise HTTPException(409,str(error)) from None
        return {'message':'A background inbox and breach check was requested.'}

    @router.post('/monitor/alerts/{alert_id}/ack')
    def acknowledge(alert_id:int,request:Request):
        require_local(request);email=own_mailbox()
        if not manager.store.acknowledge(email,alert_id):raise HTTPException(404,'Alert not found for this mailbox.')
        return {'acknowledged':True}

    @router.delete('/monitor/data')
    def forget(request:Request):
        require_local(request);email=own_mailbox()
        if not manager.stop(wait=True):raise HTTPException(409,'Monitoring is still finishing a request. Wait briefly and delete again.')
        manager.store.forget(email)
        return {'message':'Saved monitoring records for this mailbox were deleted locally. Downloaded reports are unchanged.'}

    @router.get('/monitor/report.{kind}')
    def saved_report(kind:Literal['pdf','html'],request:Request):
        require_local(request);own_mailbox()
        return download(manager.status(),kind)

    @router.post('/reports/footprint.{kind}')
    def snapshot_report(kind:Literal['pdf','html'],body:SnapshotReport,request:Request):
        require_local(request)
        checks={check.domain.lower():check.model_dump() for check in body.checks}
        accounts=[{**service_summary(service),'breach_check':checks.get(service.domain.lower(),{})} for service in body.services]
        demo=body.is_demo or any(event.source=='demo' for service in body.services for event in service.timeline)
        return download({'email':body.email,'accounts':accounts,'coverage':body.coverage,'is_demo':demo,
                         'breach_checked_at':body.checked_at,'gmail_checked_at':body.coverage.get('scanned_at'),'alerts':[]},kind)
    return router
