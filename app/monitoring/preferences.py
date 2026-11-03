"""Local decisions bound to the actual Gmail identity, independent of monitoring."""
from datetime import date
from typing import Literal
import re
from fastapi import APIRouter,Depends,HTTPException,Request,Response
from pydantic import BaseModel,Field
from app.gmail.scanner import GmailScanner

DOMAIN=r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'

class FindingReview(BaseModel):
    email:str=Field(max_length=254)
    domain:str=Field(max_length=253,pattern=DOMAIN)
    status:Literal['confirmed','dismissed','unconfirmed']
    today:date|None=None

class ActionReview(BaseModel):
    email:str=Field(max_length=254)
    domain:str=Field(max_length=253,pattern=DOMAIN)
    action_id:Literal['open','password','mfa','sessions','recovery','phishing']
    title:str=Field(min_length=1,max_length=300)
    status:Literal['pending','done']
    due_date:date|None=None
    today:date|None=None

def create_preferences_router(manager,require_local):
    cache={}
    def local(request:Request):
        if request.url.hostname not in {'localhost','127.0.0.1'}:raise HTTPException(403,'Use the local dashboard.')
    router=APIRouter(dependencies=[Depends(local)])
    def identity(expected=None):
        credentials,generation=manager.provider()
        if credentials is None:raise HTTPException(401,'Connect Gmail to save mailbox decisions.')
        if cache.get('credentials') is not credentials or cache.get('generation')!=generation:
            try:email=manager.email if manager.current_owner() else GmailScanner(credentials).get_email_address()
            except Exception:raise HTTPException(502,'Could not verify the Gmail identity. Reconnect and try again.') from None
            current=manager.provider()
            if current[0] is not credentials or current[1]!=generation:raise HTTPException(409,'Gmail connection changed.')
            if not isinstance(email,str) or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email):raise HTTPException(502,'Mailbox identity unavailable.')
            cache.update(credentials=credentials,generation=generation,email=email.lower())
        email=cache['email']
        if expected and expected.lower()!=email:raise HTTPException(409,'This decision belongs to a different mailbox. Scan the connected mailbox first.')
        return email

    @router.get('/preferences')
    def get_preferences(request:Request,response:Response,today:date|None=None):
        response.headers['Cache-Control']='no-store'
        return manager.store.preferences(identity(request.headers.get('x-cybertwin-mailbox')),today.isoformat() if today else None)

    @router.post('/preferences/finding')
    def save_finding(body:FindingReview,request:Request):
        require_local(request);email=identity(body.email)
        manager.store.review_finding(email,body.domain.lower(),body.status)
        return manager.store.preferences(email,body.today.isoformat() if body.today else None)

    @router.post('/preferences/action')
    def save_action(body:ActionReview,request:Request):
        require_local(request);email=identity(body.email)
        manager.store.save_action(email,body.domain.lower(),body.action_id,body.title,body.status,body.due_date.isoformat() if body.due_date else None)
        return manager.store.preferences(email,body.today.isoformat() if body.today else None)

    @router.delete('/preferences')
    def clear(request:Request):
        require_local(request);email=identity(request.headers.get('x-cybertwin-mailbox'))
        manager.store.clear_preferences(email)
        return manager.store.preferences(email)
    return router
