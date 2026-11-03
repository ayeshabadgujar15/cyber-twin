'use strict';
let monitorSnapshot = null;
let monitorRefreshActive = false;
let monitorActionActive = false;
let monitorAlertCursor = null;
let monitorTimer = null;
let reportBusy = false;

function reportButtons() {
  const saved = $('report-source').value === 'monitor';
  const count = saved ? monitorSnapshot?.account_count || 0 : workspaceRecords.length;
  $('report-pdf').disabled = !count || reportBusy;
  $('report-html').disabled = !count || reportBusy;
}
function renderMonitor() {
  const data = monitorSnapshot || {state:'stopped',accounts:[],alerts:[]};
  const live = data.running;
  $('monitor-start').disabled = monitorActionActive || live || data.state==='stopping' || !window.gmailConnected || workspaceDemo;
  $('monitor-stop').disabled = monitorActionActive || !['running','stopping'].includes(data.state);
  $('monitor-check').disabled = monitorActionActive || !live;
  $('monitor-delete').disabled = monitorActionActive || !data.email;
  $('monitor-state').textContent = (data.email ? data.email + ' · ' : '') + data.state.replaceAll('_',' ') + ' · ' + (data.account_count || 0) + ' saved services · ' + (data.unread_alerts || 0) + ' unread alerts' + (data.error ? ' · ' + data.error : '') + (workspaceDemo ? ' · Demo loaded: live monitoring is disabled; demo report download is available.' : '');
  const coverage = data.coverage || {};
  $('monitor-coverage').textContent = 'Last successful inbox check: ' + date(data.gmail_checked_at) + ' · Last breach-check attempt: ' + date(data.breach_checked_at) + '. ' + (coverage.history_gap ? 'COVERAGE GAP: ' + coverage.gap_note + ' ' : '') + (coverage.backlog_pending ? 'New messages are queued for the next pass. ' : '') + (data.note || 'Start monitoring after connecting Gmail.');
  const alerts = $('monitor-alerts'); alerts.replaceChildren(node('h2','Monitoring alerts'));
  if (!data.alerts?.length) alerts.append(node('p','No saved alerts for the current monitoring session/mailbox. This is not an assessment that the account is safe.','evidence-note'));
  for (const alert of data.alerts || []) {
    const card = node('article',undefined,'monitor-alert ' + alert.kind + (alert.acknowledged ? ' acknowledged' : ''));
    card.append(node('h3',alert.title),node('p',date(alert.created_at)),node('p',alert.detail));
    if (!alert.acknowledged) {
      const button = workspaceButton('Acknowledge',async()=>{
        button.disabled=true;
        try { await api('/monitor/alerts/'+alert.id+'/ack',{method:'POST'}); await refreshMonitor(); }
        catch(error){showMessage(error.message,true);button.disabled=false;}
      },'secondary');card.append(button);
    } else card.append(node('p','Acknowledged · this does not mark an account secured.','evidence-note'));
    alerts.append(card);
  }
  $('monitor-inventory-note').textContent='Showing '+(data.accounts?.length || 0)+' of '+(data.account_count || 0)+' saved services. Download the report for the complete inventory. Records are retained on this computer until you delete them.';
  const inventory=$('monitor-inventory');inventory.replaceChildren();
  for(const item of data.accounts || []) {
    const check=item.breach_check || {}; const action=check.known_breach || item.security_alert || item.password_event;
    const row=node('div',undefined,'monitor-inventory-row');
    row.append(node('span',item.service_name+' · '+item.domain),node('span',action?'Action / review needed':check.status==='checked'?'No flagged signals':'Not checked',action?'action-needed':check.status==='checked'?'':'check-needed'));inventory.append(row);
  }
  reportButtons();
}
async function refreshMonitor() {
  if(monitorRefreshActive)return;
  monitorRefreshActive=true;
  try {
    const data=await api('/monitor/status');
    const maximum=Math.max(0,...(data.alerts || []).map(alert=>alert.id));
    const sameMailbox=monitorSnapshot && monitorSnapshot.email===data.email;
    const incoming=monitorAlertCursor==null || !sameMailbox?[]:(data.alerts || []).filter(alert=>alert.id>monitorAlertCursor && !alert.acknowledged);
    if(incoming.length && typeof Notification!=='undefined' && Notification.permission==='granted') {
      let enabled=false;try{enabled=localStorage.getItem('cybertwin.monitor-notifications')==='yes';}catch{}
      if(enabled)try{new Notification('Cyber Twin: '+incoming.length+' new alert(s)',{body:incoming[0].title,tag:'cybertwin-monitor'});}catch{}
    }
    monitorAlertCursor=maximum;monitorSnapshot=data;renderMonitor();
  } catch {
    $('monitor-state').textContent='Cannot reach the monitoring server. Status is unknown; saved information may be stale.';
  } finally {monitorRefreshActive=false;}
}
async function monitorAction(path,body) {
  if(monitorActionActive)return;
  monitorActionActive=true;renderMonitor();
  try {
    const result=await api(path,{method:'POST',headers:{'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
    if(result.message)showMessage(result.message);
    await refreshMonitor();
  } catch(error){showMessage(error.message,true);}
  finally{monitorActionActive=false;renderMonitor();}
}
async function downloadFootprint(kind) {
  if(reportBusy)return;
  reportBusy=true;reportButtons();
  const saved=$('report-source').value==='monitor';
  const button=$(kind==='pdf'?'report-pdf':'report-html');button.disabled=true;
  $('report-status').textContent='Preparing your '+(workspaceDemo && !saved?'fictional demo ':'')+'report…';
  try {
    const options=saved?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      services:workspaceRecords,checks:moduleBreachData?.checks || [],email:workspaceCoverage?.mailbox_email || null,
      coverage:workspaceCoverage || {},is_demo:workspaceDemo,checked_at:moduleBreachData?.checked_at || null})};
    const response=await fetch(saved?'/monitor/report.'+kind:'/reports/footprint.'+kind,options);
    if(!response.ok){let error={};try{error=await response.json();}catch{}throw new Error(typeof error.detail==='string'?error.detail:'Report could not be generated.');}
    const url=URL.createObjectURL(await response.blob());const link=document.createElement('a');link.href=url;link.download='digital-footprint-security-report.'+kind;
    document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
    $('report-status').textContent='Report downloaded. It contains personal account information; keep it private.';
  } catch(error){$('report-status').textContent=error.message;}
  finally{reportBusy=false;reportButtons();}
}
document.addEventListener('DOMContentLoaded',()=>{
  $('monitor-start').addEventListener('click',()=>{
    const matched=!workspaceDemo && workspaceRecords.length && workspaceCoverage?.mailbox_email;
    monitorAction('/monitor/start',{seed_services:matched?workspaceRecords:[],seed_email:matched?workspaceCoverage.mailbox_email:null,
      scan_complete:matched?Boolean(workspaceCoverage.scan_complete):false,messages_scanned:matched?workspaceCoverage.messages_scanned || 0:0,
      gmail_interval:Number($('monitor-inbox-interval').value),breach_interval:Number($('monitor-breach-interval').value)});
  });
  $('monitor-stop').addEventListener('click',()=>monitorAction('/monitor/stop'));
  $('monitor-check').addEventListener('click',()=>monitorAction('/monitor/check-now'));
  $('monitor-notify').addEventListener('click',async()=>{
    if(typeof Notification==='undefined'){showMessage('This browser does not support desktop alerts. Alerts are still saved in the app.');return;}
    let permission;try{permission=await Notification.requestPermission();}catch{showMessage('Browser alerts are unavailable here. Saved in-app alerts still work.');return;}
    try{localStorage.setItem('cybertwin.monitor-notifications',permission==='granted'?'yes':'no');}catch{}
    showMessage(permission==='granted'?'Browser alerts enabled while this dashboard is open. Saved alerts remain available in the app.':'Browser alerts were not enabled. In-app alert history still works.');
  });
  $('monitor-delete').addEventListener('click',async()=>{
    if(!window.confirm('Stop monitoring and delete saved service records, checkpoints and alerts for this mailbox from this computer? Downloaded reports will remain.'))return;
    try{const result=await api('/monitor/data',{method:'DELETE'});showMessage(result.message);monitorAlertCursor=null;await refreshMonitor();}
    catch(error){showMessage(error.message,true);}
  });
  $('report-source').addEventListener('change',reportButtons);
  $('report-pdf').addEventListener('click',()=>downloadFootprint('pdf'));
  $('report-html').addEventListener('click',()=>downloadFootprint('html'));
  initialConnectionStatus.finally(refreshMonitor);
  monitorTimer=setInterval(refreshMonitor,15000);
});
window.addEventListener('pagehide',()=>{if(monitorTimer)clearInterval(monitorTimer);});
