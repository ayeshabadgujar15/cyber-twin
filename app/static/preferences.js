'use strict';
let preferenceScope=null;
let preferenceState={reviews:{},actions:[],reminders:[]};
let preferenceLoading=false;
function decisionScope(){
  if(workspaceDemo)return 'demo';
  if(!window.gmailConnected)return null;
  return workspaceCoverage?.mailbox_email || (typeof monitorSnapshot!=='undefined'?monitorSnapshot?.email:null) || null;
}
function localToday(){const d=new Date();return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');}
function findingStatus(domain){return preferenceScope===decisionScope()?preferenceState.reviews[domain] || 'unconfirmed':'unconfirmed';}
function actionRecord(domain,id){return preferenceScope===decisionScope()?preferenceState.actions.find(item=>item.domain===domain && item.action_id===id):null;}
function actionDone(domain,id){return actionRecord(domain,id)?.status==='done';}
function demoReminders(){preferenceState.reminders=preferenceState.actions.filter(item=>item.status==='pending' && item.due_date && item.due_date<=localToday() && preferenceState.reviews[item.domain]!=='dismissed');}
function repaintDecisions(){
  document.querySelectorAll('.finding-controls').forEach(box=>box.replaceWith(findingControls(box.dataset.domain)));
  renderActionReminders();
  if(activeView==='breaches')renderBreachModule();
  if(activeView==='secure')renderSecurityModule();
}
async function refreshPreferences(){
  const scope=decisionScope();if(preferenceLoading)return;
  if(scope!==preferenceScope){preferenceScope=scope;preferenceState={reviews:{},actions:[],reminders:[]};}
  if(!scope){repaintDecisions();return;}
  if(scope==='demo'){
    try{const saved=JSON.parse(localStorage.getItem('cybertwin.demo-decisions.v1') || 'null');if(saved && typeof saved.reviews==='object' && Array.isArray(saved.actions))preferenceState=saved;}catch{}
    demoReminders();repaintDecisions();return;
  }
  preferenceLoading=true;
  try{
    const data=await api('/preferences?today='+localToday(),{headers:{'X-CyberTwin-Mailbox':scope}});
    if(decisionScope()===scope && data.email===scope.toLowerCase()){preferenceScope=scope;preferenceState=data;repaintDecisions();}
  }catch{renderActionReminders();}
  finally{preferenceLoading=false;}
}
async function saveDecision(path,body){
  const scope=decisionScope();if(!scope)throw new Error('Load a Gmail scan to save decisions for its mailbox.');
  if(scope!==preferenceScope){await refreshPreferences();if(scope!==preferenceScope)throw new Error('Mailbox changed. Try again.');}
  if(scope==='demo'){
    const copy=JSON.parse(JSON.stringify(preferenceState));
    if(path==='finding')copy.reviews[body.domain]=body.status;
    else{copy.actions=copy.actions.filter(item=>!(item.domain===body.domain && item.action_id===body.action_id));copy.actions.push(body);}
    localStorage.setItem('cybertwin.demo-decisions.v1',JSON.stringify(copy));preferenceState=copy;demoReminders();
  }else{
    const data=await api('/preferences/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...body,email:scope,today:localToday()})});
    if(decisionScope()!==scope || data.email!==scope.toLowerCase())return;
    preferenceState=data;
  }
  repaintDecisions();
}
function findingControls(domain){
  const box=node('div',undefined,'finding-controls');box.dataset.domain=domain;
  const status=findingStatus(domain);if(status==='dismissed')box.classList.add('dismissed');
  box.append(node('span',status==='confirmed'?'Confirmed by you':status==='dismissed'?'Dismissed · excluded from checks':'Account ownership unconfirmed'));
  for(const [value,title] of status==='unconfirmed'?[['confirmed','Confirm mine'],['dismissed','Dismiss']]:[['unconfirmed','Undo']]){
    const button=workspaceButton(title,async()=>{button.disabled=true;try{await saveDecision('finding',{domain,status:value});}catch(error){showMessage(error.message,true);button.disabled=false;}},'secondary');
    button.disabled=!decisionScope() || !MigrationModel.validDomain(domain);box.append(button);
  }
  return box;
}
async function saveSecurityAction(domain,step,done,due){
  const previous=actionRecord(domain,step.id);
  await saveDecision('action',{domain,action_id:step.id,title:step.title,status:done?'done':'pending',due_date:due===undefined?previous?.due_date || null:due || null});
}
function actionReminderControl(domain,step){
  const label=node('label',undefined,'action-reminder');label.append(node('span','Remind me in app:'));
  const input=node('input');input.type='date';input.value=actionRecord(domain,step.id)?.due_date || '';input.setAttribute('aria-label','Reminder date for '+step.title+' on '+domain);input.disabled=!decisionScope();
  input.addEventListener('change',async()=>{input.disabled=true;try{await saveSecurityAction(domain,step,actionDone(domain,step.id),input.value);}catch(error){showMessage(error.message,true);}finally{input.disabled=false;}});
  label.append(input);return label;
}
function renderActionReminders(){
  const area=$('action-reminders');if(!area)return;area.replaceChildren();
  if(preferenceScope!==decisionScope())return;
  const items=preferenceState.reminders || [];
  if(!items.length)return;
  area.append(node('strong',items.length+' pending action(s) due today or overdue'));
  for(const item of items.slice(0,50)){
    const row=node('div');row.append(node('p',item.domain+' · '+item.title+' · due '+item.due_date));
    row.append(workspaceButton('Mark done',async()=>{try{await saveSecurityAction(item.domain,{id:item.action_id,title:item.title},true,item.due_date);}catch(error){showMessage(error.message,true);}},'secondary'));area.append(row);
  }
}
document.addEventListener('DOMContentLoaded',()=>{
  $('clear-preferences').addEventListener('click',async()=>{
    const scope=decisionScope();if(!scope || !window.confirm('Clear saved finding reviews, action statuses and reminder dates for this mailbox?'))return;
    try{
      if(scope==='demo'){localStorage.removeItem('cybertwin.demo-decisions.v1');preferenceState={reviews:{},actions:[],reminders:[]};}
      else preferenceState=await api('/preferences',{method:'DELETE',headers:{'X-CyberTwin-Mailbox':scope}});
      repaintDecisions();showMessage('Saved reviews and actions cleared. Online accounts were not changed.');
    }catch(error){showMessage(error.message,true);}
  });
  initialConnectionStatus.finally(refreshPreferences);
  setInterval(()=>{if(decisionScope())refreshPreferences();},60000);
});
