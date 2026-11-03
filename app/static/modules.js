'use strict';
let moduleBreachData = null;
let moduleSourceVersion = 0;
let breachRequestActive = false;
const reviewedSecuritySteps = new Set();

function moduleServices() {
  return workspaceRecords.filter(service => MigrationModel.validDomain(service.domain)).map(service => ({
    domain:service.domain, service_name:String(service.service_name || service.domain).slice(0,200),
    security_alert:(service.timeline || []).some(event => event.event_type === 'security' && event.confidence_score >= 85),
    password_event:(service.timeline || []).some(event => event.event_type === 'password')
  }));
}
function resetModuleWorkflow() {
  moduleSourceVersion++; moduleBreachData = null; reviewedSecuritySteps.clear();
  $('security-plan-results').replaceChildren();
  $('continue-breaches').hidden = !workspaceRecords.length;
  $('email-breach-results').replaceChildren();
  renderBreachModule();
}
function restoreModuleView() {
  if (activeView === 'gmail') {
    $('empty-state').hidden = Boolean(workspaceRecords.length);
    $('results').hidden = !workspaceRecords.length;
    $('workspace-insights').hidden = !workspaceInsights;
    $('all-activity').hidden = true;
  } else if (activeView === 'breaches') renderBreachModule();
  else if (activeView === 'secure') renderSecurityModule();
}
function openSecurityReview(category) {
  document.querySelector('[data-view="secure"]').click();
  reviewCategory = category; $('review-details').open = true;
  if (workspaceInsights) { renderReviewQueue(); $('review-area').hidden = false; }
}
function breachEvent(breach) {
  const area = node('section', undefined, 'breach-event');
  area.append(node('h4', breach.name), node('p', 'Reported incident date: ' + (breach.breach_date || 'Not supplied') + (breach.breach_year ? ' · Year ' + breach.breach_year : '')));
  area.append(node('p', breach.description || 'No description supplied.'));
  const meta = node('div', undefined, 'breach-meta');
  meta.append(metric('DATA EXPOSED', (breach.data_exposed || []).join(', ') || 'Not supplied'), metric('RECORDS INDEXED BY PROVIDER', breach.affected_records == null ? 'Not supplied' : Number(breach.affected_records).toLocaleString()));
  area.append(meta, node('p', breach.is_demo ? 'FICTIONAL INCIDENT · DEMO ONLY' : breach.verified ? 'Verified by HIBP' : 'Unverified report · source and attribution need care', 'evidence-note'));
  if (breach.match_type === 'sender_subdomain') area.append(node('p', 'Matched parent service domain: ' + breach.domain + '. The email sender has not been authenticated.', 'evidence-note'));
  const details = node('details'); details.append(node('summary', 'Catalogue dates & source'), node('p', 'Added to catalogue: ' + date(breach.added_date) + ' · Updated: ' + date(breach.modified_date), 'evidence-note'));
  if (breach.source_url) details.append(safeLink(breach.source_url, 'HIBP source record ↗'));
  if (breach.attribution) details.append(node('p', 'Attribution: ' + breach.attribution));
  if (breach.sensitive || breach.retired) details.append(node('p', 'Provider flags: ' + [breach.sensitive ? 'sensitive' : '', breach.retired ? 'retired' : ''].filter(Boolean).join(', ')));
  area.append(details); return area;
}
function renderBreachModule() {
  const services = moduleServices(); const area = $('service-breach-results'); area.replaceChildren();
  $('check-service-breaches').disabled = !services.length || breachRequestActive;
  $('breach-source').textContent = services.length ? services.length + ' service domains from ' + (workspaceDemo ? 'the fictional demo.' : workspaceCoverage?.mailbox_email || 'your loaded mailbox scan.') : 'Complete Module 1 to load your service list.';
  if (workspaceRecords.length > services.length) area.append(node('p', (workspaceRecords.length - services.length) + ' sender domains are invalid for breach lookup and were not checked.', 'coverage partial'));
  if (!moduleBreachData) { area.append(node('p', 'Service breach history has not been checked for this snapshot.', 'coverage')); return; }
  if (moduleBreachData.is_demo) area.append(node('p', 'DEMO · All breach records below are fictional. No provider was contacted.', 'module-demo'));
  area.append(node('p', moduleBreachData.note, 'evidence-note'));
  const toolbar = node('div', undefined, 'result-toolbar'); const search = node('input'); search.placeholder='Find a service'; search.setAttribute('aria-label','Find a service in breach results');
  const only = node('input'); only.type='checkbox'; const label=node('label','Only services with breach records '); label.prepend(only); toolbar.append(search,label); area.append(toolbar);
  const count = node('p','','subtle'); count.setAttribute('role','status'); count.setAttribute('aria-live','polite'); area.append(count);
  const list=node('div'); area.append(list); let limit=50;
  const more=workspaceButton('Show 50 more services',()=>{limit+=50; draw();}); area.append(more);
  function draw() {
    list.replaceChildren(); const matches=moduleBreachData.checks.filter(check=>(check.domain+' '+check.service_name).toLowerCase().includes(search.value.toLowerCase()) && (!only.checked || check.known_breach === true));
    count.textContent=Math.min(limit,matches.length)+' of '+matches.length+' services'; more.hidden=limit>=matches.length;
    for (const check of matches.slice(0,limit)) {
    const card = node('article', undefined, 'breach-card'); card.append(node('h3', check.service_name || check.domain), node('p', check.domain, 'subtle'));
    card.append(node('p', check.status !== 'checked' ? 'Lookup unavailable · not checked' : check.known_breach ? check.breaches.length + ' service breach record(s) found' : 'No matching service breach returned · this does not establish safety.'));
    if (check.note) card.append(node('p', check.note, 'evidence-note'));
    for (const breach of check.breaches || []) card.append(breachEvent(breach));
    list.append(card);
    }
  }
  search.addEventListener('input',()=>{limit=50;draw();}); only.addEventListener('change',()=>{limit=50;draw();}); draw();
}
async function checkServiceBreaches() {
  const services = moduleServices(); if (!services.length || breachRequestActive) return;
  const version = moduleSourceVersion; breachRequestActive = true; renderBreachModule();
  showMessage(workspaceDemo ? 'Preparing fictional breach examples…' : 'Checking public service breach history…');
  try {
    const data = await api('/accounts/service-breaches', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({services,is_demo:workspaceDemo})});
    if (version !== moduleSourceVersion) return;
    moduleBreachData = data;
    showMessage(data.checks.some(check => check.status !== 'checked') ? 'Some breach checks were unavailable. You can retry; Module 3 still offers general guidance.' : 'Breach lookup complete. Continue to Module 3 for security steps.');
  } catch (error) {
    if (version === moduleSourceVersion) showMessage(error.message, true);
  } finally {
    breachRequestActive = false;
    if (activeView === 'breaches') renderBreachModule();
    if (activeView === 'secure') renderSecurityModule();
  }
}
function generalSecurityPlan(services) {
  return services.map(service => ({...service, priority:service.security_alert ? 'review_first' : 'routine',
    reason:'Breach lookup is not completed. These are general protections, not an assessment that your account is safe.',
    steps:[
      {id:'open',title:'Open the service directly',detail:'Use its official app or a trusted bookmark and confirm this account is yours.'},
      {id:'password',title:'Check your password',detail:'Use a unique password. If you find unfamiliar activity or believe the current password was exposed, change it and update other accounts where you reused it.'},
      {id:'mfa',title:'Enable stronger sign-in protection',detail:'Use a passkey, security key or two-factor authentication if supported.'},
      {id:'sessions',title:'Review sessions and recovery settings',detail:'Inspect devices, recent activity, recovery email/phone and connected apps. Follow the service’s recovery process for unfamiliar changes.'}
    ]}));
}
function renderSecurityModule() {
  const area = $('security-plan-results'); area.replaceChildren();
  const services = moduleServices();
  if (!services.length) area.append(node('p', 'Complete Module 1 to get steps for your discovered services.', 'coverage'));
  if (workspaceDemo) area.append(node('p', 'DEMO · Fictional accounts and incident examples.', 'module-demo'));
  const plans = moduleBreachData?.security_plan || generalSecurityPlan(services);
  const toolbar = node('div', undefined, 'result-toolbar'); const search = node('input');
  search.placeholder = 'Find a service to secure'; search.setAttribute('aria-label', 'Find a service to secure'); toolbar.append(search); area.append(toolbar);
  const count = node('p', '', 'subtle'); count.setAttribute('role','status'); count.setAttribute('aria-live','polite'); area.append(count);
  const list = node('div'); area.append(list); let limit = 50;
  const more = workspaceButton('Show 50 more services', () => { limit += 50; draw(); }); area.append(more);
  function draw() {
    list.replaceChildren(); const matches = plans.filter(plan => (plan.domain + ' ' + plan.service_name).toLowerCase().includes(search.value.toLowerCase()));
    count.textContent = Math.min(limit,matches.length) + ' of ' + matches.length + ' services'; more.hidden = limit >= matches.length;
    for (const [index,plan] of matches.slice(0,limit).entries()) {
    const card = node('details', undefined, 'security-service'); card.open = index === 0;
    card.append(node('summary', (plan.service_name || plan.domain) + ' · ' + (plan.priority === 'review_first' ? 'Review first' : 'Routine protection')), node('p', plan.domain, 'subtle'), node('p', plan.reason, 'evidence-note'));
    for (const step of plan.steps) {
      const key = plan.domain + ':' + step.id; const label = node('label', undefined, 'security-step');
      const box = node('input'); box.type = 'checkbox'; box.checked = reviewedSecuritySteps.has(key); box.setAttribute('aria-label', 'Reviewed ' + step.title + ' for ' + plan.domain);
      box.addEventListener('change', () => { if (box.checked) reviewedSecuritySteps.add(key); else reviewedSecuritySteps.delete(key); });
      label.append(box, node('strong', step.title), node('small', step.detail)); card.append(label);
    }
    list.append(card);
    }
  }
  search.addEventListener('input', () => { limit=50; draw(); }); draw();
  area.append(node('p', 'Security settings differ by service. These Google guides illustrate account review and stronger sign-in protection:', 'evidence-note'), safeLink('https://support.google.com/accounts/answer/6294825', 'Google account review ↗'), node('span', ' · '), safeLink('https://support.google.com/accounts/answer/185839', 'Google two-step verification ↗'));
  if (workspaceInsights) { renderReviewQueue(); $('review-area').hidden = false; }
  else $('review-area').hidden = true;
  renderMigration();
}
document.addEventListener('DOMContentLoaded', () => {
  $('connection-email').addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); $('connect-gmail').click(); } });
  $('continue-breaches').addEventListener('click', () => { document.querySelector('[data-view="breaches"]').click(); checkServiceBreaches(); });
  $('check-service-breaches').addEventListener('click', checkServiceBreaches);
  $('continue-security').addEventListener('click', () => document.querySelector('[data-view="secure"]').click());
  $('connect-gmail').addEventListener('click', event => {
    event.preventDefault();
    if (busy) return;
    if (!window.gmailSetupReady) { document.querySelector('[data-view="guide"]').click(); return; }
    const input = $('connection-email'); if (!input.reportValidity()) return;
    try { sessionStorage.setItem('cybertwin.connect-and-scan', JSON.stringify({email:input.value.trim(), limit:$('message-limit').value})); }
    catch { showMessage('Automatic scan could not be remembered. After Google connects, click Start scan.'); }
    location.assign('/gmail/login?return_to_dashboard=true&email=' + encodeURIComponent(input.value.trim()));
  });
  if (params.has('gmail_error')) { try { sessionStorage.removeItem('cybertwin.connect-and-scan'); } catch {} }
  if (params.get('gmail') === 'connected') {
    let pending = null;
    try { pending = JSON.parse(sessionStorage.getItem('cybertwin.connect-and-scan') || 'null'); sessionStorage.removeItem('cybertwin.connect-and-scan'); } catch {}
    if (pending) initialConnectionStatus.then(async () => {
      try {
        const identity = await api('/gmail/identity'); $('connection-email').value = identity.email;
        if (identity.email.toLowerCase() !== String(pending.email).toLowerCase()) {
          showMessage('Google connected ' + identity.email + ' instead of ' + pending.email + '. Click Start scan to inspect the connected inbox, or disconnect to choose another account.', true); return;
        }
        const limit = Number(pending.limit); $('message-limit').value = Number.isInteger(limit) && limit >= 0 && limit <= 10000 ? String(limit) : '0';
        $('gmail-form').requestSubmit();
      } catch { showMessage('Gmail connected. Click Start scan when ready.'); }
    });
  }
  resetModuleWorkflow();
});
