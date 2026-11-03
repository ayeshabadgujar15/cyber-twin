'use strict';
const $ = id => document.getElementById(id);
let busy = false;
let activeView = 'gmail';
let currentResults = [];
const titles = {migration: ['Move email', 'Move on from your old email.', 'Keep track of accounts to update before you retire an old address.'], public: ['GitHub profile', 'Inspect a GitHub profile.', 'Public profile dates and recent public activity for a username you choose.'], gmail: ['Inbox & services', '1. Connect your inbox.', 'Connect your email, scan the mailbox and see the services you may have joined.'], breaches: ['Breach lookup', '2. Look up service breaches.', 'Use the service list from Module 1 to inspect known breach history.'], secure: ['Secure accounts', '3. Secure your accounts.', 'Follow practical steps based on the breach results and your mailbox evidence.'], guide: ['Help & setup', 'Get connected. Start discovering.', 'Fix Google access, check the setup, and understand your results.']};
function node(tag, text, cls) { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (cls) element.className = cls; return element; }
function showMessage(text, error = false) { const box = $('message'); box.textContent = text; box.className = 'message' + (error ? ' error' : ''); box.hidden = false; }
function date(value) { if (!value) return 'Not available'; const parsed = new Date(value); if (Number.isNaN(parsed.getTime())) return 'Not available'; return parsed.toLocaleString(undefined, {year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', timeZoneName:'short'}); }
const labels = {account_creation:'Account creation evidence', account_verification:'Verification request', login:'Successful-login notification', security:'Security notification', password:'Password event', transaction:'Transaction signal', activity:'Activity evidence'};
function basis(value) { return (value || 'unspecified').replaceAll('_', ' ').replace(/^public event:.*/, 'public event'); }
function safeLink(url, title) { try { const parsed = new URL(url); if (parsed.protocol !== 'https:') return node('span', title); const link = node('a', title); link.href = parsed.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; return link; } catch { return node('span', title); } }
function metric(label, value, note) { const box = node('div', undefined, 'metric'); box.append(node('div', label, 'metric-label'), node('div', value, 'metric-value')); if (note) box.append(node('small', note)); return box; }
function card(record) {
  const service = record.service || record;
  const box = node('article', undefined, 'result-card');
  const head = node('div', undefined, 'account-head'); head.append(node('div', record.provider === 'chess.com' ? '♞' : '◈', 'account-icon'));
  const name = node('div'); name.append(node('h3', record.username || service.service_name || service.domain)); name.append(record.profile_url ? safeLink(record.profile_url, service.domain + ' ↗') : node('span', service.domain, 'subtle')); head.append(name);
  const status = service.activity_status || 'unknown'; head.append(node('span', {recent_evidence:'Recent evidence', possibly_dormant:'Possibly dormant', unknown:'Activity unknown'}[status], 'badge' + (status === 'recent_evidence' ? '' : ' neutral'))); box.append(head);
  const metrics = node('div', undefined, 'metrics'); metrics.append(metric('FIRST DATED EVIDENCE', date(service.first_seen)), metric('LAST DATED EVIDENCE', date(service.last_seen), record.last_seen_basis ? basis(record.last_seen_basis) : 'Latest classified mailbox evidence'));
  const locations = record.locations || []; if (record.provider) metrics.append(metric('REPORTED LOCATION', locations.length ? locations.map(x => x.value).join(' · ') : 'Not available', locations.length ? 'Profile/provider reported · not current location' : 'This source supplied no location evidence')); else metrics.append(metric('CLASSIFIED MESSAGES', String((service.timeline || []).length))); box.append(metrics);
  if (record.provider) box.append(node('p', 'Public activity: ' + date(record.last_public_activity) + ' · Account ownership has not been verified.', 'evidence-note'));
  else box.append(node('p', 'Latest successful-login notification: ' + date(service.last_confirmed_login) + ' · Latest security event: ' + date(service.last_security_event), 'evidence-note'));
  if (record.coverage?.note) box.append(node('p', record.coverage.note, 'evidence-note'));
  if (record.profile_updated_at) box.append(node('p', 'Profile updated: ' + date(record.profile_updated_at) + ' · Metadata edit, not a login or public activity date.', 'evidence-note'));
  for (const location of locations) { const attribution = node('p', location.source + ' · ' + location.kind.replaceAll('_', ' ') + ' · Retrieved ' + date(location.retrieved_at) + ' · ', 'evidence-note'); if (location.source_url) attribution.append(safeLink(location.source_url, 'Location source ↗')); box.append(attribution); }
  if (record.linked_profiles?.length) { const links = node('div', undefined, 'evidence-note'); links.append(node('p', 'Provider-linked profiles · not independently checked or assigned to you')); for (const url of record.linked_profiles) { const line = node('p'); line.append(safeLink(url, url)); links.append(line); } box.append(links); }
  if (record.coverage?.activity_error) box.append(node('p', 'Activity feed unavailable: ' + record.coverage.activity_error, 'coverage partial'));
  const confidence = node('details'); confidence.append(node('summary', 'Evidence strength: ' + (service.confidence_score || 0) + '/100 · What does this mean?'), node('p', service.confidence_explanation || 'Heuristic evidence strength, not an accuracy percentage.', 'evidence-note')); box.append(confidence);
  if (service.activity_status_explanation) confidence.append(node('p', service.activity_status_explanation, 'evidence-note'));
  const timeline = [...(service.timeline || [])].reverse(); const detail = node('details'); detail.open = currentResults.length === 1; detail.append(node('summary', 'Evidence timeline · ' + timeline.length + ' event' + (timeline.length === 1 ? '' : 's')));
  if (!timeline.length) detail.append(node('p', 'No supported dated evidence was returned.', 'evidence-note'));
  const list = node('ol', undefined, 'timeline'); for (const event of timeline) { const item = node('li'); item.append(node('strong', labels[event.event_type] || event.event_type), node('span', date(event.observed_at) + ' · ' + event.source + ' · ' + basis(event.timestamp_basis))); if (event.classification_explanation) item.append(node('small', event.classification_explanation)); list.append(item); } detail.append(list); box.append(detail); return box;
}
function renderRecords(records, coverage, title, insights = null, demo = false) {
  const publicLookup = records.some(record => record.provider);
  if (!publicLookup && typeof renderWorkspace === 'function') { renderWorkspace(records, coverage, insights, demo); workspaceRecords = records; workspaceCoverage = coverage; workspaceInsights = insights; workspaceDemo = Boolean(demo); if (typeof resetModuleWorkflow === 'function') resetModuleWorkflow(); }
  currentResults = records; const area = $(publicLookup ? 'public-results' : 'results'); area.replaceChildren(); area.hidden = false; $('empty-state').hidden = true;
  const heading = node('div', undefined, 'results-heading'); heading.append(node('h2', title), node('span', records.length + ' result' + (records.length === 1 ? '' : 's'), 'subtle')); area.append(heading);
  if (coverage) { const partial = coverage.scan_complete === false || coverage.history_complete === false; let text = coverage.messages_scanned !== undefined ? coverage.messages_scanned + ' messages scanned. ' + (coverage.scan_complete ? 'Reached the end of the mailbox.' : 'Partial scan — messages may be missing. Review the coverage details before drawing conclusions.') : coverage.note || 'Public source coverage is incomplete.'; if (demo) text = coverage.messages_scanned + ' fictional sample records. No Gmail mailbox was read.'; if (coverage.oldest_scanned_evidence) text += ' Scanned dates: ' + date(coverage.oldest_scanned_evidence) + ' to ' + date(coverage.newest_scanned_evidence) + '.'; if (coverage.unavailable_messages) text += ' ' + coverage.unavailable_messages + ' messages became unavailable during scanning.'; if (coverage.excluded_sent_or_draft) text += ' ' + coverage.excluded_sent_or_draft + ' sent/draft messages excluded.'; area.append(node('div', text, 'coverage' + (partial ? ' partial' : ''))); }
  if (!records.length) { area.append(node('p', 'No supported evidence found in this lookup. This does not prove an account is absent or inactive.', 'evidence-note')); return; }
  const toolbar = node('div', undefined, 'result-toolbar'); const filter = node('input'); filter.placeholder = 'Filter results by service or username'; filter.setAttribute('aria-label', 'Filter results'); const statusFilter = node('select'); statusFilter.setAttribute('aria-label', 'Filter by activity status');
  for (const [value, label] of [['', 'All activity states'], ['recent_evidence', 'Recent evidence'], ['possibly_dormant', 'Possibly dormant'], ['unknown', 'Activity unknown']]) { const option = node('option', label); option.value = value; statusFilter.append(option); }
  const securityOnly = node('input'); securityOnly.type = 'checkbox'; const securityLabel = node('label', 'Show security/password evidence '); securityLabel.prepend(securityOnly);
  toolbar.append(filter, statusFilter, securityLabel); area.append(toolbar);
  const cards = records.map(record => { const element = card(record); area.append(element); return {element, service: record.service || record, text: JSON.stringify([record.username, (record.service || record).domain, (record.service || record).service_name]).toLowerCase()}; }); const applyFilters = () => { let visible = 0; for (const item of cards) { const matches = item.text.includes(filter.value.toLowerCase()) && (!statusFilter.value || item.service.activity_status === statusFilter.value) && (!securityOnly.checked || (item.service.timeline || []).some(event => ['security', 'password'].includes(event.event_type))); item.element.hidden = !matches; if (matches) visible += 1; } heading.lastChild.textContent = visible + ' of ' + cards.length + ' results'; heading.lastChild.setAttribute('role', 'status'); heading.lastChild.setAttribute('aria-live', 'polite'); };
  filter.addEventListener('input', applyFilters); statusFilter.addEventListener('change', applyFilters); securityOnly.addEventListener('change', applyFilters);
}
async function api(url, options) { const response = await fetch(url, options); let data; try { data = await response.json(); } catch { throw new Error('The server returned an unexpected response. Restart Cyber Twin and try again.'); } if (!response.ok || data.error) { let message = data.detail || data.error || 'Request failed.'; if (Array.isArray(message)) message = message.map(x => x.msg).join(' · '); throw new Error((data.source_outcome ? data.source_outcome + ': ' : '') + message); } return data; }
async function run(task, text) { if (busy) return; busy = true; if (typeof hideWorkspacePanels === 'function') hideWorkspacePanels(); const buttons = [...document.querySelectorAll('form button, #discover-button, #demo-button, #disconnect-gmail')]; const states = buttons.map(button => button.disabled); buttons.forEach(button => button.disabled = true); $('results').hidden = true; $('empty-state').hidden = true; showMessage(text); try { const outcome = await task(); if (outcome?.notice) showMessage(outcome.notice); else $('message').hidden = true; } catch (error) { showMessage(error.message || 'Unable to complete the request.', true); await refreshStatus(); } finally { busy = false; buttons.forEach((button, index) => button.disabled = states[index]); await refreshStatus(); if (typeof restoreModuleView === 'function') restoreModuleView(); } }
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => { if (busy) { showMessage('Please wait for the current lookup to finish.'); return; } activeView = button.dataset.view; document.querySelectorAll('[data-view]').forEach(item => item.classList.toggle('selected', item === button)); document.querySelectorAll('.view-panel').forEach(panel => panel.hidden = panel.id !== activeView + '-panel'); $('breadcrumb').textContent = titles[activeView][0]; $('page-title').textContent = titles[activeView][1]; $('page-description').textContent = titles[activeView][2]; $('message').hidden = true; $('results').hidden = true; if (typeof hideWorkspacePanels === 'function') hideWorkspacePanels(); $('empty-state').hidden = activeView !== 'gmail'; document.querySelector('.optional-check').hidden = activeView !== 'breaches'; if (typeof restoreModuleView === 'function') restoreModuleView(); }));

document.querySelectorAll('[data-example]').forEach(button => button.addEventListener('click', () => { $('username').value = button.dataset.example.split(':')[1]; $('username').focus(); }));
$('setup-help').addEventListener('click', () => document.querySelector('[data-view="guide"]').click());
$('public-form').addEventListener('submit', event => { event.preventDefault(); run(async () => { const data = await api('/accounts/public-activity', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({provider:'github', username:$('username').value.trim()})}); renderRecords([data], data.coverage, 'GitHub profile evidence'); }, 'Looking up the GitHub profile…'); });
$('gmail-form').addEventListener('submit', event => { event.preventDefault(); run(async () => { return await runMailboxScan(); }, 'Reading Gmail metadata and reconstructing account evidence… Larger scans can take several minutes.'); });
$('discover-button').addEventListener('click', () => run(async () => {
  const data = await api('/accounts/discover');
  const records = data.accounts.map(account => ({...account, timeline:[], activity_status:'unknown', confidence_score:0}));
  renderRecords(records, {scan_complete:false, note:'Legacy registration search: first 100 matches per phrase; not a complete mailbox scan.'}, 'Registration service clues');
}, 'Searching registration emails…'));
async function refreshStatus() {
  try {
    const status = await api('/api/status');
    $('gmail-state').textContent = status.gmail_connected ? '● Gmail connected · read-only access' : '○ Connect Gmail to find your accounts';
    $('scan-button').disabled = !status.gmail_connected;
    $('discover-button').disabled = !status.gmail_connected; if ($('disconnect-gmail')) $('disconnect-gmail').hidden = !status.gmail_connected;
    const setup = await api('/gmail/setup');
    $('setup-state').textContent = setup.configured ? 'Ready. Click Connect Gmail and choose your account.' : 'Complete the one-time Desktop app setup above, then click Connect Gmail.';
    $('desktop-setup').open = !setup.configured;
    $('callback-url').textContent = setup.callback_url || 'GOOGLE_REDIRECT_URI in your project .env';
    $('audience-link').href = setup.audience_url;
    if (setup.dashboard_url) $('canonical-dashboard').href = setup.dashboard_url;
    window.gmailSetupReady = setup.configured;
    $('connect-gmail').href = setup.configured ? '/gmail/login?return_to_dashboard=true' : '/?gmail_error=configuration';
  } catch { showMessage('Cannot reach Cyber Twin. Make sure the server is running.', true); }
}
const initialConnectionStatus = refreshStatus();
const params = new URLSearchParams(location.search);
if (params.get('gmail') === 'connected') { showMessage('Gmail connected. Preparing your service scan…'); history.replaceState(null, '', '/'); }
if (params.has('gmail_error')) {
  document.querySelector('[data-view="guide"]').click();
  const errors = {configuration:'Google setup is incomplete. Follow the setup checklist below.', access_denied:'Google did not grant access. Add your Gmail account to the Google Cloud test-user list, then reconnect.', token_exchange:'The Google connection could not be completed. Check the exact callback URL, then reconnect.'};
  showMessage(errors[params.get('gmail_error')] || 'Reconnect Gmail using the setup guide.', true);
  history.replaceState(null, '', '/');
}

document.getElementById('desktop-client-form').addEventListener('submit', async event => {
  event.preventDefault(); const file = document.getElementById('desktop-client-file').files[0];
  const status = document.getElementById('desktop-client-status');
  if (!file || file.size > 100000) { status.textContent = 'Choose the small Google Desktop client JSON file.'; return; }
  const button = event.currentTarget.querySelector('button'); button.disabled = true;
  try {
    const raw = await file.text();
    try { JSON.parse(raw); } catch { throw new Error('Choose a valid JSON file.'); }
    const result = await api('/gmail/setup-client', {method:'POST', headers:{'Content-Type':'application/json'}, body:raw});
    status.textContent = result.message; document.getElementById('desktop-client-file').value = '';
    await refreshStatus(); document.querySelector('[data-view="gmail"]').click(); showMessage('Setup complete. Click Connect Gmail.');
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
});
