'use strict';
let workspaceRecords = [];
let workspaceCoverage = null;
let workspaceInsights = null;
let workspaceDemo = false;
let workspaceTab = 'accounts';
let reviewCategory = '';
const reviewedItems = new Set();
let activeScanId = null;
let cancelScanRequested = false;
const categoryNames = {security:'Security', password:'Password', billing:'Billing', forgotten:'Forgotten accounts', identity:'Unconfirmed accounts'};

function workspaceButton(label, action, cls = 'secondary') { const button = node('button', label, cls); button.type = 'button'; button.addEventListener('click', action); return button; }
function clearWorkspace() {
  $('email-breach-results').replaceChildren();
  workspaceRecords = []; workspaceInsights = null; workspaceCoverage = null; workspaceDemo = false; currentResults = []; reviewedItems.clear(); document.body.classList.remove('has-workspace', 'show-scan-options');
  for (const id of ['workspace-insights', 'review-area', 'all-activity', 'results']) { $(id).replaceChildren(); $(id).hidden = true; }
  $('empty-state').hidden = false;
  if (typeof resetModuleWorkflow === 'function') resetModuleWorkflow();
  showMessage('Results cleared from this page. Nothing was deleted from Gmail.');
}
function selectWorkspaceTab(tab) {
  workspaceTab = tab;
  $('results').hidden = tab !== 'accounts'; $('review-area').hidden = tab !== 'review'; $('all-activity').hidden = tab !== 'timeline';
  document.querySelectorAll('[data-workspace-tab]').forEach(button => { button.classList.toggle('selected', button.dataset.workspaceTab === tab); button.setAttribute('aria-pressed', String(button.dataset.workspaceTab === tab)); });
  if (tab === 'review') renderReviewQueue();
  if (tab === 'timeline') renderCombinedTimeline();
}
function renderWorkspace(records, coverage, insights, demo) {
  const area = $('workspace-insights');
  if (!insights || records.some(record => record.provider)) { area.hidden = true; $('review-area').hidden = true; $('all-activity').hidden = true; return; }
  document.body.classList.add('has-workspace'); document.body.classList.remove('show-scan-options'); $('toggle-scan-controls').setAttribute('aria-expanded', 'false');
  workspaceRecords = records; workspaceCoverage = coverage; workspaceInsights = insights; workspaceDemo = Boolean(demo); reviewedItems.clear(); reviewCategory = ''; workspaceTab = 'accounts';
  area.replaceChildren(); area.hidden = false;
  const banner = node('div', undefined, workspaceDemo ? 'workspace-banner demo-banner' : 'workspace-banner');
  banner.append(node('div', workspaceDemo ? 'DEMO WORKSPACE · FICTIONAL DATA' : 'YOUR MAILBOX SNAPSHOT', 'eyebrow'), node('h2', workspaceDemo ? 'Demo account snapshot.' : 'Your evidence snapshot.'), node('p', workspaceDemo ? 'These example accounts are fictional. Your Gmail has not been read.' : 'A view of the evidence you scanned. Review clues at your own pace; email alone does not verify account ownership.'));
  banner.append(workspaceButton('Clear results', clearWorkspace, 'text-button')); area.append(banner);
  const stats = node('div', undefined, 'overview-grid');
  for (const [label, value, note, action] of [
    ['Services found', insights.service_count, 'Exact sender domains', () => selectWorkspaceTab('accounts')],
    ['Recent evidence', insights.recent_services, 'Within 90 days · not live activity', () => selectWorkspaceTab('accounts')],
    ['Security alerts', insights.security_services, 'Alert/attempt wording · excludes OTPs', () => { openSecurityReview('security'); }],
    ['Billing clues', insights.billing_services, 'Receipts or renewal wording', () => { openSecurityReview('billing'); }],
  ]) { const button = workspaceButton('', action, 'overview-stat'); button.append(node('span', label, 'stat-label'), node('strong', String(value), 'stat-value'), node('small', note)); stats.append(button); }
  area.append(stats);
  const story = node('div', undefined, 'activity-story'); const intro = node('div'); intro.append(node('div', 'THE SHAPE OF YOUR EVIDENCE', 'eyebrow'), node('h3', 'Evidence by month.'), node('p', 'Classified notifications by UTC month, not time spent online. Select a month to explore its evidence.')); story.append(intro);
  const chart = node('div', undefined, 'month-chart'); chart.setAttribute('aria-label', 'Classified evidence over the last twelve months');
  const maximum = Math.max(1, ...insights.monthly_activity.map(month => month.evidence_count));
  for (const month of insights.monthly_activity) { const label = new Date(month.month + '-01T12:00:00Z').toLocaleString(undefined, {month:'short', timeZone:'UTC'}); const button = workspaceButton('', () => { selectWorkspaceTab('timeline'); $('timeline-month').value = month.month; $('timeline-month').dispatchEvent(new Event('change')); }, 'month-column'); button.setAttribute('aria-label', month.month + ': ' + month.evidence_count + ' evidence records'); button.title = month.month + ' · ' + month.evidence_count + ' records'; const track = node('span', undefined, 'bar-track'); const bar = node('span', undefined, 'bar-fill'); bar.style.height = Math.max(3, month.evidence_count / maximum * 100) + '%'; if (!month.evidence_count) bar.className += ' empty-bar'; track.append(bar); button.append(node('small', String(month.evidence_count), 'bar-count'), track, node('small', label, 'month-label')); chart.append(button); } story.append(chart); const monthly = node('details', undefined, 'module-chart'); monthly.append(node('summary', 'Optional: monthly evidence chart'), story); area.append(monthly);
  const nav = node('div', undefined, 'workspace-tabs'); nav.setAttribute('aria-label', 'Explore your evidence');
  for (const [tab, label] of [['accounts', 'My accounts'], ['timeline', 'All activity']]) { const button = workspaceButton(label, () => selectWorkspaceTab(tab), 'workspace-tab' + (tab === 'accounts' ? ' selected' : '')); button.dataset.workspaceTab = tab; button.setAttribute('aria-pressed', String(tab === 'accounts')); nav.append(button); } area.append(nav);
  $('review-area').hidden = true; $('all-activity').hidden = true;
}
function renderReviewQueue() {
  const area = $('review-area'); area.replaceChildren();
  const heading = node('div', undefined, 'results-heading'); heading.append(node('h2', 'Account review queue.'), node('span', reviewedItems.size + ' reviewed this session', 'subtle')); area.append(heading);
  area.append(node('p', 'These are review prompts, not confirmed threats or subscriptions. Your review marks stay in this page only and reset on a new scan or refresh.', 'evidence-note'));
  const toolbar = node('div', undefined, 'result-toolbar'); const category = node('select'); category.setAttribute('aria-label', 'Review category');
  for (const [value, label] of [['', 'All review prompts'], ...Object.entries(categoryNames)]) { const option = node('option', label); option.value = value; category.append(option); } category.id = 'review-category'; category.value = reviewCategory; category.addEventListener('change', () => { reviewCategory = category.value; renderReviewQueue(); $('review-category').focus(); }); toolbar.append(category); area.append(toolbar);
  const visible = workspaceInsights.review_queue.filter(item => !reviewCategory || item.category === reviewCategory);
  if (!visible.length) area.append(node('p', 'No prompts in this category within the scanned evidence. This does not establish that the accounts are secure or inactive.', 'coverage'));
  for (const item of visible) {
    const checked = reviewedItems.has(item.id); const card = node('article', undefined, 'review-card' + (checked ? ' reviewed' : ''));
    const top = node('div', undefined, 'review-card-heading'); top.append(node('span', categoryNames[item.category], 'review-kind ' + item.category), node('span', date(item.observed_at), 'subtle')); card.append(top);
    card.append(node('h3', item.title), node('p', item.service_name + ' · ' + item.domain, 'review-service'), node('p', item.explanation), node('div', item.suggested_action, 'suggested-action'));
    const actions = node('div', undefined, 'review-actions'); const actionId = 'review-' + encodeURIComponent(item.id); const mark = workspaceButton(checked ? '✓ Reviewed this session · Undo' : 'Mark reviewed this session', () => { if (reviewedItems.has(item.id)) reviewedItems.delete(item.id); else reviewedItems.add(item.id); renderReviewQueue(); $(actionId).focus(); }, checked ? 'secondary' : 'primary'); mark.id = actionId; actions.append(mark, workspaceButton('See account evidence', () => { document.querySelector('[data-view="gmail"]').click(); selectWorkspaceTab('accounts'); const filter = $('results').querySelector('input'); filter.value = item.domain; filter.dispatchEvent(new Event('input')); filter.focus({preventScroll:true}); $('results').scrollIntoView({behavior:'smooth', block:'start'}); }, 'text-button')); card.append(actions); area.append(card);
  }
  if (workspaceInsights.review_queue_truncated) area.append(node('p', 'Showing the first 1,000 prompts. Use account evidence to explore the remaining services.', 'evidence-note'));
}
function renderCombinedTimeline() {
  const area = $('all-activity'); area.replaceChildren(); area.append(node('h2', 'All activity.'));
  area.append(node('p', 'Filters apply to loaded evidence only. Times reflect email metadata, not verified session times.', 'evidence-note'));
  const toolbar = node('div', undefined, 'result-toolbar');
  const search = node('input'); search.placeholder = 'Find a service'; search.setAttribute('aria-label', 'Find a service in all activity');
  const kind = node('select'); kind.setAttribute('aria-label', 'Event type');
  for (const [value, label] of [['', 'All event types'], ...Object.entries(labels)]) { const option = node('option', label); option.value = value; kind.append(option); }
  const month = node('select'); month.id = 'timeline-month'; month.setAttribute('aria-label', 'Evidence month');
  const all = node('option', 'All dates in this scan'); all.value = ''; month.append(all);
  const events = workspaceRecords.flatMap(service => (service.timeline || []).map(event => ({...event, domain:service.domain, name:service.service_name}))).sort((a,b) => new Date(b.observed_at) - new Date(a.observed_at));
  const months = [...new Set(events.map(event => new Date(event.observed_at).toISOString().slice(0,7)))].sort().reverse();
  for (const value of [...new Set([...months, ...workspaceInsights.monthly_activity.map(item => item.month)])].sort().reverse()) { const option = node('option', value); option.value = value; month.append(option); }
  toolbar.append(search, kind, month); area.append(toolbar);
  const count = node('p', '', 'subtle'); count.setAttribute('role', 'status'); count.setAttribute('aria-live', 'polite'); area.append(count); const list = node('ol', undefined, 'timeline combined-timeline'); area.append(list);
  let pageLimit = 100; const more = workspaceButton('Show 100 more records', () => { pageLimit += 100; draw(); }); area.append(more);
  function draw() { list.replaceChildren(); const matches = events.filter(event => (event.domain + ' ' + event.name).toLowerCase().includes(search.value.toLowerCase()) && (!kind.value || event.event_type === kind.value) && (!month.value || new Date(event.observed_at).toISOString().startsWith(month.value))); count.textContent = Math.min(pageLimit, matches.length) + ' of ' + matches.length + ' matching records';
    for (const event of matches.slice(0,pageLimit)) { const item = node('li'); item.append(node('strong', labels[event.event_type] || event.event_type), node('p', event.name + ' · ' + event.domain, 'timeline-service'), node('span', date(event.observed_at) + ' · ' + basis(event.timestamp_basis)), node('small', event.classification_explanation || 'Normalized source evidence.')); list.append(item); } more.hidden = matches.length <= pageLimit; if (!matches.length) list.append(node('li', 'No loaded evidence matches these filters.')); }
  for (const input of [search, kind, month]) input.addEventListener(input === search ? 'input' : 'change', () => { pageLimit = 100; draw(); }); draw();
}
function hideWorkspacePanels() { for (const id of ['workspace-insights', 'review-area', 'all-activity']) $(id).hidden = true; }
document.addEventListener('DOMContentLoaded', () => {
  $('toggle-scan-controls').addEventListener('click', () => { const open = document.body.classList.toggle('show-scan-options'); $('toggle-scan-controls').setAttribute('aria-expanded', String(open)); });
  $('demo-button').addEventListener('click', () => run(async () => { const data = await api('/accounts/activity-demo'); renderRecords(data.services, data.coverage, 'Example accounts', data.insights, true); }, 'Preparing fictional sample evidence…'));
  $('disconnect-gmail').addEventListener('click', () => run(async () => { await api('/gmail/disconnect', {method:'POST'}); clearWorkspace(); await refreshStatus(); }, 'Clearing the local Gmail connection…'));
  document.querySelectorAll('[data-scan-limit]').forEach(button => button.addEventListener('click', () => { $('message-limit').value = button.dataset.scanLimit; document.querySelectorAll('[data-scan-limit]').forEach(item => item.setAttribute('aria-pressed', String(item === button))); }));
});


async function runMailboxScan() {
  const panel = $('scan-progress'); const startedAt = Date.now();
  panel.hidden = false; $('cancel-scan').disabled = false; $('scan-progress-meter').removeAttribute('value');
  $('scan-progress-text').textContent = 'Starting a read-only scan…'; cancelScanRequested = false;
  try {
    let source = null;
    try { source = await api('/gmail/identity'); } catch { /* The scan still works; migration import requires verified identity. */ }
    const job = await api('/accounts/activity/scans?max_messages=' + encodeURIComponent($('message-limit').value), {method:'POST'});
    activeScanId = job.scan_id;
    while (true) {
      if (cancelScanRequested) { await api('/accounts/activity/scans/' + activeScanId, {method:'DELETE'}); cancelScanRequested = false; }
      const state = await api('/accounts/activity/scans/' + activeScanId);
      const progress = state.progress || {}; const fetched = progress.message_fetches || 0;
      if (progress.message_limit) { $('scan-progress-meter').max = progress.message_limit; $('scan-progress-meter').value = fetched; } else { $('scan-progress-meter').removeAttribute('value'); }
      $('scan-progress-text').textContent = fetched + ' messages inspected · ' + (progress.messages_scanned || 0) + ' received messages · ' + Math.floor((Date.now() - startedAt) / 1000) + 's elapsed';
      if (state.status === 'completed') { const data = state.result; if (source && source.connection_generation === job.connection_generation) data.coverage.mailbox_email = source.email; renderRecords(data.services, data.coverage, 'Your account evidence', data.insights, false); await api('/accounts/activity/scans/' + activeScanId, {method:'DELETE'}); break; }
      if (state.status === 'cancelled') { $('scan-progress-text').textContent = 'Scan cancelled. Partial results were discarded.'; return {notice:'Scan cancelled. No partial results were kept.'}; }
      if (state.status === 'failed') throw new Error(state.error?.detail || 'Scan failed. Try reconnecting Gmail.');
      if (state.status === 'cancelling') $('scan-progress-text').textContent += ' · stopping after the current request';
      await new Promise(resolve => setTimeout(resolve, 800));
    }
  } finally { activeScanId = null; $('cancel-scan').disabled = true; panel.hidden = true; }
}
document.addEventListener('DOMContentLoaded', () => {
  $('cancel-scan').addEventListener('click', () => { cancelScanRequested = true; $('cancel-scan').disabled = true; $('scan-progress-text').textContent = 'Cancellation requested. The current network request may finish first.'; });
});

window.addEventListener('pagehide', () => { if (activeScanId) fetch('/accounts/activity/scans/' + activeScanId, {method:'DELETE', keepalive:true}).catch(() => {}); });

document.addEventListener('DOMContentLoaded', () => {
  $('check-email-breaches').addEventListener('click', async () => {
    const button = $('check-email-breaches'); const area = $('email-breach-results');
    button.disabled = true; area.replaceChildren(node('p', 'Checking your connected email…'));
    try {
      const data = await api('/accounts/email-breaches', {method:'POST'});
      area.replaceChildren(node('p', data.note));
      if (data.status === 'checked') {
        area.append(node('p', data.email + ': ' + data.breaches.length + ' breach records returned.'));
        for (const breach of data.breaches) area.append(breachEvent(breach));
      }
    } catch (error) { area.replaceChildren(node('p', error.message)); }
    finally { button.disabled = false; }
  });
  $('revoke-gmail').addEventListener('click', () => run(async () => {
    await api('/gmail/disconnect?revoke=true', {method:'POST'});
    $('email-breach-results').replaceChildren(); clearWorkspace();
    return {notice:'Google permission revoked. Local connection and results cleared.'};
  }, 'Revoking Google permission…'));
});
