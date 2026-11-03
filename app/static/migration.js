'use strict';
const migrationStorageKey = 'cybertwin.migration.v1';
let migrationPlans = [];
let migrationEmail = '';
let migrationStorageReady = true;

function saveMigration() {
  if (!migrationStorageReady) {
    showMessage('Saved checklist data could not be read. Export or clear this site’s migration data before saving new changes.', true);
    return false;
  }
  try {
    localStorage.setItem(migrationStorageKey, JSON.stringify({version:1, plans:migrationPlans}));
    return true;
  } catch {
    showMessage('This browser could not save your checklist. Changes are temporary until browser storage is available.', true);
    return false;
  }
}
function migrationPlan() { return migrationPlans.find(plan => plan.email === migrationEmail); }
function renderMigration() {
  const area = $('migration-list'); area.replaceChildren();
  const picker = $('migration-picker'); picker.replaceChildren();
  for (const plan of migrationPlans) {
    const option = node('option', plan.email); option.value = plan.email; picker.append(option);
  }
  picker.value = migrationEmail; picker.hidden = migrationPlans.length < 2;
  const plan = migrationPlan();
  $('migration-actions').hidden = !plan;
  $('migration-heading').textContent = plan ? 'Moving away from ' + plan.email : 'Choose the email you want to retire.';
  const source = workspaceCoverage?.mailbox_email;
  const importAllowed = MigrationModel.canImport(plan, workspaceCoverage, workspaceDemo, workspaceRecords);
  $('migration-import').disabled = !importAllowed;
  $('migration-import-note').textContent = importAllowed
    ? 'Add ' + workspaceRecords.length + ' service clues from your loaded scan of ' + source + '. Existing decisions stay unchanged.'
    : 'To import: connect this old Gmail address and run a mailbox scan first. You can also add services manually below. Demo and public-profile results cannot be imported.';
  if (!plan) { $('migration-progress').textContent = ''; return; }
  const updated = plan.items.filter(item => item.status === 'updated').length;
  $('migration-progress').textContent = updated + ' of ' + plan.items.length + ' marked updated · ' + plan.items.filter(item => item.status === 'pending' && item.priority === 'essential').length + ' essential accounts pending';
  const filter = $('migration-filter').value;
  const items = plan.items.filter(item => !filter || item.status === filter).slice().sort((a,b) => (a.status === 'updated') - (b.status === 'updated') || (a.priority !== 'essential') - (b.priority !== 'essential') || a.name.localeCompare(b.name));
  if (!items.length) area.append(node('p', plan.items.length ? 'No accounts match this filter.' : 'Add accounts from a scan, or enter a service you know uses this email.', 'coverage'));
  for (const item of items) {
    const row = node('article', undefined, 'migration-row');
    const info = node('div'); info.append(node('h3', item.name), node('p', item.domain, 'subtle')); row.append(info);
    const priority = node('select'); priority.setAttribute('aria-label', 'Priority for ' + item.domain);
    for (const [value,label] of [['other','Other'],['essential','Essential']]) { const option = node('option', label); option.value = value; priority.append(option); }
    priority.value = item.priority;
    priority.addEventListener('change', () => { item.priority = priority.value; const saved = saveMigration(); renderMigration(); if (saved) showMessage('Migration priority saved in this browser.'); });
    const toggle = node('button', item.status === 'updated' ? 'Updated · Undo' : 'Mark updated', item.status === 'updated' ? 'secondary' : 'primary');
    toggle.type = 'button'; toggle.id = 'migration-status-' + item.domain; toggle.setAttribute('aria-label', (item.status === 'updated' ? 'Mark pending: ' : 'Mark updated: ') + item.domain);
    toggle.addEventListener('click', () => { item.status = item.status === 'updated' ? 'pending' : 'updated'; const saved = saveMigration(); renderMigration(); const next = document.getElementById(toggle.id); if (next) next.focus(); if (saved) showMessage('Migration status saved. This is your confirmation; Cyber Twin has not changed the service.'); });
    row.append(priority, toggle); area.append(row);
  }
}
document.addEventListener('DOMContentLoaded', () => {
  try { migrationPlans = MigrationModel.read(localStorage.getItem(migrationStorageKey)); }
  catch { migrationStorageReady = false; showMessage('Saved migration data could not be loaded. It has not been overwritten.', true); }
  migrationEmail = migrationPlans[0]?.email || '';
  $('migration-form').addEventListener('submit', event => {
    event.preventDefault();
    try {
      const email = MigrationModel.normalizeEmail($('migration-email').value);
      if (!migrationPlans.some(plan => plan.email === email)) migrationPlans.push({email, items:[]});
      migrationEmail = email; const saved = saveMigration(); renderMigration();
      if (saved) showMessage('Checklist ready. Add accounts to update before retiring this email.');
    } catch (error) { showMessage(error.message, true); }
  });
  $('migration-picker').addEventListener('change', () => { migrationEmail = $('migration-picker').value; renderMigration(); });
  $('migration-filter').addEventListener('change', renderMigration);
  $('migration-import').addEventListener('click', () => {
    const plan = migrationPlan();
    if (!MigrationModel.canImport(plan, workspaceCoverage, workspaceDemo, workspaceRecords)) return;
    const added = MigrationModel.merge(plan, workspaceRecords); const saved = saveMigration(); renderMigration();
    if (saved) showMessage(added + ' services added. These are mailbox clues; confirm each account yourself.');
  });
  $('migration-manual-form').addEventListener('submit', event => {
    event.preventDefault(); const plan = migrationPlan(); if (!plan) return;
    const domain = $('migration-domain').value.trim().toLowerCase();
    if (!MigrationModel.validDomain(domain)) { showMessage('Enter a service domain such as example.com, without a URL or email address.', true); return; }
    const added = MigrationModel.merge(plan, [{domain, service_name:domain}]); const saved = saveMigration();
    $('migration-domain').value = ''; renderMigration(); if (saved) showMessage(added ? 'Service added to your migration checklist.' : 'That service is already on your checklist.');
  });
  $('migration-export').addEventListener('click', () => {
    const plan = migrationPlan(); if (!plan) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify({version:1, plans:[plan]}, null, 2)], {type:'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = 'cyber-twin-migration.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $('migration-delete').addEventListener('click', () => {
    if (!migrationPlan() || !window.confirm('Delete this migration checklist from this browser? Your online accounts will not be changed.')) return;
    migrationPlans = migrationPlans.filter(plan => plan.email !== migrationEmail); migrationEmail = migrationPlans[0]?.email || '';
    const saved = saveMigration(); renderMigration(); if (saved) showMessage('Migration checklist deleted from this browser.');
  });
  renderMigration();
});
