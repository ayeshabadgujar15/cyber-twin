'use strict';
// Only migration decisions are saved. Mail contents, credentials and timelines
// never enter this model. Shared with the offline tests.
const MigrationModel = (() => {
  const validEmail = value => typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  const validDomain = value => typeof value === 'string' && value.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);
  function normalizeEmail(value) {
    const email = String(value || '').trim().toLowerCase();
    if (!validEmail(email)) throw new Error('Enter a valid old email address.');
    return email;
  }
  function read(raw) {
    if (!raw) return [];
    const data = JSON.parse(raw);
    if (data.version !== 1 || !Array.isArray(data.plans)) throw new Error('Saved migration data is not supported.');
    for (const plan of data.plans) {
      if (!validEmail(plan.email) || !Array.isArray(plan.items)) throw new Error('Saved migration checklist is invalid.');
      for (const item of plan.items) {
        if (!validDomain(item.domain) || typeof item.name !== 'string' || item.name.length > 200 || !['essential', 'other'].includes(item.priority) || !['pending', 'updated'].includes(item.status)) throw new Error('Saved migration entry is invalid.');
      }
    }
    if (new Set(data.plans.map(plan => plan.email)).size !== data.plans.length) throw new Error('Saved migration checklists contain duplicates.');
    return data.plans;
  }
  function merge(plan, services) {
    const seen = new Set(plan.items.map(item => item.domain));
    let added = 0;
    for (const service of services) {
      const domain = String(service.domain || '').trim().toLowerCase();
      if (!validDomain(domain) || seen.has(domain)) continue;
      plan.items.push({domain, name: String(service.service_name || domain).slice(0, 200), priority:'other', status:'pending'});
      seen.add(domain); added++;
    }
    return added;
  }
  function canImport(plan, coverage, demo, records) {
    return Boolean(plan && !demo && coverage && typeof coverage.mailbox_email === 'string' && coverage.mailbox_email.toLowerCase() === plan.email && records.length && !records.some(record => record.provider));
  }
  return {normalizeEmail, validDomain, read, merge, canImport};
})();
if (typeof module !== 'undefined') module.exports = MigrationModel;
