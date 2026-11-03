const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {}; this.hidden = false; this.value = ''; this.checked = false; this.ownText = ''; }
  set textContent(text) { this.ownText = String(text); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent).join(''); }
  get lastChild() { return this.children.at(-1); }
  append(...children) { this.children.push(...children); }
  prepend(...children) { this.children.unshift(...children); }
  replaceChildren(...children) { this.ownText = ''; this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
const elements = new Map();
const document = {createElement: tag => new Element(tag), getElementById: id => { if (!elements.has(id)) elements.set(id, new Element('div')); return elements.get(id); }};
const context = vm.createContext({document, URL, Date});
const source = fs.readFileSync(__dirname + '/../app/static/dashboard.js', 'utf8').split('async function api(')[0];
vm.runInContext(source, context);
const first = {domain:'alpha.com', service_name:'Alpha', activity_status:'recent_evidence', confidence_score:90, timeline:[
  {event_type:'login', observed_at:'2026-01-01T00:00:00Z', source:'gmail'},
  {event_type:'security', observed_at:'2026-10-01T00:00:00Z', source:'gmail', classification_explanation:'Security challenge; not a confirmed login.'}]};
const second = {domain:'beta.com', service_name:'Beta', activity_status:'unknown', timeline:[]};
context.renderRecords([first, second], {messages_scanned:2, scan_complete:false, unavailable_messages:1}, 'Mailbox');
const area = elements.get('results');
const toolbar = area.children.find(child => child.className === 'result-toolbar');
const [filter, status, securityLabel] = toolbar.children;
const security = securityLabel.children[0];
const cards = area.children.filter(child => child.tag === 'article');
assert.equal(cards.length, 2);
const detail = cards[0].children.filter(child => child.tag === 'details').at(-1);
const list = detail.children.find(child => child.tag === 'ol');
assert.equal(list.children[0].children[0].textContent, 'Security notification');
assert.ok(list.children[0].textContent.includes('not a confirmed login'));
assert.equal(first.timeline[0].event_type, 'login', 'Rendering must not mutate API ordering');
status.value = 'unknown'; status.listeners.change();
assert.equal(cards[0].hidden, true); assert.equal(cards[1].hidden, false);
status.value = ''; security.checked = true; security.listeners.change();
assert.equal(cards[0].hidden, false); assert.equal(cards[1].hidden, true);
filter.value = 'beta'; filter.listeners.input();
assert.ok(cards.every(card => card.hidden));
assert.equal(area.children[0].lastChild.textContent, '0 of 2 results');
assert.ok(area.children[1].textContent.includes('became unavailable'));
console.log('Dashboard filter, newest-first timeline, coverage, and explanation checks passed.');
