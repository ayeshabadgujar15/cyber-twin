'use strict';
const fs=require('node:fs'), vm=require('node:vm'), assert=require('node:assert/strict');
class Element {
  constructor(tag,text=''){this.tag=tag;this.ownText=text;this.children=[];this.listeners={};this.value='';this.hidden=false;this.attributes={};}
  append(...items){this.children.push(...items);}
  prepend(...items){this.children.unshift(...items);}
  replaceChildren(...items){this.children=items;this.ownText='';}
  setAttribute(key,value){this.attributes[key]=value;}
  addEventListener(event,fn){this.listeners[event]=fn;}
  get textContent(){return this.ownText+this.children.map(item=>item.textContent).join('');}
  set textContent(value){this.ownText=String(value);this.children=[];}
  set innerHTML(value){throw new Error('Provider data must not be rendered as HTML');}
}
const elements=new Map();
const get=id=>{if(!elements.has(id))elements.set(id,new Element('section'));return elements.get(id);};
const ctx=vm.createContext({
  document:{addEventListener(){},getElementById:get}, $:get,
  node:(tag,text='',cls='')=>{const item=new Element(tag,text);item.className=cls;return item;},
  metric:(label,value)=>new Element('div',label+value), safeLink:(url,text)=>new Element('a',text),date:value=>value||'Not supplied',
  workspaceButton:(label,action)=>{const b=new Element('button',label);b.addEventListener('click',action);return b;},
  renderReviewQueue(){},renderMigration(){},showMessage(){},
  MigrationModel:require('../app/static/email_migration_model.js'),
  workspaceRecords:[{domain:'example.com',service_name:'Example',timeline:[]}],workspaceCoverage:{mailbox_email:'owner@example.com'},workspaceDemo:false,workspaceInsights:null,activeView:'breaches'
});
vm.runInContext(fs.readFileSync(__dirname+'/../app/static/module_workflow.js','utf8'),ctx);
const result={is_demo:false,note:'Service history only.',checks:[{domain:'example.com',service_name:'Example',status:'checked',known_breach:true,breaches:[{name:'Example incident',description:'Plain description',breach_date:'2023-04-17',breach_year:2023,data_exposed:['Passwords'],verified:true}]}],security_plan:[{domain:'example.com',service_name:'Example',priority:'review_first',reason:'Service history; personal exposure unknown.',steps:[{id:'password',title:'Review password',detail:'Change if exposed.'}]}]};
(async()=>{
  ctx.api=async()=>result;
  await ctx.checkServiceBreaches();
  assert.ok(get('service-breach-results').textContent.includes('2023-04-17'));
  assert.ok(get('service-breach-results').textContent.includes('Plain description'));
  ctx.renderSecurityModule();
  assert.ok(get('security-plan-results').textContent.includes('Review password'));
  const oldRequest={};ctx.api=()=>new Promise(resolve=>oldRequest.resolve=resolve);
  const pending=ctx.checkServiceBreaches();ctx.workspaceRecords=[];ctx.resetModuleWorkflow();oldRequest.resolve(result);await pending;
  assert.equal(vm.runInContext('moduleBreachData',ctx),null,'A late response must not repopulate a cleared/new mailbox snapshot');
  assert.equal(get('check-service-breaches').disabled,true);
  assert.equal(get('security-plan-results').children.length,0);
  console.log('Module UI handoff, breach details, security actions and stale-response checks passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
