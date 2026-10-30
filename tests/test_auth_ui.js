'use strict';
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const path = require('path');
const root = path.join(__dirname, '..');
const script = fs.readFileSync(path.join(root,'manager/static/app.js'),'utf8');
const match = script.match(/function authUI\(showLogin\)\{[^\n]+\}/);
assert(match, 'authUI must define showLogin flag');
const elems = {};
for (const id of ['login-screen','app-screen']) {
  elems[id] = {hidden:true, classList:{ toggle(cls,shouldHide){assert.equal(cls,'hidden');elems[id].hidden=shouldHide;} }};
}
const ctx = { $: id=>elems[id] };
vm.createContext(ctx);
vm.runInContext(match[0],ctx);
ctx.authUI(true);
assert.equal(elems['login-screen'].hidden,false,'Unauthenticated: login visible');
assert.equal(elems['app-screen'].hidden,true,'Unauthenticated: dashboard hidden');
ctx.authUI(false);
assert.equal(elems['login-screen'].hidden,true,'After login: login hidden');
assert.equal(elems['app-screen'].hidden,false,'After login: dashboard visible');
const html=fs.readFileSync(path.join(root,'manager/static/index.html'),'utf8');
assert(html.includes('/assets/app.js?v=1.8.1'),'JS cache busting is required');
console.log('PASS: login/logout screen visibility and static JS version');
