"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");
const html=fs.readFileSync("v2/static/index.html","utf8");
const js=fs.readFileSync("v2/static/app.js","utf8");
const css=fs.readFileSync("v2/static/style.css","utf8");
new vm.Script(js);
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
const unique=new Set(ids);
assert.equal(unique.size,ids.length,"Every HTML id must be unique");
for(const id of [
  "login-screen","login-username","login-password","shell","sidebar","toggle-sidebar","page-nodes","page-configs",
  "page-presets","page-settings","bridge-list","other-nodes","modal","plan-dialog",
  "config-files","config-content","config-save","preset-form","panel-form",
  "panel-profile-select","plan-diff","plan-json","plan-approve",
]){
  assert(unique.has(id),"Required UI element: "+id);
}
assert.match(html,/\/static\/icons\.svg/);
assert.match(html,/\/static\/app\.js\?v=2\.1\.0/);
assert.match(css,/\.sidebar\.collapsed/);
assert.match(css,/\.workspace\{flex:1;min-width:0;width:0/);
assert.match(css,/prefers-reduced-motion/);
assert.match(js,/bridgeExitModal/,"Bridge expansion is functional");
assert.match(js,/highlightTokens/,"Editor highlights template parameters");
assert.match(js,/X-CSRF-Token/,"Mutating calls need CSRF");
assert.match(js,/await signIn\(\$\("login-username"\)/,"Login requires username");
assert(!html.includes("wizard-project"),"Multi-panel project control must be absent");
assert(!js.includes("projectCache"),"Multi-panel project JavaScript must be absent");
console.log("PASS: clean single-panel v2 interface wiring and layout");
