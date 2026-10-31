"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");
const html=fs.readFileSync("v2/static/index.html","utf8");
const js=fs.readFileSync("v2/static/app.js","utf8");
const css=fs.readFileSync("v2/static/style.css","utf8");
new vm.Script(js);
const vps=fs.readFileSync("v2/static/vps.js","utf8");
new vm.Script(vps);
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
const unique=new Set(ids);
assert.equal(unique.size,ids.length,"Every HTML id must be unique");
for(const id of [
  "login-screen","login-username","login-password","panel-caddy-key","panel-caddy-details","shell","sidebar","toggle-sidebar","page-nodes","page-configs",
  "page-presets","page-settings","page-updates","update-check","update-start","update-status","bridge-list","other-nodes","modal","plan-dialog",
  "config-files","config-content","config-save","preset-form","panel-form",
  "plan-diff","plan-json","plan-approve","vps-dialog","vps-form","vps-probe-button","vps-install",
]){
  assert(unique.has(id),"Required UI element: "+id);
}
assert.match(html,/\/static\/icons\.svg/);
assert.match(html,/\/static\/app\.js\?v=2\.4\.1/);
assert.match(css,/\.sidebar\.collapsed/);
assert.match(css,/\.workspace\{flex:1;min-width:0;width:0/);
assert.match(css,/prefers-reduced-motion/);
assert.match(vps,/async function installVps/,"SSH VPS wizard must launch install");
assert(!html.includes('id="panel-profile-select"'),"Remove obsolete global profile setting");
assert.match(js,/bridgeExitModal/,"Bridge expansion is functional");
assert.match(js,/highlightTokens/,"Editor highlights template parameters");
assert.match(js,/X-CSRF-Token/,"Mutating calls need CSRF");
assert.match(js,/caddy_api_key/,"Save-and-check sends optional Caddy API key");
assert.match(js,/async function checkUpdates/,"Check GitHub updates inside the panel");
assert.match(js,/async function startUpdate/,"Start updates inside the panel");
assert.match(js,/await signIn\(\$\("login-username"\)/,"Login requires username");
assert(!html.includes("wizard-project"),"Multi-panel project control must be absent");
assert(!js.includes("projectCache"),"Multi-panel project JavaScript must be absent");
console.log("PASS: clean single-panel v2 interface wiring and layout");

assert.match(js,/async function nodeLifecycleModal/,"Node lifecycle confirmation UI exists");
assert.match(js,/continueFullNodeDeletion/,"Full cleanup is resumable in the UI");
assert.match(html,/nodes-show-archived/,"Archived nodes can be shown");

assert.match(js,/Уже удалена — убрать запись из менеджера/,"Offline VPS prompts local deletion");
assert.match(js,/value="full" disabled/,"Offline VPS cannot trigger agent-only cleanup");
assert.match(js,/value="abandon"/,"An interrupted deletion has explicit local-only recovery");
assert.match(js,/node-lifecycle-profile-option/,"Profile removal checkbox has contextual visibility");
