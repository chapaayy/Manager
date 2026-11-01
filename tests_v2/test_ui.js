"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");
const html=fs.readFileSync("v2/static/index.html","utf8");
const js=fs.readFileSync("v2/static/app.js","utf8");
const css=fs.readFileSync("v2/static/style.css","utf8");
new vm.Script(js);
const nodeDetail=fs.readFileSync("v2/static/node-detail.js","utf8");
const nodeSecurity=fs.readFileSync("v2/static/node-security.js","utf8");
new vm.Script(nodeSecurity);
new vm.Script(nodeDetail);
const vps=fs.readFileSync("v2/static/vps.js","utf8");
new vm.Script(vps);
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
const unique=new Set(ids);
assert.equal(unique.size,ids.length,"Every HTML id must be unique");
for(const id of [
  "login-screen","login-username","login-password","panel-caddy-key","panel-caddy-details","shell","sidebar","toggle-sidebar","page-nodes","page-configs",
  "page-presets","page-settings","page-updates","update-check","update-start","update-status","other-nodes","modal",
  "config-files","config-content","config-save","preset-form","panel-form","monitoring-form","monitoring-interval","monitoring-status",
  "metric-nodes","metric-ready","metric-archived","vps-dialog","vps-form","vps-probe-button","vps-install",
]){
  assert(unique.has(id),"Required UI element: "+id);
}
assert.match(html,/\/static\/icons\.svg/);
assert.match(html,/\/static\/app\.js\?v=2\.7\.0/);
assert.match(css,/\.sidebar\.collapsed/);
assert.match(css,/\.workspace\{flex:1;min-width:0;width:0/);
assert.match(css,/prefers-reduced-motion/);
assert.match(vps,/async function installVps/,"SSH VPS wizard must launch install");
assert(!html.includes('id="panel-profile-select"'),"Remove obsolete global profile setting");
assert.doesNotMatch(html,/id="bridge-list"|id="new-bridge"|id="plan-dialog"/,"Bridge topology is removed from active UI");
assert.doesNotMatch(js,/function bridgeExitModal|function bridgeModal/,"Bridge topology JavaScript removed");
assert.match(js,/function renderMonitoringSettings/,"Monitoring settings are functional");
assert.match(js,/function monitoringTick/,"Live monitoring loop exists");
assert.match(js,/setTimeout\(resolve,i<25\?200:500\)/,"Agent task result polling is sub-second");
assert.match(html,/1 секунда · очень быстро/,"One-second monitoring mode offered");
assert.match(html,/5 секунд · обычно/,"Five-second monitoring mode offered");
assert.match(js,/highlightTokens/,"Editor highlights template parameters");
assert.match(html,/data-config-category="xray"/,"Xray tab shown");
assert.match(html,/data-config-category="system"/,"Server configuration tab shown");
assert.match(js,/configCategory==="xray"/,"Tab actually filters configuration files");
assert.match(html,/id="preset-mode"/,"Preset deployment mode editable");
assert.match(vps,/renderVpsPresets/,"VPS wizard lists direct-node installation bundles");
assert.doesNotMatch(vps,/mode==="bridge"|value="entry"|value="exit"/,"VPS wizard has no bridge roles");
assert.match(vps,/preset_id:data.preset_id/,"Preview uses chosen preset");

assert.match(js,/X-CSRF-Token/,"Mutating calls need CSRF");
assert.match(js,/caddy_api_key/,"Save-and-check sends optional Caddy API key");
assert.match(js,/async function checkUpdates/,"Check GitHub updates inside the panel");
assert.match(js,/async function startUpdate/,"Start updates inside the panel");
assert.match(js,/await signIn\(\$\("login-username"\)/,"Login requires username");
assert(!html.includes("wizard-project"),"Multi-panel project control must be absent");
assert(!js.includes("projectCache"),"Multi-panel project JavaScript must be absent");
console.log("PASS: clean single-panel v2 interface wiring and layout");

assert.doesNotMatch(html,/data-page="agents"/,"No Agents sidebar item");
assert.doesNotMatch(html,/data-page="node-certs"/,"No TLS sidebar item");
assert.match(html,/id="node-detail"/,"Node detail in Nodes page");
assert.match(nodeDetail,/function openNodeWorkspace/,"Unified node workspace");
assert.match(nodeDetail,/function loadNodeSSHAccess/,"Saved SSH access is visible per node");
assert.match(nodeDetail,/function loadNodeConfigChoices/,"Independent per-node config choices exist");
assert.match(nodeDetail,/data-node-config-choice-save/,"Config choices have explicit save action");
assert.match(html,/node-security[.]js[?]v=1[.]0[.]0/,"Security dashboard asset loaded");
assert.match(nodeSecurity,/function securityNetworkBody/,"Network page uses compact security layout");
assert.match(nodeSecurity,/function installNodeSSHProtection/,"Confirmed SSH-only install wizard exists");
assert.match(nodeSecurity,/function unbanNodeSSH/,"Unban action requires confirmation");

assert.match(nodeDetail,/function nodeCertText/,"Inline certificate state");
assert.match(js,/async function nodeLifecycleModal/,"Node lifecycle confirmation UI exists");
assert.match(js,/\/removal-preview/,"Deletion preview inspects Remnawave assignments");
assert.match(js,/\/remove","POST"/,"Deletion uses one scoped API operation");
assert.doesNotMatch(js,/continueFullNodeDeletion/,"UI must not invoke VPS full cleanup");
assert.doesNotMatch(js,/\/full\/start/,"UI must not start destructive VPS cleanup");
assert.match(js,/shared_profile_confirmation|shared_confirmation/,"Shared profile requires explicit confirmation");
assert.match(js,/Удалить запись из XPPN Manager/,"Manager removal is always explicit");
assert.match(js,/toggle-node-archive/,"Archive remains available");
assert.match(vps,/await nodeLifecycleModal\(id\)/,"Failed install removal uses the same wizard");
assert.match(html,/nodes-show-archived/,"Archived nodes can be shown");
assert.doesNotMatch(html,/Ноды и мосты|Создать мост|Подключённых выходов|Топология/,"Active bridge labels removed");

assert.match(js,/migrateNodeTLSModal/,"UI supports per-node TLS path migration");
assert.match(js,/data-tls-migrate/,"TLS migration is visible only as an explicit action");
