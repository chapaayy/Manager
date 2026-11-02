"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");

const html=fs.readFileSync("v2/static/index.html","utf8");
const css=fs.readFileSync("v2/static/style.css","utf8");
const core=fs.readFileSync("v2/static/core.js","utf8");
const nodes=fs.readFileSync("v2/static/nodes.js","utf8");
const library=fs.readFileSync("v2/static/library.js","utf8");
const settings=fs.readFileSync("v2/static/settings.js","utf8");
const app=fs.readFileSync("v2/static/app.js","utf8");
const nodeDetail=fs.readFileSync("v2/static/node-detail.js","utf8");
const nodeSecurity=fs.readFileSync("v2/static/node-security.js","utf8");
const nodeMonitoring=fs.readFileSync("v2/static/node-monitoring.js","utf8");
const vps=fs.readFileSync("v2/static/vps.js","utf8");
const frontend=[core,nodes,library,settings,app,nodeDetail,nodeSecurity,nodeMonitoring,vps].join("\n");

for(const [name,source] of Object.entries({
  core,nodes,library,settings,app,nodeDetail,nodeSecurity,nodeMonitoring,vps
})){
  assert.doesNotThrow(()=>new vm.Script(source),name+" must parse as JavaScript");
}
assert.doesNotThrow(
  ()=>new vm.Script(frontend),
  "Classic frontend scripts must share one global lexical scope without duplicate declarations"
);

const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
const unique=new Set(ids);
assert.equal(unique.size,ids.length,"Every HTML id must be unique");
for(const id of [
  "login-screen","login-username","login-password","panel-caddy-key","panel-caddy-details",
  "shell","sidebar","toggle-sidebar","page-nodes","page-configs","page-presets",
  "page-settings","page-updates","update-check","update-start","update-status","other-nodes",
  "modal","monitoring-form","monitoring-interval","config-files","config-content",
  "config-save","preset-form","panel-form","vps-dialog","vps-form","vps-probe-button",
  "vps-install",
]){
  assert(unique.has(id),"Required UI element: "+id);
}

assert.match(html,/\/static\/icons\.svg/);
for(const asset of ["core","library","settings","nodes"]){
  assert.match(html,new RegExp("/static/"+asset+"[.]js[?]v=1[.]0[.]0"));
}
assert.match(html,/\/static\/app\.js\?v=3\.0\.0/);
assert.match(css,/\.sidebar\.collapsed/);
assert.match(css,/\.workspace\{flex:1;min-width:0;width:0/);
assert.match(css,/prefers-reduced-motion/);

assert.match(vps,/async function installVps/,"SSH VPS wizard must launch install");
assert(!html.includes('id="panel-profile-select"'),"Remove obsolete global profile setting");
assert.doesNotMatch(html,/id="bridge-list"/,"Bridge topology is removed from active UI");
assert.doesNotMatch(html,/id="new-bridge"/,"No create bridge action");
assert.doesNotMatch(html,/value="entry"|value="exit"/,"VPS role selector is regular-only");
assert.doesNotMatch(html,/id="page-agents"|id="page-node-certs"/,
  "Old standalone Agent/TLS pages must not remain hidden in the DOM");
assert.doesNotMatch(html,/id="plan-dialog"|id="plan-diff"|id="plan-json"/,
  "Disabled Bridge plan UI must not remain hidden in the DOM");

assert.match(library,/highlightTokens/,"Editor highlights template parameters");
assert.match(html,/data-config-category="xray"/,"Xray tab shown");
assert.match(html,/data-config-category="system"/,"Server configuration tab shown");
assert.match(library,/configCategory==="xray"/,"Tab actually filters configuration files");
assert.match(html,/id="preset-mode"/,"Preset deployment mode editable");
assert.match(vps,/renderVpsPresets/,"VPS wizard lists installation presets");
assert.match(core,/restartMonitoringTimer/,"Monitoring interval controls automatic refresh");
assert.match(nodeDetail,/loadNodeSSHCredentials/,"Node workspace shows saved SSH credentials");
assert.match(vps,/preset_id:data.preset_id/,"Preview uses chosen preset");

assert.match(core,/X-CSRF-Token/,"Mutating calls need CSRF");
assert.match(settings,/caddy_api_key/,"Save-and-check sends optional Caddy API key");
assert.match(settings,/async function checkUpdates/,"Check GitHub updates inside the panel");
assert.match(settings,/async function startUpdate/,"Start updates inside the panel");
assert.match(app,/await signIn\(\s*\$\("login-username"\)/,"Login requires username");
assert(!html.includes("wizard-project"),"Multi-panel project control must be absent");
assert(!frontend.includes("projectCache"),"Multi-panel project JavaScript must be absent");

assert.doesNotMatch(html,/data-page="agents"/,"No Agents sidebar item");
assert.doesNotMatch(html,/data-page="node-certs"/,"No TLS sidebar item");
assert.match(html,/id="node-detail"/,"Node detail in Nodes page");
assert.match(nodeDetail,/function openNodeWorkspace/,"Unified node workspace");
assert.match(html,/node-security[.]js[?]v=1[.]2[.]0/,"Security dashboard asset loaded");
assert.match(html,/node-monitoring[.]js[?]v=1[.]0[.]0/,"Monitoring dashboard asset loaded");
assert.match(nodeSecurity,/function securityNetworkBody/,"Network page uses compact security layout");
assert.match(nodeDetail,/monitor:"Мониторинг"/,"Node has dedicated Monitoring tab");
assert.match(nodeMonitoring,/function refreshNodeMonitoring/,"Monitoring tab has incremental live refresh");
assert.match(nodeMonitoring,/function drawMonitoringChart/,"Monitoring tab renders SVG charts");
assert.match(core,/selectedNodeTab==="monitor"/,"Fast interval only refreshes Monitoring tab");
assert.doesNotMatch(core,/if\(selectedNodeId\)\{\s*await refreshNodeWorkspaceData/,
  "Fast timer must not rerender management tabs");
assert.match(nodeSecurity,/function saveNodeSecuritySettings/,"Structured security profile can be saved and applied");
assert.match(nodeSecurity,/function unbanNodeSSH/,"Unban action requires confirmation");
assert.match(nodeSecurity,new RegExp("security-settings/apply"),
  "Security changes use a dedicated confirmed endpoint");
assert.match(nodeSecurity,/Remnawave Node API · TCP 2222/,"Node API firewall is clearly named");

assert.match(nodeDetail,/function nodeCertText/,"Inline certificate state");
assert.match(nodes,/async function nodeLifecycleModal/,"Node lifecycle confirmation UI exists");
assert.match(nodes,/\/removal-preview/,"Deletion preview inspects Remnawave assignments");
assert.match(nodes,/\/remove","POST"/,"Deletion uses one scoped API operation");
assert.doesNotMatch(frontend,/continueFullNodeDeletion/,"UI must not invoke VPS full cleanup");
assert.doesNotMatch(frontend,/\/full\/start/,"UI must not start destructive VPS cleanup");
assert.match(nodes,/shared_profile_confirmation|shared_confirmation/,
  "Shared profile requires explicit confirmation");
assert.match(nodes,/Удалить запись из XPPN Manager/,"Manager removal is always explicit");
assert.match(nodes,/toggle-node-archive/,"Archive remains available");
assert.match(vps,/await nodeLifecycleModal\(id\)/,"Failed install removal uses the same wizard");
assert.match(html,/nodes-show-archived/,"Archived nodes can be shown");

assert.match(nodes,/migrateNodeTLSModal/,"UI supports per-node TLS path migration");
assert.match(nodeDetail,/data-tls-migrate/,"TLS migration remains an explicit node action");

for(const dead of [
  "function bridgeModal(","function bridgeExitModal(","function bridgeImportModal(",
  "function openPlan(","function openPlanId(","renderAgents(","renderNodeCertificates("
]){
  assert(!frontend.includes(dead),"Dead legacy frontend must be removed: "+dead);
}
assert(app.split("\n").length<80,"app.js should remain a thin composition layer");
assert(core.split("\n").length<220,"core.js should stay focused");
assert(nodes.split("\n").length<320,"nodes.js should stay focused");
assert(library.split("\n").length<300,"library.js should stay focused");
assert(settings.split("\n").length<220,"settings.js should stay focused");

console.log("PASS: modular single-panel v2 frontend wiring and layout");
