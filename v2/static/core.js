"use strict";
const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
}[c]));
const icon = name => '<svg><use href="/static/icons.svg#i-'+name+'"></use></svg>';
const titles = {nodes:"Ноды",configs:"Конфигурации",presets:"Пресеты",settings:"Настройки",updates:"Обновления"};
let csrf = "", currentPage = "nodes", toastTimer = null;
let state = {panel:{},nodes:[],configs:[],presets:[]};
let monitoringTimer = null, monitoringMs = 5000;

function message(text, error=false){
  const box = $("toast");
  box.textContent = text;
  box.classList.toggle("error",error);
  box.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>box.classList.remove("visible"),4400);
}
function apiError(value){
  if(typeof value === "string")return value;
  if(value && typeof value.detail === "string")return value.detail;
  if(value && Array.isArray(value.detail))return value.detail.map(x=>x.msg).join("; ");
  return "Неизвестная ошибка";
}
async function api(path,method="GET",payload){
  const headers = {"Accept":"application/json"};
  if(payload !== undefined)headers["Content-Type"]="application/json";
  if(method!=="GET")headers["X-CSRF-Token"]=csrf;
  let response;
  try{
    response = await fetch("/api"+path,{method,headers,credentials:"same-origin",
      ...(payload===undefined?{}:{body:JSON.stringify(payload)})});
  }catch{
    throw new Error("Сервер менеджера недоступен. Проверь соединение.");
  }
  let body=null;
  try{body=await response.json()}catch{}
  if(!response.ok){
    if(response.status===401&&path!=="/auth/login")setAuthorized(false);
    throw new Error(apiError(body)||"HTTP "+response.status);
  }
  return body;
}
function setAuthorized(value){
  $("login-screen").classList.toggle("hidden",value);
  $("shell").classList.toggle("hidden",!value);
}
async function refresh(){
  const [dashboard,configs,presets]=await Promise.all([
    api("/dashboard"),api("/configs"),api("/presets")
  ]);
  // Supplemental state may fail without making the server list unusable.
  const extra=await Promise.allSettled([api("/agents"),api("/node-certificates")]);
  if(extra[0].status==="fulfilled")nodeOverviewAgents=extra[0].value.agents||[];
  if(extra[1].status==="fulfilled")nodeOverviewCerts=extra[1].value.nodes||[];
  state.panel=dashboard.panel;
  monitoringMs=Math.max(1000,Number(state.panel.monitor_interval||5)*1000);
  restartMonitoringTimer();
  state.nodes=dashboard.nodes;
  state.configs=configs;
  state.presets=presets;
  renderNodes();
  if(selectedNodeId&&["overview","tls"].includes(selectedNodeTab))renderNodeWorkspace();
  renderConfigList();
  renderPresets();
  renderPanel();
}
async function signIn(username,password){
  const result=await api("/auth/login","POST",{username,password});
  csrf=result.csrf;
  setAuthorized(true);
  await refresh();
}
async function start(){
  bindEvents();
  try{
    const data=await api("/auth/session");
    csrf=data.csrf;
    setAuthorized(true);
    await refresh();
  }catch(e){
    setAuthorized(false);
  }
  try{
    const collapsed=localStorage.getItem("xppn-v2-collapsed");
    $("sidebar").classList.toggle("collapsed",collapsed==="1"||(collapsed===null&&innerWidth<1000));
  }catch{}
  initializeLibraryPreview();
}
function showPage(page){
  if(configDirty&&currentPage==="configs"&&page!=="configs"){
    if(!confirm("В редакторе есть несохранённые изменения. Покинуть страницу?"))return;
    configDirty=false;
  }
  currentPage=page;
  document.querySelectorAll(".nav-link").forEach(el=>
    el.classList.toggle("active",el.dataset.page===page));
  document.querySelectorAll("main > section").forEach(el=>
    el.classList.toggle("hidden",el.id!=="page-"+page));
  $("current-page-name").textContent=titles[page]||page;
  if(page==="updates")refreshUpdateStatus();
  if(page==="settings")loadMonitoringSettings();
}
async function waitAgentTask(nodeId,jobId){
  const started=performance.now(),deadline=Date.now()+60000;
  while(Date.now()<deadline){
    const result=await api("/agents/"+encodeURIComponent(nodeId)+"/tasks/"+encodeURIComponent(jobId));
    if(["done","failed","expired"].includes(result.status)){
      if(result.status!=="done")throw Error(result.error||"Агент не выполнил задачу");
      result.result._manager_latency_ms=Math.round(performance.now()-started);
      return result.result;
    }
    const elapsed=performance.now()-started;
    await new Promise(resolve=>setTimeout(resolve,elapsed<3000?120:500));
  }
  throw Error("Агент ещё выполняет задачу. Результат будет доступен позже.");
}
async function agentTask(nodeId,action,payload={},confirmed=false){
  const job=await api("/agents/"+encodeURIComponent(nodeId)+"/tasks","POST",{action,payload,confirmed});
  return await waitAgentTask(nodeId,job.id);
}

function restartMonitoringTimer(){
  if(monitoringTimer){clearInterval(monitoringTimer);monitoringTimer=null}
  monitoringTimer=setInterval(async()=>{
    if(document.hidden)return;
    try{
      // Fast monitoring must never re-render configuration, security or management tabs.
      // Only the dedicated Monitoring tab consumes the selected 1–60s interval.
      if(selectedNodeId){
        if(selectedNodeTab==="monitor")await refreshNodeMonitoring();
        return;
      }
      if(currentPage==="nodes"){
        const data=await api("/agents");
        nodeOverviewAgents=data.agents||[];
        renderNodes();
      }
    }catch{}
  },monitoringMs);
}

function openModal(title,kicker,content,submit){
  $("modal-title").textContent=title;$("modal-kicker").textContent=kicker;
  $("modal-content").innerHTML=content;
  $("modal").showModal();
  const form=$("modal-content").querySelector("form");
  if(form)form.addEventListener("submit",async e=>{
    e.preventDefault();
    const b=form.querySelector('button[type="submit"]');
    if(b)b.disabled=true;
    try{await submit(new FormData(form));$("modal").close();await refresh()}
    catch(err){message(err.message,true)}
    finally{if(b)b.disabled=false}
  });
}
