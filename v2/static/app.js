"use strict";
const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
}[c]));
const icon = name => '<svg><use href="/static/icons.svg#i-'+name+'"></use></svg>';
const types = {xray:"Xray JSON",nginx:"Nginx",nginx_compose:"Nginx Compose",node_compose:"Remnawave Compose"};
const titles = {nodes:"Ноды",agents:"Агенты VPS","node-certs":"Сертификаты нод",configs:"Конфигурации",presets:"Пресеты",settings:"Настройки",updates:"Обновления"};
const labels = {regular:"Обычная",entry:"Обычная",exit:"Обычная"};
let csrf = "", currentPage = "nodes", currentConfig = null, configRevision = 0,
    configBase = "", configDirty = false, currentPreset = null, currentPlan = null,
    panelProfiles = [], expanded = new Set(), toastTimer = null;
let state = {panel:{},nodes:[],bridges:[],configs:[],presets:[]};
let updateDetails = null, updatePolling = null, monitoringTimer = null, monitoringMs = 5000;
let showArchivedNodes=false;
let configCategory="xray";

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
  state.bridges=dashboard.bridges;
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
  renderVariablePreview();
  api("/template/variables").then(x=>{
    $("template-variable-list").innerHTML=x.variables.map(v=>
      '<div class="variable-pill">'+esc("{{"+v.key+"}}")+'<small>'+esc(v.description)+'</small></div>'
    ).join("");
  }).catch(()=>{});
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
  if(page==="node-certs")renderNodeCertificates();
  if(page==="agents")renderAgents();
  if(page==="settings")loadMonitoringSettings();
}
async function waitAgentTask(nodeId,jobId){
  for(let i=0;i<30;i++){
    const result=await api("/agents/"+encodeURIComponent(nodeId)+"/tasks/"+encodeURIComponent(jobId));
    if(["done","failed","expired"].includes(result.status)){
      if(result.status!=="done")throw Error(result.error||"Агент не выполнил задачу");
      return result.result;
    }
    await new Promise(resolve=>setTimeout(resolve,2000));
  }
  throw Error("Агент ещё выполняет задачу. Результат будет доступен в истории заданий.");
}
async function agentTask(nodeId,action,payload={},confirmed=false){
  const job=await api("/agents/"+encodeURIComponent(nodeId)+"/tasks","POST",{action,payload,confirmed});
  return await waitAgentTask(nodeId,job.id);
}
async function renderAgents(){
  const target=$("agents-list");
  try{
    const data=await api("/agents");
    target.innerHTML=(data.agents||[]).filter(n=>showArchivedNodes||!state.nodes.find(x=>x.id===n.id)?.archived).map(n=>{
      const status=n.online?"Онлайн":n.revoked?"Доступ отозван":n.last_seen?"Нет связи":n.installed?"Ожидается первое подключение":"Не установлен";
      const m=n.metrics||{};
      const ram=m.MemTotal_bytes?Math.round((m.MemTotal_bytes-(m.MemAvailable_bytes||0))/m.MemTotal_bytes*100)+"%":"—";
      return '<div class="node-card" style="flex-wrap:wrap"><span class="feature-icon">'+icon("server")+'</span>'+
        '<div style="flex:1;min-width:190px"><strong>'+esc(n.code)+' · '+esc(n.domain)+'</strong>'+
        '<p>'+esc(status)+(n.version?" · v"+esc(n.version):"")+
        (n.last_seen?" · Был на связи: "+esc(new Date(n.last_seen*1000).toLocaleString("ru-RU")):"")+'</p>'+
        (n.online?'<p>RAM: '+esc(ram)+' · Uptime: '+esc(Math.round((m.uptime_seconds||0)/3600))+' ч</p>':'')+
        '</div>'+(n.online?
        '<button class="btn subtle" data-agent-id="'+esc(n.id)+'" data-agent-action="system.status">Сервер</button>'+
        '<button class="btn subtle" data-agent-id="'+esc(n.id)+'" data-agent-action="docker.status">Docker</button>'+
        '<button class="btn subtle" data-agent-id="'+esc(n.id)+'" data-agent-action="service.status">Службы</button>'+
        '<button class="btn subtle" data-agent-id="'+esc(n.id)+'" data-agent-action="docker.logs">Логи</button>'+
        '<button class="btn subtle" data-agent-id="'+esc(n.id)+'" data-agent-action="logs.read">Xray логи</button>'+
        '<button class="btn subtle" data-agent-id="'+esc(n.id)+'" data-agent-action="cert.status">Certbot</button>'+
        '<button class="btn subtle" data-agent-id="'+esc(n.id)+'" data-agent-action="config.read">Nginx</button>'+
        '<button class="btn subtle" data-agent-id="'+esc(n.id)+'" data-agent-action="docker.restart">Рестарт ноды</button>'+
        '<button class="btn subtle" data-agent-repair="'+esc(n.id)+'" title="Восстановление после ошибки sudo при первой установке">Исправить helper</button>'+
        '<button class="btn subtle" data-node-lifecycle="'+esc(n.id)+'">Удаление</button>'+
        (n.version==="1.0.0"?'<button class="btn subtle" data-agent-upgrade="'+esc(n.id)+'">Обновить агент 1.1</button>':'')+
        '<button class="btn subtle" data-agent-revoke="'+esc(n.id)+'">Отозвать доступ</button>':
        (!n.installed||n.revoked||!n.last_seen)?'<button class="btn primary" data-agent-install="'+esc(n.id)+'">'+(n.revoked?"Повторная регистрация":n.installed?"Повторить первичную установку":"Установить агент (один раз SSH)")+'</button>':'')+
        '</div>';
    }).join("")||'<p class="muted">Серверов пока нет.</p>';
  }catch(e){target.textContent=e.message;target.className="form-feedback error";}
}
function agentRepairModal(id){
  const node=state.nodes.find(n=>n.id===id);
  if(!node)return;
  openModal("Исправить helper: "+node.code,"ВОССТАНОВЛЕНИЕ ПЕРВИЧНОЙ УСТАНОВКИ",
    '<p class="muted small">Исправляем системные ограничения первоначально установленного агента, из-за которых Docker, логи и Certbot показывают «agent helper rejected operation». Однократно используется SSH. Токен агента, Xray, Nginx и сертификаты не меняются; перезапустится только служба самого агента.</p>'+
    '<form><label>SSH-пароль root <span class="muted">· необязательно, если сохранён</span><input name="password" type="password" autocomplete="new-password" placeholder="Использовать сохранённый пароль"></label>'+
    '<label class="check-row"><input name="confirm" type="checkbox" required> Подтверждаю исправление только службы агента на VPS</label>'+
    '<div class="form-buttons"><button class="btn primary" type="submit">Исправить права агента</button></div></form>',
    async fd=>{
      await api("/agents/"+encodeURIComponent(id)+"/repair-helper","POST",{
        password:fd.get("password"),confirm_ssh_migration:fd.get("confirm")==="on"});
      message("Права helper исправлены. Проверь кнопки Docker и Службы.");
      await renderAgents();
    });
}
async function nodeLifecycleModal(id){
  try{
    const data=await api("/nodes/"+encodeURIComponent(id)+"/removal-preview");
    const base="/nodes/"+encodeURIComponent(id);
    const blocked=Boolean(data.blocked);
    const shared=data.shared_nodes||[];
    const hasRemote=Boolean(data.remote_uuid||data.profile_uuid);
    const remoteReady=Boolean(data.remnawave_available&&hasRemote);
    const canDeleteProfile=Boolean(data.profile_uuid&&data.profile_present&&data.profile_owned);
    const profileTitle=esc(data.profile_name||"Без названия");
    const sharedList=shared.map(n=>'<li>'+esc(n.name)+' <span class="muted small">('+esc(n.uuid)+')</span></li>').join("");
    const issue=data.remnawave_error?
      '<p class="form-feedback error">'+esc(data.remnawave_error)+'</p>':'';
    const bridgeInfo=blocked?
      '<p class="form-feedback error">У ноды остались legacy-связи старой системы топологии. Сначала отвяжи их локально; рабочий Xray на VPS изменён не будет.</p>':'';
    const profileInfo=!hasRemote?
      '<p class="muted small">В менеджере не сохранены UUID объектов Remnawave. Доступно удаление локальной записи; проверь Remnawave вручную.</p>':
      !data.profile_uuid?'':(!data.profile_present?
      '<p class="muted small">Сохранённый профиль уже отсутствует в Remnawave.</p>':
      !data.profile_owned?
      '<p class="form-feedback error">Профиль не совпадает с созданным для этой ноды. Автоматически удалять его нельзя.</p>':'');
    const sharedInfo=shared.length?
      '<div class="form-feedback error"><strong>Общий Xray-профиль '+profileTitle+'</strong><p class="small">Он используется ещё на '+shared.length+' нодах:</p><ul>'+sharedList+'</ul>'+
      '<p class="small">Удаление профиля может нарушить работу всех перечисленных нод. По умолчанию он сохраняется.</p></div>':'';
    const existingPhase=data.phase?
      '<p class="muted small">Предыдущий процесс удаления: '+esc(data.phase)+
      '. Новый способ не запускает его повторно и не очищает VPS.</p>':'';
    const remoteCheckbox='<label class="check-row"><input type="checkbox" name="remove_remote" '+
      (remoteReady?"checked":"disabled")+'> Удалить ноду из Remnawave</label>';
    const profileCheckbox=data.profile_uuid?
      '<label class="check-row" id="remove-profile-choice"><input type="checkbox" name="delete_profile" '+
      (!canDeleteProfile||!remoteReady?'disabled':shared.length?'':'checked')+
      '> Удалить Xray-профиль '+profileTitle+'</label>':'';
    const sharedConfirm=shared.length&&canDeleteProfile?
      '<label id="shared-profile-confirm" class="hidden">Для удаления общего профиля введи точно: <strong>'+profileTitle+
      '</strong><input name="shared_confirmation" autocomplete="off" placeholder="'+profileTitle+'"></label>':'';
    openModal("Удалить "+data.code,"НОДА / REMNAWAVE",
      '<p class="muted small"><strong>'+esc(data.code)+'</strong> · '+esc(data.domain)+'</p>'+
      '<p class="muted small">С VPS ничего не удаляется: Docker, Nginx, сертификаты и агент остаются на сервере.</p>'+
      existingPhase+issue+bridgeInfo+profileInfo+sharedInfo+
      '<form><label class="check-row"><input type="checkbox" checked disabled> Удалить запись из XPPN Manager</label>'+
      remoteCheckbox+profileCheckbox+sharedConfirm+
      '<label>Подтверждение: введи код '+esc(data.code)+
      '<input name="code" placeholder="'+esc(data.code)+'" required autocomplete="off"></label>'+
      '<div class="form-buttons"><button type="submit" class="btn primary" '+(blocked?'disabled':'')+
      '>Удалить выбранное</button></div></form>'+
      '<div class="form-buttons">'+
      (blocked?'<button type="button" class="btn subtle" id="detach-before-remove">Удалить локальные связи с мостами</button>':'')+
      '<button type="button" class="btn subtle" id="toggle-node-archive">'+
      (data.archived?'Вернуть из архива':'В архив')+'</button></div>',
      async fd=>{
        if(blocked)throw Error("Сначала удали локальные связи с мостами");
        if(fd.get("code")!==data.code)throw Error("Неверный код подтверждения");
        const removeRemote=fd.has("remove_remote");
        const deleteProfile=removeRemote&&fd.has("delete_profile");
        const sharedConfirmation=String(fd.get("shared_confirmation")||"");
        if(deleteProfile&&shared.length&&sharedConfirmation!==data.profile_name)
          throw Error("Для удаления общего профиля нужно ввести его точное название");
        if(deleteProfile&&shared.length&&!confirm("ВНИМАНИЕ: профиль используется на "+shared.length+
          " ДРУГИХ нодах. Удаление может отключить их от VPN. Удалить общий профиль?"))return;
        if(!confirm(removeRemote?
          "Удалить "+data.code+" из менеджера и Remnawave? VPS останется без изменений.":
          "Удалить "+data.code+" ТОЛЬКО из менеджера? Нода и профиль в Remnawave останутся."))return;
        const result=await api(base+"/remove","POST",{
          code:data.code,remove_remote:removeRemote,delete_profile:deleteProfile,
          shared_confirmation:sharedConfirmation,
          expected_shared_ids:shared.map(x=>x.uuid)
        });
        message("Нода удалена из менеджера. VPS не изменялась."+
          (result.profile_retained?" Xray-профиль сохранён.":""));
        await renderAgents();
      });
    const form=$("modal-content").querySelector("form");
    const remoteToggle=form.elements.remove_remote;
    const profileToggle=form.elements.delete_profile;
    const profileChoice=$("remove-profile-choice");
    const sharedField=$("shared-profile-confirm");
    const updateOptions=()=>{
      if(profileToggle){
        profileToggle.disabled=!remoteToggle.checked||!canDeleteProfile;
        if(!remoteToggle.checked)profileToggle.checked=false;
      }
      if(profileChoice)profileChoice.classList.toggle("hidden",!remoteToggle.checked);
      if(sharedField)sharedField.classList.toggle("hidden",!(profileToggle&&profileToggle.checked));
    };
    remoteToggle.addEventListener("change",updateOptions);
    if(profileToggle)profileToggle.addEventListener("change",updateOptions);
    updateOptions();
    const archive=$("toggle-node-archive");
    if(archive)archive.onclick=async()=>{
      try{
        await api(base+"/archive","PUT",{archived:!data.archived});
        $("modal").close();
        message(data.archived?"Нода возвращена из архива":"Нода перемещена в архив");
        await refresh();
      }catch(e){message(e.message,true)}
    };
    const detach=$("detach-before-remove");
    if(detach)detach.onclick=async()=>{
      if(form.elements.code.value!==data.code)
        return message("Сначала введи точный код ноды для отвязки",true);
      if(!confirm("Удалить legacy-связи "+data.code+
        "? Это НЕ изменяет рабочие Xray-конфигурации и VPS."))return;
      try{
        await api(base+"/detach-dependencies","POST",{code:data.code});
        $("modal").close();
        await refresh();
        await nodeLifecycleModal(id);
      }catch(e){message(e.message,true)}
    };
  }catch(e){message(e.message,true)}
}

function agentBootstrapModal(id){
  const node=state.nodes.find(n=>n.id===id);
  if(!node)return;
  openModal("Установить агент: "+node.code,"ОДИН РАЗ ЧЕРЕЗ SSH",
    '<p class="muted small">Этот шаг установит Go-агент, выделенного системного пользователя и ограниченный helper на уже работающий VPS. Сначала используется сохранённый SSH-пароль этой ноды; при необходимости его можно указать вручную. Дальше управление идёт через Agent.</p>'+
    '<form><label>SSH-пароль root<input name="password" type="password" required autocomplete="new-password"></label>'+
    '<label class="check-row"><input name="confirm" type="checkbox" required> Подтверждаю установку агента на VPS</label>'+
    '<div class="form-buttons"><button class="btn primary" type="submit">Установить</button></div></form>',
    async fd=>{
      await api("/agents/"+encodeURIComponent(id)+"/bootstrap","POST",{
        password:fd.get("password"),confirm_ssh_migration:fd.get("confirm")==="on"});
      message("Агент установлен. Ожидаем подключения к менеджеру.");
      await renderAgents();
    });
}
async function agentActionModal(id,action){
  const node=state.nodes.find(n=>n.id===id);
  if(!node)return;
  let payload={};
  if(action==="docker.logs"){
    const name=prompt("Логи контейнера: nginx или remnanode","remnanode");
    if(!["nginx","remnanode"].includes(name))return;
    payload={name,tail:100};
  }else if(action==="logs.read"){
    const source=prompt("Логи: xray-error, xray-access, nginx-access, nginx-error, certbot","xray-error");
    if(!["xray-error","xray-access","nginx-access","nginx-error","certbot"].includes(source))return;
    payload={source,tail:100};
  }else if(action==="config.read")payload={name:"nginx"};
  else if(action==="docker.restart"){
    if(!confirm("Перезапустить контейнер remnanode на "+node.code+"? Активные VPN-подключения кратковременно прервутся."))return;
    payload={name:"remnanode"};
  }
  try{
    message("Задача отправлена агенту "+node.code);
    const data=await agentTask(id,action,payload,action==="docker.restart");
    if(action==="config.read"){
      openModal("Nginx · "+node.code,"РЕДАКТОР КОНФИГУРАЦИИ",
        '<form><label>Содержимое nginx.conf<textarea name="content" rows="16" required>'+esc(data.content||"")+'</textarea></label>'+
        '<p class="muted small">Сначала сравни изменения. Перед применением агент проверит SHA-256 версии, сделает резервную копию и выполнит nginx -t. При ошибке конфиг восстановится.</p>'+
        '<label class="check-row"><input name="confirmed" type="checkbox" required> Подтверждаю применение изменений</label>'+
        '<div class="form-buttons"><button type="submit" class="btn primary">Проверить и применить</button></div></form>',
        async fd=>{
          await agentTask(id,"config.apply",{name:"nginx",content:fd.get("content"),
            expected_sha256:data.sha256},fd.get("confirmed")==="on");
          message("Конфигурация Nginx применена. Проверка прошла.");
        });
    }else{
      openModal("Агент · "+node.code,"РЕЗУЛЬТАТ "+action,
        '<pre class="wizard-preview">'+esc(["docker.logs","logs.read"].includes(action)?data.logs||"Нет строк":JSON.stringify(data,null,2))+'</pre>');
    }
  }catch(e){message(e.message,true)}
}
function migrateNodeTLSModal(id){
  const n=state.nodes.find(v=>v.id===id);
  if(!n)return message("Нода не найдена в менеджере",true);
  openModal("TLS на VPS · "+n.code,"БЕЗ ИЗМЕНЕНИЙ СЕРВЕРА ПАНЕЛИ",
    '<p class="muted small">Агент проверит сертификат и Docker Compose на '+esc(n.domain)+
    '. Затем API изменит только отдельный профиль этой ноды: PEM заменится на keyFile/certificateFile. При проблемах с Xray менеджер попробует откатить профиль. Другие ноды и файлы Remnawave Panel не затрагиваются.</p>'+
    '<form><label>Введи код '+esc(n.code)+' для подтверждения'+
    '<input name="code" required autocomplete="off" placeholder="'+esc(n.code)+'"></label>'+
    '<label class="check-row"><input type="checkbox" name="confirmed" required> Подтверждаю кратковременный перезапуск Xray только этой ноды</label>'+
    '<div class="form-buttons"><button class="btn primary" type="submit">Проверить и мигрировать</button></div></form>',
    async fd=>{
      if(fd.get("code")!==n.code)throw Error("Код ноды не совпадает");
      message("Проверяем TLS и Docker Compose на "+n.code);
      const base="/agents/"+encodeURIComponent(id)+"/tasks";
      const cert=await api(base,"POST",{action:"cert.status",payload:{}});
      await waitAgentTask(id,cert.id);
      const compose=await api(base,"POST",{action:"config.read",payload:{name:"node-compose"}});
      await waitAgentTask(id,compose.id);
      const result=await api("/node-certificates/"+encodeURIComponent(id)+"/migrate","POST",{
        code:n.code,certificate_job_id:cert.id,compose_job_id:compose.id});
      message(result.migrated?"Xray теперь использует сертификаты только на VPS":"Файловые пути уже настроены");
      await renderNodeCertificates();
    });
}

async function renderNodeCertificates(){
  const target=$("node-certs-list");
  try{
    const data=await api("/node-certificates");
    target.innerHTML=(data.nodes||[]).map(n=>{
      const expiry=n.expires_at?new Date(n.expires_at*1000).toLocaleDateString("ru-RU"):"Ещё не проверен";
      return '<div class="node-card"><span class="feature-icon">'+icon("shield-check")+'</span>'+
        '<div style="flex:1;min-width:210px"><strong>'+esc(n.code)+' · '+esc(n.domain)+'</strong>'+
        '<p>Сертификат: '+esc(expiry)+' · '+(n.auto_sync?"Агент онлайн, автопроверка 6 ч":"Агент пока офлайн")+
        (n.last_checked?" · Проверен "+esc(new Date(n.last_checked*1000).toLocaleString("ru-RU")):"")+'</p>'+
        (n.last_error?'<p class="form-feedback error" role="status">Ошибка TLS: '+esc(n.last_error)+'</p>':'')+
        '</div><button class="btn subtle" data-node-cert-check="'+esc(n.id)+'" type="button" '+(!n.auto_sync?"disabled":"")+'>Проверить через агент</button>'+
        '<button class="btn subtle" data-tls-migrate="'+esc(n.id)+'" type="button" '+(!n.auto_sync?"disabled":"")+'>Перейти на локальные TLS</button></div>';
    }).join("")||'<p class="muted">Ноды пока не добавлены.</p>';
  }catch(e){target.textContent=e.message;target.className="form-feedback error"}
}

function renderNodes(){
  $("metric-nodes").textContent=String(state.nodes.length);
  $("metric-ready-nodes").textContent=String(state.nodes.filter(n=>n.status==="ready").length);
  $("metric-online-agents").textContent=String(nodeOverviewAgents.filter(a=>a.online).length);
  const others=state.nodes.filter(n=>showArchivedNodes||!n.archived);
  $("other-nodes").innerHTML=others.length?others.map(n=>
    '<div class="node-card"><span class="feature-icon">'+icon("server")+'</span><div><strong>'+
    esc(n.code)+' · '+esc(n.name)+'</strong><p>'+esc(n.domain)+
    '</p>'+nodeListBadges(n.id)+'</div><span class="tiny-chip '+(n.status==="registered"||n.status==="ready"?"success":"warning")+'">'+
    esc(n.archived?"Архив":n.lifecycle_phase?"Удаление: "+n.lifecycle_phase:n.status==="planned"?"Черновик":n.status)+'</span>'+
    '<button type="button" class="btn primary" data-node-open="'+esc(n.id)+'">Открыть ноду</button>'+
    (n.status==="planned"?'<button type="button" class="btn subtle" data-delete-draft="'+esc(n.id)+'">Удалить черновик</button>':"")+
    (n.status==="planned"?'<button type="button" class="btn subtle" data-draft-install="'+esc(n.id)+'">Установить VPS</button>':
       '<button type="button" class="btn subtle" data-install-node="'+esc(n.id)+'">Статус</button>')+
    (["failed","interrupted"].includes(n.status)?
       '<button type="button" class="btn primary" data-retry-vps="'+esc(n.id)+'">Продолжить</button>'+
       '<button type="button" class="btn subtle" data-forget-vps="'+esc(n.id)+'">Удалить…</button>':"")+
    '</div>'
  ).join(""):'<div class="empty-state"><h3>Нод пока нет</h3><p>Добавь VPS — она появится здесь без дополнительных ролей и топологии.</p></div>';
}
function restartMonitoringTimer(){
  if(monitoringTimer){clearInterval(monitoringTimer);monitoringTimer=null}
  monitoringTimer=setInterval(async()=>{
    if(document.hidden)return;
    try{
      if(selectedNodeId){
        await refreshNodeWorkspaceData();
      }else if(currentPage==="agents"){
        await renderAgents();
      }else if(currentPage==="nodes"){
        const data=await api("/agents");
        nodeOverviewAgents=data.agents||[];
        renderNodes();
      }
    }catch{}
  },monitoringMs);
}
async function loadMonitoringSettings(){
  try{
    const data=await api("/settings/monitoring");
    $("monitoring-interval").value=String(data.interval);
    $("monitoring-status").textContent="Текущая частота: "+data.interval+" сек.";
  }catch(e){$("monitoring-status").textContent=e.message}
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
function bridgeModal(){
  const entries=state.nodes.filter(n=>n.role==="entry"&&!state.bridges.some(b=>b.entry_id===n.id));
  if(!entries.length)return message("Сначала добавь сервер с ролью «Вход моста».",true);
  openModal("Создать мост","ТОПОЛОГИЯ / НОВЫЙ МОСТ",
    '<form><label>Название<input name="name" required placeholder="RU-01 · Мост"></label>'+
    '<label>Входная нода<select name="entry_id">'+entries.map(n=>
    '<option value="'+esc(n.id)+'">'+esc(n.code)+' · '+esc(n.name)+'</option>').join("")+
    '</select></label><p class="muted small">Выходы можно добавить после создания. Существующий Xray-конфиг сначала импортируй как копию.</p>'+
    '<div class="form-buttons"><button class="btn primary" type="submit">Создать мост</button></div></form>',
    async fd=>{const r=await api("/bridges","POST",Object.fromEntries(fd));expanded.add(r.id);message("Мост создан. Действующие серверы не изменены.")});
}
function bridgeExitModal(id){
  const bridge=state.bridges.find(x=>x.id===id);
  if(!bridge)return;
  const exits=state.nodes.filter(n=>n.role==="exit"&&!bridge.exits.some(e=>e.id===n.id));
  if(!exits.length)return message("Сначала добавь новую выходную ноду, например NL1.",true);
  openModal("Добавить выходную ноду","BRIDGE / ПЛАН ИЗМЕНЕНИЙ",
    '<p class="muted small">Создадим дополнительный outbound, выделим свободный inbound-порт и покажем разницу. Существующий маршрут не перезаписывается.</p>'+
    '<form><label>Выходная нода<select name="exit_id">'+exits.map(n=>
    '<option value="'+esc(n.id)+'">'+esc(n.code)+' · '+esc(n.domain)+'</option>').join("")+
    '</select></label>'+
    (!bridge.has_snapshot?'<label>Шаблон Xray <span class="muted">· для нового моста</span><select name="config_template_id"><option value="">Стандартный образец XPPN</option>'+state.configs.filter(f=>f.kind==="xray").map(f=>'<option value="'+esc(f.id)+'">'+esc(f.name)+'</option>').join("")+'</select></label>':'')+
    '<label>UUID межсерверного VLESS <span class="muted">· необязательно</span><input name="outgoing_uuid" placeholder="Пусто = создать новый UUID" autocomplete="off"></label>'+
    (bridge.has_snapshot?'<label>Дополнительный TCP-порт <span class="muted">· автоматически</span><input name="inbound_port" type="number" min="8444" max="8999" placeholder="8444"></label>':'')+
    '<p class="muted small">UUID должен совпадать с пользователем принимающего outbound на выходном сервере. Автоматическая синхронизация обеих сторон пока не включена.</p>'+
    '<div class="form-buttons"><button type="submit" class="btn primary">Подготовить изменения</button></div></form>',
    async fd=>{
      const data={exit_id:fd.get("exit_id")};
      if(fd.get("outgoing_uuid"))data.outgoing_uuid=fd.get("outgoing_uuid");
      if(fd.get("inbound_port"))data.inbound_port=Number(fd.get("inbound_port"));
      if(fd.get("config_template_id"))data.config_template_id=fd.get("config_template_id");
      const plan=await api("/bridges/"+encodeURIComponent(id)+"/plans","POST",data);
      setTimeout(()=>openPlan(plan),80);
      message("Черновик моста подготовлен без изменений на VPS.");
    });
}
async function bridgeImportModal(id){
  const b=await api("/bridges/"+encodeURIComponent(id));
  openModal("Импорт текущего Xray","BRIDGE / ТОЛЬКО ЧТЕНИЕ",
    '<p class="muted small">Вставь JSON действующего моста. Менеджер сохранит его в зашифрованной базе только как снимок. Это НЕ загрузка конфига на VPS.</p>'+
    '<form><label>Действующий Xray JSON<textarea name="config" rows="14" required spellcheck="false" placeholder="{ ... }"></textarea></label>'+
    '<label><input type="checkbox" name="confirm" required> Я понимаю, что на VPS ничего не меняется.</label>'+
    '<div class="form-buttons"><button class="btn primary" type="submit">Сохранить снимок</button></div></form>',
    async fd=>{
      let parsed;
      try{parsed=JSON.parse(fd.get("config"))}catch{throw new Error("JSON не удалось прочитать")}
      await api("/bridges/"+encodeURIComponent(id)+"/import","POST",{
        config:parsed,revision:b.revision,confirm_read_only:fd.has("confirm")
      });
      message("Снимок текущего Xray сохранён зашифрованно.");
    });
}
function openPlan(plan){
  currentPlan=plan;
  $("plan-diff").innerHTML=String(plan.diff||"").split("\n").map(line=>{
    const kind=line.startsWith("+")?"added":line.startsWith("-")?"removed":
      line.startsWith("@")?"hunk":"";
    return '<span class="'+kind+'">'+esc(line)+'</span>';
  }).join("\n");
  $("plan-json").textContent=JSON.stringify(plan.config||{},null,2);
  $("plan-approve").disabled=plan.status!=="draft";
  $("plan-approve").textContent=plan.status==="approved"?
    "Черновик утверждён (не применён)":"Утвердить черновик (без применения)";
  $("plan-dialog").showModal();
}
async function openPlanId(id){
  try{openPlan(await api("/plans/"+encodeURIComponent(id)))}
  catch(e){message(e.message,true)}
}
function renderVariablePreview(){
  const fallback='{\\n  "inbounds":[{"tag":"{{source.code}}_{{exit.code}}_VLESS_TLS_IN"}],\\n  "outbounds":[{"address":"{{exit.domain}}","id":"{{bridge.user_id}}"}]\\n}';
  const source=$("config-content").value||fallback;
  const clipped=source.length>30000?source.slice(0,30000)+"\\n… предпросмотр ограничен 30 000 символами":source;
  $("placeholder-preview").innerHTML=highlightTokens(clipped);
}
function markConfigDirty(){
  const now=JSON.stringify({
    name:$("config-name").value,kind:$("config-kind").value,content:$("config-content").value
  });
  configDirty=now!==configBase;
  renderVariablePreview();
  $("config-hint").textContent=configDirty?"● Несохранённые изменения":"Файл хранится в библиотеке; никакие VPS не изменены.";
}
function setConfigClean(){
  configBase=JSON.stringify({
    name:$("config-name").value,kind:$("config-kind").value,content:$("config-content").value
  });
  configDirty=false;markConfigDirty();
}
function discardConfig(){return !configDirty||confirm("Отменить несохранённые изменения?")}
function resetConfig(force=false){
  if(!force&&!discardConfig())return;
  currentConfig=null;configRevision=0;
  $("config-name").value="";$("config-content").value="";
  $("config-kind").disabled=false;$("config-kind").value=configCategory==="xray"?"xray":"nginx";
  $("config-editor-title").textContent="Новый файл";
  $("config-version").textContent="Не сохранён";
  $("config-delete").classList.add("hidden");
  setConfigClean();renderConfigList();
  if(!$("config-dialog").open)$("config-dialog").showModal();
}
async function openConfig(id){
  if(!discardConfig())return;
  try{
    const file=await api("/configs/"+encodeURIComponent(id));
    currentConfig=id;configRevision=file.revision;
    $("config-name").value=file.name;$("config-content").value=file.content;
    $("config-kind").value=file.kind;$("config-kind").disabled=true;
    $("config-editor-title").textContent=file.name;
    $("config-version").textContent="Версия "+file.revision;
    $("config-delete").classList.remove("hidden");
    setConfigClean();renderConfigList();
    if(!$("config-dialog").open)$("config-dialog").showModal();
  }catch(e){message(e.message,true)}
}
function renderConfigList(){
  const q=$("config-search").value.toLowerCase().trim();
  const files=state.configs.filter(f=>
    (configCategory==="xray"?f.kind==="xray":f.kind!=="xray") &&
    (f.name+" "+types[f.kind]).toLowerCase().includes(q));
  $("config-count").textContent=files.length+" файлов";
  $("config-files").innerHTML=files.length?files.map(f=>
    '<button class="library-tile" data-open-config="'+esc(f.id)+'" type="button">'+
    '<span class="feature-icon">'+icon("file-code")+'</span>'+
    '<span class="library-tile-content"><strong>'+esc(f.name)+'</strong>'+
    '<small>'+esc(types[f.kind])+' · версия '+f.revision+'</small></span>'+
    '<span class="tiny-chip">Открыть</span></button>'
    ).join(""):'<div class="empty-state"><h3>Конфигураций пока нет</h3><p>Нажми «Создать конфиг», чтобы добавить первый файл.</p></div>';
}
function highlightTokens(value){
  return String(value).split(/(\{\{[a-z0-9.*_-]+\}\})/gi).map(part=>
    /^\{\{[a-z0-9.*_-]+\}\}$/i.test(part)?'<span class="placeholder-token">'+esc(part)+'</span>':esc(part)
  ).join("");
}
async function saveConfig(){
  const payload={name:$("config-name").value.trim(),kind:$("config-kind").value,
                 content:$("config-content").value};
  if(!payload.name||!payload.content.trim())return message("Укажи название и содержимое.",true);
  if(currentConfig)payload.revision=configRevision;
  try{
    const result=await api(currentConfig?"/configs/"+encodeURIComponent(currentConfig):"/configs",
                           currentConfig?"PUT":"POST",payload);
    configDirty=false;await refresh();await openConfig(result.id);
    message("Файл сохранён. На серверах ничего не изменилось.");
  }catch(e){message(e.message,true)}
}
async function deleteConfig(){
  if(!currentConfig||!confirm("Удалить файл из библиотеки? Файлы пресетов защищены от случайного удаления."))return;
  try{
    await api("/configs/"+encodeURIComponent(currentConfig),"DELETE");
    resetConfig(true);await refresh();message("Файл удалён.");
  }catch(e){message(e.message,true)}
}
function resetPreset(){
  currentPreset=null;$("preset-name").value="";$("preset-description").value="";
  $("preset-edit-title").textContent="Новый пресет";
  $("preset-mode").value="direct";
  for(const s of document.querySelectorAll("[data-preset-kind]"))s.value="";
}
function renderPresetSelects(selected={}){
  $("preset-selects").innerHTML=Object.entries(types).map(([kind,label])=>
    '<label>'+esc(label)+'<select data-preset-kind="'+kind+'"><option value="">Без этого файла</option>'+
    state.configs.filter(f=>f.kind===kind).map(f=>
      '<option value="'+esc(f.id)+'" '+(selected[kind]===f.id?"selected":"")+'>'+
      esc(f.name)+' · v'+f.revision+'</option>').join("")+
    '</select></label>'
  ).join("");
}
function renderPresets(){
  $("preset-count").textContent=String(state.presets.length);
  let selected={};
  if(currentPreset){
    const p=state.presets.find(x=>x.id===currentPreset);
    if(p)selected=Object.fromEntries(p.items.map(i=>[i.kind,i.config_id]));
  }
  renderPresetSelects(selected);
  $("preset-cards").innerHTML=state.presets.length?state.presets.map(p=>
    '<article class="preset-card"><h3>'+esc(p.name)+'</h3>'+
    '<span class="preset-mode">'+esc(p.mode==="direct"?"Обычная / выходная VPS":p.mode==="bridge"?"Входной мост":"Библиотека")+'</span>'+
    '<p>'+esc(p.description||"Пользовательский набор")+'</p>'+
    p.items.map(i=>'<div class="preset-file-chip">'+esc(types[i.kind])+'<strong>'+
    esc(i.config_name)+'</strong></div>').join("")+
    '<div class="form-buttons"><button class="btn subtle" data-preset-edit="'+esc(p.id)+'">Изменить</button>'+
    '<button class="btn subtle" data-preset-delete="'+esc(p.id)+'">Удалить</button></div></article>'
  ).join(""):'<div class="empty-state"><span class="feature-icon">'+icon("layers")+
    '</span><h3>Пресетов пока нет</h3><p>Сначала сохрани конфиги, затем объединяй их в готовые наборы.</p></div>';
}
function editPreset(id){
  const p=state.presets.find(x=>x.id===id);if(!p)return;
  currentPreset=id;$("preset-name").value=p.name;$("preset-description").value=p.description;
  $("preset-mode").value=p.mode||"custom";
  $("preset-edit-title").textContent=p.name;
  renderPresetSelects(Object.fromEntries(p.items.map(x=>[x.kind,x.config_id])));
  $("preset-dialog").showModal();
}
async function savePreset(){
  const ids=[...document.querySelectorAll("[data-preset-kind]")].map(x=>x.value).filter(Boolean);
  if(!ids.length)return message("Добавь хотя бы один файл.",true);
  const body={name:$("preset-name").value.trim(),mode:$("preset-mode").value,
    description:$("preset-description").value.trim(),config_ids:ids};
  try{
    await api(currentPreset?"/presets/"+encodeURIComponent(currentPreset):"/presets",
              currentPreset?"PUT":"POST",body);
    resetPreset();$("preset-dialog").close();await refresh();message("Набор сохранён в библиотеке.");
  }catch(e){message(e.message,true)}
}
async function removePreset(id){
  if(!confirm("Удалить пресет? Сами конфигурации останутся."))return;
  try{await api("/presets/"+encodeURIComponent(id),"DELETE");
    if(currentPreset===id)resetPreset();await refresh();message("Пресет удалён.");
  }catch(e){message(e.message,true)}
}
function renderPanel(){
  $("panel-url").value=state.panel.url||"";
  $("panel-ip").value=state.panel.outbound_ip||"";
  $("panel-token").value="";
  $("panel-caddy-key").value="";
  $("panel-caddy-key").placeholder=state.panel.has_caddy_api_key?
    "Ключ Caddy сохранён · оставь пустым":"Если используется защита Caddy/MFA";
  $("panel-token").placeholder=state.panel.has_token?
    "Токен уже сохранён · оставь пустым":"Введи API-токен Remnawave";
  $("panel-status").textContent=state.panel.url?
    "Одна основная панель · "+state.panel.url:"Панель пока не подключена.";
}
async function savePanel(){
  const body={url:$("panel-url").value.trim(),token:$("panel-token").value,
              caddy_api_key:$("panel-caddy-key").value,
              outbound_ip:$("panel-ip").value.trim()};
  try{
    state.panel=await api("/panel","PUT",body);
    renderPanel();
    message("Настройки сохранены. Проверяем авторизацию API…");
    await checkPanel();
  }catch(e){message(e.message,true)}
}
async function checkPanel(){
  $("panel-status").textContent="Проверяем Remnawave API…";
  try{
    const check=await api("/panel/check","POST");
    panelProfiles=check.config_profiles||[];
    $("panel-status").textContent="API доступен · "+panelProfiles.length+
      " профилей · ключ ноды "+(check.node_key_available?"получен":"не найден")+
      ". Выбор Xray-профиля выполняется при установке VPS.";
    $("panel-status").className="form-feedback success";
  }catch(e){
    $("panel-status").textContent=e.message;
    $("panel-status").className="form-feedback error";
    if(/HTTP (401|403|30[1278])/.test(e.message))$("panel-caddy-details").open=true;
  }
}

function updateRender(data){
  updateDetails=data;
  $("update-installed").textContent=data.installed_sha?data.installed_sha.slice(0,10):"Неизвестно";
  if(data.latest_sha)$("update-remote").textContent=data.latest_sha.slice(0,10);
  const stateName=data.state||"unavailable";
  const messages={
    unavailable:data.message||"Служба обновлений ещё не активирована.",
    idle:"Панель готова к проверке обновлений.",
    running:data.message||"Обновляем… возможен короткий разрыв соединения.",
    succeeded:data.message||"Обновление завершено.",
    failed:data.message||"Обновление завершилось ошибкой."
  };
  const status=$("update-status");
  status.textContent=messages[stateName]||"Неизвестный статус";
  status.className="form-feedback "+(stateName==="failed"?"error":stateName==="succeeded"?"success":"");
  const busy=stateName==="running";
  $("update-check").disabled=!data.enabled||busy;
  $("update-start").disabled=!data.enabled||busy||data.update_available!==true;
  if(!data.enabled){
    $("update-help").textContent="Для обновлений с сайта один раз активируй системную службу на VPS. После этого SSH для каждой новой версии не нужен.";
  }else if(busy){
    $("update-help").textContent="Панель может кратковременно перестать отвечать. Оставь эту страницу открытой — состояние появится после перезапуска.";
  }else{
    $("update-help").textContent="Перед обновлением сохраняется резервная копия базы и конфигурации. Если новая версия не запускается, восстанавливается предыдущий код.";
  }
}
async function refreshUpdateStatus(){
  try{
    const data=await api("/system/update");
    updateRender({...data,latest_sha:updateDetails?.latest_sha||"",
      update_available:updateDetails?.update_available===true &&
        updateDetails?.installed_sha===data.installed_sha});
  }catch(e){
    if(currentPage==="updates")$("update-status").textContent="Панель перезапускается или недоступна. Проверяем соединение…";
  }
}
async function checkUpdates(){
  $("update-check").disabled=true;
  $("update-status").textContent="Проверяем GitHub…";
  try{
    const data=await api("/system/update/check","POST");
    updateRender(data);
    $("update-status").textContent=data.update_available?
      "Доступно обновление. Нажми «Установить обновление».":"Установлена актуальная версия.";
  }catch(e){
    if(updateDetails)updateRender({...updateDetails,update_available:false});
    $("update-status").textContent=e.message;
    $("update-status").className="form-feedback error";
  }
}
async function startUpdate(){
  if(!updateDetails?.update_available)return;
  if(!confirm("Обновить XPPN Manager до последней версии GitHub? Будет кратковременный перезапуск, база и настройки сохраняются."))return;
  $("update-start").disabled=true;
  try{
    const result=await api("/system/update","POST");
    message(result.message);
    updateRender({...updateDetails,state:"running",message:result.message,update_available:false});
  }catch(e){message(e.message,true);refreshUpdateStatus()}
}

function bindEvents(){
  bindNodeWorkspace();
  $("login-form").addEventListener("submit",async e=>{
    e.preventDefault();
    const btn=e.currentTarget.querySelector("button");btn.disabled=true;
    $("login-error").textContent="";
    try{await signIn($("login-username").value.trim(),$("login-password").value);$("login-password").value=""}
    catch(err){$("login-error").textContent=err.message}
    finally{btn.disabled=false}
  });
  document.querySelectorAll(".nav-link").forEach(btn=>
    btn.addEventListener("click",()=>showPage(btn.dataset.page)));
  $("toggle-sidebar").onclick=()=>{
    const collapsed=$("sidebar").classList.toggle("collapsed");
    $("toggle-sidebar").title=collapsed?"Развернуть меню":"Свернуть меню";
    try{localStorage.setItem("xppn-v2-collapsed",collapsed?"1":"0")}catch{}
  };
  $("refresh").onclick=()=>refresh().then(()=>message("Данные обновлены")).catch(e=>message(e.message,true));
  $("monitoring-form").onsubmit=async e=>{
    e.preventDefault();
    const interval=Number($("monitoring-interval").value);
    try{
      const result=await api("/settings/monitoring","PUT",{interval});
      monitoringMs=result.monitor_interval*1000;restartMonitoringTimer();
      $("monitoring-status").textContent="Сохранено: "+result.monitor_interval+" сек.";
      message("Частота мониторинга обновлена");
    }catch(err){message(err.message,true)}
  };
  $("update-check").onclick=checkUpdates;
  $("update-start").onclick=startUpdate;
  updatePolling=setInterval(()=>{if(currentPage==="updates")refreshUpdateStatus()},4500);
  $("nodes-show-archived").onchange=e=>{
    showArchivedNodes=!!e.target.checked;renderNodes();renderAgents();
  };
  $("other-nodes").addEventListener("click",e=>{
    const btn=e.target.closest("[data-node-lifecycle]");
    if(btn)nodeLifecycleModal(btn.dataset.nodeLifecycle);
  });
  $("agents-refresh").onclick=renderAgents;
  $("agents-list").addEventListener("click",e=>{
    const manage=e.target.closest("[data-node-lifecycle]");
    if(manage){nodeLifecycleModal(manage.dataset.nodeLifecycle);return;}
    const upgrade=e.target.closest("[data-agent-upgrade]");
    if(upgrade){agentBootstrapModal(upgrade.dataset.agentUpgrade);return;}
    const repair=e.target.closest("[data-agent-repair]");
    if(repair){agentRepairModal(repair.dataset.agentRepair);return;}
    const revoke=e.target.closest("[data-agent-revoke]");
    if(revoke){
      const id=revoke.dataset.agentRevoke;
      if(!confirm("Отозвать доступ агента этой VPS? Она больше не сможет управляться через менеджер до повторной регистрации."))return;
      api("/agents/"+encodeURIComponent(id)+"/revoke","POST",{confirmed:true})
        .then(()=>renderAgents()).catch(err=>message(err.message,true));
      return;
    }
    const install=e.target.closest("[data-agent-install]");
    const action=e.target.closest("[data-agent-action]");
    if(install)agentBootstrapModal(install.dataset.agentInstall);
    else if(action)agentActionModal(action.dataset.agentId,action.dataset.agentAction);
  });
  $("node-certs-refresh").onclick=renderNodeCertificates;
  $("node-certs-list").addEventListener("click",async e=>{
    const migrate=e.target.closest("[data-tls-migrate]");
    if(migrate){migrateNodeTLSModal(migrate.dataset.tlsMigrate);return;}
    const sync=e.target.closest("[data-node-cert-check]");
    if(!sync)return;
    try{
      const job=await api("/node-certificates/"+encodeURIComponent(sync.dataset.nodeCertCheck)+"/sync","POST");
      message("Запрос проверки TLS отправлен агенту");
      const result=await waitAgentTask(sync.dataset.nodeCertCheck,job.id);
      message(result.mode==="migration_required"?"Найден встроенный PEM. Для перехода нажми «Перейти на локальные TLS».":result.updated?"Xray этой ноды перезапущен после обновления сертификата":"Локальный TLS сертификат проверен, изменений нет");
      await renderNodeCertificates();
    }catch(err){message(err.message,true)}
  });
  /* Bridge topology is intentionally disabled while the model is redesigned. */
  /* no bridge UI bindings */
  $("modal-close").onclick=()=>$("modal").close();
  $("plan-close").onclick=()=>$("plan-dialog").close();
  $("plan-dismiss").onclick=()=>$("plan-dialog").close();
  $("plan-approve").onclick=async()=>{
    if(!currentPlan||!confirm("Утвердить черновик? Это НЕ применяет изменения к Remnawave или VPS."))return;
    try{
      await api("/plans/"+encodeURIComponent(currentPlan.id)+"/approve","POST");
      $("plan-dialog").close();await refresh();
      message("Черновик утверждён, но НЕ применён на сервере.");
    }catch(e){message(e.message,true)}
  };
  $("new-config").onclick=()=>resetConfig();
  $("config-load-bridge").onclick=async()=>{
    if(!discardConfig())return;
    try{
      const sample=await api("/template/default");
      resetConfig(true);
      $("config-name").value=sample.name;
      $("config-kind").value="xray";
      $("config-content").value=sample.content;
      markConfigDirty();
      message("Загружен образец. Переменные выделены ниже, файл пока не сохранён.");
    }catch(e){message(e.message,true)}
  };
  document.querySelectorAll("[data-config-category]").forEach(btn=>btn.addEventListener("click",()=>{
    configCategory=btn.dataset.configCategory;
    document.querySelectorAll("[data-config-category]").forEach(tab=>{
      const selected=tab.dataset.configCategory===configCategory;
      tab.classList.toggle("active",selected);
      tab.setAttribute("aria-selected",String(selected));
    });
    renderConfigList();
  }));
  $("config-search").addEventListener("input",renderConfigList);
  $("config-files").addEventListener("click",e=>{
    const button=e.target.closest("[data-open-config]");
    if(button)openConfig(button.dataset.openConfig);
  });
  ["config-name","config-kind","config-content"].forEach(id=>
    $(id).addEventListener("input",markConfigDirty));
  $("config-content").addEventListener("keydown",e=>{
    if(e.key==="Tab"){e.preventDefault();const x=e.target;
      x.setRangeText("  ",x.selectionStart,x.selectionEnd,"end");markConfigDirty()}
    if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="s"){
      e.preventDefault();saveConfig()}
  });
  $("config-save").onclick=saveConfig;$("config-delete").onclick=deleteConfig;
  $("config-close").onclick=()=>{if(discardConfig()){$("config-dialog").close();configDirty=false;}};
  $("preset-close").onclick=()=>$("preset-dialog").close();
  $("config-dialog").addEventListener("cancel",e=>{if(!discardConfig())e.preventDefault();else configDirty=false;});
  $("new-preset").onclick=()=>{resetPreset();$("preset-dialog").showModal()};$("preset-reset").onclick=resetPreset;
  $("preset-form").onsubmit=e=>{e.preventDefault();savePreset()};
  $("preset-cards").addEventListener("click",e=>{
    const edit=e.target.closest("[data-preset-edit]");
    const remove=e.target.closest("[data-preset-delete]");
    if(edit)editPreset(edit.dataset.presetEdit);
    if(remove)removePreset(remove.dataset.presetDelete);
  });
  $("panel-form").onsubmit=e=>{e.preventDefault();savePanel()};
  $("panel-check").onclick=checkPanel;
  window.addEventListener("beforeunload",e=>{
    if(configDirty){e.preventDefault();e.returnValue=""}
  });
}
document.addEventListener("DOMContentLoaded",start);
