"use strict";
// Single node workspace inside the Nodes section. All data comes from Manager,
// not from the Remnawave host filesystem.
let selectedNodeId=null, selectedNodeTab="overview", nodeOverviewAgents=[], nodeOverviewCerts=[];
let nodeTaskRequest=0, nodeTaskBusy=false;
const nodeTabs={overview:"Обзор",docker:"Docker и службы",logs:"Логи",tls:"Сертификат",network:"Сеть и защита",configs:"Конфигурации",manage:"Управление"};
const nodeTime=t=>t?new Date(t*1000).toLocaleString("ru-RU"):"Ещё нет";
const nodeSize=n=>typeof n==="number"&&Number.isFinite(n)?(n/1073741824).toFixed(1)+" ГБ":"—";
const nodePercent=(a,b)=>b>0?Math.max(0,Math.min(100,Math.round(a/b*100)))+"%":"—";
const nodeDuration=s=>Number.isFinite(Number(s))?Math.floor(Number(s)/86400)+" д "+Math.floor(Number(s)%86400/3600)+" ч":"—";
const nodeStatus=(value,good,bad="Нет данных")=>'<span class="node-state '+(value===true?'is-good':value===false?'is-bad':'')+'">'+
  (value===true?good:value===false?bad:"Неизвестно")+'</span>';
function currentNode(){return state.nodes.find(n=>n.id===selectedNodeId)}
function currentAgent(){return nodeOverviewAgents.find(n=>n.id===selectedNodeId)||{}}
function currentCert(){return nodeOverviewCerts.find(n=>n.id===selectedNodeId)||{}}
function nodeCertText(c){
  if(c.last_error)return nodeStatus(false,"", "Ошибка проверки");
  if(c.checked&&c.expires_at)return nodeStatus(true,"Действует до "+new Date(c.expires_at*1000).toLocaleDateString("ru-RU"));
  if(c.checking)return '<span class="node-state">Проверяется…</span>';
  return c.agent_installed?"Ожидает автоматической проверки":"Пока не проверен";
}
function nodeListBadges(id){
  const a=nodeOverviewAgents.find(n=>n.id===id)||{};
  const c=nodeOverviewCerts.find(n=>n.id===id)||{};
  return '<div class="node-list-meta"><span class="node-state '+(a.online?"is-good":"")+'">'+
    (a.online?"Агент онлайн":a.installed?"Агент офлайн":"Без агента")+'</span>'+
    '<span class="node-state '+(c.checked&&!c.last_error?"is-good":"")+'">'+
    (c.last_error?"TLS ошибка":c.checked&&c.expires_at?"TLS до "+new Date(c.expires_at*1000).toLocaleDateString("ru-RU"):
      c.checking?"TLS проверяется":"TLS без проверки")+'</span></div>';
}
function openNodeWorkspace(id,tab="overview"){
  if(!state.nodes.some(n=>n.id===id))return message("Нода не найдена",true);
  selectedNodeId=id;
  selectedNodeTab=tab;
  nodeSecuritySnapshot=null;
  nodeTaskRequest++;
  $("nodes-home").classList.add("hidden");
  $("node-detail").classList.remove("hidden");
  showPage("nodes");
  renderNodeWorkspace();
  window.scrollTo({top:0,behavior:"auto"});
}
function closeNodeWorkspace(){
  selectedNodeId=null;nodeSecuritySnapshot=null;nodeTaskRequest++;
  $("node-detail").classList.add("hidden");
  $("nodes-home").classList.remove("hidden");
  renderNodes();
}
function renderNodeWorkspace(){
  if(!selectedNodeId)return;
  const n=currentNode();
  if(!n){closeNodeWorkspace();return}
  const a=currentAgent(),c=currentCert(),m=a.metrics||{};
  const online=Boolean(a.online),hasAgent=Boolean(a.installed&&!a.revoked);
  $("node-detail").innerHTML=
    '<div class="node-ws-head"><button type="button" class="btn subtle" data-node-back>'+icon("arrow-left")+
    ' Все ноды</button><div class="node-ws-heading"><p class="eyebrow">СЕРВЕР / '+esc(n.country)+'</p>'+
    '<h1>'+esc(n.code)+'</h1><p class="muted">'+esc(n.domain)+' · '+esc(labels[n.role]||n.role)+'</p></div>'+
    '<span class="node-state '+(online?'is-good':'')+'">'+(online?"Агент онлайн":hasAgent?"Нет связи":"Агент не установлен")+'</span></div>'+
    '<div class="node-ws-summary">'+
    '<div class="node-ws-stat"><small>Сервер</small><strong>'+esc(n.status==="ready"?"Установлен":n.status)+'</strong><span>'+esc(nodeTime(a.last_seen))+'</span></div>'+
    '<div class="node-ws-stat"><small>Оперативная память</small><strong>'+esc(nodePercent((m.MemTotal_bytes||0)-(m.MemAvailable_bytes||0),m.MemTotal_bytes||0))+'</strong><span>'+esc(nodeSize(m.MemTotal_bytes))+' всего</span></div>'+
    '<div class="node-ws-stat"><small>Диск</small><strong>'+esc(nodePercent(m.disk_total_bytes-m.disk_available_bytes,m.disk_total_bytes))+'</strong><span>'+esc(nodeSize(m.disk_total_bytes))+' всего</span></div>'+
    '<div class="node-ws-stat"><small>Сертификат TLS</small><strong>'+nodeCertText(c)+'</strong><span>'+esc(c.last_checked?"Проверен "+nodeTime(c.last_checked):"Certbot на VPS")+'</span></div>'+
    '</div>'+
    '<div class="node-ws-tabs" role="tablist" aria-label="Разделы ноды">'+
    Object.entries(nodeTabs).map(([key,label])=>'<button type="button" role="tab" aria-selected="'+(key===selectedNodeTab)+
      '" class="node-ws-tab '+(key===selectedNodeTab?'active':'')+'" data-node-tab="'+key+'">'+label+'</button>').join("")+
    '</div><div id="node-ws-body" class="node-ws-body">'+nodeWorkspaceBody(n,a,c)+'</div>';
}
function nodeWorkspaceBody(n,a,c){
  const online=Boolean(a.online),m=a.metrics||{};
  switch(selectedNodeTab){
  case "overview":
    return '<div class="node-ws-columns"><div class="node-panel"><div class="node-panel-head"><h2>Система</h2>'+
      '<button class="btn subtle" data-node-task="system.status">Обновить данные</button></div>'+
      '<div class="node-kv"><span>Агент</span><strong>'+esc(a.version?"v"+a.version:"Не установлен")+'</strong>'+
      '<span>Связь</span><strong>'+nodeStatus(online,"Онлайн","Офлайн")+'</strong>'+
      '<span>Последний heartbeat</span><strong>'+esc(nodeTime(a.last_seen))+'</strong>'+
      '<span>Uptime</span><strong>'+esc(nodeDuration(m.uptime_seconds))+'</strong>'+
      '<span>Нагрузка</span><strong>'+esc([m.load1,m.load5,m.load15].filter(x=>x!==undefined).join(" / ")||"—")+'</strong></div>'+
      '</div><div class="node-panel"><div class="node-panel-head"><h2>Сертификат и безопасность</h2>'+
      '<button class="btn subtle" data-node-tab="tls">Подробнее</button></div>'+
      '<div class="node-kv"><span>Домен</span><strong>'+esc(n.domain)+'</strong>'+
      '<span>Проверка TLS</span><strong>'+nodeCertText(c)+'</strong>'+
      '<span>Последняя проверка</span><strong>'+esc(nodeTime(c.last_checked))+'</strong>'+
      '<span>Режим</span><strong>Файлы на VPS</strong></div>'+
      (c.last_error?'<p class="form-feedback error">'+esc(c.last_error)+'</p>':'')+'</div></div>'+
      '<div id="node-task-output"></div>'+
      '<p class="muted small">Все сведения получены через Manager и агент VPS. Статус контейнеров и служб доступен в соответствующем разделе.</p>';
  case "docker":
    return '<div class="node-panel"><div class="node-panel-head"><h2>Docker и системные службы</h2>'+
      '<button class="btn subtle" data-node-task="docker.status">Проверить Docker</button>'+
      '<button class="btn subtle" data-node-task="service.status">Проверить службы</button></div>'+
      '<p class="muted small">Данные проверяются агентом. Перезапуск конкретного контейнера потребует отдельного подтверждения.</p>'+
      '<div id="node-task-output"><p class="muted">Выбери проверку Docker или служб.</p></div></div>';
  case "logs":
    return '<div class="node-panel"><div class="node-panel-head"><h2>Логи сервера</h2></div>'+
      '<div class="node-log-controls"><label>Источник<select id="node-log-source">'+
      '<option value="docker:remnanode">Docker · Remnawave Node</option>'+
      '<option value="docker:nginx">Docker · Nginx</option>'+
      '<option value="file:xray-error">Xray · Ошибки</option>'+
      '<option value="file:xray-access">Xray · Подключения</option>'+
      '<option value="file:nginx-error">Nginx · Ошибки</option>'+
      '<option value="file:nginx-access">Nginx · Доступ</option>'+
      '<option value="file:certbot">Certbot</option></select></label>'+
      '<label>Строк<select id="node-log-tail"><option>50</option><option selected>100</option><option>200</option></select></label>'+
      '<button class="btn primary" type="button" data-node-logs>Получить логи</button></div>'+
      '<div id="node-task-output"><p class="muted">Выбери источник и нажми «Получить логи».</p></div></div>';
  case "tls":
    return '<div class="node-panel"><div class="node-panel-head"><h2>TLS / Certbot</h2>'+
      '<button class="btn subtle" data-node-cert-check="'+esc(n.id)+'" '+(!online?'disabled':'')+'>Проверить сейчас</button></div>'+
      '<div class="node-kv"><span>Домен</span><strong>'+esc(n.domain)+'</strong>'+
      '<span>Состояние</span><strong>'+nodeCertText(c)+'</strong>'+
      '<span>Истекает</span><strong>'+esc(c.expires_at?nodeTime(c.expires_at):"Ожидает проверки")+'</strong>'+
      '<span>Проверен</span><strong>'+esc(nodeTime(c.last_checked))+'</strong>'+
      '<span>Хранение</span><strong>Только на VPS</strong></div>'+
      (c.last_error?'<p class="form-feedback error">'+esc(c.last_error)+'</p>':'')+
      '<p class="muted small">После установки проверка запускается автоматически при готовности ноды. Приватные ключи на панель не передаются. Продление Certbot остаётся на VPS.</p>'+
      '<div id="node-task-output"></div>'+
      '<button class="btn subtle" data-tls-migrate="'+esc(n.id)+'" '+(!online?'disabled':'')+'>Проверить совместимость TLS-профиля</button></div>';
  case "network":return securityNetworkBody(n,a,m);
  case "configs":
    return '<div class="node-panel"><div class="node-panel-head"><h2>Конфигурации VPS</h2>'+
      '<div class="node-config-choices"><button class="btn subtle" data-node-config="nginx">Nginx</button>'+
      '<button class="btn subtle" data-node-config="node-compose">Remnawave Compose</button>'+
      '<button class="btn subtle" data-node-config="nginx-compose">Nginx Compose</button></div></div>'+
      '<p class="muted small">Nginx можно безопасно применить после проверки версии. Остальные конфиги здесь только для просмотра.</p>'+
      '<div id="node-task-output"></div></div>';
  case "manage":
    return '<div class="node-panel"><h2>Управление нодой</h2>'+
      '<p class="muted small">Изменения на VPS выполняются только через агент. Удаление из Remnawave и Manager никогда не очищает VPS.</p>'+
      '<div class="node-manage-actions">'+
      '<button class="btn subtle" data-node-action="docker.restart" '+(!online?'disabled':'')+'>Перезапустить Remnawave Node</button>'+
      '<button class="btn subtle" data-node-repair '+(!online?'disabled':'')+'>Исправить helper</button>'+
      '<button class="btn subtle" data-node-agent-install>Установить / восстановить агент</button>'+
      '<button class="btn subtle" data-node-archive>В архив / вернуть</button>'+
      '<button class="btn subtle" data-node-remove>Удалить ноду…</button></div>'+
      '<div class="node-panel" id="node-ssh-access"><h2>SSH-доступ</h2><p class="muted small">Загружаем сохранённый доступ…</p></div>'+
      '<div class="node-panel" id="node-agent-updater"><h2>Обновления агента</h2>'+
      '<p class="muted small">Загружаем версии агента…</p></div></div>';
  }
  return "";
}
function nodeReport(action,data){
  if(action==="system.status"){
    return '<div class="node-panel"><h2>Актуальные показатели</h2><div class="node-kv">'+
      Object.entries({RAM:nodeSize(data.MemTotal_bytes),Свободно:nodeSize(data.MemAvailable_bytes),
        Диск:nodeSize(data.disk_total_bytes),Свободно_на_диске:nodeSize(data.disk_available_bytes),
        Uptime:nodeDuration(data.uptime_seconds),Load_1:data.load1??"—",
        Load_5:data.load5??"—",Load_15:data.load15??"—"}).map(([k,v])=>'<span>'+esc(k.replaceAll("_"," "))+'</span><strong>'+esc(v)+'</strong>').join("")+
      '</div></div>';
  }
  if(action==="docker.status"){
    return '<div class="node-status-grid">'+(data.containers||[]).map(x=>
      '<div class="node-panel"><h3>'+esc(x.name)+'</h3>'+
      nodeStatus(x.running===true,"Работает","Остановлен")+
      '<p class="muted small">Статус: '+esc(x.status||"—")+'</p></div>').join("")+'</div>';
  }
  if(action==="service.status"){
    return '<div class="node-status-grid">'+(data.services||[]).map(x=>
      '<div class="node-panel"><h3>'+esc(x.name)+'</h3>'+
      nodeStatus(x.active===true,"Активна","Неактивна")+'</div>').join("")+'</div>';
  }
  if(action==="docker.logs"||action==="logs.read"){
    const raw=String(data.logs||"Лог пуст");
    const clean=raw.replace(/\x1b\[[0-9;]*[A-Za-z]/g,"");
    return '<div class="node-log-head"><span>'+esc(data.name||data.source||"Лог")+'</span>'+
      '<button class="btn subtle" data-node-copy>Скопировать</button></div>'+
      '<pre class="node-log-output">'+esc(clean)+'</pre>';
  }
  if(action==="baseline.status")return securityStatusReport(data);
  if(action==="cert.status"){
    return '<p class="form-feedback success">Проверка TLS завершена. '+
      esc(data.mode==="migration_required"?"Профиль требует ручной миграции.":"Сертификат подтверждён агентом.")+'</p>';
  }
  return '<pre class="node-log-output">'+esc(JSON.stringify(data,null,2))+'</pre>';
}
async function executeNodeTask(action,payload={}){
  if(nodeTaskBusy)return;
  const id=selectedNodeId,seq=++nodeTaskRequest;
  const output=$("node-task-output");
  if(!output)return;
  nodeTaskBusy=true;
  output.innerHTML='<p class="muted">Получаем сведения от агента…</p>';
  try{
    const result=await agentTask(id,action,payload,action==="docker.restart");
    if(id===selectedNodeId&&seq===nodeTaskRequest){
      if(action==="baseline.status")nodeSecuritySnapshot=result;
      output.innerHTML=nodeReport(action,result);
      if(action==="cert.status")await refreshNodeWorkspaceData();
    }
  }catch(e){
    if(id===selectedNodeId&&seq===nodeTaskRequest)output.innerHTML='<p class="form-feedback error">'+esc(e.message)+'</p>';
  }finally{nodeTaskBusy=false}
}
async function refreshNodeWorkspaceData(){
  const [agents,certs]=await Promise.all([api("/agents"),api("/node-certificates")]);
  nodeOverviewAgents=agents.agents||[];
  nodeOverviewCerts=certs.nodes||[];
  if(selectedNodeId){
    renderNodeWorkspace();
    if(selectedNodeTab==="manage"){await loadNodeSSHAccess();await loadNodeAgentUpdates();}
  }
}
async function showNodeConfig(name){
  if(nodeTaskBusy)return;
  const id=selectedNodeId,seq=++nodeTaskRequest;
  const output=$("node-task-output");
  nodeTaskBusy=true;output.innerHTML='<p class="muted">Загружаем конфигурацию…</p>';
  try{
    const r=await agentTask(id,"config.read",{name});
    if(id!==selectedNodeId||seq!==nodeTaskRequest)return;
    const editable=name==="nginx";
    output.innerHTML='<div class="node-panel"><div class="node-panel-head"><h2>'+esc(name)+'</h2>'+
      (editable?'<button type="button" class="btn primary" data-node-apply>Проверить и применить</button>':
      '<span class="muted small">Только просмотр</span>')+'</div>'+
      '<textarea id="node-config-text" class="node-config-text" spellcheck="false" '+
      (editable?'':'readonly')+'>'+esc(r.content||"")+'</textarea>'+
      '<p class="muted small">'+(editable?"Перед применением агент проверит SHA-256 и nginx -t, создаст резервную копию.":"Применение Docker Compose через эту вкладку отключено.")+'</p></div>';
    if(editable){
      const btn=output.querySelector("[data-node-apply]");
      btn.onclick=async()=>{
        const value=$("node-config-text").value;
        if(!confirm("Применить Nginx на "+currentNode().code+"? Агент проверит конфигурацию и при ошибке восстановит предыдущую."))return;
        btn.disabled=true;
        try{
          await agentTask(id,"config.apply",{name:"nginx",content:value,expected_sha256:r.sha256},true);
          message("Nginx проверен и применён.");
        }catch(e){message(e.message,true)}
        finally{btn.disabled=false}
      };
    }
  }catch(e){if(id===selectedNodeId)output.innerHTML='<p class="form-feedback error">'+esc(e.message)+'</p>'}
  finally{nodeTaskBusy=false}
}
async function loadNodeSSHAccess(){
  const id=selectedNodeId,box=$("node-ssh-access");
  if(!id||!box)return null;
  try{
    const info=await api("/nodes/"+encodeURIComponent(id)+"/ssh-access");
    if(selectedNodeId!==id||!document.getElementById("node-ssh-access"))return info;
    nodeSSHAccess=info;
    box.innerHTML='<div class="node-panel-head"><h2>SSH-доступ</h2>'+
      '<span class="node-state '+(info.has_password?"is-good":"is-bad")+'">'+
      (info.has_password?"Пароль сохранён":"Пароль не сохранён")+'</span></div>'+
      '<div class="node-kv"><span>IPv4 VPS</span><strong>'+esc(info.ip)+'</strong>'+
      '<span>SSH-порт</span><strong>'+esc(info.port)+'</strong>'+
      '<span>Fingerprint</span><strong><code>'+esc(info.ssh_fingerprint)+'</code></strong></div>'+
      '<p class="muted small">Пароль хранится только в зашифрованном виде на сервере Manager и никогда не возвращается браузеру.</p>'+
      '<div class="form-buttons"><button class="btn subtle" data-ssh-save>'+
      (info.has_password?"Изменить пароль":"Сохранить пароль")+'</button>'+
      (info.has_password?'<button class="btn subtle" data-ssh-clear>Удалить сохранённый пароль</button>':'')+'</div>';
    return info;
  }catch(e){box.innerHTML='<h2>SSH-доступ</h2><p class="form-feedback error">'+esc(e.message)+'</p>';return null}
}
function saveNodeSSHPassword(){
  const id=selectedNodeId,n=currentNode();if(!id||!n)return;
  openModal("SSH-доступ · "+n.code,"ЗАШИФРОВАННОЕ ХРАНЕНИЕ",
    '<p class="muted small">Пароль будет сохранён на Manager в зашифрованном виде. В браузер при следующих операциях он не возвращается.</p>'+
    '<form><label>Пароль root SSH<input type="password" name="password" required autocomplete="new-password"></label>'+
    '<div class="form-buttons"><button class="btn primary" type="submit">Сохранить пароль</button></div></form>',
    async fd=>{await api("/nodes/"+encodeURIComponent(id)+"/ssh-access","PUT",{password:fd.get("password")});
      message("SSH-пароль сохранён зашифрованно");await loadNodeSSHAccess();});
}
async function clearNodeSSHPassword(){
  const id=selectedNodeId;if(!id||!confirm("Удалить сохранённый SSH-пароль этой ноды из Manager?"))return;
  try{await api("/nodes/"+encodeURIComponent(id)+"/ssh-access","DELETE");message("Сохранённый SSH-пароль удалён");await loadNodeSSHAccess()}
  catch(e){message(e.message,true)}
}
async function nodeHasSavedSSH(){
  if(nodeSSHAccess&&nodeSSHAccess.node_id===selectedNodeId)return nodeSSHAccess.has_password;
  const info=await api("/nodes/"+encodeURIComponent(selectedNodeId)+"/ssh-access");
  nodeSSHAccess=info;return !!info.has_password;
}

async function loadNodeAgentUpdates(){
  const id=selectedNodeId,box=$("node-agent-updater");
  if(!id||!box)return;
  box.innerHTML='<h2>Обновления агента</h2><p class="muted small">Проверяем версии…</p>';
  try{
    const u=await api("/agents/"+encodeURIComponent(id)+"/update-status");
    if(selectedNodeId!==id||!document.getElementById("node-agent-updater"))return;
    const label=u.supports_self_update?"Через защищённое соединение агента":
      "Первый переход требует SSH";
    box.innerHTML='<div class="node-panel-head"><h2>Обновления агента</h2>'+
      '<button class="btn subtle" type="button" data-agent-update-refresh>Проверить версии</button></div>'+
      '<div class="node-kv"><span>Текущая версия</span><strong>'+esc(u.current_version||"Неизвестна")+'</strong>'+
      '<span>Версия в Manager</span><strong>'+esc(u.latest_version||"Недоступна")+'</strong>'+
      '<span>Архитектура</span><strong>'+esc(u.architecture)+'</strong>'+
      '<span>Способ обновления</span><strong>'+esc(label)+'</strong></div>'+
      '<label class="check-row"><input type="checkbox" id="agent-auto-update-switch" '+
      (u.auto_update?'checked':'')+'> Автоматически обновлять агент при появлении новой версии</label>'+
      '<p class="muted small">По умолчанию выключено. Обновляется только Agent. Если новая версия не подтвердит подключение, старая восстанавливается.</p>'+
      (u.one_time_ssh_migration_required?
      '<p class="muted small">Сейчас установлен старый агент. Для первого перехода потребуется пароль SSH root. В дальнейшем SSH не нужен.</p>':'')+
      '<div class="form-buttons"><button type="button" class="btn primary" data-agent-update-now '+
      (!u.online||!u.upgrade_needed||!u.artifact_ready?'disabled':'')+'>'+
      (u.upgrade_needed?'Обновить агент':'Последняя версия установлена')+'</button></div>';
    const input=$("agent-auto-update-switch");
    input.onchange=async()=>{
      input.disabled=true;
      try{
        await api("/agents/"+encodeURIComponent(id)+"/auto-update","PUT",{enabled:input.checked});
        message(input.checked?"Автообновление агента включено":"Автообновление агента отключено");
      }catch(e){input.checked=!input.checked;message(e.message,true)}
      finally{input.disabled=false}
    };
  }catch(e){
    box.innerHTML='<h2>Обновления агента</h2><p class="form-feedback error">'+esc(e.message)+'</p>';
  }
}
async function updateNodeAgentNow(){
  const id=selectedNodeId,n=currentNode();
  if(!id||!n)return;
  try{
    const state=await api("/agents/"+encodeURIComponent(id)+"/update-status");
    if(!state.upgrade_needed)return message("Агент уже последней версии");
    if(state.one_time_ssh_migration_required){
      if(await nodeHasSavedSSH()){
        if(!confirm("Обновить только Agent на "+n.code+" через сохранённый SSH-доступ?"))return;
        await api("/agents/"+encodeURIComponent(id)+"/update","POST",{confirmed:true,password:""});
        message("Агент перезапущен. Ожидаем heartbeat новой версии.");
        return refreshNodeWorkspaceData();
      }
      openModal("Обновить агент "+n.code,"ОДНОКРАТНО ЧЕРЕЗ SSH",
        '<p class="muted small">SSH-пароль ещё не сохранён. Введи его один раз — Manager сохранит его зашифрованно.</p>'+
        '<form><label>Пароль root SSH<input name="password" type="password" required autocomplete="new-password"></label>'+
        '<label class="check-row"><input type="checkbox" name="confirm" required> Подтверждаю обновление только агента</label>'+
        '<div class="form-buttons"><button class="btn primary" type="submit">Обновить агент</button></div></form>',
        async fd=>{
          await api("/nodes/"+encodeURIComponent(id)+"/ssh-access","PUT",{password:fd.get("password")});
          await api("/agents/"+encodeURIComponent(id)+"/update","POST",{confirmed:fd.get("confirm")==="on",password:""});
          message("Агент перезапущен. Ожидаем heartbeat новой версии.");
          await refreshNodeWorkspaceData();
        });
      return;
    }
    if(!confirm("Обновить только Agent на "+n.code+" до "+state.latest_version+
       "? Если он не подключится, предыдущая версия будет восстановлена."))return;
    await api("/agents/"+encodeURIComponent(id)+"/update","POST",{confirmed:true});
    message("Обновление поставлено в очередь. Проверяй версию после следующего heartbeat.");
    return loadNodeAgentUpdates();
  }catch(e){message(e.message,true)}
}

function bindNodeWorkspace(){
  $("node-detail").addEventListener("click",async e=>{
    const control=e.target.closest("button");if(!control)return;
    if(control.hasAttribute("data-node-back"))return closeNodeWorkspace();
    if(control.hasAttribute("data-ssh-save"))return saveNodeSSHPassword();
    if(control.hasAttribute("data-ssh-clear"))return clearNodeSSHPassword();
    if(control.hasAttribute("data-agent-update-now"))return updateNodeAgentNow();
    if(control.hasAttribute("data-agent-update-refresh"))return loadNodeAgentUpdates();
    if(control.dataset.nodeTab){
      selectedNodeTab=control.dataset.nodeTab;nodeTaskRequest++;renderNodeWorkspace();
      if(selectedNodeTab==="manage"){loadNodeSSHAccess();return loadNodeAgentUpdates()}
      if(selectedNodeTab==="network"){
        const agent=currentAgent();
        if(agent.online&&/^1\.(?:[2-9]|[1-9][0-9])\./.test(agent.version||""))
          return executeNodeTask("baseline.status");
      }
      return;
    }
    if(control.hasAttribute("data-node-network-refresh"))return refreshNodeWorkspaceData();
    if(control.hasAttribute("data-security-helper"))return prepareNodeSecurity();
    if(control.hasAttribute("data-security-install"))return installNodeSSHProtection();
    if(control.hasAttribute("data-security-unban"))return unbanNodeSSH(control.dataset.securityUnban);
    if(control.dataset.nodeTask)return executeNodeTask(control.dataset.nodeTask);
    if(control.hasAttribute("data-node-logs")){
      const source=$("node-log-source").value,tail=Number($("node-log-tail").value);
      return executeNodeTask(source.startsWith("docker:")?"docker.logs":"logs.read",
        source.startsWith("docker:")?{name:source.split(":")[1],tail}:{source:source.split(":")[1],tail});
    }
    if(control.dataset.nodeConfig)return showNodeConfig(control.dataset.nodeConfig);
    if(control.hasAttribute("data-node-copy")){
      const value=$("node-task-output")?.querySelector("pre")?.textContent||"";
      await navigator.clipboard.writeText(value).then(()=>message("Логи скопированы")).catch(()=>message("Не удалось скопировать",true));
      return;
    }
    if(control.dataset.nodeCertCheck){
      const id=control.dataset.nodeCertCheck;
      try{
        const job=await api("/node-certificates/"+encodeURIComponent(id)+"/sync","POST");
        const result=await waitAgentTask(id,job.id);
        await refreshNodeWorkspaceData();
        message(result.mode==="migration_required"?"Профиль требует миграции":"Сертификат проверен");
      }catch(err){message(err.message,true)}
      return;
    }
    if(control.dataset.tlsMigrate)return migrateNodeTLSModal(control.dataset.tlsMigrate);
    if(control.dataset.nodeAction)return agentActionModal(selectedNodeId,control.dataset.nodeAction);
    if(control.hasAttribute("data-node-repair"))return agentRepairModal(selectedNodeId);
    if(control.hasAttribute("data-node-agent-install"))return agentBootstrapModal(selectedNodeId);
    if(control.hasAttribute("data-node-remove"))return nodeLifecycleModal(selectedNodeId);
    if(control.hasAttribute("data-node-archive"))return nodeLifecycleModal(selectedNodeId);
  });
  document.addEventListener("click",e=>{
    const btn=e.target.closest("[data-node-open]");
    if(btn){
      e.preventDefault();
      openNodeWorkspace(btn.dataset.nodeOpen);
    }
  });
}
