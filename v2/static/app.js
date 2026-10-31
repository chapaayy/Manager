"use strict";
const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
}[c]));
const icon = name => '<svg><use href="/static/icons.svg#i-'+name+'"></use></svg>';
const types = {xray:"Xray JSON",nginx:"Nginx",nginx_compose:"Nginx Compose",node_compose:"Remnawave Compose"};
const titles = {nodes:"Ноды",certificates:"Сертификаты",configs:"Конфигурации",presets:"Пресеты",settings:"Настройки",updates:"Обновления"};
const labels = {regular:"Обычная",entry:"Входная / мост",exit:"Выходная"};
let csrf = "", currentPage = "nodes", currentConfig = null, configRevision = 0,
    configBase = "", configDirty = false, currentPreset = null, currentPlan = null,
    panelProfiles = [], expanded = new Set(), toastTimer = null;
let state = {panel:{},nodes:[],bridges:[],configs:[],presets:[]};
let updateDetails = null, updatePolling = null;

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
  state.panel=dashboard.panel;
  state.nodes=dashboard.nodes;
  state.bridges=dashboard.bridges;
  state.configs=configs;
  state.presets=presets;
  renderNodes();
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
  if(page==="certificates")refreshCertificates();
}
async function refreshCertificates(){
  const target=$("cert-nodes");
  try{
    const result=await api("/certificates");
    const ready=result.enabled;
    $("cert-global-status").textContent=ready?
      "Файловая синхронизация включена. Подключение общего тома к Remnawave обязательно.":
      "Синхронизация выключена. Прежде чем включать, подключи том к панели Remnawave.";
    $("cert-global-status").className="form-feedback "+(ready?"success":"");
    $("cert-enable").disabled=ready;
    $("cert-disable").disabled=!ready;
    target.innerHTML=(result.nodes||[]).map(n=>{
      let expiration=n.expires_at?
        new Date(n.expires_at*1000).toLocaleDateString("ru-RU"):"Сертификат не синхронизирован";
      const expired=n.expires_at&&n.expires_at*1000<Date.now();
      const warning=n.expires_at&&n.expires_at*1000<Date.now()+21*86400000;
      return '<div class="node-card"><span class="feature-icon">'+icon("shield-check")+
        '</span><div style="flex:1;min-width:200px"><strong>'+esc(n.code)+' · '+esc(n.domain)+
        '</strong><p>'+esc(expiration)+' · '+(n.auto_sync?"Автоматически (6 ч)":"Только вручную")+
        '</p>'+(n.last_synced?'<p>Синхронизирован: '+esc(new Date(n.last_synced*1000).toLocaleString("ru-RU"))+'</p>':'')+
        (n.last_error?'<p class="form-feedback error">'+esc(n.last_error)+'</p>':'')+
        (n.staged?'<details><summary class="muted small">Пути для Remnawave</summary><code>'+esc(n.panel_paths.certificateFile)+
        '</code><p><code>'+esc(n.panel_paths.keyFile)+'</code></p></details>':'')+
        '</div><span class="tiny-chip '+(expired||warning?"warning":"success")+'">'+
        (expired?"Истёк":warning?"Скоро истечёт":n.staged?"Синхронизирован":"Не настроен")+
        '</span><button class="btn subtle" type="button" data-cert-sync="'+esc(n.id)+
        '" '+(!ready?"disabled":"")+'>Синхронизировать</button>'+
        '<button class="btn subtle" type="button" data-cert-enroll="'+esc(n.id)+
        '" '+(!ready?"disabled":"")+'>Автосинхронизация</button>'+
        (n.staged&&n.node_status==="ready"&&n.profile_mode==="inline"?
          '<button class="btn primary" type="button" data-cert-migrate="'+esc(n.id)+'">Перейти на файлы</button>':"")+
        (n.profile_mode==="files"?
          '<button class="btn subtle" type="button" data-cert-restore="'+esc(n.id)+'">Откатить Xray</button>':"")+
        '</div>';
    }).join("")||'<p class="muted">Нет серверов для синхронизации.</p>';
  }catch(e){target.textContent=e.message;target.className="form-feedback error";}
}
async function certMigrationModal(id, restore=false){
  const node=state.nodes.find(n=>n.id===id);
  if(!node)return;
  try{
    if(restore){
      if(!confirm("Восстановить предыдущий Xray-конфиг "+node.code+"? Будет перезапуск ноды и кратковременный разрыв соединений."))return;
      await api("/certificates/"+encodeURIComponent(id)+"/restore","POST",{confirm_restore:true});
      message("Запрошен откат Xray "+node.code+". Проверь работу клиентов.");
      await refreshCertificates();return;
    }
    const plan=await api("/certificates/"+encodeURIComponent(id)+"/migration");
    openModal("Переключить "+node.code+" на файловые сертификаты","XRAY / ПРОВЕРКА",
      '<p>Изменится <strong>только путь к TLS-сертификату</strong> внутри штатного inbound.</p>'+
      '<p class="muted small">Профиль: '+esc(plan.profile_uuid)+'</p>'+
      '<p class="muted small">Ключ: <code>'+esc(plan.panel_paths.keyFile)+'</code></p>'+
      '<p class="muted small">Сертификат: <code>'+esc(plan.panel_paths.certificateFile)+'</code></p>'+
      '<p class="inline-info">Том должен быть подключён к Remnawave Panel. Сохранится зашифрованная резервная копия прежнего конфига. Потребуется перезапуск Xray, возможен разрыв подключений.</p>'+
      '<form><label class="check-row"><input type="checkbox" required name="confirmed"> Подтверждаю переключение работающей ноды</label>'+
      '<div class="form-buttons"><button type="submit" class="btn primary">Применить и перезапустить</button></div></form>',
      async fd=>{
        await api("/certificates/"+encodeURIComponent(id)+"/migration","POST",{
          sha256:plan.sha256,confirm_change:fd.get("confirmed")==="on"
        });
        message("Файловые сертификаты включены для "+node.code+". Проверь работу Xray.");
        await refreshCertificates();
      });
  }catch(e){message(e.message,true)}
}

function certSyncModal(id, auto=false){
  const node=state.nodes.find(n=>n.id===id);
  if(!node)return;
  openModal(auto?"Подключить автосинхронизацию":"Синхронизировать сертификат",
    "TLS / "+node.code,
    '<p class="muted small">'+(auto?
      'Установим на VPS отдельный SSH-ключ, который позволяет только прочитать TLS-сертификат и ключ. Пароль root не сохраняется.':
      'Прочитаем сертификат и ключ по защищённому SSH, проверим домен и срок, затем поместим в том Remnawave. Действующий Xray-конфиг не изменится.')+
    '</p><form><label>SSH-пароль root<input type="password" name="password" required autocomplete="new-password"></label>'+
    (auto?'<label class="check-row"><input name="confirm" type="checkbox" required> Подтверждаю установку ограниченного SSH-ключа на VPS</label>':'')+
    '<div class="form-buttons"><button class="btn primary" type="submit">'+
      (auto?"Подключить и проверить":"Синхронизировать")+'</button></div></form>',
    async fd=>{
      const password=fd.get("password");
      const target=auto?"/certificates/"+encodeURIComponent(id)+"/enroll":
        "/certificates/"+encodeURIComponent(id)+"/sync";
      await api(target,"POST",auto?{password,confirm_root_forced_command:fd.get("confirm")==="on"}:{password});
      message("Сертификат "+node.code+" проверен и сохранён в общем томе панели.");
      await refreshCertificates();
    });
}

function renderNodes(){
  $("metric-nodes").textContent=String(state.nodes.length);
  $("metric-bridges").textContent=String(state.bridges.length);
  $("metric-exits").textContent=String(state.bridges.reduce((n,b)=>n+b.exits.length,0));
  const bridges = state.bridges;
  const target=$("bridge-list");
  if(!bridges.length){
    target.innerHTML='<div class="empty-state"><span class="feature-icon">'+icon("git-branch")+
      '</span><h3>Мостов пока нет</h3><p>Добавь входной VPS и создай мост. Внутри него будут появляться все выходные серверы и планы изменений.</p>'+
      '<button class="btn subtle" data-action="bridge-new">'+icon("plus")+' Создать первый мост</button></div>';
  }else{
    target.innerHTML=bridges.map(b=>{
      const open=expanded.has(b.id);
      const main=b.entry;
      const children=b.exits.map(e=>
        '<div class="bridge-child">'+icon("server")+
        '<div class="child-body"><strong>'+esc(e.code)+' · '+esc(e.name)+'</strong><small>'+
          esc(e.domain)+' · TCP/'+esc(e.inbound_port)+'</small></div>'+
        '<span class="tiny-chip success">Связан</span></div>'
      ).join("");
      const pending=b.plans.map(p=>
        '<button class="bridge-child" data-action="open-plan" data-plan="'+esc(p.id)+'" type="button">'+
        icon("file-code")+'<div class="child-body"><strong>'+esc(p.exit_code)+
        ' · черновик</strong><small>Не применён на VPS · TCP/'+esc(p.inbound_port)+'</small></div>'+
        '<span class="tiny-chip warning">'+esc(p.status)+'</span></button>'
      ).join("");
      return '<article class="bridge-card '+(open?'open':'')+'">'+
        '<button class="bridge-head" data-action="toggle-bridge" data-bridge="'+esc(b.id)+'" aria-expanded="'+open+'">'+
        '<span class="feature-icon">'+icon("git-branch")+'</span>'+
        '<span class="bridge-title"><strong>'+esc(main.code)+' · '+esc(b.name)+
        '</strong><small>'+esc(main.domain)+' · '+b.exits.length+' связанных нод</small></span>'+
        '<span class="tiny-chip">'+(b.has_snapshot?"Xray сохранён":"Bridge")+'</span>'+
        '<span class="bridge-chevron">'+icon("chevron-down")+'</span></button>'+
        (open?'<div class="bridge-children">'+(children||'<p class="muted small">Пока нет подключённых выходов.</p>')+pending+
          '<div class="bridge-footer">'+
          '<button class="btn subtle" data-action="bridge-exit" data-bridge="'+esc(b.id)+'">'+icon("plus")+' Добавить выход</button>'+
          '<button class="btn subtle" data-action="bridge-import" data-bridge="'+esc(b.id)+'">'+icon("file-code")+' Импорт Xray</button>'+
          '</div></div>':'')+'</article>';
    }).join("");
  }
  const grouped=new Set(state.bridges.flatMap(b=>[b.entry_id,...b.exits.map(e=>e.id)]));
  const others=state.nodes.filter(n=>!grouped.has(n.id));
  $("other-nodes").innerHTML=others.length?others.map(n=>
    '<div class="node-card"><span class="feature-icon">'+icon("server")+'</span><div><strong>'+
    esc(n.code)+' · '+esc(n.name)+'</strong><p>'+esc(n.domain)+' · '+esc(labels[n.role])+
    '</p></div><span class="tiny-chip '+(n.status==="registered"||n.status==="ready"?"success":"warning")+'">'+
    esc(n.status==="planned"?"Черновик":n.status)+'</span>'+
    (n.status==="planned"?
       '<button type="button" class="btn subtle" data-delete-draft="'+esc(n.id)+'">Удалить черновик</button>':"")+
    (n.status==="planned" && (n.role==="regular"||n.role==="exit")?
       '<button type="button" class="btn subtle" data-draft-install="'+esc(n.id)+'">Установить VPS</button>':
       n.status!=="planned"?
       '<button type="button" class="btn subtle" data-install-node="'+esc(n.id)+'">Статус</button>':"")+
    (["failed","interrupted"].includes(n.status)?
       '<button type="button" class="btn primary" data-retry-vps="'+esc(n.id)+'">Продолжить</button>'+
       '<button type="button" class="btn subtle" data-forget-vps="'+esc(n.id)+'">Убрать запись</button>':"")+
    '</div>'
  ).join(""):'<div class="empty-state"><h3>Незадействованных серверов нет</h3><p>Новые VPS появятся здесь, пока ты не включишь их в мост.</p></div>';
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
  $("config-kind").disabled=false;$("config-kind").value="xray";
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
  const files=state.configs.filter(f=>(f.name+" "+types[f.kind]).toLowerCase().includes(q));
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
    '<article class="preset-card"><h3>'+esc(p.name)+'</h3><p>'+esc(p.description||"Пользовательский набор")+'</p>'+
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
  $("preset-edit-title").textContent=p.name;
  renderPresetSelects(Object.fromEntries(p.items.map(x=>[x.kind,x.config_id])));
  $("preset-dialog").showModal();
}
async function savePreset(){
  const ids=[...document.querySelectorAll("[data-preset-kind]")].map(x=>x.value).filter(Boolean);
  if(!ids.length)return message("Добавь хотя бы один файл.",true);
  const body={name:$("preset-name").value.trim(),
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
  $("update-check").onclick=checkUpdates;
  $("update-start").onclick=startUpdate;
  updatePolling=setInterval(()=>{if(currentPage==="updates")refreshUpdateStatus()},4500);
  $("new-bridge").onclick=bridgeModal;
  $("bridge-list").addEventListener("click",e=>{
    const button=e.target.closest("[data-action]");
    if(!button)return;
    const action=button.dataset.action,id=button.dataset.bridge;
    if(action==="toggle-bridge"){
      expanded.has(id)?expanded.delete(id):expanded.add(id);
      renderNodes();
    }else if(action==="bridge-new")bridgeModal();
    else if(action==="bridge-exit")bridgeExitModal(id);
    else if(action==="bridge-import")bridgeImportModal(id).catch(err=>message(err.message,true));
    else if(action==="open-plan")openPlanId(button.dataset.plan);
  });
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
  $("cert-refresh").onclick=refreshCertificates;
  $("cert-enable").onclick=async()=>{
    if(!confirm("Я подключил Docker volume xppn-v2-panel-certs в Remnawave Panel и проверил, что панель читает файлы. Включить файловую синхронизацию?"))return;
    try{await api("/certificates/settings","POST",{enabled:true,confirmed_panel_mount:true});await refreshCertificates()}
    catch(e){message(e.message,true)}
  };
  $("cert-disable").onclick=async()=>{
    if(!confirm("Выключить синхронизацию? Уже созданные файлы и действующие профили не изменятся."))return;
    try{await api("/certificates/settings","POST",{enabled:false});await refreshCertificates()}
    catch(e){message(e.message,true)}
  };
  $("cert-nodes").addEventListener("click",e=>{
    const sync=e.target.closest("[data-cert-sync]");
    const migrate=e.target.closest("[data-cert-migrate]");
    const restore=e.target.closest("[data-cert-restore]");
    if(migrate){certMigrationModal(migrate.dataset.certMigrate);return}
    if(restore){certMigrationModal(restore.dataset.certRestore,true);return}
    const auto=e.target.closest("[data-cert-enroll]");
    if(sync)certSyncModal(sync.dataset.certSync,false);
    else if(auto)certSyncModal(auto.dataset.certEnroll,true);
  });
  $("panel-check").onclick=checkPanel;
  window.addEventListener("beforeunload",e=>{
    if(configDirty){e.preventDefault();e.returnValue=""}
  });
}
document.addEventListener("DOMContentLoaded",start);
