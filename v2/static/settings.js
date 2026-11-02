"use strict";
let updateDetails=null,updatePolling=null;

async function loadMonitoringSettings(){
  try{
    const data=await api("/settings/monitoring");
    $("monitoring-interval").value=String(data.interval);
    $("monitoring-status").textContent="Текущая частота: "+data.interval+" сек.";
  }catch(e){$("monitoring-status").textContent=e.message}
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
    const profiles=check.config_profiles||[];
    $("panel-status").textContent="API доступен · "+profiles.length+
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

function bindSettingsEvents(){
  $("monitoring-form").onsubmit=async e=>{
    e.preventDefault();
    const interval=Number($("monitoring-interval").value);
    try{
      const result=await api("/settings/monitoring","PUT",{interval});
      monitoringMs=result.monitor_interval*1000;
      restartMonitoringTimer();
      $("monitoring-status").textContent="Сохранено: "+result.monitor_interval+" сек.";
      message("Частота мониторинга обновлена");
    }catch(err){
      message(err.message,true);
    }
  };
  $("update-check").onclick=checkUpdates;
  $("update-start").onclick=startUpdate;
  updatePolling=setInterval(()=>{
    if(currentPage==="updates")refreshUpdateStatus();
  },4500);
  $("panel-form").onsubmit=e=>{
    e.preventDefault();
    savePanel();
  };
  $("panel-check").onclick=checkPanel;
}
