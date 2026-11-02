"use strict";
let showArchivedNodes=false;

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
    '<form><label>SSH-пароль root <span class="muted">· необязательно, если сохранён</span><input name="password" type="password" autocomplete="new-password" placeholder="Использовать сохранённый пароль"></label>'+
    '<label class="check-row"><input name="confirm" type="checkbox" required> Подтверждаю установку агента на VPS</label>'+
    '<div class="form-buttons"><button class="btn primary" type="submit">Установить</button></div></form>',
    async fd=>{
      await api("/agents/"+encodeURIComponent(id)+"/bootstrap","POST",{
        password:fd.get("password"),confirm_ssh_migration:fd.get("confirm")==="on"});
      message("Агент установлен. Ожидаем подключения к менеджеру.");
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
    });
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

function bindNodeListEvents(){
  $("nodes-show-archived").onchange=e=>{
    showArchivedNodes=!!e.target.checked;
    renderNodes();
  };
  $("other-nodes").addEventListener("click",e=>{
    const btn=e.target.closest("[data-node-lifecycle]");
    if(btn)nodeLifecycleModal(btn.dataset.nodeLifecycle);
  });
}
