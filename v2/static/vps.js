"use strict";
// VPS wizard is intentionally separate from configuration/preset editors.
// Password is held only in memory during preflight and install request.
let vpsPayload=null,vpsInspection=null,vpsTimer=null;
function openVpsWizard(){
  vpsPayload=null;vpsInspection=null;
  if(vpsTimer){clearInterval(vpsTimer);vpsTimer=null}
  const form=document.getElementById("vps-form");
  form.reset();
  form.elements.namedItem("panel_ip").value=state.panel.outbound_ip||"";
  document.getElementById("vps-fields").classList.remove("hidden");
  document.getElementById("vps-preflight").classList.add("hidden");
  document.getElementById("vps-progress").classList.add("hidden");
  document.getElementById("vps-fingerprint-ok").checked=false;
  document.getElementById("vps-clean-ok").checked=false;
  document.getElementById("vps-install").disabled=true;
  document.getElementById("vps-dialog").showModal();
}
async function probeVps(event){
  event.preventDefault();
  const button=document.getElementById("vps-probe-button");
  button.disabled=true;button.textContent="Проверяем SSH и сеть…";
  try{
    const data=Object.fromEntries(new FormData(document.getElementById("vps-form")));
    data.port=Number(data.port||22);
    data.code=data.code.trim().toUpperCase();
    data.country=data.country.toUpperCase();
    data.domain=data.domain.trim().toLowerCase();
    data.ip=data.ip.trim();
    vpsInspection=await api("/vps/probe","POST",{
      ip:data.ip,port:data.port,domain:data.domain,password:data.password
    });
    const preview=await api("/vps/preview","POST",{
      code:data.code,domain:data.domain,country:data.country
    });
    vpsPayload=data;
    document.getElementById("vps-fields").classList.add("hidden");
    document.getElementById("vps-preflight").classList.remove("hidden");
    const info=vpsInspection,good=info.ready;
    document.getElementById("vps-check-details").innerHTML=
      '<div class="wizard-result '+(good?"wizard-good":"wizard-bad")+'">'+
      (good?"VPS прошёл предварительную проверку":"Есть проблемы — установка заблокирована")+'</div>'+
      '<p>Система: <strong>'+esc(info.os)+' '+esc(info.version)+'</strong></p>'+
      '<p>Архитектура: '+esc(info.architecture)+' · Свободно '+esc(info.free_disk_mb)+' МБ</p>'+
      '<p>SSH fingerprint: <code>'+esc(info.fingerprint)+'</code></p>'+
      (info.warnings.length?'<p class="wizard-errors">'+info.warnings.map(esc).join("; ")+'</p>':
        '<p>Порты 80/443/2222 свободны, DNS совпадает с VPS.</p>')+
      '<p class="muted small">Будут установлены Docker, Nginx, TLS и Remnawave Node, создан отдельный Xray Config Profile.</p>'+
      '<details class="template-info"><summary>Посмотреть замены и файлы перед установкой</summary>'+
      preview.variables.map(x=>'<div class="wizard-mapping"><code>'+esc(x.key)+'</code><span>→</span><strong>'+esc(x.value)+'</strong></div>').join("")+
      '<p class="muted small">'+esc(preview.note)+'</p>'+
      '<h3>Результат Xray</h3><pre class="wizard-preview">'+esc(JSON.stringify(preview.xray,null,2))+'</pre>'+
      '<h3>Nginx</h3><pre class="wizard-preview">'+esc(preview.nginx)+'</pre>'+
      '<p>Файлы: '+preview.files.map(esc).join(", ")+'</p></details>';
    document.getElementById("vps-install").disabled=true;
  }catch(e){message(e.message,true)}
  finally{button.disabled=false;button.textContent="Проверить SSH, DNS и порты"}
}
function updateVpsConsent(){
  document.getElementById("vps-install").disabled=!(vpsInspection?.ready &&
    document.getElementById("vps-fingerprint-ok").checked &&
    document.getElementById("vps-clean-ok").checked);
}
async function installVps(){
  if(!vpsPayload||!vpsInspection?.ready)return;
  document.getElementById("vps-install").disabled=true;
  try{
    const payload={...vpsPayload,fingerprint:vpsInspection.fingerprint,confirm_clean:true};
    const job=await api("/vps/install","POST",payload);
    vpsPayload.password="";vpsPayload=null;
    document.getElementById("vps-form").elements.namedItem("password").value="";
    document.getElementById("vps-preflight").classList.add("hidden");
    document.getElementById("vps-progress").classList.remove("hidden");
    document.getElementById("vps-progress-head").textContent="Установка "+job.node_id.slice(0,8);
    document.getElementById("vps-progress-text").textContent=job.message;
    const poll=async()=>{
      try{
        const result=await api("/vps/jobs/"+encodeURIComponent(job.node_id));
        document.getElementById("vps-progress-text").textContent=result.note;
        const done=["ready","failed","interrupted"].includes(result.stage);
        document.getElementById("vps-progress-head").textContent=
          result.stage==="registered"?"Зарегистрирована, ожидаем связь с Xray":
          result.stage==="ready"?"Нода работает":
          result.stage==="failed"?"Установка завершилась ошибкой":
          result.stage==="interrupted"?"Установка прервана":"Установка · "+result.stage;
        if(done){if(vpsTimer)clearInterval(vpsTimer);vpsTimer=null;await refresh()}
      }catch{
        document.getElementById("vps-progress-text").textContent="Проверяем связь с менеджером…";
      }
    };
    await poll();
    if(!vpsTimer&&!["Нода работает","Установка завершилась ошибкой","Установка прервана"].includes(document.getElementById("vps-progress-head").textContent))
      vpsTimer=setInterval(poll,4000);
  }catch(e){message(e.message,true);updateVpsConsent()}
}
async function showVpsJob(id){
  try{
    const info=await api("/vps/jobs/"+encodeURIComponent(id));
    openModal("Установка VPS","СОСТОЯНИЕ СЕРВЕРА",
      '<p><strong>'+esc(info.stage)+'</strong></p><p class="muted">'+esc(info.note)+'</p>'+
      '<p class="muted small">SSH: '+esc(info.ip)+':'+esc(info.port)+'</p>'+
      (info.remote_uuid?'<p>Remnawave UUID: '+esc(info.remote_uuid)+'</p>':'')+
      '<p class="muted small">Регистрация ещё не означает доступность клиентских подключений. Для них необходимы Hosts и Internal Squads.</p>');
  }catch(e){message(e.message,true)}
}
async function deleteDraft(id){
  const node=state.nodes.find(n=>n.id===id);
  if(!node||node.status!=="planned")return;
  if(!confirm("Удалить тестовый черновик "+node.code+" ("+node.domain+")?\n\nЭто удалит только запись из менеджера. VPS и Remnawave не изменятся."))return;
  try{
    await api("/nodes/"+encodeURIComponent(id),"DELETE");
    message("Черновик "+node.code+" удалён.");
    await refresh();
  }catch(e){message(e.message,true)}
}

document.addEventListener("DOMContentLoaded",()=>{
  document.getElementById("new-node").onclick=openVpsWizard;
  document.getElementById("vps-form").onsubmit=probeVps;
  document.getElementById("vps-fingerprint-ok").onchange=updateVpsConsent;
  document.getElementById("vps-clean-ok").onchange=updateVpsConsent;
  document.getElementById("vps-back").onclick=()=>{
    document.getElementById("vps-preflight").classList.add("hidden");
    document.getElementById("vps-fields").classList.remove("hidden");
    document.getElementById("vps-install").disabled=true;
  };
  document.getElementById("vps-install").onclick=installVps;
  document.getElementById("vps-close").onclick=()=>{document.getElementById("vps-dialog").close();vpsPayload=null};
  document.getElementById("vps-progress-close").onclick=()=>{document.getElementById("vps-dialog").close();vpsPayload=null};
  document.getElementById("other-nodes").addEventListener("click",e=>{
    const del=e.target.closest("[data-delete-draft]");
    if(del){deleteDraft(del.dataset.deleteDraft);return}
    const target=e.target.closest("[data-install-node]");
    if(target)showVpsJob(target.dataset.installNode);
  });
});
