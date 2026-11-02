"use strict";
const types={xray:"Xray JSON",nginx:"Nginx",nginx_compose:"Nginx Compose",node_compose:"Remnawave Compose"};
let currentConfig=null,configRevision=0,configBase="",configDirty=false,currentPreset=null;
let configCategory="xray";

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

function initializeLibraryPreview(){
  renderVariablePreview();
  api("/template/variables").then(x=>{
    $("template-variable-list").innerHTML=x.variables.map(v=>
      '<div class="variable-pill">'+esc("{{"+v.key+"}}")+'<small>'+esc(v.description)+'</small></div>'
    ).join("");
  }).catch(()=>{});
}

function bindLibraryEvents(){
  $("new-config").onclick=()=>resetConfig();
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
    if(e.key==="Tab"){
      e.preventDefault();
      const input=e.target;
      input.setRangeText("  ",input.selectionStart,input.selectionEnd,"end");
      markConfigDirty();
    }
    if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="s"){
      e.preventDefault();
      saveConfig();
    }
  });
  $("config-save").onclick=saveConfig;
  $("config-delete").onclick=deleteConfig;
  $("config-close").onclick=()=>{
    if(discardConfig()){
      $("config-dialog").close();
      configDirty=false;
    }
  };
  $("config-dialog").addEventListener("cancel",e=>{
    if(!discardConfig())e.preventDefault();
    else configDirty=false;
  });

  $("preset-close").onclick=()=>$("preset-dialog").close();
  $("new-preset").onclick=()=>{
    resetPreset();
    $("preset-dialog").showModal();
  };
  $("preset-reset").onclick=resetPreset;
  $("preset-form").onsubmit=e=>{
    e.preventDefault();
    savePreset();
  };
  $("preset-cards").addEventListener("click",e=>{
    const edit=e.target.closest("[data-preset-edit]");
    const remove=e.target.closest("[data-preset-delete]");
    if(edit)editPreset(edit.dataset.presetEdit);
    if(remove)removePreset(remove.dataset.presetDelete);
  });

  window.addEventListener("beforeunload",e=>{
    if(configDirty){
      e.preventDefault();
      e.returnValue="";
    }
  });
}
