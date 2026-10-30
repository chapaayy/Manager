'use strict';
let csrf='', selectedNode=null,nodesCache=[],selectedTab='overview',expectedFingerprint='',configState=null,liveSource=null,logCursor=0,logText='',wizardStep=1,logPollTimer=null;
const $=id=>document.getElementById(id);
const escapeHtml=v=>String(v??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const fmtBytes=n=>!n?'—':(n/1073741824).toFixed(1)+' ГБ';
const errorText=e=>String(e?.message||e).slice(0,700);
let toastTimer;
function toast(s){const el=$('toast');el.textContent=s;el.classList.remove('hidden');clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.add('hidden'),5500)}
async function api(path,method='GET',body=null){const h={};if(method!=='GET')h['X-CSRF-Token']=csrf;if(body!==null)h['Content-Type']='application/json';const r=await fetch('/api'+path,{method,credentials:'same-origin',cache:'no-store',headers:h,body:body===null?null:JSON.stringify(body)});let data;try{data=await r.json()}catch{throw Error('Ответ сервера не JSON')}if(!r.ok)throw Error(typeof data.detail==='string'?data.detail:'Ошибка '+r.status);return data}
function authUI(showLogin){$('login-screen').classList.toggle('hidden',!showLogin);$('app-screen').classList.toggle('hidden',showLogin)}
async function init(){const me=await api('/me');if(!me.authenticated){authUI(true);return}csrf=me.csrf;authUI(false);showPage('servers');await loadNodes()}
$('login-form').onsubmit=async e=>{e.preventDefault();$('login-error').textContent='';try{const d=await api('/login','POST',{username:$('login-user').value.trim(),password:$('login-pass').value});csrf=d.csrf;$('login-pass').value='';authUI(false);showPage('servers');await loadNodes()}catch(e){$('login-error').textContent=errorText(e)}};
$('logout').onclick=async()=>{try{await api('/logout','POST',{})}finally{csrf='';stopStream();authUI(true)}};
$('nav-presets').onclick=()=>showPage('presets');$('nav-overview').onclick=()=>showPage('overview');$('nav-configs').onclick=()=>showPage('configs');$('nav-logs').onclick=()=>showPage('logs');$('nav-monitoring').onclick=()=>showPage('monitoring');$('nav-updates').onclick=()=>showPage('updates');$('nav-settings').onclick=()=>showPage('settings');$('nav-projects').onclick=()=>showPage('projects');$('nav-servers').onclick=()=>showPage('servers');$('nav-add').onclick=()=>showPage('add');$('top-add').onclick=()=>showPage('add');$('go-back').onclick=()=>showPage('servers');$('cancel-add').onclick=()=>showPage('servers');$('refresh').onclick=()=>loadNodes().catch(e=>toast(errorText(e)));
function showPage(page){if(page!=='detail'){stopStream();stopLiveLogs()}if(page!=='logs')logCenterActive=false;for(const p of ['servers','add','detail','projects','overview','configs','presets','logs','monitoring','updates','settings'])$(p+'-page').classList.toggle('hidden',p!==page);for(const n of ['servers','add','projects','overview','configs','presets','logs','monitoring','updates','settings'])$('nav-'+n).classList.toggle('active',page===n||(page==='detail'&&n==='servers'));$('breadcrumb').textContent={servers:'Ноды',add:'Новая нода',detail:'Управление',projects:'Проекты',overview:'Обзор',configs:'Конфигурации',presets:'Пресеты',logs:'Логи',monitoring:'Мониторинг',updates:'Обновления',settings:'Настройки'}[page];if(page==='add'){setWizardStep(1);refreshWizardProjects().catch(e=>toast(errorText(e)))}if(page==='projects')loadProjectsUI().catch(e=>toast(errorText(e)));if(page==='servers')loadNodes().catch(e=>toast(errorText(e)));if(page==='overview')loadOverview().catch(e=>toast(errorText(e)));if(page==='monitoring')loadMonitoring().catch(e=>toast(errorText(e)));if(page==='logs'){logCenterActive=true;loadLogCenter().catch(e=>toast(errorText(e)))}if(page==='configs'){loadConfigCenter().catch(e=>toast(errorText(e)));loadLibraryPanel().catch(e=>toast(errorText(e)))}if(page==='presets')loadPresetBundles().catch(e=>toast(errorText(e)));if(page==='updates')loadUpdateStatus().catch(e=>toast(errorText(e)));if(page==='settings')loadSettings().catch(e=>toast(errorText(e)))}
function inventory(r){return r?.components||{}}
function installed(r,c){return !!inventory(r)[c]?.installed}
function containerPresent(r,c){return !!inventory(r)[c]?.container}
function isOnline(r){return r?.stage==='ready'&&r.online}
function managedCount(r){return ['remnanode','nginx'].filter(c=>installed(r,c)).length}
function capabilityTabs(r){const present=managedCount(r);return {
  overview:true, components:true, docker:present>0, configs:Object.values(inventory(r).configs||{}).some(Boolean),
  logs:true, node:installed(r,'remnanode'), network:(r.telemetry?.capabilities||[]).includes('network.status'), jobs:true
}}
function syncTabs(r){const tabs=capabilityTabs(r);document.querySelectorAll('#detail-tabs .tab').forEach(b=>b.classList.toggle('hidden',!tabs[b.dataset.tab]));if(!tabs[selectedTab])selectedTab='components';}
function componentBadge(c){return c?.running?'<span class="soft-tag good">Работает</span>':c?.installed?'<span class="soft-tag caution">Установлен · выключен</span>':'<span class="soft-tag">Не установлен</span>'}
function refreshAfterJob(id){return waitJob(id).then(async j=>{await refreshDetail();renderTab();return j})}
function statusLabel(r){if(r.stage==='registration_failed')return 'Ошибка регистрации';if(r.stage==='registering')return 'Регистрация в панели';if(r.stage==='failed')return 'Ошибка';if(r.stage==='installing')return 'Установка';if(r.stage==='waiting')return 'Ожидание агента';if(r.stage==='provisioning')return 'Настройка';if(r.stage==='verifying')return 'Проверка';return r.online?(installed(r,'remnanode')?'Агент онлайн · нода установлена':'Агент онлайн'):'Агент не отвечает'}
async function loadNodes(){if(!csrf)return;nodesCache=await api('/nodes');const ready=nodesCache.filter(x=>x.stage==='ready'&&x.online).length;const busy=nodesCache.filter(x=>!['ready','failed','registration_failed'].includes(x.stage)).length;$('total-count').textContent=nodesCache.length;$('stats').innerHTML=[['Все серверы',nodesCache.length],['Работают',ready],['Устанавливаются',busy]].map(s=>`<div class="stat"><small>${s[0]}</small><div class="num">${s[1]}</div></div>`).join('');$('server-list').innerHTML=nodesCache.length?nodesCache.map(r=>`<article class="server" data-node="${escapeHtml(r.id)}"><div class="server-head"><span class="server-name"><span class="server-icon"><svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-server"></use></svg></span>${escapeHtml(r.name)}</span><span class="state ${r.stage==='ready'?(r.online?'':'off'):escapeHtml(r.stage)}">${escapeHtml(statusLabel(r))}</span></div><p class="server-host">${escapeHtml(r.ip)} · ${escapeHtml(projectCache.find(p=>p.id===r.project_id)?.name||'Основной проект')} · ${escapeHtml({agent:'Управление',node:'Remnawave',full:'Полный XPPN'}[r.preset]||'—')}</p><div class="server-line"><span>${r.stage==='ready'?`${managedCount(r)} сервиса · ${inventory(r).agent?.running?'агент подключён':'нет телеметрии'}`:'Установка инфраструктуры'}</span><span>${r.online?'На связи':r.stage==='failed'?'Требуется внимание':'Ожидание'}</span></div></article>`).join(''):'<div class="servers-empty"><div class="servers-empty-icon"><svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-server"></use></svg></div><h2>Пока нет подключённых нод</h2><p>Добавь сервер в мастер установки, либо сначала подготовь свои конфиги и пресеты — для этого нода не нужна.</p><div class="servers-empty-actions"><button id="nodes-empty-add" class="btn primary" type="button">Добавить VPS</button><button id="nodes-empty-configs" class="btn secondary" type="button">Открыть конфиги</button><button id="nodes-empty-presets" class="btn secondary" type="button">Пресеты</button></div></div>';document.querySelectorAll('[data-node]').forEach(el=>el.onclick=()=>openNode(el.dataset.node))}

let projectCache=[], profilesCache=[], transportCache=[], remoteProjectProfiles=[], remoteDeploymentProfiles=[];
const profileTitle = p=>`${p.name} · ${p.transport} · v${p.revision}`;
function resetProjectForm(){for(const id of ['project-id','project-name','project-url','project-panel-ip','project-secret','project-token'])$(id).value='';$('project-form-title').textContent='Новый проект';$('project-defaults').classList.add('hidden');$('project-sync-msg').textContent=''}
function resetProfileForm(){for(const id of ['profile-id','profile-name'])$(id).value='';$('profile-mode').value='node';$('profile-transport').value='tls-raw';$('profile-port').value='443';$('profile-site').value='static';$('profile-logs').value='standard';$('profile-udp').value='60';$('profile-xhttp-path').value='/xhttp';$('profile-bbr').checked=false;$('profile-fail2ban').checked=false;$('profile-form-title').textContent='Новый шаблон';$('profile-panel-config-profile').value='';renderProfileInboundOptions([])}
async function fetchProjects(){projectCache=await api('/projects');transportCache=await api('/transports');const sel=$('profile-transport');const old=sel.value;sel.innerHTML=transportCache.map(p=>`<option value="${escapeHtml(p.id)}">${escapeHtml(p.title)}</option>`).join('');sel.value=transportCache.some(p=>p.id===old)?old:'tls-raw'}
function fillProjectSelect(id,selected){$(id).innerHTML=projectCache.map(p=>`<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join('');if(selected&&projectCache.some(p=>p.id===selected))$(id).value=selected}
async function loadProjectsUI(){const selected=$('profile-project').value;await fetchProjects();fillProjectSelect('profile-project',selected);$('projects-list').innerHTML=projectCache.map(p=>`<div class="project-record"><b>${escapeHtml(p.name)}</b><small>${escapeHtml(p.panel_url||'Не настроена панель')} · ${p.has_secret_key?'Secret Key задан':'Нет Secret Key'} · ${p.has_api_token?'API задан':'Нет API'}</small><button type="button" class="btn secondary sm project-edit" data-id="${escapeHtml(p.id)}">Редактировать</button></div>`).join('');document.querySelectorAll('.project-edit').forEach(b=>b.onclick=()=>{const p=projectCache.find(p=>p.id===b.dataset.id);if(!p)return;$('project-id').value=p.id;$('project-name').value=p.name;$('project-url').value=p.panel_url;$('project-panel-ip').value=p.panel_ip;$('project-secret').value='';$('project-token').value='';$('project-form-title').textContent='Редактировать: '+p.name;$('project-editor').open=true;$('project-defaults').classList.add('hidden');$('project-sync-msg').textContent='Профиль выбран: '+(p.panel_config_profile_uuid||'не задан')+'; inbound-ов: '+(p.panel_active_inbounds?.length||0)});await loadProfilesUI()}
async function loadProfilesUI(){const pid=$('profile-project').value;if(!pid)return;profilesCache=await api('/projects/'+encodeURIComponent(pid)+'/profiles');$('profiles-list').innerHTML=profilesCache.map(p=>`<div class="project-record"><b>${escapeHtml(p.name)}</b><small>${escapeHtml(p.transport)} · ${escapeHtml(p.mode)} · v${p.revision}</small><button class="btn secondary sm profile-edit" data-id="${escapeHtml(p.id)}">Редактировать</button></div>`).join('');try{await loadProfilePanelOptions(pid)}catch(e){$('profile-panel-status').textContent=errorText(e)}document.querySelectorAll('.profile-edit').forEach(b=>b.onclick=()=>{const p=profilesCache.find(p=>p.id===b.dataset.id);if(!p)return;$('profile-id').value=p.id;$('profile-name').value=p.name;$('profile-mode').value=p.mode;$('profile-transport').value=p.transport;$('profile-port').value=p.settings.port||443;$('profile-site').value=p.settings.site||'static';$('profile-logs').value=p.settings.logs||'standard';$('profile-udp').value=p.settings.udp_idle_timeout||60;$('profile-xhttp-path').value=p.settings.xhttp_path||'/xhttp';$('profile-bbr').checked=!!p.settings.bbr;$('profile-fail2ban').checked=!!p.settings.fail2ban;$('profile-form-title').textContent='Редактировать: '+p.name;$('profile-editor').open=true;setProfilePanelOverride(p.settings)})}
async function loadProfilePanelOptions(pid){
 remoteDeploymentProfiles=await api('/projects/'+encodeURIComponent(pid)+'/panel/profiles');
 const sel=$('profile-panel-config-profile');sel.innerHTML='<option value="">Наследовать из VPN-проекта</option>'+remoteDeploymentProfiles.map(x=>`<option value="${escapeHtml(x.uuid)}">${escapeHtml(x.name||x.uuid)}</option>`).join('');
 $('profile-panel-status').textContent=`Загружено ${remoteDeploymentProfiles.length} профилей Remnawave`;renderProfileInboundOptions([]);
}
function renderProfileInboundOptions(preselected){
 const selected=$('profile-panel-config-profile').value;
 const row=remoteDeploymentProfiles.find(x=>x.uuid===selected);
 $('profile-panel-inbounds').innerHTML=(row?.inbounds||[]).map(x=>`<label class="checkbox-row"><input class="profile-panel-inbound" type="checkbox" value="${escapeHtml(x.uuid)}" ${preselected.includes(x.uuid)?'checked':''}>${escapeHtml(x.tag||x.uuid)}</label>`).join('');
}
function setProfilePanelOverride(settings){
 const id=settings?.panel_config_profile_uuid||'';
 $('profile-panel-config-profile').value=remoteDeploymentProfiles.some(x=>x.uuid===id)?id:'';
 renderProfileInboundOptions(settings?.panel_active_inbounds||[]);
}
$('profile-panel-config-profile').onchange=()=>renderProfileInboundOptions([]);
$('profile-project').onchange=()=>loadProfilesUI().catch(e=>toast(errorText(e)));
$('project-reset').onclick=resetProjectForm;
$('profile-reset').onclick=resetProfileForm;
$('project-form').onsubmit=async e=>{e.preventDefault();const id=$('project-id').value;const payload={name:$('project-name').value.trim(),panel_url:$('project-url').value.trim(),panel_ip:$('project-panel-ip').value.trim(),secret_key:$('project-secret').value,api_token:$('project-token').value};try{const result=await api(id?'/projects/'+encodeURIComponent(id):'/projects',id?'PATCH':'POST',payload);resetProjectForm();await loadProjectsUI();const savedId=id||result.id;const p=projectCache.find(x=>x.id===savedId);if(p){$('project-id').value=savedId;$('project-name').value=p.name;$('project-url').value=p.panel_url;$('project-panel-ip').value=p.panel_ip;$('project-form-title').textContent='Настройки: '+p.name;$('project-editor').open=true}toast('Проект сохранён. Нажми «Проверить API», чтобы получить ключ и inbound-ы')}catch(err){toast(errorText(err))}};
function displayProjectProfiles(list){
  remoteProjectProfiles=list;
  const pid=$('project-id').value;
  const p=projectCache.find(p=>p.id===pid);
  const sel=$('project-config-profile');
  sel.innerHTML=list.map(x=>`<option value="${escapeHtml(x.uuid)}">${escapeHtml(x.name||x.uuid)}</option>`).join('');
  if(p?.panel_config_profile_uuid&&list.some(x=>x.uuid===p.panel_config_profile_uuid))sel.value=p.panel_config_profile_uuid;
  const show=()=>{const prof=list.find(x=>x.uuid===sel.value);$('project-inbounds').innerHTML=(prof?.inbounds||[]).map(i=>`<label class="checkbox-row"><input type="checkbox" class="project-inbound" value="${escapeHtml(i.uuid)}" ${(p?.panel_active_inbounds||[]).includes(i.uuid)?'checked':''}>${escapeHtml(i.tag||i.uuid)}</label>`).join('')||'<p class="warn">Нет inbound-ов — проверь конфигурационный профиль Remnawave.</p>'};
  sel.onchange=show;show();$('project-country').value=p?.panel_country_code||'XX';$('project-defaults').classList.remove('hidden');
}
$('project-sync').onclick=async()=>{
 const pid=$('project-id').value;if(!pid)return toast('Сначала сохрани проект и открой его на редактирование');
 const b=$('project-sync');b.disabled=true;$('project-sync-msg').textContent='Проверяем API, получаем ключ ноды и конфиги…';
 try{const d=await api('/projects/'+encodeURIComponent(pid)+'/panel/sync','POST',{});await fetchProjects();displayProjectProfiles(d.profiles);$('project-sync-msg').textContent=`API подключён. Ключ ноды получен и зашифрован. Профилей: ${d.profiles.length}.`}
 catch(e){$('project-sync-msg').textContent=errorText(e)}finally{b.disabled=false}
};
$('project-save-defaults').onclick=async()=>{
 const pid=$('project-id').value;const chosen=[...document.querySelectorAll('.project-inbound:checked')].map(x=>x.value);
 if(!pid||!chosen.length)return toast('Выбери хотя бы один inbound');
 try{await api('/projects/'+encodeURIComponent(pid)+'/panel/defaults','PUT',{config_profile_uuid:$('project-config-profile').value,active_inbounds:chosen,country_code:$('project-country').value.toUpperCase().trim()});
 toast('Config Profile и inbound-ы сохранены для этого проекта');await fetchProjects();$('project-sync-msg').textContent='Параметры сохранены. Новые ноды будут регистрироваться автоматически.'}
 catch(e){$('project-sync-msg').textContent=errorText(e)}
};
$('profile-form').onsubmit=async e=>{e.preventDefault();const id=$('profile-id').value;const settings={port:Number($('profile-port').value),site:$('profile-site').value,logs:$('profile-logs').value,udp_idle_timeout:Number($('profile-udp').value),xhttp_path:$('profile-xhttp-path').value,bbr:$('profile-bbr').checked,fail2ban:$('profile-fail2ban').checked};const panelProfile=$('profile-panel-config-profile').value;if(panelProfile){settings.panel_config_profile_uuid=panelProfile;settings.panel_active_inbounds=[...document.querySelectorAll('.profile-panel-inbound:checked')].map(i=>i.value);if(!settings.panel_active_inbounds.length)return toast('Выбери inbound-ы шаблона Remnawave')}const payload={name:$('profile-name').value.trim(),mode:$('profile-mode').value,transport:$('profile-transport').value,settings};try{await api(id?'/profiles/'+encodeURIComponent(id):'/projects/'+encodeURIComponent($('profile-project').value)+'/profiles',id?'PUT':'POST',payload);resetProfileForm();await loadProfilesUI();toast('Шаблон сохранён · существующие ноды не изменены')}catch(err){toast(errorText(err))}};
$('profile-preview-btn').onclick=async()=>{const id=$('profile-id').value;if(!id){toast('Сначала открой сохранённый шаблон на редактирование');return}try{const d=await api('/profiles/'+encodeURIComponent(id)+'/preview?domain='+encodeURIComponent($('profile-preview-domain').value.trim()));$('profile-preview-result').textContent=JSON.stringify(d,null,2)}catch(e){toast(errorText(e))}};
async function refreshWizardProjects(){const pid=$('wizard-project').value;await fetchProjects();fillProjectSelect('wizard-project',pid);await wizardProjectChange()}
async function wizardProjectChange(){const pid=$('wizard-project').value;profilesCache=await api('/projects/'+encodeURIComponent(pid)+'/profiles');$('wizard-profile').innerHTML=profilesCache.map(p=>`<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)} (${escapeHtml(p.transport)})</option>`).join('');wizardProfileChange()}
function wizardProfileChange(){const p=profilesCache.find(x=>x.id===$('wizard-profile').value);if(!p)return;const radio=document.querySelector(`input[name="preset"][value="${p.mode}"]`);if(radio)radio.checked=true;onPresetChange();$('wizard-profile-hint').textContent=`${p.name} · ${p.transport} · шаблон v${p.revision}. В Remnawave будет выбран конфигурационный профиль и inbound-ы проекта. Сам JSON Xray не переписывается.`;$('wizard-panel-ip-field').classList.add('hidden');$('wizard-secret-field').classList.add('hidden');const project=projectCache.find(x=>x.id===$('wizard-project').value);$('wizard-country').value=project?.panel_country_code||'XX';$('wizard-dns-egress').checked=false;$('wizard-dns-egress-field').classList.toggle('hidden',!!project?.panel_ip)}
$('wizard-project').onchange=()=>wizardProjectChange().catch(e=>toast(errorText(e)));
$('wizard-profile').onchange=wizardProfileChange;

const presets={full:{name:'Полная XPPN-нода',parts:['Docker','XPPN Agent','Remnawave','Nginx','SSL','Fail2Ban']},node:{name:'Remnawave Node',parts:['Docker','XPPN Agent','Remnawave','Firewall']},agent:{name:'Только управление',parts:['Docker','XPPN Agent']}};
const preset=()=>document.querySelector('input[name="preset"]:checked')?.value||'full';
function onPresetChange(){document.querySelectorAll('.preset').forEach(el=>el.classList.toggle('active',el.querySelector('input').checked));$('preset-components').innerHTML=presets[preset()].parts.map(x=>`<span class="chip">${escapeHtml(x)}</span>`).join('');$('preset-config').classList.toggle('hidden',preset()==='agent');$('agent-info').classList.toggle('hidden',preset()!=='agent');$('domain-field').classList.toggle('hidden',preset()!=='full');$('logs-preset-field').classList.toggle('hidden',preset()!=='full');$('confirm-clean-label').classList.toggle('hidden',preset()!=='full');$('wizard-country-field').classList.toggle('hidden',preset()==='agent');$('wizard-dns-egress-field').classList.toggle('hidden',preset()==='agent'||!!projectCache.find(x=>x.id===$('wizard-project').value)?.panel_ip)}
document.querySelectorAll('input[name="preset"]').forEach(e=>e.onchange=()=>{const match=profilesCache.find(p=>p.mode===preset());if(match)$('wizard-profile').value=match.id;wizardProfileChange()});onPresetChange();
function setWizardStep(n){wizardStep=n;for(let i=1;i<=3;i++)$('wizard-'+i).classList.toggle('hidden',i!==n);document.querySelectorAll('[data-step-label]').forEach(el=>el.classList.toggle('active',Number(el.dataset.stepLabel)===n));$('wizard-back').classList.toggle('hidden',n===1);$('wizard-next').classList.toggle('hidden',n===3);$('enroll-btn').classList.toggle('hidden',n!==3)}
$('wizard-back').onclick=()=>setWizardStep(Math.max(1,wizardStep-1));
function validateWizard(){for(const id of ['server-name','server-ip','server-port','server-password']){if(!$((id)).value.trim())throw Error('Заполни обязательные поля IP, название, порт и пароль')}const port=Number($('server-port').value);if(!(port>0&&port<65536))throw Error('Неверный SSH-порт');if(preset()!=='agent'){if(!/^\d+\.\d+\.\d+$/.test($('wizard-version').value.trim()))throw Error('Версия должна выглядеть как 3.4.2');const pj=projectCache.find(x=>x.id===$('wizard-project').value);const tmpl=profilesCache.find(x=>x.id===$('wizard-profile').value);if(!tmpl?.settings?.panel_config_profile_uuid&&(!pj?.panel_config_profile_uuid||!pj.panel_active_inbounds?.length))throw Error('В настройках проекта или шаблона выбери Config Profile и inbound-ы');if(!pj.panel_ip&&!$('wizard-dns-egress').checked)throw Error('Укажи исходящий IPv4 панели в проекте или подтверди использование DNS A-записи');if(!/^[A-Z]{2}$/.test($('wizard-country').value.toUpperCase().trim()))throw Error('Страна: две буквы, например NL')}if(preset()==='full'){if(!$('wizard-domain').value.trim())throw Error('Укажи домен ноды');if(!$('confirm-clean').checked)throw Error('Подтверди, что VPS чистый')}}
$('wizard-next').onclick=()=>{if(wizardStep===2){try{validateWizard()}catch(e){toast(errorText(e));return}$('review-server').textContent=$('server-name').value.trim()+' · '+$('server-ip').value.trim()+':'+$('server-port').value;$('review-preset').textContent=presets[preset()].name;$('review-details').textContent=preset()==='agent'?'Установка только агента':$('wizard-version').value.trim()+(preset()==='full'?' · '+$('wizard-domain').value.trim():'');expectedFingerprint='';$('fingerprint-box').classList.add('hidden');$('enroll-btn').disabled=true}setWizardStep(Math.min(3,wizardStep+1))};
let fingerprintTarget='';
$('probe-btn').onclick=async()=>{const b=$('probe-btn');b.disabled=true;b.textContent='Проверяем SSH…';try{const ip=$('server-ip').value.trim(),port=Number($('server-port').value);const d=await api('/ssh/probe','POST',{ip,port});expectedFingerprint=d.fingerprint;fingerprintTarget=ip+':'+port;$('fingerprint').textContent=d.fingerprint;$('fingerprint-confirm').checked=false;$('fingerprint-box').classList.remove('hidden');$('enroll-msg').textContent='';fingerprintCheck()}catch(e){$('enroll-msg').textContent=errorText(e)}finally{b.disabled=false;b.textContent='Повторно проверить SSH-ключ'}};
function fingerprintCheck(){$('enroll-btn').disabled=!($('fingerprint-confirm').checked&&fingerprintTarget===$('server-ip').value.trim()+':'+$('server-port').value)}$('fingerprint-confirm').onchange=fingerprintCheck;['server-ip','server-port'].forEach(id=>$(id).addEventListener('input',()=>{expectedFingerprint='';fingerprintCheck()}));
$('enroll-form').onsubmit=async e=>{e.preventDefault();if(wizardStep!==3||$('enroll-btn').disabled)return;const p=preset();const body={name:$('server-name').value.trim(),ip:$('server-ip').value.trim(),port:Number($('server-port').value),password:$('server-password').value,fingerprint:expectedFingerprint,preset:p,project_id:$('wizard-project').value,profile_id:$('wizard-profile').value,version:$('wizard-version').value.trim(),panel_ip:$('wizard-panel-ip').value.trim(),secret_key:p==='agent'?'':$('wizard-secret').value,country_code:$('wizard-country').value.toUpperCase().trim(),confirm_panel_dns_as_egress:$('wizard-dns-egress').checked,domain:p==='full'?$('wizard-domain').value.trim():'',confirm_clean:p==='full'&&$('confirm-clean').checked,logs_preset:p==='full'?$('logs-preset').value:'standard'};$('enroll-btn').disabled=true;$('enroll-btn').textContent='Проверяем пароль SSH…';try{const r=await api('/ssh/enroll','POST',body);$('server-password').value='';$('wizard-secret').value='';toast('Подключение успешно, установка началась');await openNode(r.id)}catch(e){$('enroll-msg').textContent=errorText(e);fingerprintCheck()}finally{$('enroll-btn').textContent='Начать установку →'}};
function stopStream(){if(liveSource){liveSource.close();liveSource=null}}
function stopLiveLogs(){if(logPollTimer){clearInterval(logPollTimer);logPollTimer=null}}
async function openNode(id){stopStream();stopLiveLogs();selectedNode=id;selectedTab='components';showPage('detail');await refreshDetail();const r=nodesCache.find(x=>x.id===id);if(r?.stage!=='ready')startStream(id);else renderTab()}
async function refreshDetail(){nodesCache=await api('/nodes');const r=nodesCache.find(n=>n.id===selectedNode);if(!r)return;$('detail-name').textContent=r.name;$('detail-ip').textContent=r.ip+' · '+(managedCount(r)?managedCount(r)+' управляемых сервиса':'Только агент');$('detail-state').textContent=statusLabel(r);$('detail-state').className='state '+(r.stage==='ready'?(r.online?'':'off'):r.stage);$('installation-panel').classList.toggle('hidden',r.stage==='ready');$('ready-panel').classList.toggle('hidden',r.stage!=='ready');if(r.stage==='ready'){syncTabs(r);if(!$('tab-content').innerHTML.trim())renderTab();const m=r.telemetry||{};const stats=[['RAM свободна',fmtBytes((m.memory?.available_kb||0)*1024)],['Диск свободен',fmtBytes(m.disk?.free)],['Управляемые сервисы',managedCount(r)]];$('detail-metrics').innerHTML=stats.map(t=>`<div class="metric"><small>${t[0]}</small><strong>${t[1]}</strong></div>`).join('')}else{const state={installing:'Подключаемся и устанавливаем агент',waiting:'Ожидаем первого подключения агента',provisioning:'Устанавливаем выбранные сервисы',verifying:'Проверяем запущенные контейнеры',registering:'Создаём ноду в Remnawave',registration_failed:'Установка выполнена, регистрация в панели не удалась',failed:'Установка остановлена с ошибкой'};$('install-heading').textContent=state[r.stage]||'Подготовка VPS';$('install-state').textContent=r.stage.toUpperCase();$('install-state').className='state '+r.stage;$('install-description').textContent=['failed','registration_failed'].includes(r.stage)?r.error||'Подробности в журнале ниже':'Операции выполняются автоматически. Не закрывай VPS и не запускай установку повторно.';$('remove-failed').classList.toggle('hidden',!['failed'].includes(r.stage));$('retry-registration').classList.toggle('hidden',r.stage!=='registration_failed');const phases=['phase-ssh','phase-agent','phase-profile','phase-ready'];const n={installing:1,waiting:2,provisioning:2,verifying:3,registering:3,registration_failed:3,ready:4,failed:0}[r.stage];phases.forEach((id,i)=>{const el=$(id);el.classList.toggle('done',i<n);el.classList.toggle('current',i===n)})}}
function startStream(id){stopStream();logCursor=0;logText='';$('install-log').textContent='Ожидание событий…';const source=new EventSource('/api/nodes/'+encodeURIComponent(id)+'/install-stream?after=0');liveSource=source;source.addEventListener('log',e=>{if(selectedNode!==id)return;const data=JSON.parse(e.data);if(data.id<=logCursor)return;logCursor=data.id;logText+=new Date(data.ts*1000).toLocaleTimeString('ru-RU')+'  '+data.message+'\n';if(logText.length>130000)logText=logText.slice(-125000);const el=$('install-log');const stick=el.scrollHeight-el.scrollTop-el.clientHeight<80;el.textContent=logText;if(stick)el.scrollTop=el.scrollHeight});source.addEventListener('state',async e=>{if(selectedNode!==id)return;const state=JSON.parse(e.data);const current=nodesCache.find(n=>n.id===id);if(current&&current.stage!==state.stage){await refreshDetail();if(state.stage==='ready'){stopStream();renderTab();toast('Нода готова к управлению')}}});source.onerror=()=>{$('install-tail').textContent='Переподключаемся к журналу…'};source.onopen=()=>{$('install-tail').textContent='Подключено · события поступают в реальном времени'}}
$('retry-registration').onclick=async()=>{if(!confirm('Сначала убедись, что нода НЕ появилась в панели Remnawave. Повторить регистрацию без переустановки VPS?'))return;try{await api('/nodes/'+selectedNode+'/panel/retry','POST',{});toast('Повторяем регистрацию — смотри журнал')}catch(e){toast(errorText(e))}};
$('copy-install-log').onclick=()=>navigator.clipboard.writeText(logText).then(()=>toast('Журнал скопирован')).catch(()=>toast('Не удалось скопировать'));
$('remove-failed').onclick=async()=>{if(!confirm('Удалить неудачную запись? Это не удалит уже установленные компоненты с VPS.'))return;try{await api('/nodes/'+selectedNode,'DELETE');stopStream();showPage('servers');toast('Запись удалена')}catch(e){toast(errorText(e))}};
document.querySelectorAll('.tab').forEach(el=>el.onclick=()=>{stopLiveLogs();selectedTab=el.dataset.tab;renderTab()});
async function queue(command,payload={}){if(!selectedNode)throw Error('Сервер не выбран');const job=await api('/nodes/'+selectedNode+'/jobs','POST',{command,payload});return job.id}
function actionButton(label,command,payload,confirmText){return `<button class="btn secondary remote-action" data-cmd="${escapeHtml(command)}" data-payload="${escapeHtml(JSON.stringify(payload))}" data-confirm="${escapeHtml(confirmText||'')}">${escapeHtml(label)}</button>`}
function bindActions(){document.querySelectorAll('.remote-action').forEach(b=>{if(!isOnline(nodesCache.find(n=>n.id===selectedNode))){b.disabled=true;b.title='Агент не отвечает';}});document.querySelectorAll('.remote-action').forEach(b=>b.onclick=async()=>{const str=b.dataset.confirm;if(str&&!confirm(str))return;b.disabled=true;try{const jid=await queue(b.dataset.cmd,JSON.parse(b.dataset.payload));if(['docker.logs','status','network.status'].includes(b.dataset.cmd)){const j=await waitJob(jid);const old=$('tab-content').querySelector('.result-log');if(old)old.remove();const el=document.createElement('pre');el.className='log result-log';el.textContent=j.output||j.status;$('tab-content').append(el)}else toast('Задание запущено; результат во вкладке «Задания».')}catch(e){toast(errorText(e))}finally{b.disabled=false}})}
async function waitJob(id){for(let n=0;n<100;n++){const jobs=await api('/nodes/'+selectedNode+'/jobs');const j=jobs.find(x=>x.id===id);if(j&&['success','error'].includes(j.status)){if(j.status==='error')throw Error(j.output||'Ошибка выполнения');return j}await new Promise(r=>setTimeout(r,1000))}throw Error('Задание выполняется дольше ожидаемого — открой «Задания»')}
function startLiveLogs(){stopLiveLogs();let busy=false;const refresh=async()=>{if(busy||selectedTab!=='docker'||$('detail-page').classList.contains('hidden'))return;busy=true;try{const jid=await queue('docker.logs',{container:'remnanode'});const j=await waitJob(jid);const out=$('live-log-output');if(out)out.textContent=j.output||'(пусто)'}catch(e){const out=$('live-log-output');if(out)out.textContent=errorText(e)}finally{busy=false}};refresh();logPollTimer=setInterval(refresh,10000)}
function renderTab(){
 stopLiveLogs();
 const r=nodesCache.find(x=>x.id===selectedNode);if(!r)return;
 syncTabs(r);
 document.querySelectorAll('#detail-tabs .tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===selectedTab));
 const el=$('tab-content'),m=r.telemetry||{},inv=inventory(r),ready=isOnline(r);
 if(selectedTab==='overview'){
  el.innerHTML=`<div class="section-title"><div><h2>Обзор сервера</h2><p class="muted">Состояние определяется ответами агента, а не выбранным при установке шаблоном.</p></div></div>
   <div class="two-col"><div class="mini-card"><h3>Операционная система</h3><div class="kv"><span>Hostname</span><b>${escapeHtml(m.hostname||'—')}</b></div><div class="kv"><span>Нагрузка</span><b>${escapeHtml((m.loadavg||[]).map(v=>Number(v).toFixed(2)).join(' / ')||'—')}</b></div><div class="kv"><span>Диск доступен</span><b>${fmtBytes(m.disk?.free)}</b></div></div>
   <div class="mini-card"><h3>Обнаруженные компоненты</h3><div class="kv"><span>Управляющий агент</span>${componentBadge(inv.agent)}</div><div class="kv"><span>Remnawave Node</span>${componentBadge(inv.remnanode)}</div><div class="kv"><span>Nginx</span>${componentBadge(inv.nginx)}</div></div></div>
   <div class="action-row">${actionButton('↻ Обновить состояние','status',{})}<button id="show-components" class="btn primary">Установка и компоненты →</button></div>`;
  bindActions();$('show-components').onclick=()=>{selectedTab='components';renderTab()};
 }else if(selectedTab==='components'){
  const node=inv.remnanode||{},nginx=inv.nginx||{};
  const project=projectCache.find(p=>p.id===r.project_id);
  el.innerHTML=`<div class="section-title"><div><p class="eyebrow">УСТАНОВКА И КОНФИГУРАЦИЯ</p><h2>Компоненты сервера</h2><p class="muted">Добавляй сервисы постепенно. Доступные действия определяются по VPS, а не по старому пресету.</p></div></div>
  <div class="component-grid">
  <article class="component-card"><div class="component-top"><div class="component-symbol"><svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-activity"></use></svg></div>${componentBadge(inv.agent)}</div><h3>XPPN Agent</h3><p>Служба управления и мониторинга по защищённому каналу.</p><div class="component-footer"><span>Установлен при подключении VPS</span></div></article>
  <article class="component-card"><div class="component-top"><div class="component-symbol"><svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-server"></use></svg></div>${componentBadge(node)}</div><h3>Remnawave Node</h3><p>Docker-контейнер, соединение с панелью, обновления Xray.</p><div class="component-footer">${node.installed?`${node.container?escapeHtml(node.image):'Конфигурация обнаружена, контейнер отсутствует'}`:'<button id="component-install-node" class="btn primary">+ Установить ноду</button>'}</div></article>
  <article class="component-card"><div class="component-top"><div class="component-symbol"><svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-settings-2"></use></svg></div>${componentBadge(nginx)}</div><h3>TLS + Nginx fallback</h3><p>Сайт, сертификаты и веб-сервер. Настройка TLS-inbound выполняется в Remnawave.</p><div class="component-footer">${nginx.installed?'Nginx обнаружен на VPS':node.installed?'<span class="muted">Для существующей ноды — пока ручная миграция конфигов</span>':'<button id="component-install-full" class="btn secondary">+ Полный стек на чистом VPS</button>'}</div></article>
  <article class="component-card"><div class="component-top"><div class="component-symbol"><svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-shield-check"></use></svg></div><span class="soft-tag">Профиль панели</span></div><h3>Hysteria 2 / XHTTP / REALITY</h3><p>Это транспортные конфигурации Xray в Remnawave, а не отдельные контейнеры.</p><div class="component-footer">${node.installed?'<button id="component-profiles" class="btn secondary">Посмотреть привязку профилей</button>':'Сначала установи Remnawave Node'}</div></article>
  </div>
  <section id="component-install-box" class="subpanel hidden"><div class="section-title"><div><h3 id="component-install-title">Установить компонент</h3><p id="component-install-intro" class="muted"></p></div><button id="component-cancel" class="quiet-button">Закрыть ✕</button></div><div class="fields-grid"><label>Версия Remnawave<input id="component-version" value="3.4.2" placeholder="3.4.2"></label><label id="component-domain-group" class="hidden">Домен ноды<input id="component-domain" placeholder="de1.example.com" value="${escapeHtml(r.domain||'')}"></label><label id="component-profile-group" class="hidden">TLS-пресет проекта<select id="component-profile"></select></label></div><label id="component-clean-group" class="checkbox-row hidden"><input id="component-clean" type="checkbox">На VPS нет существующих Remnawave, Nginx, сторонних сервисов на нужных портах; я проверил DNS и сделал резервную копию</label><p class="hint">Secret Key и IP панели берутся из проекта «${escapeHtml(project?.name||'Основной')}». Firewall TCP 2222 настраивается по исходящему IP панели. При ошибке используй журнал задания — не переустанавливай весь VPS.</p><div class="action-row"><button id="component-confirm" class="btn primary">Запустить установку</button></div></section>
  ${!(r.telemetry?.capabilities||[]).length?`<div class="hint">На VPS работает старый агент без списка поддерживаемых функций. Обнови XPPN Agent локально через защищённый SSH перед изменением системных параметров.</div>`:""}<div class="subpanel"><h3>Аккуратная переустановка</h3><p class="muted">«Применить Compose» пересоздаёт контейнер Remnawave без удаления VPS. Полное удаление стека сейчас намеренно отключено: старые установки не имеют надёжной метки владения файлами. Для чистого развёртывания используй отдельный VPS или сначала согласуй план удаления конкретных компонентов.</p>${node.compose?actionButton('↻ Пересоздать Remnawave','node.deploy',{},'Пересоздать remnanode? Активные подключения временно прервутся.'):'<span class="soft-tag">Remnawave не установлен</span>'}</div>`;
  bindActions();bindComponentActions(r);
 }else if(selectedTab==='docker'){
  const containers=(m.containers||[]).filter(x=>['remnanode','nginx'].includes(String(x.Names||'').replace(/^\//,'')));
  el.innerHTML=`<div class="section-title"><div><h2>Контейнеры</h2><p class="muted">Только реально обнаруженные сервисы. XPPN Agent не останавливается из веб-панели.</p></div></div><div class="two-col">${containers.map(c=>`<article class="mini-card"><div class="component-top"><h3>${escapeHtml(c.Names)}</h3><span class="soft-tag ${String(c.State).toLowerCase()==='running'?'good':'caution'}">${escapeHtml(c.State||c.Status||'—')}</span></div><p class="muted">${escapeHtml(c.Image||'')}</p><div class="action-row">${actionButton('↻ Перезапуск','docker.action',{action:'restart',container:c.Names},'Перезапустить '+c.Names+'? Активные соединения могут оборваться.')}${actionButton('▶ Запустить','docker.action',{action:'start',container:c.Names})}${actionButton('■ Остановить','docker.action',{action:'stop',container:c.Names},'Остановить '+c.Names+'?')}${actionButton('Логи','docker.logs',{container:c.Names})}</div></article>`).join('')}</div>${containers.some(c=>c.Names==='remnanode')?`<div class="subpanel"><label class="checkbox-row"><input id="live-logs-toggle" type="checkbox">Показывать логи Remnawave с автообновлением каждые 10 секунд</label><pre id="live-log-output" class="log">Включи автообновление, чтобы увидеть новые записи.</pre></div>`:''}`;
  bindActions();if($('live-logs-toggle'))$('live-logs-toggle').onchange=e=>{if(e.target.checked)startLiveLogs();else stopLiveLogs()};
 }else if(selectedTab==='configs'){
  el.innerHTML='<h2>Центральный редактор конфигураций</h2><p class="muted">Копии файлов и история сохраняются на главном сервере. Для первой загрузки достаточно один раз синхронизировать файл с ноды.</p><button class="btn primary" id="open-global-configs">Открыть редактор</button>';
  $('open-global-configs').onclick=()=>showPage('configs');
 }else if(selectedTab==='logs'){
  el.innerHTML='<h2>Логи ноды</h2><p class="muted">Docker, Xray, Nginx, systemd и правила хранения логов.</p><button class="btn primary" id="open-global-logs">Открыть логи</button>';
  $('open-global-logs').onclick=()=>{showPage('logs');$('hub-log-node').value=selectedNode};
 }else if(selectedTab==='node'){
  el.innerHTML=`<div class="section-title"><div><h2>Remnawave Node</h2><p class="muted">Установлена на сервере. Управление работает через агента.</p></div>${componentBadge(inv.remnanode)}</div><div class="two-col"><div class="mini-card"><h3>Обновление ноды</h3><p class="muted">Изменяет только управляемый Compose и образ; перед обновлением сохраняется резервная копия.</p><label>Новая версия<input id="upgrade-version" value="3.4.2"></label><button class="btn primary" id="upgrade-btn">Обновить версию</button>${inv.remnanode.compose?`<div class="action-row">${actionButton('Применить Compose','node.deploy',{},'Пересоздать remnanode?')}</div>`:''}</div><div class="mini-card"><h3>Панель Remnawave</h3><p class="muted">${r.panel_node_uuid?'Нода зарегистрирована в панели. UUID: '+escapeHtml(r.panel_node_uuid):'Нода ещё не зарегистрирована в панели.'}</p><button class="btn secondary" id="panel-read-profiles" ${r.panel_node_uuid?'disabled':''}>${r.panel_node_uuid?'Уже зарегистрирована':'Выбрать inbound-ы и зарегистрировать'}</button><div id="panel-registration" class="hidden"><label>Config Profile<select id="panel-config-profile"></select></label><div id="panel-active-inbounds"></div><label>Страна<input id="panel-country" maxlength="2" placeholder="DE"></label><button id="panel-register-submit" class="btn primary">Зарегистрировать ноду</button></div><p id="panel-reg-result" class="muted"></p></div></div>${inv.nginx?.installed?`<div class="action-row">${actionButton('Продлить SSL','ssl.renew',{},'Запустить продление сертификатов?')}</div>`:''}`;
  bindActions();$('upgrade-btn').onclick=async()=>{const v=$('upgrade-version').value.trim();if(!/^\d+\.\d+\.\d+$/.test(v))return toast('Версия должна выглядеть как 3.4.2');if(!confirm('Обновить Remnawave Node? Возможен кратковременный обрыв VPN.'))return;try{const j=await queue('node.upgrade',{version:v});toast('Обновление запущено: смотри «Задания»');}catch(e){toast(errorText(e))}};bindPanelRegistration();
 }else if(selectedTab==='network'){
  el.innerHTML=`<h2>Сеть и безопасность</h2><p class="help">Команды безопасны для агент-only VPS. BBR влияет на TCP, но не управляет QUIC Hysteria 2.</p><div class="action-row">${actionButton('Проверить сеть, BBR и Fail2Ban','network.status',{})}${actionButton('Включить TCP BBR','network.bbr',{algorithm:'bbr'},'Изменить TCP congestion control для всего VPS?')}${actionButton('Вернуться к CUBIC','network.bbr',{algorithm:'cubic'},'Вернуть CUBIC для всего VPS?')}</div><div class="hint">Изменение правил Fail2Ban и Firewall отключено до реализации безопасного механизма отката при потере SSH.</div>`;bindActions();
 }else if(selectedTab==='jobs'){
  el.innerHTML=`<div class="section-title"><div><h2>История заданий</h2><p class="muted">Обновляется автоматически. Пароли, ключи и запросы установки не показываются.</p></div><span class="soft-tag">Live</span></div><div id="jobs-container"><p class="muted">Загрузка…</p></div>`;refreshJobs();
 }
}
function bindComponentActions(r){
 if(!isOnline(r)){document.querySelectorAll('#tab-content button').forEach(b=>b.disabled=true);return}
 let mode='';
 async function openInstall(m){mode=m;const box=$('component-install-box');box.classList.remove('hidden');$('component-install-title').textContent=m==='node'?'Добавить Remnawave Node':'Установить полный стек XPPN';$('component-install-intro').textContent=m==='node'?'Будет установлен только Remnawave Node; агент останется без изменений.':'Полная установка на VPS без Remnawave и Nginx. Сертификат, сайт и панель подключаются через старый установщик.';$('component-domain-group').classList.toggle('hidden',m!=='full');$('component-profile-group').classList.toggle('hidden',m!=='full');$('component-clean-group').classList.toggle('hidden',m!=='full');if(m==='full'){try{const list=await api('/projects/'+encodeURIComponent(r.project_id)+'/profiles');const candidates=list.filter(p=>p.mode==='full'&&p.transport==='tls-raw');$('component-profile').innerHTML=candidates.map(p=>`<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join('');if(!candidates.length){$('component-profile').innerHTML='<option value="">Создай TLS-шаблон проекта</option>';}}catch(e){toast(errorText(e))}}box.scrollIntoView({behavior:'smooth',block:'nearest'});}
 if($('component-install-node'))$('component-install-node').onclick=()=>openInstall('node');
 if($('component-install-full'))$('component-install-full').onclick=()=>openInstall('full');
 if($('component-cancel'))$('component-cancel').onclick=()=>$('component-install-box').classList.add('hidden');
 if($('component-profiles'))$('component-profiles').onclick=()=>{toast('Для Hysteria/XHTTP выбери совместимые inbound-ы в разделе «Проекты и шаблоны». Существующая нода не переключается автоматически: поддержка безопасного PATCH панели ещё не реализована.');};
 if($('component-confirm'))$('component-confirm').onclick=async()=>{
  const v=$('component-version').value.trim();if(!/^\d+\.\d+\.\d+$/.test(v))return toast('Укажи закреплённую версию, например 3.4.2');
  let command='project.node.install',payload={version:v};
  if(mode==='full'){
   const domain=$('component-domain').value.trim().toLowerCase();
   if(!/^[a-z0-9][a-z0-9.-]{2,250}$/.test(domain)||domain.includes('..')||domain.endsWith('.'))return toast('Укажи действительный домен');
   if(!$('component-clean').checked)return toast('Подтверди чистый VPS и резервную копию');
   command='project.stack.install';payload={version:v,domain,confirm_clean:true,profile_id:$('component-profile').value};if(!payload.profile_id)return toast('Нет TLS-пресета, открой «Проекты и шаблоны»');
  }
  if(!confirm('Запустить установку на '+r.name+'? Перед запуском убедись, что нет сторонних сервисов на нужных портах.'))return;
  const b=$('component-confirm');b.disabled=true;
  try{const job=await queue(command,payload);$('component-install-box').classList.add('hidden');selectedTab='jobs';renderTab();toast('Задание '+job+' поставлено в очередь. Результат появится в истории.')}
  catch(e){toast(errorText(e))}finally{b.disabled=false}
 };
}
async function refreshJobs(){if(selectedTab!=='jobs')return;try{const jobs=await api('/nodes/'+selectedNode+'/jobs');const root=$('jobs-container');if(!root)return;root.innerHTML=jobs.length?jobs.map(j=>{let output=j.output||'';if(j.command==='status'&&j.status==='success'){try{const v=JSON.parse(output);output=`Агент: ${v.hostname||'—'}; Контейнеров: ${(v.containers||[]).length}; Свободное место: ${fmtBytes(v.disk?.free)}`;}catch{output='Состояние обновлено'}}return `<div class="job"><div class="job-head"><strong>${escapeHtml(j.command)}</strong><span class="soft-tag ${j.status==='success'?'good':j.status==='error'?'danger':''}">${escapeHtml({success:'Успешно',error:'Ошибка',running:'Выполняется',queued:'Ожидает'}[j.status]||j.status)}</span></div><p><small>${new Date(j.created_at*1000).toLocaleString('ru-RU')}</small></p>${output?`<pre class="log">${escapeHtml(output)}</pre>`:''}</div>`}).join(''):'<div class="empty">Пока нет заданий</div>'}catch(e){toast(errorText(e))}}
function bindNodeActions(){const ver=$('upgrade-version'),upgrade=$('upgrade-btn');upgrade.onclick=async()=>{if(!/^\d+\.\d+\.\d+$/.test(ver.value.trim()))return toast('Неверная версия');if(!confirm('Обновить Remnawave до '+ver.value+'? На время пересоздания VPN-соединения будут прерваны.'))return;try{await queue('node.upgrade',{version:ver.value.trim()});toast('Обновление запущено — смотри вкладку Задания')}catch(e){toast(errorText(e))}};$('install-node').onclick=async()=>{const key=$('node-key').value,version=$('node-version').value.trim(),panel_ip=$('node-panel-ip').value.trim();if(!confirm('Установить новую Remnawave Node? Рабочие конфигурации перезаписаны не будут.'))return;try{await queue('node.install',{secret_key:key,version,panel_ip});$('node-key').value='';toast('Установка Remnawave запущена')}catch(e){toast(errorText(e))}};$('legacy-install').onclick=async()=>{const domain=$('legacy-domain').value.trim().toLowerCase(),secret_key=$('legacy-key').value,version=$('legacy-version').value.trim(),panel_ip=$('legacy-panel-ip').value.trim();if(!confirm('ОПАСНО: полная установка Nginx, SSL, Docker и Remnawave на ЧИСТЫЙ VPS. Продолжить?'))return;try{await queue('legacy.install',{domain,secret_key,version,panel_ip,confirm_clean:true});$('legacy-key').value='';toast('Полная установка запущена — следи за результатом в заданиях')}catch(e){toast(errorText(e))}}}


let remotePanelProfiles=[];
function bindPanelRegistration(){
 const node=nodesCache.find(n=>n.id===selectedNode);
 if(node?.panel_node_uuid){$('panel-reg-result').textContent='Зарегистрирована в панели: '+node.panel_node_uuid; $('panel-read-profiles').disabled=true;return}
 $('panel-read-profiles').onclick=async()=>{try{
  remotePanelProfiles=await api('/projects/'+encodeURIComponent(node.project_id)+'/panel/profiles');
  if(!remotePanelProfiles.length)throw Error('В панели нет доступных конфигурационных профилей');
  $('panel-registration').classList.remove('hidden');
  $('panel-config-profile').innerHTML=remotePanelProfiles.map(p=>`<option value="${escapeHtml(p.uuid)}">${escapeHtml(p.name||p.uuid)}</option>`).join('');
  const updateInboundChecks=()=>{const p=remotePanelProfiles.find(x=>x.uuid===$('panel-config-profile').value);$('panel-active-inbounds').innerHTML=p?.inbounds?.map(i=>`<label class="checkbox-row"><input type="checkbox" class="panel-inbound" value="${escapeHtml(i.uuid)}">${escapeHtml(i.tag||i.uuid)}</label>`).join('')||'В профиле нет inbound-ов'};
  $('panel-config-profile').onchange=updateInboundChecks;updateInboundChecks();
 }catch(e){toast(errorText(e))}};
 $('panel-register-submit').onclick=async()=>{
  const chosen=[...document.querySelectorAll('.panel-inbound:checked')].map(i=>i.value);
  if(!chosen.length)return toast('Выбери хотя бы один inbound');
  const country=$('panel-country').value.trim().toUpperCase();
  const p=remotePanelProfiles.find(p=>p.uuid===$('panel-config-profile').value);
  if(!/^[A-Z]{2}$/.test(country))return toast('Укажи код страны: DE, NL, RU и т.д.');
  if(!confirm(`Создать в Remnawave новую ноду «${node.name}» с профилем «${p?.name}» и ${chosen.length} inbound(ами)?`))return;
  const b=$('panel-register-submit');b.disabled=true;
  try{const res=await api('/nodes/'+encodeURIComponent(selectedNode)+'/panel/register','POST',{config_profile_uuid:p.uuid,active_inbounds:chosen,country_code:country});$('panel-reg-result').textContent='Нода зарегистрирована: '+res.panel_node_uuid;toast('Remnawave Node зарегистрирована');await refreshDetail();renderTab()}
  catch(e){toast(errorText(e))}finally{b.disabled=false}
 };
}


async function loadSettings(){const s=await api('/settings/status');$('hub-settings-user').value=s.username;$('hub-settings-status').textContent=`Копий базы: ${s.backup_count} · Последняя: ${s.latest_backup||'пока нет'}\nTelegram: ${s.telegram_configured?'настроен':'отключён'} · GitHub-обновления: ${s.updates_enabled?'настроены':'отключены'}\nСрок сессии: ${s.session_days} дней · История метрик: ${s.history_days} дней`}
$('hub-settings-refresh').onclick=()=>loadSettings().catch(e=>toast(errorText(e)));
$('hub-settings-backup').onclick=async()=>{try{const r=await api('/settings/backup','POST',{});toast('Создана копия '+r.backup);await loadSettings()}catch(e){toast(errorText(e))}};
$('hub-settings-credentials').onsubmit=async e=>{e.preventDefault();if(!confirm('Изменить логин и пароль доступа к XPPN Manager?'))return;try{await api('/settings/credentials','POST',{username:$('hub-settings-user').value.trim(),current_password:$('hub-settings-current').value,new_password:$('hub-settings-new').value});$('hub-settings-current').value='';$('hub-settings-new').value='';toast('Логин и пароль обновлены')}catch(e){toast(errorText(e))}};
// v1.5 infrastructure workspace
let logCenterActive=false,logCenterLoading=false,storedRevision=0,configCenterLoading=false;
const hubNodeOptions=()=>nodesCache.map(n=>`<option value="${escapeHtml(n.id)}">${escapeHtml(n.name)} · ${escapeHtml(n.ip)}</option>`).join('');
async function ensureHubNodes(){if(!nodesCache.length)await loadNodes();for(const id of ['hub-log-node','hub-config-node']){const el=$(id),old=el.value;el.innerHTML=hubNodeOptions();if(nodesCache.some(n=>n.id===old))el.value=old;else if(nodesCache.some(n=>n.id===selectedNode))el.value=selectedNode}}
function percent(n){return Math.min(100,Math.max(0,Math.round(n||0)))}
async function loadOverview(){await loadNodes();const online=nodesCache.filter(n=>n.online&&n.stage==='ready').length;const bad=nodesCache.filter(n=>n.stage==='failed'||n.stage==='registration_failed'||(n.stage==='ready'&&!n.online)).length;const all=nodesCache.length;$('overview-stats').innerHTML=[['Всего нод',all],['Онлайн',online],['Требуют внимания',bad]].map(([label,val])=>`<div class="stat"><small>${label}</small><div class="num">${val}</div></div>`).join('');$('overview-list').innerHTML=nodesCache.map(n=>`<button class="hub-node-row" data-open-node="${escapeHtml(n.id)}"><strong>${escapeHtml(n.name)}</strong><small>${escapeHtml(n.ip)} · ${escapeHtml(statusLabel(n))}</small><span class="state ${n.online?'':'off'}">${n.online?'Онлайн':'Офлайн'}</span></button>`).join('')||'<p class="muted">Нод пока нет.</p>';document.querySelectorAll('[data-open-node]').forEach(b=>b.onclick=()=>openNode(b.dataset.openNode))}
function sparkline(values,color='currentColor'){if(!values.length)return '<p class="muted">История пока не накоплена</p>';const arr=values.filter(x=>Number.isFinite(x));if(!arr.length)return '<p class="muted">Нет данных</p>';const min=0,max=100;const pts=arr.map((v,i)=>`${(i*280/Math.max(1,arr.length-1)).toFixed(1)},${(64-(Math.min(max,Math.max(min,v))-min)/(max-min)*56).toFixed(1)}`).join(' ');return `<svg class="monitor-spark" viewBox="0 0 280 70" preserveAspectRatio="none" role="img" aria-label="История использования CPU"><polyline fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" points="${pts}"></polyline></svg>`}
async function loadMonitoring(){await loadNodes();const period=Number($('hub-monitor-period').value)||24;const history=await Promise.all(nodesCache.map(n=>api('/nodes/'+encodeURIComponent(n.id)+'/metrics?hours='+period).catch(()=>[])));$('monitoring-list').innerHTML=nodesCache.map((n,i)=>{const t=n.telemetry||{},mem=t.memory||{},disk=t.disk||{},hist=history[i]||[];const mu=mem.total_kb?(mem.total_kb-mem.available_kb)*100/mem.total_kb:0,du=disk.total?(disk.total-disk.free)*100/disk.total:0;return `<article class="mini-card monitor-card"><div class="component-top"><h3>${escapeHtml(n.name)}</h3><span class="state ${n.online?'':'off'}">${n.online?'Онлайн':'Офлайн'}</span></div><p class="muted">${escapeHtml(n.ip)} · ${escapeHtml(t.hostname||'—')}</p><div class="kv"><span>Load average</span><strong>${escapeHtml((t.loadavg||[]).map(x=>Number(x).toFixed(2)).join(' · ')||'—')}</strong></div><div class="kv"><span>CPU сейчас</span><strong>${t.cpu_percent===undefined?'—':percent(t.cpu_percent)+'%'}</strong></div>${sparkline(hist.map(x=>Number(x.cpu_percent)), '#a4f4bc')}<div class="kv"><span>RAM</span><strong>${percent(mu)}%</strong></div><div class="meter"><span style="width:${percent(mu)}%"></span></div><div class="kv"><span>Диск</span><strong>${percent(du)}%</strong></div><div class="meter"><span style="width:${percent(du)}%"></span></div><div class="kv"><span>Свободно</span><strong>${fmtBytes(disk.free)}</strong></div><p class="muted">Измерений за период: ${hist.length}</p></article>`}).join('')||'<p class="muted">Нет данных.</p>'}
$('hub-monitor-period').onchange=()=>loadMonitoring().catch(e=>toast(errorText(e)));
async function loadLogCenter(){await ensureHubNodes();}
async function fetchLogs(){if(logCenterLoading)return;const id=$('hub-log-node').value;if(!id)return toast('Выбери ноду');logCenterLoading=true;try{const jid=(await api('/nodes/'+encodeURIComponent(id)+'/jobs','POST',{command:'logs.read',payload:{source:$('hub-log-source').value,lines:Number($('hub-log-lines').value)}})).id;let response=await waitNodeJob(id,jid,50);$('hub-log-content').textContent=response.output||'Нет записей.'}catch(e){$('hub-log-content').textContent=errorText(e)}finally{logCenterLoading=false}}
async function waitNodeJob(id,jid,limit=90){for(let i=0;i<limit;i++){const jobs=await api('/nodes/'+encodeURIComponent(id)+'/jobs');const j=jobs.find(v=>v.id===jid);if(j&&['success','error'].includes(j.status)){if(j.status==='error')throw Error(j.output||'Ошибка задания');return j}await new Promise(r=>setTimeout(r,1000))}throw Error('Команда выполняется дольше ожидаемого: проверь историю заданий')}
$('hub-log-batch').onclick=async()=>{await ensureHubNodes();const candidates=nodesCache.filter(n=>n.online&&n.stage==='ready'&&(n.telemetry?.capabilities||[]).includes('logs.policy'));if(!candidates.length)return toast('Нет доступных нод с новым агентом');if(!confirm(`Применить политику ${$('hub-log-preset').value} на ${candidates.length} нодах?`))return;try{const result=await api('/nodes/batch/log-policy','POST',{node_ids:candidates.map(n=>n.id),preset:$('hub-log-preset').value});const queued=result.results.filter(r=>r.status==='queued').length;const failed=result.results.filter(r=>r.status!=='queued').length;toast(`Заданий поставлено: ${queued}; пропущено: ${failed}`);$('hub-log-content').textContent=result.results.map(r=>`${r.name||r.node_id}: ${r.status}${r.reason?' ('+r.reason+')':''}`).join('\n')}catch(e){toast(errorText(e))}};
$('hub-log-load').onclick=fetchLogs;$('hub-log-copy').onclick=()=>navigator.clipboard?.writeText($('hub-log-content').textContent).then(()=>toast('Скопировано')).catch(()=>toast('Не удалось скопировать'));
$('hub-log-policy').onclick=async()=>{const id=$('hub-log-node').value;if(!id||!confirm('Настроить автоматическую ротацию Xray и Nginx на этой ноде?'))return;try{const j=await api('/nodes/'+encodeURIComponent(id)+'/jobs','POST',{command:'logs.policy',payload:{preset:$('hub-log-preset').value}});toast('Настройка отправлена, задача '+j.id);await waitNodeJob(id,j.id);toast('Ротация файлов настроена')}catch(e){toast(errorText(e))}};
setInterval(()=>{if(logCenterActive&&$('hub-log-auto').checked&&!document.hidden)fetchLogs()},10000);
async function loadConfigCenter(){await ensureHubNodes();await loadStoredConfig()}
$('hub-config-node').onchange=()=>loadStoredConfig().catch(e=>toast(errorText(e)));
$('hub-config-name').onchange=()=>loadStoredConfig().catch(e=>toast(errorText(e)));
$('hub-config-load').onclick=()=>loadStoredConfig().catch(e=>toast(errorText(e)));
const configUrl=()=>'/nodes/'+encodeURIComponent($('hub-config-node').value)+'/configs/'+encodeURIComponent($('hub-config-name').value);
async function loadStoredConfig(){if(configCenterLoading)return;configCenterLoading=true;try{const data=await api(configUrl());storedRevision=data.revision;$('hub-config-text').value=data.content;$('hub-config-editor').classList.remove('hidden');$('hub-config-state').textContent=`Версия ${data.revision} · ${data.status} · SHA256 на ноде: ${data.remote_sha.slice(0,16)}…`;
const hist=await api(configUrl()+'/history');$('hub-config-history').innerHTML=hist.map(v=>`<button class="btn secondary sm config-restore" data-revision="${v.revision}">v${v.revision} · ${new Date(v.created_at*1000).toLocaleString('ru-RU')}</button>`).join(' ')||'<p class="muted">Пока нет версий.</p>';document.querySelectorAll('.config-restore').forEach(b=>b.onclick=async()=>{if(!confirm('Восстановить версию '+b.dataset.revision+' в новый черновик?'))return;try{await api(configUrl()+'/restore/'+b.dataset.revision,'POST',{});await loadStoredConfig();toast('Черновик восстановлен')}catch(e){toast(errorText(e))}})}catch(e){$('hub-config-state').textContent=errorText(e)+' · При первом открытии нажми «Первичная загрузка». ';$('hub-config-editor').classList.add('hidden')}finally{configCenterLoading=false}}
$('hub-config-import').onclick=async()=>{if(!confirm('Считать файл с VPS и обновить центральную копию? Несохранённый черновик импортировать нельзя.'))return;try{const j=await api(configUrl()+'/import','POST',{});$('hub-config-state').textContent='Считываем файл с ноды…';await waitNodeJob($('hub-config-node').value,j.id);await loadStoredConfig();toast('Файл загружен в центральное хранилище')}catch(e){toast(errorText(e))}};
$('hub-config-save').onclick=async()=>{try{const res=await api(configUrl(),'PUT',{content:$('hub-config-text').value,revision:storedRevision});storedRevision=res.revision;toast('Черновик сохранён в главной панели');await loadStoredConfig()}catch(e){toast(errorText(e))}};
$('hub-config-apply').onclick=async()=>{if(!confirm('Применить сохранённую конфигурацию? Docker Compose может перезапустить VPN-соединения. Сначала сохрани черновик.'))return;try{const j=await api(configUrl()+'/apply','POST',{});$('hub-config-state').textContent='Применяем на ноде…';await waitNodeJob($('hub-config-node').value,j.id,180);await loadStoredConfig();toast('Конфигурация применена и проверена')}catch(e){toast(errorText(e));await loadStoredConfig()}};
async function loadUpdateStatus(){try{const s=await api('/updates/status');$('hub-updates-status').textContent=`${s.enabled?'Обновления доступны':'Обновления не настроены'} · ${s.status||'нет операций'} · ${s.detail||''}`;$('hub-updates-run').disabled=!s.enabled}catch(e){$('hub-updates-run').disabled=true;$('hub-updates-status').textContent=errorText(e)}}
$('hub-updates-refresh').onclick=loadUpdateStatus;
$('hub-updates-run').onclick=async()=>{if(!confirm('Обновить главный сервер из настроенного GitHub? На время пересборки панель может быть недоступна, конфигурации и данные сохраняются.'))return;try{await api('/updates/request','POST',{});toast('Обновление поставлено в очередь');await loadUpdateStatus()}catch(e){toast(errorText(e))}};
$('hub-monitor-refresh').onclick=()=>loadMonitoring().catch(e=>toast(errorText(e)));
setInterval(()=>{if(csrf&&selectedNode&&!$('detail-page').classList.contains('hidden')){refreshDetail().catch(()=>{});if(selectedTab==='jobs')refreshJobs();else if(selectedTab==='components' && $('component-install-box')?.classList.contains('hidden'))renderTab()}},7000);
init().catch(e=>{authUI(true);$('login-error').textContent=errorText(e)});


/* v1.6.1 browser configuration workspace */
let configFetchSerial = 0;
let configDirty = false;
let configBaseline = '';
let configLastSelection = {node:'', name:''};
const configFiles = {nginx:'nginx.conf',nginx_compose:'nginx / docker-compose.yml',node_compose:'remnanode / docker-compose.yml'};
function configStatus(message,kind) {
  $('hub-config-state').textContent=message;
  $('hub-config-pill').textContent=kind==='ready'?'Открыт':kind==='dirty'?'Есть изменения':kind==='saving'?'Загрузка':kind==='error'?'Недоступен':'Не загружен';
  $('hub-config-pill').dataset.kind=kind||'empty';
}
function configEmpty(title,description,canImport) {
  $('hub-config-editor').classList.add('hidden');
  $('hub-config-empty').classList.remove('hidden');
  $('hub-config-empty-title').textContent=title;
  $('hub-config-empty-description').textContent=description;
  $('hub-config-empty-action').disabled=!canImport;
  $('hub-config-import').disabled=!canImport;
}
function configCanImport(node,name) {
  return !!(node && node.online && node.stage==='ready' && node.components && node.components.configs && node.components.configs[name]);
}
function configResetDirty() {
  configDirty=false;
  configBaseline=$('hub-config-text').value;
  $('hub-config-dirty').textContent='Изменений нет';
  $('hub-config-save').disabled=true;
  $('hub-config-apply').disabled=false;
}
function configEditChanged() {
  configDirty=$('hub-config-text').value!==configBaseline;
  $('hub-config-dirty').textContent=configDirty?'● Несохранённые изменения':'Изменений нет';
  $('hub-config-save').disabled=!configDirty;
  $('hub-config-apply').disabled=configDirty;
  $('hub-config-lines').textContent='Строк: '+($('hub-config-text').value.split('\n').length);
  if(configDirty)configStatus('Редактирование в браузере · нажми «Сохранить черновик», затем «Применить к ноде».','dirty');
}
$('hub-config-text').addEventListener('input',configEditChanged);
$('hub-config-text').addEventListener('keydown',e=>{
  if(e.key==='Tab'){e.preventDefault();const el=e.target,a=el.selectionStart,b=el.selectionEnd;el.setRangeText('  ',a,b,'end');configEditChanged();}
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();$('hub-config-save').click();}
});
window.addEventListener('beforeunload',e=>{if(configDirty){e.preventDefault();e.returnValue='';}});
function configSelectionChanged() {
  if(configDirty&&!confirm('Несохранённые изменения будут потеряны. Перейти к другому файлу?')){
    $('hub-config-node').value=configLastSelection.node;
    $('hub-config-name').value=configLastSelection.name;
    return;
  }
  configDirty=false;
  loadStoredConfig().catch(e=>toast(errorText(e)));
}
$('hub-config-node').onchange=configSelectionChanged;
$('hub-config-name').onchange=configSelectionChanged;
$('hub-config-load').onclick=()=>{if(configDirty&&!confirm('Отменить несохранённые изменения и загрузить файл заново?'))return;loadStoredConfig().catch(e=>toast(errorText(e)));};
loadConfigCenter=async function(){
  await ensureHubNodes();
  if(selectedNode && nodesCache.some(n=>n.id===selectedNode)) $('hub-config-node').value=selectedNode;
  const selected=nodesCache.find(n=>n.id===$('hub-config-node').value);
  if(selected && selected.components && selected.components.configs){
    const files=selected.components.configs;
    if(!files[$('hub-config-name').value]){
      const found=['nginx','nginx_compose','node_compose'].find(k=>files[k]);
      if(found)$('hub-config-name').value=found;
    }
  }
  await loadStoredConfig();
};
loadStoredConfig=async function(){
  const serial=++configFetchSerial;
  const id=$('hub-config-node').value,name=$('hub-config-name').value;
  const node=nodesCache.find(n=>n.id===id);
  const canImport=configCanImport(node,name);
  $('hub-config-filename').textContent=configFiles[name]||name;
  $('hub-config-import').disabled=!canImport;
  configLastSelection={node:id,name};
  configEmpty('Открываем файл','Проверяем сохранённую копию конфигурации.',canImport);
  if(!id){
    configStatus('Нет подключённых нод. Добавь VPS во вкладке «Ноды».','empty');
    configEmpty('Нет подключённых нод','Сначала подключи сервер к XPPN Manager.',false);
    return;
  }
  configStatus('Загружаем конфигурацию…','saving');
  const url='/nodes/'+encodeURIComponent(id)+'/configs/'+encodeURIComponent(name);
  let snapshot;
  try{
    try{snapshot=await api(url);}
    catch(e){
      if(!String(e.message||e).includes('Import config from node once first'))throw e;
      if(!canImport){
        const hint=node && !node.online?'Нода сейчас не на связи. Дождись подключения агента.':
          node && !(node.telemetry?.capabilities||[]).includes('config.read')?'Установлена старая версия агента. Обнови XPPN Agent для работы с конфигами.':
          'Этот файл не найден на выбранной ноде. Выбери другой конфиг.';
        configStatus(hint,'empty');
        configEmpty('Файл пока недоступен',hint,false);
        return;
      }
      configStatus('Первое открытие: считываем файл с VPS. Это только чтение, работа VPN не прервётся.','saving');
      const job=await api(url+'/import','POST',{});
      await waitNodeJob(id,job.id,100);
      if(serial!==configFetchSerial)return;
      snapshot=await api(url);
    }
    if(serial!==configFetchSerial)return;
    storedRevision=snapshot.revision;
    $('hub-config-text').value=snapshot.content||'';
    $('hub-config-empty').classList.add('hidden');
    $('hub-config-editor').classList.remove('hidden');
    configResetDirty();
    $('hub-config-lines').textContent='Строк: '+($('hub-config-text').value.split('\n').length);
    const state=snapshot.status==='draft'?'Черновик сохранён, ещё не применён':snapshot.status==='synced'?'Синхронизировано с нодой':'Состояние: '+snapshot.status;
    configStatus('Версия '+snapshot.revision+' · '+state+'. Изменения можно делать прямо в поле ниже.','ready');
    const history=await api(url+'/history');
    if(serial!==configFetchSerial)return;
    $('hub-config-history').innerHTML=history.map(v=>'<button class="btn secondary sm config-restore" data-revision="'+v.revision+'">Версия '+v.revision+' · '+new Date(v.created_at*1000).toLocaleString('ru-RU')+'</button>').join(' ')||'<p class="muted">История пока пустая.</p>';
    document.querySelectorAll('#hub-config-history .config-restore').forEach(button=>button.onclick=async()=>{
      if(configDirty&&!confirm('Отменить несохранённые изменения?'))return;
      if(!confirm('Восстановить версию '+button.dataset.revision+' в новый черновик?'))return;
      try{await api(url+'/restore/'+button.dataset.revision,'POST',{});await loadStoredConfig();toast('История восстановлена в новый черновик')}catch(e){toast(errorText(e));}
    });
  }catch(e){
    if(serial!==configFetchSerial)return;
    const msg=errorText(e);
    configStatus('Не удалось открыть конфиг: '+msg,'error');
    configEmpty('Не удалось открыть файл',canImport?'Попробуй «Считать с ноды». Если ошибка повторится, проверь агент на VPS.':msg,canImport);
  }
};
$('hub-config-empty-action').onclick=()=>$('hub-config-import').click();
$('hub-config-import').onclick=async()=>{
  const id=$('hub-config-node').value,name=$('hub-config-name').value;
  const node=nodesCache.find(n=>n.id===id);
  if(!configCanImport(node,name))return toast('Файл не обнаружен или нода недоступна.');
  if(configDirty&&!confirm('Есть несохранённые изменения. Отменить их и считать файл заново?'))return;
  if(!confirm('Считать актуальный файл с ноды? Сохранённый черновик при этом может препятствовать импорту.'))return;
  const btn=$('hub-config-import');btn.disabled=true;
  try{
    const url=configUrl();
    configStatus('Считываем конфигурацию с ноды…','saving');
    const j=await api(url+'/import','POST',{});
    await waitNodeJob(id,j.id,100);
    await loadStoredConfig();
    toast('Файл загружен в редактор');
  }catch(e){toast(errorText(e));configStatus(errorText(e),'error')}finally{btn.disabled=false;}
};
$('hub-config-save').onclick=async()=>{
  if(!configDirty)return;
  const btn=$('hub-config-save');btn.disabled=true;
  try{
    const r=await api(configUrl(),'PUT',{content:$('hub-config-text').value,revision:storedRevision});
    storedRevision=r.revision;
    await loadStoredConfig();
    toast('Черновик сохранён. Нода ещё не изменена.');
  }catch(e){btn.disabled=false;toast(errorText(e));}
};
$('hub-config-apply').onclick=async()=>{
  if(configDirty)return toast('Сначала сохрани изменения в черновик');
  if(!confirm('Применить сохранённый файл к выбранной ноде? Сервис может перезапуститься, активные VPN-подключения могут прерваться.'))return;
  const btn=$('hub-config-apply');btn.disabled=true;
  try{
    configStatus('Применяем конфигурацию на ноде…','saving');
    const job=await api(configUrl()+'/apply','POST',{});
    await waitNodeJob($('hub-config-node').value,job.id,180);
    await loadStoredConfig();
    toast('Конфигурация применена');
  }catch(e){toast(errorText(e));await loadStoredConfig()}finally{btn.disabled=false;}
};
const originalNodeList=loadNodes;
loadNodes=async function(){
  await originalNodeList();
  document.querySelectorAll('#server-list [data-node]').forEach(card=>{
    if(card.querySelector('.server-config-link'))return;
    const btn=document.createElement('button');
    btn.type='button';btn.className='server-config-link';
    btn.innerHTML='<svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-files"></use></svg> Открыть конфиги';
    btn.onclick=e=>{e.preventDefault();e.stopPropagation();selectedNode=card.dataset.node;showPage('configs');};
    card.appendChild(btn);
  });
  if($('nodes-empty-add')){
    $('nodes-empty-add').onclick=()=>showPage('add');
    $('nodes-empty-configs').onclick=()=>showPage('configs');
    $('nodes-empty-presets').onclick=()=>showPage('presets');
  }
};
const originalCapabilityTabs=capabilityTabs;
capabilityTabs=function(node){const tabs=originalCapabilityTabs(node);tabs.configs=true;return tabs;};
const originalShowPage=showPage;
showPage=function(page){
  if(page!=='configs'&&!$('configs-page').classList.contains('hidden')&&configDirty){
    if(!confirm('В редакторе остался несохранённый текст. Закрыть без сохранения?'))return;
    configDirty=false;
  }
  if(page!=='configs')++configFetchSerial;
  return originalShowPage(page);
};


/* v1.7: saved-file library, multi-file presets, and persistent sidebar. */
let libraryFiles=[],libraryId=null,libraryRevision=0,libraryBaseline='',libraryDirty=false;
let presetBundles=[],presetBundleId=null,presetDirty=false;
let pendingPresetSelection=null;
const libTypes={nginx:'nginx.conf',nginx_compose:'Nginx Compose',node_compose:'Remnawave Compose'};
const libraryFormData=()=>({name:$('lib-name').value.trim(),kind:$('lib-kind').value,content:$('lib-content').value});
function markLibraryDirty(){
  libraryDirty=JSON.stringify(libraryFormData())!==libraryBaseline;
  $('lib-edit-hint').textContent=libraryDirty?'● Есть несохранённые изменения':'Файл хранится на главном сервере. Сам по себе не меняет VPN-ноды.';
}
function librarySetClean(){libraryBaseline=JSON.stringify(libraryFormData());libraryDirty=false;markLibraryDirty();}
function libraryConfirmDiscard(){return !libraryDirty||confirm('В библиотечном редакторе есть несохранённые изменения. Отменить их?');}
['lib-name','lib-kind','lib-content'].forEach(id=>$(id).addEventListener('input',markLibraryDirty));
$('lib-search').oninput=()=>renderLibraryList();
function renderLibraryList(){
  const term=$('lib-search').value.trim().toLowerCase();
  const items=libraryFiles.filter(f=>(f.name+' '+libTypes[f.kind]).toLowerCase().includes(term));
  $('lib-files').innerHTML=items.length?items.map(f=>`<button class="library-file ${f.id===libraryId?'active':''}" data-file="${escapeHtml(f.id)}" type="button"><span class="library-file-glyph"><svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-files"></use></svg></span><span><strong>${escapeHtml(f.name)}</strong><small>${escapeHtml(libTypes[f.kind]||f.kind)} · v${f.revision}</small></span></button>`).join(''):'<p class="empty-note">Файлов пока нет. Создай первый конфиг прямо здесь.</p>';
  document.querySelectorAll('#lib-files [data-file]').forEach(b=>b.onclick=()=>openLibraryFile(b.dataset.file));
}
function resetLibraryEditor(force=false){
  if(!force&&!libraryConfirmDiscard())return;
  libraryId=null;libraryRevision=0;
  $('lib-name').value='';$('lib-kind').value='nginx';$('lib-kind').disabled=false;
  $('lib-content').value='';
  $('lib-edit-caption').textContent='Новый конфиг';$('lib-edit-revision').textContent='Не сохранён';
  $('lib-delete').classList.add('hidden');librarySetClean();renderLibraryList();
}
$('lib-new').onclick=()=>resetLibraryEditor();
async function openLibraryFile(id){
  if(!libraryConfirmDiscard())return;
  try{
    const f=await api('/config-library/'+encodeURIComponent(id));
    libraryId=f.id;libraryRevision=f.revision;
    $('lib-name').value=f.name;$('lib-kind').value=f.kind;$('lib-kind').disabled=true;
    $('lib-content').value=f.content;
    $('lib-edit-caption').textContent=f.name;$('lib-edit-revision').textContent='Версия '+f.revision;
    $('lib-delete').classList.remove('hidden');librarySetClean();renderLibraryList();
  }catch(e){toast(errorText(e))}
}
async function loadLibraryPanel(openId=null){
  libraryFiles=await api('/config-library');
  if(openId){await openLibraryFile(openId);return}
  if(libraryId&&!libraryFiles.some(f=>f.id===libraryId))resetLibraryEditor(true);
  renderLibraryList();
}
$('lib-save').onclick=async()=>{
  const data=libraryFormData();
  if(!data.name||!data.content.trim())return toast('Укажи название и текст конфига');
  if(data.content.length>100000)return toast('Файл слишком большой для библиотеки (до 100 КБ)');
  const btn=$('lib-save');btn.disabled=true;
  try{
    const id=libraryId;
    const saved=await api(id?'/config-library/'+encodeURIComponent(id):'/config-library',id?'PUT':'POST',id?{...data,revision:libraryRevision}:data);
    libraryDirty=false;libraryId=saved.id;
    await loadLibraryPanel(saved.id);
    toast('Файл сохранён в библиотеке');
  }catch(e){toast(errorText(e))}finally{btn.disabled=false}
};
$('lib-delete').onclick=async()=>{
  if(!libraryId||!confirm('Удалить файл из библиотеки? Файлы, входящие в пресеты, сначала нужно убрать из них.'))return;
  try{
    await api('/config-library/'+encodeURIComponent(libraryId),'DELETE');
    libraryDirty=false;resetLibraryEditor(true);await loadLibraryPanel();
    toast('Файл удалён');
  }catch(e){toast(errorText(e))}
};
$('lib-from-node').onclick=()=>{
  if($('hub-config-editor').classList.contains('hidden'))return toast('Сначала открой конфиг подключённой ноды ниже');
  if(!libraryConfirmDiscard())return;
  resetLibraryEditor(true);
  $('lib-kind').value=$('hub-config-name').value;
  $('lib-name').value='Копия '+($('hub-config-node').selectedOptions[0]?.textContent||'ноды')+' · '+(libTypes[$('hub-config-name').value]||'конфиг');
  $('lib-content').value=$('hub-config-text').value;
  markLibraryDirty();$('lib-name').focus();
  toast('Копия в редакторе. Нажми «Сохранить файл»');
};
$('lib-to-node').onclick=async()=>{
  if(!libraryId)return toast('Выбери сохранённый файл из библиотеки');
  const id=$('hub-config-node').value;
  if(!id||$('hub-config-editor').classList.contains('hidden'))return toast('Нужно сначала открыть конфиг подключённой ноды');
  if(configDirty&&!confirm('Заменить несохранённые изменения на текст из библиотеки?'))return;
  try{
    const f=await api('/config-library/'+encodeURIComponent(libraryId));
    if(f.kind!==$('hub-config-name').value)return toast('Типы файла и конфига ноды различаются. Выбери соответствующий файл на ноде.');
    if(!confirm('Вставить «'+f.name+'» в текстовый редактор ноды? На VPS ничего не изменится до применения.'))return;
    $('hub-config-text').value=f.content;configEditChanged();
    $('hub-config-text').scrollIntoView({behavior:'smooth',block:'center'});
    toast('Файл вставлен. Сначала сохрани черновик, затем примени к ноде.');
  }catch(e){toast(errorText(e))}
};
function resetPresetEditor(){
  presetBundleId=null;presetDirty=false;
  $('preset-bundle-form').reset();$('preset-editor-title').textContent='Новый пресет';
  $('preset-editor-state').textContent='Не сохранён';
}
$('preset-new').onclick=resetPresetEditor;
$('preset-cancel').onclick=resetPresetEditor;
['preset-bundle-name','preset-bundle-description','preset-file-nginx','preset-file-nginx_compose','preset-file-node_compose'].forEach(id=>$(id).oninput=()=>{presetDirty=true;$('preset-editor-state').textContent='Изменён'});
function presetOptions(kind,chosen=''){
  return '<option value="">Без этого файла</option>'+libraryFiles.filter(f=>f.kind===kind).map(f=>`<option value="${escapeHtml(f.id)}" ${f.id===chosen?'selected':''}>${escapeHtml(f.name)} · v${f.revision}</option>`).join('');
}
function renderPresetSelectors(selected={}){
  for(const kind of Object.keys(libTypes))$('preset-file-'+kind).innerHTML=presetOptions(kind,selected[kind]||'');
}
async function loadPresetBundles(){
  [libraryFiles,presetBundles]=await Promise.all([api('/config-library'),api('/config-presets')]);
  const selected={};
  if(presetBundleId){
    const old=presetBundles.find(p=>p.id===presetBundleId);
    for(const item of old?.items||[])selected[item.kind]=item.config_id;
  }
  renderPresetSelectors(selected);
  if(pendingPresetSelection){
    const {kind,id}=pendingPresetSelection;
    resetPresetEditor();
    $('preset-file-'+kind).value=id;
    presetDirty=true;
    $('preset-editor-state').textContent='Выбран файл · сохрани пресет';
    pendingPresetSelection=null;
    toast('Файл добавлен в форму пресета');
  }
  renderPresetCards();
}
function renderPresetCards(){
  $('preset-count').textContent=presetBundles.length+' набора';
  $('preset-cards').innerHTML=presetBundles.length?presetBundles.map(p=>`<article class="bundle-card">
    <div class="bundle-card-header"><span class="bundle-card-icon"><svg class="lucide-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#xicon-layers"></use></svg></span><div><h3>${escapeHtml(p.name)}</h3><p>${escapeHtml(p.description||'Пользовательский набор конфигураций')}</p></div></div>
    <div class="bundle-files">${p.items.map(i=>`<button type="button" data-open-library="${escapeHtml(i.config_id)}" class="bundle-file"><span>${escapeHtml(libTypes[i.kind])}</span><strong>${escapeHtml(i.config_name)}</strong></button>`).join('')}</div>
    <div class="bundle-card-actions"><button type="button" data-edit-preset="${escapeHtml(p.id)}" class="btn secondary sm">Настроить</button><button type="button" data-delete-preset="${escapeHtml(p.id)}" class="btn secondary sm">Удалить</button></div>
  </article>`).join(''):'<div class="empty-note">Пресетов пока нет. Создай конфиги во вкладке «Конфигурации», затем собери их здесь.</div>';
  document.querySelectorAll('[data-edit-preset]').forEach(b=>b.onclick=()=>editPreset(b.dataset.editPreset));
  document.querySelectorAll('[data-delete-preset]').forEach(b=>b.onclick=()=>deletePreset(b.dataset.deletePreset));
  document.querySelectorAll('[data-open-library]').forEach(b=>b.onclick=()=>{const id=b.dataset.openLibrary;showPage('configs');loadLibraryPanel(id).catch(e=>toast(errorText(e)));});
}
function editPreset(id){
  const p=presetBundles.find(x=>x.id===id);if(!p)return;
  if(presetDirty&&!confirm('Отменить несохранённые изменения другого пресета?'))return;
  presetBundleId=id;presetDirty=false;
  $('preset-bundle-name').value=p.name;$('preset-bundle-description').value=p.description;
  const selected=Object.fromEntries(p.items.map(i=>[i.kind,i.config_id]));
  renderPresetSelectors(selected);
  $('preset-editor-title').textContent=p.name;$('preset-editor-state').textContent='Сохранён';
  $('preset-bundle-name').focus();
}
$('preset-bundle-form').onsubmit=async e=>{
  e.preventDefault();
  const ids=Object.keys(libTypes).map(k=>$('preset-file-'+k).value).filter(Boolean);
  if(!ids.length)return toast('Добавь хотя бы один файл в пресет');
  const body={name:$('preset-bundle-name').value.trim(),description:$('preset-bundle-description').value.trim(),config_ids:ids};
  const id=presetBundleId;
  try{
    await api(id?'/config-presets/'+encodeURIComponent(id):'/config-presets',id?'PUT':'POST',body);
    resetPresetEditor();await loadPresetBundles();toast('Пресет сохранён');
  }catch(e){toast(errorText(e))}
};
async function deletePreset(id){
  const p=presetBundles.find(x=>x.id===id);
  if(!p||!confirm('Удалить пресет «'+p.name+'»? Сами файлы библиотеки сохранятся.'))return;
  try{
    await api('/config-presets/'+encodeURIComponent(id),'DELETE');
    if(presetBundleId===id)resetPresetEditor();
    await loadPresetBundles();toast('Пресет удалён, файлы не затронуты');
  }catch(e){toast(errorText(e))}
}
$('lib-add-to-preset').onclick=async()=>{
  if(!libraryId)return toast('Сначала сохрани и выбери файл в библиотеке');
  if(libraryDirty)return toast('Сначала сохрани изменения в файле');
  const file=libraryFiles.find(x=>x.id===libraryId);
  if(!file)return toast('Файл не найден');
  pendingPresetSelection={kind:file.kind,id:file.id};
  showPage('presets');
};
const side=$('app-screen'),toggle=$('sidebar-toggle');
function applySidebarCollapsed(collapsed){
  side.classList.toggle('sidebar-collapsed',collapsed);
  toggle.setAttribute('aria-expanded',String(!collapsed));
  toggle.setAttribute('aria-label',collapsed?'Развернуть меню':'Свернуть меню');
  toggle.title=collapsed?'Развернуть меню':'Свернуть меню';
}
try{const saved=localStorage.getItem('xppn:sidebarCollapsed');applySidebarCollapsed(saved===null?window.matchMedia('(max-width:850px)').matches:saved==='1')}catch{applySidebarCollapsed(false)}
toggle.onclick=()=>{
  const collapsed=!side.classList.contains('sidebar-collapsed');
  applySidebarCollapsed(collapsed);
  try{localStorage.setItem('xppn:sidebarCollapsed',collapsed?'1':'0')}catch{}
};
const earlierPage=showPage;
showPage=function(page){
  if(page!=='configs'&&libraryDirty&&!$('configs-page').classList.contains('hidden')){
    if(!confirm('В библиотеке есть несохранённый конфиг. Закрыть страницу без сохранения?'))return;
    libraryDirty=false;
  }
  if(page!=='presets'&&presetDirty&&!$('presets-page').classList.contains('hidden')){
    if(!confirm('В пресете есть несохранённые изменения. Закрыть без сохранения?'))return;
    presetDirty=false;
  }
  return earlierPage(page);
};


/* v1.8 — first-node onboarding: one Remnawave panel, predictable install modes. */
let wizardMainProject=null,wizardPanelReady=false,wizardPanelProfiles=[],wizardStatusLoading=false;
let wizardPreflightOk=false,wizardPreflightBusy=false,wizardPreflightStamp='',wizardPreflightIssue='';
const primaryPanel=()=>projectCache.find(p=>p.id==='default')||projectCache[0]||null;
const mainPanelNeedsSetup=()=>preset()!=='agent'&&!wizardPanelReady;
function wizardStatus(text,kind='info'){
  const el=$('wizard-panel-message');el.textContent=text;el.dataset.kind=kind;
}
function wizardPanelSummary(){
  const p=primaryPanel();
  wizardMainProject=p;
  wizardPanelReady=!!(p&&p.panel_url&&p.panel_ip&&p.has_api_token&&p.has_secret_key&&p.panel_config_profile_uuid&&(p.panel_active_inbounds||[]).length);
  const agent=preset()==='agent';
  $('wizard-panel-setup').classList.toggle('hidden',agent);
  $('wizard-panel-status-title').textContent=wizardPanelReady?'Remnawave подключена':'Один раз подключи Remnawave';
  $('wizard-panel-status-detail').textContent=wizardPanelReady
    ?(p.panel_url+' · настройки для новых нод сохранены')
    :'Введи URL, API-токен и исходящий IP панели. После этого новые VPS будут подключаться автоматически.';
  $('wizard-panel-setup').dataset.ready=wizardPanelReady?'true':'false';
  $('wizard-panel-edit').textContent=wizardPanelReady?'Изменить':'Подключить';
}
function fillWizardPanelSettings(){
  const p=primaryPanel();if(!p)return;
  $('wizard-remna-url').value=p.panel_url||'';
  $('wizard-remna-token').value='';
  $('wizard-remna-egress').value=p.panel_ip||'';
  wizardStatus('');
}
async function prepareWizardTemplates(preferredMode){
  const mode=preferredMode||preset();
  const p=primaryPanel();
  if(!p)return;
  const id=$('wizard-profile').value;
  profilesCache=await api('/projects/'+encodeURIComponent(p.id)+'/profiles');
  const subset=profilesCache.filter(x=>x.mode===mode && (mode!=='full'||x.transport==='tls-raw'));
  $('wizard-profile').innerHTML=subset.map(x=>'<option value="'+escapeHtml(x.id)+'">'+escapeHtml(x.name)+'</option>').join('');
  const selected=subset.find(x=>x.id===id)||subset.find(x=>x.transport==='tls-raw')||subset[0];
  if(selected)$('wizard-profile').value=selected.id;
  $('wizard-profile-hint').textContent=selected
    ?'Шаблон «'+selected.name+'». Дополнительные параметры подставятся автоматически.'
    :'Шаблон для этого режима не найден. Менеджер использует стандартные параметры.';
}
refreshWizardProjects=async function(){
  await fetchProjects();
  const p=primaryPanel();
  $('wizard-project').innerHTML=p?'<option value="'+escapeHtml(p.id)+'">'+escapeHtml(p.name)+'</option>':'';
  if(!p)return wizardStatus('В менеджере нет основной панели. Проверь базу данных.','error');
  $('wizard-project').value=p.id;
  await prepareWizardTemplates(preset());
  wizardPanelSummary();
  fillWizardPanelSettings();
  $('wizard-panel-settings').classList.toggle('hidden',wizardPanelReady);
  $('wizard-panel-profiles').classList.add('hidden');
  if(preset()==='full')$('confirm-clean').checked=false;
};
wizardProjectChange=async()=>refreshWizardProjects();
wizardProfileChange=function(){
  const found=profilesCache.find(x=>x.id===$('wizard-profile').value);
  if(found)$('wizard-profile-hint').textContent='Шаблон «'+found.name+'» · будет применён к выбранной установке.';
};
const originalPresetChange=onPresetChange;
onPresetChange=function(){
  originalPresetChange();
  wizardPanelSummary();
  // Choosing a mode must NOT silently switch back to the first project template.
  prepareWizardTemplates(preset()).catch(e=>wizardStatus(errorText(e),'error'));
};
document.querySelectorAll('input[name="preset"]').forEach(el=>el.onchange=()=>onPresetChange());
$('wizard-profile').onchange=wizardProfileChange;
$('wizard-panel-edit').onclick=()=>{
  $('wizard-panel-settings').classList.toggle('hidden');
  if(!$('wizard-panel-settings').classList.contains('hidden'))fillWizardPanelSettings();
};
function showPanelOptions(profiles){
  wizardPanelProfiles=profiles.filter(p=>p.uuid && Array.isArray(p.inbounds)&&p.inbounds.length);
  const select=$('wizard-remna-profile');
  select.innerHTML=wizardPanelProfiles.map(p=>'<option value="'+escapeHtml(p.uuid)+'">'+escapeHtml(p.name||p.uuid)+'</option>').join('');
  const main=primaryPanel();
  if(main?.panel_config_profile_uuid&&wizardPanelProfiles.some(p=>p.uuid===main.panel_config_profile_uuid))select.value=main.panel_config_profile_uuid;
  renderPanelInbounds();
  $('wizard-panel-profiles').classList.remove('hidden');
}
function renderPanelInbounds(){
  const selected=wizardPanelProfiles.find(p=>p.uuid===$('wizard-remna-profile').value);
  const existing=primaryPanel();
  const preselected=selected?.uuid===existing?.panel_config_profile_uuid?(existing.panel_active_inbounds||[]):[];
  $('wizard-remna-inbounds').innerHTML=(selected?.inbounds||[]).map(x=>
    '<label class="checkbox-row"><input type="checkbox" class="wizard-inbound" value="'+escapeHtml(x.uuid)+'" '+(preselected.length?preselected.includes(x.uuid):true?'checked':'')+'><span>'+escapeHtml(x.tag||x.uuid)+'</span></label>'
  ).join('')||'<p class="setup-notice">В профиле нет доступных inbound-ов. Проверь конфигурацию Remnawave.</p>';
}
$('wizard-remna-profile').onchange=renderPanelInbounds;
$('wizard-panel-connect').onclick=async()=>{
  const p=primaryPanel();
  if(!p)return wizardStatus('Основной проект не обнаружен.','error');
  const url=$('wizard-remna-url').value.trim(),token=$('wizard-remna-token').value;
  const egress=$('wizard-remna-egress').value.trim();
  if(!url||!/^https:\/\//i.test(url))return wizardStatus('Укажи HTTPS-адрес панели Remnawave.','error');
  if(!token&&!p.has_api_token)return wizardStatus('Введи API-токен Remnawave.','error');
  if(!egress)return wizardStatus('Укажи исходящий IPv4 панели — он используется для разрешения доступа к ноде.','error');
  const btn=$('wizard-panel-connect');btn.disabled=true;wizardStatus('Сохраняем подключение и проверяем API…');
  try{
    await api('/projects/'+encodeURIComponent(p.id),'PATCH',{name:p.name,panel_url:url,panel_ip:egress,api_token:token});
    const connected=await api('/projects/'+encodeURIComponent(p.id)+'/panel/sync','POST',{});
    await fetchProjects();wizardPanelSummary();
    showPanelOptions(connected.profiles||[]);
    if(!wizardPanelProfiles.length)wizardStatus('API доступен, но нет профилей с inbound-ами. Настрой один Config Profile в Remnawave и повтори проверку.','error');
    else wizardStatus('Подключение проверено. Выбери профиль и сохрани его для всех будущих нод.','success');
    $('wizard-remna-token').value='';
  }catch(e){wizardStatus(errorText(e),'error')}finally{btn.disabled=false}
};
$('wizard-panel-save').onclick=async()=>{
  const p=primaryPanel();
  const ids=[...document.querySelectorAll('.wizard-inbound:checked')].map(e=>e.value);
  if(!ids.length)return wizardStatus('Выбери хотя бы один inbound для автоматической регистрации новых нод.','error');
  const btn=$('wizard-panel-save');btn.disabled=true;
  try{
    await api('/projects/'+encodeURIComponent(p.id)+'/panel/defaults','PUT',{
      config_profile_uuid:$('wizard-remna-profile').value,active_inbounds:ids,country_code:'XX'
    });
    await fetchProjects();wizardPanelSummary();
    $('wizard-panel-settings').classList.add('hidden');
    wizardStatus('Основная Remnawave готова. Все новые ноды будут использовать эти настройки.','success');
    toast('Подключение Remnawave сохранено');
  }catch(e){wizardStatus(errorText(e),'error')}finally{btn.disabled=false}
};
validateWizard=function(){
  for(const id of ['server-name','server-ip','server-password']){
    if(!$(id).value.trim())throw Error('Укажи название, IP-адрес и пароль root.');
  }
  const port=Number($('server-port').value);
  if(!Number.isInteger(port)||port<1||port>65535)throw Error('SSH-порт должен быть от 1 до 65535.');
  if(preset()!=='agent'){
    if(!wizardPanelReady)throw Error('Сначала подключи Remnawave один раз на первом шаге.');
    if(!/^\d+\.\d+\.\d+$/.test($('wizard-version').value.trim()))throw Error('Версия ноды: например 3.4.2.');
  }
  if(preset()==='full'){
    if(!$('wizard-domain').value.trim())throw Error('Для полной установки укажи домен ноды. TLS-сертификат нельзя получить по одному IP.');
    if(!$('confirm-clean').checked)throw Error('Подтверди, что VPS подготовлен для полной установки.');
  }
};
function resetWizardPreflight(){
  wizardPreflightOk=false;wizardPreflightBusy=false;wizardPreflightStamp='';
  $('wizard-preflight').dataset.kind='idle';
  $('wizard-preflight').innerHTML='<span class="wizard-spinner"></span><span>После подтверждения SSH-ключа проверим ОС, диск, Docker и занятые порты. Ничего не изменяем.</span>';
  $('enroll-btn').disabled=true;
}
$('wizard-next').onclick=()=>{
  if(wizardStep===1){
    if(mainPanelNeedsSetup()){
      $('wizard-panel-settings').classList.remove('hidden');
      wizardStatus('Сначала настрой подключение Remnawave. Это потребуется сделать только один раз.','error');
      $('wizard-panel-setup').scrollIntoView({behavior:'smooth',block:'center'});
      return;
    }
    if(preset()!=='agent'&&(!$('wizard-profile').value))return toast('Не найден шаблон установки для выбранного режима.');
    setWizardStep(2);return;
  }
  if(wizardStep===2){
    try{validateWizard()}catch(e){toast(errorText(e));return}
    $('review-server').textContent=$('server-name').value.trim()+' · '+$('server-ip').value.trim()+':'+$('server-port').value;
    $('review-preset').textContent=presets[preset()].name;
    $('review-details').textContent=preset()==='agent'?'Только агент':$('wizard-version').value.trim()+(preset()==='full'?' · '+$('wizard-domain').value.trim():'');
    expectedFingerprint='';fingerprintTarget='';
    $('fingerprint-box').classList.add('hidden');
    $('fingerprint-confirm').checked=false;
    resetWizardPreflight();setWizardStep(3);
  }
};
const originalFingerprintCheck=fingerprintCheck;
const preflightIdentity=()=>$('server-ip').value.trim()+':'+$('server-port').value+':'+expectedFingerprint;
fingerprintCheck=function(){
  const valid=!!($('fingerprint-confirm').checked&&expectedFingerprint&&fingerprintTarget===$('server-ip').value.trim()+':'+$('server-port').value);
  $('enroll-btn').disabled=!(valid&&wizardPreflightOk);
  if(valid&&!wizardPreflightOk&&!wizardPreflightBusy){
    runReadOnlyPreflight().catch(e=>{
      wizardPreflightOk=false;wizardPreflightBusy=false;
      $('wizard-preflight').dataset.kind='error';
      $('wizard-preflight').textContent='Не удалось проверить сервер: '+errorText(e)+'. Повтори проверку SSH-ключа.';
      $('enroll-btn').disabled=true;
    });
  }
};
async function runReadOnlyPreflight(){
  wizardPreflightBusy=true;wizardPreflightStamp=preflightIdentity();
  $('wizard-preflight').dataset.kind='busy';
  $('wizard-preflight').innerHTML='<span class="wizard-spinner"></span><span>Проверяем VPS без изменений на сервере…</span>';
  const response=await api('/ssh/preflight','POST',{
    ip:$('server-ip').value.trim(),port:Number($('server-port').value),
    password:$('server-password').value,fingerprint:expectedFingerprint
  });
  if(wizardPreflightStamp!==preflightIdentity())return;
  const conflicts=(response.ports_in_use||[]).filter(port=>preset()==='full'?[80,443,2222].includes(port):preset()==='node'?port===2222:false);
  const problems=[...(response.warnings||[])];
  wizardPreflightOk=!conflicts.length;
  $('wizard-preflight').dataset.kind=conflicts.length?'error':problems.length?'warning':'success';
  const details=escapeHtml(response.os+' '+response.version+' · '+response.arch+' · '+(response.free_disk_mb||'—')+' МБ свободно');
  const notices=problems.length?'<ul>'+problems.map(t=>'<li>'+escapeHtml(t)+'</li>').join('')+'</ul>':'';
  $('wizard-preflight').innerHTML='<div><strong>'+ (wizardPreflightOk?'Сервер проверен':'Обнаружен конфликт портов') +'</strong><p>'+details+'</p>'+notices+
    (conflicts.length?'<p>Полную установку поверх этих сервисов запускать нельзя. Выбери «Только управление» или освободи порты и проверь снова.</p>':'<p>Проверка ничего не изменила на VPS. Для установки нажми кнопку ниже.</p>')+'</div>';
  wizardPreflightBusy=false;
  $('enroll-btn').disabled=!(wizardPreflightOk&&$('fingerprint-confirm').checked);
}
$('fingerprint-confirm').onchange=fingerprintCheck;
['server-ip','server-port','server-password'].forEach(id=>$(id).addEventListener('input',resetWizardPreflight));
