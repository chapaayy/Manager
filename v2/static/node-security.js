"use strict";
// Per-node desired security profile + read-only actual VPS state.
let nodeSecuritySnapshot=null,nodeSecuritySettings=null;

const trafficSize=v=>{
  if(typeof v!=="number"||!Number.isFinite(v)||v<0)return "—";
  let n=v,i=0;const units=["Б","КБ","МБ","ГБ","ТБ"];
  while(n>=1024&&i<units.length-1){n/=1024;i++}
  return n.toLocaleString("ru-RU",{maximumFractionDigits:n<10&&i?2:1})+" "+units[i];
};
function securityVersionAtLeast(value,minimum=[1,7,0]){
  const m=String(value||"").match(/^(\d+)\.(\d+)\.(\d+)$/);if(!m)return false;
  const a=m.slice(1).map(Number);
  for(let i=0;i<3;i++){if(a[i]>minimum[i])return true;if(a[i]<minimum[i])return false}
  return true;
}
const securitySources=v=>String(v||"").split(/[\s,;]+/).map(x=>x.trim()).filter(Boolean);
const securityNum=(id,fallback)=>{const el=$(id),n=Number(el?.value);return Number.isFinite(n)?Math.trunc(n):fallback};

function securityNetworkBody(n,a,m){
  const online=!!a.online;
  return '<div class="security-workspace">'+
    '<div class="node-panel security-audit"><div class="node-panel-head"><div><h2>Сеть и защита</h2>'+
    '<p class="muted small">Желаемые настройки хранятся в Manager, фактическое состояние проверяется Agent на VPS.</p></div>'+
    '<button class="btn subtle" data-security-refresh '+(!online?'disabled':'')+'>Проверить состояние</button></div>'+
    '<div id="node-task-output">'+(nodeSecuritySnapshot?securityStatusReport(nodeSecuritySnapshot):
      '<p class="muted small">Проверяем TCP, SSH, Node API 2222 и ротацию логов…</p>')+'</div></div>'+
    '<div class="node-panel security-settings-panel" id="security-settings-panel">'+
      (nodeSecuritySettings?securitySettingsEditor(n,a):'<p class="muted small">Загружаем сохранённый профиль…</p>')+
    '</div></div>';
}

function securityActualMatches(data){
  const state=nodeSecuritySettings?.config;if(!state)return {};
  const f=state.fail2ban,fw=state.firewall,tcp=state.tcp,logs=state.logs;
  const tcpOk=tcp.enabled
    ? data.tcp_congestion===tcp.congestion_control&&data.default_qdisc===tcp.qdisc
    : data.bbr_config_managed!==true;
  const f2bOk=f.enabled
    ? data.fail2ban_active===true&&data.sshd_jail_active===true&&
      Number(data.fail2ban_maxretry)===f.maxretry&&
      Number(data.fail2ban_findtime)===f.findtime_seconds&&
      Number(data.fail2ban_bantime)===f.bantime_seconds
    : data.sshd_jail_active!==true;
  const fwOk=fw.enabled
    ? data.panel_firewall_ipv4_rule===true&&data.panel_firewall_service_active===true&&
      data.panel_firewall_service_enabled===true&&(!fw.block_ipv6||data.panel_firewall_ipv6_rule===true)
    : data.panel_firewall_ipv4_rule!==true;
  const logOk=(!logs.nginx.enabled||data.nginx_logrotate===true)&&
    (!logs.remnanode.enabled||data.remnanode_logrotate===true)&&
    ((!logs.nginx.enabled&&!logs.remnanode.enabled)||data.logrotate_timer_active===true);
  return {tcpOk,f2bOk,fwOk,logOk};
}

function securityStatusReport(data){
  nodeSecuritySnapshot=data;
  const match=securityActualMatches(data);
  const desired=nodeSecuritySettings?.config;
  const active=data.fail2ban_active===true&&data.sshd_jail_active===true;
  const ips=Array.isArray(data.banned_ips)?data.banned_ips:[];
  const history=Array.isArray(data.history)?data.history:[];
  const qdiscActual=data.active_qdisc?data.default_qdisc+" → "+data.active_qdisc:data.default_qdisc||"—";
  const firewallDetails=data.panel_firewall_ipv4_rule
    ? "IPv4 защищён"+(data.panel_firewall_ipv6_rule?" · IPv6 защищён":" · IPv6 требует проверки")
    : "Правило 2222 не подтверждено";
  const logDetails=(trafficSize(data.nginx_log_bytes)+" Nginx · "+trafficSize(data.remnanode_log_bytes)+" Node");
  const records=[
    ["TCP",String(data.tcp_congestion||"—")+" / "+qdiscActual,match.tcpOk],
    ["Fail2Ban SSH",active?"Защищён":"Не защищён",match.f2bOk],
    ["Remnawave Node API · 2222",firewallDetails,match.fwOk],
    ["Логи и ротация",logDetails,match.logOk]
  ];
  let out='<div class="security-status-grid">'+records.map(([heading,value,good])=>
    '<div class="security-status-item"><small>'+esc(heading)+'</small><strong>'+esc(value)+'</strong>'+
    nodeStatus(good===true,"Совпадает с Manager",good===false?"Отличается от Manager":"Проверено")+'</div>').join("")+'</div>';

  if(desired){
    const changed=nodeSecuritySettings.changed_since_apply;
    out+='<div class="security-sync-line"><span class="node-state '+(!changed?'is-good':'')+'">'+
      (changed?'Есть неприменённые изменения':'Сохранённая ревизия применена')+'</span>'+
      '<small>Ревизия '+esc(nodeSecuritySettings.revision)+' · применена '+esc(nodeSecuritySettings.applied_revision||0)+'</small></div>';
  }

  if(data.security_settings_supported!==true){
    out+='<div class="security-upgrade-note"><strong>Helper этой VPS ещё не поддерживает полные настройки.</strong>'+
      '<p class="muted small">Один раз обнови служебный helper через сохранённый SSH. VPN, Xray и токен Agent не меняются.</p>'+
      '<button class="btn subtle" data-security-helper>Подготовить управление сетью и защитой</button></div>';
  }else if(!securityVersionAtLeast(currentAgent().version)){
    out+='<div class="security-upgrade-note"><strong>Для применения нужен Agent 1.7.0 или новее.</strong>'+
      '<p class="muted small">Сначала обнови Agent во вкладке «Управление». Сохранить профиль можно уже сейчас.</p></div>';
  }

  out+='<div class="security-ssh"><div class="node-panel-head"><h3>Активные блокировки SSH</h3>'+
    (active?'<span class="node-state is-good">'+esc(data.fail2ban_maxretry||"—")+' попыток · окно '+
      esc(data.fail2ban_findtime||"—")+' с · бан '+esc(data.fail2ban_bantime||"—")+' с</span>':
      '<span class="node-state is-bad">SSH jail не активен</span>')+'</div>'+
    '<p class="security-bans">Сейчас заблокировано: <strong>'+esc(data.sshd_banned_count??ips.length)+' IP</strong></p>'+
    (ips.length?ips.map(ip=>'<div class="security-ban-row"><code>'+esc(ip)+'</code>'+
      '<button class="btn subtle" data-security-unban="'+esc(ip)+'">Разблокировать</button></div>').join(""):
      '<p class="muted small">Нет активных блокировок.</p>')+
    '<details class="security-history"><summary>Последние Ban / Unban</summary>'+
    (history.length?history.slice(-15).reverse().map(item=>
      '<div class="security-history-row"><span>'+esc(item.action==="ban"?"Блокировка":"Разблокировка")+
      '</span><code>'+esc(item.ip)+'</code><small>'+esc(item.when)+'</small></div>').join(""):
      '<p class="muted small">Событий пока нет.</p>')+'</details></div>'+
    '<p class="muted small security-foot">Зелёный статус означает совпадение сохранённого профиля Manager с фактическим состоянием VPS, а не просто наличие файла.</p>';
  return out;
}

function securitySettingsEditor(n,a){
  const st=nodeSecuritySettings,c=st.config,t=c.tcp,f=c.fail2ban,fw=c.firewall,l=c.logs;
  const canApply=!!a.online&&securityVersionAtLeast(a.version)&&nodeSecuritySnapshot?.security_settings_supported===true;
  const saved=st.updated_at?new Date(st.updated_at*1000).toLocaleString("ru-RU"):"ещё не сохранялся";
  return '<div class="node-panel-head"><div><h2>Профиль ноды</h2>'+
    '<p class="muted small">Меняй только параметры. Manager сам собирает системные конфиги и проверяет их на VPS.</p></div>'+
    '<span class="node-state '+(!st.changed_since_apply?'is-good':'')+'">rev '+esc(st.revision)+'</span></div>'+
    '<form id="security-settings-form" class="security-settings-form">'+
    '<section class="security-setting-card"><div class="security-setting-head"><div><h3>TCP</h3>'+
    '<p>Congestion control и default qdisc. Фактический qdisc интерфейса показывается выше.</p></div>'+
    '<label class="switch-row"><input id="security-tcp-enabled" type="checkbox" '+(t.enabled?'checked':'')+'> Управлять</label></div>'+
    '<div class="security-fields two-fields"><label>Congestion control<select id="security-tcp-cc">'+
    ['bbr','cubic','reno'].map(v=>'<option '+(t.congestion_control===v?'selected':'')+'>'+v+'</option>').join('')+
    '</select></label><label>Default qdisc<select id="security-tcp-qdisc">'+
    ['fq','fq_codel'].map(v=>'<option '+(t.qdisc===v?'selected':'')+'>'+v+'</option>').join('')+
    '</select></label></div></section>'+
    '<section class="security-setting-card"><div class="security-setting-head"><div><h3>Fail2Ban · SSH</h3>'+
    '<p>Защищается только sshd. Сторонний Fail2Ban без XPPN-конфига автоматически не перезаписывается.</p></div>'+
    '<label class="switch-row"><input id="security-f2b-enabled" type="checkbox" '+(f.enabled?'checked':'')+'> Включён</label></div>'+
    '<div class="security-fields security-three"><label>Ошибок до бана<input id="security-f2b-retry" type="number" min="1" max="20" value="'+esc(f.maxretry)+'"></label>'+
    '<label>Окно, минут<input id="security-f2b-find" type="number" min="1" max="1440" value="'+esc(Math.round(f.findtime_seconds/60))+'"></label>'+
    '<label>Бан, минут <span class="muted">-1 = навсегда</span><input id="security-f2b-ban" type="number" min="-1" max="10080" value="'+esc(f.bantime_seconds===-1?-1:Math.round(f.bantime_seconds/60))+'"></label></div>'+
    '<label>Доверенные IP / CIDR<textarea id="security-f2b-trusted" rows="3" placeholder="8.8.8.8/32&#10;2001:db8::/64">'+esc(f.trusted_sources.join("\n"))+'</textarea></label></section>'+
    '<section class="security-setting-card"><div class="security-setting-head"><div><h3>Remnawave Node API · TCP 2222</h3>'+
    '<p>IPv4 Remnawave Panel добавляется в allowlist автоматически и не может быть случайно исключён.</p></div>'+
    '<label class="switch-row danger-switch"><input id="security-fw-enabled" type="checkbox" '+(fw.enabled?'checked':'')+'> Защита включена</label></div>'+
    '<label>Дополнительные разрешённые IP / CIDR<textarea id="security-fw-extra" rows="3" placeholder="Резервная panel / админский адрес">'+esc(fw.extra_allowed_sources.join("\n"))+'</textarea></label>'+
    '<label class="check-row"><input id="security-fw-ipv6" type="checkbox" '+(fw.block_ipv6?'checked':'')+'> Блокировать TCP 2222 по IPv6, если IPv6 allowlist не задан</label></section>'+
    '<section class="security-setting-card"><div class="security-setting-head"><div><h3>Логи и хранение</h3>'+
    '<p>Ротация файлов Nginx и Remnawave/Xray. Docker stdout остаётся ограничен Compose-параметрами.</p></div></div>'+
    securityLogRow("nginx","Nginx",l.nginx)+securityLogRow("remnanode","Remnawave / Xray",l.remnanode)+'</section>'+
    '<div class="security-savebar"><div><small class="muted">Последнее сохранение: '+esc(saved)+'</small>'+
    '<p class="muted small">«Сохранить» не меняет VPS. «Сохранить и применить» отправляет одно подтверждённое задание Agent.</p></div>'+
    '<div class="form-buttons"><button type="button" class="btn subtle" data-security-save>Сохранить</button>'+
    '<button type="button" class="btn primary" data-security-apply '+(!canApply?'disabled':'')+'>Сохранить и применить</button></div></div>'+
    (!canApply?'<p class="muted small">Для применения нужны онлайн Agent 1.7+ и новый helper. Сохранять настройки можно независимо.</p>':'')+
    '</form>';
}

function securityLogRow(key,label,cfg){
  return '<div class="security-log-row"><label class="switch-row"><input id="security-log-'+key+'-enabled" type="checkbox" '+(cfg.enabled?'checked':'')+'> '+esc(label)+'</label>'+
    '<label>Размер, МБ<input id="security-log-'+key+'-size" type="number" min="1" max="2048" value="'+esc(cfg.size_mb)+'"></label>'+
    '<label>Архивов<input id="security-log-'+key+'-archives" type="number" min="1" max="30" value="'+esc(cfg.archives)+'"></label>'+
    '<label class="check-row"><input id="security-log-'+key+'-compress" type="checkbox" '+(cfg.compress?'checked':'')+'> Сжимать</label></div>';
}

function collectSecuritySettings(){
  const banMinutes=securityNum("security-f2b-ban",60);
  return {
    tcp:{enabled:$("security-tcp-enabled").checked,congestion_control:$("security-tcp-cc").value,qdisc:$("security-tcp-qdisc").value},
    fail2ban:{enabled:$("security-f2b-enabled").checked,maxretry:securityNum("security-f2b-retry",6),
      findtime_seconds:securityNum("security-f2b-find",10)*60,
      bantime_seconds:banMinutes===-1?-1:banMinutes*60,
      trusted_sources:securitySources($("security-f2b-trusted").value)},
    firewall:{enabled:$("security-fw-enabled").checked,extra_allowed_sources:securitySources($("security-fw-extra").value),
      block_ipv6:$("security-fw-ipv6").checked},
    logs:{
      nginx:collectSecurityLog("nginx"),
      remnanode:collectSecurityLog("remnanode")
    }
  };
}
function collectSecurityLog(key){
  return {enabled:$("security-log-"+key+"-enabled").checked,size_mb:securityNum("security-log-"+key+"-size",20),
    archives:securityNum("security-log-"+key+"-archives",7),compress:$("security-log-"+key+"-compress").checked};
}

async function loadNodeSecuritySettings(){
  const id=selectedNodeId;if(!id)return;
  const st=await api("/nodes/"+encodeURIComponent(id)+"/security-settings");
  if(selectedNodeId!==id)return;
  nodeSecuritySettings=st;
  const box=$("security-settings-panel");
  if(box)box.innerHTML=securitySettingsEditor(currentNode(),currentAgent());
}
async function securityReload(){
  const id=selectedNodeId;if(!id||selectedNodeTab!=="network")return;
  try{await loadNodeSecuritySettings()}catch(e){message(e.message,true)}
  if(selectedNodeId!==id||selectedNodeTab!=="network")return;
  if(currentAgent().online)await executeNodeTask("baseline.status");
}
async function saveNodeSecuritySettings(applyNow=false){
  const id=selectedNodeId;if(!id||!nodeSecuritySettings)return;
  try{
    const config=collectSecuritySettings();
    nodeSecuritySettings=await api("/nodes/"+encodeURIComponent(id)+"/security-settings","PUT",
      {config,revision:nodeSecuritySettings.revision});
    const box=$("security-settings-panel");if(box)box.innerHTML=securitySettingsEditor(currentNode(),currentAgent());
    if(!applyNow){message("Профиль сети и защиты сохранён. VPS не изменялась.");return}
    if(!securityVersionAtLeast(currentAgent().version))throw new Error("Сначала обнови Agent до 1.7.0 или новее");
    if(nodeSecuritySnapshot?.security_settings_supported!==true)throw new Error("Сначала подготовь новый helper для этой VPS");
    if(!confirm("Применить сохранённый профиль сети и защиты на "+currentNode().code+"?"))return;
    const job=await api("/nodes/"+encodeURIComponent(id)+"/security-settings/apply","POST",{confirmed:true});
    message("Настройки отправлены Agent. Проверяем результат…");
    await waitAgentTask(id,job.id);
    await securityReload();
    message("Настройки применены и состояние VPS перепроверено");
  }catch(e){message(e.message,true)}
}

function prepareNodeSecurity(){
  const id=selectedNodeId,n=currentNode();if(!n)return;
  openModal("Управление сетью и защитой · "+n.code,"ОДНОКРАТНОЕ ОБНОВЛЕНИЕ HELPER",
    '<p class="muted small">Через SSH с проверкой fingerprint обновим только root-helper и служебный Fail2Ban installer. Agent, токен, Xray, Nginx и Remnawave не переустанавливаются.</p>'+
    '<form><label>Пароль root SSH <span class="muted">· необязательно, если сохранён</span><input type="password" name="password" autocomplete="new-password" placeholder="Использовать сохранённый пароль"></label>'+
    '<label class="check-row"><input type="checkbox" name="confirmed" required> Подтверждаю обновление служебного helper</label>'+
    '<div class="form-buttons"><button type="submit" class="btn primary">Подготовить</button></div></form>',
    async fd=>{
      await api("/agents/"+encodeURIComponent(id)+"/ssh-protection/helper","POST",
        {password:fd.get("password"),confirmed:fd.get("confirmed")==="on"});
      message("Helper обновлён. Перепроверяем возможности VPS.");await securityReload();
    });
}

async function unbanNodeSSH(ip){
  if(!selectedNodeId||!ip)return;
  const id=selectedNodeId;
  if(!confirm("Разблокировать IP "+ip+" только в SSH jail Fail2Ban?"))return;
  try{
    const job=await api("/agents/"+encodeURIComponent(id)+"/ssh-protection/unban","POST",{ip,confirmed:true});
    await waitAgentTask(id,job.id);
    message("IP "+ip+" разблокирован в SSH jail");
    await securityReload();
  }catch(e){message(e.message,true)}
}
