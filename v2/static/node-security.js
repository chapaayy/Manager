"use strict";
// One node, one security workspace. No state changes without explicit approval.
let nodeSecuritySnapshot=null;
const trafficSize=v=>{
  if(typeof v!=="number"||!Number.isFinite(v)||v<0)return "—";
  let n=v,i=0;const units=["Б","КБ","МБ","ГБ","ТБ"];
  while(n>=1024&&i<units.length-1){n/=1024;i++}
  return n.toLocaleString("ru-RU",{maximumFractionDigits:n<10&&i?2:1})+" "+units[i];
};
const trafficRate=v=>{
  if(typeof v!=="number"||!Number.isFinite(v)||v<0)return "Ожидаем замер";
  if(v>=1)return v.toLocaleString("ru-RU",{maximumFractionDigits:2})+" Мбит/с";
  if(v>=.001)return (v*1000).toLocaleString("ru-RU",{maximumFractionDigits:1})+" Кбит/с";
  return (v*1e6).toLocaleString("ru-RU",{maximumFractionDigits:0})+" бит/с";
};
function securityNetworkBody(n,a,m){
  const online=!!a.online;
  return '<div class="security-workspace"><div class="node-panel security-network">'+
    '<div class="node-panel-head"><h2>Сеть и производительность</h2>'+
    '<button class="btn subtle" data-node-network-refresh>Обновить показатели</button></div>'+
    '<div class="security-metrics">'+
    [['Входящая скорость',trafficRate(m.net_rx_mbps),"Всего "+trafficSize(m.net_rx_bytes)],
     ['Исходящая скорость',trafficRate(m.net_tx_mbps),"Всего "+trafficSize(m.net_tx_bytes)],
     ['TCP-соединения',m.tcp_established??"—","Установлены сейчас"],
     ['TCP retransmits',m.tcp_retrans_segs??"—","Накопительно с запуска системы"]
    ].map(([heading,value,note])=>'<div class="security-metric"><small>'+esc(heading)+'</small>'+
      '<strong>'+esc(value)+'</strong><span>'+esc(note)+'</span></div>').join("")+
    '</div><p class="muted small">Интерфейс: '+esc(m.net_interface||"—")+
    ' · Потери пакетов RX/TX: '+esc(m.net_rx_dropped??"—")+
    ' / '+esc(m.net_tx_dropped??"—")+
    '. Счётчики накопительные; скорость рассчитывается между замерами Agent.</p></div>'+
    '<div class="node-panel security-audit"><div class="node-panel-head"><h2>Защита VPS</h2>'+
    '<button class="btn subtle" data-node-task="baseline.status" '+(!online?'disabled':'')+
    '>Проверить состояние</button></div>'+
    '<div id="node-task-output">'+(nodeSecuritySnapshot?securityStatusReport(nodeSecuritySnapshot):
    '<p class="muted small">Проверяем SSH, BBR/FQ, Fail2Ban и firewall 2222…</p>')+
    '</div></div></div>';
}
function securityStatusReport(data){
  const agent=currentAgent(),modern=/^1\.(?:[4-9]|[1-9][0-9])\./.test(agent.version||"");
  const ready=data.security_helper_ready===true;
  const active=data.fail2ban_active===true&&data.sshd_jail_active===true;
  const ips=Array.isArray(data.banned_ips)?data.banned_ips:[];
  const history=Array.isArray(data.history)?data.history:[];
  const labels={"installing-packages":"Устанавливаются пакеты","ssh-protected":"Защита SSH установлена",
    "already-protected":"Защита уже активна","package-install-failed":"Не удалось установить пакет через apt",
    "ssh-jail-not-started":"Не удалось запустить SSH jail",
    "existing-fail2ban-needs-review":"Есть сторонний Fail2Ban: автоматическое изменение запрещено",
    "existing-xppn-config-needs-review":"Существующая конфигурация требует ручной проверки",
    "ssh-port-unavailable":"Не удалось определить порт SSH","configuration-invalid":"Ошибка конфигурации Fail2Ban",
    "no-supported-firewall-tool":"Не найден firewall backend"};
  const records=[
    ["BBR / FQ",(data.tcp_congestion||"—")+" / "+(data.default_qdisc||"—"),
      data.tcp_congestion==="bbr"&&data.default_qdisc==="fq"],
    ["Fail2Ban SSH",active?"Защищён":"Не защищён",active],
    ["Firewall API 2222",data.panel_firewall_ipv4_rule?"Правило подтверждено":"Не подтверждено",
      data.panel_firewall_ipv4_rule===true],
    ["Ротация Nginx",data.nginx_logrotate?"Настроена":"Не обнаружена",data.nginx_logrotate===true]
  ];
  let out='<div class="security-status-grid">'+records.map(([heading,value,good])=>
    '<div class="security-status-item"><small>'+esc(heading)+'</small><strong>'+esc(value)+'</strong>'+
    nodeStatus(good,"Работает","Требует проверки")+'</div>').join("")+'</div>'+
    '<div class="security-ssh"><div class="node-panel-head"><h3>SSH · Fail2Ban</h3>'+
    (active?'<span class="node-state is-good">6 попыток / 10 мин · бан на 1 час</span>':
    '<span class="node-state is-bad">SSH jail не работает</span>')+'</div>';
  if(data.ssh_install_state)out+='<p class="security-reason">'+esc(labels[data.ssh_install_state]||data.ssh_install_state)+'</p>';
  if(!active){
    out+='<p class="muted small">Устанавливается только защита SSH. Конфигурация SSH, Docker, Nginx, Xray и правила Remnawave остаются без изменений.</p>';
    if(!modern)out+='<p class="muted small">Для управления защита требует Agent v1.4 или новее. Обнови его в разделе «Управление».</p>';
    else if(!ready)out+='<button class="btn subtle" data-security-helper>Подготовить управление SSH-защитой</button>'+
      '<p class="muted small">Для однократного обновления helper потребуется SSH root. Без изменения токена агента или VPN.</p>';
    else out+='<button class="btn primary" data-security-install>Установить Fail2Ban для SSH</button>';
  }else{
    out+='<p class="security-bans">Сейчас заблокировано: <strong>'+esc(data.sshd_banned_count??ips.length)+' IP</strong></p>'+
      '<h3>Активные блокировки</h3>'+
      (ips.length?ips.map(ip=>'<div class="security-ban-row"><code>'+esc(ip)+'</code>'+
      '<button class="btn subtle" data-security-unban="'+esc(ip)+'">Разблокировать</button></div>').join(""):
      '<p class="muted small">Нет заблокированных адресов.</p>')+
      '<h3>Последние события</h3>'+
      (history.length?history.slice(-15).reverse().map(item=>
      '<div class="security-history-row"><span>'+esc(item.action==="ban"?"Блокировка":"Разблокировка")+
      '</span><code>'+esc(item.ip)+'</code><small>'+esc(item.when)+'</small></div>').join(""):
      '<p class="muted small">В журнале пока нет событий Ban/Unban.</p>');
  }
  return out+'</div><p class="muted small security-foot">Диагностика VPS, а не предполагаемое состояние. Нет подтверждения — нет зелёного статуса.</p>';
}
async function securityReload(){
  if(selectedNodeTab==="network"&&selectedNodeId)await executeNodeTask("baseline.status");
}
async function prepareNodeSecurity(){
  const id=selectedNodeId,n=currentNode();if(!n)return;
  try{
    if(await nodeHasSavedSSH()){
      if(!confirm("Подготовить helper SSH-защиты на "+n.code+" через сохранённый SSH-доступ?"))return;
      await api("/agents/"+encodeURIComponent(id)+"/ssh-protection/helper","POST",{password:"",confirmed:true});
      message("Служебные файлы безопасности подготовлены.");return securityReload();
    }
    openModal("Подготовить SSH-защиту · "+n.code,"ОДНОКРАТНОЕ ОБНОВЛЕНИЕ HELPER",
      '<p class="muted small">SSH-пароль ещё не сохранён. Введи его один раз — Manager сохранит его зашифрованно. VPN и Agent не перезапускаются.</p>'+
      '<form><label>Пароль root SSH<input type="password" name="password" autocomplete="new-password" required></label>'+
      '<label class="check-row"><input type="checkbox" name="confirmed" required> Подтверждаю обновление helper</label>'+
      '<div class="form-buttons"><button type="submit" class="btn primary">Сохранить и подготовить</button></div></form>',
      async fd=>{
        await api("/nodes/"+encodeURIComponent(id)+"/ssh-access","PUT",{password:fd.get("password")});
        await api("/agents/"+encodeURIComponent(id)+"/ssh-protection/helper","POST",{password:"",confirmed:fd.get("confirmed")==="on"});
        message("SSH-доступ сохранён. Служебные файлы установлены.");await securityReload();
      });
  }catch(e){message(e.message,true)}
}
function installNodeSSHProtection(){
  const id=selectedNodeId,n=currentNode();if(!n)return;
  openModal("Fail2Ban для SSH · "+n.code,"ЗАЩИТА SSH / ПРОВЕРКА",
    '<p class="muted small">Введи публичный IPv4, с которого администрируешь VPS по SSH. Он будет исключён из блокировок. Устанавливается только jail SSH (6 ошибок за 10 минут, бан 1 час). SSH, порты, Docker и Remnawave не меняются.</p>'+
    '<form><label>Твой доверенный IPv4<input name="admin_ip" placeholder="Например, публичный IP компьютера" required inputmode="decimal"></label>'+
    '<label class="check-row"><input type="checkbox" name="confirmed" required> Подтверждаю установку Fail2Ban только для SSH</label>'+
    '<div class="form-buttons"><button class="btn primary" type="submit">Установить</button></div></form>',
    async fd=>{
      const job=await api("/agents/"+encodeURIComponent(id)+"/ssh-protection/install","POST",
        {admin_ip:String(fd.get("admin_ip")).trim(),confirmed:fd.get("confirmed")==="on"});
      await waitAgentTask(id,job.id);
      message("Настройка поставлена в очередь. Статус можно проверить на этой вкладке.");
      await securityReload();
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
