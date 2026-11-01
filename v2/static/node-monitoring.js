"use strict";
// Live node monitoring. This is intentionally isolated from management/configuration tabs:
// the fast refresh timer only calls refreshNodeMonitoring while this tab is open.
let nodeMonitoringRange=3600;
let nodeMonitoringSamples=[];
let nodeMonitoringBusy=false;
let nodeMonitoringLastNode="";

const monitorNumber=v=>typeof v==="number"&&Number.isFinite(v)?v:null;
const monitorPercent=(used,total)=>total>0?Math.max(0,Math.min(100,used/total*100)):null;
const monitorPctText=v=>v===null?"—":v.toLocaleString("ru-RU",{maximumFractionDigits:1})+"%";
const monitorRateText=v=>{
  if(v===null)return "—";
  if(v>=1)return v.toLocaleString("ru-RU",{maximumFractionDigits:2})+" Мбит/с";
  if(v>=.001)return (v*1000).toLocaleString("ru-RU",{maximumFractionDigits:1})+" Кбит/с";
  return (v*1e6).toLocaleString("ru-RU",{maximumFractionDigits:0})+" бит/с";
};
const monitorTime=ts=>new Date(ts*1000).toLocaleTimeString("ru-RU",{hour:"2-digit",minute:"2-digit",second:"2-digit"});

function nodeMonitoringBody(n,a){
  return '<div class="node-monitoring">'+
    '<div class="node-panel monitor-head"><div class="node-panel-head"><div><h2>Мониторинг ноды</h2>'+
    '<p class="muted small">Живая телеметрия Agent. Быстрое обновление работает только в этой вкладке.</p></div>'+
    '<div class="monitor-range" role="group" aria-label="Диапазон графиков">'+
    [[900,"15 мин"],[3600,"1 час"],[21600,"6 часов"]].map(([seconds,label])=>
      '<button class="btn subtle '+(nodeMonitoringRange===seconds?'active':'')+'" type="button" data-monitor-range="'+seconds+'">'+label+'</button>').join("")+
    '</div></div>'+
    '<div class="monitor-live-line"><span id="monitor-agent-state" class="node-state '+(a.online?'is-good':'')+'">'+
    (a.online?'Agent онлайн':'Agent офлайн')+'</span><span id="monitor-last-seen" class="muted small">'+
    (a.last_seen?'Heartbeat '+esc(nodeTime(a.last_seen)):'Heartbeat ещё не получен')+'</span>'+
    '<span class="muted small">Обновление: '+esc((monitoringMs/1000).toLocaleString("ru-RU"))+' сек.</span></div></div>'+
    '<div class="monitor-kpis">'+
      '<div class="monitor-kpi"><small>CPU</small><strong id="monitor-cpu">—</strong><span>Загрузка процессора</span></div>'+
      '<div class="monitor-kpi"><small>RAM</small><strong id="monitor-ram">—</strong><span id="monitor-ram-note">Использование памяти</span></div>'+
      '<div class="monitor-kpi"><small>Диск</small><strong id="monitor-disk">—</strong><span id="monitor-disk-note">Корневой раздел</span></div>'+
      '<div class="monitor-kpi"><small>Сеть ↓ / ↑</small><strong id="monitor-network">—</strong><span id="monitor-network-note">Текущая скорость</span></div>'+
      '<div class="monitor-kpi"><small>TCP</small><strong id="monitor-tcp">—</strong><span>Установленные соединения</span></div>'+
    '</div>'+
    '<div class="monitor-grid">'+
      monitorChartShell("monitor-chart-resources","CPU / RAM / диск","Проценты, 0–100%")+
      monitorChartShell("monitor-chart-network","Сетевой трафик","Входящая и исходящая скорость")+
      monitorChartShell("monitor-chart-tcp","TCP-соединения","Текущее количество established")+
      monitorChartShell("monitor-chart-retrans","TCP retransmits","Повторные передачи в секунду")+
    '</div>'+
    '<p id="monitor-empty-note" class="muted small">Загружаем историю телеметрии…</p>'+
  '</div>';
}

function monitorChartShell(id,title,note){
  return '<section class="node-panel monitor-chart-card"><div class="monitor-chart-head"><div><h3>'+esc(title)+
    '</h3><span>'+esc(note)+'</span></div></div><div class="monitor-chart" id="'+id+'">'+
    '<div class="monitor-chart-empty">Нет данных</div></div></section>';
}

function monitoringRows(){
  let previous=null;
  return nodeMonitoringSamples.map(sample=>{
    const m=sample.metrics||{};
    const total=monitorNumber(m.MemTotal_bytes),available=monitorNumber(m.MemAvailable_bytes);
    const diskTotal=monitorNumber(m.disk_total_bytes),diskAvailable=monitorNumber(m.disk_available_bytes);
    let retransRate=null;
    const retrans=monitorNumber(m.tcp_retrans_segs);
    if(previous&&retrans!==null&&previous.retrans!==null&&sample.ts>previous.ts&&retrans>=previous.retrans){
      retransRate=(retrans-previous.retrans)/(sample.ts-previous.ts);
    }
    const row={ts:sample.ts,
      cpu:monitorNumber(m.cpu_percent),
      ram:total!==null&&available!==null?monitorPercent(total-available,total):null,
      disk:diskTotal!==null&&diskAvailable!==null?monitorPercent(diskTotal-diskAvailable,diskTotal):null,
      rx:monitorNumber(m.net_rx_mbps),tx:monitorNumber(m.net_tx_mbps),
      tcp:monitorNumber(m.tcp_established),retransRate,
      memTotal:total,memAvailable:available,diskTotal,diskAvailable,
      iface:String(m.net_interface||"")};
    previous={ts:sample.ts,retrans};
    return row;
  });
}

function mergeMonitoringSamples(incoming){
  const map=new Map(nodeMonitoringSamples.map(x=>[Number(x.ts),x]));
  for(const item of incoming||[]){
    const ts=Number(item.ts);
    if(Number.isFinite(ts)&&item.metrics&&typeof item.metrics==="object")map.set(ts,{ts,metrics:item.metrics});
  }
  const cutoff=Math.floor(Date.now()/1000)-nodeMonitoringRange;
  nodeMonitoringSamples=[...map.values()].filter(x=>x.ts>=cutoff).sort((a,b)=>a.ts-b.ts);
  // Hard browser-side cap protects the UI even if an API regression returns too much.
  if(nodeMonitoringSamples.length>5000)nodeMonitoringSamples=nodeMonitoringSamples.slice(-5000);
}

function setMonitorText(id,value){
  const el=$(id);if(el)el.textContent=value;
}

function renderNodeMonitoring(data){
  if(selectedNodeTab!=="monitor"||!selectedNodeId)return;
  const rows=monitoringRows(),latest=rows[rows.length-1]||null;
  const stateEl=$("monitor-agent-state");
  if(stateEl){
    stateEl.className="node-state "+(data.online?"is-good":"is-bad");
    stateEl.textContent=data.online?"Agent онлайн":"Agent офлайн";
  }
  setMonitorText("monitor-last-seen",data.last_seen?"Heartbeat "+nodeTime(data.last_seen):"Heartbeat ещё не получен");
  if(latest){
    setMonitorText("monitor-cpu",latest.cpu===null?"Ожидаем Agent 1.6":monitorPctText(latest.cpu));
    setMonitorText("monitor-ram",monitorPctText(latest.ram));
    setMonitorText("monitor-disk",monitorPctText(latest.disk));
    setMonitorText("monitor-network",monitorRateText(latest.rx)+" / "+monitorRateText(latest.tx));
    setMonitorText("monitor-tcp",latest.tcp===null?"—":latest.tcp.toLocaleString("ru-RU"));
    setMonitorText("monitor-ram-note",latest.memTotal?nodeSize(latest.memTotal)+" всего":"Использование памяти");
    setMonitorText("monitor-disk-note",latest.diskTotal?nodeSize(latest.diskTotal)+" всего":"Корневой раздел");
    setMonitorText("monitor-network-note",(latest.iface?"Интерфейс "+latest.iface+" · ":"")+"↓ / ↑");
  }
  const note=$("monitor-empty-note");
  if(note)note.textContent=rows.length<2?"Для графиков нужны минимум два замера. Оставь вкладку открытой на несколько секунд.":"Хранится до 6 часов истории; точки в базе не чаще одного раза в 5 секунд.";
  drawMonitoringChart("monitor-chart-resources",rows,[
    {key:"cpu",label:"CPU",className:"series-a"},
    {key:"ram",label:"RAM",className:"series-b"},
    {key:"disk",label:"Диск",className:"series-c"}
  ],{min:0,max:100,suffix:"%"});
  drawMonitoringChart("monitor-chart-network",rows,[
    {key:"rx",label:"Вход",className:"series-a"},
    {key:"tx",label:"Выход",className:"series-b"}
  ],{min:0,suffix:" Мбит/с"});
  drawMonitoringChart("monitor-chart-tcp",rows,[
    {key:"tcp",label:"TCP",className:"series-a"}
  ],{min:0,integer:true});
  drawMonitoringChart("monitor-chart-retrans",rows,[
    {key:"retransRate",label:"Retransmits",className:"series-c"}
  ],{min:0,suffix:"/с"});
}

function drawMonitoringChart(id,rows,series,options={}){
  const box=$(id);if(!box)return;
  const usable=rows.filter(row=>series.some(s=>monitorNumber(row[s.key])!==null));
  if(usable.length<2){box.innerHTML='<div class="monitor-chart-empty">Недостаточно данных</div>';return}
  const width=900,height=245,left=54,right=18,top=18,bottom=34;
  const plotW=width-left-right,plotH=height-top-bottom;
  const minX=usable[0].ts,maxX=usable[usable.length-1].ts||minX+1;
  const values=[];
  for(const row of usable)for(const item of series){const v=monitorNumber(row[item.key]);if(v!==null)values.push(v)}
  let minY=options.min??Math.min(...values),maxY=options.max??Math.max(...values);
  if(!Number.isFinite(minY))minY=0;
  if(!Number.isFinite(maxY)||maxY<=minY)maxY=minY+1;
  if(options.max===undefined)maxY*=1.12;
  const x=ts=>left+((ts-minX)/Math.max(1,maxX-minX))*plotW;
  const y=value=>top+(1-(value-minY)/(maxY-minY))*plotH;
  let svg='<svg viewBox="0 0 '+width+' '+height+'" role="img" aria-label="График мониторинга">';
  for(let i=0;i<=4;i++){
    const gy=top+plotH*i/4,value=maxY-(maxY-minY)*i/4;
    svg+='<line class="monitor-grid-line" x1="'+left+'" y1="'+gy+'" x2="'+(width-right)+'" y2="'+gy+'"></line>'+
      '<text class="monitor-axis-label" x="'+(left-8)+'" y="'+(gy+4)+'" text-anchor="end">'+
      esc(formatMonitorAxis(value,options))+'</text>';
  }
  for(const item of series){
    let d="",started=false;
    for(const row of usable){
      const value=monitorNumber(row[item.key]);
      if(value===null){started=false;continue}
      d+=(started?" L ":" M ")+x(row.ts).toFixed(2)+" "+y(value).toFixed(2);started=true;
    }
    svg+='<path class="monitor-line '+item.className+'" d="'+d+'"></path>';
  }
  const ticks=[minX,minX+(maxX-minX)/2,maxX];
  for(const ts of ticks)svg+='<text class="monitor-axis-time" x="'+x(ts)+'" y="'+(height-8)+'" text-anchor="'+
    (ts===minX?"start":ts===maxX?"end":"middle")+'">'+esc(monitorTime(ts))+'</text>';
  svg+='</svg><div class="monitor-legend">'+series.map(item=>
    '<span><i class="'+item.className+'"></i>'+esc(item.label)+'</span>').join("")+'</div>';
  box.innerHTML=svg;
}

function formatMonitorAxis(value,options){
  if(options.integer)return Math.round(value).toLocaleString("ru-RU");
  const digits=Math.abs(value)<10?1:0;
  return value.toLocaleString("ru-RU",{maximumFractionDigits:digits})+(options.suffix||"");
}

async function refreshNodeMonitoring(reset=false){
  if(nodeMonitoringBusy||selectedNodeTab!=="monitor"||!selectedNodeId)return;
  const id=selectedNodeId;
  if(nodeMonitoringLastNode!==id){nodeMonitoringLastNode=id;reset=true}
  if(reset)nodeMonitoringSamples=[];
  nodeMonitoringBusy=true;
  try{
    const last=nodeMonitoringSamples.length?nodeMonitoringSamples[nodeMonitoringSamples.length-1].ts:0;
    const since=reset?0:Math.max(0,last-10);
    const data=await api("/agents/"+encodeURIComponent(id)+"/monitoring?seconds="+nodeMonitoringRange+"&since="+since);
    if(id!==selectedNodeId||selectedNodeTab!=="monitor")return;
    mergeMonitoringSamples(data.samples||[]);
    renderNodeMonitoring(data);
  }catch(e){
    const note=$("monitor-empty-note");if(note)note.textContent=e.message;
  }finally{nodeMonitoringBusy=false}
}

function setNodeMonitoringRange(seconds){
  const value=Number(seconds);
  if(![900,3600,21600].includes(value))return;
  nodeMonitoringRange=value;
  document.querySelectorAll("[data-monitor-range]").forEach(btn=>btn.classList.toggle("active",Number(btn.dataset.monitorRange)===value));
  refreshNodeMonitoring(true);
}
