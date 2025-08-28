const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

const tabs = $$('.tabs button');
tabs.forEach(b=>b.onclick=()=>{ tabs.forEach(x=>x.classList.remove('active')); b.classList.add('active'); $$('.tab').forEach(x=>x.classList.remove('active')); $('#tab-'+b.dataset.tab).classList.add('active'); });

let CSRF = '';

$('#btn-refresh').onclick = refresh;

// Header actions
$$('header .actions button[data-act]').forEach(btn=>{
  btn.onclick = async () => {
    const act = btn.dataset.act;
    btn.disabled = true;
    try {
      await fetch('/api/control', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body: JSON.stringify({action: act})});
      toast(`Triggered: ${act}`);
    } catch(e) {
      console.error(e); toast(`Failed: ${act}`);
    } finally {
      btn.disabled = false;
    }
  };
});

function toast(msg){
  const t = document.createElement('div');
  t.textContent = msg;
  t.style.position='fixed'; t.style.right='14px'; t.style.bottom='14px';
  t.style.background='#0a1426'; t.style.border='1px solid #173764'; t.style.borderRadius='8px'; t.style.padding='8px 10px'; t.style.color='#cfe6ff'; t.style.zIndex=9999;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 2500);
}

async function api(path, opts){
  const r = await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}},opts||{}));
  if(r.status===401){
    showLogin(); throw new Error('unauthorized');
  }
  if(r.status===403){
    toast('Forbidden or CSRF'); throw new Error('forbidden');
  }
  if(!r.ok){ throw new Error('API error'); }
  return r;
}

function human(val, unit=''){ if(val===undefined || val===null) return '?'; return `${val}${unit}`; }
function setCard(id, text){ const el = $('#'+id); el.textContent = text; }

async function refresh(){
  try{
    const r = await api('/api/status'); const j = await r.json();
    CSRF = j.csrf || '';
    const cpu = j.cpu || {};
    setCard('cpu', `Load: ${human(cpu.load1)} | Level: ${cpu.level || 'OK'}`);
    const mem = j.memory || {};
    setCard('mem', `Used: ${human(mem.used_pct, '%')} | Warn: ${human(mem.warn, '%')} | Crit: ${human(mem.crit, '%')} | Level: ${mem.level || 'OK'}`);
    const dsk = j.disk || {};
    setCard('disk', `Mount: ${dsk.mount || '/'} | Used: ${human(dsk.use_pct, '%')} | Level: ${dsk.level || 'OK'}`);
    const net = j.network || {};
    setCard('net', `IP: ${net.ip || '?'} | Public: ${net.public_ip || '?'} | Loss: ${human(net.loss_pct, '%')} | RTT: ${human(net.rtt_avg_ms, 'ms')} | Level: ${net.level || 'OK'}`);
    setCard('int', `Integrity monitor active`);
    setCard('proc', `Process watch active`);
    setCard('user', `User sessions tracked`);
    setCard('svc', `Service checks ${j.services ? 'active' : 'n/a'}`);
    setCard('meta', `Projects: ${j.projects_count} | Modules: ${j.modules_count} | Version: ${j.version} | TS: ${j.ts}`);
    const ul = $('#alerts'); ul.innerHTML='';
    (j.alerts||[]).slice(-200).reverse().forEach(line=>{ const li=document.createElement('li'); li.textContent=line; ul.appendChild(li);});
    const levels = {cpu:j.cpu?.level, memory:j.memory?.level, disk:j.disk?.level, network:j.network?.level};
    const map = {OK:'ok', WARN:'warn', CRIT:'crit'};
    Object.entries(levels).forEach(([k,v])=>{
      const ids = {memory:'mem', disk:'disk', network:'net', cpu:'cpu'};
      const cardId = {memory:'card-mem', disk:'card-disk', network:'card-net', cpu:'card-cpu'}[k];
      const el = $('#'+cardId);
      if(!el) return; el.classList.remove('ok','warn','crit'); if(map[v]) el.classList.add(map[v]);
    });
    const conf = await (await api('/api/config')).text(); $('#config').textContent = conf;
  }catch(e){ console.error(e); }
}

// Monitors toggles
async function post(action,target){
  try{ await api('/api/control',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({action,target})}); toast(`${action} ${target}`); }catch(e){ toast('Action failed'); }
}
$$('.toggle').forEach(b=>{
  b.onclick=async()=>{
    const t=b.dataset.target;
    try{ await post('disable',t); await post('enable',t); refresh(); }catch(e){}
  };
});

// File Manager
$('#btn-list').onclick=()=>list($('#cwd').value);
async function list(dir){
  try{
    const j = await (await api('/api/fs?dir='+encodeURIComponent(dir.replace(/^~\//, (window.homedir||'')+'/')))).json();
    $('#cwd').value = j.dir;
    const wrap = $('#filelist'); wrap.innerHTML='';
    (j.entries||[]).forEach(e=>{
      const row = document.createElement('div');
      row.style.cursor='pointer';
      row.textContent = (e.is_dir?'[D] ':'[F] ') + e.name + (e.size?(' ('+e.size+'b)'):'');
      row.onclick = ()=>{
        if(e.is_dir){
          list(j.dir.replace(/\/+$/,'') + '/' + e.name);
        } else {
          viewFile(j.dir.replace(/\/+$/,'') + '/' + e.name);
        }
      };
      wrap.appendChild(row);
    });
  }catch(e){ console.error(e); toast('List failed'); }
}
async function viewFile(path){
  try{
    const j = await (await api('/api/fs_read?path='+encodeURIComponent(path))).json();
    if(!j.ok){ toast('Open failed'); return; }
    $('#viewer-title').textContent = `Viewer â€” ${j.path} (${j.size} bytes)`;
    $('#viewer-content').textContent = j.content || '';
    $('#viewer').style.display = '';
  }catch(e){ console.error(e); toast('Open failed'); }
}
$('#btn-mkdir').onclick=async()=>{
  const p=$('#newpath').value.trim(); if(!p) return;
  try{ await api('/api/fs_mkdir',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path:p})}); toast('mkdir ok'); list($('#cwd').value);}catch(e){toast('mkdir failed')}
}
$('#btn-save').onclick=async()=>{
  const p=$('#newpath').value.trim(); const c=$('#viewer-content').textContent;
  if(!p) return; try{ await api('/api/fs_write',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path:p,content:c})}); toast('saved'); list($('#cwd').value);}catch(e){toast('save failed')}
}

// Jarvis chat
$('#send').onclick=async()=>{
  const prompt = $('#prompt').value.trim(); if(!prompt) return;
  const log = $('#chatlog'); const you = document.createElement('div'); you.textContent='You: '+prompt; log.appendChild(you);
  try{
    const j = await (await api('/api/chat',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({prompt})})).json();
    const ai = document.createElement('div'); ai.textContent='Jarvis: '+j.reply; log.appendChild(ai); $('#prompt').value=''; log.scrollTop=log.scrollHeight;
  }catch(e){ console.error(e); }
};

// Web Terminal
let ws=null;
function connectTerm(){
  try{
    const proto = location.protocol==='https:'?'wss':'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/term`);
    const term = $('#term');
    term.textContent='';
    ws.binaryType='arraybuffer';
    ws.onopen=()=>{ term.focus(); toast('Terminal connected'); };
    ws.onmessage=(ev)=>{
      if(ev.data instanceof ArrayBuffer){
        const dec = new TextDecoder('utf-8',{fatal:false}); const txt = dec.decode(new Uint8Array(ev.data));
        term.textContent += txt; term.scrollTop = term.scrollHeight;
      }else{
        term.textContent += ev.data; term.scrollTop = term.scrollHeight;
      }
    };
    ws.onclose=()=>{ toast('Terminal closed'); ws=null; };
    term.onkeydown=(e)=>{
      if(!ws || ws.readyState!==1) return;
      e.preventDefault();
      let out='';
      if(e.key==='Enter') out='\r';
      else if(e.key==='Backspace') out='\x7f';
      else if(e.key==='Tab') out='\t';
      else if(e.key==='ArrowUp') out='\x1b[A';
      else if(e.key==='ArrowDown') out='\x1b[B';
      else if(e.key==='ArrowRight') out='\x1b[C';
      else if(e.key==='ArrowLeft') out='\x1b[D';
      else if(e.ctrlKey && e.key.toLowerCase()==='c') out='\x03';
      else if(e.ctrlKey && e.key.toLowerCase()==='d') out='\x04';
      else if(e.key.length===1) out=e.key;
      if(out){ ws.send(new TextEncoder().encode(out)); }
    };
  }catch(e){ console.error(e); toast('Terminal connection failed'); }
}
$('#tab-terminal').addEventListener('click', ()=>{ if(!ws) connectTerm(); });

function showLogin(){
  $('#login').style.display='';
}
$('#li-btn').onclick=async()=>{
  const user=$('#li-user').value.trim(), pass=$('#li-pass').value, otp=$('#li-otp').value.trim();
  try{
    const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'}, body:JSON.stringify({user,pass,otp})});
    if(r.ok){ const j=await r.json(); CSRF=j.csrf||''; $('#login').style.display='none'; refresh(); }
    else{ $('#li-msg').textContent='Login failed'; }
  }catch(e){ $('#li-msg').textContent='Login error'; }
};

refresh(); setInterval(refresh, 5000);
