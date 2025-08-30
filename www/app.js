const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

// Initialize tabs
const tabs = $$('.tabs button');
tabs.forEach(b=>b.onclick=()=>{ 
  tabs.forEach(x=>x.classList.remove('active')); 
  b.classList.add('active'); 
  $$('.tab').forEach(x=>x.classList.remove('active')); 
  $('#tab-'+b.dataset.tab).classList.add('active'); 
  
  // Load data when switching to specific tabs
  if(b.dataset.tab === 'admin') loadUsers();
  if(b.dataset.tab === 'webgen') loadPages();
});

let CSRF = '';
let currentFile = null;

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

function toast(msg, type='info'){
  const t = document.createElement('div');
  t.textContent = msg;
  t.style.position='fixed'; t.style.right='14px'; t.style.bottom='14px';
  t.style.background='#0a1426'; t.style.border='1px solid #173764'; t.style.borderRadius='8px'; 
  t.style.padding='8px 10px'; t.style.zIndex='9999';
  if(type==='error') { t.style.color='#ef4444'; t.style.borderColor='#dc2626'; }
  else if(type==='success') { t.style.color='#10b981'; t.style.borderColor='#059669'; }
  else { t.style.color='#cfe6ff'; }
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 3000);
}

function confirm(msg, callback) {
  if(window.confirm(msg)) callback();
}

async function api(path, opts){
  const r = await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}},opts||{}));
  if(r.status===401){
    showLogin(); throw new Error('unauthorized');
  }
  if(r.status===403){
    toast('Forbidden or CSRF', 'error'); throw new Error('forbidden');
  }
  if(!r.ok){ 
    const text = await r.text().catch(()=>'');
    let msg = 'API error';
    try { const j = JSON.parse(text); msg = j.error || msg; } catch(e) {}
    throw new Error(msg); 
  }
  return r;
}

function human(val, unit=''){ if(val===undefined || val===null) return '?'; return `${val}${unit}`; }
function setCard(id, text){ const el = $('#'+id); if(el) el.textContent = text; }

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
    
    const ul = $('#alerts'); if(ul) { ul.innerHTML=''; (j.alerts||[]).slice(-200).reverse().forEach(line=>{ const li=document.createElement('li'); li.textContent=line; ul.appendChild(li);}); }
    
    const levels = {cpu:j.cpu?.level, memory:j.memory?.level, disk:j.disk?.level, network:j.network?.level};
    const map = {OK:'ok', WARN:'warn', CRIT:'crit'};
    Object.entries(levels).forEach(([k,v])=>{
      const cardId = {memory:'card-mem', disk:'card-disk', network:'card-net', cpu:'card-cpu'}[k];
      const el = $('#'+cardId);
      if(!el) return; el.classList.remove('ok','warn','crit'); if(map[v]) el.classList.add(map[v]);
    });
    
    // Load config if on config tab
    if($('.tabs button[data-tab="config"]').classList.contains('active')) {
      const conf = await (await api('/api/config')).text(); 
      $('#config').value = conf;
    }
  }catch(e){ console.error(e); }
}

// Monitors toggles
async function post(action,target){
  try{ await api('/api/control',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({action,target})}); toast(`${action} ${target}`, 'success'); }catch(e){ toast('Action failed', 'error'); }
}
$$('.toggle').forEach(b=>{
  b.onclick=async()=>{
    const t=b.dataset.target;
    try{ await post('disable',t); await post('enable',t); refresh(); }catch(e){}
  };
});

// Enhanced File Manager
$('#btn-list').onclick=()=>list($('#cwd').value);
$('#btn-new-file').onclick=()=>{
  const name = prompt('File name:');
  if(name) createFile($('#cwd').value + '/' + name);
};
$('#btn-new-folder').onclick=()=>{
  const name = prompt('Folder name:');
  if(name) mkdir($('#cwd').value + '/' + name);
};

async function list(dir){
  try{
    let d = dir || '';
    if(d.trim().startsWith('~')) d='';
    const j = await (await api('/api/fs?dir='+encodeURIComponent(d))).json();
    $('#cwd').value = j.dir;
    const wrap = $('#filelist'); wrap.innerHTML='';
    
    // Add parent directory option
    if(j.dir !== '/home/runner/.novashield' && j.dir !== '') {
      const parent = document.createElement('div');
      parent.className = 'file-item';
      parent.innerHTML = '<span>[D] ..</span>';
      parent.onclick = ()=>{ 
        const parts = j.dir.split('/'); parts.pop(); 
        list(parts.join('/') || '/home/runner/.novashield'); 
      };
      wrap.appendChild(parent);
    }
    
    (j.entries||[]).forEach(e=>{
      const row = document.createElement('div');
      row.className = 'file-item';
      const actions = document.createElement('div');
      actions.style.display = 'flex';
      actions.style.gap = '5px';
      
      if(!e.is_dir) {
        const editBtn = document.createElement('button');
        editBtn.textContent = 'Edit';
        editBtn.style.fontSize = '11px';
        editBtn.style.padding = '2px 6px';
        editBtn.onclick = (e)=>{ e.stopPropagation(); viewFile(j.dir.replace(/\/+$/,'') + '/' + e.name); };
        actions.appendChild(editBtn);
      }
      
      const delBtn = document.createElement('button');
      delBtn.textContent = 'Del';
      delBtn.style.fontSize = '11px';
      delBtn.style.padding = '2px 6px';
      delBtn.style.background = '#dc2626';
      delBtn.onclick = (event)=>{ event.stopPropagation(); deleteItem(j.dir.replace(/\/+$/,'') + '/' + e.name); };
      actions.appendChild(delBtn);
      
      row.innerHTML = `<span>${e.is_dir?'[D] ':'[F] '}${e.name}${e.size?(' ('+e.size+'b)'):''}</span>`;
      row.appendChild(actions);
      row.onclick = ()=>{ if(e.is_dir){ list(j.dir.replace(/\/+$/,'') + '/' + e.name); } else { viewFile(j.dir.replace(/\/+$/,'') + '/' + e.name); } };
      wrap.appendChild(row);
    });
  }catch(e){ console.error(e); toast('List failed', 'error'); }
}

async function viewFile(path){
  try{
    const j = await (await api('/api/fs_read?path='+encodeURIComponent(path))).json();
    if(!j.ok){ toast('Open failed', 'error'); return; }
    currentFile = path;
    $('#viewer-title').textContent = `Editing: ${j.path} (${j.size} bytes)`;
    $('#viewer-content').value = j.content || '';
    $('#viewer').style.display = '';
  }catch(e){ console.error(e); toast('Open failed', 'error'); }
}

async function createFile(path) {
  try{
    await api('/api/fs_write',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path,content:''})});
    toast('File created', 'success'); 
    list($('#cwd').value);
    viewFile(path);
  }catch(e){toast('Create failed: ' + e.message, 'error')}
}

async function mkdir(path){
  try{
    await api('/api/fs_mkdir',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path})});
    toast('Folder created', 'success'); 
    list($('#cwd').value);
  }catch(e){toast('Mkdir failed: ' + e.message, 'error')}
}

async function deleteItem(path) {
  confirm(`Delete ${path}?`, async ()=>{
    try{
      await api('/api/fs_rm',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path})});
      toast('Deleted', 'success'); 
      list($('#cwd').value);
      if(currentFile === path) {
        $('#viewer').style.display = 'none';
        currentFile = null;
      }
    }catch(e){toast('Delete failed: ' + e.message, 'error')}
  });
}

$('#btn-save-file').onclick=async()=>{
  if(!currentFile) return;
  const content = $('#viewer-content').value;
  try{
    await api('/api/fs_write',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path:currentFile,content})});
    toast('File saved', 'success'); 
    list($('#cwd').value);
  }catch(e){toast('Save failed: ' + e.message, 'error')}
};

$('#btn-close-viewer').onclick=()=>{
  $('#viewer').style.display = 'none';
  currentFile = null;
};

$('#btn-delete-file').onclick=()=>{
  if(!currentFile) return;
  deleteItem(currentFile);
};

$('#btn-mkdir').onclick=()=>mkdir($('#newpath').value.trim());
$('#btn-save').onclick=async()=>{
  const p=$('#newpath').value.trim(); const c=$('#viewer-content').value;
  if(!p) return; 
  try{ 
    await api('/api/fs_write',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path:p,content:c})}); 
    toast('Saved to path', 'success'); 
    list($('#cwd').value);
  }catch(e){toast('Save failed: ' + e.message, 'error')}
};

// Jarvis chat
$('#send').onclick=async()=>{
  const prompt = $('#prompt').value.trim(); if(!prompt) return;
  const log = $('#chatlog'); const you = document.createElement('div'); you.textContent='You: '+prompt; log.appendChild(you);
  $('#prompt').value = '';
  try{
    const j = await (await api('/api/chat',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({prompt})})).json();
    const ai = document.createElement('div'); ai.textContent='Jarvis: '+j.reply; log.appendChild(ai); log.scrollTop=log.scrollHeight;
  }catch(e){ console.error(e); toast('Chat failed', 'error'); }
};
$('#prompt').addEventListener('keydown',e=>{ if(e.key==='Enter') $('#send').click(); });

// Web Terminal
let ws=null;
function connectTerm(){
  try{
    const proto = location.protocol==='https:'?'wss':'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/term`);
    const term = $('#term');
    term.textContent='Connecting...\n';
    ws.binaryType='arraybuffer';
    ws.onopen=()=>{ term.focus(); toast('Terminal connected', 'success'); };
    ws.onmessage=(ev)=>{
      if(ev.data instanceof ArrayBuffer){
        const dec = new TextDecoder('utf-8',{fatal:false}); 
        const txt = dec.decode(new Uint8Array(ev.data));
        term.textContent += txt; term.scrollTop = term.scrollHeight;
      }else{
        term.textContent += ev.data; term.scrollTop = term.scrollHeight;
      }
    };
    ws.onclose=()=>{ toast('Terminal closed', 'warning'); ws=null; };
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
  }catch(e){ console.error(e); toast('Terminal connection failed', 'error'); }
}
$('#tab-terminal').addEventListener('click', ()=>{ if(!ws) connectTerm(); });

// Website Builder
$('#wmake').onclick = async()=>{
  const title = $('#wtitle').value.trim();
  const content = $('#wcontent').value.trim();
  if(!title) { toast('Title required', 'error'); return; }
  try{
    const j = await (await api('/api/webgen',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({title,content})})).json();
    $('#wresult').innerHTML = `<a href="${j.page}" target="_blank">View: ${j.page}</a>`;
    toast('Page created', 'success');
    loadPages();
  }catch(e){ toast('Page creation failed: ' + e.message, 'error'); }
};

async function loadPages() {
  try{
    const r = await api('/api/site_pages');
    const pages = await r.json();
    const list = $('#page-list');
    list.innerHTML = '';
    pages.forEach(page => {
      const item = document.createElement('div');
      item.className = 'page-item';
      item.innerHTML = `
        <span>${page}</span>
        <div class="page-actions">
          <button onclick="editPage('${page}')">Edit</button>
          <button onclick="deletePage('${page}')" style="background:#dc2626;">Delete</button>
        </div>
      `;
      list.appendChild(item);
    });
  }catch(e){ console.error(e); }
}

async function editPage(page) {
  try{
    const r = await api(`/api/site_read?page=${encodeURIComponent(page)}`);
    const data = await r.json();
    $('#wtitle').value = data.title || page.replace('.html','');
    $('#wcontent').value = data.content || '';
    toast('Page loaded for editing', 'success');
  }catch(e){ toast('Failed to load page', 'error'); }
}

async function deletePage(page) {
  confirm(`Delete page ${page}?`, async ()=>{
    try{
      await api('/api/site_delete',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({page})});
      toast('Page deleted', 'success');
      loadPages();
    }catch(e){ toast('Delete failed: ' + e.message, 'error'); }
  });
}

// Config Editor
$('#btn-save-config').onclick = async()=>{
  const content = $('#config').value;
  try{
    await api('/api/config_save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({content})});
    toast('Config saved', 'success');
    $('#config-msg').textContent = '';
  }catch(e){ 
    toast('Config save failed: ' + e.message, 'error');
    $('#config-msg').innerHTML = `<span class="error">Save failed: ${e.message}</span>`;
  }
};

$('#btn-reload-config').onclick = async()=>{
  try{
    const conf = await (await api('/api/config')).text(); 
    $('#config').value = conf;
    toast('Config reloaded', 'success');
  }catch(e){ toast('Reload failed', 'error'); }
};

$('#btn-validate-config').onclick = ()=>{
  const content = $('#config').value;
  try{
    // Basic YAML validation - check for common issues
    const lines = content.split('\n');
    let errors = [];
    lines.forEach((line, i) => {
      if(line.includes('\t')) errors.push(`Line ${i+1}: Use spaces, not tabs`);
      if(line.match(/^\s*-\s*[^-\s]/)) {
        // Check list item indentation
      }
    });
    if(errors.length > 0) {
      $('#config-msg').innerHTML = `<span class="warning">Warnings: ${errors.join('; ')}</span>`;
    } else {
      $('#config-msg').innerHTML = `<span class="success">YAML appears valid</span>`;
    }
  }catch(e){
    $('#config-msg').innerHTML = `<span class="error">Validation error: ${e.message}</span>`;
  }
};

// Admin Panel
$('#btn-add-user').onclick = async()=>{
  const username = $('#new-username').value.trim();
  const password = $('#new-password').value;
  if(!username || !password) { toast('Username and password required', 'error'); return; }
  try{
    await api('/api/admin/add_user',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({username,password})});
    toast('User added', 'success');
    $('#new-username').value = '';
    $('#new-password').value = '';
    loadUsers();
  }catch(e){ toast('Add user failed: ' + e.message, 'error'); }
};

async function loadUsers() {
  try{
    const r = await api('/api/admin/users');
    const users = await r.json();
    const list = $('#user-list');
    list.innerHTML = '';
    users.forEach(user => {
      const item = document.createElement('div');
      item.className = 'user-item';
      item.innerHTML = `
        <span>${user.username}</span>
        <div class="user-actions">
          <button onclick="resetPassword('${user.username}')">Reset Password</button>
          <button onclick="toggle2FA('${user.username}', ${user.has_2fa})">${user.has_2fa ? 'Disable' : 'Enable'} 2FA</button>
          <button onclick="deleteUser('${user.username}')" style="background:#dc2626;">Delete</button>
        </div>
      `;
      list.appendChild(item);
    });
  }catch(e){ console.error(e); }
}

async function resetPassword(username) {
  const newPass = prompt(`New password for ${username}:`);
  if(!newPass) return;
  try{
    await api('/api/admin/reset_password',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({username,password:newPass})});
    toast('Password reset', 'success');
  }catch(e){ toast('Reset failed: ' + e.message, 'error'); }
}

async function toggle2FA(username, currently_enabled) {
  try{
    const action = currently_enabled ? 'disable' : 'enable';
    const r = await api('/api/admin/toggle_2fa',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({username,action})});
    const result = await r.json();
    if(action === 'enable' && result.secret) {
      alert(`2FA enabled. Secret: ${result.secret}\nAdd this to your authenticator app.`);
    }
    toast(`2FA ${action}d for ${username}`, 'success');
    loadUsers();
  }catch(e){ toast('2FA toggle failed: ' + e.message, 'error'); }
}

async function deleteUser(username) {
  confirm(`Delete user ${username}?`, async ()=>{
    try{
      await api('/api/admin/delete_user',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({username})});
      toast('User deleted', 'success');
      loadUsers();
    }catch(e){ toast('Delete failed: ' + e.message, 'error'); }
  });
}

// Backup & Restore and Notifications
$('#btn-backup-restore').onclick = async()=>{
  try{
    const r = await api('/api/admin/backup_restore');
    const data = await r.json();
    alert(`Backup Status:\n${JSON.stringify(data, null, 2)}`);
  }catch(e){ toast('Backup info failed', 'error'); }
};

$('#btn-notification-setup').onclick = async()=>{
  try{
    const r = await api('/api/admin/notifications');
    const data = await r.json();
    alert(`Notification Setup:\n${JSON.stringify(data, null, 2)}`);
  }catch(e){ toast('Notification info failed', 'error'); }
};

// Login modal
function showLogin(){
  $('#login').style.display='';
}

$('#li-btn').onclick=async()=>{
  const user=$('#li-user').value.trim(), pass=$('#li-pass').value, otp=$('#li-otp').value.trim();
  if(!user || !pass) { $('#li-msg').textContent='Username and password required'; return; }
  $('#li-btn').disabled = true;
  $('#li-msg').textContent = 'Signing in...';
  try{
    const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'}, body:JSON.stringify({user,pass,otp})});
    if(r.ok){ 
      const j=await r.json(); 
      CSRF=j.csrf||''; 
      $('#login').style.display='none'; 
      toast('Logged in', 'success');
      refresh(); 
    } else { 
      const err = await r.json().catch(()=>({}));
      $('#li-msg').textContent = err.need_2fa ? '2FA required/invalid' : 'Login failed'; 
    }
  }catch(e){ 
    $('#li-msg').textContent='Login error: ' + e.message; 
  }
  $('#li-btn').disabled = false;
};

// Auto-refresh and initialization
refresh(); 
setInterval(refresh, 10000); // Reduced frequency to 10s

// Initialize file manager
setTimeout(()=>list(''), 1000);
