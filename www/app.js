const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

// Global state
let CSRF = '';
let loginAttempts = 0;
let isLoggedIn = false;
let refreshInterval = null;

// Tab management
const tabs = $$('.tabs button');
tabs.forEach(b=>b.onclick=()=>{ 
  tabs.forEach(x=>x.classList.remove('active')); 
  b.classList.add('active'); 
  $$('.tab').forEach(x=>x.classList.remove('active')); 
  $('#tab-'+b.dataset.tab).classList.add('active'); 
  
  // Load content for specific tabs
  const tab = b.dataset.tab;
  if(tab === 'config') loadConfig();
  else if(tab === 'admin') loadAdminData();
  else if(tab === 'webgen') loadPages();
});

// Loading indicator
function showLoading(text = 'Loading...') {
  const loading = $('#loading');
  if(loading) {
    $('#loading .loading-text').textContent = text;
    loading.style.display = '';
  }
}

function hideLoading() {
  const loading = $('#loading');
  if(loading) loading.style.display = 'none';
}

// Enhanced toast with types
function toast(msg, type = 'info'){
  const t = document.createElement('div');
  t.textContent = msg;
  t.style.position='fixed'; t.style.right='14px'; t.style.bottom='14px';
  t.style.borderRadius='8px'; t.style.padding='8px 10px'; t.style.zIndex=9999;
  t.style.minWidth='200px'; t.style.textAlign='center';
  
  if(type === 'error') {
    t.style.background='#441b1b'; t.style.border='1px solid #ef4444'; t.style.color='#fca5a5';
  } else if(type === 'success') {
    t.style.background='#1a3d29'; t.style.border='1px solid #10b981'; t.style.color='#86efac';
  } else if(type === 'warning') {
    t.style.background='#3d2c1a'; t.style.border='1px solid #f59e0b'; t.style.color='#fbbf24';
  } else {
    t.style.background='#0a1426'; t.style.border='1px solid #173764'; t.style.color='#cfe6ff';
  }
  
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), type === 'error' ? 4000 : 2500);
}

// Enhanced API with better error handling
async function api(path, opts = {}){
  try {
    const headers = {
      'Content-Type': 'application/json',
      ...((opts.headers || {}))
    };
    if(CSRF) headers['X-CSRF'] = CSRF;
    
    const response = await fetch(path, {
      ...opts,
      headers
    });
    
    if(response.status === 401) {
      isLoggedIn = false;
      showLogin();
      throw new Error('Unauthorized - please login');
    }
    
    if(response.status === 403) {
      toast('Access forbidden or CSRF token invalid', 'error');
      throw new Error('Forbidden');
    }
    
    if(response.status === 429) {
      toast('Rate limit exceeded - please wait', 'warning');
      throw new Error('Rate limited');
    }
    
    if(!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      throw new Error(`API Error (${response.status}): ${errorText}`);
    }
    
    return response;
  } catch(error) {
    console.error('API Error:', error);
    throw error;
  }
}

// Utility functions
function human(val, unit=''){ 
  if(val === undefined || val === null) return '?'; 
  if(typeof val === 'number' && unit === '%') return `${val.toFixed(1)}${unit}`;
  if(typeof val === 'number' && unit === 'ms') return `${val.toFixed(0)}${unit}`;
  return `${val}${unit}`; 
}

function setCard(id, text){ 
  const el = $('#'+id); 
  if(el) el.textContent = text; 
}

// Enhanced refresh with error handling
async function refresh(){
  try{
    showLoading('Refreshing status...');
    const r = await api('/api/status');
    const j = await r.json();
    
    CSRF = j.csrf || '';
    isLoggedIn = true;
    
    // Update system metrics
    const cpu = j.cpu || {};
    setCard('cpu', `Load: ${human(cpu.load1)} | Level: ${cpu.level || 'OK'}`);
    
    const mem = j.memory || {};
    setCard('mem', `Used: ${human(mem.used_pct, '%')} | Warn: ${human(mem.warn, '%')} | Crit: ${human(mem.crit, '%')} | Level: ${mem.level || 'OK'}`);
    
    const dsk = j.disk || {};
    setCard('disk', `Mount: ${dsk.mount || '/'} | Used: ${human(dsk.use_pct, '%')} | Level: ${dsk.level || 'OK'}`);
    
    const net = j.network || {};
    setCard('net', `IP: ${net.ip || '?'} | Public: ${net.public_ip || '?'} | Loss: ${human(net.loss_pct, '%')} | RTT: ${human(net.rtt_avg_ms, 'ms')} | Level: ${net.level || 'OK'}`);
    
    setCard('int', `Integrity monitor ${j.integrity_active ? 'active' : 'inactive'}`);
    setCard('proc', `Process watch ${j.process_active ? 'active' : 'inactive'}`);
    setCard('user', `User sessions: ${j.user_sessions || 0}`);
    setCard('svc', `Service checks ${j.services ? 'active' : 'n/a'}`);
    setCard('meta', `Projects: ${j.projects_count || 0} | Modules: ${j.modules_count || 0} | Version: ${j.version || '?'} | TS: ${j.ts || '?'}`);
    
    // Update alerts
    const ul = $('#alerts'); 
    if(ul) {
      ul.innerHTML='';
      (j.alerts||[]).slice(-200).reverse().forEach(line=>{
        const li=document.createElement('li'); 
        li.textContent=line; 
        ul.appendChild(li);
      });
    }
    
    // Update card status colors
    const levels = {cpu:j.cpu?.level, memory:j.memory?.level, disk:j.disk?.level, network:j.network?.level};
    const map = {OK:'ok', WARN:'warn', CRIT:'crit'};
    Object.entries(levels).forEach(([k,v])=>{
      const cardId = {memory:'card-mem', disk:'card-disk', network:'card-net', cpu:'card-cpu'}[k];
      const el = $('#'+cardId);
      if(!el) return; 
      el.classList.remove('ok','warn','crit'); 
      if(map[v]) el.classList.add(map[v]);
    });
    
    hideLoading();
  } catch(e) { 
    console.error('Refresh failed:', e);
    hideLoading();
    if(e.message.includes('Unauthorized')) {
      // Don't show error for auth failures, showLogin() handles it
      return;
    }
    toast('Failed to refresh status: ' + e.message, 'error'); 
  }
}

// Header action buttons
$('#btn-refresh').onclick = refresh;

$$('header .actions button[data-act]').forEach(btn=>{
  btn.onclick = async () => {
    const act = btn.dataset.act;
    btn.disabled = true;
    try {
      showLoading(`Executing ${act}...`);
      await api('/api/control', {
        method:'POST', 
        body: JSON.stringify({action: act})
      });
      toast(`Successfully triggered: ${act}`, 'success');
    } catch(e) {
      console.error(e); 
      toast(`Failed to execute ${act}: ${e.message}`, 'error');
    } finally {
      btn.disabled = false;
      hideLoading();
    }
  };
});

// Monitor toggles
async function post(action, target){
  return await api('/api/control', {
    method:'POST', 
    body:JSON.stringify({action, target})
  });
}

$$('.toggle').forEach(b=>{
  b.onclick=async()=>{
    const t=b.dataset.target;
    b.disabled = true;
    try{ 
      await post('disable',t); 
      await post('enable',t); 
      toast(`Restarted ${t}`, 'success');
      refresh(); 
    } catch(e) {
      toast(`Failed to restart ${t}: ${e.message}`, 'error');
    } finally {
      b.disabled = false;
    }
  };
});

// Enhanced File Manager
$('#btn-list').onclick=()=>list($('#cwd').value);

async function list(dir){
  try{
    showLoading('Loading directory...');
    let d = dir || '';
    if(d.trim().startsWith('~')) d='';
    const j = await (await api('/api/fs?dir='+encodeURIComponent(d))).json();
    $('#cwd').value = j.dir;
    const wrap = $('#filelist'); 
    wrap.innerHTML='';
    
    // Add parent directory link
    if(j.dir !== '/home/runner/.novashield') {
      const parentRow = document.createElement('div');
      parentRow.style.cursor='pointer';
      parentRow.style.color='#93a3c0';
      parentRow.textContent = '[D] ..';
      parentRow.onclick = ()=>{ 
        const parent = j.dir.split('/').slice(0,-1).join('/') || '/';
        list(parent); 
      };
      wrap.appendChild(parentRow);
    }
    
    (j.entries||[]).forEach(e=>{
      const row = document.createElement('div');
      row.style.cursor='pointer';
      row.style.padding='4px';
      row.style.borderRadius='4px';
      row.textContent = (e.is_dir?'[D] ':'[F] ') + e.name + (e.size?(' ('+e.size+'b)'):'');
      row.onclick = ()=>{ 
        if(e.is_dir){ 
          list(j.dir.replace(/\/+$/,'') + '/' + e.name); 
        } else { 
          viewFile(j.dir.replace(/\/+$/,'') + '/' + e.name); 
        } 
      };
      row.onmouseenter = ()=> row.style.background='#112540';
      row.onmouseleave = ()=> row.style.background='transparent';
      wrap.appendChild(row);
    });
    hideLoading();
  }catch(e){ 
    console.error(e); 
    hideLoading();
    toast('Failed to list directory: ' + e.message, 'error'); 
  }
}

async function viewFile(path){
  try{
    showLoading('Loading file...');
    const j = await (await api('/api/fs_read?path='+encodeURIComponent(path))).json();
    if(!j.ok){ 
      hideLoading();
      toast('Failed to open file: ' + (j.error || 'Unknown error'), 'error'); 
      return; 
    }
    $('#viewer-title').textContent = `Viewer — ${j.path} (${j.size} bytes)`;
    $('#viewer-content').textContent = j.content || '';
    $('#newpath').value = path; // Set current file path for saving
    $('#viewer').style.display = '';
    hideLoading();
  }catch(e){ 
    console.error(e); 
    hideLoading();
    toast('Failed to open file: ' + e.message, 'error'); 
  }
}

// File operations
$('#btn-mkdir').onclick=async()=>{
  const p=$('#newpath').value.trim(); 
  if(!p) {
    toast('Please enter a path', 'warning');
    return;
  }
  try{ 
    await api('/api/fs_mkdir',{
      method:'POST', 
      body:JSON.stringify({path:p})
    }); 
    toast('Directory created successfully', 'success'); 
    list($('#cwd').value);
  } catch(e) {
    toast('Failed to create directory: ' + e.message, 'error');
  }
}

$('#btn-save').onclick=async()=>{
  const p=$('#newpath').value.trim(); 
  const c=$('#viewer-content').textContent;
  if(!p) {
    toast('Please enter a file path', 'warning');
    return;
  }
  try{ 
    await api('/api/fs_write',{
      method:'POST', 
      body:JSON.stringify({path:p,content:c})
    }); 
    toast('File saved successfully', 'success'); 
    list($('#cwd').value);
  } catch(e) {
    toast('Failed to save file: ' + e.message, 'error');
  }
}

$('#btn-delete').onclick=async()=>{
  const p=$('#newpath').value.trim(); 
  if(!p) {
    toast('Please enter a path to delete', 'warning');
    return;
  }
  if(!confirm(`Are you sure you want to delete: ${p}?`)) return;
  
  try{ 
    await api('/api/fs_rm',{
      method:'POST', 
      body:JSON.stringify({path:p})
    }); 
    toast('Item deleted successfully', 'success'); 
    list($('#cwd').value);
    $('#viewer').style.display = 'none';
  } catch(e) {
    toast('Failed to delete: ' + e.message, 'error');
  }
}

$('#btn-rename').onclick=async()=>{
  const p=$('#newpath').value.trim(); 
  if(!p) {
    toast('Please enter the current path', 'warning');
    return;
  }
  const newName = prompt('Enter new name:');
  if(!newName) return;
  
  const newPath = p.split('/').slice(0,-1).concat(newName).join('/');
  try{ 
    await api('/api/fs_mv',{
      method:'POST', 
      body:JSON.stringify({src:p, dst:newPath})
    }); 
    toast('Item renamed successfully', 'success'); 
    list($('#cwd').value);
    $('#newpath').value = newPath;
  } catch(e) {
    toast('Failed to rename: ' + e.message, 'error');
  }
}

$('#btn-move').onclick=async()=>{
  const p=$('#newpath').value.trim(); 
  if(!p) {
    toast('Please enter the source path', 'warning');
    return;
  }
  const destPath = prompt('Enter destination path:');
  if(!destPath) return;
  
  try{ 
    await api('/api/fs_mv',{
      method:'POST', 
      body:JSON.stringify({src:p, dst:destPath})
    }); 
    toast('Item moved successfully', 'success'); 
    list($('#cwd').value);
    $('#newpath').value = destPath;
  } catch(e) {
    toast('Failed to move: ' + e.message, 'error');
  }
}

// AI Chat
$('#send').onclick=async()=>{
  const prompt = $('#prompt').value.trim(); 
  if(!prompt) return;
  
  const log = $('#chatlog'); 
  const you = document.createElement('div'); 
  you.textContent='You: '+prompt; 
  you.style.marginBottom='8px';
  you.style.color='#d7e3ff';
  log.appendChild(you);
  
  $('#prompt').value = '';
  
  try{
    const j = await (await api('/api/chat',{
      method:'POST',
      body:JSON.stringify({prompt})
    })).json();
    
    const ai = document.createElement('div'); 
    ai.textContent='Jarvis: '+j.reply; 
    ai.style.marginBottom='8px';
    ai.style.color='#86efac';
    log.appendChild(ai); 
    log.scrollTop=log.scrollHeight;
  }catch(e){ 
    console.error(e);
    const error = document.createElement('div'); 
    error.textContent='Jarvis: Sorry, I encountered an error.'; 
    error.style.marginBottom='8px';
    error.style.color='#fca5a5';
    log.appendChild(error); 
    log.scrollTop=log.scrollHeight;
  }
};

$('#prompt').addEventListener('keydown', (e) => {
  if(e.key === 'Enter') $('#send').click();
});

// Web Terminal
let ws=null;

function connectTerm(){
  try{
    const proto = location.protocol==='https:'?'wss':'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/term`);
    const term = $('#term');
    term.textContent='Connecting to terminal...\n';
    ws.binaryType='arraybuffer';
    
    ws.onopen=()=>{ 
      term.focus(); 
      toast('Terminal connected', 'success'); 
      term.textContent = 'NovaShield Terminal Connected\n$ ';
    };
    
    ws.onmessage=(ev)=>{
      if(ev.data instanceof ArrayBuffer){
        const dec = new TextDecoder('utf-8',{fatal:false}); 
        const txt = dec.decode(new Uint8Array(ev.data));
        term.textContent += txt; 
        term.scrollTop = term.scrollHeight;
      } else {
        term.textContent += ev.data; 
        term.scrollTop = term.scrollHeight;
      }
    };
    
    ws.onclose=(ev)=>{ 
      toast('Terminal disconnected', 'warning'); 
      term.textContent += '\n[Connection closed]\n';
      ws=null; 
    };
    
    ws.onerror=(err)=>{
      console.error('WebSocket error:', err);
      toast('Terminal connection error', 'error');
    };
    
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
      
      if(out){ 
        ws.send(new TextEncoder().encode(out)); 
      }
    };
  }catch(e){ 
    console.error(e); 
    toast('Terminal connection failed: ' + e.message, 'error'); 
  }
}

function disconnectTerm(){
  if(ws) {
    ws.close();
    ws = null;
    $('#term').textContent += '\n[Disconnected by user]\n';
    toast('Terminal disconnected', 'info');
  }
}

function clearTerm(){
  $('#term').textContent = '';
}

// Terminal controls
$('#term-connect').onclick = connectTerm;
$('#term-disconnect').onclick = disconnectTerm;
$('#term-clear').onclick = clearTerm;
$('#tab-terminal').addEventListener('click', ()=>{ 
  if(!ws) setTimeout(connectTerm, 100); 
});

// Config Editor
async function loadConfig(){
  try{
    showLoading('Loading configuration...');
    const response = await api('/api/config');
    const config = await response.text();
    $('#config-editor').value = config;
    hideLoading();
  } catch(e) {
    hideLoading();
    toast('Failed to load config: ' + e.message, 'error');
  }
}

$('#config-reload').onclick = loadConfig;

$('#config-save').onclick = async ()=>{
  const config = $('#config-editor').value;
  try{
    showLoading('Saving configuration...');
    await api('/api/config', {
      method: 'POST',
      body: JSON.stringify({config})
    });
    toast('Configuration saved successfully', 'success');
    hideLoading();
  } catch(e) {
    hideLoading();
    toast('Failed to save config: ' + e.message, 'error');
  }
}

$('#config-validate').onclick = async ()=>{
  const config = $('#config-editor').value;
  try{
    showLoading('Validating YAML...');
    const response = await api('/api/config/validate', {
      method: 'POST',
      body: JSON.stringify({config})
    });
    const result = await response.json();
    
    if(result.valid) {
      $('#config-status').innerHTML = '<span class="text-success">✓ Valid YAML</span>';
      toast('Configuration is valid', 'success');
    } else {
      $('#config-status').innerHTML = `<span class="text-error">✗ Invalid YAML: ${result.error}</span>`;
      toast('Invalid YAML: ' + result.error, 'error');
    }
    hideLoading();
  } catch(e) {
    hideLoading();
    $('#config-status').innerHTML = `<span class="text-error">✗ Validation failed: ${e.message}</span>`;
    toast('Validation failed: ' + e.message, 'error');
  }
}

// Web Generator
async function loadPages(){
  try{
    const response = await api('/api/webgen/pages');
    const pages = await response.json();
    const container = $('#pages');
    container.innerHTML = '';
    
    pages.forEach(page => {
      const pageDiv = document.createElement('div');
      pageDiv.style.padding = '8px';
      pageDiv.style.border = '1px solid #173764';
      pageDiv.style.borderRadius = '6px';
      pageDiv.style.margin = '4px 0';
      pageDiv.innerHTML = `
        <span style="color: #d7e3ff">${page.title}</span>
        <button onclick="editPage('${page.filename}')" style="margin-left: 8px; font-size: 12px;">Edit</button>
        <button onclick="deletePage('${page.filename}')" style="margin-left: 4px; font-size: 12px;">Delete</button>
      `;
      container.appendChild(pageDiv);
    });
  } catch(e) {
    console.error('Failed to load pages:', e);
  }
}

$('#wmake').onclick = async ()=>{
  const title = $('#wtitle').value.trim();
  const content = $('#wcontent').value;
  
  if(!title || !content) {
    toast('Please enter both title and content', 'warning');
    return;
  }
  
  try{
    showLoading('Creating page...');
    const response = await api('/api/webgen/create', {
      method: 'POST',
      body: JSON.stringify({title, content})
    });
    const result = await response.json();
    
    $('#wresult').innerHTML = `<span class="text-success">Page created: ${result.filename}</span>`;
    toast('Page created successfully', 'success');
    loadPages();
    hideLoading();
  } catch(e) {
    hideLoading();
    $('#wresult').innerHTML = `<span class="text-error">Failed: ${e.message}</span>`;
    toast('Failed to create page: ' + e.message, 'error');
  }
}

window.editPage = async (filename) => {
  try{
    const response = await api(`/api/webgen/page/${filename}`);
    const page = await response.json();
    $('#wtitle').value = page.title;
    $('#wcontent').value = page.content;
    toast('Page loaded for editing', 'info');
  } catch(e) {
    toast('Failed to load page: ' + e.message, 'error');
  }
}

window.deletePage = async (filename) => {
  if(!confirm(`Delete page: ${filename}?`)) return;
  
  try{
    await api(`/api/webgen/page/${filename}`, {method: 'DELETE'});
    toast('Page deleted successfully', 'success');
    loadPages();
  } catch(e) {
    toast('Failed to delete page: ' + e.message, 'error');
  }
}

// Admin Panel
async function loadAdminData(){
  try{
    const response = await api('/api/admin/users');
    const users = await response.json();
    const container = $('#user-list');
    container.innerHTML = '';
    
    users.forEach(user => {
      const userDiv = document.createElement('div');
      userDiv.style.padding = '8px';
      userDiv.style.border = '1px solid #173764';
      userDiv.style.borderRadius = '6px';
      userDiv.style.margin = '4px 0';
      userDiv.style.display = 'flex';
      userDiv.style.justifyContent = 'space-between';
      userDiv.style.alignItems = 'center';
      
      userDiv.innerHTML = `
        <span style="color: #d7e3ff">${user.username} ${user.has_2fa ? '🔐' : ''}</span>
        <div>
          <button onclick="resetPassword('${user.username}')" style="font-size: 12px; margin-right: 4px;">Reset Password</button>
          <button onclick="toggle2FA('${user.username}', ${!user.has_2fa})" style="font-size: 12px; margin-right: 4px;">
            ${user.has_2fa ? 'Disable' : 'Enable'} 2FA
          </button>
          <button onclick="deleteUser('${user.username}')" style="font-size: 12px;">Delete</button>
        </div>
      `;
      container.appendChild(userDiv);
    });
  } catch(e) {
    console.error('Failed to load users:', e);
  }
}

$('#add-user').onclick = async ()=>{
  const username = $('#new-username').value.trim();
  const password = $('#new-password').value;
  
  if(!username || !password) {
    toast('Please enter username and password', 'warning');
    return;
  }
  
  try{
    showLoading('Adding user...');
    await api('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify({username, password})
    });
    
    $('#new-username').value = '';
    $('#new-password').value = '';
    toast('User added successfully', 'success');
    loadAdminData();
    hideLoading();
  } catch(e) {
    hideLoading();
    toast('Failed to add user: ' + e.message, 'error');
  }
}

window.deleteUser = async (username) => {
  if(!confirm(`Delete user: ${username}?`)) return;
  
  try{
    await api(`/api/admin/users/${username}`, {method: 'DELETE'});
    toast('User deleted successfully', 'success');
    loadAdminData();
  } catch(e) {
    toast('Failed to delete user: ' + e.message, 'error');
  }
}

window.resetPassword = async (username) => {
  const newPassword = prompt(`Enter new password for ${username}:`);
  if(!newPassword) return;
  
  try{
    await api(`/api/admin/users/${username}/password`, {
      method: 'POST',
      body: JSON.stringify({password: newPassword})
    });
    toast('Password reset successfully', 'success');
  } catch(e) {
    toast('Failed to reset password: ' + e.message, 'error');
  }
}

window.toggle2FA = async (username, enable) => {
  try{
    await api(`/api/admin/users/${username}/2fa`, {
      method: 'POST',
      body: JSON.stringify({enable})
    });
    toast(`2FA ${enable ? 'enabled' : 'disabled'} for ${username}`, 'success');
    loadAdminData();
  } catch(e) {
    toast(`Failed to ${enable ? 'enable' : 'disable'} 2FA: ` + e.message, 'error');
  }
}

// Backup controls
$('#create-backup').onclick = async ()=>{
  try{
    showLoading('Creating backup...');
    const response = await api('/api/admin/backup', {method: 'POST'});
    const result = await response.json();
    $('#backup-status').innerHTML = `<span class="text-success">Backup created: ${result.filename}</span>`;
    toast('Backup created successfully', 'success');
    hideLoading();
  } catch(e) {
    hideLoading();
    $('#backup-status').innerHTML = `<span class="text-error">Backup failed: ${e.message}</span>`;
    toast('Backup failed: ' + e.message, 'error');
  }
}

$('#list-backups').onclick = async ()=>{
  try{
    const response = await api('/api/admin/backups');
    const backups = await response.json();
    const list = backups.map(b => b.filename).join(', ');
    $('#backup-status').innerHTML = `<span class="text-info">Available backups: ${list}</span>`;
  } catch(e) {
    $('#backup-status').innerHTML = `<span class="text-error">Failed to list backups: ${e.message}</span>`;
  }
}

$('#restore-backup').onclick = async ()=>{
  const filename = $('#restore-file').value.trim();
  if(!filename) {
    toast('Please enter backup filename', 'warning');
    return;
  }
  
  if(!confirm(`Restore from backup: ${filename}? This will overwrite current data.`)) return;
  
  try{
    showLoading('Restoring backup...');
    await api('/api/admin/restore', {
      method: 'POST',
      body: JSON.stringify({filename})
    });
    $('#backup-status').innerHTML = `<span class="text-success">Restore completed</span>`;
    toast('Backup restored successfully', 'success');
    hideLoading();
  } catch(e) {
    hideLoading();
    $('#backup-status').innerHTML = `<span class="text-error">Restore failed: ${e.message}</span>`;
    toast('Restore failed: ' + e.message, 'error');
  }
}

// Notification settings
$('#save-email').onclick = async ()=>{
  const config = {
    server: $('#email-server').value.trim(),
    port: parseInt($('#email-port').value) || 587,
    username: $('#email-user').value.trim(),
    password: $('#email-pass').value
  };
  
  try{
    await api('/api/admin/notifications/email', {
      method: 'POST',
      body: JSON.stringify(config)
    });
    toast('Email settings saved', 'success');
  } catch(e) {
    toast('Failed to save email settings: ' + e.message, 'error');
  }
}

$('#save-telegram').onclick = async ()=>{
  const config = {
    token: $('#telegram-token').value.trim(),
    chat_id: $('#telegram-chat').value.trim()
  };
  
  try{
    await api('/api/admin/notifications/telegram', {
      method: 'POST',
      body: JSON.stringify(config)
    });
    toast('Telegram settings saved', 'success');
  } catch(e) {
    toast('Failed to save Telegram settings: ' + e.message, 'error');
  }
}

$('#save-discord').onclick = async ()=>{
  const config = {
    webhook_url: $('#discord-webhook').value.trim()
  };
  
  try{
    await api('/api/admin/notifications/discord', {
      method: 'POST',
      body: JSON.stringify(config)
    });
    toast('Discord settings saved', 'success');
  } catch(e) {
    toast('Failed to save Discord settings: ' + e.message, 'error');
  }
}

$('#li-btn').onclick=async()=>{
  const user=$('#li-user').value.trim();
  const pass=$('#li-pass').value;
  const otp=$('#li-otp').value.trim();
  
  if(!user || !pass) {
    $('#li-msg').textContent = 'Please enter username and password';
    return;
  }
  
  $('#li-btn').disabled = true;
  $('#li-msg').textContent = 'Signing in...';
  
  try{
    const r = await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'}, 
      body:JSON.stringify({user,pass,otp})
    });
    
    if(r.ok){ 
      const j=await r.json(); 
      CSRF=j.csrf||''; 
      isLoggedIn = true;
      loginAttempts = 0;
      $('#login').style.display='none'; 
      toast('Login successful', 'success');
      refresh();
      startAutoRefresh();
    } else { 
      loginAttempts++;
      const errorData = await r.json().catch(() => ({}));
      
      if(r.status === 429) {
        $('#li-msg').textContent = 'Too many attempts. Please wait before trying again.';
      } else if(errorData.need_2fa) {
        $('#li-msg').textContent = '2FA code required or invalid';
      } else if(errorData.error) {
        $('#li-msg').textContent = errorData.error;
      } else {
        $('#li-msg').textContent = 'Invalid username or password';
      }
      
      $('#login-attempts').textContent = `Failed attempts: ${loginAttempts}`;
    }
  }catch(e){ 
    console.error('Login error:', e);
    $('#li-msg').textContent = 'Login error: ' + e.message; 
    loginAttempts++;
    $('#login-attempts').textContent = `Failed attempts: ${loginAttempts}`;
  } finally {
    $('#li-btn').disabled = false;
  }
};

// Login on Enter key
$('#li-user').addEventListener('keydown', (e) => {
  if(e.key === 'Enter') $('#li-pass').focus();
});
$('#li-pass').addEventListener('keydown', (e) => {
  if(e.key === 'Enter') $('#li-otp').focus();
});
$('#li-otp').addEventListener('keydown', (e) => {
  if(e.key === 'Enter') $('#li-btn').click();
});

// Auto-refresh management
function startAutoRefresh() {
  if(refreshInterval) clearInterval(refreshInterval);
  refreshInterval = setInterval(() => {
    if(isLoggedIn) refresh();
  }, 10000); // Refresh every 10 seconds
}

function stopAutoRefresh() {
  if(refreshInterval) {
    clearInterval(refreshInterval);
    refreshInterval = null;
  }
}

// Initialize application
window.addEventListener('load', () => {
  // Try initial refresh (will trigger login modal if needed)
  refresh().then(() => {
    if(isLoggedIn) {
      startAutoRefresh();
      // Load initial file listing
      list('');
    }
  }).catch(() => {
    // Refresh failed, probably need to login
    showLogin();
  });
  
  // Set up periodic token refresh
  setInterval(() => {
    if(isLoggedIn) {
      // Refresh CSRF token silently
      api('/api/status').then(r => r.json()).then(j => {
        CSRF = j.csrf || CSRF;
      }).catch(() => {
        // Token might be expired, trigger login
        isLoggedIn = false;
        showLogin();
      });
    }
  }, 300000); // Check every 5 minutes
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
  if(document.hidden) {
    stopAutoRefresh();
  } else if(isLoggedIn) {
    refresh();
    startAutoRefresh();
  }
});

// Handle window beforeunload
window.addEventListener('beforeunload', () => {
  if(ws) ws.close();
  stopAutoRefresh();
});