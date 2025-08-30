const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

// Global state
let CSRF = '';
let isLoggedIn = false;
let ws = null; // WebSocket for terminal
let loginAttempts = 0;
let maxLoginAttempts = 5;
let lockoutTime = 300000; // 5 minutes
let isLocked = false;

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initAuth();
  initEventHandlers();
  checkAuthStatus();
});

// Tab management
function initTabs() {
  const tabs = $$('.tabs button');
  tabs.forEach(b => {
    b.onclick = () => {
      tabs.forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      $$('.tab').forEach(x => x.classList.remove('active'));
      const targetTab = $('#tab-' + b.dataset.tab);
      if (targetTab) {
        targetTab.classList.add('active');
        
        // Load tab-specific data
        switch(b.dataset.tab) {
          case 'terminal':
            if (!ws) connectTerm();
            break;
          case 'admin':
            loadUsers();
            loadNotificationSettings();
            loadBackups();
            break;
          case 'config':
            loadConfig();
            break;
        }
      }
    };
  });
}

// Authentication management
function initAuth() {
  const loginModal = $('#login');
  const loginBtn = $('#li-btn');
  const userField = $('#li-user');
  const passField = $('#li-pass');
  const otpField = $('#li-otp');
  const msgField = $('#li-msg');

  loginBtn.onclick = async () => {
    if (isLocked) {
      showMessage(msgField, 'Account locked due to too many failed attempts', 'error');
      return;
    }
    
    const user = userField.value.trim();
    const pass = passField.value;
    const otp = otpField.value.trim();
    
    if (!user || !pass) {
      showMessage(msgField, 'Username and password required', 'error');
      return;
    }
    
    showLoading('Signing in...');
    loginBtn.disabled = true;
    
    try {
      const r = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user, pass, otp })
      });
      
      const data = await r.json().catch(() => ({}));
      
      if (r.ok) {
        isLoggedIn = true;
        loginAttempts = 0;
        loginModal.style.display = 'none';
        showMessage(msgField, '', 'success');
        await refresh();
        toast('Login successful');
      } else {
        loginAttempts++;
        updateLoginAttempts();
        
        if (data.need_2fa) {
          showMessage(msgField, '2FA code required or invalid', 'error');
          otpField.focus();
        } else if (data.locked) {
          isLocked = true;
          showMessage(msgField, 'Account locked due to too many failed attempts', 'error');
          setTimeout(() => { isLocked = false; }, lockoutTime);
        } else {
          showMessage(msgField, data.error || 'Login failed', 'error');
        }
        
        if (loginAttempts >= maxLoginAttempts) {
          isLocked = true;
          showMessage(msgField, 'Too many failed attempts. Account locked for 5 minutes.', 'error');
          setTimeout(() => { 
            isLocked = false; 
            loginAttempts = 0;
            updateLoginAttempts();
          }, lockoutTime);
        }
      }
    } catch (e) {
      console.error(e);
      showMessage(msgField, 'Network error', 'error');
    } finally {
      hideLoading();
      loginBtn.disabled = false;
    }
  };

  // Enter key support for login
  [userField, passField, otpField].forEach(field => {
    field.addEventListener('keydown', e => {
      if (e.key === 'Enter') loginBtn.click();
    });
  });
}

function updateLoginAttempts() {
  const attemptsDiv = $('#login-attempts');
  if (loginAttempts > 0) {
    attemptsDiv.textContent = `Failed attempts: ${loginAttempts}/${maxLoginAttempts}`;
  } else {
    attemptsDiv.textContent = '';
  }
}

function showLogin() {
  $('#login').style.display = 'flex';
  setTimeout(() => $('#li-user').focus(), 100);
}

function hideLogin() {
  $('#login').style.display = 'none';
}

async function checkAuthStatus() {
  try {
    const r = await fetch('/api/status');
    if (r.status === 401) {
      isLoggedIn = false;
      showLogin();
    } else {
      isLoggedIn = true;
      hideLogin();
      await refresh();
    }
  } catch (e) {
    console.error('Auth check failed:', e);
    showLogin();
  }
}

// Event handlers
function initEventHandlers() {
  // Header actions
  $('#btn-refresh').onclick = refresh;
  
  $$('header .actions button[data-act]').forEach(btn => {
    btn.onclick = async () => {
      const act = btn.dataset.act;
      
      if (act === 'logout') {
        await logout();
        return;
      }
      
      btn.disabled = true;
      showLoading(`Processing ${act}...`);
      
      try {
        await api('/api/control', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
          body: JSON.stringify({ action: act })
        });
        toast(`${act} completed successfully`);
        
        if (act === 'backup') {
          setTimeout(() => loadBackups(), 1000);
        }
      } catch (e) {
        console.error(e);
        toast(`${act} failed: ${e.message}`, 'error');
      } finally {
        btn.disabled = false;
        hideLoading();
      }
    };
  });

  // Monitor toggles
  $$('.toggle').forEach(b => {
    b.onclick = async () => {
      const target = b.dataset.target;
      const action = b.classList.contains('active') ? 'disable' : 'enable';
      
      try {
        await post(action, target);
        b.classList.toggle('active');
        setTimeout(refresh, 500);
      } catch (e) {
        toast('Action failed', 'error');
      }
    };
  });

  // File manager
  initFileManager();
  
  // Terminal
  initTerminal();
  
  // Chat
  initChat();
  
  // Admin panel
  initAdmin();
  
  // Config editor
  initConfig();
}

// File Manager
function initFileManager() {
  $('#btn-list').onclick = () => list($('#cwd').value);
  $('#btn-parent').onclick = () => {
    const current = $('#cwd').value;
    const parent = current.split('/').slice(0, -1).join('/') || '/';
    list(parent);
  };
  $('#btn-home').onclick = () => list('~/.novashield');
  
  $('#btn-mkdir').onclick = async () => {
    const path = $('#newpath').value.trim();
    if (!path) {
      toast('Path required', 'error');
      return;
    }
    
    try {
      await api('/api/fs_mkdir', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
        body: JSON.stringify({ path })
      });
      toast('Directory created');
      list($('#cwd').value);
    } catch (e) {
      toast('Create failed: ' + e.message, 'error');
    }
  };
  
  $('#btn-save').onclick = async () => {
    const path = $('#newpath').value.trim();
    const content = $('#viewer-content').textContent;
    
    if (!path) {
      toast('Path required', 'error');
      return;
    }
    
    try {
      await api('/api/fs_write', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
        body: JSON.stringify({ path, content })
      });
      toast('File saved');
      list($('#cwd').value);
    } catch (e) {
      toast('Save failed: ' + e.message, 'error');
    }
  };
  
  $('#btn-delete').onclick = async () => {
    const path = $('#newpath').value.trim();
    if (!path) {
      toast('Path required', 'error');
      return;
    }
    
    const confirmed = await showConfirm('Delete File/Directory', `Are you sure you want to delete "${path}"?`);
    if (!confirmed) return;
    
    try {
      await api('/api/fs_delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
        body: JSON.stringify({ path })
      });
      toast('Deleted successfully');
      list($('#cwd').value);
    } catch (e) {
      toast('Delete failed: ' + e.message, 'error');
    }
  };
  
  $('#btn-rename').onclick = async () => {
    const oldPath = $('#newpath').value.trim();
    if (!oldPath) {
      toast('Current path required', 'error');
      return;
    }
    
    const newName = prompt('Enter new name:');
    if (!newName) return;
    
    const newPath = oldPath.split('/').slice(0, -1).concat([newName]).join('/');
    
    try {
      await api('/api/fs_move', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
        body: JSON.stringify({ from: oldPath, to: newPath })
      });
      toast('Renamed successfully');
      list($('#cwd').value);
    } catch (e) {
      toast('Rename failed: ' + e.message, 'error');
    }
  };
  
  $('#btn-move').onclick = async () => {
    const from = $('#newpath').value.trim();
    if (!from) {
      toast('Source path required', 'error');
      return;
    }
    
    const to = prompt('Enter destination path:');
    if (!to) return;
    
    try {
      await api('/api/fs_move', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
        body: JSON.stringify({ from, to })
      });
      toast('Moved successfully');
      list($('#cwd').value);
    } catch (e) {
      toast('Move failed: ' + e.message, 'error');
    }
  };
}

async function list(dir) {
  try {
    let d = dir || '';
    if (d.trim().startsWith('~')) d = '';
    
    const j = await (await api('/api/fs?dir=' + encodeURIComponent(d))).json();
    $('#cwd').value = j.dir;
    
    const wrap = $('#filelist');
    wrap.innerHTML = '';
    
    (j.entries || []).forEach(e => {
      const row = document.createElement('div');
      row.style.cursor = 'pointer';
      row.style.padding = '4px 8px';
      row.style.borderRadius = '4px';
      row.style.margin = '2px 0';
      row.textContent = (e.is_dir ? '[D] ' : '[F] ') + e.name + (e.size ? (' (' + formatBytes(e.size) + ')') : '');
      
      row.onmouseover = () => row.style.background = '#143055';
      row.onmouseout = () => row.style.background = '';
      
      row.onclick = () => {
        if (e.is_dir) {
          list(j.dir.replace(/\/+$/, '') + '/' + e.name);
        } else {
          viewFile(j.dir.replace(/\/+$/, '') + '/' + e.name);
        }
      };
      
      wrap.appendChild(row);
    });
  } catch (e) {
    console.error(e);
    toast('List failed: ' + e.message, 'error');
  }
}

async function viewFile(path) {
  try {
    const j = await (await api('/api/fs_read?path=' + encodeURIComponent(path))).json();
    if (!j.ok) {
      toast('Open failed', 'error');
      return;
    }
    
    $('#viewer-title').textContent = `Viewer — ${j.path} (${formatBytes(j.size || 0)})`;
    $('#viewer-content').textContent = j.content || '';
    $('#newpath').value = path;
    $('#viewer').style.display = '';
  } catch (e) {
    console.error(e);
    toast('Open failed: ' + e.message, 'error');
  }
}

// Terminal
function initTerminal() {
  $('#term-connect').onclick = connectTerm;
  $('#term-disconnect').onclick = disconnectTerm;
  $('#term-clear').onclick = () => {
    $('#term').textContent = '';
  };
  
  // Connect on tab click if not connected
  $$('[data-tab="terminal"]').forEach(tab => {
    tab.addEventListener('click', () => {
      if (!ws) setTimeout(connectTerm, 100);
    });
  });
}

function connectTerm() {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  
  try {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/term`);
    
    const term = $('#term');
    term.textContent = '';
    
    ws.binaryType = 'arraybuffer';
    
    ws.onopen = () => {
      term.focus();
      toast('Terminal connected');
    };
    
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        const dec = new TextDecoder('utf-8', { fatal: false });
        const txt = dec.decode(new Uint8Array(ev.data));
        term.textContent += txt;
      } else {
        term.textContent += ev.data;
      }
      term.scrollTop = term.scrollHeight;
    };
    
    ws.onclose = () => {
      toast('Terminal closed', 'warn');
      ws = null;
    };
    
    ws.onerror = (e) => {
      console.error('WebSocket error:', e);
      toast('Terminal connection error', 'error');
    };
    
    term.onkeydown = (e) => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      
      e.preventDefault();
      let out = '';
      
      if (e.key === 'Enter') out = '\r';
      else if (e.key === 'Backspace') out = '\x7f';
      else if (e.key === 'Tab') out = '\t';
      else if (e.key === 'ArrowUp') out = '\x1b[A';
      else if (e.key === 'ArrowDown') out = '\x1b[B';
      else if (e.key === 'ArrowRight') out = '\x1b[C';
      else if (e.key === 'ArrowLeft') out = '\x1b[D';
      else if (e.ctrlKey && e.key.toLowerCase() === 'c') out = '\x03';
      else if (e.ctrlKey && e.key.toLowerCase() === 'd') out = '\x04';
      else if (e.key.length === 1) out = e.key;
      
      if (out) {
        ws.send(new TextEncoder().encode(out));
      }
    };
    
  } catch (e) {
    console.error(e);
    toast('Terminal connection failed', 'error');
  }
}

function disconnectTerm() {
  if (ws) {
    ws.close();
    ws = null;
    toast('Terminal disconnected');
  }
}

// Chat
function initChat() {
  $('#send').onclick = sendChat;
  $('#clear-chat').onclick = () => {
    $('#chatlog').innerHTML = '';
  };
  
  $('#prompt').addEventListener('keydown', e => {
    if (e.key === 'Enter') sendChat();
  });
}

async function sendChat() {
  const prompt = $('#prompt').value.trim();
  if (!prompt) return;
  
  const log = $('#chatlog');
  const you = document.createElement('div');
  you.textContent = 'You: ' + prompt;
  you.style.margin = '4px 0';
  you.style.padding = '4px 8px';
  you.style.background = '#143055';
  you.style.borderRadius = '6px';
  log.appendChild(you);
  
  $('#prompt').value = '';
  
  try {
    const j = await (await api('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify({ prompt })
    })).json();
    
    const ai = document.createElement('div');
    ai.textContent = 'Jarvis: ' + j.reply;
    ai.style.margin = '4px 0';
    ai.style.padding = '4px 8px';
    ai.style.background = '#0a1426';
    ai.style.borderRadius = '6px';
    ai.style.borderLeft = '3px solid var(--accent)';
    log.appendChild(ai);
    
    log.scrollTop = log.scrollHeight;
  } catch (e) {
    console.error(e);
    toast('Chat failed', 'error');
  }
}

// Admin Panel
function initAdmin() {
  $('#btn-add-user').onclick = addUser;
  $('#btn-save-email').onclick = saveEmailConfig;
  $('#btn-test-email').onclick = testEmail;
  $('#btn-save-telegram').onclick = saveTelegramConfig;
  $('#btn-test-telegram').onclick = testTelegram;
  $('#btn-save-discord').onclick = saveDiscordConfig;
  $('#btn-test-discord').onclick = testDiscord;
  $('#btn-create-backup').onclick = createBackup;
  $('#btn-list-backups').onclick = loadBackups;
}

async function addUser() {
  const username = $('#new-username').value.trim();
  const password = $('#new-password').value;
  const confirmPassword = $('#new-password-confirm').value;
  
  if (!username || !password) {
    toast('Username and password required', 'error');
    return;
  }
  
  if (password !== confirmPassword) {
    toast('Passwords do not match', 'error');
    return;
  }
  
  if (password.length < 8) {
    toast('Password must be at least 8 characters', 'error');
    return;
  }
  
  try {
    await api('/api/admin/add_user', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify({ username, password })
    });
    
    toast('User created successfully');
    $('#new-username').value = '';
    $('#new-password').value = '';
    $('#new-password-confirm').value = '';
    loadUsers();
  } catch (e) {
    toast('Create user failed: ' + e.message, 'error');
  }
}

async function loadUsers() {
  try {
    const j = await (await api('/api/admin/users')).json();
    const list = $('#users-list');
    list.innerHTML = '';
    
    (j.users || []).forEach(user => {
      const div = document.createElement('div');
      div.className = 'user-item';
      
      div.innerHTML = `
        <span>${user.username}</span>
        <div class="user-actions">
          <button onclick="resetPassword('${user.username}')">Reset Password</button>
          <button onclick="toggle2FA('${user.username}', ${user.has_2fa || false})">${user.has_2fa ? 'Disable' : 'Enable'} 2FA</button>
          <button onclick="deleteUser('${user.username}')" style="background:var(--crit);">Delete</button>
        </div>
      `;
      
      list.appendChild(div);
    });
  } catch (e) {
    console.error(e);
  }
}

async function deleteUser(username) {
  const confirmed = await showConfirm('Delete User', `Are you sure you want to delete user "${username}"?`);
  if (!confirmed) return;
  
  try {
    await api('/api/admin/delete_user', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify({ username })
    });
    
    toast('User deleted successfully');
    loadUsers();
  } catch (e) {
    toast('Delete user failed: ' + e.message, 'error');
  }
}

async function resetPassword(username) {
  const newPassword = prompt(`Enter new password for ${username}:`);
  if (!newPassword) return;
  
  if (newPassword.length < 8) {
    toast('Password must be at least 8 characters', 'error');
    return;
  }
  
  try {
    await api('/api/admin/reset_password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify({ username, password: newPassword })
    });
    
    toast('Password reset successfully');
  } catch (e) {
    toast('Password reset failed: ' + e.message, 'error');
  }
}

async function toggle2FA(username, currentState) {
  const action = currentState ? 'disable' : 'enable';
  
  try {
    await api('/api/admin/toggle_2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify({ username, enable: !currentState })
    });
    
    toast(`2FA ${action}d for ${username}`);
    loadUsers();
  } catch (e) {
    toast(`2FA ${action} failed: ` + e.message, 'error');
  }
}

// Notification configs
async function saveEmailConfig() {
  const config = {
    smtp_server: $('#email-smtp-server').value.trim(),
    smtp_port: parseInt($('#email-smtp-port').value) || 587,
    username: $('#email-username').value.trim(),
    password: $('#email-password').value,
    from_addr: $('#email-from').value.trim(),
    to_addr: $('#email-to').value.trim()
  };
  
  try {
    await api('/api/admin/config_email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify(config)
    });
    
    toast('Email configuration saved');
  } catch (e) {
    toast('Save email config failed: ' + e.message, 'error');
  }
}

async function testEmail() {
  try {
    await api('/api/admin/test_email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF }
    });
    
    toast('Test email sent');
  } catch (e) {
    toast('Test email failed: ' + e.message, 'error');
  }
}

async function saveTelegramConfig() {
  const config = {
    bot_token: $('#telegram-token').value.trim(),
    chat_id: $('#telegram-chat-id').value.trim()
  };
  
  try {
    await api('/api/admin/config_telegram', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify(config)
    });
    
    toast('Telegram configuration saved');
  } catch (e) {
    toast('Save telegram config failed: ' + e.message, 'error');
  }
}

async function testTelegram() {
  try {
    await api('/api/admin/test_telegram', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF }
    });
    
    toast('Test telegram message sent');
  } catch (e) {
    toast('Test telegram failed: ' + e.message, 'error');
  }
}

async function saveDiscordConfig() {
  const config = {
    webhook_url: $('#discord-webhook').value.trim()
  };
  
  try {
    await api('/api/admin/config_discord', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify(config)
    });
    
    toast('Discord configuration saved');
  } catch (e) {
    toast('Save discord config failed: ' + e.message, 'error');
  }
}

async function testDiscord() {
  try {
    await api('/api/admin/test_discord', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF }
    });
    
    toast('Test discord message sent');
  } catch (e) {
    toast('Test discord failed: ' + e.message, 'error');
  }
}

// Backup management
async function createBackup() {
  showLoading('Creating backup...');
  
  try {
    await api('/api/admin/create_backup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF }
    });
    
    toast('Backup created successfully');
    loadBackups();
  } catch (e) {
    toast('Create backup failed: ' + e.message, 'error');
  } finally {
    hideLoading();
  }
}

async function loadBackups() {
  try {
    const j = await (await api('/api/admin/backups')).json();
    const list = $('#backups-list');
    list.innerHTML = '';
    
    if (!j.backups || j.backups.length === 0) {
      list.innerHTML = '<p>No backups found</p>';
      return;
    }
    
    j.backups.forEach(backup => {
      const div = document.createElement('div');
      div.style.margin = '8px 0';
      div.style.padding = '8px';
      div.style.background = '#081426';
      div.style.border = '1px solid #143055';
      div.style.borderRadius = '6px';
      
      div.innerHTML = `
        <div>${backup.name}</div>
        <div style="font-size:12px; color:var(--muted); margin:4px 0;">${backup.date} - ${backup.size}</div>
        <button onclick="restoreBackup('${backup.name}')">Restore</button>
        <button onclick="downloadBackup('${backup.name}')">Download</button>
      `;
      
      list.appendChild(div);
    });
  } catch (e) {
    console.error(e);
  }
}

async function restoreBackup(name) {
  const confirmed = await showConfirm('Restore Backup', `Are you sure you want to restore backup "${name}"? This will overwrite current configuration.`);
  if (!confirmed) return;
  
  showLoading('Restoring backup...');
  
  try {
    await api('/api/admin/restore_backup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify({ name })
    });
    
    toast('Backup restored successfully');
    setTimeout(() => location.reload(), 2000);
  } catch (e) {
    toast('Restore backup failed: ' + e.message, 'error');
  } finally {
    hideLoading();
  }
}

function downloadBackup(name) {
  const link = document.createElement('a');
  link.href = `/api/admin/download_backup?name=${encodeURIComponent(name)}`;
  link.download = name;
  link.click();
}

// Config Editor
function initConfig() {
  $('#btn-reload-config').onclick = loadConfig;
  $('#btn-save-config').onclick = saveConfig;
  $('#btn-backup-config').onclick = backupConfig;
  
  // Auto-validate on edit
  $('#config').addEventListener('input', validateConfig);
}

async function loadConfig() {
  try {
    const config = await (await api('/api/config')).text();
    $('#config').textContent = config;
    updateConfigStatus('Config loaded', 'success');
  } catch (e) {
    toast('Load config failed: ' + e.message, 'error');
  }
}

async function saveConfig() {
  const content = $('#config').textContent;
  
  if (!validateConfig()) {
    toast('Configuration has errors, cannot save', 'error');
    return;
  }
  
  const confirmed = await showConfirm('Save Configuration', 'Are you sure you want to save the configuration? Invalid configuration may break the system.');
  if (!confirmed) return;
  
  try {
    await api('/api/admin/save_config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify({ content })
    });
    
    toast('Configuration saved successfully');
    updateConfigStatus('Saved', 'success');
  } catch (e) {
    toast('Save config failed: ' + e.message, 'error');
    updateConfigStatus('Save failed', 'error');
  }
}

async function backupConfig() {
  try {
    await api('/api/admin/backup_config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF }
    });
    
    toast('Configuration backed up');
  } catch (e) {
    toast('Backup config failed: ' + e.message, 'error');
  }
}

function validateConfig() {
  const content = $('#config').textContent;
  const validation = $('#config-validation');
  
  try {
    // Basic YAML validation
    if (content.includes('\t')) {
      throw new Error('YAML should use spaces, not tabs');
    }
    
    // Check for basic structure
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim() && !line.startsWith('#')) {
        if (line.includes(':') && !line.trim().endsWith(':')) {
          // Check if it's a key:value pair
          const parts = line.split(':');
          if (parts.length >= 2) {
            continue;
          }
        } else if (line.trim().endsWith(':')) {
          // Section header
          continue;
        } else if (line.startsWith('  ') || line.startsWith('- ')) {
          // Indented content or list item
          continue;
        } else {
          throw new Error(`Line ${i + 1}: Invalid YAML syntax`);
        }
      }
    }
    
    validation.textContent = '';
    validation.className = 'config-validation';
    updateConfigStatus('Valid', 'success');
    return true;
  } catch (e) {
    validation.textContent = 'Error: ' + e.message;
    validation.className = 'config-validation error';
    updateConfigStatus('Invalid', 'error');
    return false;
  }
}

function updateConfigStatus(message, type) {
  const status = $('#config-status');
  status.textContent = message;
  status.className = `config-status-${type}`;
}

// Utility functions
async function api(path, opts) {
  const r = await fetch(path, Object.assign({
    headers: { 'Content-Type': 'application/json' }
  }, opts || {}));
  
  if (r.status === 401) {
    isLoggedIn = false;
    showLogin();
    throw new Error('Unauthorized');
  }
  
  if (r.status === 403) {
    toast('Forbidden or CSRF error', 'error');
    throw new Error('Forbidden');
  }
  
  if (!r.ok) {
    const error = await r.text().catch(() => 'API error');
    throw new Error(error);
  }
  
  return r;
}

async function post(action, target) {
  try {
    await api('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': CSRF },
      body: JSON.stringify({ action, target })
    });
    toast(`${action} ${target}`);
  } catch (e) {
    toast('Action failed', 'error');
    throw e;
  }
}

async function logout() {
  try {
    await api('/api/logout', { method: 'POST' });
  } catch (e) {
    // Ignore errors
  }
  
  isLoggedIn = false;
  CSRF = '';
  showLogin();
  toast('Logged out');
}

function toast(msg, type = 'info') {
  const t = document.createElement('div');
  t.textContent = msg;
  t.style.position = 'fixed';
  t.style.right = '14px';
  t.style.bottom = '14px';
  t.style.borderRadius = '8px';
  t.style.padding = '8px 12px';
  t.style.zIndex = '9999';
  t.style.fontSize = '14px';
  t.style.maxWidth = '300px';
  t.style.wordWrap = 'break-word';
  
  switch (type) {
    case 'error':
      t.style.background = 'var(--crit)';
      t.style.color = '#fff';
      break;
    case 'warn':
      t.style.background = 'var(--warn)';
      t.style.color = '#000';
      break;
    case 'success':
      t.style.background = 'var(--ok)';
      t.style.color = '#fff';
      break;
    default:
      t.style.background = '#0a1426';
      t.style.border = '1px solid #173764';
      t.style.color = '#cfe6ff';
  }
  
  document.body.appendChild(t);
  setTimeout(() => t.remove(), type === 'error' ? 5000 : 3000);
}

function showLoading(message = 'Loading...') {
  const loading = $('#loading');
  const msg = $('#loading-message');
  msg.textContent = message;
  loading.style.display = 'flex';
}

function hideLoading() {
  $('#loading').style.display = 'none';
}

function showMessage(element, message, type) {
  element.textContent = message;
  element.className = type === 'error' ? 'msg error' : 'msg';
}

async function showConfirm(title, message) {
  return new Promise((resolve) => {
    const dialog = $('#confirm-dialog');
    $('#confirm-title').textContent = title;
    $('#confirm-message').textContent = message;
    
    dialog.style.display = 'flex';
    
    const cleanup = () => {
      dialog.style.display = 'none';
      $('#confirm-yes').onclick = null;
      $('#confirm-no').onclick = null;
    };
    
    $('#confirm-yes').onclick = () => {
      cleanup();
      resolve(true);
    };
    
    $('#confirm-no').onclick = () => {
      cleanup();
      resolve(false);
    };
  });
}

function human(val, unit = '') {
  if (val === undefined || val === null) return '?';
  return `${val}${unit}`;
}

function setCard(id, text) {
  const el = $('#' + id);
  if (el) el.textContent = text;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function refresh() {
  if (!isLoggedIn) return;
  
  try {
    const r = await api('/api/status');
    const j = await r.json();
    
    CSRF = j.csrf || '';
    
    // Update system cards
    const cpu = j.cpu || {};
    setCard('cpu', `Load: ${human(cpu.load1)} | Level: ${cpu.level || 'OK'}`);
    
    const mem = j.memory || {};
    setCard('mem', `Used: ${human(mem.used_pct, '%')} | Warn: ${human(mem.warn, '%')} | Crit: ${human(mem.crit, '%')} | Level: ${mem.level || 'OK'}`);
    
    const dsk = j.disk || {};
    setCard('disk', `Mount: ${dsk.mount || '/'} | Used: ${human(dsk.use_pct, '%')} | Level: ${dsk.level || 'OK'}`);
    
    const net = j.network || {};
    setCard('net', `IP: ${net.ip || '?'} | Public: ${net.public_ip || '?'} | Loss: ${human(net.loss_pct, '%')} | RTT: ${human(net.rtt_avg_ms, 'ms')} | Level: ${net.level || 'OK'}`);
    
    setCard('int', 'Integrity monitor active');
    setCard('proc', 'Process watch active');
    setCard('user', 'User sessions tracked');
    setCard('svc', `Service checks ${j.services ? 'active' : 'n/a'}`);
    setCard('meta', `Projects: ${j.projects_count || 0} | Modules: ${j.modules_count || 0} | Version: ${j.version || '?'} | TS: ${j.ts || '?'}`);
    
    // Update alerts
    const ul = $('#alerts');
    ul.innerHTML = '';
    (j.alerts || []).slice(-200).reverse().forEach(line => {
      const li = document.createElement('li');
      li.textContent = line;
      ul.appendChild(li);
    });
    
    // Update status level indicators
    const levels = {
      cpu: j.cpu?.level,
      memory: j.memory?.level,
      disk: j.disk?.level,
      network: j.network?.level
    };
    
    const map = { OK: 'ok', WARN: 'warn', CRIT: 'crit' };
    Object.entries(levels).forEach(([k, v]) => {
      const cardId = { memory: 'card-mem', disk: 'card-disk', network: 'card-net', cpu: 'card-cpu' }[k];
      const el = $('#' + cardId);
      if (!el) return;
      
      el.classList.remove('ok', 'warn', 'crit');
      if (map[v]) el.classList.add(map[v]);
    });
    
  } catch (e) {
    console.error('Refresh failed:', e);
    if (e.message === 'Unauthorized') {
      // Auth error already handled in api()
      return;
    }
    toast('Refresh failed', 'error');
  }
}

async function loadNotificationSettings() {
  try {
    const j = await (await api('/api/admin/notification_settings')).json();
    
    if (j.email) {
      $('#email-smtp-server').value = j.email.smtp_server || '';
      $('#email-smtp-port').value = j.email.smtp_port || 587;
      $('#email-username').value = j.email.username || '';
      $('#email-from').value = j.email.from_addr || '';
      $('#email-to').value = j.email.to_addr || '';
    }
    
    if (j.telegram) {
      $('#telegram-token').value = j.telegram.bot_token || '';
      $('#telegram-chat-id').value = j.telegram.chat_id || '';
    }
    
    if (j.discord) {
      $('#discord-webhook').value = j.discord.webhook_url || '';
    }
  } catch (e) {
    console.error('Load notification settings failed:', e);
  }
}

// Start the app
refresh();
setInterval(() => {
  if (isLoggedIn) refresh();
}, 5000);
