
/* Shared JS for pages */

// --- init: create default stored credentials if not exist
function initCommon(){
  if(!localStorage.getItem('credentials')){
    const defaultCreds = { user: 'Janel Cabasag', pass: 'JaNuAry16hEh3' };
    localStorage.setItem('credentials', JSON.stringify(defaultCreds));
  }
  // ensure journal arrays exist
  if(!localStorage.getItem('myJournalEntries')) localStorage.setItem('myJournalEntries', JSON.stringify([]));
  if(!localStorage.getItem('auditLogs')) localStorage.setItem('auditLogs', JSON.stringify([]));
}

// get stored credentials
function getStoredCreds(){
  return JSON.parse(localStorage.getItem('credentials'));
}

// --- SMS generation: store in sessionStorage (not console)
function generateAndStoreSms(){
  const code = String(Math.floor(100000 + Math.random()*900000));
  sessionStorage.setItem('smsCode', code);
  // expire after 5 minutes
  setTimeout(()=>{ if(sessionStorage.getItem('smsCode')===code) sessionStorage.removeItem('smsCode') }, 5*60*1000);
  return code;
}

// show onscreen notification (element 'notif' exists in forgot.html)
function showNotification(msg){
  const el = document.getElementById('notif');
  if(!el) return;
  el.style.display = 'block';
  el.innerText = msg;
  // auto-hide after 6s
  setTimeout(()=>{ el.style.display='none'; }, 6000);
}

// ---------- Audit logs (persistent) ----------
function addAuditLog(msg){
  const arr = JSON.parse(localStorage.getItem('auditLogs') || '[]');
  arr.push({ time: new Date().toISOString(), msg: msg });
  localStorage.setItem('auditLogs', JSON.stringify(arr));
}

// convenient wrapper used by pages
function addLog(msg){
  addAuditLog(msg);
}

// refresh audit UI (for home page)
function refreshAuditUI(){
  const box = document.getElementById('auditBox');
  if(!box) return;
  const arr = JSON.parse(localStorage.getItem('auditLogs') || '[]');
  box.innerHTML = arr.slice().reverse().map(r => `[${new Date(r.time).toLocaleTimeString()}] ${r.msg}`).join('<br>');
}

// ---------- Journal storage ----------
function saveEntryToStorage(encrypted){
  const arr = JSON.parse(localStorage.getItem('myJournalEntries') || '[]');
  arr.push({ time: new Date().toISOString(), encrypted: encrypted });
  localStorage.setItem('myJournalEntries', JSON.stringify(arr));
}

function getLastEntry(){
  const arr = JSON.parse(localStorage.getItem('myJournalEntries') || '[]');
  return arr.length ? arr[arr.length - 1] : null;
}

// ---------- Simple Caesar encryption +3 ----------
function encrypt(text){
  let out = '';
  for(let i=0;i<text.length;i++){
    out += String.fromCharCode(text.charCodeAt(i) + 3);
  }
  return out;
}
function decrypt(text){
  let out = '';
  for(let i=0;i<text.length;i++){
    out += String.fromCharCode(text.charCodeAt(i) - 3);
  }
  return out;
}

// ---------- Logout / session ----------
function doLogout(){
  sessionStorage.removeItem('loggedIn');
  sessionStorage.removeItem('username');
  // redirect to login
  location.href = 'login.html';
}

// ---------- used by home page ----------
function doLogoutIfNeeded(){
  doLogout();
}

// ---------- Inactivity monitor (5 minutes) ----------
let _inactivityTimer = null;
function startInactivityMonitor(){
  function reset(){
    if(_inactivityTimer) clearTimeout(_inactivityTimer);
    _inactivityTimer = setTimeout(()=>{
      addAuditLog('Auto-logout after inactivity (5 min).');
      doLogout();
    }, 10 * 1000); // 5 minutes
  }
  // reset on common events
  ['mousemove','keydown','click','touchstart'].forEach(ev =>
    document.addEventListener(ev, reset)
  );
  reset();
}

// ---------- Behavior analytics: rapid typing detector ----------
let _lastKeyTs = 0;
function setupBehaviorAnalytics(){
  const box = document.getElementById('behaviorBox');
  document.addEventListener('keydown', (e)=>{
    const now = Date.now();
    if(_lastKeyTs && (now - _lastKeyTs) < 50){ // very fast => suspicious
      addAuditLog('Suspicious rapid typing detected.');
      if(box){
        box.innerHTML += `Rapid typing detected at ${new Date().toLocaleTimeString()}<br>`;
      }
    }
    _lastKeyTs = now;
  });
  // also refresh behavior UI with existing logs
}

// refresh behavior UI (simple)
function refreshBehaviorUI(){
  const box = document.getElementById('behaviorBox');
  if(!box) return;
  // show recent audit lines that mention 'typing' or 'Suspicious'
  const arr = JSON.parse(localStorage.getItem('auditLogs') || '[]');
  const filtered = arr.filter(r=>/typing|Suspicious|XSS/i.test(r.msg)).slice(-20);
  box.innerHTML = filtered.map(r=>`[${new Date(r.time).toLocaleTimeString()}] ${r.msg}`).join('<br>')
}

/* ============================
   XSS / SCRIPT DETECTOR
   Monitors ALL input and textarea fields.
   If suspicious characters or patterns are typed,
   it logs, alerts, and force-logs-out the session.
============================ */
function setupInputMonitor(){
  const suspicious = /<|>|script|onerror|onload|alert|\(|\)|{|}|;|\"|\'|&|\/|insert|drop|--/i;

  document.addEventListener('input', (e)=>{
    if(e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')){
      const val = e.target.value;
      if(suspicious.test(val)){
        // log the attempt with page info (persistent)
        addAuditLog(`XSS attempt detected on ${location.pathname}: ${val}`);

        // update UI audit immediately if present
        refreshAuditUI();

        // warn and logout
        alert("⚠️ Suspicious input detected! Session terminated for security.");
        doLogout();
      }
    }
  });

  // Also guard paste events (in case of paste attack)
  document.addEventListener('paste', (e)=>{
    const pasted = (e.clipboardData || window.clipboardData).getData('text');
    if(suspicious.test(pasted)){
      addAuditLog(`XSS paste attempt on ${location.pathname}: ${pasted}`);
      refreshAuditUI();
      alert("⚠️ Suspicious content pasted! Session terminated for security.");
      doLogout();
    }
  });
}


script