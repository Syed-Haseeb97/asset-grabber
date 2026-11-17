const $ = (s) => document.querySelector(s);
const TYPES = [['all', 'All'], ['image', 'Images'], ['video', 'Videos'], ['audio', 'Audio'], ['pdf', 'PDFs'], ['document', 'Documents'], ['archive', 'Archives'], ['config', 'Config & data'], ['stream', 'Streams'], ['font', 'Fonts']];
const ICONS = { all: '🗂️', image: '🖼️', video: '🎬', audio: '🎵', pdf: '📕', document: '📄', archive: '🗜️', config: '⚙️', stream: '📡', font: '🔤' };
const FOLDERS = { image: 'images', video: 'videos', audio: 'audio', pdf: 'pdfs', document: 'documents', archive: 'archives', config: 'config', stream: 'streams', font: 'fonts' };
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const MIME_EXT = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp', 'image/svg+xml': 'svg', 'image/avif': 'avif',
  'video/mp4': 'mp4', 'video/webm': 'webm', 'audio/mpeg': 'mp3', 'audio/ogg': 'ogg', 'audio/wav': 'wav', 'audio/mp4': 'm4a',
  'application/pdf': 'pdf',
};

const state = {
  items: [], info: null, pageUrl: '', mode: '', filter: 'all', query: '', hideTiny: false, access: 'any', sort: 'found',
  selected: new Set(), busy: false, ctl: null, lastTs: 0, audit: null, sevFilter: 'all', reveal: false, devView: 'findings',
};

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sleep = AGUtil.sleep;
const fmt = (n) => n === undefined ? '…' : n === null ? '—' : n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB';

function setStatus(text, kind = '') {
  const el = $('#status');
  el.textContent = text;
  el.className = 'status ' + kind;
}
function setProgress(frac) {
  const bar = $('#bar');
  bar.hidden = frac == null;
  if (frac != null) bar.firstElementChild.style.width = Math.round(frac * 100) + '%';
}

/* ---------- helpers ---------- */

function typeFromMime(m) {
  m = (m || '').toLowerCase();
  if (m.startsWith('image/')) return 'image';
  if (m.startsWith('video/')) return 'video';
  if (m.startsWith('audio/')) return 'audio';
  if (m === 'application/pdf') return 'pdf';
  if (m.includes('mpegurl') || m.includes('dash+xml')) return 'stream';
  if (m.includes('zip') || m.includes('rar') || m.includes('7z') || m.includes('tar')) return 'archive';
  if (m.includes('font')) return 'font';
  if (m.includes('word') || m.includes('excel') || m.includes('powerpoint') || m.includes('officedocument') || m.includes('opendocument') || m === 'text/plain' || m === 'text/csv') return 'document';
  return null;
}
const dedupe = (items) => { const seen = new Set(); return items.filter((i) => (seen.has(i.url) ? false : (seen.add(i.url), true))); };
function nameFromUrl(url) {
  try { const u = new URL(url); return decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || '') || u.hostname; } catch (e) { return 'file'; }
}
function hostDir() {
  try { return new URL(state.pageUrl).hostname.replace(/[^a-z0-9.-]/gi, '_'); } catch (e) { return 'download'; }
}
function fileNameFor(it) {
  let n = nameFromUrl(it.url).replace(/[\\/:*?"<>|]+/g, '_').slice(0, 120);
  if (it.type === 'stream' && /\.m3u8$/i.test(n)) n = n.replace(/\.m3u8$/i, '') + '.' + (it.saveExt || 'ts');
  if (!/\.[a-z0-9]{2,5}$/i.test(n)) { const ext = MIME_EXT[(it.mime || '').toLowerCase()]; if (ext) n += '.' + ext; }
  return n || 'file';
}
function normalizeUrl(raw) {
  let url = raw.trim();
  if (!url) throw new Error('Paste a link first.');
  if (!/^https?:\/\//i.test(url)) url = (/^(localhost|127\.|\[::1\])/.test(url) ? 'http://' : 'https://') + url;
  try { new URL(url); } catch (e) { throw new Error("That doesn't look like a valid link."); }
  return url;
}
const creds = () => ($('#creds').checked ? 'include' : 'omit');

function setBusy(b, cancellable = true) {
  state.busy = b;
  ['#scan', '#scanTab', '#runAudit'].forEach((s) => ($(s).disabled = b));
  $('#scan').textContent = b ? 'Working…' : 'Scan';
  $('#cancel').hidden = !(b && cancellable);
  if (!b) { setProgress(null); state.ctl = null; }
}
function newController() { state.ctl = new AbortController(); return state.ctl.signal; }

/* ---------- scanning ---------- */

async function fetchScan(url, signal) {
  const res = await AGUtil.xfetch(url, { credentials: creds(), signal });
  if (!res.ok) throw new Error(`The site answered with HTTP ${res.status}.${res.status === 401 || res.status === 403 ? ' It needs a login: tick "Use my login" or use "Scan the tab I\'m on".' : ''}`);
  const ct = res.headers.get('content-type') || '';
  const finalUrl = res.url || url;
  if (!/html|xml/i.test(ct)) {
    if (res.body) res.body.cancel();
    return { items: [{ url: finalUrl, type: typeFromMime(ct) || 'document', tag: 'direct' }], info: AGCrawl.emptyInfo() };
  }
  const doc = new DOMParser().parseFromString(await res.text(), 'text/html');
  const info = AGCrawl.mergeInfo(AGCrawl.emptyInfo(), window.__assetPageInfo(doc, finalUrl));
  return { items: window.__assetScan(doc, finalUrl), info };
}

async function pickTab() {
  const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
  if (!tabs.length) throw new Error('Open a regular web page (http or https) in another tab first.');
  tabs.sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0));
  return tabs[0];
}
async function scanCurrentTab() {
  const tab = await pickTab();
  await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, files: ['scanner.js'] });
  const res = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    func: () => ({ items: window.__assetScan(document, location.href), info: window.__assetPageInfo(document, location.href) }),
  });
  const info = AGCrawl.emptyInfo();
  for (const r of res) if (r.result) AGCrawl.mergeInfo(info, r.result.info);
  return { items: dedupe(res.flatMap((r) => (r.result && r.result.items) || [])), info, pageUrl: tab.url };
}

// One entry point used by both the Scan button and the audit.
async function acquire(url, signal) {
  if ($('#crawl').checked) {
    const max = Math.min(150, Math.max(2, +$('#pages').value || 25));
    const r = await AGCrawl.crawl(url, { maxPages: max, signal, credentials: creds(), onProgress: (t) => setStatus(t) });
    if (!r.pages.length) throw new Error(r.failed[0] ? `Could not load the page (HTTP ${r.failed[0].status || 'network error'}).` : 'Could not load the page.');
    return { items: r.items, info: r.info, mode: 'crawl', note: `${r.pages.length} pages crawled${r.failed.length ? `, ${r.failed.length} failed` : ''}` };
  }
  if ($('#deep').checked) {
    setStatus('Deep scan: a small window opens, loads the page, scrolls it and closes. Takes about 10 to 20 seconds.');
    const r = await chrome.runtime.sendMessage({ type: 'deepScan', url });
    if (!r || !r.ok) throw new Error((r && r.error) || 'Deep scan failed.');
    return { items: r.items, info: r.info, mode: 'deep' };
  }
  setStatus('Fetching the page…');
  const r = await fetchScan(url, signal);
  return { ...r, mode: 'fast' };
}

async function runScan() {
  if (state.busy) return;
  let url;
  try { url = normalizeUrl($('#url').value); } catch (e) { return setStatus(e.message, 'err'); }
  $('#url').value = url;
  const signal = newController();
  setBusy(true, !$('#deep').checked || $('#crawl').checked);
  try {
    const r = await acquire(url, signal);
    loadItems(r.items, r.info, url, r.mode, false, r.note);
  } catch (e) {
    setStatus(signal.aborted ? 'Cancelled.' : e.message || String(e), signal.aborted ? '' : 'err');
  } finally { setBusy(false); }
}

async function runScanTab() {
  if (state.busy) return;
  setBusy(true, false);
  try {
    setStatus('Reading the tab…');
    const { items, info, pageUrl } = await scanCurrentTab();
    $('#url').value = pageUrl;
    loadItems(items, info, pageUrl, 'tab');
  } catch (e) {
    setStatus("Couldn't read that tab: " + (e.message || e), 'err');
  } finally { setBusy(false); }
}

function loadItems(items, info, pageUrl, mode, silent, note) {
  state.pageUrl = pageUrl;
  state.mode = mode;
  state.info = info || AGCrawl.emptyInfo();
  state.items = dedupe(items).map((it, i) => ({ ...it, id: i, name: nameFromUrl(it.url), size: undefined, mime: null, access: '' }));
  state.selected.clear();
  state.filter = 'all';
  state.query = '';
  $('#q').value = '';
  render();
  if (!silent) {
    state.lastTs = Date.now();
    const slim = { ...state.info, inline: [], comments: [] };
    chrome.storage.session.set({ last: { url: pageUrl, items, info: slim, mode, ts: state.lastTs } }).catch(() => {});
  }
  if (!state.items.length) {
    setStatus(mode === 'fast' ? 'Nothing found in the page source. This page probably loads its content with JavaScript. Tick "Deep scan" and try again.' : 'Nothing found on this page.', 'err');
  } else {
    setStatus(`Found ${state.items.length} file${state.items.length === 1 ? '' : 's'}${note ? ` (${note})` : ''}. Checking access and sizes…`, 'ok');
    probeSizes(note);
  }
}

/* ---------- sizes and anonymous access ---------- */

let probeToken = 0;
async function probe(it, signal) {
  try {
    let r = await AGUtil.xfetch(it.url, { method: 'HEAD', credentials: 'omit', timeout: 8000, retries: 0, signal });
    let size = r.headers.get('content-length');
    if (!r.ok && r.status !== 401 && r.status !== 403 && r.status !== 404) {
      r = await AGUtil.xfetch(it.url, { headers: { Range: 'bytes=0-0' }, credentials: 'omit', timeout: 8000, retries: 0, signal });
      if (r.body) r.body.cancel();
      const cr = r.headers.get('content-range');
      size = cr && cr.includes('/') ? cr.split('/')[1] : r.headers.get('content-length');
    }
    if ((size === null || size === '') && (r.status === 200 || r.status === 206)) {
      // Server sent no Content-Length: measure by reading up to 2 MB.
      try {
        const g = await AGUtil.xfetch(it.url, { credentials: 'omit', timeout: 10000, retries: 0, signal });
        const bytes = await AGUtil.readBytes(g, 2 * 1048576 + 1);
        if (bytes.length <= 2 * 1048576) size = String(bytes.length);
      } catch (e) {}
    }
    it.access = r.status === 200 || r.status === 206 ? (r.redirected && /login|signin|sign-in|auth/i.test(r.url) ? 'login' : 'public') : r.status === 401 || r.status === 403 ? 'blocked' : 'error';
    it.status = r.status;
    it.size = size !== null && size !== '' && !isNaN(+size) ? +size : null;
    it.mime = (r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  } catch (e) {
    it.size = null; it.access = 'error';
  }
}

async function probeSizes(note) {
  const token = ++probeToken;
  const queue = state.items.slice(0, 500);
  let i = 0;
  const worker = async () => {
    while (i < queue.length && token === probeToken) {
      const it = queue[i++];
      await probe(it);
      if (token !== probeToken) return;
      const row = document.querySelector(`.row[data-id="${it.id}"]`);
      if (row) {
        row.querySelector('.size').textContent = fmt(it.size);
        const a = row.querySelector('.acc');
        a.textContent = it.access === 'error' ? `HTTP ${it.status || 'err'}` : it.access;
        a.className = 'acc acc-' + it.access;
      }
    }
  };
  await Promise.all(Array.from({ length: 6 }, worker));
  if (token !== probeToken) return;
  const pub = state.items.filter((x) => x.access === 'public').length;
  setStatus(`Found ${state.items.length} file${state.items.length === 1 ? '' : 's'}${note ? ` (${note})` : ''}. ${pub} reachable without logging in.`, 'ok');
  if (state.hideTiny || state.access !== 'any' || state.sort === 'size') render();
}

/* ---------- Files tab rendering ---------- */

function visible() {
  const q = state.query.toLowerCase();
  let v = state.items.filter((it) =>
    (state.filter === 'all' || it.type === state.filter) &&
    (!q || it.url.toLowerCase().includes(q)) &&
    !(state.hideTiny && typeof it.size === 'number' && it.size < 2048) &&
    (state.access === 'any' || (state.access === 'public' && it.access === 'public') || (state.access === 'blocked' && (it.access === 'blocked' || it.access === 'login'))));
  if (state.sort === 'name') v = [...v].sort((a, b) => a.name.localeCompare(b.name));
  else if (state.sort === 'size') v = [...v].sort((a, b) => (b.size || 0) - (a.size || 0));
  else if (state.sort === 'type') v = [...v].sort((a, b) => a.type.localeCompare(b.type) || a.name.localeCompare(b.name));
  return v;
}

function rowHtml(it) {
  const thumb = it.type === 'image'
    ? `<img class="timg" src="${esc(it.url)}" loading="lazy" referrerpolicy="no-referrer" alt="">`
    : `<span class="ticon">${ICONS[it.type] || '📄'}</span>`;
  let host = '';
  try { host = new URL(it.url).hostname; } catch (e) {}
  const acc = it.access ? (it.access === 'error' ? `HTTP ${it.status || 'err'}` : it.access) : '…';
  return `<div class="row t-${it.type}" data-id="${it.id}">
    <input type="checkbox" class="chk" ${state.selected.has(it.id) ? 'checked' : ''} aria-label="Select ${esc(it.name)}">
    <a class="thumb" href="${esc(it.url)}" target="_blank" rel="noreferrer" title="Open in a new tab">${thumb}</a>
    <div class="meta"><div class="name" title="${esc(it.url)}">${esc(it.name)}</div>
      <div class="sub"><span class="tp">${it.type}</span> · <span class="size">${fmt(it.size)}</span> · <span class="acc acc-${it.access}">${esc(acc)}</span> · ${esc(host)}</div></div>
    <button class="dl" title="Download this file">Download</button>
  </div>`;
}

function render() {
  const counts = { all: state.items.length };
  state.items.forEach((i) => (counts[i.type] = (counts[i.type] || 0) + 1));
  $('#chips').innerHTML = TYPES.filter(([k]) => k === 'all' || counts[k])
    .map(([k, l]) => `<button class="tile t-${k} ${state.filter === k ? 'active' : ''}" data-type="${k}"><span class="ti">${ICONS[k] || ''}</span><span class="tn">${counts[k] || 0}</span><span class="tl">${l}</span></button>`).join('');
  const vis = visible();
  $('#list').innerHTML = vis.length ? vis.map(rowHtml).join('')
    : `<div class="empty">${state.items.length ? 'No files match this filter.' : 'Files found on the page will appear here.<br>Paste a link above and press Scan.'}</div>`;
  updateFooter();
}

function updateFooter() {
  const vis = visible();
  const n = state.selected.size;
  $('#count').textContent = `${n} selected of ${vis.length} shown`;
  $('#copy').disabled = vis.length === 0;
  $('#csv').disabled = state.items.length === 0;
  $('#dlSel').disabled = n === 0;
  $('#dlZip').disabled = n === 0;
  $('#all').checked = vis.length > 0 && vis.every((i) => state.selected.has(i.id));
}

/* ---------- downloading ---------- */

let failedDownloads = 0;
const myDownloads = new Set();
chrome.downloads.onChanged.addListener((d) => {
  if (myDownloads.has(d.id) && d.state && d.state.current === 'interrupted') {
    failedDownloads++;
    setStatus(`${failedDownloads} download${failedDownloads === 1 ? '' : 's'} failed. The server may block direct downloads, or the file needs a login.`, 'err');
  }
});

async function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const id = await chrome.downloads.download({ url, filename, conflictAction: 'uniquify' });
  myDownloads.add(id);
  setTimeout(() => URL.revokeObjectURL(url), 5 * 60 * 1000);
}
async function saveText(text, name, mime) { await downloadBlob(new Blob([text], { type: mime }), `AssetGrabber/${name}`); }

async function downloadStream(it, signal) {
  const r = await AGStream.download(it.url, { signal, onProgress: (d, n) => { setStatus(`Saving stream: segment ${d} of ${n}…`); setProgress(d / n); } });
  it.saveExt = r.ext;
  await downloadBlob(r.blob, `AssetGrabber/${hostDir()}/${fileNameFor(it)}`);
}

async function downloadOne(it) {
  if (it.type === 'stream') {
    const signal = newController();
    setBusy(true);
    try { await downloadStream(it, signal); setStatus('Stream saved.', 'ok'); return true; }
    catch (e) { setStatus(signal.aborted ? 'Cancelled.' : e.message || String(e), signal.aborted ? '' : 'err'); return false; }
    finally { setBusy(false); }
  }
  const filename = `AssetGrabber/${hostDir()}/${fileNameFor(it)}`;
  try {
    const id = await chrome.downloads.download({ url: it.url, filename, conflictAction: 'uniquify' });
    myDownloads.add(id);
    return true;
  } catch (e) {
    try {
      const r = await AGUtil.xfetch(it.url, { credentials: 'omit', timeout: 60000 });
      if (!r.ok) throw new Error('bad');
      await downloadBlob(await r.blob(), filename);
      return true;
    } catch (e2) { return false; }
  }
}
const selectedItems = () => state.items.filter((i) => state.selected.has(i.id));

async function downloadSelected() {
  const items = selectedItems();
  failedDownloads = 0;
  let bad = 0;
  for (let k = 0; k < items.length; k++) {
    setStatus(`Starting download ${k + 1} of ${items.length}…`);
    if (!(await downloadOne(items[k]))) bad++;
    await sleep(120);
  }
  setStatus(bad ? `Started ${items.length - bad} downloads. ${bad} could not be started.` : `Started ${items.length} download${items.length === 1 ? '' : 's'}.`, bad ? 'err' : 'ok');
}

async function downloadZip() {
  const items = selectedItems();
  if (!items.length || state.busy) return;
  const known = items.reduce((s, i) => s + (i.size || 0), 0);
  if (known > 300 * 1048576 && !confirm(`These files add up to about ${fmt(known)}. The ZIP is built in memory, so this may be slow. Continue?`)) return;
  const signal = newController();
  setBusy(true);
  try {
    const got = [], failed = [];
    const queue = [...items];
    let done = 0;
    await AGUtil.pool(queue, 4, async (it) => {
      try {
        if (it.type === 'stream') {
          const s = await AGStream.download(it.url, { signal });
          it.saveExt = s.ext;
          got.push({ it, data: new Uint8Array(await s.blob.arrayBuffer()) });
        } else {
          const r = await AGUtil.xfetch(it.url, { credentials: 'omit', timeout: 60000, signal });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          got.push({ it, data: new Uint8Array(await r.arrayBuffer()) });
        }
      } catch (e) { failed.push(it); }
      done++;
      setStatus(`Fetching files for the ZIP: ${done} of ${items.length}…`);
      setProgress(done / items.length);
    }, signal);
    if (signal.aborted) throw new Error('Cancelled.');
    if (!got.length) throw new Error('None of the selected files could be fetched.');
    got.sort((a, b) => a.it.id - b.it.id);
    const used = new Map();
    const entries = got.map(({ it, data }) => {
      let name = `${FOLDERS[it.type] || 'other'}/${fileNameFor(it)}`;
      const n = used.get(name) || 0;
      used.set(name, n + 1);
      if (n) name = name.replace(/(\.[^./]+)?$/, ` (${n})$1`);
      return { name, data };
    });
    setStatus('Building the ZIP…');
    await downloadBlob(AGZip.buildZip(entries), `AssetGrabber/${hostDir()}-assets.zip`);
    setStatus(failed.length ? `ZIP saved with ${got.length} files. ${failed.length} could not be fetched.` : `ZIP saved with ${got.length} files.`, failed.length ? 'err' : 'ok');
  } catch (e) {
    setStatus(e.message || String(e), 'err');
  } finally { setBusy(false); }
}

async function copyLinks() {
  const items = selectedItems();
  const list = items.length ? items : visible();
  await navigator.clipboard.writeText(list.map((i) => i.url).join('\n'));
  setStatus(`Copied ${list.length} link${list.length === 1 ? '' : 's'}.`, 'ok');
}

function exportCsv() {
  const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = [['url', 'type', 'name', 'size_bytes', 'anonymous_access', 'http_status', 'content_type', 'found_via']];
  for (const i of state.items) rows.push([i.url, i.type, i.name, i.size ?? '', i.access, i.status ?? '', i.mime ?? '', i.tag ?? '']);
  return saveText(rows.map((r) => r.map(q).join(',')).join('\n'), `${hostDir()}-files.csv`, 'text/csv').then(() => setStatus('CSV saved.', 'ok'));
}

/* ---------- Developer tab ---------- */

const mask = (s) => AGAudit.redact(String(s));
const secretOf = (f) => f.secret || f.raw || '';
const shown = (f) => (state.reveal ? secretOf(f) : f.secret ? mask(f.secret) : '•••• file contents hidden ••••');

function auditOpts() {
  return { paths: $('#oPaths').checked, headers: $('#oHeaders').checked, secrets: $('#oSecrets').checked, cloud: $('#oCloud').checked, files: $('#oFiles').checked };
}

async function runAuditClick() {
  if (state.busy) return;
  let url;
  try { url = normalizeUrl($('#url').value); } catch (e) { return setStatus(e.message, 'err'); }
  $('#url').value = url;
  const signal = newController();
  setBusy(true);
  state.audit = null;
  state.reveal = false;
  renderDev();
  try {
    const sameTarget = state.pageUrl === url && state.items.length;
    const needCrawl = $('#crawl').checked && state.mode !== 'crawl';
    if (!sameTarget || needCrawl) {
      const r = await acquire(url, signal);
      loadItems(r.items, r.info, url, r.mode, false, r.note);
    }
    const result = await AGAudit.run({
      pageUrl: url, items: state.items, info: state.info, opts: auditOpts(), signal, credentials: creds(),
      onProgress: (label, frac) => { setStatus(label); setProgress(frac); },
    });
    state.audit = result;
    renderDev();
    const c = (s) => result.findings.filter((f) => f.sev === s).length;
    const ns = result.findings.filter(secretOf).length;
    setStatus(`Done: ${c('critical')} critical, ${c('high')} high, ${c('medium')} medium, ${c('low')} low. ${ns} secret${ns === 1 ? '' : 's'} or sensitive file${ns === 1 ? '' : 's'} found.${result.errors.length ? ` ${result.errors.length} check(s) could not run.` : ''}`, c('critical') || c('high') ? 'err' : 'ok');
  } catch (e) {
    setStatus(signal.aborted ? 'Audit cancelled.' : e.message || String(e), signal.aborted ? '' : 'err');
  } finally { setBusy(false); }
}

const copyBtn = (idx) => (state.reveal ? `<button class="mini" data-fi="${idx}">Copy</button>` : '');

function findingsView(r) {
  const list = r.findings.map((f, i) => [f, i]).filter(([f]) => state.sevFilter === 'all' || f.sev === state.sevFilter);
  if (!list.length) return `<div class="empty">${r.findings.length ? 'Nothing at this severity.' : 'No findings. These checks did not detect anything exposed.'}${r.errors.length ? '<br><br>Checks that could not run:<br>' + r.errors.map(esc).join('<br>') : ''}</div>`;
  return list.map(([f, i]) => `<div class="find sev-${f.sev}">
      <div class="fh"><span class="sv">${SEV_LABEL[f.sev]}</span><b>${esc(f.title)}</b></div>
      <div class="fu"><a href="${esc(f.url.split(' (')[0])}" target="_blank" rel="noreferrer">${esc(f.url)}</a></div>
      <div class="fe">${esc(f.evidence)}</div>
      ${secretOf(f) ? `<div class="fsec"><code>${esc(shown(f))}</code>${copyBtn(i)}</div>` : ''}
      <div class="ff">Fix: ${esc(f.fix)}</div></div>`).join('');
}

function secretsView(r) {
  const list = r.findings.map((f, i) => [f, i]).filter(([f]) => secretOf(f));
  const inv = r.inventory.cloud;
  if (!list.length && !inv.anon.length) return `<div class="empty">No secrets or sensitive file contents were found.<br>The checks cover API keys, tokens, private keys, connection strings and exposed config files.</div>`;
  let h = `<div class="secthead">${list.length} secret${list.length === 1 ? '' : 's'} and sensitive file${list.length === 1 ? '' : 's'}<span class="spacer"></span>${state.reveal ? '<button class="mini" data-copyall="1">Copy all values</button>' : '<span class="subnote" style="padding:0">Values are masked. Use “Reveal secret values”.</span>'}</div>`;
  h += list.map(([f, i]) => `<div class="srow">
      <div class="sk"><b>${esc(f.title.replace(/ found in client-side code$/, ''))}</b><span>${esc(f.url)}</span></div>
      <div class="sval">${esc(shown(f))}</div>${copyBtn(i)}</div>`).join('');
  return h;
}

const stateLabel = { open: ['open without login', 'open'], protected: ['needs login', 'protected'], redirect: ['redirects', 'other'], page: ['returns a page', 'other'], other: ['', 'other'] };

function endpointsView(r) {
  const inv = r.inventory;
  let h = `<div class="secthead">API endpoints (${inv.endpointsFound.length} found in code and network)</div>`;
  if (!inv.endpoints.length) h += `<div class="subnote">${inv.endpointsFound.length ? 'Endpoints were found but not tested (API checks were off).' : 'No API endpoints were found. Single-page apps often reveal more with Deep scan.'}</div>`;
  else h += `<table class="kv">${inv.endpoints.map((e) => { const [t, c] = stateLabel[e.state] || stateLabel.other; return `<tr><td>${esc(e.url.replace(r.origin, ''))}</td><td><span class="pill ${c}">${esc(t || 'HTTP ' + e.status)}</span> HTTP ${e.status || '—'}</td></tr>`; }).join('')}</table>`;
  h += `<div class="secthead">Scripts (${inv.scripts.length} read, ${inv.inlineScripts} inline)</div>`;
  h += inv.scripts.length ? `<table class="kv">${inv.scripts.map((s) => `<tr><td>${esc(s.url)}</td><td>${fmt(s.bytes)} ${s.sourceMap ? '<span class="pill bad">source map public</span>' : s.status === 200 ? '<span class="pill good">no source map</span>' : `HTTP ${s.status}`}</td></tr>`).join('')}</table>` : '<div class="subnote">No external scripts were read.</div>';
  const c = inv.cloud;
  h += `<div class="secthead">Cloud references</div>`;
  const rows = [
    ...c.supabase.map((u) => ['Supabase project', u]),
    ...c.anon.map((k) => ['Supabase anon key', state.reveal ? k : mask(k)]),
    ...c.firebase.map((u) => ['Firebase database', u]),
    ...c.buckets.map(([u, l]) => [l + ' bucket', u]),
  ];
  h += rows.length ? `<table class="kv">${rows.map(([a, b]) => `<tr><td>${esc(a)}</td><td>${esc(b)}</td></tr>`).join('')}</table>` : '<div class="subnote">No Supabase, Firebase or bucket URLs were found in the client code.</div>';
  return h;
}

function detailsView(r) {
  const inv = r.inventory;
  const hdr = Object.entries(inv.headers || {});
  let h = `<div class="secthead">Response headers (HTTP ${inv.status || '—'})</div>`;
  h += hdr.length ? `<table class="kv">${hdr.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table>` : '<div class="subnote">Headers were not read (header checks were off).</div>';
  h += `<div class="secthead">Cookies your browser holds for this site (names and flags only)</div>`;
  h += inv.cookies.length ? `<table class="kv">${inv.cookies.map((c) => `<tr><td>${esc(c.name)}</td><td>${c.secure ? '<span class="pill good">Secure</span>' : '<span class="pill bad">not Secure</span>'} ${c.httpOnly ? '<span class="pill good">HttpOnly</span>' : '<span class="pill other">JS-readable</span>'} <span class="pill other">SameSite ${esc(c.sameSite)}</span></td></tr>`).join('')}</table>` : '<div class="subnote">No cookies stored for this site.</div>';
  h += `<div class="secthead">Forms</div>`;
  h += inv.forms.length ? `<table class="kv">${inv.forms.map((f) => `<tr><td>${esc(f.method.toUpperCase())}</td><td>${esc(f.action)} ${f.password ? '<span class="pill other">password field</span>' : ''}</td></tr>`).join('')}</table>` : '<div class="subnote">No forms found.</div>';
  h += `<div class="secthead">robots.txt</div>`;
  h += inv.robots.disallow.length ? `<table class="kv">${inv.robots.disallow.map((d) => `<tr><td>Disallow</td><td>${esc(d)}</td></tr>`).join('')}</table>` : '<div class="subnote">No Disallow rules (or no robots.txt).</div>';
  if (inv.generator) h += `<div class="secthead">Generator</div><div class="subnote">${esc(inv.generator)}</div>`;
  return h;
}

function renderDev() {
  const r = state.audit;
  $('#reveal').disabled = !r;
  $('#reveal').textContent = state.reveal ? 'Hide secret values' : 'Reveal secret values';
  $('#reveal').setAttribute('aria-pressed', String(state.reveal));
  $('#expMd').disabled = !r;
  $('#expJson').disabled = !r;
  const nSec = r ? r.findings.filter(secretOf).length : 0;
  document.querySelectorAll('#devtabs .subtab').forEach((b) => {
    b.classList.toggle('active', b.dataset.view === state.devView);
    const base = { findings: 'Findings', secrets: 'Secrets', endpoints: 'Endpoints & scripts', details: 'Page details' }[b.dataset.view];
    b.textContent = r && b.dataset.view === 'findings' ? `${base} (${r.findings.length})` : r && b.dataset.view === 'secrets' ? `${base} (${nSec})` : base;
  });
  $('#sevchips').hidden = !(r && state.devView === 'findings');
  const view = $('#devView');
  if (!r) {
    $('#devcount').textContent = '';
    view.innerHTML = `<div class="empty">Press “Find all vulnerabilities and secrets”.<br>You get findings with fixes, every secret and sensitive file, the API endpoints and scripts, and the page's headers and cookies.</div>`;
    return;
  }
  const counts = {};
  r.findings.forEach((f) => (counts[f.sev] = (counts[f.sev] || 0) + 1));
  $('#sevchips').innerHTML = `<button class="chip ${state.sevFilter === 'all' ? 'active' : ''}" data-sev="all">All<b>${r.findings.length}</b></button>` +
    AGAudit.SEV.filter((s) => counts[s]).map((s) => `<button class="chip sevchip sev-${s} ${state.sevFilter === s ? 'active' : ''}" data-sev="${s}">${SEV_LABEL[s]}<b>${counts[s]}</b></button>`).join('');
  view.innerHTML = { findings: findingsView, secrets: secretsView, endpoints: endpointsView, details: detailsView }[state.devView](r);
  $('#devcount').textContent = `${r.origin} · ${r.fileCount} files examined · ${Math.round((r.finished - r.started) / 1000)}s`;
}

async function copyText(t, msg) { await navigator.clipboard.writeText(t); setStatus(msg, 'ok'); }

/* ---------- wiring ---------- */

function showTab(t) {
  $('#panelFiles').hidden = t !== 'files';
  $('#panelDev').hidden = t !== 'dev';
  $('#tabFiles').classList.toggle('active', t === 'files');
  $('#tabDev').classList.toggle('active', t === 'dev');
}
$('#tabFiles').addEventListener('click', () => showTab('files'));
$('#tabDev').addEventListener('click', () => showTab('dev'));
$('#scan').addEventListener('click', runScan);
$('#scanTab').addEventListener('click', runScanTab);
$('#runAudit').addEventListener('click', runAuditClick);
$('#cancel').addEventListener('click', () => { if (state.ctl) state.ctl.abort(); });
$('#url').addEventListener('keydown', (e) => { if (e.key === 'Enter') (!$('#panelDev').hidden ? runAuditClick : runScan)(); });
$('#deep').addEventListener('change', (e) => { if (e.target.checked) $('#crawl').checked = false; });
$('#crawl').addEventListener('change', (e) => { if (e.target.checked) $('#deep').checked = false; });
$('#q').addEventListener('input', (e) => { state.query = e.target.value; render(); });
$('#tiny').addEventListener('change', (e) => { state.hideTiny = e.target.checked; render(); });
$('#access').addEventListener('change', (e) => { state.access = e.target.value; render(); });
$('#sort').addEventListener('change', (e) => { state.sort = e.target.value; render(); });
$('#dlSel').addEventListener('click', downloadSelected);
$('#dlZip').addEventListener('click', downloadZip);
$('#copy').addEventListener('click', copyLinks);
$('#csv').addEventListener('click', exportCsv);
const wantSecrets = () => state.reveal && confirm('Include the revealed secret values in this report?\n\nThe file will contain real secrets, so store it privately and rotate anything listed.');
$('#expMd').addEventListener('click', () => saveText(AGAudit.toMarkdown(state.audit, { secrets: wantSecrets() }), `${hostDir()}-security-report.md`, 'text/markdown'));
$('#expJson').addEventListener('click', () => saveText(AGAudit.toJson(state.audit, { secrets: wantSecrets() }), `${hostDir()}-security-report.json`, 'application/json'));
$('#reveal').addEventListener('click', () => { state.reveal = !state.reveal; renderDev(); });
$('#devtabs').addEventListener('click', (e) => { const b = e.target.closest('.subtab'); if (b) { state.devView = b.dataset.view; renderDev(); } });
$('#devView').addEventListener('click', (e) => {
  const one = e.target.closest('[data-fi]');
  if (one) return copyText(secretOf(state.audit.findings[+one.dataset.fi]), 'Copied.');
  if (e.target.closest('[data-copyall]')) {
    const vals = state.audit.findings.filter(secretOf).map((f) => `${f.title} (${f.url})\n${secretOf(f)}`);
    copyText(vals.join('\n\n'), `Copied ${vals.length} values.`);
  }
});
$('#popout').addEventListener('click', async () => {
  await chrome.tabs.create({ url: chrome.runtime.getURL('popup.html?tab=1') });
  window.close();
});
$('#all').addEventListener('change', (e) => {
  visible().forEach((it) => (e.target.checked ? state.selected.add(it.id) : state.selected.delete(it.id)));
  document.querySelectorAll('#list .chk').forEach((c) => (c.checked = e.target.checked));
  updateFooter();
});
$('#chips').addEventListener('click', (e) => { const b = e.target.closest('.tile'); if (b) { state.filter = b.dataset.type; render(); } });
$('#sevchips').addEventListener('click', (e) => { const b = e.target.closest('.chip'); if (b) { state.sevFilter = b.dataset.sev; renderDev(); } });
$('#list').addEventListener('change', (e) => {
  if (!e.target.classList.contains('chk')) return;
  const id = +e.target.closest('.row').dataset.id;
  e.target.checked ? state.selected.add(id) : state.selected.delete(id);
  updateFooter();
});
$('#list').addEventListener('click', async (e) => {
  const b = e.target.closest('.dl');
  if (!b) return;
  const it = state.items[+b.closest('.row').dataset.id];
  failedDownloads = 0;
  if (it.type !== 'stream') setStatus(`Downloading ${fileNameFor(it)}…`);
  const ok = await downloadOne(it);
  if (it.type !== 'stream') setStatus(ok ? 'Download started.' : "That file couldn't be downloaded.", ok ? 'ok' : 'err');
});
$('#list').addEventListener('error', (e) => {
  if (e.target.classList && e.target.classList.contains('timg')) {
    const s = document.createElement('span');
    s.className = 'ticon';
    s.textContent = ICONS.image;
    e.target.replaceWith(s);
  }
}, true);

// A deep scan keeps running if this popup closes; pick up its result when it lands.
chrome.storage.onChanged.addListener((ch, area) => {
  if (area === 'session' && ch.last && ch.last.newValue && !state.busy) {
    const l = ch.last.newValue;
    if (l.ts === state.lastTs) return;
    state.lastTs = l.ts;
    $('#url').value = l.url;
    loadItems(l.items, l.info, l.url, l.mode, true);
  }
});

(async function init() {
  if (new URLSearchParams(location.search).get('tab')) document.body.classList.add('tabmode');
  render();
  renderDev();
  try {
    const { last, busy } = await chrome.storage.session.get(['last', 'busy']);
    if (last) {
      state.lastTs = last.ts;
      $('#url').value = last.url;
      loadItems(last.items, last.info, last.url, last.mode, true);
    }
    if (busy && Date.now() - busy.ts < 90000) {
      $('#url').value = busy.url;
      setStatus('A deep scan is still running. Results will appear here when it finishes.');
    }
  } catch (e) {}
  $('#url').focus();
})();
