// Deep scan: open the page in a small real window (so JavaScript and lazy-loading work),
// scroll it, collect assets and page facts, then close the window.
// It runs here so it keeps going if the popup closes.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function waitComplete(tabId, timeoutMs) {
  return new Promise((resolve) => {
    const finish = () => {
      chrome.tabs.onUpdated.removeListener(listener);
      clearTimeout(timer);
      resolve();
    };
    const listener = (id, info) => { if (id === tabId && info.status === 'complete') finish(); };
    chrome.tabs.onUpdated.addListener(listener);
    const timer = setTimeout(finish, timeoutMs);
    chrome.tabs.get(tabId).then((t) => {
      if (t.status === 'complete' && t.url && t.url !== 'about:blank') finish();
    }).catch(() => {});
  });
}

// Runs inside the page (must be self-contained).
async function scrollAndScan(maxMs) {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const height = () => Math.max(document.documentElement.scrollHeight, document.body ? document.body.scrollHeight : 0);
  const start = Date.now();
  let last = -1, stable = 0;
  while (Date.now() - start < maxMs) {
    window.scrollTo(0, height());
    await wait(600);
    const h = height();
    if (h === last) { if (++stable >= 3) break; } else { stable = 0; last = h; }
  }
  window.scrollTo(0, 0);
  await wait(500);
  return { items: window.__assetScan(document, location.href), info: window.__assetPageInfo(document, location.href) };
}

async function deepScan(url) {
  const win = await chrome.windows.create({ url, type: 'popup', focused: false, width: 520, height: 380, left: 0, top: 0 });
  const tabId = win.tabs[0].id;
  const keepAlive = setInterval(() => chrome.runtime.getPlatformInfo(), 20000);
  try {
    await waitComplete(tabId, 30000);
    await sleep(1500); // let single-page apps finish rendering
    await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['scanner.js'] });
    const res = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, func: scrollAndScan, args: [10000] });
    const seen = new Set();
    const items = res.flatMap((r) => (r.result && r.result.items) || []).filter((i) => (seen.has(i.url) ? false : (seen.add(i.url), true)));
    const info = { scripts: [], inline: [], forms: [], links: [], comments: [], requests: [], generator: '' };
    const sS = new Set(), sR = new Set();
    for (const r of res) {
      const x = r.result && r.result.info;
      if (!x) continue;
      for (const s of x.scripts) if (!sS.has(s.url)) { sS.add(s.url); info.scripts.push(s); }
      for (const q of x.requests) if (!sR.has(q.url)) { sR.add(q.url); info.requests.push(q); }
      info.inline.push(...x.inline.slice(0, 60));
      info.forms.push(...x.forms);
      info.comments.push(...x.comments.slice(0, 100));
      info.links.push(...x.links.slice(0, 200));
      if (!info.generator) info.generator = x.generator;
    }
    return { items, info };
  } finally {
    clearInterval(keepAlive);
    try { await chrome.windows.remove(win.id); } catch (e) {}
  }
}

const slim = (info) => ({ ...info, inline: [], comments: [] }); // keep stored state small

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== 'deepScan') return;
  chrome.storage.session.set({ busy: { url: msg.url, ts: Date.now() } });
  deepScan(msg.url)
    .then(async ({ items, info }) => {
      await chrome.storage.session.remove('busy');
      await chrome.storage.session.set({ last: { url: msg.url, items, info: slim(info), mode: 'deep', ts: Date.now() } });
      sendResponse({ ok: true, items, info });
    })
    .catch(async (e) => {
      await chrome.storage.session.remove('busy');
      sendResponse({ ok: false, error: (e && e.message) || String(e) });
    });
  return true;
});
