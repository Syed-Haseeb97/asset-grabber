// Same-site crawler (static HTML only) plus robots.txt / sitemap helpers.
(() => {
  const { xfetch, readBytes, pool } = AGUtil;
  const dec = new TextDecoder('utf-8', { fatal: false });
  const ASSET_LINK = /\.(?:jpe?g|png|gif|webp|svg|avif|ico|pdf|zip|rar|7z|gz|docx?|xlsx?|pptx?|mp[34]|webm|mov|avi|css|js|map|woff2?|ttf|json|xml|txt)(?:[?#]|$)/i;

  const emptyInfo = () => ({ scripts: [], inline: [], forms: [], links: [], comments: [], requests: [], generator: '' });

  function mergeInfo(a, b) {
    const seenS = new Set(a.scripts.map((s) => s.url));
    for (const s of b.scripts || []) if (!seenS.has(s.url)) { seenS.add(s.url); a.scripts.push(s); }
    a.inline.push(...(b.inline || []));
    if (a.inline.length > 120) a.inline.length = 120;
    a.forms.push(...(b.forms || []));
    a.comments.push(...(b.comments || []));
    if (a.comments.length > 300) a.comments.length = 300;
    const seenL = new Set(a.links);
    for (const l of b.links || []) if (!seenL.has(l)) { seenL.add(l); a.links.push(l); }
    const seenR = new Set(a.requests.map((r) => r.url));
    for (const r of b.requests || []) if (!seenR.has(r.url)) { seenR.add(r.url); a.requests.push(r); }
    if (!a.generator && b.generator) a.generator = b.generator;
    return a;
  }

  async function fetchRobots(origin, signal) {
    const out = { disallow: [], sitemaps: [] };
    try {
      const r = await xfetch(origin + '/robots.txt', { signal, retries: 0, timeout: 8000 });
      if (!r.ok || /html/i.test(r.headers.get('content-type') || '')) return out;
      const t = dec.decode(await readBytes(r, 200000));
      for (const line of t.split(/\r?\n/)) {
        let m = /^\s*disallow:\s*(\S+)/i.exec(line);
        if (m && !out.disallow.includes(m[1])) out.disallow.push(m[1]);
        m = /^\s*sitemap:\s*(\S+)/i.exec(line);
        if (m && !out.sitemaps.includes(m[1])) out.sitemaps.push(m[1]);
      }
    } catch (e) {}
    return out;
  }

  async function sitemapUrls(origin, robots, signal) {
    const urls = new Set();
    const maps = robots.sitemaps.length ? robots.sitemaps.slice(0, 3) : [origin + '/sitemap.xml'];
    for (const m of maps) {
      try {
        const r = await xfetch(m, { signal, retries: 0, timeout: 8000 });
        if (!r.ok) continue;
        const t = dec.decode(await readBytes(r, 500000));
        for (const x of t.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)) { if (x[1].startsWith(origin)) urls.add(x[1]); if (urls.size >= 60) break; }
      } catch (e) {}
    }
    return [...urls];
  }

  async function crawl(start, o = {}) {
    const { maxPages = 25, maxDepth = 3, signal, credentials = 'omit', onProgress } = o;
    const origin = new URL(start).origin;
    const seen = new Set();
    const queue = [{ url: start, depth: 0 }];
    const items = new Map();
    const info = emptyInfo();
    const pages = [], failed = [];
    const robots = await fetchRobots(origin, signal);
    for (const u of await sitemapUrls(origin, robots, signal)) queue.push({ url: u, depth: 1 });

    while (queue.length && pages.length < maxPages && !(signal && signal.aborted)) {
      const batch = [];
      while (queue.length && batch.length < 4) {
        const n = queue.shift();
        const key = n.url.split('#')[0];
        if (seen.has(key)) continue;
        seen.add(key);
        batch.push(n);
      }
      await pool(batch, 4, async (n) => {
        if (pages.length >= maxPages) return;
        try {
          const res = await xfetch(n.url, { credentials, signal });
          if (!res.ok) { failed.push({ url: n.url, status: res.status }); return; }
          if (!/html/i.test(res.headers.get('content-type') || '')) return;
          const doc = new DOMParser().parseFromString(await res.text(), 'text/html');
          const finalUrl = res.url || n.url;
          pages.push(finalUrl);
          for (const it of window.__assetScan(doc, finalUrl)) if (!items.has(it.url)) items.set(it.url, it);
          const pi = window.__assetPageInfo(doc, finalUrl);
          mergeInfo(info, pi);
          if (n.depth < maxDepth) {
            for (const l of pi.links) {
              try {
                const u = new URL(l);
                if (u.origin !== origin || ASSET_LINK.test(u.pathname + u.search)) continue;
                const key = u.href.split('#')[0];
                if (!seen.has(key)) queue.push({ url: key, depth: n.depth + 1 });
              } catch (e) {}
            }
          }
          if (onProgress) onProgress(`Crawling… ${pages.length} page${pages.length === 1 ? '' : 's'}, ${items.size} files`);
        } catch (e) {
          if (!(signal && signal.aborted)) failed.push({ url: n.url, status: 0 });
        }
      }, signal);
    }
    return { items: [...items.values()], info, pages, failed, robots };
  }

  globalThis.AGCrawl = { crawl, fetchRobots, emptyInfo, mergeInfo };
})();
