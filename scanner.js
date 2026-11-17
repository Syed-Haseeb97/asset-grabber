// Shared page scanner. Used in two ways:
//  1. popup.js calls it on a DOMParser document (static scan of fetched HTML)
//  2. it is injected into a real tab (deep scan / current tab) where it can also
//     read computed styles and the browser's own list of loaded resources.
(() => {
  if (window.__assetScan) return;

  const EXT = {};
  const reg = (type, list) => list.split(' ').forEach((e) => (EXT[e] = type));
  reg('image', 'jpg jpeg jfif png gif webp svg avif bmp ico tif tiff heic apng');
  reg('video', 'mp4 webm mov mkv avi m4v ogv flv wmv 3gp mpg mpeg');
  reg('audio', 'mp3 wav ogg oga m4a aac flac opus wma aif aiff');
  reg('pdf', 'pdf');
  reg('document', 'doc docx xls xlsx ppt pptx odt ods odp rtf txt csv tsv epub mobi');
  reg('archive', 'zip rar 7z tar gz tgz bz2 xz');
  reg('stream', 'm3u8 mpd');
  reg('font', 'woff woff2 ttf otf eot');
  reg('config', 'env sql sqlite sqlite3 db bak old orig swp log pem key crt cer p12 pfx ini conf cfg yml yaml toml properties map');

  const typeFromPath = (pathname) => {
    const m = /\.([a-z0-9]{2,5})$/i.exec(pathname);
    return m ? EXT[m[1].toLowerCase()] || null : null;
  };

  const LAZY_IMG = ['data-src', 'data-lazy-src', 'data-original', 'data-lazy', 'data-image', 'data-img', 'data-full', 'data-hi-res-src'];
  const META_KEYS = {
    'og:image': 'image', 'og:image:url': 'image', 'og:image:secure_url': 'image',
    'twitter:image': 'image', 'twitter:image:src': 'image',
    'og:video': 'video', 'og:video:url': 'video', 'og:video:secure_url': 'video',
    'og:audio': 'audio', 'og:audio:url': 'audio', 'og:audio:secure_url': 'audio',
  };

  window.__assetScan = (doc, base) => {
    const live = !!doc.defaultView;
    const found = new Map();

    let baseHref = base;
    try {
      const b = doc.querySelector('base[href]');
      if (b) baseHref = new URL(b.getAttribute('href'), base).href;
    } catch (e) {}

    const push = (raw, hint, tag) => {
      if (!raw) return;
      raw = String(raw).trim();
      if (!raw || /^(data:|blob:|javascript:|about:|mailto:|tel:|#)/i.test(raw)) return;
      let abs;
      try { abs = new URL(raw, baseHref); } catch (e) { return; }
      if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return;
      abs.hash = '';
      const type = typeFromPath(abs.pathname) || hint;
      if (!type) return;
      const url = abs.href;
      if (!found.has(url)) found.set(url, { url, type, tag });
    };
    const pushSrcset = (v, hint, tag) => {
      if (!v) return;
      v.split(',').forEach((part) => {
        const u = part.trim().split(/\s+/)[0];
        if (u) push(u, hint, tag);
      });
    };
    const pushCss = (text, tag) => {
      if (!text) return;
      const re = /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi;
      let m;
      while ((m = re.exec(text))) push(m[2], 'image', tag);
    };

    // Images
    doc.querySelectorAll('img').forEach((el) => {
      push(el.getAttribute('src'), 'image', 'img');
      LAZY_IMG.forEach((a) => push(el.getAttribute(a), 'image', 'img'));
      pushSrcset(el.getAttribute('srcset'), 'image', 'img');
      pushSrcset(el.getAttribute('data-srcset'), 'image', 'img');
      if (live) push(el.currentSrc, 'image', 'img');
    });
    doc.querySelectorAll('[data-bg],[data-background],[data-background-image],[data-poster]').forEach((el) => {
      ['data-bg', 'data-background', 'data-background-image', 'data-poster'].forEach((a) => push(el.getAttribute(a), 'image', 'lazy'));
    });

    // <source> inside picture / video / audio
    doc.querySelectorAll('source').forEach((el) => {
      const p = el.parentElement ? el.parentElement.tagName.toLowerCase() : '';
      const hint = p === 'video' ? 'video' : p === 'audio' ? 'audio' : p === 'picture' ? 'image' : null;
      push(el.getAttribute('src'), hint, 'source');
      pushSrcset(el.getAttribute('srcset'), 'image', 'source');
    });

    // Media elements
    doc.querySelectorAll('video').forEach((el) => {
      push(el.getAttribute('src'), 'video', 'video');
      push(el.getAttribute('data-src'), 'video', 'video');
      push(el.getAttribute('poster'), 'image', 'poster');
      if (live) push(el.currentSrc, 'video', 'video');
    });
    doc.querySelectorAll('audio').forEach((el) => {
      push(el.getAttribute('src'), 'audio', 'audio');
      if (live) push(el.currentSrc, 'audio', 'audio');
    });

    // Embedded documents
    doc.querySelectorAll('embed[src]').forEach((el) => push(el.getAttribute('src'), null, 'embed'));
    doc.querySelectorAll('object[data]').forEach((el) => push(el.getAttribute('data'), null, 'object'));
    doc.querySelectorAll('iframe[src]').forEach((el) => push(el.getAttribute('src'), null, 'iframe'));

    // Links to files
    doc.querySelectorAll('a[href]').forEach((el) => push(el.getAttribute('href'), null, 'link'));

    // Meta + link tags
    doc.querySelectorAll('meta[content]').forEach((el) => {
      const key = (el.getAttribute('property') || el.getAttribute('name') || '').toLowerCase();
      if (META_KEYS[key]) push(el.getAttribute('content'), META_KEYS[key], 'meta');
    });
    doc.querySelectorAll('link[href]').forEach((el) => {
      const rel = (el.getAttribute('rel') || '').toLowerCase();
      if (/\b(icon|apple-touch-icon|mask-icon|image_src)\b/.test(rel)) push(el.getAttribute('href'), 'image', 'icon');
      else if (rel.includes('preload')) {
        const as = (el.getAttribute('as') || '').toLowerCase();
        push(el.getAttribute('href'), { image: 'image', video: 'video', audio: 'audio', font: 'font' }[as] || null, 'preload');
      }
    });

    // CSS url(...) in inline styles and <style> blocks
    doc.querySelectorAll('[style]').forEach((el) => pushCss(el.getAttribute('style'), 'css'));
    doc.querySelectorAll('style').forEach((el) => pushCss(el.textContent, 'css'));

    // Live-page extras: computed backgrounds and everything the browser actually loaded
    if (live) {
      const view = doc.defaultView;
      const els = doc.querySelectorAll('*');
      const cap = Math.min(els.length, 6000);
      for (let i = 0; i < cap; i++) {
        let bg = '';
        try { bg = view.getComputedStyle(els[i]).backgroundImage; } catch (e) {}
        if (bg && bg !== 'none') pushCss(bg, 'css');
      }
      try {
        for (const e of view.performance.getEntriesByType('resource')) {
          const hint = { img: 'image', video: 'video', audio: 'audio' }[e.initiatorType] || null;
          push(e.name, hint, 'network');
        }
      } catch (e) {}
    }

    return Array.from(found.values());
  };

  // Extra page facts used by the security audit.
  window.__assetPageInfo = (doc, base) => {
    const live = !!doc.defaultView;
    let baseHref = base;
    try { const b = doc.querySelector('base[href]'); if (b) baseHref = new URL(b.getAttribute('href'), base).href; } catch (e) {}
    const abs = (raw) => {
      try { const u = new URL(raw, baseHref); u.hash = ''; return /^https?:$/.test(u.protocol) ? u.href : null; } catch (e) { return null; }
    };
    const scripts = [];
    const seen = new Set();
    doc.querySelectorAll('script[src]').forEach((el) => {
      const u = abs(el.getAttribute('src'));
      if (u && !seen.has(u)) { seen.add(u); scripts.push({ url: u, integrity: el.getAttribute('integrity') || '' }); }
    });
    const inline = [];
    doc.querySelectorAll('script:not([src])').forEach((el) => { const t = el.textContent; if (t && t.trim()) inline.push(t.slice(0, 300000)); });
    const forms = [];
    doc.querySelectorAll('form').forEach((f) => forms.push({
      action: abs(f.getAttribute('action') || '') || base,
      method: (f.getAttribute('method') || 'get').toLowerCase(),
      password: !!f.querySelector('input[type=password]'),
    }));
    const links = new Set();
    doc.querySelectorAll('a[href]').forEach((a) => { const u = abs(a.getAttribute('href')); if (u) links.add(u); });
    const comments = [];
    try {
      const w = doc.createTreeWalker(doc, 128);
      let n;
      while ((n = w.nextNode()) && comments.length < 200) comments.push(n.nodeValue.slice(0, 500));
    } catch (e) {}
    const gen = doc.querySelector('meta[name="generator"]');
    const requests = [];
    if (live) {
      try {
        for (const e of doc.defaultView.performance.getEntriesByType('resource')) {
          if (['fetch', 'xmlhttprequest', 'script', 'beacon'].includes(e.initiatorType)) {
            requests.push({ url: e.name, type: e.initiatorType });
            if (e.initiatorType === 'script' && !seen.has(e.name)) { seen.add(e.name); scripts.push({ url: e.name, integrity: '' }); }
          }
        }
      } catch (e) {}
    }
    return { scripts, inline, forms, links: [...links], comments, generator: gen ? gen.getAttribute('content') || '' : '', requests };
  };
})();
