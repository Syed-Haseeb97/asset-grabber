// Looks inside files for things you would not want to ship: GPS in photos, author names in
// PDFs/Office files, macros, scripts hidden in images/SVG, wrong file types, databases, executables.
(() => {
  const dec = new TextDecoder('utf-8', { fatal: false });
  const lat1 = (b) => { let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return s; };
  const at = (b, arr, off = 0) => arr.every((v, i) => b[off + i] === v);

  const SIGS = [
    ['png', [0x89, 0x50, 0x4e, 0x47], 0, ['png']],
    ['jpeg', [0xff, 0xd8, 0xff], 0, ['jpg', 'jpeg', 'jfif']],
    ['gif', [0x47, 0x49, 0x46, 0x38], 0, ['gif']],
    ['pdf', [0x25, 0x50, 0x44, 0x46], 0, ['pdf']],
    ['zip', [0x50, 0x4b, 0x03, 0x04], 0, ['zip', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'epub', 'jar', 'apk']],
    ['gzip', [0x1f, 0x8b], 0, ['gz', 'tgz']],
    ['7z', [0x37, 0x7a, 0xbc, 0xaf], 0, ['7z']],
    ['rar', [0x52, 0x61, 0x72, 0x21], 0, ['rar']],
    ['sqlite', [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66], 0, ['sqlite', 'sqlite3', 'db']],
    ['exe', [0x4d, 0x5a], 0, ['exe', 'dll']],
    ['elf', [0x7f, 0x45, 0x4c, 0x46], 0, []],
    ['ole', [0xd0, 0xcf, 0x11, 0xe0], 0, ['doc', 'xls', 'ppt']],
    ['mp4', [0x66, 0x74, 0x79, 0x70], 4, ['mp4', 'm4v', 'mov', 'm4a', '3gp', 'heic', 'avif']],
    ['ogg', [0x4f, 0x67, 0x67, 0x53], 0, ['ogg', 'oga', 'ogv', 'opus']],
    ['matroska', [0x1a, 0x45, 0xdf, 0xa3], 0, ['webm', 'mkv']],
    ['mp3', [0x49, 0x44, 0x33], 0, ['mp3']],
    ['woff2', [0x77, 0x4f, 0x46, 0x32], 0, ['woff2']],
    ['woff', [0x77, 0x4f, 0x46, 0x46], 0, ['woff']],
  ];
  const BINARY_EXTS = new Set(['jpg', 'jpeg', 'jfif', 'png', 'gif', 'webp', 'pdf', 'zip', 'docx', 'xlsx', 'pptx', 'mp4', 'mp3', 'gz', '7z', 'rar', 'woff', 'woff2']);

  function detectKind(b) {
    for (const [kind, sig, off, exts] of SIGS) if (b.length >= off + sig.length && at(b, sig, off)) return { kind, exts };
    if (b.length >= 12 && at(b, [0x52, 0x49, 0x46, 0x46])) {
      const sub = lat1(b.subarray(8, 12));
      if (sub === 'WEBP') return { kind: 'webp', exts: ['webp'] };
      if (sub === 'WAVE') return { kind: 'wav', exts: ['wav'] };
      if (sub === 'AVI ') return { kind: 'avi', exts: ['avi'] };
    }
    if (b.length > 1 && b[0] === 0xff && (b[1] & 0xe0) === 0xe0) return { kind: 'mp3', exts: ['mp3'] };
    const n = Math.min(b.length, 512);
    if (!n) return { kind: 'empty', exts: [] };
    let printable = 0;
    for (let i = 0; i < n; i++) { const c = b[i]; if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 128) printable++; }
    return { kind: printable / n > 0.97 && !b.subarray(0, n).includes(0) ? 'text' : 'binary', exts: [] };
  }

  /* ---------- EXIF (JPEG) ---------- */
  const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
  function readIfd(dv, off, le) {
    const out = {};
    if (off + 2 > dv.byteLength) return out;
    const n = dv.getUint16(off, le);
    for (let i = 0; i < n; i++) {
      const e = off + 2 + i * 12;
      if (e + 12 > dv.byteLength) break;
      const type = dv.getUint16(e + 2, le), count = dv.getUint32(e + 4, le);
      const size = (TYPE_SIZE[type] || 1) * count;
      out[dv.getUint16(e, le)] = { type, count, off: size <= 4 ? e + 8 : dv.getUint32(e + 8, le) };
    }
    return out;
  }
  const exAscii = (dv, ent) => {
    let s = '';
    for (let i = 0; i < ent.count && ent.off + i < dv.byteLength; i++) { const c = dv.getUint8(ent.off + i); if (!c) break; s += String.fromCharCode(c); }
    return s.trim();
  };
  const exRat = (dv, ent, le) => {
    const r = [];
    for (let i = 0; i < ent.count; i++) {
      if (ent.off + i * 8 + 8 > dv.byteLength) break;
      const a = dv.getUint32(ent.off + i * 8, le), d = dv.getUint32(ent.off + i * 8 + 4, le);
      r.push(d ? a / d : 0);
    }
    return r;
  };

  function parseExif(b) {
    let o = 2;
    while (o + 4 < b.length && b[o] === 0xff) {
      const marker = b[o + 1], len = (b[o + 2] << 8) | b[o + 3];
      if (marker === 0xda) break;
      if (marker === 0xe1 && lat1(b.subarray(o + 4, o + 10)) === 'Exif\0\0') {
        const start = o + 10;
        const dv = new DataView(b.buffer, b.byteOffset + start, Math.max(0, Math.min(len - 8, b.length - start)));
        if (dv.byteLength < 12) return null;
        const le = dv.getUint16(0) === 0x4949;
        const ifd0 = readIfd(dv, dv.getUint32(4, le), le);
        const res = { make: '', model: '', software: '', artist: '', copyright: '', owner: '', serial: '', gps: null };
        if (ifd0[0x010f]) res.make = exAscii(dv, ifd0[0x010f]);
        if (ifd0[0x0110]) res.model = exAscii(dv, ifd0[0x0110]);
        if (ifd0[0x0131]) res.software = exAscii(dv, ifd0[0x0131]);
        if (ifd0[0x013b]) res.artist = exAscii(dv, ifd0[0x013b]);
        if (ifd0[0x8298]) res.copyright = exAscii(dv, ifd0[0x8298]);
        if (ifd0[0x8769]) {
          const ex = readIfd(dv, dv.getUint32(ifd0[0x8769].off, le), le);
          if (ex[0xa430]) res.owner = exAscii(dv, ex[0xa430]);
          if (ex[0xa431]) res.serial = exAscii(dv, ex[0xa431]);
        }
        if (ifd0[0x8825]) {
          const g = readIfd(dv, dv.getUint32(ifd0[0x8825].off, le), le);
          if (g[2] && g[4]) {
            const la = exRat(dv, g[2], le), lo = exRat(dv, g[4], le);
            if (la.length === 3 && lo.length === 3) {
              let lat = la[0] + la[1] / 60 + la[2] / 3600, lon = lo[0] + lo[1] / 60 + lo[2] / 3600;
              if (g[1] && exAscii(dv, g[1]) === 'S') lat = -lat;
              if (g[3] && exAscii(dv, g[3]) === 'W') lon = -lon;
              res.gps = { lat, lon };
            }
          }
        }
        return res;
      }
      o += 2 + len;
    }
    return null;
  }

  /* ---------- ZIP / Office ---------- */
  function readZipEntries(b) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    let e = b.length - 22;
    while (e >= 0 && dv.getUint32(e, true) !== 0x06054b50) e--;
    if (e < 0) return null;
    const count = dv.getUint16(e + 10, true);
    let off = dv.getUint32(e + 16, true);
    const entries = [];
    for (let i = 0; i < count && off + 46 <= b.length; i++) {
      if (dv.getUint32(off, true) !== 0x02014b50) break;
      const nlen = dv.getUint16(off + 28, true), elen = dv.getUint16(off + 30, true), clen = dv.getUint16(off + 32, true);
      entries.push({
        name: dec.decode(b.subarray(off + 46, off + 46 + nlen)),
        method: dv.getUint16(off + 10, true), csize: dv.getUint32(off + 20, true),
        usize: dv.getUint32(off + 24, true), lho: dv.getUint32(off + 42, true),
      });
      off += 46 + nlen + elen + clen;
    }
    return entries;
  }
  async function readEntry(b, ent, cap = 2000000) {
    if (ent.usize > cap) return null;
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const start = ent.lho + 30 + dv.getUint16(ent.lho + 26, true) + dv.getUint16(ent.lho + 28, true);
    const data = b.subarray(start, start + ent.csize);
    if (ent.method === 0) return data;
    if (ent.method !== 8) return null;
    const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
  const xmlTag = (xml, tag) => { const m = new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`).exec(xml); return m ? m[1].trim() : ''; };

  /* ---------- PDF ---------- */
  function pdfString(s) {
    return s.replace(/\\([nrtbf()\\])/g, (_, c) => ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' }[c] || c)).replace(/\\(\d{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8))).trim();
  }
  function pdfMeta(text) {
    const out = {};
    for (const key of ['Author', 'Creator', 'Producer', 'Title', 'Subject']) {
      let m = new RegExp(`/${key}\\s*\\(((?:\\\\.|[^\\\\)])*)\\)`).exec(text);
      if (m) { out[key] = pdfString(m[1]); continue; }
      m = new RegExp(`/${key}\\s*<([0-9A-Fa-f\\s]+)>`).exec(text);
      if (m) {
        const hex = m[1].replace(/\s+/g, '');
        let s = '';
        for (let i = 0; i + 3 < hex.length; i += 4) s += String.fromCharCode(parseInt(hex.slice(i, i + 4), 16));
        out[key] = s.replace(/^\ufeff/, '').trim();
      }
    }
    return out;
  }

  /* ---------- main ---------- */
  async function analyze({ url, ext, mime, bytes, tail }) {
    const out = [];
    const add = (sev, title, evidence, fix) => out.push({ sev, title, url, evidence, fix, cat: 'File contents' });
    ext = (ext || '').toLowerCase();
    const k = detectKind(bytes);
    const head = dec.decode(bytes.subarray(0, 300));

    if (k.kind === 'exe' || k.kind === 'elf') add('high', 'Executable binary is publicly downloadable', `${k.kind.toUpperCase()} signature`, 'Remove it from the public folder or serve it only to authenticated users.');
    if (k.kind === 'sqlite') add('critical', 'SQLite database is publicly downloadable', 'SQLite file header found', 'Keep databases outside the web root and never ship them in the build output.');

    const claimedBinary = BINARY_EXTS.has(ext);
    if (claimedBinary && k.kind !== 'binary' && k.kind !== 'empty') {
      if (k.kind === 'text') {
        const script = /^\s*(<!doctype html|<html|<\?php|<script|#!)/i.test(head);
        add(script ? 'high' : 'medium', script ? `Script or HTML is served as .${ext}` : `File named .${ext} is plain text`, head.replace(/\s+/g, ' ').slice(0, 80), script ? 'Reject uploads whose content does not match the extension, and serve user files from a separate domain with a safe Content-Type.' : 'Check why a text file carries a binary extension (often an error page saved by mistake).');
      } else if (!k.exts.includes(ext)) {
        add('medium', `Content does not match the .${ext} extension`, `Looks like ${k.kind}`, 'Validate file signatures on upload and serve with the correct Content-Type plus X-Content-Type-Options: nosniff.');
      }
    }

    if (ext === 'svg' || /svg/i.test(mime || '')) {
      const t = dec.decode(bytes);
      const m = /<script[\s>]|\son[a-z]+\s*=|javascript:|<foreignObject/i.exec(t);
      if (m) add('medium', 'SVG contains active content', `matched: ${m[0].trim()}`, 'Sanitize SVGs (strip scripts and event handlers), or serve them as downloads / from a cookieless domain.');
    }

    if (k.kind === 'jpeg') {
      let ex = null;
      try { ex = parseExif(bytes); } catch (e) {}
      if (ex && ex.gps) add('high', 'Photo embeds GPS location', `lat ${ex.gps.lat.toFixed(3)}, lon ${ex.gps.lon.toFixed(3)}`, 'Strip metadata before publishing (exiftool -all= file.jpg, or re-encode the image in your build step).');
      if (ex) {
        const bits = [['camera', [ex.make, ex.model].filter(Boolean).join(' ')], ['software', ex.software], ['artist', ex.artist], ['owner', ex.owner], ['serial', ex.serial ? 'present' : '']].filter(([, v]) => v);
        if (bits.length) add(ex.artist || ex.owner || ex.serial ? 'medium' : 'low', 'Photo metadata reveals device or author details', bits.map(([a, v]) => `${a}: ${v}`).join('; '), 'Strip EXIF metadata before publishing.');
      }
    }

    if (k.kind === 'pdf') {
      const text = lat1(bytes) + '\n' + (tail ? lat1(tail) : '');
      const m = pdfMeta(text);
      const keys = Object.keys(m).filter((x) => m[x]);
      const people = ['Author', 'Creator', 'Producer'].filter((x) => m[x]);
      if (people.length) {
        const pathy = Object.values(m).some((v) => /[A-Za-z]:\\|\/Users\/|\/home\//.test(v));
        add(pathy ? 'medium' : 'low', 'PDF metadata reveals author or tooling', keys.map((x) => `${x}: ${m[x].slice(0, 60)}`).join('; '), 'Clear document properties before publishing (Export with "remove metadata", or exiftool -all= file.pdf).');
      }
      if (/\/Launch\b/.test(text)) add('high', 'PDF contains a Launch action', '/Launch', 'Do not publish PDFs that can start programs.');
      else if (/\/(JavaScript|JS)\b/.test(text)) add('medium', 'PDF contains embedded JavaScript', '/JavaScript', 'Remove scripts from PDFs you publish.');
    }

    if (k.kind === 'zip' && ['docx', 'xlsx', 'pptx'].includes(ext)) {
      let entries = null;
      try { entries = readZipEntries(bytes); } catch (e) {}
      if (entries) {
        const names = entries.map((e) => e.name);
        const get = async (n) => { const ent = entries.find((e) => e.name === n); if (!ent) return ''; try { const d = await readEntry(bytes, ent); return d ? dec.decode(d) : ''; } catch (e) { return ''; } };
        if (names.some((n) => /vbaProject\.bin$/i.test(n))) add('high', 'Office file contains macros', 'vbaProject.bin', 'Publish macro-free files (.docx/.xlsx), or export to PDF instead.');
        if (names.some((n) => /(^|\/)comments[^/]*\.xml$/i.test(n))) add('medium', 'Office file contains comments', 'comments part present', 'Delete comments before publishing (Inspect Document in Office).');
        if (names.some((n) => /externalLinks\//i.test(n))) add('low', 'Office file links to other files', 'externalLinks present', 'Break links and remove references to internal paths.');
        const core = await get('docProps/core.xml'), app = await get('docProps/app.xml');
        const meta = [['creator', xmlTag(core, 'dc:creator')], ['last modified by', xmlTag(core, 'cp:lastModifiedBy')], ['company', xmlTag(app, 'Company')], ['manager', xmlTag(app, 'Manager')]].filter(([, v]) => v);
        if (meta.length) add('low', 'Office metadata reveals people or company', meta.map(([a, v]) => `${a}: ${v}`).join('; '), 'Remove personal information (File > Info > Inspect Document) before publishing.');
        if (ext === 'docx') {
          const doc = await get('word/document.xml');
          if (/<w:(ins|del)\s/.test(doc)) add('medium', 'Document has tracked changes', 'w:ins / w:del found', 'Accept or reject all changes so earlier text is not recoverable.');
        }
      }
    }
    return out;
  }

  globalThis.AGInspect = { analyze, parseExif, readZipEntries, readEntry, detectKind, pdfMeta };
})();
