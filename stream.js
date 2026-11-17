// Saves ordinary (unencrypted, non-live) HLS streams as one file by joining the segments.
// Encrypted/DRM streams and live streams are refused with a clear message.
(() => {
  const { xfetch, pool } = AGUtil;
  const attrs = (s) => {
    const o = {};
    s.replace(/([A-Z0-9-]+)=("([^"]*)"|[^,]*)/g, (_, k, v, q) => { o[k] = q !== undefined ? q : v; return ''; });
    return o;
  };

  async function download(url, { signal, onProgress = () => {}, depth = 0 } = {}) {
    if (!/\.m3u8(\?|$)/i.test(url) && depth === 0) throw new Error('Only HLS (.m3u8) streams can be saved. DASH (.mpd) streams are not supported.');
    const r = await xfetch(url, { signal, timeout: 20000 });
    if (!r.ok) throw new Error(`Playlist request failed (HTTP ${r.status}).`);
    const text = await r.text();
    const base = r.url || url;
    if (!/^#EXTM3U/.test(text.trim())) throw new Error('That is not an HLS playlist.');
    const lines = text.split(/\r?\n/).map((l) => l.trim());

    if (lines.some((l) => l.startsWith('#EXT-X-STREAM-INF:'))) {
      if (depth > 2) throw new Error('Playlist nesting is too deep.');
      let best = null;
      lines.forEach((l, i) => {
        if (!l.startsWith('#EXT-X-STREAM-INF:')) return;
        const u = lines.slice(i + 1).find((x) => x && !x.startsWith('#'));
        const bw = +attrs(l.slice(18)).BANDWIDTH || 0;
        if (u && (!best || bw > best.bw)) best = { bw, url: new URL(u, base).href };
      });
      if (!best) throw new Error('No playable quality found in the playlist.');
      return download(best.url, { signal, onProgress, depth: depth + 1 });
    }

    for (const l of lines) {
      if (!l.startsWith('#EXT-X-KEY:')) continue;
      const m = attrs(l.slice(11)).METHOD;
      if (m && m !== 'NONE') throw new Error('This stream is encrypted, so it cannot be saved here.');
    }
    if (!lines.includes('#EXT-X-ENDLIST')) throw new Error('This is a live stream (no end marker), so there is no complete file to save.');

    let init = null;
    const segs = [];
    for (const l of lines) {
      if (l.startsWith('#EXT-X-MAP:')) { const a = attrs(l.slice(11)); if (a.URI) init = new URL(a.URI, base).href; }
      else if (l && !l.startsWith('#')) segs.push(new URL(l, base).href);
    }
    if (!segs.length) throw new Error('The playlist has no segments.');
    const list = init ? [init, ...segs] : segs;
    const parts = new Array(list.length);
    let done = 0, firstErr = '';
    await pool(list, 6, async (u, i) => {
      try {
        const s = await xfetch(u, { signal, timeout: 60000, retries: 2 });
        if (!s.ok) throw new Error(`Segment ${i + 1} failed (HTTP ${s.status})`);
        parts[i] = await s.arrayBuffer();
      } catch (e) { if (!firstErr) firstErr = e.message || String(e); throw e; }
      onProgress(++done, list.length);
    }, signal);
    if (signal && signal.aborted) throw new DOMException('Cancelled', 'AbortError');
    if (parts.some((p) => !p)) throw new Error(firstErr || 'Some segments could not be downloaded.');
    return { blob: new Blob(parts, { type: init ? 'video/mp4' : 'video/mp2t' }), ext: init ? 'mp4' : 'ts', segments: list.length };
  }

  globalThis.AGStream = { download };
})();
