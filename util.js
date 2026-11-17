// Shared helpers: resilient fetch (timeout, retry, cancel), partial body reads, bounded concurrency.
(() => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const combine = (signal, ms) => {
    const t = AbortSignal.timeout(ms);
    return signal && AbortSignal.any ? AbortSignal.any([signal, t]) : signal || t;
  };

  async function xfetch(url, o = {}) {
    const { retries = 1, timeout = 15000, signal, ...init } = o;
    init.credentials = init.credentials || 'omit';
    for (let a = 0; ; a++) {
      try {
        const res = await fetch(url, { ...init, signal: combine(signal, timeout) });
        if ((res.status === 429 || res.status === 503) && a < retries) { await sleep(800 * (a + 1)); continue; }
        return res;
      } catch (e) {
        if ((signal && signal.aborted) || a >= retries) throw e;
        await sleep(400 * (a + 1));
      }
    }
  }

  // Read at most `max` bytes of a response body, then cancel the rest of the download.
  async function readBytes(res, max) {
    if (!res.body) return new Uint8Array(0);
    const reader = res.body.getReader();
    const chunks = [];
    let got = 0;
    while (got < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      got += value.length;
    }
    reader.cancel().catch(() => {});
    const out = new Uint8Array(Math.min(got, max));
    let p = 0;
    for (const c of chunks) {
      const take = Math.min(c.length, out.length - p);
      out.set(c.subarray(0, take), p);
      p += take;
      if (p >= out.length) break;
    }
    return out;
  }

  async function pool(items, limit, fn, signal) {
    let i = 0;
    const worker = async () => {
      while (i < items.length && !(signal && signal.aborted)) {
        const k = i++;
        try { await fn(items[k], k); } catch (e) { if (signal && signal.aborted) return; }
      }
    };
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  }

  globalThis.AGUtil = { sleep, xfetch, readBytes, pool };
})();
