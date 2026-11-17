// Pre-deploy security audit. Read-only: every request is a GET/HEAD, nothing is written anywhere.
(() => {
  const { xfetch, readBytes, pool } = AGUtil;
  const dec = new TextDecoder('utf-8', { fatal: false });
  const SEV = ['critical', 'high', 'medium', 'low', 'info'];
  const redact = (s) => (s.length <= 10 ? '••••' : `${s.slice(0, 4)}…${s.slice(-3)} (${s.length} chars)`);
  const extOf = (u) => { try { const m = /\.([a-z0-9]{2,6})$/i.exec(new URL(u).pathname); return m ? m[1].toLowerCase() : ''; } catch (e) { return ''; } };
  const isLocal = (h) => /^(localhost|127\.|\[::1\]|0\.0\.0\.0)/.test(h) || /\.local$/.test(h);

  /* ---------- secret patterns ---------- */
  const ROTATE = 'Remove it from client-side code, rotate the key now, and call the service from a server or edge function.';
  const SECRETS = [
    ['AWS access key ID', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 'high', ROTATE],
    ['Google API key', /\bAIza[0-9A-Za-z_\-]{35}\b/g, 'low', 'Often public by design (Maps, Firebase). Make sure it is restricted by HTTP referrer and API in Google Cloud Console.'],
    ['Stripe live secret key', /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g, 'critical', ROTATE],
    ['Stripe test secret key', /\bsk_test_[0-9a-zA-Z]{20,}\b/g, 'medium', ROTATE],
    ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, 'critical', ROTATE],
    ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g, 'critical', ROTATE],
    ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, 'high', ROTATE],
    ['Slack webhook URL', /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g, 'high', ROTATE],
    ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, 'critical', ROTATE],
    ['OpenAI API key', /\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b/g, 'critical', ROTATE],
    ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_\-]{30,}\b/g, 'critical', ROTATE],
    ['SendGrid API key', /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/g, 'high', ROTATE],
    ['Mailgun key', /\bkey-[0-9a-zA-Z]{32}\b/g, 'high', ROTATE],
    ['Database connection string with password', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@\/'"`]+:[^\s@\/'"`]+@[^\s'"`]+/g, 'critical', ROTATE],
    ['Hard-coded credential', /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["'][^"'\s]{8,}["']/gi, 'medium', 'Review this match. If it is a real secret, move it to server-side configuration and rotate it.'],
  ];
  const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
  const decodeJwt = (t) => {
    try {
      const p = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(atob(p + '='.repeat((4 - (p.length % 4)) % 4)));
    } catch (e) { return null; }
  };
  const FIREBASE = [/https:\/\/[a-z0-9-]+\.firebaseio\.com/g, /https:\/\/[a-z0-9-]+-default-rtdb\.[a-z0-9-]+\.firebasedatabase\.app/g];
  const SUPABASE = /https:\/\/([a-z0-9]{15,25})\.supabase\.co/g;
  const BUCKETS = [
    [/https?:\/\/([a-z0-9.\-]{3,63})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/g, (m) => `https://${m[1]}.s3.amazonaws.com/`, 'Amazon S3'],
    [/https?:\/\/s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9.\-]{3,63})/g, (m) => `https://s3.amazonaws.com/${m[1]}/`, 'Amazon S3'],
    [/https?:\/\/storage\.googleapis\.com\/([a-z0-9._\-]{3,63})/g, (m) => `https://storage.googleapis.com/${m[1]}`, 'Google Cloud Storage'],
    [/https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9\-]{3,63})/g, (m) => `https://${m[1]}.blob.core.windows.net/${m[2]}?restype=container&comp=list`, 'Azure Blob Storage'],
  ];
  const ENDPOINT = /["'`](\/(?:api|rest|graphql|trpc|v[0-9]+|_next\/data)(?:\/[A-Za-z0-9_\-.~%]+)*)\/?["'`]/g;

  function scanText(ctx, text, where, isJs) {
    if (!text) return;
    for (const [name, re, sev, fix] of SECRETS) {
      re.lastIndex = 0;
      let m, n = 0;
      while ((m = re.exec(text)) && n < 3) {
        n++;
        ctx.add({ sev, title: `${name} found in client-side code`, url: where, evidence: redact(m[0]), secret: m[0], fix, cat: 'Secrets' });
      }
    }
    JWT.lastIndex = 0;
    let m, n = 0;
    while ((m = JWT.exec(text)) && n < 6) {
      n++;
      const p = decodeJwt(m[0]);
      if (!p) continue;
      if (p.role === 'service_role') ctx.add({ sev: 'critical', title: 'Supabase service_role key found in client-side code', url: where, evidence: redact(m[0]), secret: m[0], fix: 'This key bypasses Row Level Security. Rotate it immediately and keep it server-side only.', cat: 'Secrets' });
      else if (p.role === 'anon') { ctx.found.anon.set(m[0], p.ref || ''); ctx.add({ sev: 'info', title: 'Supabase anon key present (public by design)', url: where, evidence: redact(m[0]), secret: m[0], fix: 'Safe only if Row Level Security is enabled on every table. The Cloud checks below test that.', cat: 'Secrets' }); }
      else ctx.add({ sev: 'low', title: 'JWT embedded in client-side code', url: where, evidence: `${redact(m[0])}; claims: ${Object.keys(p).slice(0, 8).join(', ')}`, secret: m[0], fix: 'If this is a user or service token, remove it and rotate it.', cat: 'Secrets' });
    }
    for (const re of FIREBASE) { re.lastIndex = 0; while ((m = re.exec(text))) ctx.found.firebase.add(m[0]); }
    SUPABASE.lastIndex = 0;
    while ((m = SUPABASE.exec(text))) ctx.found.supabase.add(m[0]);
    for (const [re, mk, label] of BUCKETS) { re.lastIndex = 0; while ((m = re.exec(text))) ctx.found.buckets.set(mk(m), label); }
    if (isJs) {
      ENDPOINT.lastIndex = 0;
      while ((m = ENDPOINT.exec(text)) && ctx.found.endpoints.size < 80) {
        if (!/[{}$]/.test(m[1])) ctx.found.endpoints.add(ctx.origin + m[1]);
      }
    }
  }

  /* ---------- exposed paths ---------- */
  const FIX_DOT = 'Do not deploy this file. Deploy only the build output folder, and block dotfiles and VCS folders at the web server.';
  const isText = (t) => !/^\s*<(!doctype|html)/i.test(t);
  const jsonOk = (t) => { try { JSON.parse(t); return true; } catch (e) { return false; } };
  const jsonHas = (t, keys) => { try { const j = JSON.parse(t); return keys.some((k) => k in j); } catch (e) { return false; } };
  const envEv = (t) => { const n = t.match(/^[A-Za-z_][A-Za-z0-9_]*(?=\s*=)/gm) || []; return `${n.length} variables, e.g. ${n.slice(0, 6).join(', ')} (values not shown)`; };
  const P = (p, sev, title, v, fix = FIX_DOT, extra = {}) => ({ p, sev, title, v, fix, ...extra });
  const PRIV = 'Keep this out of the public folder; ship only the compiled output.';
  const backupMagic = (t, b) => (b[0] === 0x50 && b[1] === 0x4b) || (b[0] === 0x1f && b[1] === 0x8b) || (b[0] === 0x37 && b[1] === 0x7a) || /^SQLite format 3/.test(t) || /(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)/i.test(t);

  const PATHS = [
    ...['/.env', '/.env.local', '/.env.production', '/.env.development', '/.env.staging', '/.env.backup'].map((p) => P(p, 'critical', 'Environment file is publicly readable', (t) => isText(t) && /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(t), FIX_DOT, { ev: envEv })),
    P('/.env.example', 'low', '.env.example is public', (t) => isText(t) && /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(t), 'Harmless if it holds no real values, but it reveals variable names.', { ev: envEv }),
    P('/.git/HEAD', 'critical', 'Git repository is exposed (source code can be downloaded)', (t) => /^ref:\s*refs\//.test(t) || /^[0-9a-f]{40}\s*$/m.test(t)),
    P('/.git/config', 'critical', 'Git config is exposed', (t) => /\[core\]/.test(t)),
    P('/.git/index', 'critical', 'Git index is exposed', (t) => t.startsWith('DIRC')),
    P('/.svn/entries', 'high', 'SVN metadata is exposed', (t) => isText(t) && t.trim().length > 0),
    P('/.hg/requires', 'high', 'Mercurial metadata is exposed', (t) => /revlogv1|fncache|store/.test(t)),
    P('/.DS_Store', 'medium', 'macOS .DS_Store is public (reveals file names)', (t, b) => b.length > 8 && b[4] === 0x42 && b[5] === 0x75 && b[6] === 0x64 && b[7] === 0x31),
    P('/.htaccess', 'medium', '.htaccess is publicly readable', (t) => /(RewriteEngine|AuthType|Require |Options |<IfModule|Header )/i.test(t)),
    P('/.htpasswd', 'critical', 'Password file (.htpasswd) is exposed', (t) => /^[^:\s]+:(\$|\{SHA\}|[A-Za-z0-9./]{13})/m.test(t)),
    P('/.npmrc', 'high', '.npmrc is exposed (may hold registry tokens)', (t) => /(_authToken|_auth=|registry=)/.test(t)),
    P('/.aws/credentials', 'critical', 'AWS credentials file is exposed', (t) => /aws_access_key_id/i.test(t)),
    P('/.ssh/id_rsa', 'critical', 'SSH private key is exposed', (t) => /BEGIN [A-Z ]*PRIVATE KEY/.test(t)),
    P('/id_rsa', 'critical', 'SSH private key is exposed', (t) => /BEGIN [A-Z ]*PRIVATE KEY/.test(t)),
    P('/.vscode/settings.json', 'low', 'Editor settings are public', jsonOk, PRIV),
    P('/.idea/workspace.xml', 'low', 'IDE workspace file is public', (t) => /<project/.test(t), PRIV),
    P('/package.json', 'low', 'package.json is public (reveals dependencies and versions)', (t) => jsonHas(t, ['name', 'dependencies', 'scripts']), PRIV),
    P('/package-lock.json', 'low', 'package-lock.json is public', jsonOk, PRIV),
    P('/yarn.lock', 'low', 'yarn.lock is public', (t) => /yarn lockfile|resolved "/.test(t), PRIV),
    P('/pnpm-lock.yaml', 'low', 'pnpm-lock.yaml is public', (t) => /lockfileVersion/.test(t), PRIV),
    P('/composer.json', 'low', 'composer.json is public', (t) => jsonHas(t, ['require', 'name']), PRIV),
    P('/composer.lock', 'low', 'composer.lock is public', jsonOk, PRIV),
    P('/docker-compose.yml', 'medium', 'docker-compose file is public', (t) => /^\s*(services|version):/m.test(t), PRIV),
    P('/docker-compose.yaml', 'medium', 'docker-compose file is public', (t) => /^\s*(services|version):/m.test(t), PRIV),
    P('/Dockerfile', 'low', 'Dockerfile is public', (t) => /^\s*FROM\s/m.test(t), PRIV),
    ...['/config.json', '/config.js', '/settings.json', '/appsettings.json', '/appsettings.Development.json', '/application.properties', '/application.yml', '/config.yml', '/config.yaml', '/secrets.json', '/credentials.json'].map((p) => P(p, 'medium', 'Configuration file is publicly readable', (t) => isText(t) && t.trim().length > 2 && (jsonOk(t) || /[=:]/.test(t)), 'Keep configuration and secrets out of the public folder. Public runtime config must never hold secrets.')),
    P('/serviceAccountKey.json', 'critical', 'Service-account key is exposed', (t) => /"private_key"/.test(t)),
    P('/firebase-adminsdk.json', 'critical', 'Firebase admin key is exposed', (t) => /"private_key"/.test(t)),
    P('/firebase.json', 'low', 'firebase.json is public', jsonOk, PRIV),
    P('/.firebaserc', 'low', '.firebaserc is public', jsonOk, PRIV),
    P('/vercel.json', 'low', 'vercel.json is public', jsonOk, PRIV),
    P('/netlify.toml', 'low', 'netlify.toml is public', (t) => /\[build\]|\[\[/.test(t), PRIV),
    P('/supabase/config.toml', 'low', 'Supabase config.toml is public', (t) => /project_id|\[api\]/.test(t), PRIV),
    P('/prisma/schema.prisma', 'medium', 'Prisma schema is public (reveals your data model)', (t) => /datasource|generator/.test(t), PRIV),
    ...['/backup.zip', '/backup.tar.gz', '/backup.tgz', '/backup.sql', '/backup.sql.gz', '/dump.sql', '/database.sql', '/db.sql', '/db.sqlite', '/database.sqlite', '/data.db', '/site.zip', '/www.zip', '/public.zip', '/src.zip', '/source.zip', '/project.zip', '/archive.zip', '/web.zip'].map((p) => P(p, 'high', 'Backup or database dump is publicly downloadable', backupMagic, 'Delete it from the server. Keep backups in private storage.')),
    ...['/wp-config.php.bak', '/wp-config.php~', '/wp-config.old', '/config.php.bak', '/config.php~'].map((p) => P(p, 'critical', 'Backup of a config file is readable', (t) => /DB_PASSWORD|DB_NAME|password/i.test(t), 'Delete backup copies from the web root.')),
    P('/phpinfo.php', 'high', 'phpinfo() page is exposed', (t) => /phpinfo\(\)|PHP Version/.test(t), 'Remove debug pages before deploying.', { html: true }),
    P('/server-status', 'medium', 'Apache server-status is exposed', (t) => /Apache Server Status|Server Version/.test(t), 'Restrict it to localhost.', { html: true }),
    ...['/swagger.json', '/openapi.json', '/api-docs', '/v2/api-docs', '/swagger/v1/swagger.json'].map((p) => P(p, 'low', 'API schema is public', (t) => /"(swagger|openapi)"/.test(t), 'Make sure the API spec is meant to be public.')),
    P('/swagger-ui/', 'low', 'Swagger UI is public', (t) => /swagger-ui/i.test(t), 'Protect API docs for internal APIs.', { html: true }),
    ...['/graphql', '/api/graphql'].map((p) => P(`${p}?query=%7B__schema%7Btypes%7Bname%7D%7D%7D`, 'medium', 'GraphQL introspection is enabled', (t) => /__schema|"types"/.test(t), 'Disable introspection in production, or require authentication.')),
    ...['/error_log', '/error.log', '/debug.log', '/npm-debug.log', '/access.log', '/logs/error.log', '/log/error.log', '/storage/logs/laravel.log', '/app.log', '/server.log'].map((p) => P(p, 'medium', 'Log file is publicly readable', (t) => isText(t) && t.trim().length > 20 && /(error|warn|exception|GET |POST |\d{4}-\d{2}-\d{2})/i.test(t), 'Write logs outside the web root.')),
    P('/@vite/client', 'medium', 'Vite dev server is reachable (not a production build)', (t) => /vite/i.test(t) && /import\.meta\.hot|HMR/.test(t), 'Deploy the built output (vite build), not the dev server.'),
    P('/_next/static/development/_devPagesManifest.json', 'medium', 'Next.js development build is deployed', jsonOk, 'Run next build and deploy that.'),
    P('/.gitignore', 'info', '.gitignore is public', (t) => isText(t) && t.trim().length > 0, PRIV),
    P('/README.md', 'info', 'README.md is public', (t) => isText(t) && t.trim().length > 0, PRIV),
    P('/CHANGELOG.md', 'info', 'CHANGELOG.md is public', (t) => isText(t) && t.trim().length > 0, PRIV),
  ];

  const LISTING = /<title>\s*Index of\s*\/|<h1>\s*Index of\s*\/|Directory listing for\s*\/|<title>\s*Directory Listing|listing directory \/|\[To Parent Directory\]|<pre><a href="\.\.\/">|Parent Directory<\/a>/i;

  async function getBaseline(ctx) {
    if (ctx.baseline) return ctx.baseline;
    ctx.baseline = { status: 0, text: '' };
    try {
      const r = await xfetch(ctx.origin + '/__ag_' + Math.random().toString(36).slice(2, 10) + '.txt', { signal: ctx.signal, retries: 0, timeout: 8000 });
      ctx.baseline = { status: r.status, text: dec.decode(await readBytes(r, 2048)).slice(0, 200) };
    } catch (e) {}
    return ctx.baseline;
  }

  async function ensureHtml(ctx) {
    if (ctx.html || ctx.htmlTried) return;
    ctx.htmlTried = true;
    try {
      const r = await xfetch(ctx.pageUrl, { credentials: ctx.credentials, signal: ctx.signal });
      ctx.mainRes = r;
      ctx.html = dec.decode(await readBytes(r, 1500000));
    } catch (e) {}
  }

  /* ---------- checks ---------- */
  async function checkHeaders(ctx) {
    await ensureHtml(ctx);
    const r = ctx.mainRes;
    if (!r) throw new Error('could not load the page to read its headers');
    const h = r.headers;
    ctx.inv.status = r.status;
    ctx.inv.headers = Object.fromEntries(h.entries());
    const u = new URL(r.url || ctx.pageUrl);
    const https = u.protocol === 'https:';
    const add = (sev, title, evidence, fix) => ctx.add({ sev, title, url: ctx.pageUrl, evidence, fix, cat: 'Headers' });

    if (!https && !isLocal(u.hostname)) add('medium', 'Page is served over HTTP', u.protocol, 'Serve everything over HTTPS and redirect HTTP to HTTPS.');
    const csp = h.get('content-security-policy');
    if (!csp) add('medium', 'No Content-Security-Policy header', 'header missing', "Add a CSP that limits where scripts, frames and connections may come from, e.g. default-src 'self'.");
    else {
      const d = {};
      csp.split(';').forEach((x) => { const [n, ...v] = x.trim().split(/\s+/); if (n) d[n.toLowerCase()] = v; });
      const sc = d['script-src'] || d['default-src'] || [];
      if (sc.includes("'unsafe-inline'") && !sc.some((x) => /^'(nonce|sha)/.test(x))) add('medium', 'CSP allows inline scripts', "script-src has 'unsafe-inline'", 'Use nonces or hashes instead of unsafe-inline.');
      if (sc.includes("'unsafe-eval'")) add('low', 'CSP allows eval()', "script-src has 'unsafe-eval'", "Remove 'unsafe-eval' if your bundle allows it.");
      if (sc.includes('*') || sc.includes('data:') || sc.includes('http:')) add('medium', 'CSP script-src is too broad', sc.join(' '), 'List only the exact script origins you use.');
      if (!d['object-src'] && !d['default-src']) add('low', 'CSP does not restrict object-src', 'object-src missing', "Add object-src 'none'.");
    }
    if (!h.get('x-frame-options') && !(csp && /frame-ancestors/i.test(csp))) add('medium', 'Page can be framed by other sites (clickjacking)', 'no X-Frame-Options or frame-ancestors', "Send X-Frame-Options: DENY or CSP frame-ancestors 'self'.");
    if ((h.get('x-content-type-options') || '').toLowerCase() !== 'nosniff') add('low', 'X-Content-Type-Options: nosniff is missing', h.get('x-content-type-options') || 'header missing', 'Send X-Content-Type-Options: nosniff so uploaded files are not sniffed into scripts.');
    const hsts = h.get('strict-transport-security');
    if (https && !hsts) add('low', 'No HSTS header', 'header missing', 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains.');
    else if (hsts) { const m = /max-age=(\d+)/i.exec(hsts); if (m && +m[1] < 15552000) add('low', 'HSTS max-age is short', hsts, 'Use at least 6 months (15552000), ideally 1 year.'); }
    if (!h.get('referrer-policy')) add('low', 'No Referrer-Policy header', 'header missing', 'Send Referrer-Policy: strict-origin-when-cross-origin.');
    if (!h.get('permissions-policy')) add('info', 'No Permissions-Policy header', 'header missing', 'Disable browser features you do not use (camera, microphone, geolocation).');
    for (const name of ['server', 'x-powered-by', 'x-aspnet-version']) {
      const v = h.get(name);
      if (v && /\d+\.\d+/.test(v)) add('low', 'Software version is disclosed', `${name}: ${v}`, 'Hide version banners so attackers cannot match known vulnerabilities.');
    }
    const acao = h.get('access-control-allow-origin');
    if (acao === '*' && (h.get('access-control-allow-credentials') || '').toLowerCase() === 'true') add('high', 'CORS allows any origin with credentials', 'ACAO * + ACAC true', 'Never combine a wildcard with credentials. Allow specific origins only.');
    else if (acao === '*') add('info', 'CORS allows any origin', 'Access-Control-Allow-Origin: *', 'Fine for public content. Do not use it on authenticated APIs.');
  }

  async function checkCookies(ctx) {
    if (typeof chrome === 'undefined' || !chrome.cookies) return;
    const cookies = await chrome.cookies.getAll({ url: ctx.pageUrl });
    const https = ctx.pageUrl.startsWith('https:');
    ctx.inv.cookies = cookies.map((c) => ({ name: c.name, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, session: !c.expirationDate }));
    for (const c of cookies) {
      const sensitive = /sess|token|auth|jwt|sid|login/i.test(c.name);
      const add = (sev, title, fix) => ctx.add({ sev, title, url: ctx.pageUrl, evidence: `cookie "${c.name}" (value not read)`, fix, cat: 'Cookies' });
      if (https && !c.secure) add(sensitive ? 'medium' : 'low', 'Cookie is missing the Secure flag', 'Set the Secure attribute so it is never sent over HTTP.');
      if (sensitive && !c.httpOnly) add('medium', 'Session-like cookie is readable by JavaScript', 'Set HttpOnly so an XSS bug cannot steal it.');
      if (sensitive && (c.sameSite === 'no_restriction' || c.sameSite === 'unspecified')) add('low', 'Session-like cookie has no SameSite restriction', 'Set SameSite=Lax or Strict.');
    }
  }

  async function checkPageContent(ctx) {
    await ensureHtml(ctx);
    const https = ctx.pageUrl.startsWith('https:');
    const info = ctx.info;
    ctx.inv.forms = info.forms;
    ctx.inv.generator = info.generator;
    ctx.inv.inlineScripts = info.inline.length;
    const add = (sev, title, evidence, fix, url = ctx.pageUrl) => ctx.add({ sev, title, url, evidence, fix, cat: 'Page content' });
    if (https) {
      const mixedScripts = info.scripts.filter((s) => s.url.startsWith('http:'));
      if (mixedScripts.length) add('high', 'HTTPS page loads scripts over HTTP', mixedScripts.slice(0, 5).map((s) => s.url).join(', '), 'Load every script over HTTPS.');
      const mixed = ctx.items.filter((i) => i.url.startsWith('http:'));
      if (mixed.length) add('medium', 'HTTPS page loads files over HTTP (mixed content)', `${mixed.length} file(s), e.g. ${mixed.slice(0, 3).map((i) => i.url).join(', ')}`, 'Switch all file URLs to HTTPS.');
    }
    const host = new URL(ctx.pageUrl).host;
    const noSri = info.scripts.filter((s) => { try { return new URL(s.url).host !== host && !s.integrity; } catch (e) { return false; } });
    if (noSri.length) add('low', 'Third-party scripts load without Subresource Integrity', noSri.slice(0, 6).map((s) => new URL(s.url).host + new URL(s.url).pathname.slice(0, 30)).join(', '), 'Add integrity="sha384-…" crossorigin="anonymous" to third-party script tags, or self-host them.');
    for (const f of info.forms) {
      if (f.password && f.action.startsWith('http:') && !isLocal(new URL(f.action).hostname)) add('high', 'Password form submits over HTTP', f.action, 'Post login forms to an HTTPS URL.');
      if (f.password && f.method === 'get') add('high', 'Password form uses GET (credentials end up in the URL)', f.action, 'Use method="post".');
    }
    const hits = info.comments.filter((c) => /(password|passwd|secret|token|api[_-]?key|todo|fixme|hack|internal|staging)/i.test(c));
    if (hits.length) add('low', 'HTML comments mention sensitive words', hits.slice(0, 3).map((c) => c.replace(/\s+/g, ' ').slice(0, 70)).join(' | '), 'Strip comments from production HTML.');
    if (info.generator) add('info', 'Site announces its generator', info.generator, 'Remove the generator meta tag if you do not want to advertise your stack.');
  }

  async function checkSensitivePaths(ctx) {
    const base = await getBaseline(ctx);
    let done = 0;
    await pool(PATHS, 6, async (p) => {
      try {
        const r = await xfetch(ctx.origin + p.p, { redirect: 'manual', signal: ctx.signal, retries: 0, timeout: 10000 });
        if (r.status !== 200 && r.status !== 206) return;
        const ct = (r.headers.get('content-type') || '').toLowerCase();
        const bytes = await readBytes(r, 8192);
        const text = dec.decode(bytes);
        if (!p.html && ct.includes('text/html')) return;
        if (base.status === 200 && text.length && text.slice(0, 200) === base.text) return;
        if (p.v && !p.v(text, bytes)) return;
        ctx.add({ sev: p.sev, title: p.title, url: ctx.origin + p.p, evidence: p.ev ? p.ev(text) : `HTTP 200, ${ct || 'unknown type'}, ${bytes.length >= 8192 ? '8 KB+' : bytes.length + ' bytes'}`, raw: isText(text) && !/[\x00-\x08]/.test(text) && ['critical', 'high', 'medium'].includes(p.sev) ? text.slice(0, 3000) : undefined, fix: p.fix, cat: 'Exposed files' });
        scanText(ctx, text, ctx.origin + p.p, false);
      } finally { ctx.sub(`Checking exposed files… ${++done}/${PATHS.length}`); }
    }, ctx.signal);
  }

  async function checkRobots(ctx) {
    const rb = ctx.robots || (ctx.robots = await AGCrawl.fetchRobots(ctx.origin, ctx.signal));
    ctx.inv.robots = rb;
    if (!rb.disallow.length) return;
    ctx.add({ sev: 'info', title: 'robots.txt lists hidden paths', url: ctx.origin + '/robots.txt', evidence: `${rb.disallow.length} Disallow rules, e.g. ${rb.disallow.slice(0, 6).join(' ')}`, fix: 'robots.txt is public and does not protect anything. Protect these paths with authentication.', cat: 'Exposed files' });
    const base = await getBaseline(ctx);
    const probe = rb.disallow.filter((d) => d.length > 1 && !/[*$?]/.test(d)).slice(0, 25);
    await pool(probe, 5, async (d) => {
      const r = await xfetch(ctx.origin + d, { redirect: 'manual', signal: ctx.signal, retries: 0, timeout: 10000 });
      if (r.status !== 200) return;
      const ct = (r.headers.get('content-type') || '').toLowerCase();
      const text = dec.decode(await readBytes(r, 2048));
      if (ct.includes('text/html') && base.status === 200 && text.slice(0, 200) === base.text) return;
      ctx.add({ sev: 'medium', title: 'Path from robots.txt is reachable without logging in', url: ctx.origin + d, evidence: `HTTP 200, ${ct || 'unknown type'}`, fix: 'If this area is private, require authentication and authorization on the server.', cat: 'Exposed files' });
    }, ctx.signal);
  }

  async function checkDirListing(ctx) {
    const dirs = new Set(['/uploads/', '/upload/', '/files/', '/images/', '/img/', '/assets/', '/static/', '/media/', '/backup/', '/backups/', '/data/', '/tmp/', '/logs/', '/.git/', '/node_modules/', '/src/', '/private/', '/docs/']);
    for (const u of [...ctx.items.map((i) => i.url), ...ctx.info.scripts.map((s) => s.url)]) {
      try {
        const x = new URL(u);
        if (x.origin !== ctx.origin) continue;
        const parts = x.pathname.split('/').filter(Boolean);
        parts.pop();
        let acc = '';
        for (const seg of parts.slice(0, 3)) { acc += '/' + seg; dirs.add(acc + '/'); }
      } catch (e) {}
    }
    await pool([...dirs].slice(0, 60), 6, async (d) => {
      const r = await xfetch(ctx.origin + d, { signal: ctx.signal, retries: 0, timeout: 10000 });
      if (!r.ok || !/html/i.test(r.headers.get('content-type') || '')) return;
      const t = dec.decode(await readBytes(r, 6000));
      if (LISTING.test(t)) ctx.add({ sev: 'medium', title: 'Directory listing is enabled', url: ctx.origin + d, evidence: 'server returns a file index', fix: 'Disable autoindex / directory browsing so folders cannot be enumerated.', cat: 'Exposed files' });
    }, ctx.signal);
  }

  const SKIP_HOST = /(googleapis|gstatic|googletagmanager|google-analytics|cdnjs|jsdelivr|unpkg|jquery|bootstrapcdn|fontawesome|facebook|doubleclick|hotjar|clarity\.ms|sentry-cdn|segment|intercom|js\.stripe)/i;

  async function checkMap(ctx, scriptUrl, text) {
    let mapUrl, found = null;
    const m = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/.exec(text.slice(-3000));
    try {
      if (m && !m[1].startsWith('data:')) mapUrl = new URL(m[1], scriptUrl).href;
      else if (!m) mapUrl = scriptUrl.split('?')[0] + '.map';
    } catch (e) { return; }
    if (!mapUrl) return;
    const r = await xfetch(mapUrl, { signal: ctx.signal, retries: 0, timeout: 15000 });
    if (r.status !== 200) return;
    const t = dec.decode(await readBytes(r, 300000));
    if (/"version"\s*:\s*3/.test(t) && /"sources"/.test(t)) {
      found = mapUrl;
      ctx.add({ sev: 'high', title: 'Source map is publicly downloadable', url: mapUrl, evidence: /"sourcesContent"/.test(t) ? 'contains the full original source code' : 'lists original file names', fix: 'Do not deploy .map files (build.sourcemap = false), or upload them privately to your error tracker.', cat: 'Source maps' });
    }
    return found;
  }

  async function checkScripts(ctx) {
    await ensureHtml(ctx);
    scanText(ctx, ctx.html, ctx.pageUrl + ' (page HTML)', false);
    ctx.info.inline.slice(0, 60).forEach((t) => scanText(ctx, t, ctx.pageUrl + ' (inline script)', true));
    const urls = [...new Set([...ctx.info.scripts.map((s) => s.url), ...ctx.info.requests.filter((r) => r.type === 'script').map((r) => r.url)])]
      .filter((u) => { try { return !SKIP_HOST.test(new URL(u).hostname); } catch (e) { return false; } }).slice(0, 80);
    let done = 0;
    await pool(urls, 4, async (u) => {
      try {
        const entry = { url: u, status: 0, bytes: 0, sourceMap: '' };
        ctx.inv.scripts.push(entry);
        const r = await xfetch(u, { signal: ctx.signal, timeout: 20000 });
        entry.status = r.status;
        if (!r.ok) return;
        const b = await readBytes(r, 3000000);
        entry.bytes = b.length;
        const t = dec.decode(b);
        scanText(ctx, t, u, true);
        if (ctx.opts.sourcemaps !== false) entry.sourceMap = (await checkMap(ctx, u, t)) || '';
      } finally { ctx.sub(`Reading scripts… ${++done}/${urls.length}`); }
    }, ctx.signal);
  }

  async function checkCloud(ctx) {
    const base = await getBaseline(ctx);
    // Supabase: can the public anon key read rows?
    for (const sb of ctx.found.supabase) {
      const ref = new URL(sb).hostname.split('.')[0];
      const keys = [...ctx.found.anon.entries()].sort((a, b) => (b[1] === ref) - (a[1] === ref));
      if (!keys.length) { ctx.add({ sev: 'info', title: 'Supabase project referenced, but no anon key found to test with', url: sb, evidence: sb, fix: 'Make sure Row Level Security is enabled on every table in the public schema.', cat: 'Cloud' }); continue; }
      const H = { apikey: keys[0][0], Authorization: 'Bearer ' + keys[0][0] };
      let tables = [];
      try {
        const r = await xfetch(sb + '/rest/v1/', { headers: H, signal: ctx.signal });
        if (r.ok) { const j = await r.json(); tables = Object.keys(j.paths || {}).map((p) => p.replace(/^\//, '')).filter((p) => p && !p.startsWith('rpc/')); }
      } catch (e) {}
      if (!tables.length) { ctx.add({ sev: 'info', title: 'Could not list Supabase tables with the anon key', url: sb, evidence: 'schema introspection returned nothing', fix: 'Good if intentional. Still verify RLS on every table, and test each table yourself.', cat: 'Cloud' }); continue; }
      await pool(tables.slice(0, 40), 4, async (t) => {
        const r = await xfetch(`${sb}/rest/v1/${encodeURIComponent(t)}?select=*&limit=1`, { headers: H, signal: ctx.signal });
        if (r.status !== 200) return;
        const j = await r.json().catch(() => null);
        if (Array.isArray(j) && j.length) ctx.add({ sev: 'high', title: 'Table is readable with the public anon key (RLS missing or too open)', url: `${sb}/rest/v1/${t}`, evidence: `table "${t}" returned a row; columns: ${Object.keys(j[0]).slice(0, 8).join(', ')} (data not shown)`, fix: `alter table ${t} enable row level security; then add policies that limit rows to their owner. Ignore if this table is meant to be public.`, cat: 'Cloud' });
        else if (Array.isArray(j)) ctx.add({ sev: 'low', title: 'Table is queryable by the anon key but returned no rows', url: `${sb}/rest/v1/${t}`, evidence: `table "${t}": empty, or RLS filtered everything`, fix: 'Check RLS policies. An empty table with RLS disabled becomes readable as soon as data is added.', cat: 'Cloud' });
      }, ctx.signal);
    }
    // Firebase Realtime Database
    for (const db of ctx.found.firebase) {
      try {
        const r = await xfetch(db + '/.json?shallow=true', { signal: ctx.signal });
        const t = dec.decode(await readBytes(r, 20000));
        if (r.status === 200 && t.trim() !== 'null') {
          let keys = '';
          try { keys = Object.keys(JSON.parse(t)).slice(0, 8).join(', '); } catch (e) {}
          ctx.add({ sev: 'critical', title: 'Firebase Realtime Database is readable without logging in', url: db, evidence: keys ? `top-level keys: ${keys}` : 'returns data', fix: 'Set rules so ".read" requires auth (and ownership), never true.', cat: 'Cloud' });
        } else if (r.status === 200) ctx.add({ sev: 'low', title: 'Firebase Realtime Database allows public reads (currently empty)', url: db, evidence: 'returns null', fix: 'Lock down rules before storing any data.', cat: 'Cloud' });
      } catch (e) {}
    }
    // Public cloud buckets
    for (const [url, label] of ctx.found.buckets) {
      try {
        const r = await xfetch(url, { signal: ctx.signal });
        const t = dec.decode(await readBytes(r, 4000));
        if (r.status === 200 && /<ListBucketResult|<EnumerationResults/.test(t)) ctx.add({ sev: 'high', title: `${label} bucket allows public listing`, url, evidence: 'returns a list of objects', fix: 'Disable public list access. Serve only specific public objects, ideally through a CDN.', cat: 'Cloud' });
      } catch (e) {}
    }
    // API endpoints found in code or seen in network traffic
    const same = (u) => { try { return new URL(u).origin === ctx.origin; } catch (e) { return false; } };
    const eps = [...new Set([...ctx.found.endpoints, ...ctx.info.requests.filter((r) => ['fetch', 'xmlhttprequest'].includes(r.type)).map((r) => r.url)])]
      .filter((u) => same(u) && !/(logout|signout|delete|remove|unsubscribe|destroy)/i.test(u)).slice(0, 40);
    let done = 0;
    ctx.inv.endpointsFound = [...new Set([...ctx.found.endpoints, ...ctx.info.requests.filter((r) => ['fetch', 'xmlhttprequest'].includes(r.type)).map((r) => r.url)])];
    await pool(eps, 4, async (u) => {
      try {
        const r = await xfetch(u, { redirect: 'manual', signal: ctx.signal, retries: 0 });
        const ct = (r.headers.get('content-type') || '').toLowerCase();
        const rec = { url: u, status: r.status, ct, state: 'other' };
        ctx.inv.endpoints.push(rec);
        if (r.type === 'opaqueredirect' || (r.status >= 300 && r.status < 400)) { rec.state = 'redirect'; return; }
        if (r.status === 401 || r.status === 403) { rec.state = 'protected'; return; }
        if (r.status !== 200) return;
        const text = dec.decode(await readBytes(r, 2048));
        if (ct.includes('text/html') || (base.status === 200 && text.slice(0, 200) === base.text)) { rec.state = 'page'; return; }
        rec.state = 'open';
        ctx.add({ sev: 'medium', title: 'API endpoint answers without logging in', url: u, evidence: `HTTP 200, ${ct || 'unknown type'}`, fix: 'Confirm this is meant to be public. Otherwise require authentication and check ownership on every record (IDOR).', cat: 'API' });
      } finally { ctx.sub(`Testing API endpoints… ${++done}/${eps.length}`); }
    }, ctx.signal);
  }

  const EXT_SEV = { env: 'critical', pem: 'critical', key: 'critical', p12: 'critical', pfx: 'critical', sql: 'high', sqlite: 'high', sqlite3: 'high', db: 'high', bak: 'high', map: 'high', old: 'medium', orig: 'medium', swp: 'medium', log: 'medium', ini: 'low', conf: 'low', cfg: 'low', yml: 'low', yaml: 'low', toml: 'low', properties: 'low' };

  async function checkFiles(ctx) {
    const rank = { config: 0, archive: 1, pdf: 2, document: 3 };
    const cands = ctx.items
      .filter((i) => ['config', 'archive', 'pdf', 'document', 'image'].includes(i.type))
      .sort((a, b) => (rank[a.type] ?? 4) - (rank[b.type] ?? 4))
      .slice(0, 150);
    let done = 0;
    await pool(cands, 4, async (it) => {
      try {
        const ext = extOf(it.url);
        const need = /^jpe?g|jfif$/.test(ext) ? 262144 : ext === 'pdf' ? 262144 : ['docx', 'xlsx', 'pptx'].includes(ext) ? 25000000 : ext === 'svg' ? 524288 : 8192;
        if (['docx', 'xlsx', 'pptx'].includes(ext) && it.size > 25000000) return;
        const r = await xfetch(it.url, { signal: ctx.signal, timeout: 30000 });
        if (!r.ok) return; // not reachable anonymously: nothing exposed
        const mime = (r.headers.get('content-type') || '').split(';')[0];
        const bytes = await readBytes(r, need);
        if (it.type === 'config' && EXT_SEV[ext]) ctx.add({ sev: EXT_SEV[ext], title: `Sensitive file type is publicly downloadable (.${ext})`, url: it.url, evidence: `HTTP ${r.status}, ${mime || 'unknown type'}`, fix: 'Remove it from the public folder. If it must exist, require authentication.', cat: 'File contents' });
        if (it.type === 'archive') ctx.add({ sev: 'low', title: 'Archive is publicly downloadable', url: it.url, evidence: `.${ext}, ${mime || 'unknown type'}`, fix: 'Check the archive holds nothing private (source, backups, keys).', cat: 'File contents' });
        let tail = null;
        if (ext === 'pdf' && it.size && it.size > need) {
          try {
            const t = await xfetch(it.url, { headers: { Range: 'bytes=-262144' }, signal: ctx.signal, retries: 0 });
            if (t.status === 206) tail = await readBytes(t, 262144);
          } catch (e) {}
        }
        for (const f of await AGInspect.analyze({ url: it.url, ext, mime, bytes, tail })) ctx.add(f);
      } finally { ctx.sub(`Inspecting files… ${++done}/${cands.length}`); }
    }, ctx.signal);
  }

  /* ---------- run + report ---------- */
  async function run({ pageUrl, items, info, opts = {}, signal, credentials = 'omit', onProgress = () => {} }) {
    const origin = new URL(pageUrl).origin;
    const findings = [], errors = [], keys = new Set();
    const ctx = {
      origin, pageUrl, items: items || [], info: info || AGCrawl.emptyInfo(), opts, signal, credentials, html: '', baseline: null,
      found: { supabase: new Set(), anon: new Map(), firebase: new Set(), buckets: new Map(), endpoints: new Set() },
      add(f) { const k = [f.title, f.url, f.evidence].join('|'); if (!keys.has(k)) { keys.add(k); findings.push(f); } },
      sub() {},
      inv: { status: 0, headers: {}, cookies: [], forms: [], generator: '', inlineScripts: 0, robots: { disallow: [], sitemaps: [] }, scripts: [], endpoints: [], endpointsFound: [], cloud: { supabase: [], anon: [], firebase: [], buckets: [] } },
    };
    const steps = [
      [opts.headers !== false, 'Headers, cookies, page content', [checkHeaders, checkCookies, checkPageContent]],
      [opts.paths !== false, 'Exposed files and folders', [checkSensitivePaths, checkRobots, checkDirListing]],
      [opts.secrets !== false, 'Secrets and source maps', [checkScripts]],
      [opts.cloud !== false, 'APIs and cloud storage', [checkCloud]],
      [opts.files !== false, 'File contents', [checkFiles]],
    ].filter((s) => s[0]);
    const started = Date.now();
    for (let i = 0; i < steps.length; i++) {
      const [, label, fns] = steps[i];
      onProgress(label + '…', i / steps.length);
      ctx.sub = (txt) => onProgress(txt, i / steps.length);
      for (const fn of fns) {
        if (signal && signal.aborted) throw new DOMException('Audit cancelled', 'AbortError');
        try { await fn(ctx); } catch (e) { if (signal && signal.aborted) throw e; errors.push(`${fn.name}: ${e.message || e}`); }
      }
    }
    findings.sort((a, b) => SEV.indexOf(a.sev) - SEV.indexOf(b.sev));
    ctx.inv.cloud = { supabase: [...ctx.found.supabase], anon: [...ctx.found.anon.keys()], firebase: [...ctx.found.firebase], buckets: [...ctx.found.buckets.entries()] };
    onProgress('Done', 1);
    return { origin, pageUrl, findings, errors, fileCount: ctx.items.length, started, finished: Date.now(), inventory: ctx.inv };
  }

  function toMarkdown(r, { secrets = false } = {}) {
    const c = Object.fromEntries(SEV.map((s) => [s, r.findings.filter((f) => f.sev === s).length]));
    let md = `# Security audit: ${r.origin}\n\nPage: ${r.pageUrl}  \nDate: ${new Date(r.finished).toISOString()}  \nFiles examined: ${r.fileCount}\n\n`;
    if (secrets) md += `> This report contains real secret values. Store it privately and rotate anything listed.\n\n`;
    md += `| Critical | High | Medium | Low | Info |\n|---|---|---|---|---|\n| ${SEV.map((s) => c[s]).join(' | ')} |\n\n`;
    if (!r.findings.length) md += 'No findings.\n\n';
    for (const s of SEV) {
      const list = r.findings.filter((f) => f.sev === s);
      if (!list.length) continue;
      md += `## ${s[0].toUpperCase() + s.slice(1)} (${list.length})\n\n`;
      for (const f of list) {
        md += `### ${f.title}\n- Where: ${f.url}\n- Evidence: ${f.evidence}\n- Fix: ${f.fix}\n`;
        if (secrets && (f.secret || f.raw)) md += `- Value:\n\n\`\`\`\n${f.secret || f.raw}\n\`\`\`\n`;
        md += '\n';
      }
    }
    if (r.errors.length) md += `## Checks that could not run\n\n${r.errors.map((e) => `- ${e}`).join('\n')}\n`;
    return md;
  }

  function toJson(r, { secrets = false } = {}) {
    return JSON.stringify(r, (k, v) => {
      if (!secrets && (k === 'secret' || k === 'raw')) return undefined;
      if (!secrets && k === 'anon' && Array.isArray(v)) return v.map(redact);
      return v;
    }, 2);
  }

  globalThis.AGAudit = { run, toMarkdown, toJson, redact, scanText, SEV, PATHS };
})();
