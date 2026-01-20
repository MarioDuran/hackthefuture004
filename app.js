// app.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3011;

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      // secure: true, // enable in production with HTTPS
      maxAge: 1000 * 60 * 60,
    },
  })
);

// Fixed "root" user
const ROOT_USERNAME = 'root';
const ROOT_PASSWORD_PLAINTEXT = process.env.ROOT_PASSWORD || 'rootpass';
const ROOT_PASSWORD_HASH = bcrypt.hashSync(ROOT_PASSWORD_PLAINTEXT, 10);

// Fixed code shown in "ACCESS GRANTED"
const FIXED_ACCESS_CODE = 'A5G2-9G2K-CF23-1PL4';

// Detect if request comes from localhost
function isLocalRequest(req) {
  const raw = (req.ip || req.connection.remoteAddress || '').replace('::ffff:', '');
  return raw === '127.0.0.1' || raw === '::1' || raw === 'localhost';
}

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/');
}

// Login page (hacker aesthetics)
// Note: client contains a snippet with password encoded in base64 (cm9vdHBhc3M=  ==> 'rootpass').
// The server will accept that password ONLY if VULN_MODE=true and the request is from localhost.
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/granted');

  res.send(`
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>Login — root</title>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <style>
      :root { --bg: #000; --panel: rgba(0,0,0,0.6); --glow: #00ff7f; --muted:#888; }
      html,body{height:100%;margin:0;background:var(--bg);font-family:"Courier New",monospace;color:var(--glow)}
      .wrap{height:100%;display:flex;align-items:center;justify-content:center;flex-direction:column;
            background-image: radial-gradient(circle at 10% 10%, rgba(0,255,127,0.035), transparent 10%),
                              linear-gradient(180deg, rgba(0,0,0,0.02), transparent 40%);}
      .console{width:480px;max-width:94%;padding:32px;background:var(--panel);border:1px solid rgba(0,255,127,0.08);
               box-shadow:0 0 40px rgba(0,255,127,0.04),inset 0 0 1px rgba(255,255,255,0.02);border-radius:10px;transition: transform 150ms ease;}
      h1{margin:0 0 12px 0;font-size:22px;letter-spacing:1px;color:var(--glow);text-align:left}
      label{display:block;margin-bottom:8px;font-size:13px;color:var(--muted);text-align:left}
      .input{width:100%;padding:12px 14px;margin-top:6px;background:transparent;border:1px solid rgba(0,255,127,0.12);
             color:var(--glow);border-radius:6px;outline:none;box-sizing:border-box;font-size:14px;text-shadow:0 0 6px rgba(0,255,127,0.06)}
      .row{margin-bottom:14px}
      .btn{width:100%;padding:12px;border-radius:6px;border:1px solid rgba(0,255,127,0.18);
           background:linear-gradient(90deg, rgba(0,255,127,0.12), rgba(0,255,127,0.06));
           color:var(--glow);font-weight:700;letter-spacing:1px;cursor:pointer;font-size:14px}
      .note{margin-top:12px;font-size:12px;color:var(--muted);text-align:left}
      .fake-terminal{font-size:12px;color:#0f0;opacity:0.85;margin-top:14px;white-space:pre-wrap;background:rgba(0,0,0,0.2);padding:8px;border-radius:4px}
      .error{margin-top:10px;color:#ff6b6b;font-size:13px;min-height:18px}
      @keyframes shake {0%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-6px)}80%{transform:translateX(6px)}100%{transform:translateX(0)}}
      .shake{animation:shake 320ms cubic-bezier(.36,.07,.19,.97)}
      .btn:hover{transform:translateY(-1px);box-shadow:0 6px 18px rgba(0,255,127,0.03)}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="console" id="panel" role="main" aria-labelledby="title">
        <h1 id="title">AUTH — ROOT</h1>
        <form id="loginForm" autocomplete="on">
          <div class="row">
            <label>Username</label>
            <input class="input" id="username" name="username" placeholder="root" required value="root" />
          </div>
          <div class="row">
            <label>Password</label>
            <input class="input" id="password" name="password" type="password" placeholder="password" />
          </div>
          <button class="btn" type="submit">SIGN IN</button>
        </form>

        <div class="error" id="errorMsg" aria-live="polite"></div>

        <div class="fake-terminal" id="terminal">
$ /* breadcrumb: have you read between lines? */ 
        </div>

        <script>
          (function () {
            // Temporary password for root is abc (change later)
            const form = document.getElementById('loginForm');
            const errorMsg = document.getElementById('errorMsg');
            const panel = document.getElementById('panel');
	    const a = 'root'; 
	    const b = 'pa';
	    const c = 'ss';

            form.addEventListener('submit', async (e) => {
              e.preventDefault();
              errorMsg.textContent = '';
              panel.classList.remove('shake');

              const username = document.getElementById('username').value.trim();
              const password = document.getElementById('password').value;
              const cfgToken = 'cm9vdHBhc3M='; 
              try {
                const resp = await fetch('/login', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ username, password })
                });

                if (resp.ok) {
                  const data = await resp.json();
                  if (data.ok) {
                    window.location = '/granted';
                    return;
                  }
                }

                let text = 'Incorrect password';
                try {
                  const js = await resp.json();
                  if (js && js.msg) text = js.msg;
                } catch (err) {}
                errorMsg.textContent = text;
                panel.classList.add('shake');

              } catch (err) {
                errorMsg.textContent = 'Connection error';
                panel.classList.add('shake');
              }
            });
          })();
        </script>
      </div>
    </div>
  </body>
</html>
  `);
});

// Login: accepts JSON (from fetch)
// Server accepts the "rootpass" password found in the client
// ONLY if VULN_MODE=true and request comes from localhost.
app.post('/login', async (req, res) => {
  const { username, password = '' } = req.body || {};

  if (username !== ROOT_USERNAME) {
    return res.status(401).json({ ok: false, msg: 'Incorrect password' });
  }

  // Special-case: explicit trap for the tempting password attempt
  if (password === 'BestProfIsMari0') {
    // Return the requested custom message
    return res.status(401).json({
      ok: false,
      msg: "Haha! good try, if something seems too good to be true, it usually isn’t."
    });
  }

  const vulnMode = process.env.VULN_MODE === 'true';
  const local = isLocalRequest(req);

  // ACCEPT the password discovered in the client ONLY in lab mode and from localhost
  if (password === ROOT_PASSWORD_PLAINTEXT && vulnMode && local) {
    console.warn('LAB MODE: access with password found on client (VULN_MODE=true, localhost).');
    req.session.user = { username: ROOT_USERNAME, lab: true };
    return res.json({ ok: true });
  }

  // Normal verification (hash)
  const ok = await bcrypt.compare(password, ROOT_PASSWORD_HASH);
  if (!ok) {
    return res.status(401).json({ ok: false, msg: 'Incorrect password' });
  }

  req.session.user = { username: ROOT_USERNAME };
  return res.json({ ok: true });
});

// "ACCESS GRANTED" page (same aesthetics) with fixed code shown below
app.get('/granted', requireAuth, (req, res) => {
  // Escape username for minimal safety (only alphanumerics expected)
  const safeUser = String(req.session.user && req.session.user.username ? req.session.user.username : '').replace(/[^a-zA-Z0-9_-]/g, '');

  res.send(`
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>ACCESS GRANTED</title>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <style>
      :root{--bg:#000;--glow:#00ff7f;--muted:#888}
      html,body{height:100%;margin:0;background:var(--bg);font-family:"Courier New",monospace;color:var(--glow)}
      .wrap{height:100%;display:flex;align-items:center;justify-content:center;flex-direction:column}
      .panel{padding:40px;background:rgba(0,0,0,0.6);border-radius:10px;border:1px solid rgba(0,255,127,0.08);text-align:center;min-width:320px}
      h1{font-size:28px;margin:0 0 8px 0;letter-spacing:2px}
      p{margin:0 0 14px 0;color:var(--muted)}
      .btn{padding:10px 14px;border-radius:6px;border:1px solid rgba(0,255,127,0.18);background:transparent;color:var(--glow);cursor:pointer}
      .access-code { margin-top:18px; padding:14px 20px; border-radius:8px; font-weight:700; letter-spacing:2px;
                      border:1px solid rgba(0,255,127,0.12); background:rgba(0,0,0,0.45); display:inline-block; font-size:18px; }
      .hint { margin-top:10px; color:var(--muted); font-size:13px; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="panel" role="main" aria-labelledby="grant">
        <h1 id="grant">ACCESS GRANTED</h1>
        <p>Connected as <strong>${safeUser}</strong></p>

        <div class="access-code" aria-label="Access code">${FIXED_ACCESS_CODE}</div>
        <div class="hint">Launch code</div>

        <form method="POST" action="/logout" style="margin-top:18px">
          <button class="btn" type="submit">LOG OUT</button>
        </form>
      </div>
    </div>
  </body>
</html>
  `);
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

app.listen(PORT, () => {
  // Avoid problematic template literal: use concatenation
  console.log('Server listening on http://localhost:' + PORT);
  if (process.env.VULN_MODE === 'true') {
    console.log('LAB MODE: VULN_MODE=true (only functional from localhost)');
  }
});
