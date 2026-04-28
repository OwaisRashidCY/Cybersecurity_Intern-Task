const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const winston = require('winston');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const fs = require('fs');
const cookieParser = require('cookie-parser'); 
const csrf = require('csurf'); 
const crypto = require('crypto');

const app = express();
const db = new sqlite3.Database(':memory:');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); 

app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    next();
});

const csrfProtection = csrf({ 
    cookie: {
        httpOnly: true,
        secure: false, 
        sameSite: 'lax' 
    } 
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 1000, 
    message: { error: "TOO_MANY_REQUESTS" }
});

app.use(cors({
    origin: function (origin, callback) {
        callback(null, true);
    },
    credentials: true
}));

app.use('/api/', apiLimiter);

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => `${timestamp} ${level}: ${message}`)
    ),
    transports: [
        new winston.transports.File({ filename: 'security.log' }),
        new winston.transports.Console()
    ],
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.tailwindcss.com", (req, res) => `'nonce-${res.locals.nonce}'`, "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"], 
            upgradeInsecureRequests: null, 
        },
    },
    xContentTypeOptions: true, 
    referrerPolicy: { policy: "no-referrer-when-downgrade" }
}));

db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, role TEXT)");
    const hash = bcrypt.hashSync("password123", 10);
    db.run("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", ["admin@example.com", hash, "admin"]);
    db.run("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", ["user@example.com", hash, "user"]);
});

function escapeHTML(str) {
    return str.replace(/[&<>"']/g, function(m) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[m];
    });
}

app.get('/', csrfProtection, (req, res) => {
    const token = req.csrfToken();
    const query = req.query.search || "";
    const escapedQuery = escapeHTML(query);

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>CyberShield Intern Portal</title>
            <script src="https://cdn.tailwindcss.com" nonce="${res.locals.nonce}"></script>
        </head>
        <body class="bg-slate-950 text-white min-h-screen p-4 md:p-8">
            <div class="max-w-5xl mx-auto">
                <header class="border-b border-slate-800 pb-6 mb-8 flex flex-wrap justify-between items-center gap-4">
                    <div>
                        <h1 class="text-2xl md:text-3xl font-black text-blue-500 tracking-tight">🛡 CYBERSHIELD V3</h1>
                        <p class="text-slate-500 text-[10px] font-mono uppercase tracking-widest text-blue-400">Node: ${req.headers.host}</p>
                    </div>
                    <div class="flex gap-4">
                        <button id="btn-logout" class="hidden text-[10px] bg-red-900/20 hover:bg-red-900/40 px-3 py-1 rounded border border-red-900/30 transition uppercase font-bold">Logout</button>
                        <button id="btn-clear" class="text-[10px] bg-slate-800 hover:bg-red-900/40 px-3 py-1 rounded border border-slate-700 transition">CLEAR LOGS</button>
                        <div class="flex items-center gap-2 bg-green-500/10 text-green-500 px-3 py-1 rounded-full border border-green-500/20 text-xs font-bold uppercase">Protected</div>
                    </div>
                </header>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 md:gap-10">
                    <div id="main-interface" class="bg-slate-900 p-6 md:p-8 rounded-3xl border border-slate-800 shadow-2xl">
                        <div id="login-box">
                            <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
                                <span class="p-2 bg-blue-500/20 rounded-lg text-blue-400 text-sm">01</span>
                                Authentication Control
                            </h2>
                            <div class="space-y-5">
                                <input type="hidden" id="csrf-token" value="${token}">
                                <div>
                                    <label class="block text-[10px] font-black text-slate-500 uppercase mb-2">Target Identity</label>
                                    <input id="email" type="email" placeholder="admin@example.com" class="w-full bg-slate-950 border border-slate-800 p-4 rounded-xl outline-none font-mono text-sm text-white">
                                </div>
                                <div>
                                    <label class="block text-[10px] font-black text-slate-500 uppercase mb-2">Access Key</label>
                                    <input id="password" type="password" placeholder="ENTER PASSWORD" class="w-full bg-slate-950 border border-slate-800 p-4 rounded-xl outline-none font-mono text-white text-sm">
                                </div>
                                <div class="grid grid-cols-1 gap-3 pt-4">
                                    <button id="btn-secure" class="bg-blue-600 hover:bg-blue-700 p-4 rounded-xl font-black uppercase tracking-tighter transition text-sm">Secure Verification</button>
                                    <button id="btn-vulnerable" class="border-2 border-red-900/50 text-red-500 hover:bg-red-500/5 p-4 rounded-xl font-black uppercase tracking-tighter transition text-xs">Execute SQLi Injection</button>
                                </div>
                            </div>
                        </div>

                        <div id="user-panel" class="hidden">
                            <h2 class="text-lg font-bold mb-4 text-blue-400 flex items-center gap-2">
                                <span class="p-2 bg-blue-500/20 rounded-lg text-sm">USER</span> User Dashboard
                            </h2>
                            <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 mb-4">
                                <p class="text-sm text-slate-400">Welcome back, intern. Your training modules are ready.</p>
                            </div>
                        </div>

                        <div id="admin-panel" class="hidden">
                            <h2 class="text-lg font-bold mb-4 text-purple-500 flex items-center gap-2">
                                <span class="p-2 bg-purple-500/20 rounded-lg text-sm">SUDO</span> Central Command
                            </h2>
                        </div>

                        <div id="auth-status" class="mt-8 p-4 rounded-xl bg-black font-mono text-xs border border-slate-800 hidden break-all"></div>
                    </div>

                    <div class="space-y-6">
                        <div class="bg-slate-900 p-6 md:p-8 rounded-3xl border border-slate-800 shadow-2xl">
                            <div class="flex justify-between items-center mb-6">
                                <h2 class="text-lg font-bold text-orange-500 flex items-center gap-2">
                                    <span class="p-2 bg-orange-500/20 rounded-lg text-orange-400 text-sm">02</span>
                                    Threat Intelligence
                                </h2>
                            </div>
                            
                            <div class="mb-6">
                                <form action="/" method="GET" class="flex gap-2">
                                    <input name="search" type="text" value="${escapedQuery}" placeholder="Probe system logs..." class="flex-1 bg-slate-950 border border-slate-800 px-4 py-2 rounded-lg text-xs outline-none focus:border-blue-500 transition text-white">
                                    <button type="submit" class="bg-blue-600 px-4 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest">Search</button>
                                </form>
                                ${query ? `
                                    <div class="mt-4 p-3 bg-black/40 rounded border border-slate-800 text-[10px] space-y-2">
                                        <div class="text-slate-500 uppercase font-bold">Query Analyzer Output:</div>
                                        <div class="p-3 border border-blue-900/30 rounded bg-blue-950/10">
                                            <span class="text-blue-400 font-bold underline">SECURE REFLECTION:</span>
                                            <p class="mt-1 text-slate-300 font-mono break-all">Result: ${escapedQuery}</p>
                                            <p class="mt-2 text-[8px] text-slate-600 font-mono italic">Verdict: XSS Attempt Neutralized via HTML Entity Encoding.</p>
                                        </div>
                                    </div>
                                ` : ''}
                            </div>

                            <div id="log-display" class="bg-black p-5 rounded-2xl h-[200px] overflow-y-auto font-mono text-[10px] text-green-500 border border-slate-800 space-y-1">
                                <div class="text-slate-700 underline">// KERNEL READY.</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <script nonce="${res.locals.nonce}">
                const API_BASE = window.location.origin;

                document.getElementById('btn-secure').addEventListener('click', () => handleLogin('secure'));
                document.getElementById('btn-vulnerable').addEventListener('click', () => handleLogin('vulnerable'));
                document.getElementById('btn-clear').addEventListener('click', clearLogs);
                document.getElementById('btn-logout').addEventListener('click', () => location.reload());

                async function handleLogin(route) {
                    const email = document.getElementById('email').value;
                    const password = document.getElementById('password').value;
                    const csrfToken = document.getElementById('csrf-token').value;
                    const status = document.getElementById('auth-status');
                    
                    status.classList.remove('hidden');
                    status.innerHTML = '<span class="animate-pulse">_ AUTHENTICATING...</span>';
                    
                    try {
                        const response = await fetch(API_BASE + '/api/login-' + route, {
                            method: 'POST',
                            credentials: 'include',
                            headers: { 
                                'Content-Type': 'application/json',
                                'CSRF-Token': csrfToken 
                            },
                            body: JSON.stringify({ email, password })
                        });
                        
                        const data = await response.json();
                        if (response.ok) {
                            status.className = "mt-8 p-4 rounded-xl bg-green-500/10 font-mono text-xs border border-green-500/30 text-green-400";
                            status.innerText = "SUCCESS: " + (data.role ? "ROLE_" + data.role.toUpperCase() : "BYPASS_MODE");
                            document.getElementById('login-box').classList.add('hidden');
                            document.getElementById('btn-logout').classList.remove('hidden');
                            if (data.role === 'admin') { document.getElementById('admin-panel').classList.remove('hidden'); } 
                            else { document.getElementById('user-panel').classList.remove('hidden'); }
                        } else {
                            status.className = "mt-8 p-4 rounded-xl bg-red-500/10 font-mono text-xs border border-red-500/30 text-red-500";
                            status.innerText = "DENIED: " + (data.error || "INVALID_CREDS");
                        }
                    } catch (err) {
                        status.innerText = "FATAL: " + err.message;
                    }
                    updateLogs();
                }

                async function updateLogs() {
                    try {
                        const res = await fetch(API_BASE + '/api/raw-logs');
                        const logs = await res.json();
                        const display = document.getElementById('log-display');
                        if (logs.length > 0) {
                            display.innerHTML = logs.map(l => '<div><span class="text-slate-600">[' + l.time + ']</span> ' + l.msg + '</div>').join('');
                            display.scrollTop = display.scrollHeight;
                        }
                    } catch (e) {}
                }

                async function clearLogs() {
                    const csrfToken = document.getElementById('csrf-token').value;
                    await fetch(API_BASE + '/api/clear-logs', { 
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'CSRF-Token': csrfToken }
                    });
                    document.getElementById('log-display').innerHTML = '<div class="text-slate-700 underline">// LOGS WIPED.</div>';
                }

                updateLogs();
                setInterval(updateLogs, 4000);
            </script>
        </body>
        </html>
    `);
});

app.post('/api/login-secure', csrfProtection, (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress; // Get Client IP
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            logger.info(`Login_Success: ${email} from ${ip}`);
            res.json({ success: true, role: user.role });
        } else {
            // LOG THE FAILURE FOR FAIL2BAN
            logger.warn(`AUTH_FAILURE: IP ${ip} tried to login as ${email}`);
            res.status(401).json({ error: "ACCESS_DENIED" });
        }
    });
});

app.post('/api/login-vulnerable', csrfProtection, (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
    db.get(query, (err, row) => {
        if (row) {
            logger.warn(`CRITICAL: SQLi_Bypass on ${email} from ${ip}`);
            res.json({ bypass: true, role: row.role });
        } else {
            // LOG THE FAILURE FOR FAIL2BAN
            logger.warn(`AUTH_FAILURE: IP ${ip} attempted SQLi/Access on ${email}`);
            res.status(401).json({ error: "QUERY_EMPTY" });
        }
    });
});

app.get('/api/raw-logs', (req, res) => {
    if (!fs.existsSync('security.log')) return res.json([]);
    const content = fs.readFileSync('security.log', 'utf8').split('\n').filter(l => l).slice(-10).map(l => {
        const parts = l.split(' ');
        return { time: parts[1] || "00:00", msg: l.split(': ')[1] || "System" };
    });
    res.json(content);
});

app.post('/api/clear-logs', csrfProtection, (req, res) => {
    fs.writeFileSync('security.log', '');
    res.json({ success: true });
});

app.use((err, req, res, next) => {
    if (err.code !== 'EBADCSRFTOKEN') return next(err);
    res.status(403).json({ error: "CSRF_FAIL" });
});

app.listen(3000, '0.0.0.0', () => {
    console.log("🚀 CYBERSHIELD V3 ONLINE: Port 3000");
});
