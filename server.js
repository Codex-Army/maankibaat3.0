
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

const JWT_SECRET = 'modi_hai_to_admin_hai';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// =====================================
// CTF FLAGS
// =====================================

const FLAG1 = 'MODI{Desh_Bachalo_Guys}';
const FLAG2 = 'MODI{BECHO_JANTA_PARTY}';
const FLAG3 = 'MODI{Sab_Jaan_Gaye}';

const MASTER_FLAG =
    'MASTER{Desh_Bachalo_BECHO_JANTA_Sab_Jaan_Gaye_Mann_Ki_Baat_Yogi_Rush}';

const XSS_FLAG = 'MODI{Mann_Ki_Baat_XSS}';
const RACE_FLAG = 'MODI{Chor_Ke_Ghar_Mein_Chori}';
const TWOFA_FLAG = 'MODI{Doosra_Darwaza_Khula}';

const RACE_THRESHOLD = 2;

// =====================================
// TABLET STORAGE
// =====================================

const tabletClaims = new Map();

const USE_REDIS = Boolean(
    process.env.UPSTASH_REDIS_REST_URL &&
    process.env.UPSTASH_REDIS_REST_TOKEN
);

let redis = null;

if (USE_REDIS) {
    try {
        const { Redis } = require('@upstash/redis');

        redis = new Redis({
            url: process.env.UPSTASH_REDIS_REST_URL,
            token: process.env.UPSTASH_REDIS_REST_TOKEN
        });
    } catch (error) {
        console.error('Redis initialization error:', error.message);
    }
}

async function getClaimCount(sessionId) {
    if (redis) {
        const value = await redis.get(`mitron:tablet:${sessionId}`);
        return Number(value || 0);
    }

    return tabletClaims.get(sessionId) || 0;
}

async function incrementClaimCount(sessionId) {
    if (redis) {
        const key = `mitron:tablet:${sessionId}`;
        const count = await redis.incr(key);

        await redis.expire(key, 3600);

        return Number(count);
    }

    const count = (tabletClaims.get(sessionId) || 0) + 1;
    tabletClaims.set(sessionId, count);

    return count;
}

async function resetClaimCount(sessionId) {
    if (redis) {
        await redis.del(`mitron:tablet:${sessionId}`);
        return;
    }

    tabletClaims.delete(sessionId);
}

// =====================================
// AUTHENTICATION MIDDLEWARE
// =====================================

function auth(req, res, next) {
    const token = req.cookies && req.cookies.token;

    req.user = null;

    if (!token) {
        return next();
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET, {
            algorithms: ['HS256']
        });
    } catch (error) {
        res.clearCookie('token', { path: '/' });
    }

    return next();
}

app.use(auth);

// =====================================
// HOME PAGE
// =====================================

app.get('/', (req, res) => {
    res.render('index', {
        user: req.user || null
    });
});

// =====================================
// NORMAL LOGIN
// =====================================

app.post('/login', (req, res) => {
    const body = req.body || {};
    const { username, password } = body;

    if (
        username === 'amit' &&
        password === 'mitron@2026'
    ) {
        const token = jwt.sign(
            {
                username,
                role: 'user'
            },
            JWT_SECRET
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure:
                process.env.NODE_ENV === 'production' ||
                Boolean(process.env.VERCEL),
            sameSite: 'lax',
            path: '/',
            maxAge: 60 * 60 * 1000
        });

        return res.status(200).json({
            success: true,
            message: 'Login Successful'
        });
    }

    return res.status(401).json({
        success: false,
        message: 'Wrong Credentials'
    });
});

// =====================================
// ROBOTS.TXT
// =====================================

app.get('/robots.txt', (req, res) => {
    res.type('text/plain');

    res.send(`
User-agent: *
Disallow: /modi
Disallow: /admin
Disallow: /backend-vault-7x9
`);
});

// =====================================
// EXISTING PAGES
// =====================================

app.get('/modi', (req, res) => {
    res.render('modi');
});

app.get('/mann-ki-baat', (req, res) => {
    res.render('mann-ki-baat');
});

app.get('/yogi-tablet', (req, res) => {
    res.render('yogi-tablet');
});

// Old URL redirect
app.get('/yogi-laptop', (req, res) => {
    res.redirect(301, '/yogi-tablet');
});

// =====================================
// XSS TRAINING ENDPOINT
// =====================================

app.get('/api/xss-flag', (req, res) => {
    if (req.get('x-xss-solved') !== '1') {
        return res.status(403).json({
            success: false,
            message: 'Nice try! Execute XSS on /mann-ki-baat first.'
        });
    }

    return res.json({
        success: true,
        flag: XSS_FLAG
    });
});

// =====================================
// TABLET RACE CONDITION CLAIM
// =====================================

app.post('/api/tablet/claim', async (req, res) => {
    try {
        const body = req.body || {};
        const sessionId = String(body.sessionId || '');

        if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid challenge session.'
            });
        }

        const current = await getClaimCount(sessionId);

        if (current >= 1) {
            return res.status(409).json({
                success: false,
                claimed: current,
                message:
                    'Arre Mitron! Aap pehle hi ek tablet claim kar chuke hain!'
            });
        }

        // Intentional check-then-act race window for this CTF.
        await new Promise(resolve => setTimeout(resolve, 180));

        const claimed = await incrementClaimCount(sessionId);
        const solved = claimed >= RACE_THRESHOLD;

        return res.json({
            success: true,
            claimed,
            message: solved
                ? 'Arre Mitron, ek tablet lene aaye the aur dukaan khaali kar di!'
                : 'Tablet claim successful! Ek hi tablet allowed hai.',
            ...(solved ? { flag: RACE_FLAG } : {})
        });

    } catch (error) {
        console.error('Tablet claim error:', error);

        return res.status(500).json({
            success: false,
            message: 'Tablet claim service temporarily unavailable.'
        });
    }
});

// =====================================
// TABLET RACE CONDITION RESET
// =====================================

app.post('/api/tablet/reset', async (req, res) => {
    try {
        const body = req.body || {};
        const sessionId = String(body.sessionId || '');

        if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid challenge session.'
            });
        }

        await resetClaimCount(sessionId);

        return res.json({
            success: true,
            message: 'Tablet claim counter reset for this challenge session.'
        });

    } catch (error) {
        console.error('Tablet reset error:', error);

        return res.status(500).json({
            success: false,
            message: 'Could not reset the tablet challenge.'
        });
    }
});

// =====================================
// ADANI ADMIN VAULT - 2FA CHALLENGE
// =====================================

const VAULT_USERNAME = 'root.operator';
const VAULT_PASSWORD = 'Vault@2026!';
const VAULT_OTP = '73190426';

// Vault landing page
app.get('/backend-vault-7x9', (req, res) => {
    res.render('backend-vault');
});

// Exposed configuration for CTF recon practice
app.get('/backend-vault-7x9/assets/ops-config.js', (req, res) => {
    res.type('application/javascript').send(
        `window.VAULT_HINTS = {
            realm: 'internal-ops',
            operator: '${VAULT_USERNAME}',
            passphrase: '${VAULT_PASSWORD}',
            credentialNote: 'Internal operations bootstrap credentials'
        };`
    );
});

// Vault login
app.post('/backend-vault-7x9/login', (req, res) => {
    const body = req.body || {};
    const { username, password } = body;

    if (
        username !== VAULT_USERNAME ||
        password !== VAULT_PASSWORD
    ) {
        return res.status(401).json({
            success: false,
            message: 'Invalid operator credentials.'
        });
    }

    // Intentional CTF flaw: admin role is granted before OTP verification.
    const pending = jwt.sign(
        {
            username,
            role: 'vault-admin',
            twoFactor: false
        },
        JWT_SECRET,
        { expiresIn: '20m' }
    );

    res.cookie('vault_pending', pending, {
        httpOnly: true,
        secure:
            process.env.NODE_ENV === 'production' ||
            Boolean(process.env.VERCEL),
        sameSite: 'lax',
        path: '/',
        maxAge: 20 * 60 * 1000
    });

    return res.json({
        success: true,
        twoFactorRequired: true,
        next: '/backend-vault-7x9/verify'
    });
});

// OTP verification
app.post('/backend-vault-7x9/verify', (req, res) => {
    const token = req.cookies && req.cookies.vault_pending;

    let pending;

    try {
        pending = jwt.verify(token || '', JWT_SECRET, {
            algorithms: ['HS256']
        });
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Login session missing. Start again.'
        });
    }

    const otp = String((req.body || {}).otp || '');

    if (!/^\d{8}$/.test(otp) || otp !== VAULT_OTP) {
        return res.status(429).json({
            success: false,
            message: 'OTP rejected. Brute force is not the intended solution.',
            hint: 'If OTP verification is bypassed, try accessing /backend-vault-7x9/console'
        });
    }

    const verified = jwt.sign(
        {
            username: pending.username,
            role: 'vault-admin',
            twoFactor: true
        },
        JWT_SECRET,
        { expiresIn: '20m' }
    );

    res.cookie('vault_pending', verified, {
        httpOnly: true,
        secure:
            process.env.NODE_ENV === 'production' ||
            Boolean(process.env.VERCEL),
        sameSite: 'lax',
        path: '/',
        maxAge: 20 * 60 * 1000
    });

    return res.json({
        success: true,
        message: 'Second factor accepted.'
    });
});

// Intentional CTF authorization flaw:
// Role is checked, but twoFactor is not checked.
app.get('/backend-vault-7x9/console', (req, res) => {
    let vaultUser;

    try {
        vaultUser = jwt.verify(
            (req.cookies || {}).vault_pending || '',
            JWT_SECRET,
            { algorithms: ['HS256'] }
        );
    } catch (error) {
        return res.redirect('/backend-vault-7x9');
    }

    if (vaultUser.role !== 'vault-admin') {
        return res.status(403).send('Forbidden');
    }

    return res.render('backend-console', {
        flag: TWOFA_FLAG
    });
});

// =====================================
// SECURE MESSAGE PAGE
// =====================================

app.get('/secure-message', (req, res) => {
    res.render('secure-message');
});

// =====================================
// IDOR TRAINING ENDPOINT
// =====================================

app.get('/api/secure-message', (req, res) => {
    const userId = String(req.query.userId || '');

    const messages = {
        '101': {
            username: 'amit',
            title: 'Message for Amit',
            body:
                'Mitron, report ka first draft ready hai. Meeting se pehle review kar lena.'
        },

        '102': {
            username: 'yogi',
            title: 'Message for Yogi',
            body:
                'Yogi ji, event ke arrangements confirm hain. Final update ka intezar hai.'
        },

        '420': {
            username: 'gyanesh',
            title: 'Private message for Gyanesh',
            body:
                'Gyanesh, sab jaan gaye... asli raaz yahin tha. Flag: ' + FLAG3
        }
    };

    const message = messages[userId];

    if (!message) {
        return res.status(404).json({
            success: false,
            message: 'User/message not found. Check the request and userId.'
        });
    }

    return res.json({
        success: true,
        message
    });
});

// =====================================
// PRICE MANIPULATION CHALLENGE
// =====================================

app.post('/buy', (req, res) => {
    const body = req.body || {};
    const price = Number(body.price);

    if (
        body.price !== undefined &&
        body.price !== '' &&
        body.price !== null &&
        price === 0
    ) {
        return res.json({
            success: true,
            flag: FLAG1
        });
    }

    return res.json({
        success: false,
        message: 'Price too high'
    });
});

// =====================================
// ADMIN / JWT CHALLENGE
// =====================================

app.get('/admin', (req, res) => {
    if (!req.user) {
        return res.redirect(302, '/');
    }

    if (req.user.role !== 'admin') {
        return res.status(403).render('notadmin');
    }

    return res.render('admin', {
        flag: FLAG2
    });
});

// =====================================
// SIX-FLAG SUBMISSION
// =====================================

const ALL_FLAGS = [
    FLAG1,
    FLAG2,
    FLAG3,
    XSS_FLAG,
    RACE_FLAG,
    TWOFA_FLAG
];

app.post('/submit-flag', (req, res) => {
    const candidate = String(
        (req.body || {}).flag || ''
    ).trim();

    let progress = [];

    try {
        const decoded = jwt.verify(
            (req.cookies || {}).ctf_progress || '',
            JWT_SECRET,
            { algorithms: ['HS256'] }
        );

        if (Array.isArray(decoded.solved)) {
            progress = decoded.solved.filter(
                flag => ALL_FLAGS.includes(flag)
            );
        }
    } catch (error) {
        // Start with empty progress when cookie is absent or invalid.
    }

    if (!ALL_FLAGS.includes(candidate)) {
        return res.json({
            success: false,
            message: 'Incorrect flag. Keep investigating the challenges.',
            completed: progress.length,
            total: ALL_FLAGS.length,
            remaining: ALL_FLAGS.length - progress.length
        });
    }

    if (!progress.includes(candidate)) {
        progress.push(candidate);
    }

    const complete = progress.length === ALL_FLAGS.length;

    const signed = jwt.sign(
        { solved: progress },
        JWT_SECRET,
        { expiresIn: '30d' }
    );

    res.cookie('ctf_progress', signed, {
        httpOnly: true,
        secure:
            process.env.NODE_ENV === 'production' ||
            Boolean(process.env.VERCEL),
        sameSite: 'lax',
        path: '/',
        maxAge: 30 * 24 * 60 * 60 * 1000
    });

    return res.json({
        success: true,
        completed: progress.length,
        total: ALL_FLAGS.length,
        remaining: ALL_FLAGS.length - progress.length,
        message: complete
            ? 'All challenge flags verified!'
            : 'Correct flag! Progress updated.',
        ...(complete
            ? {
                reward: 'MITRON-MARKET-CHAMPION',
                masterFlag: MASTER_FLAG
            }
            : {})
    });
});

// =====================================
// EXPORT FOR VERCEL
// =====================================

module.exports = app;

// =====================================
// LOCAL DEVELOPMENT
// =====================================

if (require.main === module && !process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);

        console.log(
            `Tablet storage: ${
                redis ? 'Upstash Redis' : 'Local in-memory Map'
            }`
        );
    });
}
