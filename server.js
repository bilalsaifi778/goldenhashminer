require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Render.com sits behind a reverse proxy
app.set('trust proxy', 1);

// Neon.tech PostgreSQL Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000
});

// Security & Body Parsing (Allow Tailwind CDN, FontAwesome, Google Fonts)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"]
      }
    }
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// PostgreSQL Session Store (Stateless container safe)
app.use(
  session({
    store: new pgSession({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || 'golden-hash-super-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    }
  })
);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// --- HELPER: Calculate Real-Time Unclaimed Mining Yield ---
// Base free rate: 50 GH/s yields $0.00000150/sec (~$0.1296/day) + active contracts
const BASE_FREE_RATE_PER_GHS_SEC = 0.00000003;

async function calculateMiningState(userId) {
  const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  if (userRes.rows.length === 0) return null;
  const user = userRes.rows[0];

  const now = new Date();
  // 1. Free base rig accrual
  const freeSeconds = Math.max(0, (now - new Date(user.last_claimed_at)) / 1000);
  const freeDailyRate = 50 * BASE_FREE_RATE_PER_GHS_SEC * 86400;
  let unclaimedUsdt = freeSeconds * (50 * BASE_FREE_RATE_PER_GHS_SEC);
  let totalDailyRate = freeDailyRate;

  // 2. Active paid contracts accrual
  const contractsRes = await pool.query(
    `SELECT uc.*, mp.name AS plan_name, mp.tier_badge 
     FROM user_contracts uc 
     JOIN mining_plans mp ON uc.plan_id = mp.id 
     WHERE uc.user_id = $1 AND uc.status = 'active'`,
    [userId]
  );

  for (const c of contractsRes.rows) {
    const expiry = new Date(c.expires_at);
    const effectiveEnd = now < expiry ? now : expiry;
    const elapsedSec = Math.max(0, (effectiveEnd - new Date(c.last_accrued_at)) / 1000);
    const perSec = parseFloat(c.daily_profit_usdt) / 86400;

    unclaimedUsdt += elapsedSec * perSec;
    if (now < expiry) {
      totalDailyRate += parseFloat(c.daily_profit_usdt);
    } else {
      await pool.query(`UPDATE user_contracts SET status = 'expired' WHERE id = $1`, [c.id]);
    }
  }

  return {
    user,
    contracts: contractsRes.rows,
    unclaimedUsdt: Number(unclaimedUsdt.toFixed(8)),
    totalDailyRate: Number(totalDailyRate.toFixed(6)),
    perSecondRate: Number((totalDailyRate / 86400).toFixed(8))
  };
}

// Middleware: Ensure Authenticated
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId || req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized admin access' });
  }
  next();
}

// ==================== ROUTES ====================

// Root Redirect
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.redirect('/login');
});

// Minimal Built-in Auth Page (if user visits /login)
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.send(`
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
      <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>GoldenHash Miner — Cloud Gold & Crypto Mining</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-4">
      <div class="w-full max-w-md bg-slate-900/90 border border-amber-500/30 rounded-2xl p-8 shadow-2xl">
        <div class="text-center mb-6">
          <div class="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-gradient-to-br from-amber-400 to-yellow-600 text-slate-950 text-2xl font-bold mb-3 shadow-lg shadow-amber-500/20">
            <i class="fa-solid fa-coins"></i>
          </div>
          <h1 class="text-2xl font-bold bg-gradient-to-r from-amber-300 via-yellow-400 to-amber-500 bg-clip-text text-transparent">GOLDEN HASH MINER</h1>
          <p class="text-xs text-slate-400 mt-1">Instant 50 GH/s Free Gold Mining Bonus on Signup</p>
        </div>
        <div class="flex gap-2 mb-6 bg-slate-950 p-1 rounded-xl">
          <button onclick="toggleForm('login')" id="tab-login" class="flex-1 py-2 rounded-lg text-sm font-semibold bg-amber-500 text-slate-950">Login</button>
          <button onclick="toggleForm('register')" id="tab-register" class="flex-1 py-2 rounded-lg text-sm font-semibold text-slate-400">Register</button>
        </div>
        <form id="login-form" action="/auth/login" method="POST" class="space-y-4">
          <input type="email" name="email" placeholder="Email Address" required class="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 focus:border-amber-500 outline-none text-sm">
          <input type="password" name="password" placeholder="Password" required class="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 focus:border-amber-500 outline-none text-sm">
          <button type="submit" class="w-full py-3 rounded-xl bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-400 hover:to-yellow-400 text-slate-950 font-bold text-sm transition">Access Mining Rig</button>
        </form>
        <form id="register-form" action="/auth/register" method="POST" class="space-y-4 hidden">
          <input type="text" name="username" placeholder="Miner Username" required class="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 focus:border-amber-500 outline-none text-sm">
          <input type="email" name="email" placeholder="Email Address" required class="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 focus:border-amber-500 outline-none text-sm">
          <input type="password" name="password" placeholder="Create Password" required class="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 focus:border-amber-500 outline-none text-sm">
          <input type="text" name="ref" placeholder="Referral Code (Optional)" class="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 focus:border-amber-500 outline-none text-sm">
          <button type="submit" class="w-full py-3 rounded-xl bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-400 hover:to-yellow-400 text-slate-950 font-bold text-sm transition">Claim 50 GH/s & Start</button>
        </form>
      </div>
      <script>
        function toggleForm(mode) {
          document.getElementById('login-form').classList.toggle('hidden', mode !== 'login');
          document.getElementById('register-form').classList.toggle('hidden', mode !== 'register');
          document.getElementById('tab-login').className = mode === 'login' ? 'flex-1 py-2 rounded-lg text-sm font-semibold bg-amber-500 text-slate-950' : 'flex-1 py-2 rounded-lg text-sm font-semibold text-slate-400';
          document.getElementById('tab-register').className = mode === 'register' ? 'flex-1 py-2 rounded-lg text-sm font-semibold bg-amber-500 text-slate-950' : 'flex-1 py-2 rounded-lg text-sm font-semibold text-slate-400';
        }
      </script>
    </body>
    </html>
  `);
});

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { username, email, password, ref } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const publicUid = Math.floor(100000 + Math.random() * 900000).toString();
    const referralCode = 'GH' + Math.random().toString(36).substring(2, 8).toUpperCase();

    let referrerId = null;
    if (ref && ref.trim() !== '') {
      const refUser = await pool.query('SELECT id FROM users WHERE referral_code = $1', [ref.trim().toUpperCase()]);
      if (refUser.rows.length > 0) referrerId = refUser.rows[0].id;
    }

    // First registered user automatically becomes admin
    const countRes = await pool.query('SELECT COUNT(*) FROM users');
    const role = parseInt(countRes.rows[0].count) === 0 ? 'admin' : 'user';

    const insertRes = await pool.query(
      `INSERT INTO users (public_uid, username, email, password_hash, referral_code, referred_by, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, role`,
      [publicUid, username.trim(), email.toLowerCase().trim(), hash, referralCode, referrerId, role]
    );

    req.session.userId = insertRes.rows[0].id;
    req.session.role = insertRes.rows[0].role;
    res.redirect('/dashboard');
  } catch (err) {
    res.status(400).send(`Registration failed: ${err.message}`);
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (userRes.rows.length === 0) return res.status(401).send('Invalid credentials');

    const user = userRes.rows[0];
    if (user.is_banned) return res.status(403).send('Account suspended');

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).send('Invalid credentials');

    req.session.userId = user.id;
    req.session.role = user.role;
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Server error during login');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Main Dashboard
app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const state = await calculateMiningState(req.session.userId);
    if (!state) return res.redirect('/logout');

    const plansRes = await pool.query('SELECT * FROM mining_plans WHERE is_active = TRUE ORDER BY price_usdt ASC');
    const txRes = await pool.query(
      'SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 15',
      [req.session.userId]
    );
    const refCountRes = await pool.query('SELECT COUNT(*) FROM users WHERE referred_by = $1', [req.session.userId]);

    let adminPendingTx = [];
    if (state.user.role === 'admin') {
      const pendingRes = await pool.query(
        `SELECT t.*, u.username, u.public_uid 
         FROM transactions t JOIN users u ON t.user_id = u.id 
         WHERE t.status = 'pending' ORDER BY t.created_at ASC`
      );
      adminPendingTx = pendingRes.rows;
    }

    res.render('dashboard', {
      user: state.user,
      contracts: state.contracts,
      unclaimedUsdt: state.unclaimedUsdt,
      totalDailyRate: state.totalDailyRate,
      perSecondRate: state.perSecondRate,
      plans: plansRes.rows,
      transactions: txRes.rows,
      referralCount: parseInt(refCountRes.rows[0].count),
      adminPendingTx,
      depositWallets: {
        'USDT-TRC20': process.env.WALLET_TRC20 || 'TX9kGoldenHashVaultTRC20DepositAddr889',
        'USDT-BEP20': process.env.WALLET_BEP20 || '0x71CGoldenHashVaultBEP20DepositAddr992',
        'BTC': process.env.WALLET_BTC || 'bc1qgoldenhashvaultbtcdepositaddr774'
      },
      baseUrl: `${req.protocol}://${req.get('host')}`
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Dashboard load error');
  }
});

// API: Claim Mined Balance to Main Wallet
app.post('/api/mine/claim', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const state = await calculateMiningState(req.session.userId);
    if (state.unclaimedUsdt < 0.0001) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Minimum claim threshold is $0.00010000 USDT' });
    }

    const now = new Date();
    const updatedUser = await client.query(
      `UPDATE users 
       SET balance_usdt = balance_usdt + $1, last_claimed_at = $2 
       WHERE id = $3 RETURNING balance_usdt`,
      [state.unclaimedUsdt, now, req.session.userId]
    );

    await client.query(
      `UPDATE user_contracts SET last_accrued_at = $1 WHERE user_id = $2 AND status = 'active'`,
      [now, req.session.userId]
    );

    await client.query(
      `INSERT INTO transactions (user_id, type, network, amount_usdt, status)
       VALUES ($1, 'mine_claim', 'INTERNAL', $2, 'completed')`,
      [req.session.userId, state.unclaimedUsdt]
    );

    await client.query('COMMIT');
    res.json({
      success: true,
      claimed: state.unclaimedUsdt,
      newBalance: parseFloat(updatedUser.rows[0].balance_usdt)
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Claim failed' });
  } finally {
    client.release();
  }
});

// API: Purchase / Upgrade Mining Contract
app.post('/api/plans/buy', requireAuth, async (req, res) => {
  const { planId } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const planRes = await client.query('SELECT * FROM mining_plans WHERE id = $1 AND is_active = TRUE', [planId]);
    if (planRes.rows.length === 0) throw new Error('Plan unavailable');
    const plan = planRes.rows[0];
    if (parseFloat(plan.price_usdt) <= 0) throw new Error('Free plan is already active');

    const userRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [req.session.userId]);
    const user = userRes.rows[0];

    if (parseFloat(user.balance_usdt) < parseFloat(plan.price_usdt)) {
      throw new Error('Insufficient USDT balance. Please deposit first.');
    }

    const dailyProfit = (parseFloat(plan.price_usdt) * parseFloat(plan.daily_roi_percent)) / 100;
    const expiresAt = new Date(Date.now() + plan.duration_days * 24 * 60 * 60 * 1000);

    await client.query(
      `UPDATE users 
       SET balance_usdt = balance_usdt - $1, total_hashrate_ghs = total_hashrate_ghs + $2 
       WHERE id = $3`,
      [plan.price_usdt, plan.hashrate_ghs, user.id]
    );

    await client.query(
      `INSERT INTO user_contracts (user_id, plan_id, hashrate_ghs, daily_profit_usdt, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [user.id, plan.id, plan.hashrate_ghs, dailyProfit, expiresAt]
    );

    await client.query(
      `INSERT INTO transactions (user_id, type, network, amount_usdt, status)
       VALUES ($1, 'plan_buy', 'INTERNAL', $2, 'completed')`,
      [user.id, plan.price_usdt]
    );

    // 10% Instant Referral Commission
    if (user.referred_by) {
      const commission = parseFloat(plan.price_usdt) * 0.1;
      await client.query(
        `UPDATE users SET balance_usdt = balance_usdt + $1, referral_earnings = referral_earnings + $1 WHERE id = $2`,
        [commission, user.referred_by]
      );
      await client.query(
        `INSERT INTO transactions (user_id, type, network, amount_usdt, status)
         VALUES ($1, 'referral', 'BONUS-10%', $2, 'completed')`,
        [user.referred_by, commission]
      );
    }

    await client.query('COMMIT');
    res.json({ success: true, message: `${plan.name} activated!` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// API: Submit Deposit Proof
app.post('/api/deposit', requireAuth, async (req, res) => {
  try {
    const { network, amount, txHash } = req.body;
    const parsedAmount = parseFloat(amount);
    if (!parsedAmount || parsedAmount < 5) {
      return res.status(400).json({ error: 'Minimum deposit is $5.00 USDT' });
    }
    if (!txHash || txHash.trim().length < 10) {
      return res.status(400).json({ error: 'Valid Transaction Hash (TXID) is required' });
    }

    await pool.query(
      `INSERT INTO transactions (user_id, type, network, amount_usdt, tx_hash, status)
       VALUES ($1, 'deposit', $2, $3, $4, 'pending')`,
      [req.session.userId, network, parsedAmount, txHash.trim()]
    );

    res.json({ success: true, message: 'Deposit submitted! Credited after network confirmation.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit deposit' });
  }
});

// API: Request Withdrawal
app.post('/api/withdraw', requireAuth, async (req, res) => {
  const { network, amount, walletAddress } = req.body;
  const parsedAmount = parseFloat(amount);
  const client = await pool.connect();

  try {
    if (!parsedAmount || parsedAmount < 5) throw new Error('Minimum withdrawal is $5.00 USDT');
    if (!walletAddress || walletAddress.trim().length < 12) throw new Error('Enter a valid destination wallet address');

    await client.query('BEGIN');
    const userRes = await client.query('SELECT balance_usdt FROM users WHERE id = $1 FOR UPDATE', [req.session.userId]);
    if (parseFloat(userRes.rows[0].balance_usdt) < parsedAmount) {
      throw new Error('Insufficient balance');
    }

    await client.query('UPDATE users SET balance_usdt = balance_usdt - $1 WHERE id = $2', [
      parsedAmount,
      req.session.userId
    ]);

    await client.query(
      `INSERT INTO transactions (user_id, type, network, amount_usdt, wallet_address, status)
       VALUES ($1, 'withdraw', $2, $3, $4, 'pending')`,
      [req.session.userId, network, parsedAmount, walletAddress.trim()]
    );

    await client.query('COMMIT');
    res.json({ success: true, message: 'Withdrawal request queued for payout!' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ADMIN API: Approve or Reject Pending Deposits / Withdrawals
app.post('/api/admin/tx/:id', requireAdmin, async (req, res) => {
  const { action } = req.body; // 'approve' or 'reject'
  const txId = req.params.id;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const txRes = await client.query('SELECT * FROM transactions WHERE id = $1 FOR UPDATE', [txId]);
    if (txRes.rows.length === 0) throw new Error('Transaction not found');
    const tx = txRes.rows[0];
    if (tx.status !== 'pending') throw new Error('Transaction already processed');

    if (action === 'approve') {
      if (tx.type === 'deposit') {
        await client.query('UPDATE users SET balance_usdt = balance_usdt + $1 WHERE id = $2', [
          tx.amount_usdt,
          tx.user_id
        ]);
      }
      await client.query(`UPDATE transactions SET status = 'approved' WHERE id = $1`, [txId]);
    } else if (action === 'reject') {
      if (tx.type === 'withdraw') {
        // Refund held balance on rejected withdrawal
        await client.query('UPDATE users SET balance_usdt = balance_usdt + $1 WHERE id = $2', [
          tx.amount_usdt,
          tx.user_id
        ]);
      }
      await client.query(`UPDATE transactions SET status = 'rejected' WHERE id = $1`, [txId]);
    }

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.listen(PORT, () => {
  console.log(`GoldenHash Miner running on port ${PORT}`);
});