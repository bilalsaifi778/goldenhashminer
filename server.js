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

app.set('trust proxy', 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000
});

// Official USDT Smart Contracts
const TRC20_USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const BEP20_USDT_CONTRACT = '0x55d398326f99059ff775485246999027b3197955';
const ERC20_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

// Receiving Wallets (Replace via Render Environment Variables later)
const DEPOSIT_WALLETS = {
  'USDT-TRC20': process.env.WALLET_TRC20 || 'TX9kGoldenHashVaultTRC20DepositAddr889',
  'USDT-BEP20': process.env.WALLET_BEP20 || '0x71CGoldenHashVaultBEP20DepositAddr992'
};

(async () => {
  try {
    await pool.query(`
      ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(100) UNIQUE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
    `);
  } catch (e) {
    console.warn('Startup schema check:', e.message);
  }
})();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: true
    }),
    name: 'ghm.sid',
    secret: process.env.SESSION_SECRET || 'golden-hash-miner-prod-secret-2026',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use('/api/', apiLimiter);

// ==================== LIVE BLOCKCHAIN VERIFIERS ====================

async function verifyTronUsdtDeposit(txHash, expectedRecipient) {
  const cleanHash = txHash.trim().replace(/^0x/i, '');
  const url = `https://api.trongrid.io/v1/transactions/${cleanHash}/events`;
  const headers = { Accept: 'application/json' };
  if (process.env.TRONGRID_API_KEY) {
    headers['TRON-PRO-API-KEY'] = process.env.TRONGRID_API_KEY;
  }

  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error('Unable to reach TRON blockchain explorer. Try again in a moment.');
  }

  const json = await response.json();
  if (!json.success || !Array.isArray(json.data) || json.data.length === 0) {
    throw new Error('Transaction not found or still confirming on TRON network. Wait 1 minute and retry.');
  }

  for (const ev of json.data) {
    if (
      ev.contract_address === TRC20_USDT_CONTRACT &&
      ev.event_name === 'Transfer' &&
      ev.result
    ) {
      const toAddr = ev.result.to || ev.result['1'];
      const rawVal = ev.result.value || ev.result['2'];

      let matchedRecipient = toAddr === expectedRecipient;
      if (!matchedRecipient && toAddr && toAddr.startsWith('0x')) {
        const tsRes = await fetch(`https://apilist.tronscanapi.com/api/transaction-info?hash=${cleanHash}`);
        if (tsRes.ok) {
          const tsData = await tsRes.json();
          if (tsData.contractRet !== 'SUCCESS') {
            throw new Error('TRON transaction failed on-chain.');
          }
          const trc20Transfers = tsData.trc20TransferInfo || [];
          const match = trc20Transfers.find(
            (t) =>
              t.contract_address === TRC20_USDT_CONTRACT &&
              t.to_address === expectedRecipient
          );
          if (match) {
            return { verified: true, amountUsdt: Number(match.amount_str) / 1e6 };
          }
        }
      }

      if (matchedRecipient && rawVal) {
        return { verified: true, amountUsdt: Number(rawVal) / 1e6 };
      }
    }
  }

  throw new Error(`No USDT (TRC20) transfer to ${expectedRecipient} found in this TXID.`);
}

async function verifyBscUsdtDeposit(txHash, expectedRecipient) {
  const cleanHash = txHash.trim().startsWith('0x') ? txHash.trim() : '0x' + txHash.trim();

  const rpcRes = await fetch('https://bsc-dataseed.binance.org/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_getTransactionReceipt',
      params: [cleanHash]
    })
  });

  if (!rpcRes.ok) {
    throw new Error('Unable to reach BNB Smart Chain RPC node.');
  }

  const rpcJson = await rpcRes.json();
  const receipt = rpcJson.result;

  if (!receipt) {
    throw new Error('Transaction not found or still pending on BNB Chain. Wait 15 seconds and retry.');
  }

  if (receipt.status !== '0x1') {
    throw new Error('This BNB Chain transaction failed (reverted) on-chain.');
  }

  const targetAddrLower = expectedRecipient.toLowerCase().replace(/^0x/, '');

  for (const log of receipt.logs || []) {
    if (
      log.address &&
      log.address.toLowerCase() === BEP20_USDT_CONTRACT &&
      Array.isArray(log.topics) &&
      log.topics.length >= 3 &&
      log.topics[0].toLowerCase() === ERC20_TRANSFER_TOPIC
    ) {
      const logRecipient = log.topics[2].toLowerCase().slice(-40);
      if (logRecipient === targetAddrLower) {
        const rawWei = BigInt(log.data);
        return { verified: true, amountUsdt: Number(rawWei) / 1e18 };
      }
    }
  }

  throw new Error(`No USDT (BEP20) transfer to ${expectedRecipient} found in this TXID.`);
}

// ==================== HELPERS ====================

async function generateUniqueIdentifiers() {
  let publicUid;
  let exists = true;
  while (exists) {
    publicUid = Math.floor(100000 + Math.random() * 900000).toString();
    const check = await pool.query('SELECT id FROM users WHERE public_uid = $1', [publicUid]);
    exists = check.rows.length > 0;
  }
  const referralCode = 'GH' + Math.random().toString(36).substring(2, 8).toUpperCase();
  return { publicUid, referralCode };
}

// Free 50 GH/s starter rig yields 1% daily on a $10 starter baseline ($0.10/day = $0.00000116/sec)
const FREE_DAILY_PROFIT_USDT = 0.10;

async function calculateMiningState(userId) {
  const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  if (userRes.rows.length === 0) return null;
  const user = userRes.rows[0];

  const now = new Date();
  const freeSeconds = Math.max(0, (now - new Date(user.last_claimed_at)) / 1000);
  let unclaimedUsdt = freeSeconds * (FREE_DAILY_PROFIT_USDT / 86400);
  let totalDailyRate = FREE_DAILY_PROFIT_USDT;

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

// ==================== AUTH ROUTES ====================

app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('auth', {
    error: req.query.error || null,
    mode: req.query.mode || 'login',
    ref: req.query.ref || '',
    googleEnabled: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET)
  });
});

app.post('/auth/register', async (req, res) => {
  try {
    const { username, email, password, ref } = req.body;
    if (!username || !email || !password || password.length < 6) {
      return res.redirect('/login?mode=register&error=' + encodeURIComponent('Username, valid email, and password (min 6 chars) are required.'));
    }

    const cleanEmail = email.toLowerCase().trim();
    const cleanUser = username.trim().replace(/[^a-zA-Z0-9_]/g, '');
    if (cleanUser.length < 3) {
      return res.redirect('/login?mode=register&error=' + encodeURIComponent('Username must be at least 3 alphanumeric characters.'));
    }

    const dupCheck = await pool.query('SELECT id FROM users WHERE email = $1 OR LOWER(username) = LOWER($2)', [cleanEmail, cleanUser]);
    if (dupCheck.rows.length > 0) {
      return res.redirect('/login?mode=register&error=' + encodeURIComponent('Email or username is already registered.'));
    }

    const hash = await bcrypt.hash(password, 10);
    const { publicUid, referralCode } = await generateUniqueIdentifiers();

    let referrerId = null;
    if (ref && ref.trim() !== '') {
      const refUser = await pool.query('SELECT id FROM users WHERE referral_code = $1', [ref.trim().toUpperCase()]);
      if (refUser.rows.length > 0) referrerId = refUser.rows[0].id;
    }

    const countRes = await pool.query('SELECT COUNT(*) FROM users');
    const role = parseInt(countRes.rows[0].count) === 0 ? 'admin' : 'user';

    const insertRes = await pool.query(
      `INSERT INTO users (public_uid, username, email, password_hash, referral_code, referred_by, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, role`,
      [publicUid, cleanUser, cleanEmail, hash, referralCode, referrerId, role]
    );

    req.session.userId = insertRes.rows[0].id;
    req.session.role = insertRes.rows[0].role;
    req.session.save(() => res.redirect('/dashboard'));
  } catch (err) {
    res.redirect('/login?mode=register&error=' + encodeURIComponent('Registration error: ' + err.message));
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (userRes.rows.length === 0) {
      return res.redirect('/login?error=' + encodeURIComponent('No account found with that email.'));
    }

    const user = userRes.rows[0];
    if (user.is_banned) return res.redirect('/login?error=' + encodeURIComponent('Account suspended.'));
    if (!user.password_hash) {
      return res.redirect('/login?error=' + encodeURIComponent('This account uses Sign in with Google.'));
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.redirect('/login?error=' + encodeURIComponent('Incorrect password.'));

    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.save(() => res.redirect('/dashboard'));
  } catch (err) {
    res.redirect('/login?error=' + encodeURIComponent('Server error during login.'));
  }
});

app.get('/auth/google', (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return res.redirect('/login?error=' + encodeURIComponent('Google Sign-In is not configured yet.'));
  }

  const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
  const stateRef = req.query.ref ? req.query.ref.trim().toUpperCase() : '';

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'online',
    prompt: 'select_account',
    state: stateRef
  });

  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.redirect('/login?error=' + encodeURIComponent('Google sign-in cancelled.'));

  try {
    const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('Failed to obtain Google token');

    const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileRes.json();
    const cleanEmail = profile.email.toLowerCase().trim();

    let userRes = await pool.query('SELECT * FROM users WHERE google_id = $1 OR email = $2', [profile.id, cleanEmail]);
    let user;

    if (userRes.rows.length > 0) {
      user = userRes.rows[0];
      if (user.is_banned) return res.redirect('/login?error=' + encodeURIComponent('Account suspended.'));
      await pool.query(
        'UPDATE users SET google_id = COALESCE(google_id, $1), avatar_url = COALESCE($2, avatar_url) WHERE id = $3',
        [profile.id, profile.picture || null, user.id]
      );
    } else {
      const { publicUid, referralCode } = await generateUniqueIdentifiers();
      const baseUsername = (profile.name || cleanEmail.split('@')[0]).replace(/[^a-zA-Z0-9_]/g, '').slice(0, 18) || 'Miner';
      const uniqueUsername = `${baseUsername}_${Math.floor(100 + Math.random() * 899)}`;

      let referrerId = null;
      if (state) {
        const refUser = await pool.query('SELECT id FROM users WHERE referral_code = $1', [state]);
        if (refUser.rows.length > 0) referrerId = refUser.rows[0].id;
      }

      const countRes = await pool.query('SELECT COUNT(*) FROM users');
      const role = parseInt(countRes.rows[0].count) === 0 ? 'admin' : 'user';

      const insertRes = await pool.query(
        `INSERT INTO users (public_uid, username, email, google_id, avatar_url, referral_code, referred_by, role)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
        [publicUid, uniqueUsername, cleanEmail, profile.id, profile.picture || null, referralCode, referrerId, role]
      );
      user = insertRes.rows[0];
    }

    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.save(() => res.redirect('/dashboard'));
  } catch (err) {
    res.redirect('/login?error=' + encodeURIComponent('Google sign-in failed: ' + err.message));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ==================== DASHBOARD & MINING APIs ====================

app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const state = await calculateMiningState(req.session.userId);
    if (!state) return res.redirect('/logout');

    const plansRes = await pool.query(
      `SELECT * FROM (
         SELECT DISTINCT ON (name) * FROM mining_plans WHERE is_active = TRUE ORDER BY name, id ASC
       ) sub ORDER BY price_usdt ASC`
    );

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
      depositWallets: DEPOSIT_WALLETS,
      baseUrl: `${req.protocol}://${req.get('host')}`
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Dashboard load error');
  }
});

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
      `UPDATE users SET balance_usdt = balance_usdt + $1, last_claimed_at = $2 WHERE id = $3 RETURNING balance_usdt`,
      [state.unclaimedUsdt, now, req.session.userId]
    );

    await client.query(
      `UPDATE user_contracts SET last_accrued_at = $1 WHERE user_id = $2 AND status = 'active'`,
      [now, req.session.userId]
    );

    await client.query(
      `INSERT INTO transactions (user_id, type, network, amount_usdt, status) VALUES ($1, 'mine_claim', 'BTC-POOL', $2, 'completed')`,
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

// Deploy Bitcoin Mining Rig (1% Daily Profit / 30% Monthly Profit over 30 Days)
app.post('/api/plans/buy', requireAuth, async (req, res) => {
  const { planId } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const planRes = await client.query('SELECT * FROM mining_plans WHERE id = $1 AND is_active = TRUE', [planId]);
    if (planRes.rows.length === 0) throw new Error('Plan unavailable');
    const plan = planRes.rows[0];
    const price = parseFloat(plan.price_usdt);
    if (price <= 0) throw new Error('Free Starter BTC Rig is already active');

    const userRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [req.session.userId]);
    const user = userRes.rows[0];

    if (parseFloat(user.balance_usdt) < price) {
      throw new Error('Insufficient USDT balance. Please deposit first.');
    }

    // Strict 1.00% daily ROI (30.00% over 30 days)
    const dailyProfit = (price * 1.0) / 100;
    const durationDays = parseInt(plan.duration_days) || 30;
    const expiresAt = new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000);

    await client.query(
      `UPDATE users SET balance_usdt = balance_usdt - $1, total_hashrate_ghs = total_hashrate_ghs + $2 WHERE id = $3`,
      [price, plan.hashrate_ghs, user.id]
    );

    await client.query(
      `INSERT INTO user_contracts (user_id, plan_id, hashrate_ghs, daily_profit_usdt, expires_at) VALUES ($1, $2, $3, $4, $5)`,
      [user.id, plan.id, plan.hashrate_ghs, dailyProfit, expiresAt]
    );

    await client.query(
      `INSERT INTO transactions (user_id, type, network, amount_usdt, status) VALUES ($1, 'plan_buy', 'BTC-RIG', $2, 'completed')`,
      [user.id, price]
    );

    if (user.referred_by) {
      const commission = price * 0.1;
      await client.query(
        `UPDATE users SET balance_usdt = balance_usdt + $1, referral_earnings = referral_earnings + $1 WHERE id = $2`,
        [commission, user.referred_by]
      );
      await client.query(
        `INSERT INTO transactions (user_id, type, network, amount_usdt, status) VALUES ($1, 'referral', 'BONUS-10%', $2, 'completed')`,
        [user.referred_by, commission]
      );
    }

    await client.query('COMMIT');
    res.json({ success: true, message: `${plan.name} deployed! Earning 1% daily (30% monthly).` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// LIVE ON-CHAIN USDT DEPOSIT VERIFICATION (TRC20 & BEP20)
app.post('/api/deposit/verify', requireAuth, async (req, res) => {
  const { network, txHash } = req.body;
  if (!txHash || txHash.trim().length < 20) {
    return res.status(400).json({ error: 'Please paste a valid blockchain Transaction Hash (TXID).' });
  }

  const normalizedHash = txHash.trim().toLowerCase();

  try {
    const existing = await pool.query('SELECT id FROM transactions WHERE LOWER(tx_hash) = $1', [normalizedHash]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'This Transaction Hash (TXID) has already been verified and credited.' });
    }

    let verification;
    if (network === 'USDT-TRC20') {
      verification = await verifyTronUsdtDeposit(txHash.trim(), DEPOSIT_WALLETS['USDT-TRC20']);
    } else if (network === 'USDT-BEP20') {
      verification = await verifyBscUsdtDeposit(txHash.trim(), DEPOSIT_WALLETS['USDT-BEP20']);
    } else {
      return res.status(400).json({ error: 'Unsupported network selected.' });
    }

    if (!verification.verified || verification.amountUsdt < 1) {
      return res.status(400).json({ error: 'Verified transfer amount must be at least $1.00 USDT.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const updatedUser = await client.query(
        `UPDATE users SET balance_usdt = balance_usdt + $1 WHERE id = $2 RETURNING public_uid, balance_usdt`,
        [verification.amountUsdt, req.session.userId]
      );

      await client.query(
        `INSERT INTO transactions (user_id, type, network, amount_usdt, tx_hash, status)
         VALUES ($1, 'deposit', $2, $3, $4, 'approved')`,
        [req.session.userId, network, verification.amountUsdt, txHash.trim()]
      );

      await client.query('COMMIT');

      res.json({
        success: true,
        creditedAmount: verification.amountUsdt,
        publicUid: updatedUser.rows[0].public_uid,
        newBalance: parseFloat(updatedUser.rows[0].balance_usdt),
        network
      });
    } catch (dbErr) {
      await client.query('ROLLBACK');
      if (dbErr.code === '23505') {
        return res.status(400).json({ error: 'This TXID has already been credited.' });
      }
      throw dbErr;
    } finally {
      client.release();
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/withdraw', requireAuth, async (req, res) => {
  const { network, amount, walletAddress } = req.body;
  const parsedAmount = parseFloat(amount);
  const client = await pool.connect();

  try {
    if (!parsedAmount || parsedAmount < 5) throw new Error('Minimum withdrawal is $5.00 USDT');
    if (!walletAddress || walletAddress.trim().length < 12) throw new Error('Enter a valid destination wallet address');

    await client.query('BEGIN');
    const userRes = await client.query('SELECT balance_usdt FROM users WHERE id = $1 FOR UPDATE', [req.session.userId]);
    if (parseFloat(userRes.rows[0].balance_usdt) < parsedAmount) throw new Error('Insufficient balance');

    await client.query('UPDATE users SET balance_usdt = balance_usdt - $1 WHERE id = $2', [parsedAmount, req.session.userId]);

    await client.query(
      `INSERT INTO transactions (user_id, type, network, amount_usdt, wallet_address, status) VALUES ($1, 'withdraw', $2, $3, $4, 'pending')`,
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

app.post('/api/admin/tx/:id', requireAdmin, async (req, res) => {
  const { action } = req.body;
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
        await client.query('UPDATE users SET balance_usdt = balance_usdt + $1 WHERE id = $2', [tx.amount_usdt, tx.user_id]);
      }
      await client.query(`UPDATE transactions SET status = 'approved' WHERE id = $1`, [txId]);
    } else if (action === 'reject') {
      if (tx.type === 'withdraw') {
        await client.query('UPDATE users SET balance_usdt = balance_usdt + $1 WHERE id = $2', [tx.amount_usdt, tx.user_id]);
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
  console.log(`Golden Hash Miner running on port ${PORT}`);
});
