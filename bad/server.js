// ============================================================
// LENG_MING 社交小游戏网站 — 后端 API 服务 (Aiven PostgreSQL 版)
// 技术栈：Node.js 22+ + Express + pg + WebSocket(ws) + bcryptjs + JWT
// 部署：需配置 DATABASE_URL 环境变量连接 Aiven PostgreSQL
//
// 安全功能（v2）：
// - 登录/注册限流（用户名+IP双重，内存Map）
// - 账号临时锁定（连续5次密码错误→锁定15分钟）
// - 单设备在线（新登录踢旧设备WS + kicked通知）
// - 密码泄露告警（security_alert WebSocket推送）
// - 异地登录检测（新旧IP对比，new_ip_login告警）
// - 安全审计日志（security_events表，7种事件类型）
// - 修改密码API（POST /api/change-password）
// - 安全事件查询API（GET /api/security/events，管理员）
// ============================================================

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createServer } = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

// ==================== PostgreSQL 连接池 ====================
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('❌ 缺少环境变量 DATABASE_URL，请在 .env 中配置 Aiven PostgreSQL 连接串');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PG_SSL === 'false' ? false : { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL 连接池异常:', err.message);
});

// ==================== 建表（PostgreSQL 语法） ====================
async function initTables() {
  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      nickname TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      avatar_url TEXT,
      is_admin INTEGER DEFAULT 0,
      is_online INTEGER DEFAULT 0,
      is_banned INTEGER DEFAULT 0,
      last_seen TEXT,
      created_at TEXT DEFAULT NOW()
    )`,

    `CREATE TABLE IF NOT EXISTS friendships (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      friend_id TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      remark TEXT,
      created_at TEXT DEFAULT NOW(),
      UNIQUE(user_id, friend_id)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_fs_user_status ON friendships(user_id, status)`,
    `CREATE INDEX IF NOT EXISTS idx_fs_friend_status ON friendships(friend_id, status)`,

    `CREATE TABLE IF NOT EXISTS private_messages (
      id TEXT PRIMARY KEY,
      sender_id TEXT NOT NULL,
      receiver_id TEXT NOT NULL,
      content TEXT,
      media_url TEXT,
      media_type TEXT,
      file_name TEXT,
      is_read INTEGER DEFAULT 0,
      is_recalled INTEGER DEFAULT 0,
      created_at TEXT DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_pm_sender ON private_messages(sender_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_pm_receiver ON private_messages(receiver_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_pm_conversation ON private_messages(sender_id, receiver_id, created_at)`,

    `CREATE TABLE IF NOT EXISTS system_logs (
      id TEXT PRIMARY KEY,
      error_time TEXT DEFAULT NOW(),
      error_type TEXT,
      error_detail TEXT,
      trigger_action TEXT,
      user_id TEXT,
      device_info TEXT
    )`,
    `CREATE INDEX IF NOT EXISTS idx_sl_time ON system_logs(error_time)`,
    `CREATE INDEX IF NOT EXISTS idx_sl_type ON system_logs(error_type)`,

    `CREATE TABLE IF NOT EXISTS config (
      config_key TEXT PRIMARY KEY,
      config_value TEXT NOT NULL,
      updated_at TEXT DEFAULT NOW()
    )`,

    `CREATE TABLE IF NOT EXISTS game_categories (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      icon TEXT,
      type TEXT,
      url TEXT,
      file_path TEXT,
      submitter_id TEXT,
      status TEXT DEFAULT 'pending',
      reviewer_id TEXT,
      review_note TEXT,
      created_at TEXT DEFAULT NOW(),
      reviewed_at TEXT
    )`,

    `CREATE TABLE IF NOT EXISTS admin_tags (
      id TEXT PRIMARY KEY,
      admin_id TEXT NOT NULL,
      target_user_id TEXT NOT NULL,
      tag TEXT,
      created_at TEXT DEFAULT NOW(),
      UNIQUE(admin_id, target_user_id)
    )`,

    `CREATE TABLE IF NOT EXISTS user_levels (
      user_id TEXT PRIMARY KEY,
      exp INTEGER DEFAULT 0,
      online_minutes DOUBLE PRECISION DEFAULT 0,
      comment_count INTEGER DEFAULT 0,
      login_count INTEGER DEFAULT 0,
      last_active_at TEXT,
      updated_at TEXT DEFAULT NOW()
    )`,

    // ===== 安全功能表 =====

    `CREATE TABLE IF NOT EXISTS login_attempts (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      ip TEXT NOT NULL,
      user_agent TEXT,
      success INTEGER DEFAULT 0,
      fail_reason TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_la_username_time ON login_attempts(username, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_la_ip_time ON login_attempts(ip, created_at)`,

    `CREATE TABLE IF NOT EXISTS user_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      device_fingerprint TEXT NOT NULL,
      ip TEXT NOT NULL,
      user_agent TEXT,
      token_issued_at TIMESTAMP NOT NULL,
      last_active_at TIMESTAMP DEFAULT NOW(),
      is_current INTEGER DEFAULT 1,
      kicked_reason TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_us_user_current ON user_sessions(user_id, is_current)`,

    `CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      user_id TEXT,
      username TEXT,
      ip TEXT,
      detail TEXT,
      severity TEXT DEFAULT 'info',
      created_at TIMESTAMP DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_se_type_time ON security_events(event_type, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_se_user_time ON security_events(user_id, created_at)`,
  ];

  for (const sql of statements) {
    await pool.query(sql);
  }
  console.log('✅ PostgreSQL 建表完成');
}

// ==================== Express 初始化 ====================
const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 托管静态前端
app.use(express.static(path.join(__dirname, 'public')));

// ==================== 环境变量 ====================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SALT_ROUNDS = 10;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'YOUR_ADMIN_PASSWORD_HERE';

// ==================== 节流防护：每IP每分钟最多60次请求 ====================
const ipThrottle = {};
function throttle(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const nowMs = Date.now();
  if (!ipThrottle[ip]) ipThrottle[ip] = [];
  ipThrottle[ip] = ipThrottle[ip].filter(t => nowMs - t < 60000);
  if (ipThrottle[ip].length >= 60) return res.status(429).json({ error: '请求过于频繁，请稍后再试' });
  ipThrottle[ip].push(nowMs);
  next();
}
app.use(throttle);

// ==================== JWT 认证中间件 ====================
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { return res.status(401).json({ error: '登录已过期，请重新登录' }); }
}

function adminMiddleware(req, res, next) {
  if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: '无管理员权限' });
  next();
}

// ==================== 工具函数 ====================
function uuid() { return crypto.randomUUID(); }
function now() { return new Date().toISOString().slice(0, 19).replace('T', ' '); }
function sanitize(str) { return typeof str === 'string' ? str.replace(/[<>'";\\]/g, '') : str; }

// ==================== DB 辅助函数 ====================
async function dbAll(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows;
}
async function dbGet(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows[0];
}
async function dbRun(sql, params = []) {
  await pool.query(sql, params);
}

// ==================== 全局错误日志写入 ====================
async function logError(errorType, errorDetail, triggerAction, userId, deviceInfo) {
  try {
    await dbRun(
      'INSERT INTO system_logs (id, error_time, error_type, error_detail, trigger_action, user_id, device_info) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [uuid(), now(), errorType, String(errorDetail).slice(0, 2000), triggerAction || '', userId || null, deviceInfo || '']
    );
  } catch (e) { console.error('写入日志失败:', e.message); }
}

// ==================== 安全功能：限流 Map ====================

// 用户名维度：登录失败计数 { username: [{ ts, ip }] }
const loginFailByUsername = new Map();
// IP维度：登录失败计数 { ip: [ts] }
const loginFailByIp = new Map();
// IP维度：注册计数 { ip: [ts] }
const registerByIp = new Map();
// 用户名维度：账号锁定 { username: lockUntilTimestamp }
const accountLocks = new Map();

// 安全事件审计日志
async function logSecurityEvent(eventType, userId, username, ip, detail, severity) {
  try {
    await dbRun(
      'INSERT INTO security_events (id, event_type, user_id, username, ip, detail, severity, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [uuid(), eventType, userId || null, username || '', ip || '', JSON.stringify(detail || {}), severity || 'info', now()]
    );
  } catch (e) { console.error('写入安全事件失败:', e.message); }
}

// 检查用户名是否被锁定
function isAccountLocked(username) {
  const lockUntil = accountLocks.get(username);
  if (!lockUntil) return false;
  if (Date.now() >= lockUntil) {
    accountLocks.delete(username);
    return false;
  }
  return true;
}

// 记录登录失败（用户名维度 + IP维度）
function recordLoginFail(username, ip) {
  const nowMs = Date.now();
  // 用户名维度
  if (!loginFailByUsername.has(username)) loginFailByUsername.set(username, []);
  loginFailByUsername.get(username).push({ ts: nowMs, ip });
  // 清理15分钟前的记录
  loginFailByUsername.set(username, loginFailByUsername.get(username).filter(r => nowMs - r.ts < 15 * 60 * 1000));
  // IP维度
  if (!loginFailByIp.has(ip)) loginFailByIp.set(ip, []);
  loginFailByIp.get(ip).push(nowMs);
  loginFailByIp.set(ip, loginFailByIp.get(ip).filter(ts => nowMs - ts < 15 * 60 * 1000));
}

// 清除某用户名失败计数（登录成功时调用）
function clearLoginFails(username) {
  loginFailByUsername.delete(username);
  accountLocks.delete(username);
}

// 获取用户名15分钟内失败次数
function getLoginFailCountByUsername(username) {
  const records = loginFailByUsername.get(username);
  if (!records) return 0;
  const cutoff = Date.now() - 15 * 60 * 1000;
  return records.filter(r => r.ts >= cutoff).length;
}

// 获取IP 15分钟内登录失败次数
function getLoginFailCountByIp(ip) {
  const records = loginFailByIp.get(ip);
  if (!records) return 0;
  const cutoff = Date.now() - 15 * 60 * 1000;
  return records.filter(ts => ts >= cutoff).length;
}

// 检查IP注册限流（1小时内最多3个）
function checkRegisterRateLimit(ip) {
  const nowMs = Date.now();
  if (!registerByIp.has(ip)) registerByIp.set(ip, []);
  const records = registerByIp.get(ip).filter(ts => nowMs - ts < 60 * 60 * 1000);
  registerByIp.set(ip, records);
  return records.length < 3;
}

function recordRegister(ip) {
  if (!registerByIp.has(ip)) registerByIp.set(ip, []);
  registerByIp.get(ip).push(Date.now());
}

// 获取客户端IP
function getClientIp(req) {
  return req.ip || req.connection?.remoteAddress || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
}

// ==================== WebSocket 连接管理 ====================
const wsClients = new Map();
const wsServer = new WebSocketServer({ noServer: true });

function wsBroadcast(userId, data) {
  const clients = wsClients.get(userId);
  if (!clients) return;
  const msg = JSON.stringify(data);
  clients.forEach(ws => { if (ws.readyState === 1) ws.send(msg); });
}

wsServer.on('connection', async (ws) => {
  let userId = null;
  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === 'auth') {
        const decoded = jwt.verify(msg.token, JWT_SECRET);
        userId = decoded.userId;
        ws.userId = userId;
        if (!wsClients.has(userId)) wsClients.set(userId, new Set());
        wsClients.get(userId).add(ws);
        await dbRun('UPDATE users SET is_online=1, last_seen=$1 WHERE id=$2', [now(), userId]);
        ws.send(JSON.stringify({ type: 'auth_ok' }));
      } else if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
      }
    } catch (e) { ws.send(JSON.stringify({ type: 'error', error: e.message })); }
  });
  ws.on('close', async () => {
    if (userId) {
      const clients = wsClients.get(userId);
      if (clients) { clients.delete(ws); if (clients.size === 0) wsClients.delete(userId); }
      setTimeout(async () => {
        if (!wsClients.has(userId) || wsClients.get(userId).size === 0) {
          try { await dbRun('UPDATE users SET is_online=0, last_seen=$1 WHERE id=$2', [now(), userId]); } catch {}
        }
      }, 5000);
    }
  });
});

// ==================== API 路由 ====================

// ---------- 健康检查 ----------
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', time: now(), db: 'postgresql' });
  } catch (e) {
    res.status(503).json({ status: 'error', db: 'disconnected' });
  }
});

// ---------- 用户注册 ----------
app.post('/api/register', async (req, res) => {
  try {
    const ip = getClientIp(req);
    // 注册限流：同一IP 1小时内最多3个账号
    if (!checkRegisterRateLimit(ip)) {
      await logSecurityEvent('rate_limited', null, '', ip, { reason: 'register_ip_limit', limit: '3/hour' }, 'warning');
      return res.status(429).json({ error: '该IP注册次数过多，请1小时后再试' });
    }

    const { username, password, nickname } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码必填' });
    if (username.length < 2 || username.length > 30) return res.status(400).json({ error: '用户名2-30字符' });
    if (password.length < 4) return res.status(400).json({ error: '密码至少4位' });
    const u = sanitize(username.trim()), n = sanitize((nickname || u).trim());
    const exist = await dbGet('SELECT id FROM users WHERE username=$1', [u]);
    if (exist) return res.status(409).json({ error: '用户名已存在' });
    const hash = bcrypt.hashSync(password, SALT_ROUNDS);
    const id = uuid();
    await dbRun('INSERT INTO users (id, username, nickname, password_hash, is_admin, is_online, is_banned, created_at) VALUES ($1,$2,$3,$4,0,1,0,$5)',
      [id, u, n, hash, now()]);
    // 初始化 user_levels
    await dbRun('INSERT INTO user_levels (user_id, exp, login_count, last_active_at, updated_at) VALUES ($1,5,1,$2,$3)', [id, now(), now()]);
    const sessionId = uuid();
    const token = jwt.sign({ userId: id, username: u, isAdmin: false, jti: sessionId }, JWT_SECRET, { expiresIn: '7d' });
    // 记录注册事件
    recordRegister(ip);
    await logSecurityEvent('register_success', id, u, ip, {}, 'info');
    res.json({ token, sessionId, user: { id, username: u, nickname: n, isAdmin: false } });
  } catch (e) { await logError('register_error', e.message, 'register', null, ''); res.status(500).json({ error: '注册失败: ' + e.message }); }
});

// ---------- 用户登录 ----------
app.post('/api/login', async (req, res) => {
  try {
    const ip = getClientIp(req);
    const ua = req.headers['user-agent'] || '';
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码必填' });
    const rawUsername = sanitize(username.trim());

    // ① 检查账号是否被锁定
    if (isAccountLocked(rawUsername)) {
      await logSecurityEvent('login_locked', null, rawUsername, ip, { reason: 'account_temporarily_locked' }, 'warning');
      return res.status(429).json({ error: '账号临时锁定，请15分钟后重试' });
    }

    // ② IP维度限流：15分钟内登录失败10次
    if (getLoginFailCountByIp(ip) >= 10) {
      await logSecurityEvent('rate_limited', null, rawUsername, ip, { reason: 'ip_login_fail_limit', limit: '10/15min' }, 'warning');
      return res.status(429).json({ error: '请求过于频繁，请稍后再试' });
    }

    // ③ 用户名维度限流：15分钟内失败5次
    if (getLoginFailCountByUsername(rawUsername) >= 5) {
      accountLocks.set(rawUsername, Date.now() + 15 * 60 * 1000);
      await logSecurityEvent('login_locked', null, rawUsername, ip, { reason: 'too_many_failed_attempts', count: 5 }, 'critical');
      return res.status(429).json({ error: '账号临时锁定，请15分钟后重试' });
    }

    // ④ 查询用户（统一返回"用户名或密码错误"，不透露用户名是否存在）
    const user = await dbGet('SELECT id, username, nickname, password_hash, is_admin, is_banned, avatar_url FROM users WHERE username=$1', [rawUsername]);
    if (!user) {
      // 即使用户不存在也记录失败，防止用户名枚举
      recordLoginFail(rawUsername, ip);
      await dbRun('INSERT INTO login_attempts (id, username, ip, user_agent, success, fail_reason, created_at) VALUES ($1,$2,$3,$4,0,$5,$6)',
        [uuid(), rawUsername, ip, ua, 'user_not_found', now()]);
      await logSecurityEvent('login_failed', null, rawUsername, ip, { reason: 'user_not_found' }, 'info');
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    if (user.is_banned) return res.status(403).json({ error: '该账号已被封禁' });

    const match = bcrypt.compareSync(password, user.password_hash);
    if (!match) {
      recordLoginFail(rawUsername, ip);
      await dbRun('INSERT INTO login_attempts (id, username, ip, user_agent, success, fail_reason, created_at) VALUES ($1,$2,$3,$4,0,$5,$6)',
        [uuid(), rawUsername, ip, ua, 'wrong_password', now()]);
      await logSecurityEvent('login_failed', user.id, rawUsername, ip, { reason: 'wrong_password' }, 'info');
      // 检查是否达到锁定阈值
      if (getLoginFailCountByUsername(rawUsername) >= 5) {
        accountLocks.set(rawUsername, Date.now() + 15 * 60 * 1000);
        await logSecurityEvent('login_locked', user.id, rawUsername, ip, { reason: 'consecutive_failures', count: 5 }, 'critical');
      }
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    // ===== 登录成功 =====
    // 清除失败计数
    clearLoginFails(rawUsername);

    // 记录成功登录尝试
    await dbRun('INSERT INTO login_attempts (id, username, ip, user_agent, success, fail_reason, created_at) VALUES ($1,$2,$3,$4,1,NULL,$5)',
      [uuid(), rawUsername, ip, ua, now()]);

    // ⑤ 异地登录检测：查询上次成功登录的IP
    const lastLogin = await dbGet("SELECT ip FROM login_attempts WHERE username=$1 AND success=1 ORDER BY created_at DESC LIMIT 1 OFFSET 1", [rawUsername]);
    if (lastLogin && lastLogin.ip && lastLogin.ip !== ip) {
      // 通过 WebSocket 通知旧设备（如果在线）
      wsBroadcast(user.id, {
        type: 'security_alert',
        alertType: 'new_ip_login',
        message: '你的账号在新设备/IP上登录',
        newIp: ip,
        oldIp: lastLogin.ip,
        timestamp: now()
      });
      await logSecurityEvent('new_ip_login', user.id, rawUsername, ip, { oldIp: lastLogin.ip, newIp: ip }, 'warning');
    }

    // ⑥ 单设备在线：踢掉旧设备
    const sessionId = uuid();
    const deviceFingerprint = crypto.createHash('md5').update(ip + ua).digest('hex');
    const oldClients = wsClients.get(user.id);
    if (oldClients && oldClients.size > 0) {
      // 向旧设备发送 kicked + security_alert
      const kickMsg = JSON.stringify({
        type: 'kicked',
        reason: 'concurrent_login',
        message: '你的账号在其他设备上登录，如非本人操作请立即修改密码！'
      });
      const alertMsg = JSON.stringify({
        type: 'security_alert',
        alertType: 'concurrent_login',
        message: '检测到你的账号在其他设备上登录，可能存在密码泄露风险！',
        suggestion: '建议立即修改密码',
        newIp: ip,
        timestamp: now()
      });
      oldClients.forEach(ws => {
        if (ws.readyState === 1) {
          ws.send(kickMsg);
          ws.send(alertMsg);
          ws.close();
        }
      });
      // 记录旧会话为已踢
      try {
        await dbRun("UPDATE user_sessions SET is_current=0, kicked_reason='concurrent_login' WHERE user_id=$1 AND is_current=1", [user.id]);
      } catch {}
      await logSecurityEvent('concurrent_login', user.id, rawUsername, ip, { kickedSessions: oldClients.size }, 'warning');
    }

    // 写入新会话记录
    try {
      await dbRun(
        'INSERT INTO user_sessions (id, user_id, device_fingerprint, ip, user_agent, token_issued_at, last_active_at, is_current, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8)',
        [sessionId, user.id, deviceFingerprint, ip, ua, now(), now(), now()]
      );
    } catch {}

    await dbRun('UPDATE users SET is_online=1, last_seen=$1 WHERE id=$2', [now(), user.id]);
    await logSecurityEvent('login_success', user.id, rawUsername, ip, { sessionId }, 'info');

    const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: !!user.is_admin, jti: sessionId }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      sessionId,
      user: { id: user.id, username: user.username, nickname: user.nickname, isAdmin: !!user.is_admin, avatarUrl: user.avatar_url }
    });
  } catch (e) { await logError('login_error', e.message, 'login', null, ''); res.status(500).json({ error: '登录失败' }); }
});

// ---------- 获取当前用户信息 ----------
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const u = await dbGet('SELECT id, username, nickname, avatar_url, is_admin, is_online FROM users WHERE id=$1', [req.user.userId]);
    if (!u) return res.status(404).json({ error: '用户不存在' });
    res.json({ id: u.id, username: u.username, nickname: u.nickname, avatarUrl: u.avatar_url, isAdmin: !!u.is_admin, isOnline: !!u.is_online });
  } catch (e) { res.status(500).json({ error: '获取用户信息失败' }); }
});

// ---------- 修改昵称/头像 ----------
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { nickname, avatarUrl } = req.body;
    const updates = [], params = [];
    if (nickname) { updates.push('nickname=$' + (params.length + 1)); params.push(sanitize(nickname.trim())); }
    if (avatarUrl) { updates.push('avatar_url=$' + (params.length + 1)); params.push(avatarUrl); }
    if (updates.length === 0) return res.status(400).json({ error: '无更新内容' });
    params.push(req.user.userId);
    await dbRun(`UPDATE users SET ${updates.join(',')} WHERE id=$${params.length}`, params);
    res.json({ success: true });
  } catch (e) { await logError('profile_error', e.message, 'update_profile', req.user.userId, ''); res.status(500).json({ error: '更新失败' }); }
});

// ---------- 搜索用户 ----------
app.get('/api/users/search', authMiddleware, async (req, res) => {
  try {
    const q = sanitize((req.query.q || '').trim());
    if (!q) return res.json([]);
    const rows = await dbAll('SELECT id, username, nickname, avatar_url, is_online FROM users WHERE (username LIKE $1 OR nickname LIKE $2) AND id!=$3 AND is_banned=0 LIMIT 20',
      [`%${q}%`, `%${q}%`, req.user.userId]);
    res.json(rows.map(r => ({ id: r.id, username: r.username, nickname: r.nickname, avatarUrl: r.avatar_url, isOnline: !!r.is_online })));
  } catch (e) { res.status(500).json({ error: '搜索失败' }); }
});

// ---------- 获取好友列表 ----------
app.get('/api/friends', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.userId;
    const friends = await dbAll(
      `SELECT u.id, u.username, u.nickname, u.avatar_url, u.is_online, f.remark
       FROM friendships f JOIN users u ON (f.friend_id = u.id)
       WHERE f.user_id=$1 AND f.status='accepted'`, [uid]);
    const pending = await dbAll(
      `SELECT f.id, u.username as fromUsername, u.nickname as fromNickname, u.avatar_url as fromAvatar, f.created_at
       FROM friendships f JOIN users u ON (f.user_id = u.id)
       WHERE f.friend_id=$1 AND f.status='pending'`, [uid]);
    const sent = await dbAll(
      `SELECT f.id, u.username as toUsername, u.nickname as toNickname, f.created_at
       FROM friendships f JOIN users u ON (f.friend_id = u.id)
       WHERE f.user_id=$1 AND f.status='pending'`, [uid]);
    const blocked = await dbAll(
      `SELECT u.id, u.username, u.nickname
       FROM friendships f JOIN users u ON (f.friend_id = u.id)
       WHERE f.user_id=$1 AND f.status='blocked'`, [uid]);
    res.json({
      friends: friends.map(f => ({ id: f.id, userId: f.id, username: f.username, nickname: f.nickname, avatarUrl: f.avatar_url, isOnline: !!f.is_online, remark: f.remark })),
      pending: pending.map(p => ({ id: p.id, fromUserId: p.fromUsername, fromNickname: p.fromNickname, fromAvatar: p.fromAvatar, createdAt: p.created_at })),
      sent: sent.map(s => ({ id: s.id, toUserId: s.toUsername, toNickname: s.toNickname, createdAt: s.created_at })),
      blocked: blocked.map(b => ({ id: b.id, userId: b.id, username: b.username, nickname: b.nickname }))
    });
  } catch (e) { await logError('friends_error', e.message, 'get_friends', req.user.userId, ''); res.status(500).json({ error: '获取好友列表失败' }); }
});

// ---------- 发送好友申请 ----------
app.post('/api/friends/request', authMiddleware, async (req, res) => {
  try {
    const { targetUserId } = req.body;
    if (!targetUserId) return res.status(400).json({ error: '缺少目标用户ID' });
    if (targetUserId === req.user.userId) return res.status(400).json({ error: '不能加自己' });
    const exist = await dbGet('SELECT id, status FROM friendships WHERE user_id=$1 AND friend_id=$2', [req.user.userId, targetUserId]);
    if (exist) {
      if (exist.status === 'accepted') return res.status(409).json({ error: '已经是好友' });
      if (exist.status === 'pending') return res.status(409).json({ error: '已发送过申请' });
      if (exist.status === 'blocked') return res.status(409).json({ error: '对方已被拉黑' });
    }
    const reverseBlock = await dbGet('SELECT id FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status=$3', [targetUserId, req.user.userId, 'blocked']);
    if (reverseBlock) return res.status(409).json({ error: '无法发送申请' });
    const id = uuid();
    await dbRun('INSERT INTO friendships (id, user_id, friend_id, status, created_at) VALUES ($1,$2,$3,$4,$5)',
      [id, req.user.userId, targetUserId, 'pending', now()]);
    wsBroadcast(targetUserId, { type: 'friend_request', data: { id, fromUserId: req.user.userId, fromUsername: req.user.username } });
    res.json({ success: true, id });
  } catch (e) { await logError('friend_request_error', e.message, 'send_friend_request', req.user.userId, ''); res.status(500).json({ error: '发送申请失败' }); }
});

// ---------- 接受好友申请 ----------
app.post('/api/friends/accept/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const row = await dbGet('SELECT user_id, friend_id, status FROM friendships WHERE id=$1', [id]);
    if (!row) return res.status(404).json({ error: '申请不存在' });
    if (row.friend_id !== req.user.userId) return res.status(403).json({ error: '无权操作' });
    if (row.status !== 'pending') return res.status(400).json({ error: '申请已处理' });
    await dbRun('UPDATE friendships SET status=$1 WHERE id=$2', ['accepted', id]);
    const reverseExist = await dbGet('SELECT id FROM friendships WHERE user_id=$1 AND friend_id=$2', [req.user.userId, row.user_id]);
    if (reverseExist) {
      await dbRun('UPDATE friendships SET status=$1 WHERE id=$2', ['accepted', reverseExist.id]);
    } else {
      await dbRun('INSERT INTO friendships (id, user_id, friend_id, status, created_at) VALUES ($1,$2,$3,$4,$5)',
        [uuid(), req.user.userId, row.user_id, 'accepted', now()]);
    }
    wsBroadcast(row.user_id, { type: 'friend_accepted', data: { byUserId: req.user.userId, byUsername: req.user.username } });
    res.json({ success: true });
  } catch (e) { await logError('friend_accept_error', e.message, 'accept_friend', req.user.userId, ''); res.status(500).json({ error: '接受失败' }); }
});

// ---------- 拒绝好友申请 ----------
app.post('/api/friends/reject/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const row = await dbGet('SELECT friend_id FROM friendships WHERE id=$1 AND status=$2', [id, 'pending']);
    if (!row) return res.status(404).json({ error: '申请不存在' });
    if (row.friend_id !== req.user.userId) return res.status(403).json({ error: '无权操作' });
    await dbRun('DELETE FROM friendships WHERE id=$1', [id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '拒绝失败' }); }
});

// ---------- 删除好友 ----------
app.delete('/api/friends/:targetUserId', authMiddleware, async (req, res) => {
  try {
    const { targetUserId } = req.params;
    await dbRun('DELETE FROM friendships WHERE ((user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)) AND status=$3',
      [req.user.userId, targetUserId, 'accepted']);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '删除失败' }); }
});

// ---------- 拉黑用户 ----------
app.post('/api/friends/block', authMiddleware, async (req, res) => {
  try {
    const { targetUserId } = req.body;
    if (!targetUserId || targetUserId === req.user.userId) return res.status(400).json({ error: '无效操作' });
    await dbRun('DELETE FROM friendships WHERE (user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)',
      [req.user.userId, targetUserId]);
    await dbRun('INSERT INTO friendships (id, user_id, friend_id, status, created_at) VALUES ($1,$2,$3,$4,$5)',
      [uuid(), req.user.userId, targetUserId, 'blocked', now()]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '拉黑失败' }); }
});

// ---------- 解除拉黑 ----------
app.post('/api/friends/unblock', authMiddleware, async (req, res) => {
  try {
    const { targetUserId } = req.body;
    await dbRun('DELETE FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status=$3',
      [req.user.userId, targetUserId, 'blocked']);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '解除拉黑失败' }); }
});

// ---------- 设置好友备注 ----------
app.put('/api/friends/remark', authMiddleware, async (req, res) => {
  try {
    const { targetUserId, remark } = req.body;
    await dbRun('UPDATE friendships SET remark=$1 WHERE user_id=$2 AND friend_id=$3 AND status=$4',
      [sanitize((remark || '').trim()), req.user.userId, targetUserId, 'accepted']);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '设置备注失败' }); }
});

// ---------- 获取私聊历史消息 ----------
app.get('/api/messages/:friendId', authMiddleware, async (req, res) => {
  try {
    const { friendId } = req.params;
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const before = req.query.before || null;
    let sql = `SELECT id, sender_id, receiver_id, content, media_url, media_type, file_name, is_read, is_recalled, created_at
               FROM private_messages
               WHERE ((sender_id=$1 AND receiver_id=$2) OR (sender_id=$2 AND receiver_id=$1))`;
    const params = [req.user.userId, friendId];
    if (before) { sql += ' AND created_at < $' + (params.length + 1); params.push(before); }
    sql += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1);
    params.push(limit);
    const rows = await dbAll(sql, params);
    await dbRun('UPDATE private_messages SET is_read=1 WHERE sender_id=$1 AND receiver_id=$2 AND is_read=0',
      [friendId, req.user.userId]);
    res.json(rows.reverse().map(m => ({
      id: m.id, senderId: m.sender_id, receiverId: m.receiver_id,
      content: m.content, mediaUrl: m.media_url, mediaType: m.media_type,
      fileName: m.file_name, isRead: !!m.is_read, isRecalled: !!m.is_recalled,
      timestamp: m.created_at
    })));
  } catch (e) { await logError('msg_history_error', e.message, 'get_messages', req.user.userId, ''); res.status(500).json({ error: '获取消息失败' }); }
});

// ---------- 发送私聊消息 ----------
app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { receiverId, content, mediaUrl, mediaType, fileName } = req.body;
    if (!receiverId) return res.status(400).json({ error: '缺少接收者' });
    if (!content && !mediaUrl) return res.status(400).json({ error: '消息为空' });
    const blocked = await dbGet('SELECT id FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status=$3', [receiverId, req.user.userId, 'blocked']);
    if (blocked) return res.status(403).json({ error: '对方已拉黑你，无法发送' });
    const selfBlocked = await dbGet('SELECT id FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status=$3', [req.user.userId, receiverId, 'blocked']);
    if (selfBlocked) return res.status(403).json({ error: '你已拉黑对方，无法发送' });
    const id = uuid();
    await dbRun(
      'INSERT INTO private_messages (id, sender_id, receiver_id, content, media_url, media_type, file_name, is_read, is_recalled, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,$9)',
      [id, req.user.userId, receiverId, content || '', mediaUrl || null, mediaType || null, fileName || null, now(), now()]
    );
    const msg = {
      id, senderId: req.user.userId, receiverId, content: content || '',
      mediaUrl: mediaUrl || null, mediaType: mediaType || null,
      fileName: fileName || null, isRead: false, isRecalled: false, timestamp: now()
    };
    wsBroadcast(receiverId, { type: 'new_message', data: msg });
    res.json(msg);
  } catch (e) { await logError('msg_send_error', e.message, 'send_message', req.user.userId, ''); res.status(500).json({ error: '发送失败' }); }
});

// ---------- 撤回消息 ----------
app.post('/api/messages/recall/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const row = await dbGet('SELECT sender_id, receiver_id, created_at FROM private_messages WHERE id=$1', [id]);
    if (!row) return res.status(404).json({ error: '消息不存在' });
    if (row.sender_id !== req.user.userId) return res.status(403).json({ error: '只能撤回自己的消息' });
    const elapsed = Date.now() - new Date(row.created_at).getTime();
    if (elapsed > 120000) return res.status(400).json({ error: '超过2分钟，无法撤回' });
    await dbRun('UPDATE private_messages SET is_recalled=1, content=$1, media_url=NULL WHERE id=$2', ['[消息已撤回]', id]);
    wsBroadcast(row.receiver_id, { type: 'message_recalled', data: { id } });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '撤回失败' }); }
});

// ---------- 标记已读 ----------
app.post('/api/messages/mark-read', authMiddleware, async (req, res) => {
  try {
    const { friendId } = req.body;
    await dbRun('UPDATE private_messages SET is_read=1 WHERE sender_id=$1 AND receiver_id=$2 AND is_read=0',
      [friendId, req.user.userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '标记失败' }); }
});

// ---------- 获取未读数 ----------
app.get('/api/messages/unread', authMiddleware, async (req, res) => {
  try {
    const rows = await dbAll(
      'SELECT sender_id as "fromUserId", COUNT(*) as count FROM private_messages WHERE receiver_id=$1 AND is_read=0 AND is_recalled=0 GROUP BY sender_id',
      [req.user.userId]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: '获取未读数失败' }); }
});

// ---------- 清空与某人的聊天记录 ----------
app.delete('/api/messages/clear/:friendId', authMiddleware, async (req, res) => {
  try {
    const { friendId } = req.params;
    await dbRun('DELETE FROM private_messages WHERE (sender_id=$1 AND receiver_id=$2) OR (sender_id=$2 AND receiver_id=$1)',
      [req.user.userId, friendId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '清空失败' }); }
});

// ---------- 文件上传 ----------
app.post('/api/upload', authMiddleware, async (req, res) => {
  try {
    const { receiverId, mediaType, mediaData, fileName } = req.body;
    if (!receiverId || !mediaData) return res.status(400).json({ error: '参数不完整' });
    const id = uuid();
    const contentPrefix = mediaType === 'image' ? '📷 图片' : mediaType === 'video' ? '🎬 视频' : '📎 文件';
    await dbRun(
      'INSERT INTO private_messages (id, sender_id, receiver_id, content, media_url, media_type, file_name, is_read, is_recalled, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,$9)',
      [id, req.user.userId, receiverId, contentPrefix, mediaData, mediaType, fileName || '', now(), now()]
    );
    const msg = { id, senderId: req.user.userId, receiverId, content: contentPrefix, mediaUrl: mediaData, mediaType, fileName: fileName || '', isRead: false, isRecalled: false, timestamp: now() };
    wsBroadcast(receiverId, { type: 'new_message', data: msg });
    res.json(msg);
  } catch (e) { await logError('upload_error', e.message, 'upload', req.user.userId, ''); res.status(500).json({ error: '上传失败' }); }
});

// ==================== 安全功能接口 ====================

// ---------- 修改密码（需登录） ----------
app.post('/api/change-password', authMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ error: '请填写旧密码和新密码' });
    if (newPassword.length < 6) return res.status(400).json({ error: '新密码至少6位' });

    const user = await dbGet('SELECT id, username, password_hash FROM users WHERE id=$1', [req.user.userId]);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const match = bcrypt.compareSync(oldPassword, user.password_hash);
    if (!match) return res.status(401).json({ error: '旧密码错误' });

    const newHash = bcrypt.hashSync(newPassword, SALT_ROUNDS);
    await dbRun('UPDATE users SET password_hash=$1 WHERE id=$2', [newHash, user.id]);

    const ip = getClientIp(req);
    await logSecurityEvent('password_changed', user.id, user.username, ip, { message: '用户主动修改密码' }, 'info');

    // 通过 WebSocket 通知该用户所有连接：密码已修改，需重新登录
    const clients = wsClients.get(user.id);
    if (clients && clients.size > 0) {
      const kickMsg = JSON.stringify({ type: 'password_changed', message: '密码已修改，请重新登录' });
      clients.forEach(ws => {
        if (ws.readyState === 1) {
          ws.send(kickMsg);
          ws.close();
        }
      });
    }

    // 将当前会话标记为无效（所有会话都需要重新登录）
    try {
      await dbRun("UPDATE user_sessions SET is_current=0, kicked_reason='password_changed' WHERE user_id=$1", [user.id]);
    } catch {}

    res.json({ success: true, message: '密码修改成功' });
  } catch (e) { await logError('change_password_error', e.message, 'change_password', req.user.userId, ''); res.status(500).json({ error: '修改密码失败' }); }
});

// ---------- 获取安全事件日志（管理员） ----------
app.get('/api/security/events', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const limit = Math.min(100, parseInt(req.query.limit) || 100);
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const total = await dbGet('SELECT COUNT(*) as cnt FROM security_events');
    const events = await dbAll(
      'SELECT id, event_type, user_id, username, ip, detail, severity, created_at FROM security_events ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset]
    );
    res.json({ total: parseInt(total.cnt), limit, offset, events });
  } catch (e) { res.status(500).json({ error: '获取安全事件失败' }); }
});

// ==================== 管理员接口 ====================

// ---------- 管理员密码校验（使用环境变量密码） ----------
app.post('/api/admin/login', async (req, res) => {
  try {
    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: '管理员密码错误' });
    const token = jwt.sign({ userId: 'admin', username: 'admin', isAdmin: true }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token });
  } catch (e) { await logError('admin_login_error', e.message, 'admin_login', null, ''); res.status(500).json({ error: '校验失败' }); }
});

// ---------- 修改管理员密码（仅本次运行有效，重启恢复环境变量值） ----------
app.post('/api/admin/change-password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: '请填写当前密码和新密码' });
    if (newPassword.length < 4) return res.status(400).json({ error: '新密码至少4位' });
    if (currentPassword !== ADMIN_PASSWORD) return res.status(401).json({ error: '当前密码错误' });
    // PostgreSQL 版将新密码写入 config 表
    const newHash = bcrypt.hashSync(newPassword, SALT_ROUNDS);
    const existing = await dbGet("SELECT config_key FROM config WHERE config_key='admin_password_hash'");
    if (existing) {
      await dbRun("UPDATE config SET config_value=$1, updated_at=$2 WHERE config_key='admin_password_hash'", [newHash, now()]);
    } else {
      await dbRun("INSERT INTO config (config_key, config_value, updated_at) VALUES ('admin_password_hash',$1,$2)", [newHash, now()]);
    }
    res.json({ success: true, message: '管理员密码修改成功（重启后需更新环境变量）' });
  } catch (e) { await logError('admin_pwd_error', e.message, 'change_admin_pwd', null, ''); res.status(500).json({ error: '修改失败' }); }
});

// ---------- 获取系统日志 ----------
app.get('/api/admin/logs', async (req, res) => {
  try {
    const { password } = req.query;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: '密码错误' });
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const size = Math.min(100, parseInt(req.query.size) || 50);
    const offset = (page - 1) * size;
    const total = await dbGet('SELECT COUNT(*) as cnt FROM system_logs');
    const logs = await dbAll('SELECT id, error_time, error_type, error_detail, trigger_action, user_id, device_info FROM system_logs ORDER BY error_time DESC LIMIT $1 OFFSET $2', [size, offset]);
    res.json({ total: total.cnt, page, size, logs });
  } catch (e) { res.status(500).json({ error: '获取日志失败' }); }
});

// ---------- 清空日志 ----------
app.delete('/api/admin/logs', async (req, res) => {
  try {
    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: '密码错误' });
    await dbRun('DELETE FROM system_logs');
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '清空失败' }); }
});

// ---------- 管理员：获取所有用户 ----------
app.get('/api/admin/users', async (req, res) => {
  try {
    const { password } = req.query;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: '密码错误' });
    const users = await dbAll('SELECT id, username, nickname, is_admin, is_online, is_banned, last_seen, created_at FROM users ORDER BY created_at DESC');
    res.json(users);
  } catch (e) { res.status(500).json({ error: '获取用户列表失败' }); }
});

// ---------- 管理员：封禁/解封用户 ----------
app.post('/api/admin/ban', async (req, res) => {
  try {
    const { password, userId, banned } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: '密码错误' });
    await dbRun('UPDATE users SET is_banned=$1 WHERE id=$2', [banned ? 1 : 0, userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '操作失败' }); }
});

// ---------- 前端上报错误日志 ----------
app.post('/api/log-error', async (req, res) => {
  try {
    const { errorType, errorDetail, triggerAction, userId, deviceInfo } = req.body;
    await logError(errorType || 'unknown', errorDetail || '', triggerAction || '', userId || null, deviceInfo || '');
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: '写入日志失败' }); }
});

// ==================== 新增接口：游戏种类、管理员标签、用户等级 ====================

// ---------- POST /api/categories 提交新种类（普通用户，需登录） ----------
app.post('/api/categories', authMiddleware, async (req, res) => {
  try {
    const { name, icon, type, url, file_path } = req.body;
    if (!name) return res.status(400).json({ error: '种类名称必填' });
    if (type && !['link', 'file'].includes(type)) return res.status(400).json({ error: 'type 必须为 link 或 file' });
    const id = uuid();
    await dbRun(
      "INSERT INTO game_categories (id, name, icon, type, url, file_path, submitter_id, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8)",
      [id, sanitize(name.trim()), icon || '', type || 'link', url || '', file_path || '', req.user.userId, now()]
    );
    res.json({ success: true, id });
  } catch (e) { await logError('category_submit_error', e.message, 'submit_category', req.user.userId, ''); res.status(500).json({ error: '提交失败' }); }
});

// ---------- GET /api/categories/approved 已通过种类列表（公开） ----------
app.get('/api/categories/approved', async (req, res) => {
  try {
    const rows = await dbAll("SELECT id, name, icon, type, url, file_path, submitter_id, created_at, reviewed_at FROM game_categories WHERE status='approved' ORDER BY reviewed_at DESC");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: '获取种类列表失败' }); }
});

// ---------- GET /api/admin/pending-categories 待审核列表（管理员） ----------
app.get('/api/admin/pending-categories', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const rows = await dbAll("SELECT id, name, icon, type, url, file_path, submitter_id, status, created_at FROM game_categories WHERE status='pending' ORDER BY created_at DESC");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: '获取待审核列表失败' }); }
});

// ---------- POST /api/admin/categories/:id/review 审核种类（管理员） ----------
app.post('/api/admin/categories/:id/review', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, note } = req.body;
    if (!['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'action 必须为 approve 或 reject' });
    const cat = await dbGet('SELECT id FROM game_categories WHERE id=$1', [id]);
    if (!cat) return res.status(404).json({ error: '种类不存在' });
    const status = action === 'approve' ? 'approved' : 'rejected';
    await dbRun('UPDATE game_categories SET status=$1, reviewer_id=$2, review_note=$3, reviewed_at=$4 WHERE id=$5',
      [status, req.user.userId, note || '', now(), id]);
    res.json({ success: true, status });
  } catch (e) { res.status(500).json({ error: '审核失败' }); }
});

// ---------- POST /api/admin/users/:id/tag 打标签（管理员） ----------
app.post('/api/admin/users/:id/tag', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { tag } = req.body;
    // null 表示移除标签
    if (tag === null || tag === undefined) {
      await dbRun('DELETE FROM admin_tags WHERE admin_id=$1 AND target_user_id=$2', [req.user.userId, id]);
      return res.json({ success: true, action: 'removed' });
    }
    if (!['sub_admin', 'fake_admin'].includes(tag)) return res.status(400).json({ error: 'tag 必须为 sub_admin 或 fake_admin' });
    const existing = await dbGet('SELECT id FROM admin_tags WHERE admin_id=$1 AND target_user_id=$2', [req.user.userId, id]);
    if (existing) {
      await dbRun('UPDATE admin_tags SET tag=$1, created_at=$2 WHERE id=$3', [tag, now(), existing.id]);
    } else {
      await dbRun('INSERT INTO admin_tags (id, admin_id, target_user_id, tag, created_at) VALUES ($1,$2,$3,$4,$5)',
        [uuid(), req.user.userId, id, tag, now()]);
    }
    res.json({ success: true, tag });
  } catch (e) { res.status(500).json({ error: '打标签失败' }); }
});

// ---------- GET /api/users/:id/tag 查某用户标签 ----------
app.get('/api/users/:id/tag', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const tags = await dbAll('SELECT admin_id, tag, created_at FROM admin_tags WHERE target_user_id=$1', [id]);
    res.json(tags);
  } catch (e) { res.status(500).json({ error: '查询标签失败' }); }
});

// ---------- GET /api/users/me/level 查自己等级经验 ----------
app.get('/api/users/me/level', authMiddleware, async (req, res) => {
  try {
    let level = await dbGet('SELECT * FROM user_levels WHERE user_id=$1', [req.user.userId]);
    if (!level) {
      await dbRun('INSERT INTO user_levels (user_id, exp, updated_at) VALUES ($1,0,$2)', [req.user.userId, now()]);
      level = await dbGet('SELECT * FROM user_levels WHERE user_id=$1', [req.user.userId]);
    }
    // 计算等级：每100经验升一级
    const levelNum = Math.floor(level.exp / 100) + 1;
    const nextLevelExp = levelNum * 100;
    res.json({ ...level, level: levelNum, nextLevelExp });
  } catch (e) { res.status(500).json({ error: '查询等级失败' }); }
});

// ---------- POST /api/activity/track 上报活跃度 ----------
app.post('/api/activity/track', authMiddleware, async (req, res) => {
  try {
    const { type, amount } = req.body;
    if (!['online', 'comment', 'login'].includes(type)) return res.status(400).json({ error: 'type 必须为 online/comment/login' });

    // 确保 user_levels 记录存在
    let level = await dbGet('SELECT * FROM user_levels WHERE user_id=$1', [req.user.userId]);
    if (!level) {
      await dbRun('INSERT INTO user_levels (user_id, exp, online_minutes, comment_count, login_count, last_active_at, updated_at) VALUES ($1,0,0,0,0,$2,$3)',
        [req.user.userId, now(), now()]);
      level = await dbGet('SELECT * FROM user_levels WHERE user_id=$1', [req.user.userId]);
    }

    let expGain = 0;
    if (type === 'online') {
      const minutes = amount || 1;
      expGain = Math.round(minutes * 0.5);
      await dbRun('UPDATE user_levels SET online_minutes = online_minutes + $1, exp = exp + $2, last_active_at=$3, updated_at=$4 WHERE user_id=$5',
        [minutes, expGain, now(), now(), req.user.userId]);
    } else if (type === 'comment') {
      expGain = 10;
      await dbRun('UPDATE user_levels SET comment_count = comment_count + 1, exp = exp + 10, last_active_at=$1, updated_at=$2 WHERE user_id=$3',
        [now(), now(), req.user.userId]);
    } else if (type === 'login') {
      expGain = 5;
      await dbRun('UPDATE user_levels SET login_count = login_count + 1, exp = exp + 5, last_active_at=$1, updated_at=$2 WHERE user_id=$3',
        [now(), now(), req.user.userId]);
    }

    const updated = await dbGet('SELECT * FROM user_levels WHERE user_id=$1', [req.user.userId]);
    const levelNum = Math.floor(updated.exp / 100) + 1;
    res.json({ success: true, expGain, totalExp: updated.exp, level: levelNum });
  } catch (e) { res.status(500).json({ error: '上报活跃度失败' }); }
});

// ==================== 启动服务器 ====================
async function startServer() {
  try {
    // 测试数据库连接
    await pool.query('SELECT 1');
    console.log('✅ PostgreSQL 连接成功');

    // 建表
    await initTables();

    // 启动 HTTP + WebSocket
    const server = createServer(app);

    // WebSocket 升级
    server.on('upgrade', (req, socket, head) => {
      wsServer.handleUpgrade(req, socket, head, (ws) => {
        wsServer.emit('connection', ws, req);
      });
    });

    server.listen(PORT, () => {
      console.log(`🚀 API服务启动 (PostgreSQL版): http://0.0.0.0:${PORT}`);
      console.log(`🐘 数据库: Aiven PostgreSQL`);
      console.log(`🌐 静态前端目录: ./public/`);
      console.log(`🔑 管理员密码: ${ADMIN_PASSWORD}`);
    });
  } catch (err) {
    console.error('❌ 启动失败:', err.message);
    process.exit(1);
  }
}

startServer();
