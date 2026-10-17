-- ============================================================
-- LENG_MING 安全功能迁移脚本 — PostgreSQL
-- 新增表：login_attempts, user_sessions, security_events
-- ============================================================

-- ========== UP ==========

-- 1. 登录尝试记录（限流 + 账号锁定）
CREATE TABLE IF NOT EXISTS login_attempts (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,                    -- 尝试登录的用户名
  ip TEXT NOT NULL,                          -- 请求来源IP
  user_agent TEXT,                           -- 浏览器UA（设备识别）
  success INTEGER DEFAULT 0,                 -- 1=成功 0=失败
  fail_reason TEXT,                          -- 失败原因（密码错误/账号被封等）
  created_at TIMESTAMP DEFAULT NOW()        -- 精确时间戳
);
CREATE INDEX IF NOT EXISTS idx_la_username_time ON login_attempts(username, created_at);
CREATE INDEX IF NOT EXISTS idx_la_ip_time ON login_attempts(ip, created_at);
COMMENT ON TABLE login_attempts IS '登录尝试记录，用于限流和账号锁定';

-- 2. 用户会话管理（单设备在线 + 踢人）
CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,                       -- 会话ID（JWT jti）
  user_id TEXT NOT NULL,                     -- 所属用户
  device_fingerprint TEXT NOT NULL,          -- 设备指纹（IP+UA哈希）
  ip TEXT NOT NULL,                          -- 登录IP
  user_agent TEXT,                           -- 浏览器UA
  token_issued_at TIMESTAMP NOT NULL,        -- Token签发时间
  last_active_at TIMESTAMP DEFAULT NOW(),   -- 最后活跃时间
  is_current INTEGER DEFAULT 1,             -- 1=当前会话 0=已踢
  kicked_reason TEXT,                        -- 被踢原因
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_us_user_current ON user_sessions(user_id, is_current);
CREATE INDEX IF NOT EXISTS idx_us_fingerprint ON user_sessions(device_fingerprint);
COMMENT ON TABLE user_sessions IS '用户会话追踪，支持单设备在线和密码泄露告警';

-- 3. 安全事件审计日志
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,                  -- 事件类型：login_locked/concurrent_login/ip_change/password_leak_warn 等
  user_id TEXT,                              -- 关联用户
  username TEXT,                             -- 关联用户名
  ip TEXT,                                   -- 事件来源IP
  detail TEXT,                               -- 事件详情JSON
  severity TEXT DEFAULT 'info',              -- info/warning/critical
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_se_type_time ON security_events(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_se_user_time ON security_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_se_severity ON security_events(severity);
COMMENT ON TABLE security_events IS '安全审计日志，记录所有安全相关事件';


-- ========== DOWN ==========

-- DROP INDEX IF EXISTS idx_se_severity;
-- DROP INDEX IF EXISTS idx_se_user_time;
-- DROP INDEX IF EXISTS idx_se_type_time;
-- DROP TABLE IF EXISTS security_events;
-- DROP INDEX IF EXISTS idx_us_fingerprint;
-- DROP INDEX IF EXISTS idx_us_user_current;
-- DROP TABLE IF EXISTS user_sessions;
-- DROP INDEX IF EXISTS idx_la_ip_time;
-- DROP INDEX IF EXISTS idx_la_username_time;
-- DROP TABLE IF EXISTS login_attempts;
