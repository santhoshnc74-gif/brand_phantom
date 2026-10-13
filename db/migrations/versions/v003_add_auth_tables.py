from sqlalchemy import text

DESCRIPTION = "Add password_hash, verification and MFA columns to users, and create sessions, auth_tokens, and rate_limits tables"

def upgrade(conn):
    # 1. Add columns to users table if not already present
    # Check existing columns in users
    result = conn.execute(text("PRAGMA table_info(users);")).fetchall()
    existing_cols = {row[1] for row in result}

    if "password_hash" not in existing_cols:
        conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255);"))
    if "is_verified" not in existing_cols:
        conn.execute(text("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0;"))
    if "mfa_secret" not in existing_cols:
        conn.execute(text("ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255);"))
    if "is_mfa_enabled" not in existing_cols:
        conn.execute(text("ALTER TABLE users ADD COLUMN is_mfa_enabled BOOLEAN DEFAULT 0;"))

    # 2. Create user_sessions table
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            token_hash VARCHAR(64) NOT NULL UNIQUE,
            ip_address VARCHAR(64),
            user_agent VARCHAR(255),
            csrf_token VARCHAR(64) NOT NULL,
            created_at DATETIME NOT NULL,
            last_activity_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            is_revoked BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON user_sessions(token_hash);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);"))

    # 3. Create auth_tokens table (for verified onboarding, password recovery, mfa temp tokens)
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            token_type VARCHAR(32) NOT NULL,
            token_hash VARCHAR(64) NOT NULL UNIQUE,
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            is_used BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash ON auth_tokens(token_hash);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_auth_tokens_type ON auth_tokens(token_type);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens(user_id);"))

    # 4. Create rate_limit_records table
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS rate_limit_records (
            id VARCHAR(36) PRIMARY KEY,
            key VARCHAR(128) NOT NULL UNIQUE,
            attempts INTEGER DEFAULT 1,
            first_attempt_at DATETIME NOT NULL,
            last_attempt_at DATETIME NOT NULL,
            blocked_until DATETIME
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_rate_limit_key ON rate_limit_records(key);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_rate_limit_blocked ON rate_limit_records(blocked_until);"))
