"""
Migration v004: Add encrypted credentials and test metadata to source connections.
Implements secure credential management, YouTube integration, and unconfigured states.
"""

from datetime import datetime
from sqlalchemy import text

DESCRIPTION = "Add encrypted credentials and test metadata columns to source_connections"

def upgrade(conn):
    # 1. Inspect existing columns
    columns_result = conn.execute(text("PRAGMA table_info(source_connections);"))
    existing_cols = {row[1] for row in columns_result.fetchall()}

    new_columns = [
        ("encrypted_credentials", "TEXT"),
        ("is_configured", "BOOLEAN DEFAULT 0"),
        ("last_tested_at", "DATETIME"),
        ("test_status", "VARCHAR(32) DEFAULT 'unconfigured'"),
        ("error_type", "VARCHAR(64)"),
        ("status_message", "VARCHAR(512)"),
        ("key_source", "VARCHAR(32) DEFAULT 'none'"),
        ("connection_metadata_json", "TEXT DEFAULT '{}'")
    ]

    for col_name, col_type in new_columns:
        if col_name not in existing_cols:
            conn.execute(text(f"ALTER TABLE source_connections ADD COLUMN {col_name} {col_type};"))

    # 2. Update existing rows: Mark unconfigured social integrations strictly as unconfigured
    # (Per requirement: Never fabricate connection success or platform coverage)
    conn.execute(text("""
        UPDATE source_connections 
        SET connection_status = 'unconfigured', 
            test_status = 'unconfigured',
            is_configured = 0,
            status_message = 'Unconfigured — Meta / Instagram Graph API credentials required'
        WHERE platform = 'instagram';
    """))

    conn.execute(text("""
        UPDATE source_connections 
        SET connection_status = 'unconfigured', 
            test_status = 'unconfigured',
            is_configured = 0,
            status_message = 'Unconfigured — X (Twitter) API v2 credentials required'
        WHERE platform = 'twitter_x';
    """))

    conn.execute(text("""
        UPDATE source_connections 
        SET connection_status = 'unconfigured', 
            test_status = 'unconfigured',
            is_configured = 0,
            status_message = 'Unconfigured — TikTok for Business API credentials required'
        WHERE platform = 'tiktok';
    """))

    conn.execute(text("""
        UPDATE source_connections 
        SET connection_status = 'unconfigured', 
            test_status = 'unconfigured',
            is_configured = 0,
            status_message = 'Requires authorized Google Play service account or developer package import'
        WHERE platform = 'google_play';
    """))

    conn.execute(text("""
        UPDATE source_connections 
        SET connection_status = 'ready_to_connect', 
            test_status = 'ready_to_connect',
            is_configured = 0,
            status_message = 'Ready for official Apple iTunes Catalog Discovery'
        WHERE platform = 'apple_app_store';
    """))

    # 3. Insert YouTube Data API v3 connector for all existing organizations if missing
    orgs_res = conn.execute(text("SELECT id FROM organizations;"))
    org_ids = [row[0] for row in orgs_res.fetchall()]

    for org_id in org_ids:
        yt_check = conn.execute(
            text("SELECT id FROM source_connections WHERE organization_id = :oid AND platform = 'youtube';"),
            {"oid": org_id}
        ).fetchone()

        if not yt_check:
            now = datetime.utcnow()
            conn.execute(text("""
                INSERT INTO source_connections (
                    id, organization_id, platform, name, connection_status,
                    rate_limit_info, is_mock, config_json, is_configured,
                    test_status, status_message, key_source, connection_metadata_json,
                    created_at, updated_at
                ) VALUES (
                    :id, :org_id, 'youtube', 'YouTube Data API v3', 'unconfigured',
                    '10,000 units/day standard quota', 0, '{}', 0,
                    'unconfigured', 'Unconfigured — YouTube Data API key required', 'none', '{}',
                    :now, :now
                );
            """), {
                "id": f"src-youtube-{org_id[:8]}",
                "org_id": org_id,
                "now": now
            })
