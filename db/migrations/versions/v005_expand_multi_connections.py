"""
Migration v005: Expand source connections for multi-platform catalog and connection instances.
Adds provider_id, auth_method, enabled_brand_ids_json, granted_permissions_json, and last_scan_at.
Seeds Telegram and Facebook connector entries for existing organizations.
"""

from datetime import datetime
from sqlalchemy import text

DESCRIPTION = "Add provider_id, auth_method, brand scoping, and granted permissions for multi-source catalog"

def upgrade(conn):
    # 1. Inspect existing columns in source_connections
    columns_result = conn.execute(text("PRAGMA table_info(source_connections);"))
    existing_cols = {row[1] for row in columns_result.fetchall()}

    new_columns = [
        ("provider_id", "VARCHAR(64)"),
        ("auth_method", "VARCHAR(64)"),
        ("enabled_brand_ids_json", "TEXT DEFAULT '[]'"),
        ("granted_permissions_json", "TEXT DEFAULT '[]'"),
        ("last_scan_at", "DATETIME")
    ]

    for col_name, col_type in new_columns:
        if col_name not in existing_cols:
            conn.execute(text(f"ALTER TABLE source_connections ADD COLUMN {col_name} {col_type};"))

    # 2. Backfill provider_id with platform where provider_id is NULL
    conn.execute(text("""
        UPDATE source_connections 
        SET provider_id = platform 
        WHERE provider_id IS NULL OR provider_id = '';
    """))

    # Set auth_methods for known existing platforms
    conn.execute(text("UPDATE source_connections SET auth_method = 'api_key' WHERE platform = 'youtube';"))
    conn.execute(text("UPDATE source_connections SET auth_method = 'public_catalog' WHERE platform = 'apple_app_store';"))
    conn.execute(text("UPDATE source_connections SET auth_method = 'service_account' WHERE platform = 'google_play';"))
    conn.execute(text("UPDATE source_connections SET auth_method = 'oauth2_token' WHERE platform = 'instagram';"))
    conn.execute(text("UPDATE source_connections SET auth_method = 'oauth2_token' WHERE platform = 'twitter_x';"))

    # 3. Seed Telegram and Facebook connectors for each existing organization if missing
    orgs_res = conn.execute(text("SELECT id FROM organizations;"))
    org_ids = [row[0] for row in orgs_res.fetchall()]

    for org_id in org_ids:
        now = datetime.utcnow()
        # Seed Telegram Bot Connector
        tg_check = conn.execute(
            text("SELECT id FROM source_connections WHERE organization_id = :oid AND platform = 'telegram';"),
            {"oid": org_id}
        ).fetchone()

        if not tg_check:
            conn.execute(text("""
                INSERT INTO source_connections (
                    id, organization_id, platform, provider_id, auth_method, name, connection_status,
                    rate_limit_info, is_mock, config_json, is_configured,
                    test_status, status_message, key_source, connection_metadata_json,
                    enabled_brand_ids_json, granted_permissions_json,
                    created_at, updated_at
                ) VALUES (
                    :id, :org_id, 'telegram', 'telegram', 'bot_token', 'Telegram Bot Monitor', 'unconfigured',
                    '30 requests/sec (Official Bot API)', 0, '{}', 0,
                    'unconfigured', 'Unconfigured — Telegram Bot token required', 'none', '{}',
                    '[]', '[]',
                    :now, :now
                );
            """), {
                "id": f"src-telegram-{org_id}",
                "org_id": org_id,
                "now": now
            })

        # Seed Facebook Meta Graph Connector
        fb_check = conn.execute(
            text("SELECT id FROM source_connections WHERE organization_id = :oid AND platform = 'facebook';"),
            {"oid": org_id}
        ).fetchone()

        if not fb_check:
            conn.execute(text("""
                INSERT INTO source_connections (
                    id, organization_id, platform, provider_id, auth_method, name, connection_status,
                    rate_limit_info, is_mock, config_json, is_configured,
                    test_status, status_message, key_source, connection_metadata_json,
                    enabled_brand_ids_json, granted_permissions_json,
                    created_at, updated_at
                ) VALUES (
                    :id, :org_id, 'facebook', 'facebook', 'oauth2_token', 'Meta Page & Graph API', 'unconfigured',
                    '200 calls/hour per user (Meta Graph API)', 0, '{}', 0,
                    'unconfigured', 'Unconfigured — Meta Page or User Access Token required', 'none', '{}',
                    '[]', '[]',
                    :now, :now
                );
            """), {
                "id": f"src-facebook-{org_id}",
                "org_id": org_id,
                "now": now
            })
