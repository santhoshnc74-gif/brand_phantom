from sqlalchemy import text

DESCRIPTION = "Create initial tables for Users, Organizations, Memberships, Brands, OfficialAssets, SourceConnections, Scans, Candidates, Detections, Reviews, and AuditEvents"

def upgrade(conn):
    # 1. Users
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(36) PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            full_name VARCHAR(255) NOT NULL,
            role VARCHAR(64) DEFAULT 'security_lead',
            is_active BOOLEAN DEFAULT 1,
            created_at DATETIME,
            updated_at DATETIME
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"))

    # 2. Organizations
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS organizations (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            slug VARCHAR(128) NOT NULL UNIQUE,
            is_sample BOOLEAN DEFAULT 0,
            created_at DATETIME,
            updated_at DATETIME
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_organizations_is_sample ON organizations(is_sample);"))

    # 3. Memberships
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS memberships (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            role VARCHAR(64) DEFAULT 'admin',
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_memberships_org_user ON memberships(organization_id, user_id);"))

    # 4. Brands
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS brands (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            name VARCHAR(255) NOT NULL,
            aliases_json TEXT DEFAULT '[]',
            logo_url VARCHAR(1024),
            industry VARCHAR(128) DEFAULT 'General Enterprise',
            status VARCHAR(32) DEFAULT 'active',
            is_sample BOOLEAN DEFAULT 0,
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_brands_org_id ON brands(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_brands_name ON brands(name);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_brands_is_sample ON brands(is_sample);"))

    # 5. OfficialAssets
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS official_assets (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            brand_id VARCHAR(36) NOT NULL,
            asset_type VARCHAR(32) NOT NULL,
            source_platform VARCHAR(64) NOT NULL,
            exact_identifier VARCHAR(512) NOT NULL,
            stable_id VARCHAR(255) NOT NULL,
            authorized_publisher_id VARCHAR(255),
            authorized_publisher_name VARCHAR(255),
            display_name VARCHAR(255),
            verified BOOLEAN DEFAULT 1,
            metadata_json TEXT DEFAULT '{}',
            is_sample BOOLEAN DEFAULT 0,
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_official_assets_org_id ON official_assets(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_official_assets_brand_id ON official_assets(brand_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_official_assets_exact_match ON official_assets(source_platform, exact_identifier);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_official_assets_stable_match ON official_assets(source_platform, stable_id);"))

    # 6. SourceConnections
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS source_connections (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            platform VARCHAR(64) NOT NULL,
            name VARCHAR(255) NOT NULL,
            connection_status VARCHAR(32) DEFAULT 'connected',
            rate_limit_info VARCHAR(255) DEFAULT 'Standard Quota',
            last_sync_at DATETIME,
            is_mock BOOLEAN DEFAULT 1,
            config_json TEXT DEFAULT '{}',
            is_sample BOOLEAN DEFAULT 0,
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_source_connections_org_id ON source_connections(organization_id);"))

    # 7. Scans
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS scans (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            brand_id VARCHAR(36) NOT NULL,
            target_query VARCHAR(512) NOT NULL,
            source_platform VARCHAR(64) DEFAULT 'all',
            status VARCHAR(32) DEFAULT 'completed',
            initiated_by_user_id VARCHAR(36),
            candidates_found INTEGER DEFAULT 0,
            detections_flagged INTEGER DEFAULT 0,
            is_sample BOOLEAN DEFAULT 0,
            created_at DATETIME,
            completed_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE CASCADE,
            FOREIGN KEY (initiated_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_org_id ON scans(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_brand_id ON scans(brand_id);"))

    # 8. Candidates
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS candidates (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            scan_id VARCHAR(36),
            source_platform VARCHAR(64) NOT NULL,
            candidate_identifier VARCHAR(512) NOT NULL,
            stable_source_id VARCHAR(255),
            publisher_identifier VARCHAR(255),
            display_name VARCHAR(255) NOT NULL,
            metadata_json TEXT DEFAULT '{}',
            is_sample BOOLEAN DEFAULT 0,
            created_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_candidates_org_id ON candidates(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_candidates_scan_id ON candidates(scan_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_candidates_platform ON candidates(source_platform);"))

    # 9. Detections
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS detections (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            brand_id VARCHAR(36) NOT NULL,
            candidate_id VARCHAR(36) NOT NULL,
            risk_level VARCHAR(32) DEFAULT 'medium',
            risk_score INTEGER DEFAULT 50,
            detection_type VARCHAR(128) NOT NULL,
            match_score VARCHAR(64) DEFAULT '85% Visual Match',
            identity_status VARCHAR(64) DEFAULT 'unauthorized_impersonator',
            similarity_details_json TEXT DEFAULT '{}',
            status VARCHAR(32) DEFAULT 'flagged',
            is_sample BOOLEAN DEFAULT 0,
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE CASCADE,
            FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_detections_org_id ON detections(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_detections_brand_id ON detections(brand_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_detections_candidate_id ON detections(candidate_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_detections_risk ON detections(risk_level);"))

    # 10. Reviews
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS reviews (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            detection_id VARCHAR(36) NOT NULL,
            reviewer_user_id VARCHAR(36),
            verdict VARCHAR(32) NOT NULL,
            notes TEXT,
            evidence_snapshot_json TEXT DEFAULT '{}',
            created_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (detection_id) REFERENCES detections(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewer_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_reviews_org_id ON reviews(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_reviews_detection_id ON reviews(detection_id);"))

    # 11. AuditEvents
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36),
            action VARCHAR(128) NOT NULL,
            entity_type VARCHAR(64) NOT NULL,
            entity_id VARCHAR(36) NOT NULL,
            details_json TEXT DEFAULT '{}',
            ip_address VARCHAR(64),
            created_at DATETIME,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_audit_events_org_id ON audit_events(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_audit_events_entity ON audit_events(entity_type, entity_id);"))
