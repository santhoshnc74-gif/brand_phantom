from sqlalchemy import text

DESCRIPTION = "Add performance indices on organization-scoped entities for fast multi-tenant querying"

def upgrade(conn):
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_official_assets_org_brand ON official_assets(organization_id, brand_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_detections_org_brand ON detections(organization_id, brand_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_candidates_org_platform ON candidates(organization_id, source_platform);"))
