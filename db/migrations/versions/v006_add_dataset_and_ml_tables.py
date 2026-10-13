"""
Migration v006: Add dataset management, ML training jobs, model artifacts, and URL scan tables.
Additive migration for PhiUSIIL phishing URL dataset import and ML prediction.
"""

from datetime import datetime
from sqlalchemy import text

DESCRIPTION = "Add tables for datasets, dataset records, ml training jobs, model artifacts, and url scans"

def upgrade(conn):
    # 1. Create datasets table
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS datasets (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            name VARCHAR(255) NOT NULL,
            filename VARCHAR(255) NOT NULL,
            file_path VARCHAR(512),
            file_hash VARCHAR(64) NOT NULL,
            file_size_bytes BIGINT NOT NULL,
            total_rows INTEGER NOT NULL DEFAULT 0,
            accepted_rows INTEGER NOT NULL DEFAULT 0,
            rejected_rows INTEGER NOT NULL DEFAULT 0,
            duplicate_rows INTEGER NOT NULL DEFAULT 0,
            conflicting_rows INTEGER NOT NULL DEFAULT 0,
            legitimate_count INTEGER NOT NULL DEFAULT 0,
            phishing_count INTEGER NOT NULL DEFAULT 0,
            cleaning_report_json TEXT DEFAULT '{}',
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        );
    """))

    # 2. Create dataset_records table
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS dataset_records (
            id VARCHAR(36) PRIMARY KEY,
            dataset_id VARCHAR(36) NOT NULL,
            organization_id VARCHAR(36) NOT NULL,
            row_index INTEGER NOT NULL,
            url TEXT NOT NULL,
            domain VARCHAR(255) NOT NULL,
            label INTEGER NOT NULL,
            label_name VARCHAR(32) NOT NULL,
            is_duplicate BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_dataset_records_dataset_id ON dataset_records(dataset_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_dataset_records_org_id ON dataset_records(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_dataset_records_domain ON dataset_records(domain);"))

    # 3. Create ml_training_jobs table
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ml_training_jobs (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            dataset_id VARCHAR(36) NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'pending',
            current_stage VARCHAR(64) NOT NULL DEFAULT 'initialized',
            progress_percent INTEGER NOT NULL DEFAULT 0,
            error_message TEXT,
            model_version VARCHAR(64),
            metrics_json TEXT DEFAULT '{}',
            started_at DATETIME,
            completed_at DATETIME,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_ml_jobs_org_id ON ml_training_jobs(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_ml_jobs_status ON ml_training_jobs(status);"))

    # 4. Create ml_model_artifacts table
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ml_model_artifacts (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            model_version VARCHAR(64) NOT NULL,
            dataset_id VARCHAR(36) NOT NULL,
            model_type VARCHAR(64) NOT NULL,
            artifact_path VARCHAR(512) NOT NULL,
            metrics_json TEXT DEFAULT '{}',
            feature_extractor_version VARCHAR(32) NOT NULL DEFAULT '1.0',
            decision_threshold FLOAT NOT NULL DEFAULT 0.5,
            is_active BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_ml_models_org_id ON ml_model_artifacts(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_ml_models_is_active ON ml_model_artifacts(is_active);"))

    # 5. Create url_scans table
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS url_scans (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            brand_id VARCHAR(36),
            url TEXT NOT NULL,
            parsed_domain VARCHAR(255) NOT NULL,
            identity_verdict VARCHAR(64) NOT NULL,
            identity_details_json TEXT DEFAULT '{}',
            phishing_verdict VARCHAR(64) NOT NULL,
            phishing_score FLOAT,
            model_version VARCHAR(64),
            created_at DATETIME NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE SET NULL
        );
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_url_scans_org_id ON url_scans(organization_id);"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_url_scans_brand_id ON url_scans(brand_id);"))
