import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, BigInteger, Float, Text, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from db.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    role = Column(String(64), default="security_lead") # security_lead, analyst, admin, viewer
    password_hash = Column(String(255), nullable=True) # Argon2id hashed password
    is_verified = Column(Boolean, default=False, index=True) # Verified onboarding flag
    mfa_secret = Column(String(255), nullable=True) # Encrypted / protected TOTP secret
    is_mfa_enabled = Column(Boolean, default=False, index=True) # Privileged administrator MFA flag
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    memberships = relationship("Membership", back_populates="user", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="reviewer")
    audit_events = relationship("AuditEvent", back_populates="user")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    auth_tokens = relationship("AuthToken", back_populates="user", cascade="all, delete-orphan")

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(128), unique=True, nullable=False, index=True)
    is_sample = Column(Boolean, default=False, index=True) # Segregates sample/demo orgs from production
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    memberships = relationship("Membership", back_populates="organization", cascade="all, delete-orphan")
    brands = relationship("Brand", back_populates="organization", cascade="all, delete-orphan")
    source_connections = relationship("SourceConnection", back_populates="organization", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="organization", cascade="all, delete-orphan")

class Membership(Base):
    __tablename__ = "memberships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(64), default="admin") # owner, admin, analyst, viewer
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="memberships")
    user = relationship("User", back_populates="memberships")

    __table_args__ = (
        Index("idx_org_user_membership", "organization_id", "user_id", unique=True),
    )

class Brand(Base):
    __tablename__ = "brands"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    aliases_json = Column(Text, default="[]") # JSON list of aliases
    logo_url = Column(String(1024), nullable=True)
    industry = Column(String(128), default="General Enterprise")
    status = Column(String(32), default="active") # active, archived
    is_sample = Column(Boolean, default=False, index=True) # Separates sample data from production
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="brands")
    official_assets = relationship("OfficialAsset", back_populates="brand", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="brand", cascade="all, delete-orphan")
    detections = relationship("Detection", back_populates="brand", cascade="all, delete-orphan")

class OfficialAsset(Base):
    __tablename__ = "official_assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    brand_id = Column(String(36), ForeignKey("brands.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(String(32), nullable=False, index=True) # domain, social_account, mobile_app
    source_platform = Column(String(64), nullable=False, index=True) # domain, instagram, twitter_x, tiktok, linkedin, google_play, apple_app_store
    
    # Exact source-scoped identifiers
    exact_identifier = Column(String(512), nullable=False, index=True) # domain (e.g. northstar.com), handle (@northstar_tech), package (com.northstar.mobile)
    stable_id = Column(String(255), nullable=False, index=True) # platform stable id e.g. ig_user_123, app_id_158932014, canonical FQDN
    authorized_publisher_id = Column(String(255), nullable=True, index=True) # pub-12345 or apple team ID
    authorized_publisher_name = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=True)
    
    verified = Column(Boolean, default=True)
    metadata_json = Column(Text, default="{}")
    is_sample = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    brand = relationship("Brand", back_populates="official_assets")

    __table_args__ = (
        Index("idx_official_asset_exact_match", "source_platform", "exact_identifier"),
        Index("idx_official_asset_stable_match", "source_platform", "stable_id"),
    )

class SourceConnection(Base):
    __tablename__ = "source_connections"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    platform = Column(String(64), nullable=False, index=True) # instagram, twitter_x, google_play, apple_app_store, tiktok, domain_registry, youtube, telegram, facebook
    provider_id = Column(String(64), nullable=True, index=True)
    auth_method = Column(String(64), nullable=True) # api_key, bot_token, oauth2_token, service_account, public_catalog
    name = Column(String(255), nullable=False)
    connection_status = Column(String(32), default="unconfigured") # connected, ready_to_connect, paused, error, rate_limited, expired, unavailable, unconfigured
    rate_limit_info = Column(String(255), default="Standard Quota")
    last_sync_at = Column(DateTime, nullable=True)
    is_mock = Column(Boolean, default=False) # Sandbox mock connector
    config_json = Column(Text, default="{}")
    encrypted_credentials = Column(Text, nullable=True) # Ciphertext encrypted with vault key
    is_configured = Column(Boolean, default=False)
    last_tested_at = Column(DateTime, nullable=True)
    last_scan_at = Column(DateTime, nullable=True)
    test_status = Column(String(32), default="unconfigured") # connected, error, unconfigured, limited_access, rate_limited, expired, unavailable
    error_type = Column(String(64), nullable=True) # INVALID_CREDENTIALS, QUOTA_EXCEEDED, TIMEOUT, OUTAGE, etc.
    status_message = Column(String(512), nullable=True)
    key_source = Column(String(32), default="none") # org_supplied, deployment_configured, developer_import, none
    connection_metadata_json = Column(Text, default="{}")
    enabled_brand_ids_json = Column(Text, default="[]") # Brand scoping for multi-brand organizations
    granted_permissions_json = Column(Text, default="[]") # Granted OAuth scopes or token permissions
    is_sample = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def effective_provider_id(self):
        return self.provider_id or self.platform

    # Relationships
    organization = relationship("Organization", back_populates="source_connections")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    brand_id = Column(String(36), ForeignKey("brands.id", ondelete="CASCADE"), nullable=False, index=True)
    target_query = Column(String(512), nullable=False)
    source_platform = Column(String(64), default="all")
    status = Column(String(32), default="completed") # pending, scanning, completed, failed
    initiated_by_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    candidates_found = Column(Integer, default=0)
    detections_flagged = Column(Integer, default=0)
    is_sample = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="scans")
    brand = relationship("Brand", back_populates="scans")
    candidates = relationship("Candidate", back_populates="scan", cascade="all, delete-orphan")

class Candidate(Base):
    __tablename__ = "candidates"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    source_platform = Column(String(64), nullable=False, index=True)
    candidate_identifier = Column(String(512), nullable=False, index=True) # e.g. @northstar_fake, com.app.trojan
    stable_source_id = Column(String(255), nullable=True, index=True) # Platform stable ID or package ID
    publisher_identifier = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=False)
    metadata_json = Column(Text, default="{}")
    is_sample = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="candidates")
    detections = relationship("Detection", back_populates="candidate", cascade="all, delete-orphan")

class Detection(Base):
    __tablename__ = "detections"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    brand_id = Column(String(36), ForeignKey("brands.id", ondelete="CASCADE"), nullable=False, index=True)
    candidate_id = Column(String(36), ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False, index=True)
    
    risk_level = Column(String(32), default="medium", index=True) # critical, high, medium, low, none
    risk_score = Column(Integer, default=50) # 0 to 100
    detection_type = Column(String(128), nullable=False) # e.g. Phishing & Fake Storefront, Trojanized APK
    match_score = Column(String(64), default="85% Visual Match")
    
    # Official identity evaluation result:
    # 'verified_official' ONLY IF exact source-scoped stable ID matches official asset!
    # 'unauthorized_impersonator' or 'suspicious_candidate' otherwise.
    identity_status = Column(String(64), default="unauthorized_impersonator", index=True)
    
    similarity_details_json = Column(Text, default="{}")
    status = Column(String(32), default="flagged", index=True) # flagged, under_review, escalated, takedown_sent, whitelisted, dismissed
    is_sample = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    brand = relationship("Brand", back_populates="detections")
    candidate = relationship("Candidate", back_populates="detections")
    reviews = relationship("Review", back_populates="detection", cascade="all, delete-orphan")

class Review(Base):
    __tablename__ = "reviews"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    detection_id = Column(String(36), ForeignKey("detections.id", ondelete="CASCADE"), nullable=False, index=True)
    reviewer_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    verdict = Column(String(32), nullable=False) # flagged, takedown_requested, whitelisted, dismissed
    notes = Column(Text, nullable=True)
    evidence_snapshot_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    detection = relationship("Detection", back_populates="reviews")
    reviewer = relationship("User", back_populates="reviews")

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(128), nullable=False, index=True) # e.g. brand.create, brand.update, asset.create, detection.review
    entity_type = Column(String(64), nullable=False, index=True) # brand, official_asset, scan, detection
    entity_id = Column(String(36), nullable=False, index=True)
    details_json = Column(Text, default="{}")
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    organization = relationship("Organization", back_populates="audit_events")
    user = relationship("User", back_populates="audit_events")

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True) # SHA-256 of session token
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    csrf_token = Column(String(64), nullable=False) # Bound CSRF token
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, index=True)

    # Relationships
    user = relationship("User", back_populates="sessions")

class AuthToken(Base):
    __tablename__ = "auth_tokens"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_type = Column(String(32), nullable=False, index=True) # email_verification, password_reset, mfa_temp
    token_hash = Column(String(64), nullable=False, unique=True, index=True) # SHA-256 hash of token
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    is_used = Column(Boolean, default=False, index=True)

    # Relationships
    user = relationship("User", back_populates="auth_tokens")

class RateLimitRecord(Base):
    __tablename__ = "rate_limit_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    key = Column(String(128), nullable=False, unique=True, index=True)
    attempts = Column(Integer, default=1)
    first_attempt_at = Column(DateTime, default=datetime.utcnow)
    last_attempt_at = Column(DateTime, default=datetime.utcnow)
    blocked_until = Column(DateTime, nullable=True, index=True)

class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=True)
    file_hash = Column(String(64), nullable=False, index=True)
    file_size_bytes = Column(BigInteger, default=0)
    total_rows = Column(Integer, default=0)
    accepted_rows = Column(Integer, default=0)
    rejected_rows = Column(Integer, default=0)
    duplicate_rows = Column(Integer, default=0)
    conflicting_rows = Column(Integer, default=0)
    legitimate_count = Column(Integer, default=0)
    phishing_count = Column(Integer, default=0)
    cleaning_report_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    records = relationship("DatasetRecord", back_populates="dataset", cascade="all, delete-orphan")
    training_jobs = relationship("MLTrainingJob", back_populates="dataset", cascade="all, delete-orphan")
    model_artifacts = relationship("MLModelArtifact", back_populates="dataset", cascade="all, delete-orphan")

class DatasetRecord(Base):
    __tablename__ = "dataset_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    dataset_id = Column(String(36), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    row_index = Column(Integer, nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    label = Column(Integer, nullable=False)
    label_name = Column(String(32), nullable=False)
    is_duplicate = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    dataset = relationship("Dataset", back_populates="records")

class MLTrainingJob(Base):
    __tablename__ = "ml_training_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    dataset_id = Column(String(36), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default="pending", index=True) # pending, running, completed, failed, cancelled
    current_stage = Column(String(64), default="initialized")
    progress_percent = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    model_version = Column(String(64), nullable=True)
    metrics_json = Column(Text, default="{}")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    dataset = relationship("Dataset", back_populates="training_jobs")

class MLModelArtifact(Base):
    __tablename__ = "ml_model_artifacts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    model_version = Column(String(64), nullable=False, index=True)
    dataset_id = Column(String(36), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    model_type = Column(String(64), nullable=False)
    artifact_path = Column(String(512), nullable=False)
    metrics_json = Column(Text, default="{}")
    feature_extractor_version = Column(String(32), default="1.0")
    decision_threshold = Column(Float, default=0.5)
    is_active = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    dataset = relationship("Dataset", back_populates="model_artifacts")

class URLScan(Base):
    __tablename__ = "url_scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    brand_id = Column(String(36), ForeignKey("brands.id", ondelete="SET NULL"), nullable=True, index=True)
    url = Column(Text, nullable=False)
    parsed_domain = Column(String(255), nullable=False)
    identity_verdict = Column(String(64), nullable=False) # Official, Not verified as official, Unable to verify
    identity_details_json = Column(Text, default="{}")
    phishing_verdict = Column(String(64), nullable=False) # Likely phishing, Likely legitimate, Unable to assess
    phishing_score = Column(Float, nullable=True)
    model_version = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

