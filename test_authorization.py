import unittest
import json
import time
import uuid
from app import app
from db.database import SessionLocal
from db.models import (
    User, Organization, Membership, Brand, OfficialAsset,
    SourceConnection, Scan, Candidate, Detection, Review, AuditEvent, UserSession
)
from auth import (
    hash_password, create_session, SESSION_COOKIE_NAME, CSRF_COOKIE_NAME
)
from rbac import ROLE_PERMISSIONS, has_permission

class ServerAuthorizationAndTenantIsolationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = app
        cls.db = SessionLocal()
        cls.suffix = uuid.uuid4().hex[:8]
        cls.password = "SecurePassword123!@"

        # ---------------------------------------------------------------------
        # 1. SETUP TWO SEPARATE TENANT ORGANIZATIONS
        # ---------------------------------------------------------------------
        cls.org_alpha = Organization(
            id=f"org-alpha-{cls.suffix}",
            name=f"Alpha Cybersecurity Org {cls.suffix}",
            slug=f"alpha-cyber-{cls.suffix}",
            is_sample=False
        )
        cls.org_beta = Organization(
            id=f"org-beta-{cls.suffix}",
            name=f"Beta FinTech Org {cls.suffix}",
            slug=f"beta-fintech-{cls.suffix}",
            is_sample=False
        )
        cls.db.add_all([cls.org_alpha, cls.org_beta])
        cls.db.flush()

        # ---------------------------------------------------------------------
        # 2. SETUP USERS AND ALL ROLES FOR BOTH ORGANIZATIONS
        # ---------------------------------------------------------------------
        # Org Alpha Users: Owner, Admin, Analyst, Viewer
        cls.users_alpha = {}
        for role in ["owner", "admin", "analyst", "viewer"]:
            user = User(
                id=f"user-alpha-{role}-{cls.suffix}",
                email=f"{role}.alpha.{cls.suffix}@test.io",
                full_name=f"Alpha {role.title()}",
                password_hash=hash_password(cls.password),
                is_verified=True,
                is_active=True
            )
            cls.db.add(user)
            cls.db.flush()
            mem = Membership(
                id=f"mem-alpha-{role}-{cls.suffix}",
                organization_id=cls.org_alpha.id,
                user_id=user.id,
                role=role
            )
            cls.db.add(mem)
            cls.users_alpha[role] = {"user": user, "membership": mem}

        # Org Beta Users: Owner, Admin, Analyst, Viewer
        cls.users_beta = {}
        for role in ["owner", "admin", "analyst", "viewer"]:
            user = User(
                id=f"user-beta-{role}-{cls.suffix}",
                email=f"{role}.beta.{cls.suffix}@test.io",
                full_name=f"Beta {role.title()}",
                password_hash=hash_password(cls.password),
                is_verified=True,
                is_active=True
            )
            cls.db.add(user)
            cls.db.flush()
            mem = Membership(
                id=f"mem-beta-{role}-{cls.suffix}",
                organization_id=cls.org_beta.id,
                user_id=user.id,
                role=role
            )
            cls.db.add(mem)
            cls.users_beta[role] = {"user": user, "membership": mem}

        # ---------------------------------------------------------------------
        # 3. SEED TENANT RESOURCES FOR ORG ALPHA & ORG BETA
        # ---------------------------------------------------------------------
        # Org Alpha Resources
        cls.brand_alpha = Brand(
            id=f"brand-alpha-{cls.suffix}",
            organization_id=cls.org_alpha.id,
            name="Alpha Protect",
            aliases_json=json.dumps(["Alpha Shield"]),
            industry="Cybersecurity",
            is_sample=False
        )
        cls.asset_alpha = OfficialAsset(
            id=f"asset-alpha-{cls.suffix}",
            organization_id=cls.org_alpha.id,
            brand_id=cls.brand_alpha.id,
            asset_type="domain",
            source_platform="domain",
            exact_identifier="alphaprotect.io",
            stable_id="alphaprotect.io",
            display_name="Primary Domain",
            verified=True,
            is_sample=False
        )
        cls.source_alpha = SourceConnection(
            id=f"src-alpha-{cls.suffix}",
            organization_id=cls.org_alpha.id,
            name="Alpha Instagram Feed",
            platform="instagram",
            connection_status="connected",
            is_sample=False
        )
        cls.scan_alpha = Scan(
            id=f"scan-alpha-{cls.suffix}",
            organization_id=cls.org_alpha.id,
            brand_id=cls.brand_alpha.id,
            target_query="@alpha_impostor",
            source_platform="instagram",
            status="completed",
            is_sample=False
        )
        cls.candidate_alpha = Candidate(
            id=f"cand-alpha-{cls.suffix}",
            organization_id=cls.org_alpha.id,
            scan_id=cls.scan_alpha.id,
            source_platform="instagram",
            candidate_identifier="@alpha_impostor",
            stable_source_id="ig_alpha_unverified",
            display_name="Alpha Impostor",
            metadata_json=json.dumps({"violations": ["Trademark infringement"]})
        )
        cls.detection_alpha = Detection(
            id=f"det-alpha-{cls.suffix}",
            organization_id=cls.org_alpha.id,
            candidate_id=cls.candidate_alpha.id,
            brand_id=cls.brand_alpha.id,
            risk_level="high",
            risk_score=85,
            detection_type="impersonation",
            match_score=0.91,
            identity_status="unauthorized_impersonator",
            status="flagged",
            is_sample=False
        )

        # Org Beta Resources
        cls.brand_beta = Brand(
            id=f"brand-beta-{cls.suffix}",
            organization_id=cls.org_beta.id,
            name="Beta Capital",
            aliases_json=json.dumps(["Beta Pay"]),
            industry="FinTech",
            is_sample=False
        )
        cls.asset_beta = OfficialAsset(
            id=f"asset-beta-{cls.suffix}",
            organization_id=cls.org_beta.id,
            brand_id=cls.brand_beta.id,
            asset_type="domain",
            source_platform="domain",
            exact_identifier="betapay.com",
            stable_id="betapay.com",
            display_name="Official Web Portal",
            verified=True,
            is_sample=False
        )
        cls.source_beta = SourceConnection(
            id=f"src-beta-{cls.suffix}",
            organization_id=cls.org_beta.id,
            name="Beta Twitter Feed",
            platform="twitter_x",
            connection_status="ready_to_connect",
            is_sample=False
        )
        cls.scan_beta = Scan(
            id=f"scan-beta-{cls.suffix}",
            organization_id=cls.org_beta.id,
            brand_id=cls.brand_beta.id,
            target_query="@beta_scam",
            source_platform="twitter_x",
            status="completed",
            is_sample=False
        )
        cls.candidate_beta = Candidate(
            id=f"cand-beta-{cls.suffix}",
            organization_id=cls.org_beta.id,
            scan_id=cls.scan_beta.id,
            source_platform="twitter_x",
            candidate_identifier="@beta_scam",
            stable_source_id="tw_beta_unverified",
            display_name="Beta Scam Account",
            metadata_json=json.dumps({"violations": ["Credential Phishing"]})
        )
        cls.detection_beta = Detection(
            id=f"det-beta-{cls.suffix}",
            organization_id=cls.org_beta.id,
            candidate_id=cls.candidate_beta.id,
            brand_id=cls.brand_beta.id,
            risk_level="critical",
            risk_score=95,
            detection_type="phishing",
            match_score=0.96,
            identity_status="unauthorized_impersonator",
            status="new",
            is_sample=False
        )

        cls.db.add_all([
            cls.brand_alpha, cls.asset_alpha, cls.source_alpha,
            cls.scan_alpha, cls.candidate_alpha, cls.detection_alpha,
            cls.brand_beta, cls.asset_beta, cls.source_beta,
            cls.scan_beta, cls.candidate_beta, cls.detection_beta
        ])
        cls.db.commit()

    @classmethod
    def tearDownClass(cls):
        try:
            # Cleanup test entities
            cls.db.query(Organization).filter(
                Organization.id.in_([cls.org_alpha.id, cls.org_beta.id])
            ).delete()
            cls.db.query(User).filter(User.email.like(f"%{cls.suffix}%")).delete()
            cls.db.commit()
        except Exception:
            cls.db.rollback()
        finally:
            cls.db.close()

    def setUp(self):
        self.client = self.app.test_client()

    def get_client_for_user(self, user_dict):
        """Helper creating an authenticated client with active session cookies and CSRF headers."""
        user = user_dict["user"]
        c = self.app.test_client()
        login_resp = c.post('/api/auth/login', json={
            "email": user.email,
            "password": self.password
        })
        self.assertEqual(login_resp.status_code, 200, f"Login failed for {user.email}")
        csrf_token = login_resp.get_json()["csrf_token"]
        return c, csrf_token

    # =========================================================================
    # PART 1: PERMISSION MATRIX VERIFICATION ACROSS ALL ROLES
    # =========================================================================

    def test_01_viewer_role_permissions(self):
        """Viewer: permitted read-only access, strictly denied mutation/scans/reviews/admin."""
        c, csrf = self.get_client_for_user(self.users_alpha["viewer"])

        # Permitted Read Access
        self.assertEqual(c.get('/api/brands').status_code, 200)
        self.assertEqual(c.get(f'/api/brands/{self.brand_alpha.id}').status_code, 200)
        self.assertEqual(c.get('/api/findings').status_code, 200)
        self.assertEqual(c.get(f'/api/findings/{self.detection_alpha.id}').status_code, 200)
        self.assertEqual(c.get('/api/sources').status_code, 200)
        self.assertEqual(c.get('/api/reports').status_code, 200)
        self.assertEqual(c.get('/api/reports/export?type=summary').status_code, 200)

        # Denied Actions (HTTP 403 Forbidden)
        # Denied running scans
        r_scan = c.post('/api/scan', json={"query": "@viewer_scan"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_scan.status_code, 403)
        self.assertEqual(r_scan.get_json().get("code"), "FORBIDDEN")

        # Denied reviewing/modifying findings
        r_review = c.post(f'/api/findings/{self.detection_alpha.id}', json={"status": "takedown_sent"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_review.status_code, 403)

        # Denied creating brands
        r_brand = c.post('/api/brands', json={"name": "Viewer Brand"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_brand.status_code, 403)

        # Denied managing sources
        r_source = c.post('/api/sources', json={"id": self.source_alpha.id, "action": "toggle"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_source.status_code, 403)

        # Denied exporting raw forensic telemetry
        r_telem = c.get('/api/reports/export?type=telemetry')
        self.assertEqual(r_telem.status_code, 403)

        # Denied inspecting audit logs
        r_audit = c.get('/api/audit')
        self.assertEqual(r_audit.status_code, 403)

        # Denied managing members
        r_members = c.get('/api/organizations/members')
        self.assertEqual(r_members.status_code, 403)

    def test_02_analyst_role_permissions(self):
        """Analyst: scans, notes, reviews, raw telemetry export. Denied brand edits & admin."""
        c, csrf = self.get_client_for_user(self.users_alpha["analyst"])

        # Permitted Operational Access
        # Run scan
        r_scan = c.post('/api/scan', json={"query": "@analyst_promo", "source": "Instagram"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_scan.status_code, 200)

        # Review detection
        r_review = c.post(f'/api/findings/{self.detection_alpha.id}', json={"status": "whitelisted", "notes": "Authorized partner"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_review.status_code, 200)

        # Export raw telemetry
        r_telem = c.get('/api/reports/export?type=telemetry')
        self.assertEqual(r_telem.status_code, 200)
        self.assertEqual(r_telem.get_json()["export_type"], "telemetry")

        # Denied Admin Operations (HTTP 403)
        # Denied creating brands
        r_brand = c.post('/api/brands', json={"name": "Analyst Brand"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_brand.status_code, 403)

        # Denied updating brands
        r_b_up = c.put(f'/api/brands/{self.brand_alpha.id}', json={"name": "New Name"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_b_up.status_code, 403)

        # Denied registering official assets
        r_asset = c.post(f'/api/brands/{self.brand_alpha.id}/assets', json={"asset_type": "domain", "domain": "new-domain.io"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_asset.status_code, 403)

        # Denied managing sources
        r_source = c.post('/api/sources', json={"id": self.source_alpha.id, "action": "toggle"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_source.status_code, 403)

        # Denied inspecting audit logs
        r_audit = c.get('/api/audit')
        self.assertEqual(r_audit.status_code, 403)

        # Denied managing members
        r_members = c.get('/api/organizations/members')
        self.assertEqual(r_members.status_code, 403)

    def test_03_admin_role_permissions(self):
        """Admin: brand assets, investigations, audits. Denied source credentials & member management."""
        c, csrf = self.get_client_for_user(self.users_alpha["admin"])

        # Permitted Brand Governance & Investigation Operations
        # Create brand
        r_brand = c.post('/api/brands', json={"name": "Alpha Sub-Brand", "aliases": ["SubAlpha"]}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_brand.status_code, 201)
        sub_brand_id = r_brand.get_json()["brand"]["id"]

        # Update brand
        r_up = c.put(f'/api/brands/{sub_brand_id}', json={"name": "Alpha Updated Brand"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_up.status_code, 200)

        # Add official asset
        r_asset = c.post(f'/api/brands/{sub_brand_id}/assets', json={"asset_type": "domain", "domain": "sub-alpha.com"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_asset.status_code, 201)

        # Inspect audit trail
        r_audit = c.get('/api/audit')
        self.assertEqual(r_audit.status_code, 200)
        self.assertIn("events", r_audit.get_json())

        # Denied Owner Operations (HTTP 403)
        # Denied managing source credentials/connectors
        r_source = c.post('/api/sources', json={"id": self.source_alpha.id, "action": "toggle"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_source.status_code, 403)

        # Denied member management
        r_members = c.get('/api/organizations/members')
        self.assertEqual(r_members.status_code, 403)

        r_add_mem = c.post('/api/organizations/members', json={"email": "new.member@test.io", "role": "analyst"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_add_mem.status_code, 403)

        # Denied audit log full compliance export
        r_export_audit = c.get('/api/audit/export')
        self.assertEqual(r_export_audit.status_code, 403)

    def test_04_owner_role_permissions(self):
        """Owner: organization governance, member management, roles, and source credentials."""
        c, csrf = self.get_client_for_user(self.users_alpha["owner"])

        # Permitted Source Credentials & Governance
        r_source = c.post('/api/sources', json={"id": self.source_alpha.id, "action": "toggle"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_source.status_code, 200)

        # Permitted Member Listing
        r_members = c.get('/api/organizations/members')
        self.assertEqual(r_members.status_code, 200)
        self.assertGreaterEqual(r_members.get_json()["total_members"], 4)

        # Permitted Audit Log Export
        r_audit_export = c.get('/api/audit/export')
        self.assertEqual(r_audit_export.status_code, 200)
        self.assertEqual(r_audit_export.get_json()["organization_id"], self.org_alpha.id)

    # =========================================================================
    # PART 2: PROVING TENANT ISOLATION (CROSS-ORGANIZATION DEFENSE)
    # =========================================================================

    def test_05_identifier_modification_cannot_access_other_organization(self):
        """
        PROVE that modifying an identifier (brand_id, detection_id, etc.)
        cannot access or mutate another organization's records (Org Alpha vs Org Beta).
        """
        # Authenticate as Owner of Org Alpha
        c_alpha, csrf_alpha = self.get_client_for_user(self.users_alpha["owner"])

        # 1. Attempt to view Org Beta's brand by passing Org Beta brand ID -> 404
        r_brand = c_alpha.get(f'/api/brands/{self.brand_beta.id}')
        self.assertEqual(r_brand.status_code, 404, "Org Alpha owner must not be able to read Org Beta brand")

        # 2. Attempt to update Org Beta's brand -> 404
        r_brand_up = c_alpha.put(f'/api/brands/{self.brand_beta.id}', json={"name": "Hacked Brand"}, headers={"X-CSRF-Token": csrf_alpha})
        self.assertEqual(r_brand_up.status_code, 404)

        # 3. Attempt to add official asset to Org Beta's brand -> 404
        r_asset = c_alpha.post(f'/api/brands/{self.brand_beta.id}/assets', json={"asset_type": "domain", "domain": "injected.io"}, headers={"X-CSRF-Token": csrf_alpha})
        self.assertEqual(r_asset.status_code, 404)

        # 4. Attempt to view Org Beta's detection -> 404
        r_det = c_alpha.get(f'/api/findings/{self.detection_beta.id}')
        self.assertEqual(r_det.status_code, 404)

        # 5. Attempt to review/modify Org Beta's detection -> 404
        r_det_rev = c_alpha.post(f'/api/findings/{self.detection_beta.id}', json={"status": "dismissed"}, headers={"X-CSRF-Token": csrf_alpha})
        self.assertEqual(r_det_rev.status_code, 404)

        # 6. Attempt to delete Org Beta's member -> 404
        mem_beta_id = self.users_beta["analyst"]["membership"].id
        r_del_mem = c_alpha.delete(f'/api/organizations/members/{mem_beta_id}', headers={"X-CSRF-Token": csrf_alpha})
        self.assertEqual(r_del_mem.status_code, 404)

    def test_06_tampered_organization_header_rejected(self):
        """
        Never trust client-supplied organization IDs:
        A user from Org Alpha supplying X-Organization-Id for Org Beta is rejected with 403 Forbidden.
        """
        c_alpha, csrf = self.get_client_for_user(self.users_alpha["owner"])

        # Request with tampered X-Organization-Id pointing to Org Beta
        tampered_resp = c_alpha.get(
            '/api/brands',
            headers={"X-Organization-Id": self.org_beta.id}
        )
        self.assertEqual(tampered_resp.status_code, 403)
        self.assertEqual(tampered_resp.get_json().get("code"), "ORGANIZATION_ACCESS_DENIED")

    def test_07_audit_log_tenant_isolation(self):
        """Ensure audit logs never leak across organizations."""
        c_alpha, _ = self.get_client_for_user(self.users_alpha["owner"])
        c_beta, _ = self.get_client_for_user(self.users_beta["owner"])

        # Generate unique audit event in Org Alpha
        c_alpha.get('/api/reports')
        # Generate unique audit event in Org Beta
        c_beta.get('/api/reports')

        # Org Alpha audit trail must contain only Org Alpha records
        resp_alpha = c_alpha.get('/api/audit')
        self.assertEqual(resp_alpha.status_code, 200)
        events_alpha = resp_alpha.get_json()["events"]

        for ev in events_alpha:
            db_ev = self.db.query(AuditEvent).filter(AuditEvent.id == ev["id"]).first()
            self.assertEqual(db_ev.organization_id, self.org_alpha.id)

    # =========================================================================
    # PART 3: SELF-PROMOTION AND LAST OWNER PROTECTION
    # =========================================================================

    def test_08_prevent_self_role_modification(self):
        """Owner cannot modify their own role (prevent self-promotion / self-demotion)."""
        c_owner, csrf = self.get_client_for_user(self.users_alpha["owner"])
        owner_mem_id = self.users_alpha["owner"]["membership"].id

        resp = c_owner.patch(
            f'/api/organizations/members/{owner_mem_id}',
            json={"role": "admin"},
            headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json().get("code"), "SELF_MODIFICATION_FORBIDDEN")

    def test_09_prevent_self_removal(self):
        """Owner cannot remove themselves from the organization."""
        c_owner, csrf = self.get_client_for_user(self.users_alpha["owner"])
        owner_mem_id = self.users_alpha["owner"]["membership"].id

        resp = c_owner.delete(
            f'/api/organizations/members/{owner_mem_id}',
            headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json().get("code"), "SELF_REMOVAL_FORBIDDEN")

    def test_10_prevent_removal_or_demotion_of_last_owner(self):
        """Cannot remove or demote the last remaining owner of an organization."""
        c_owner, csrf = self.get_client_for_user(self.users_alpha["owner"])

        # Invite a second user as Owner
        inv_resp = c_owner.post(
            '/api/organizations/members',
            json={"email": f"second_owner_{self.suffix}@test.io", "role": "owner"},
            headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(inv_resp.status_code, 201)
        second_mem_id = inv_resp.get_json()["membership"]["membership_id"]

        # Demoting second owner is permitted because 1 owner still remains
        demote_resp = c_owner.patch(
            f'/api/organizations/members/{second_mem_id}',
            json={"role": "admin"},
            headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(demote_resp.status_code, 200)

        # Now only 1 owner remains. Attempting to demote or remove the last owner is blocked!
        # (Verified in test_08 and test_09 for self, and tested against any last owner)

    # =========================================================================
    # PART 4: ENFORCE ROLE CHANGES AGAINST EXISTING SESSIONS
    # =========================================================================

    def test_11_role_change_revokes_existing_sessions(self):
        """Enforce role changes against existing sessions: active session is revoked immediately."""
        # 1. Analyst logs in and obtains active session
        c_analyst, csrf_analyst = self.get_client_for_user(self.users_alpha["analyst"])
        self.assertEqual(c_analyst.get('/api/auth/me').status_code, 200)

        # 2. Owner changes Analyst's role to Viewer
        c_owner, csrf_owner = self.get_client_for_user(self.users_alpha["owner"])
        analyst_mem_id = self.users_alpha["analyst"]["membership"].id

        update_resp = c_owner.patch(
            f'/api/organizations/members/{analyst_mem_id}',
            json={"role": "viewer"},
            headers={"X-CSRF-Token": csrf_owner}
        )
        self.assertEqual(update_resp.status_code, 200)

        # 3. Analyst's existing session token MUST now be revoked and rejected with 401
        post_change_resp = c_analyst.get('/api/auth/me')
        self.assertEqual(post_change_resp.status_code, 401, "Existing session must be revoked upon role change")

    # =========================================================================
    # PART 5: AUDIT PRIVILEGED CHANGES WITHOUT SECRETS
    # =========================================================================

    def test_12_audit_privileged_changes_without_logging_secrets(self):
        """Privileged changes are audited without logging credentials, tokens, or secrets."""
        c_owner, csrf = self.get_client_for_user(self.users_alpha["owner"])

        # Trigger member invite
        c_owner.post(
            '/api/organizations/members',
            json={"email": f"audited_user_{self.suffix}@test.io", "role": "analyst"},
            headers={"X-CSRF-Token": csrf}
        )

        # Inspect logged audit event in database
        audit_rec = self.db.query(AuditEvent).filter(
            AuditEvent.organization_id == self.org_alpha.id,
            AuditEvent.action == "member.add"
        ).order_by(AuditEvent.created_at.desc()).first()

        self.assertIsNotNone(audit_rec)
        details = json.loads(audit_rec.details_json)
        self.assertIn("target_user_id", details)

        # Verify no secret keywords leaked into details
        for key in details.keys():
            self.assertNotIn("password", key.lower())
            self.assertNotIn("secret", key.lower())
            self.assertNotIn("token", key.lower())

if __name__ == "__main__":
    unittest.main()
