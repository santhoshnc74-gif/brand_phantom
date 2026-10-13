import json
from datetime import datetime
from db.database import SessionLocal
from db.models import (
    User, Organization, Membership, Brand, OfficialAsset,
    SourceConnection, Scan, Candidate, Detection, Review, AuditEvent
)

def seed_database():
    session = SessionLocal()
    try:
        # Check if Northstar sample organization is already seeded
        existing_org = session.query(Organization).filter(Organization.slug == "northstar-tech").first()
        if existing_org:
            print("Fictional Northstar sample organization already seeded. Skipping.")
            return existing_org.id

        print("Seeding fictional Northstar organization and sample assets...")

        # 1. Organization (Clearly marked is_sample=True)
        org = Organization(
            id="org-northstar-fictional",
            name="Northstar Technologies Org",
            slug="northstar-tech",
            is_sample=True
        )
        session.add(org)

        # 2. User
        user = User(
            id="user-vinay-kumar",
            email="security@northstar-tech.io",
            full_name="Vinay Kumar",
            role="security_lead",
            is_active=True
        )
        session.add(user)

        # 3. Membership
        membership = Membership(
            id="mem-vinay-northstar",
            organization_id=org.id,
            user_id=user.id,
            role="owner"
        )
        session.add(membership)

        # 4. Brands (All with is_sample=True)
        brand_tech = Brand(
            id="brand-northstar-tech",
            organization_id=org.id,
            name="Northstar Technologies",
            aliases_json=json.dumps(["Northstar", "Northstar Cloud", "Northstar Tech", "StarGuard", "TrueVerify"]),
            logo_url="/static/img/northstar_star.svg",
            industry="Enterprise Cloud & Cybersecurity",
            status="active",
            is_sample=True
        )
        brand_athletics = Brand(
            id="brand-northstar-athletics",
            organization_id=org.id,
            name="Northstar Athletics",
            aliases_json=json.dumps(["Northstar Gear", "Northstar Performance"]),
            logo_url=None,
            industry="Apparel & Retail",
            status="active",
            is_sample=True
        )
        brand_fintech = Brand(
            id="brand-northstar-fintech",
            organization_id=org.id,
            name="Northstar FinTech",
            aliases_json=json.dumps(["Northstar Pay", "Northstar Capital"]),
            logo_url=None,
            industry="Financial Services",
            status="active",
            is_sample=True
        )
        session.add_all([brand_tech, brand_athletics, brand_fintech])

        # 5. Official Assets for Northstar Technologies (with EXACT stable IDs)
        # Official Domains
        dom1 = OfficialAsset(
            id="asset-dom-1",
            organization_id=org.id,
            brand_id=brand_tech.id,
            asset_type="domain",
            source_platform="domain",
            exact_identifier="northstar-tech.io",
            stable_id="northstar-tech.io",
            display_name="Primary Enterprise Domain",
            verified=True,
            is_sample=True
        )
        dom2 = OfficialAsset(
            id="asset-dom-2",
            organization_id=org.id,
            brand_id=brand_tech.id,
            asset_type="domain",
            source_platform="domain",
            exact_identifier="northstar.com",
            stable_id="northstar.com",
            display_name="Corporate Gateway",
            verified=True,
            is_sample=True
        )

        # Official Social Channels with Stable IDs
        soc_ig = OfficialAsset(
            id="asset-soc-ig",
            organization_id=org.id,
            brand_id=brand_tech.id,
            asset_type="social_account",
            source_platform="instagram",
            exact_identifier="@northstar_tech",
            stable_id="ig_act_982348123", # Stable platform channel ID
            display_name="Northstar Official Instagram",
            verified=True,
            is_sample=True,
            metadata_json=json.dumps({"followers": "248K", "verified_badge": True})
        )
        soc_tw = OfficialAsset(
            id="asset-soc-tw",
            organization_id=org.id,
            brand_id=brand_tech.id,
            asset_type="social_account",
            source_platform="twitter_x",
            exact_identifier="@northstar_support",
            stable_id="tw_act_128938192301", # Stable platform user ID
            display_name="Northstar Customer Support",
            verified=True,
            is_sample=True,
            metadata_json=json.dumps({"followers": "89.5K", "verified_badge": True})
        )
        soc_tt = OfficialAsset(
            id="asset-soc-tt",
            organization_id=org.id,
            brand_id=brand_tech.id,
            asset_type="social_account",
            source_platform="tiktok",
            exact_identifier="@northstar_official",
            stable_id="tt_act_77391029381", # Stable platform user ID
            display_name="Northstar TikTok",
            verified=True,
            is_sample=True,
            metadata_json=json.dumps({"followers": "120K", "verified_badge": True})
        )
        soc_li = OfficialAsset(
            id="asset-soc-li",
            organization_id=org.id,
            brand_id=brand_tech.id,
            asset_type="social_account",
            source_platform="linkedin",
            exact_identifier="company/northstar-technologies",
            stable_id="li_org_5510293", # Stable organization ID
            display_name="Northstar Enterprise LinkedIn",
            verified=True,
            is_sample=True,
            metadata_json=json.dumps({"followers": "65K", "verified_badge": True})
        )

        # Official Mobile Apps with Package / Stable App IDs & Authorized Publisher IDs
        app_play = OfficialAsset(
            id="asset-app-play",
            organization_id=org.id,
            brand_id=brand_tech.id,
            asset_type="mobile_app",
            source_platform="google_play",
            exact_identifier="com.northstar.mobile",
            stable_id="com.northstar.mobile", # Stable package name
            authorized_publisher_id="pub-northstar-official-9021",
            authorized_publisher_name="Northstar Technologies LLC",
            display_name="Northstar Mobile Security",
            verified=True,
            is_sample=True,
            metadata_json=json.dumps({"install_count": "1.2M+", "rating": 4.7})
        )
        app_apple = OfficialAsset(
            id="asset-app-apple",
            organization_id=org.id,
            brand_id=brand_tech.id,
            asset_type="mobile_app",
            source_platform="apple_app_store",
            exact_identifier="158932014",
            stable_id="158932014", # Stable Apple App Store ID
            authorized_publisher_id="team-NST-7821",
            authorized_publisher_name="Northstar Technologies LLC",
            display_name="Northstar Mobile Authenticator & Suite",
            verified=True,
            is_sample=True,
            metadata_json=json.dumps({"ratings_count": "42K", "rating": 4.8})
        )

        session.add_all([dom1, dom2, soc_ig, soc_tw, soc_tt, soc_li, app_play, app_apple])

        # 6. Source Connections
        sources = [
            SourceConnection(
                id="src-youtube", organization_id=org.id, platform="youtube",
                name="YouTube Data API v3", connection_status="unconfigured",
                test_status="unconfigured", is_configured=False,
                status_message="Unconfigured — YouTube Data API key required",
                rate_limit_info="10,000 units/day standard quota", is_mock=False, is_sample=True
            ),
            SourceConnection(
                id="src-apple", organization_id=org.id, platform="apple_app_store",
                name="Apple App Store Connect", connection_status="ready_to_connect",
                test_status="ready_to_connect", is_configured=False,
                status_message="Ready for official Apple iTunes Catalog Discovery",
                rate_limit_info="Standard Apple iTunes Quota (~20 req/min)", is_mock=False, is_sample=True
            ),
            SourceConnection(
                id="src-play", organization_id=org.id, platform="google_play",
                name="Google Play Developer API", connection_status="unconfigured",
                test_status="unconfigured", is_configured=False,
                status_message="Requires authorized Google Play service account or developer package import",
                rate_limit_info="Google Play Quota (200,000 queries/day)", is_mock=False, is_sample=True
            ),
            SourceConnection(
                id="src-dns", organization_id=org.id, platform="domain_registry",
                name="Global Domain Registry & DNS Feed", connection_status="connected",
                test_status="connected", is_configured=True,
                status_message="Live Domain Registry Telemetry Stream operational",
                rate_limit_info="Live Telemetry Feed", is_mock=True, is_sample=True
            ),
            SourceConnection(
                id="src-ig", organization_id=org.id, platform="instagram",
                name="Instagram Graph API", connection_status="unconfigured",
                test_status="unconfigured", is_configured=False,
                status_message="Unconfigured — Instagram Graph API credentials required",
                rate_limit_info="Integration Unavailable", is_mock=True, is_sample=True
            ),
            SourceConnection(
                id="src-tw", organization_id=org.id, platform="twitter_x",
                name="X (Twitter) API v2", connection_status="unconfigured",
                test_status="unconfigured", is_configured=False,
                status_message="Unconfigured — X (Twitter) API v2 credentials required",
                rate_limit_info="Integration Unavailable", is_mock=True, is_sample=True
            ),
            SourceConnection(
                id="src-tiktok", organization_id=org.id, platform="tiktok",
                name="TikTok for Business API", connection_status="unconfigured",
                test_status="unconfigured", is_configured=False,
                status_message="Unconfigured — TikTok for Business API credentials required",
                rate_limit_info="Integration Unavailable", is_mock=True, is_sample=True
            ),
        ]
        session.add_all(sources)

        # 7. Sample Initial Scan
        scan = Scan(
            id="scan-sample-01",
            organization_id=org.id,
            brand_id=brand_tech.id,
            target_query="@northstar_official_sale",
            source_platform="all",
            status="completed",
            initiated_by_user_id=user.id,
            candidates_found=8,
            detections_flagged=8,
            is_sample=True
        )
        session.add(scan)

        # 8. Sample Candidates & Detections
        # Candidate 1: Instagram phishing
        cand1 = Candidate(
            id="cand-sample-001",
            organization_id=org.id,
            scan_id=scan.id,
            source_platform="instagram",
            candidate_identifier="@northstar_official_sale",
            stable_source_id="ig_unauthorized_9982410", # Completely different from official ig_act_982348123
            display_name="Northstar Official VIP Outlet",
            metadata_json=json.dumps({
                "followers": "14.2K",
                "account_age": "Created 4 days ago (Oct 8, 2026)",
                "target_handle": "@northstar_official_sale",
                "violations": [
                    "Unauthorized exact reproduction of Northstar starburst logo in avatar",
                    "Bio directs followers to fraudulent checkout domain: northstar-vip-discount.xyz",
                    "Direct message campaign offering fake employee discount vouchers"
                ],
                "host_telemetry": "Origin IP: 198.51.100.42 (Anonymous VPN / Proxy)",
                "visual_comparison": {
                    "logo_similarity": "98.4% Vector Match",
                    "color_palette": "Exact hex palette match (#0B132B, #3B82F6)",
                    "typography": "Mimicking Northstar brand font family"
                }
            }),
            is_sample=True
        )
        session.add(cand1)

        det1 = Detection(
            id="det-sample-001",
            organization_id=org.id,
            brand_id=brand_tech.id,
            candidate_id=cand1.id,
            risk_level="critical",
            risk_score=96,
            detection_type="Phishing & Fake Storefront",
            match_score="98% Visual Match",
            identity_status="unauthorized_impersonator", # NEVER official because stable ID differs
            similarity_details_json=json.dumps({"logo_similarity": "98.4%", "bio_text_overlap": "89.1%"}),
            status="flagged",
            is_sample=True
        )
        session.add(det1)

        # Candidate 2: Trojanized APK
        cand2 = Candidate(
            id="cand-sample-002",
            organization_id=org.id,
            scan_id=scan.id,
            source_platform="google_play",
            candidate_identifier="com.northstar.auth.token.free",
            stable_source_id="com.northstar.auth.token.free",
            publisher_identifier="pub-devstar-mobile-771", # Unauthorized publisher
            display_name="Northstar Mobile Authenticator",
            metadata_json=json.dumps({
                "audience": "5,000+ Downloads reported",
                "account_age": "Published Oct 2, 2026 (Unsigned Cert)",
                "violations": [
                    "Deceptively named to intercept corporate SSO two-factor authentication codes",
                    "Hardcoded external telemetry transmitting device identifiers and keystrokes",
                    "Decompiled APK contains unauthorized copyrighted UI icons and graphics"
                ],
                "host_telemetry": "Server C2 endpoint: 203.0.113.88 (Offshore cloud)",
                "visual_comparison": {
                    "logo_similarity": "94.2% Glyph Match",
                    "color_palette": "Near match (#0A1128 background, altered teal rim)"
                }
            }),
            is_sample=True
        )
        session.add(cand2)

        det2 = Detection(
            id="det-sample-002",
            organization_id=org.id,
            brand_id=brand_tech.id,
            candidate_id=cand2.id,
            risk_level="critical",
            risk_score=94,
            detection_type="Trojanized APK Package",
            match_score="94% Asset Similarity",
            identity_status="unauthorized_impersonator",
            status="under_review",
            is_sample=True
        )
        session.add(det2)

        # Candidate 3: X (Twitter) Support Impersonation
        cand3 = Candidate(
            id="cand-sample-003",
            organization_id=org.id,
            scan_id=scan.id,
            source_platform="twitter_x",
            candidate_identifier="@NorthstarHelpDesk_v2",
            stable_source_id="tw_fake_881923011",
            display_name="Northstar Support HelpDesk",
            metadata_json=json.dumps({
                "audience": "312 followers (Active bot network)",
                "account_age": "Created Oct 10, 2026",
                "violations": [
                    "Aggressively replying to customer complaint threads asking for wallet keys and OTP tokens",
                    "Using manipulated blue badge emoji in display name to simulate verification"
                ],
                "host_telemetry": "Automated API bot client detected via automated heuristics",
                "visual_comparison": {
                    "logo_similarity": "91.0% Circular crop of official avatar"
                }
            }),
            is_sample=True
        )
        session.add(cand3)

        det3 = Detection(
            id="det-sample-003",
            organization_id=org.id,
            brand_id=brand_tech.id,
            candidate_id=cand3.id,
            risk_level="high",
            risk_score=88,
            detection_type="Support Account Impersonation",
            match_score="91% Bio & Name Match",
            identity_status="unauthorized_impersonator",
            status="flagged",
            is_sample=True
        )
        session.add(det3)

        # Candidate 4: Apple App Store Fake Rewards
        cand4 = Candidate(
            id="cand-sample-004",
            organization_id=org.id,
            scan_id=scan.id,
            source_platform="apple_app_store",
            candidate_identifier="982341908",
            stable_source_id="982341908",
            publisher_identifier="team-starpeak-fake",
            display_name="Northstar VIP Rewards Club",
            metadata_json=json.dumps({
                "audience": "850 Reviews (4.8 artificially inflated rating)",
                "account_age": "Released Sep 28, 2026",
                "violations": [
                    "Promising non-existent $500 corporate credits in exchange for recurring subscription fee",
                    "Infringes Northstar registered trademarks 'TrueVerify' and 'StarGuard'"
                ],
                "host_telemetry": "CDN Hosted Product Page (Region: EMEA)"
            }),
            is_sample=True
        )
        session.add(cand4)

        det4 = Detection(
            id="det-sample-004",
            organization_id=org.id,
            brand_id=brand_tech.id,
            candidate_id=cand4.id,
            risk_level="high",
            risk_score=82,
            detection_type="Counterfeit Loyalty App",
            match_score="87% Typography Match",
            identity_status="unauthorized_impersonator",
            status="escalated",
            is_sample=True
        )
        session.add(det4)

        # 9. Initial Audit Event
        audit = AuditEvent(
            id="audit-seed-001",
            organization_id=org.id,
            user_id=user.id,
            action="organization.seeded",
            entity_type="organization",
            entity_id=org.id,
            details_json=json.dumps({
                "message": "Fictional Northstar organization and baseline sample assets initialized in demo sandbox.",
                "brand_count": 3,
                "asset_count": 8
            }),
            ip_address="127.0.0.1"
        )
        session.add(audit)

        session.commit()
        print("Northstar sample data seeded successfully with is_sample=True.")
        return org.id

    except Exception as e:
        session.rollback()
        print(f"Error seeding database: {e}")
        raise
    finally:
        session.close()

if __name__ == "__main__":
    seed_database()
